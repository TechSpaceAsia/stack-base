"""Tests for stackbase.http: retrying, Bearer-authenticated JSON requests."""

import unittest

from stackbase.http import ApiError, request
from tests.fakes import FakeServer


class RetryTests(unittest.TestCase):
    def test_429_with_retry_after_sleeps_then_succeeds(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/thing", 429, {"error": "slow down"}, headers={"Retry-After": "2"})
            server.script("GET", "/thing", 200, {"ok": True})

            sleeps: list[float] = []
            result = request("GET", f"{server.url}/thing", token="tok_abc123", sleep=sleeps.append)

            self.assertEqual(result, {"ok": True})
            self.assertEqual(sleeps, [2.0])
            self.assertEqual(len(server.requests), 2)

    def test_four_consecutive_503_raises_api_error(self) -> None:
        with FakeServer() as server:
            for _ in range(4):
                server.script("GET", "/thing", 503, {"error": "unavailable"})

            with self.assertRaises(ApiError) as ctx:
                request("GET", f"{server.url}/thing", token="tok_abc123", sleep=lambda _seconds: None)

            self.assertEqual(ctx.exception.status, 503)
            self.assertEqual(len(server.requests), 4)

    def test_400_is_not_retried(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/thing", 400, {"error": "bad request"})

            with self.assertRaises(ApiError) as ctx:
                request(
                    "POST",
                    f"{server.url}/thing",
                    token="tok_abc123",
                    json_body={"name": "x"},
                    sleep=lambda _seconds: None,
                )

            self.assertEqual(ctx.exception.status, 400)
            self.assertEqual(len(server.requests), 1)

    def test_retries_are_capped_by_the_retries_parameter(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/thing", 502, {"error": "bad gateway"})

            with self.assertRaises(ApiError):
                request("GET", f"{server.url}/thing", token="tok_abc123", retries=1, sleep=lambda _seconds: None)

            # retries=1 means exactly one attempt -- no retry, no sleep.
            self.assertEqual(len(server.requests), 1)


class TokenLeakTests(unittest.TestCase):
    def test_token_never_appears_in_api_error(self) -> None:
        token = "sk_live_super_secret_token_value_12345"
        with FakeServer() as server:
            server.script("GET", "/thing", 401, {"error": f"invalid credential {token}"})

            with self.assertRaises(ApiError) as ctx:
                request("GET", f"{server.url}/thing", token=token, sleep=lambda _seconds: None)

            err = ctx.exception
            self.assertNotIn(token, str(err))
            self.assertNotIn(token, err.body)
            self.assertNotIn(token, err.message)
            self.assertNotIn(token, err.hint)


class HeadersTests(unittest.TestCase):
    """L1 (live --plan finding): Hostinger's API sits behind Cloudflare,
    which returns HTTP 403 / "error code: 1010" for urllib's default
    User-Agent (`Python-urllib/3.x`). Every request must carry an explicit,
    identifying User-Agent plus an explicit Accept header.
    """

    def test_every_request_carries_an_explicit_user_agent_and_accept_header(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/thing", 200, {"ok": True})

            request("GET", f"{server.url}/thing", token="tok_abc123")

            headers = server.requests[0]["headers"]
            self.assertIn("user-agent", headers)
            self.assertNotIn("python-urllib", headers["user-agent"].lower())
            self.assertTrue(headers["user-agent"].startswith("stack-base/"))
            self.assertIn("github.com/matiboy/stack-base", headers["user-agent"])
            self.assertEqual(headers.get("accept"), "application/json")

    def test_the_user_agent_carries_stackbase_version(self) -> None:
        from stackbase import __version__

        with FakeServer() as server:
            server.script("GET", "/thing", 200, {"ok": True})

            request("GET", f"{server.url}/thing", token="tok_abc123")

            self.assertIn(__version__, server.requests[0]["headers"]["user-agent"])


class CloudflareFirewallBlockTests(unittest.TestCase):
    """L1: a Cloudflare edge block (HTTP 403, body 'error code: 1010') is not
    a token-permission problem -- it must get its own hint, and must not be
    confused with an ordinary JSON 403 from the API itself.
    """

    def test_a_1010_block_gets_the_firewall_hint_not_the_permission_hint(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/thing", 403, "error code: 1010")

            with self.assertRaises(ApiError) as ctx:
                request("GET", f"{server.url}/thing", token="tok_abc123", sleep=lambda _seconds: None)

            self.assertEqual(ctx.exception.status, 403)
            self.assertIn("1010", ctx.exception.hint)
            self.assertIn("not a problem with your token", ctx.exception.hint)
            self.assertNotIn("doesn't have permission", ctx.exception.hint)

    def test_an_ordinary_json_403_keeps_the_permission_hint(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/thing", 403, {"error": "forbidden"})

            with self.assertRaises(ApiError) as ctx:
                request("GET", f"{server.url}/thing", token="tok_abc123", sleep=lambda _seconds: None)

            self.assertEqual(ctx.exception.status, 403)
            self.assertIn("doesn't have permission", ctx.exception.hint)
            self.assertNotIn("1010", ctx.exception.hint)


class BodyHandlingTests(unittest.TestCase):
    def test_empty_body_2xx_returns_empty_dict(self) -> None:
        with FakeServer() as server:
            server.script("DELETE", "/thing/1", 204, None)

            result = request("DELETE", f"{server.url}/thing/1", token="tok_abc123")

            self.assertEqual(result, {})

    def test_non_json_error_body_is_truncated_and_redacted(self) -> None:
        token = "tok_abc123"
        long_text = f"gateway error token={token}: " + ("x" * 2000)
        with FakeServer() as server:
            server.script("GET", "/thing", 502, long_text)

            with self.assertRaises(ApiError) as ctx:
                request("GET", f"{server.url}/thing", token=token, retries=1)

            self.assertEqual(ctx.exception.status, 502)
            self.assertLess(len(ctx.exception.body), len(long_text))
            self.assertTrue(ctx.exception.body.startswith("gateway error token="))
            self.assertNotIn(token, ctx.exception.body)

    def test_sends_json_body_and_returns_parsed_response(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/things", 201, {"id": 1})

            result = request(
                "POST",
                f"{server.url}/things",
                token="tok_abc123",
                json_body={"name": "widget"},
            )

            self.assertEqual(result, {"id": 1})
            self.assertEqual(len(server.requests), 1)
            recorded = server.requests[0]
            self.assertEqual(recorded["method"], "POST")
            self.assertEqual(recorded["path"], "/things")
            self.assertEqual(recorded["body"], {"name": "widget"})

    def test_delete_method_is_allowed(self) -> None:
        with FakeServer() as server:
            server.script("DELETE", "/things/1", 200, {"deleted": True})

            result = request("DELETE", f"{server.url}/things/1", token="tok_abc123")

            self.assertEqual(result, {"deleted": True})
            self.assertEqual(server.requests[0]["method"], "DELETE")


if __name__ == "__main__":
    unittest.main()
