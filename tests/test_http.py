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
            self.assertEqual(
                server.requests,
                [{"method": "POST", "path": "/things", "body": {"name": "widget"}}],
            )

    def test_delete_method_is_allowed(self) -> None:
        with FakeServer() as server:
            server.script("DELETE", "/things/1", 200, {"deleted": True})

            result = request("DELETE", f"{server.url}/things/1", token="tok_abc123")

            self.assertEqual(result, {"deleted": True})
            self.assertEqual(server.requests[0]["method"], "DELETE")


if __name__ == "__main__":
    unittest.main()
