"""Tests for stackbase.cloudflare.CloudflareClient, against tests.fakes.FakeServer."""

from __future__ import annotations

import unittest

from stackbase.cloudflare import CloudflareClient
from stackbase.errors import StackError
from stackbase.http import ApiError
from tests.fakes import FakeServer


def _envelope(result, *, success: bool = True, errors=None, result_info=None):
    body = {"success": success, "errors": errors or [], "result": result}
    if result_info is not None:
        body["result_info"] = result_info
    return body


def _zone(zone_id: str, name: str) -> dict:
    return {"id": zone_id, "name": name}


def _page_info(page: int = 1, total_pages: int = 1) -> dict:
    return {"page": page, "per_page": 20, "count": 0, "total_count": 0, "total_pages": total_pages}


def _record(record_id: str, *, name: str, content: str, proxied: bool = True) -> dict:
    return {"id": record_id, "type": "A", "name": name, "content": content, "proxied": proxied}


class ZoneForTests(unittest.TestCase):
    def test_picks_longest_suffix_match(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/zones?name=a.b.example.com&page=1", 200, _envelope([], result_info=_page_info()))
            server.script("GET", "/zones?name=b.example.com&page=1", 200, _envelope([], result_info=_page_info()))
            server.script(
                "GET",
                "/zones?name=example.com&page=1",
                200,
                _envelope([_zone("zone123", "example.com")], result_info=_page_info()),
            )
            client = CloudflareClient("tok", base_url=server.url)

            zone_id, zone_name = client.zone_for("a.b.example.com")

            self.assertEqual(zone_id, "zone123")
            self.assertEqual(zone_name, "example.com")
            self.assertEqual(len(server.requests), 3)

    def test_never_queries_a_bare_tld(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones?name=example.com&page=1",
                200,
                _envelope([_zone("zone123", "example.com")], result_info=_page_info()),
            )
            client = CloudflareClient("tok", base_url=server.url)

            client.zone_for("example.com")

            self.assertEqual(len(server.requests), 1)
            self.assertEqual(server.requests[0]["path"], "/zones?name=example.com&page=1")

    def test_no_zone_found_raises_stack_error_naming_token_access(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/zones?name=a.example.com&page=1", 200, _envelope([], result_info=_page_info()))
            server.script("GET", "/zones?name=example.com&page=1", 200, _envelope([], result_info=_page_info()))
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(StackError) as ctx:
                client.zone_for("a.example.com")

            self.assertIn("token", ctx.exception.hint.lower())

    def test_walks_pagination_before_giving_up_on_a_candidate(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones?name=example.com&page=1",
                200,
                _envelope([], result_info=_page_info(page=1, total_pages=2)),
            )
            server.script(
                "GET",
                "/zones?name=example.com&page=2",
                200,
                _envelope([_zone("zoneXYZ", "example.com")], result_info=_page_info(page=2, total_pages=2)),
            )
            client = CloudflareClient("tok", base_url=server.url)

            zone_id, zone_name = client.zone_for("example.com")

            self.assertEqual(zone_id, "zoneXYZ")
            self.assertEqual(zone_name, "example.com")


class UpsertARecordTests(unittest.TestCase):
    def test_creates_when_absent(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=1",
                200,
                _envelope([], result_info=_page_info()),
            )
            server.script(
                "POST",
                "/zones/zone1/dns_records",
                200,
                _envelope(_record("rec1", name="a.example.com", content="1.2.3.4")),
            )
            client = CloudflareClient("tok", base_url=server.url)

            record_id = client.upsert_a_record("zone1", "a.example.com", "1.2.3.4")

            self.assertEqual(record_id, "rec1")
            post_req = server.requests[-1]
            self.assertEqual(post_req["method"], "POST")
            self.assertEqual(
                post_req["body"],
                {"type": "A", "name": "a.example.com", "content": "1.2.3.4", "proxied": True},
            )

    def test_noops_when_content_and_proxied_already_match(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=1",
                200,
                _envelope(
                    [_record("rec1", name="a.example.com", content="1.2.3.4", proxied=True)],
                    result_info=_page_info(),
                ),
            )
            client = CloudflareClient("tok", base_url=server.url)

            record_id = client.upsert_a_record("zone1", "a.example.com", "1.2.3.4", proxied=True)

            self.assertEqual(record_id, "rec1")
            mutating = [r for r in server.requests if r["method"] in ("POST", "PUT", "PATCH")]
            self.assertEqual(mutating, [], "must not write when already converged")

    def test_updates_on_ip_change(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=1",
                200,
                _envelope(
                    [_record("rec1", name="a.example.com", content="9.9.9.9", proxied=True)],
                    result_info=_page_info(),
                ),
            )
            server.script(
                "PATCH",
                "/zones/zone1/dns_records/rec1",
                200,
                _envelope(_record("rec1", name="a.example.com", content="1.2.3.4", proxied=True)),
            )
            client = CloudflareClient("tok", base_url=server.url)

            record_id = client.upsert_a_record("zone1", "a.example.com", "1.2.3.4", proxied=True)

            self.assertEqual(record_id, "rec1")
            patch_req = server.requests[-1]
            self.assertEqual(patch_req["method"], "PATCH")
            self.assertEqual(patch_req["body"], {"content": "1.2.3.4", "proxied": True})

    def test_updates_on_proxied_change_only(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=1",
                200,
                _envelope(
                    [_record("rec1", name="a.example.com", content="1.2.3.4", proxied=False)],
                    result_info=_page_info(),
                ),
            )
            server.script(
                "PATCH",
                "/zones/zone1/dns_records/rec1",
                200,
                _envelope(_record("rec1", name="a.example.com", content="1.2.3.4", proxied=True)),
            )
            client = CloudflareClient("tok", base_url=server.url)

            record_id = client.upsert_a_record("zone1", "a.example.com", "1.2.3.4", proxied=True)

            self.assertEqual(record_id, "rec1")
            self.assertEqual(server.requests[-1]["method"], "PATCH")

    def test_multiple_records_raises_without_guessing(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=1",
                200,
                _envelope(
                    [
                        _record("rec1", name="a.example.com", content="1.2.3.4"),
                        _record("rec2", name="a.example.com", content="5.6.7.8"),
                    ],
                    result_info=_page_info(),
                ),
            )
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.upsert_a_record("zone1", "a.example.com", "1.2.3.4")

            mutating = [r for r in server.requests if r["method"] in ("POST", "PUT", "PATCH", "DELETE")]
            self.assertEqual(mutating, [], "must not guess which duplicate to keep")

    def test_walks_pagination_to_detect_a_duplicate_across_pages(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=1",
                200,
                _envelope(
                    [_record("rec1", name="a.example.com", content="1.2.3.4")],
                    result_info=_page_info(page=1, total_pages=2),
                ),
            )
            server.script(
                "GET",
                "/zones/zone1/dns_records?type=A&name=a.example.com&page=2",
                200,
                _envelope(
                    [_record("rec2", name="a.example.com", content="5.6.7.8")],
                    result_info=_page_info(page=2, total_pages=2),
                ),
            )
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.upsert_a_record("zone1", "a.example.com", "1.2.3.4")


class IpRangesTests(unittest.TestCase):
    def test_returns_v4_and_v6_lists(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/ips",
                200,
                _envelope({"ipv4_cidrs": ["173.245.48.0/20"], "ipv6_cidrs": ["2400:cb00::/32"], "etag": "abc"}),
            )
            client = CloudflareClient("tok", base_url=server.url)

            v4, v6 = client.ip_ranges()

            self.assertEqual(v4, ["173.245.48.0/20"])
            self.assertEqual(v6, ["2400:cb00::/32"])


class CreateOriginCertTests(unittest.TestCase):
    def test_returns_certificate_pem(self) -> None:
        with FakeServer() as server:
            server.script(
                "POST",
                "/certificates",
                200,
                _envelope({"id": "cert1", "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}),
            )
            client = CloudflareClient("tok", base_url=server.url)

            cert = client.create_origin_cert(["a.example.com"], "-----BEGIN CERTIFICATE REQUEST-----\n...")

            self.assertTrue(cert.startswith("-----BEGIN CERTIFICATE-----"))
            req = server.requests[-1]
            self.assertEqual(req["body"]["hostnames"], ["a.example.com"])
            self.assertEqual(req["body"]["requested_validity"], 5475)
            self.assertEqual(req["body"]["request_type"], "origin-rsa")
            self.assertIn("csr", req["body"])

    def test_is_not_retried_on_transient_failure(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/certificates", 503, {"error": "unavailable"})
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.create_origin_cert(["a.example.com"], "csr-pem")

            self.assertEqual(len(server.requests), 1)

    def test_403_gives_a_hint_naming_the_ssl_edit_permission(self) -> None:
        with FakeServer() as server:
            server.script(
                "POST",
                "/certificates",
                403,
                _envelope(None, success=False, errors=[{"code": 9109, "message": "Unauthorized"}]),
            )
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(StackError) as ctx:
                client.create_origin_cert(["a.example.com"], "csr-pem")

            self.assertIn("SSL and Certificates", ctx.exception.hint)
            self.assertIn("Edit", ctx.exception.hint)


class ApiSuccessFalseTests(unittest.TestCase):
    def test_success_false_raises_api_error_carrying_cloudflare_message(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/ips",
                200,
                _envelope(None, success=False, errors=[{"code": 1000, "message": "Invalid API token"}]),
            )
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(ApiError) as ctx:
                client.ip_ranges()

            self.assertIn("Invalid API token", str(ctx.exception))

    def test_success_false_with_no_errors_still_raises_with_a_message(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/ips", 200, _envelope(None, success=False, errors=[]))
            client = CloudflareClient("tok", base_url=server.url)

            with self.assertRaises(ApiError):
                client.ip_ranges()


if __name__ == "__main__":
    unittest.main()
