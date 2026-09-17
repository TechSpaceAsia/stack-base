"""Tests for stackbase.hostinger.HostingerClient, against tests.fakes.FakeServer."""

from __future__ import annotations

import unittest
from unittest import mock

from stackbase.errors import StackError
from stackbase.hostinger import HostingerClient
from stackbase.http import ApiError
from tests.fakes import FakeServer


def _vm(vps_id: int, *, state: str = "running", actions_lock: str = "unlocked") -> dict:
    return {
        "id": vps_id,
        "state": state,
        "actions_lock": actions_lock,
        "hostname": f"srv{vps_id}.hstgr.cloud",
        "ipv4": [{"id": 1, "address": "1.2.3.4"}],
        "ipv6": [{"id": 2, "address": "::1"}],
        "template": None,
        "data_center_id": None,
    }


class HeadersTests(unittest.TestCase):
    """L1: every request the Hostinger client makes must carry the explicit
    User-Agent/Accept headers `stackbase.http.request` sets -- Hostinger's
    API sits behind Cloudflare, which 403s urllib's default User-Agent.
    """

    def test_list_vms_request_carries_user_agent_and_accept(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/virtual-machines", 200, [])
            client = HostingerClient("tok", base_url=server.url)

            client.list_vms()

            headers = server.requests[0]["headers"]
            self.assertTrue(headers["user-agent"].startswith("stack-base/"))
            self.assertEqual(headers["accept"], "application/json")


class ListAndGetVmTests(unittest.TestCase):
    def test_list_vms_returns_the_bare_array(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/virtual-machines", 200, [_vm(1), _vm(2)])
            client = HostingerClient("tok", base_url=server.url)

            result = client.list_vms()

            self.assertEqual([vm["id"] for vm in result], [1, 2])
            self.assertEqual(server.requests[0]["path"], "/api/vps/v1/virtual-machines")

    def test_get_vm_hits_the_detail_endpoint(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/virtual-machines/123", 200, _vm(123, state="initial", actions_lock="unlocked"))
            client = HostingerClient("tok", base_url=server.url)

            result = client.get_vm(123)

            self.assertEqual(result["id"], 123)
            self.assertEqual(result["state"], "initial")
            self.assertEqual(server.requests[0]["path"], "/api/vps/v1/virtual-machines/123")


class DataCenterIdTests(unittest.TestCase):
    _DATA_CENTERS = [
        {"id": 21, "name": "kul", "location": "my", "city": "Kuala Lumpur"},
        {"id": 29, "name": "phx", "location": "us", "city": "Phoenix"},
    ]

    def test_matches_case_insensitively(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/data-centers", 200, self._DATA_CENTERS)
            client = HostingerClient("tok", base_url=server.url)

            self.assertEqual(client.data_center_id("KUL"), 21)

    def test_unknown_name_raises_with_valid_names_in_hint(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/data-centers", 200, self._DATA_CENTERS)
            client = HostingerClient("tok", base_url=server.url)

            with self.assertRaises(StackError) as ctx:
                client.data_center_id("nowhere")

            self.assertIn("kul", ctx.exception.hint)
            self.assertIn("phx", ctx.exception.hint)


class TemplateIdTests(unittest.TestCase):
    def test_picks_highest_plain_os_version_numerically(self) -> None:
        templates = [
            {"id": 1225, "name": "NixOS 25.11"},
            {"id": 1226, "name": "NixOS 26.05"},
            {"id": 999, "name": "NixOS 25.11 with Docker"},  # not a plain OS template -- excluded
            {"id": 5, "name": "Ubuntu 20.04"},  # different prefix -- excluded
        ]
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/templates", 200, templates)
            client = HostingerClient("tok", base_url=server.url)

            self.assertEqual(client.template_id("NixOS"), 1226)

    def test_compares_versions_numerically_not_lexically(self) -> None:
        # Lexical comparison would put "9.0" ahead of "10.0" ("1" < "9").
        templates = [
            {"id": 1, "name": "NixOS 9.0"},
            {"id": 2, "name": "NixOS 10.0"},
        ]
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/templates", 200, templates)
            client = HostingerClient("tok", base_url=server.url)

            self.assertEqual(client.template_id("NixOS"), 2)

    def test_no_match_raises_stack_error(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/templates", 200, [{"id": 5, "name": "Ubuntu 20.04"}])
            client = HostingerClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.template_id("NixOS")


class EnsurePublicKeyTests(unittest.TestCase):
    def test_idempotent_returns_existing_id_without_creating(self) -> None:
        existing = {"id": 42, "name": "matt", "key": "ssh-ed25519 AAAA matt@laptop"}
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/public-keys?page=1",
                200,
                {"data": [existing], "meta": {"current_page": 1, "per_page": 15, "total": 1}},
            )
            client = HostingerClient("tok", base_url=server.url)

            result = client.ensure_public_key("matt", "ssh-ed25519 AAAA matt@laptop")

            self.assertEqual(result, 42)
            post_requests = [r for r in server.requests if r["method"] == "POST"]
            self.assertEqual(post_requests, [], "must not create a key that already exists")

    def test_walks_pagination_to_find_a_match(self) -> None:
        page1 = {"id": 1, "name": "other", "key": "ssh-ed25519 AAAA other@laptop"}
        page2 = {"id": 2, "name": "matt", "key": "ssh-ed25519 AAAA matt@laptop"}
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/public-keys?page=1",
                200,
                {"data": [page1], "meta": {"current_page": 1, "per_page": 1, "total": 2}},
            )
            server.script(
                "GET",
                "/api/vps/v1/public-keys?page=2",
                200,
                {"data": [page2], "meta": {"current_page": 2, "per_page": 1, "total": 2}},
            )
            client = HostingerClient("tok", base_url=server.url)

            result = client.ensure_public_key("matt", "ssh-ed25519 AAAA matt@laptop")

            self.assertEqual(result, 2)

    def test_creates_when_absent(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/public-keys?page=1",
                200,
                {"data": [], "meta": {"current_page": 1, "per_page": 15, "total": 0}},
            )
            server.script(
                "POST",
                "/api/vps/v1/public-keys",
                200,
                {"id": 99, "name": "matt", "key": "ssh-ed25519 AAAA matt@laptop"},
            )
            client = HostingerClient("tok", base_url=server.url)

            result = client.ensure_public_key("matt", "ssh-ed25519 AAAA matt@laptop")

            self.assertEqual(result, 99)
            created = server.requests[-1]
            self.assertEqual(created["method"], "POST")
            self.assertEqual(created["path"], "/api/vps/v1/public-keys")
            self.assertEqual(created["body"], {"name": "matt", "key": "ssh-ed25519 AAAA matt@laptop"})


_KEY = ("matt", "ssh-ed25519 AAAA matt@laptop")


class ListPaginatedTests(unittest.TestCase):
    def test_a_non_positive_per_page_stops_rather_than_looping_forever(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/public-keys?page=1",
                200,
                # per_page=0 would make current_page * per_page never reach
                # total -- without a guard this loops forever.
                {"data": [{"id": 1, "name": "a", "key": "k"}], "meta": {"current_page": 1, "per_page": 0, "total": 5}},
            )
            client = HostingerClient("tok", base_url=server.url)

            result = client.list_public_keys()

            self.assertEqual(len(result), 1)
            self.assertEqual(len(server.requests), 1, "must not request a second page")


class SetupVmTests(unittest.TestCase):
    def test_sends_inline_public_key_and_attaches_extras_then_returns_no_warnings(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines/7/setup", 200, _vm(7, state="initial"))
            server.script("POST", "/api/vps/v1/public-keys/attach/7", 200, {"id": 1, "name": "attach", "state": "success"})
            client = HostingerClient("tok", base_url=server.url)

            warnings = client.setup_vm(
                7,
                template_id=1226,
                data_center_id=21,
                hostname="a.acme.example.com",
                public_key=_KEY,
                public_key_ids=[42],
            )

            self.assertEqual(warnings, [])
            setup_req, attach_req = server.requests
            self.assertEqual(setup_req["path"], "/api/vps/v1/virtual-machines/7/setup")
            self.assertEqual(setup_req["body"]["template_id"], 1226)
            self.assertEqual(setup_req["body"]["data_center_id"], 21)
            self.assertEqual(setup_req["body"]["hostname"], "a.acme.example.com")
            self.assertEqual(setup_req["body"]["public_key"], {"name": "matt", "key": "ssh-ed25519 AAAA matt@laptop"})
            password = setup_req["body"]["password"]
            self.assertEqual(len(password), 32)
            self.assertEqual(attach_req["path"], "/api/vps/v1/public-keys/attach/7")
            self.assertEqual(attach_req["body"], {"ids": [42]})

    def test_password_is_random_each_call(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines/1/setup", 200, _vm(1))
            server.script("POST", "/api/vps/v1/virtual-machines/2/setup", 200, _vm(2))
            client = HostingerClient("tok", base_url=server.url)

            client.setup_vm(1, template_id=1, data_center_id=1, hostname="a", public_key=_KEY)
            client.setup_vm(2, template_id=1, data_center_id=1, hostname="b", public_key=_KEY)

            passwords = [r["body"]["password"] for r in server.requests]
            self.assertNotEqual(passwords[0], passwords[1])

    def test_no_key_attach_call_when_public_key_ids_omitted(self) -> None:
        # public_key_ids defaults to () -- omitting it must not attempt an attach.
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines/7/setup", 200, _vm(7))
            client = HostingerClient("tok", base_url=server.url)

            warnings = client.setup_vm(7, template_id=1, data_center_id=1, hostname="a", public_key=_KEY)

            self.assertEqual(warnings, [])
            self.assertEqual(len(server.requests), 1)

    def test_no_key_attach_call_when_public_key_ids_empty(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines/7/setup", 200, _vm(7))
            client = HostingerClient("tok", base_url=server.url)

            warnings = client.setup_vm(7, template_id=1, data_center_id=1, hostname="a", public_key=_KEY, public_key_ids=[])

            self.assertEqual(warnings, [])
            self.assertEqual(len(server.requests), 1)

    def test_setup_failure_is_not_retried(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines/7/setup", 503, {"error": "unavailable"})
            client = HostingerClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.setup_vm(7, template_id=1, data_center_id=1, hostname="a", public_key=_KEY)

            # retries=1: exactly one attempt, no retry despite a retryable status.
            self.assertEqual(len(server.requests), 1)

    def test_extra_key_attach_failure_is_a_warning_not_a_raise(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines/7/setup", 200, _vm(7, state="initial"))
            server.script("POST", "/api/vps/v1/public-keys/attach/7", 422, {"message": "invalid key id"})
            client = HostingerClient("tok", base_url=server.url)

            # Must not raise -- setup itself succeeded via the required inline public_key.
            warnings = client.setup_vm(
                7,
                template_id=1,
                data_center_id=1,
                hostname="a",
                public_key=_KEY,
                public_key_ids=[999],
            )

            self.assertEqual(len(warnings), 1)
            self.assertIn("7", warnings[0])
            # Exactly the setup call plus the one (failed, not retried) attach call.
            self.assertEqual(len(server.requests), 2)


class PurchaseVmTests(unittest.TestCase):
    def test_sends_inline_public_key_in_nested_setup_body_and_returns_vps_id_and_no_warnings(self) -> None:
        order_response = {
            "order": {"id": "order-1"},
            "virtual_machine": _vm(555, state="initial"),
        }
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines", 200, order_response)
            server.script("POST", "/api/vps/v1/public-keys/attach/555", 200, {"id": 1, "name": "attach", "state": "success"})
            client = HostingerClient("tok", base_url=server.url)

            vps_id, warnings = client.purchase_vm(
                price_item="hostingercom-vps-kvm2-usd-1m",
                template_id=1226,
                data_center_id=21,
                hostname="a.acme.example.com",
                public_key=_KEY,
                public_key_ids=[42],
            )

            self.assertEqual(vps_id, 555)
            self.assertEqual(warnings, [])
            purchase_req = server.requests[0]
            self.assertEqual(purchase_req["path"], "/api/vps/v1/virtual-machines")
            self.assertEqual(purchase_req["body"]["item_id"], "hostingercom-vps-kvm2-usd-1m")
            self.assertEqual(purchase_req["body"]["setup"]["template_id"], 1226)
            self.assertEqual(purchase_req["body"]["setup"]["data_center_id"], 21)
            self.assertEqual(purchase_req["body"]["setup"]["hostname"], "a.acme.example.com")
            self.assertEqual(
                purchase_req["body"]["setup"]["public_key"],
                {"name": "matt", "key": "ssh-ed25519 AAAA matt@laptop"},
            )
            self.assertEqual(len(purchase_req["body"]["setup"]["password"]), 32)
            self.assertEqual(server.requests[1]["path"], "/api/vps/v1/public-keys/attach/555")

    def test_no_attach_call_when_public_key_ids_omitted(self) -> None:
        order_response = {"order": {"id": "order-1"}, "virtual_machine": _vm(555, state="initial")}
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines", 200, order_response)
            client = HostingerClient("tok", base_url=server.url)

            vps_id, warnings = client.purchase_vm(
                price_item="x", template_id=1, data_center_id=1, hostname="a", public_key=_KEY
            )

            self.assertEqual(vps_id, 555)
            self.assertEqual(warnings, [])
            self.assertEqual(len(server.requests), 1)

    def test_payment_processing_response_raises_without_double_purchasing(self) -> None:
        # HTTP 202: payment still processing, no virtual_machine in the body.
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines", 202, {"order": {"id": "order-1"}})
            client = HostingerClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.purchase_vm(
                    price_item="hostingercom-vps-kvm2-usd-1m",
                    template_id=1,
                    data_center_id=1,
                    hostname="a",
                    public_key=_KEY,
                    public_key_ids=[42],
                )

            # Exactly the one purchase request -- no retry, no attach attempt.
            self.assertEqual(len(server.requests), 1)

    def test_a_network_level_failure_warns_the_purchase_may_have_gone_through(self) -> None:
        network_error = ApiError(
            "POST https://developers.hostinger.com/api/vps/v1/virtual-machines failed: timed out",
            "check network connectivity and that the host is reachable",
            status=0,
            body="",
        )
        client = HostingerClient("tok", base_url="http://127.0.0.1:0")

        with mock.patch("stackbase.hostinger.request", side_effect=network_error):
            with self.assertRaises(StackError) as ctx:
                client.purchase_vm(
                    price_item="x", template_id=1, data_center_id=1, hostname="a", public_key=_KEY
                )

        message = str(ctx.exception).lower()
        self.assertIn("hpanel", message)
        self.assertIn("do not retry", message)
        self.assertIn("may have gone through", message)

    def test_purchase_failure_is_not_retried(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines", 503, {"error": "unavailable"})
            client = HostingerClient("tok", base_url=server.url)

            with self.assertRaises(StackError):
                client.purchase_vm(
                    price_item="x", template_id=1, data_center_id=1, hostname="a", public_key=_KEY
                )

            self.assertEqual(len(server.requests), 1)

    def test_extra_key_attach_failure_after_purchase_is_a_warning_not_a_raise(self) -> None:
        order_response = {"order": {"id": "order-1"}, "virtual_machine": _vm(555, state="initial")}
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/virtual-machines", 200, order_response)
            server.script("POST", "/api/vps/v1/public-keys/attach/555", 422, {"message": "invalid key id"})
            client = HostingerClient("tok", base_url=server.url)

            # Must not raise, and the new vps id must still come back -- the purchase
            # already succeeded and must not be thrown away over an optional extra.
            vps_id, warnings = client.purchase_vm(
                price_item="x",
                template_id=1,
                data_center_id=1,
                hostname="a",
                public_key=_KEY,
                public_key_ids=[999],
            )

            self.assertEqual(vps_id, 555)
            self.assertEqual(len(warnings), 1)
            self.assertIn("555", warnings[0])
            self.assertEqual(len(server.requests), 2)


class WaitRunningTests(unittest.TestCase):
    def test_returns_once_running_and_unlocked(self) -> None:
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/virtual-machines/9", 200, _vm(9, state="creating", actions_lock="locked"))
            server.script("GET", "/api/vps/v1/virtual-machines/9", 200, _vm(9, state="running", actions_lock="unlocked"))
            client = HostingerClient("tok", base_url=server.url)
            sleeps: list[float] = []

            result = client.wait_running(9, timeout=100, poll=5, sleep=sleeps.append)

            self.assertEqual(result["state"], "running")
            self.assertEqual(sleeps, [5])
            self.assertEqual(len(server.requests), 2)

    def test_times_out_with_a_hint_naming_hpanel(self) -> None:
        with FakeServer() as server:
            for _ in range(3):
                server.script("GET", "/api/vps/v1/virtual-machines/9", 200, _vm(9, state="creating", actions_lock="locked"))
            client = HostingerClient("tok", base_url=server.url)
            sleeps: list[float] = []

            with self.assertRaises(StackError) as ctx:
                client.wait_running(9, timeout=20, poll=10, sleep=sleeps.append)

            self.assertIn("hPanel", ctx.exception.hint)
            self.assertEqual(sleeps, [10, 10])
            self.assertEqual(len(server.requests), 3)


class EnsureFirewallTests(unittest.TestCase):
    def _rule(self, rule_id: int, protocol: str, port: str, source: str = "any", source_detail: str = "any") -> dict:
        return {"id": rule_id, "protocol": protocol, "port": port, "source": source, "source_detail": source_detail}

    def test_no_op_when_current_rules_already_match(self) -> None:
        firewall = {
            "id": 1,
            "name": "web",
            "rules": [self._rule(10, "TCP", "443", "any", "any")],
        }
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/firewall?page=1",
                200,
                {"data": [firewall], "meta": {"current_page": 1, "per_page": 15, "total": 1}},
            )
            client = HostingerClient("tok", base_url=server.url)

            result = client.ensure_firewall("web", [{"protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"}])

            self.assertEqual(result, 1)
            mutations = [r for r in server.requests if r["method"] in ("POST", "PUT", "DELETE") and "rules" in r["path"]]
            self.assertEqual(mutations, [], "already-converged firewall must not issue any rule writes")

    def test_adds_missing_and_removes_stale_rules(self) -> None:
        firewall = {
            "id": 1,
            "name": "web",
            "rules": [self._rule(10, "TCP", "22", "any", "any")],  # stale: not in desired
        }
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/firewall?page=1",
                200,
                {"data": [firewall], "meta": {"current_page": 1, "per_page": 15, "total": 1}},
            )
            server.script(
                "POST",
                "/api/vps/v1/firewall/1/rules",
                200,
                self._rule(11, "TCP", "443", "any", "any"),
            )
            server.script("DELETE", "/api/vps/v1/firewall/1/rules/10", 200, {"success": True})
            client = HostingerClient("tok", base_url=server.url)

            result = client.ensure_firewall("web", [{"protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"}])

            self.assertEqual(result, 1)
            methods_and_paths = {(r["method"], r["path"]) for r in server.requests}
            self.assertIn(("POST", "/api/vps/v1/firewall/1/rules"), methods_and_paths)
            self.assertIn(("DELETE", "/api/vps/v1/firewall/1/rules/10"), methods_and_paths)

    def test_distinguishes_rules_by_source_detail_not_just_source(self) -> None:
        # Two "custom" rules on the same protocol/port but different source_detail
        # (e.g. two distinct admin IPs) must both be kept -- collapsing on
        # (protocol, port, source) alone would treat them as the same rule.
        firewall = {
            "id": 1,
            "name": "ssh",
            "rules": [
                self._rule(1, "SSH", "22", "custom", "1.1.1.1/32"),
                self._rule(2, "SSH", "22", "custom", "2.2.2.2/32"),
            ],
        }
        desired = [
            {"protocol": "SSH", "port": "22", "source": "custom", "source_detail": "1.1.1.1/32"},
            {"protocol": "SSH", "port": "22", "source": "custom", "source_detail": "2.2.2.2/32"},
        ]
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/firewall?page=1",
                200,
                {"data": [firewall], "meta": {"current_page": 1, "per_page": 15, "total": 1}},
            )
            client = HostingerClient("tok", base_url=server.url)

            client.ensure_firewall("ssh", desired)

            mutations = [r for r in server.requests if r["method"] in ("POST", "DELETE") and "rules" in r["path"]]
            self.assertEqual(mutations, [], "both distinct-by-source_detail rules already exist -- no-op expected")

    def test_creates_firewall_when_absent_then_adds_all_rules(self) -> None:
        with FakeServer() as server:
            server.script(
                "GET",
                "/api/vps/v1/firewall?page=1",
                200,
                {"data": [], "meta": {"current_page": 1, "per_page": 15, "total": 0}},
            )
            server.script(
                "POST",
                "/api/vps/v1/firewall",
                200,
                {"id": 5, "name": "web", "rules": []},
            )
            server.script(
                "POST",
                "/api/vps/v1/firewall/5/rules",
                200,
                self._rule(1, "TCP", "443", "any", "any"),
            )
            client = HostingerClient("tok", base_url=server.url)

            result = client.ensure_firewall("web", [{"protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"}])

            self.assertEqual(result, 5)
            created = server.requests[1]
            self.assertEqual(created["method"], "POST")
            self.assertEqual(created["path"], "/api/vps/v1/firewall")
            self.assertEqual(created["body"], {"name": "web"})
            self.assertEqual(server.requests[2]["path"], "/api/vps/v1/firewall/5/rules")


class ActivateFirewallTests(unittest.TestCase):
    def test_hits_the_activate_endpoint(self) -> None:
        with FakeServer() as server:
            server.script("POST", "/api/vps/v1/firewall/5/activate/9", 200, {"id": 1, "name": "activate", "state": "success"})
            client = HostingerClient("tok", base_url=server.url)

            result = client.activate_firewall(5, 9)

            self.assertIsNone(result)
            self.assertEqual(server.requests[0]["path"], "/api/vps/v1/firewall/5/activate/9")
            self.assertEqual(server.requests[0]["method"], "POST")


if __name__ == "__main__":
    unittest.main()
