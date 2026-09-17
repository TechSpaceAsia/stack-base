"""Tests for stackbase.reconcile / stackbase.steps: observe -> plan -> apply.

`plan()` is pure, so most of the ordering/convergence cases here are plain
data-in/data-out assertions with no fakes at all. `observe()` and `apply()`
run against `tests.fakes.FakeServer` (both REST APIs) and
`tests.fakes.FakeRunner`/`FakePopen` (ssh, rsync, ssh-keyscan, openssl,
nixos-rebuild). Nothing in this file touches a real API, a real server or a
real token.
"""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

from stackbase.cloudflare import CloudflareClient
from stackbase.config import CloudflareState, HostingerState, Node, NodeState, StackConfig, StackState
from stackbase.errors import StackError
from stackbase.hostinger import HostingerClient
from stackbase.reconcile import (
    Action,
    Context,
    Local,
    Observed,
    ObservedNode,
    Step,
    apply,
    compute_rev,
    firewall_name,
    hostname_for,
    local_facts,
    observe,
    plan,
)
from tests.fakes import FakePopen, FakeRunner, FakeServer

_DOMAIN = "acme.example.com"
_IPV4 = "1.2.3.4"
_IPV6 = "2001:db8::1"
_VPS_ID = 1984476
_REV = "rev-one"
_KEY_MATT = "ssh-ed25519 AAAAmattkeybody matt@laptop"
_KEY_KIM = "ssh-ed25519 AAAAkimkeybody kim@laptop"
_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIcert\n-----END CERTIFICATE-----\n"
_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIkey\n-----END PRIVATE KEY-----\n"

_FULL_SEQUENCE = [
    Action.ENSURE_KEYS,
    Action.SETUP,
    Action.WAIT_RUNNING,
    Action.ENSURE_FIREWALL,
    Action.PIN_HOST_KEY,
    Action.CAPTURE_HARDWARE,
    Action.ENSURE_ORIGIN_CERT,
    Action.PUSH_CONFIG,
    Action.REBUILD,
    Action.UPSERT_DNS,
]


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _config(*, nodes=None, admins=("matt", "kim"), price_item="kvm1-price-item") -> StackConfig:
    keys = {"matt": _KEY_MATT, "kim": _KEY_KIM}
    return StackConfig(
        project="acme",
        domain=_DOMAIN,
        owner="matt",
        datacenter="kul",
        plan="KVM 1",
        price_item=price_item,
        auto_patch=True,
        admins=list(admins),
        nodes=nodes if nodes is not None else {"a": Node(name="a", role="primary", vps_id=_VPS_ID)},
        admin_keys={admin: keys[admin] for admin in admins},
    )


def _local(
    *,
    rev: str = _REV,
    has_origin_cert: bool = False,
    pinned: tuple[str, ...] = (),
    captured: tuple[str, ...] = (),
) -> Local:
    return Local(
        desired_rev=rev,
        has_origin_cert=has_origin_cert,
        pinned_hosts=frozenset(pinned),
        captured_nodes=frozenset(captured),
    )


def _observed_fresh(local: Local | None = None) -> Observed:
    """What observe() sees for a bought-but-uninitialised node: nothing else exists yet."""
    return Observed(
        local=local or _local(),
        nodes={"a": ObservedNode(vps_id=_VPS_ID, state="initial", actions_lock="unlocked")},
        public_key_ids={},
        zone_id="zone1",
        zone_name="example.com",
    )


def _converged_state(*, rev: str = _REV, nodes=("a",)) -> StackState:
    return StackState(
        nodes={
            name: NodeState(
                vps_id=_VPS_ID,
                ipv4=_IPV4,
                ipv6=_IPV6,
                host_key_pinned=True,
                hardware_captured=True,
                applied_rev=rev,
            )
            for name in nodes
        },
        cloudflare=CloudflareState(zone_id="zone1", record_id="rec1"),
        hostinger=HostingerState(firewall_id=7, ssh_key_ids={"matt": 11, "kim": 12}),
    )


def _converged_observed(*, rev: str = _REV, nodes=("a",)) -> Observed:
    return Observed(
        local=_local(rev=rev, has_origin_cert=True, pinned=(_IPV4,), captured=nodes),
        nodes={
            name: ObservedNode(
                vps_id=_VPS_ID,
                state="running",
                actions_lock="unlocked",
                ipv4=_IPV4,
                ipv6=_IPV6,
                firewall_group_id=7,
            )
            for name in nodes
        },
        public_key_ids={"matt": 11, "kim": 12},
        firewall_id=7,
        firewall_rules_match=True,
        zone_id="zone1",
        zone_name="example.com",
        record_id="rec1",
        record_matches=True,
    )


# --------------------------------------------------------------------------
# plan() -- pure
# --------------------------------------------------------------------------


class PlanTests(unittest.TestCase):
    def test_fresh_node_with_vps_id_plans_the_whole_sequence(self) -> None:
        steps = plan(_config(), StackState(), _observed_fresh())

        self.assertEqual([step.action for step in steps], _FULL_SEQUENCE)
        self.assertTrue(all(step.node == "a" for step in steps if step.action not in
                            (Action.ENSURE_KEYS, Action.ENSURE_ORIGIN_CERT)))

    def test_converged_stack_plans_nothing(self) -> None:
        steps = plan(_config(), _converged_state(), _converged_observed())

        self.assertEqual(steps, [])

    def test_node_without_vps_id_plans_a_purchase_instead_of_setup(self) -> None:
        cfg = _config(nodes={"a": Node(name="a", role="primary", vps_id=None)})
        observed = Observed(local=_local(), nodes={"a": ObservedNode()}, public_key_ids={}, zone_id="zone1")

        actions = [step.action for step in plan(cfg, StackState(), observed)]

        self.assertIn(Action.PURCHASE, actions)
        self.assertNotIn(Action.SETUP, actions)
        self.assertEqual(actions, [Action.PURCHASE if a is Action.SETUP else a for a in _FULL_SEQUENCE])

    def test_all_nodes_are_provisioned_before_dns_and_dns_targets_the_primary(self) -> None:
        cfg = _config(
            nodes={
                "a": Node(name="a", role="primary", vps_id=_VPS_ID),
                "b": Node(name="b", role="replica", vps_id=_VPS_ID + 1),
            }
        )
        observed = Observed(
            local=_local(),
            nodes={
                "a": ObservedNode(vps_id=_VPS_ID, state="initial", actions_lock="unlocked"),
                "b": ObservedNode(vps_id=_VPS_ID + 1, state="initial", actions_lock="unlocked"),
            },
            public_key_ids={},
            zone_id="zone1",
        )

        steps = plan(cfg, StackState(), observed)
        actions = [step.action for step in steps]

        self.assertIs(actions[-1], Action.UPSERT_DNS)
        self.assertEqual(steps[-1].node, "a")
        # Every provisioning step for node b precedes the first deploy step.
        first_push = actions.index(Action.PUSH_CONFIG)
        b_provisioning = [i for i, step in enumerate(steps) if step.node == "b" and step.action is Action.CAPTURE_HARDWARE]
        self.assertTrue(b_provisioning and b_provisioning[0] < first_push)

    def test_origin_cert_is_planned_once_for_the_whole_stack(self) -> None:
        cfg = _config(
            nodes={
                "a": Node(name="a", role="primary", vps_id=_VPS_ID),
                "b": Node(name="b", role="replica", vps_id=_VPS_ID + 1),
            }
        )
        observed = Observed(
            local=_local(),
            nodes={
                "a": ObservedNode(vps_id=_VPS_ID, state="running", actions_lock="unlocked", ipv4=_IPV4),
                "b": ObservedNode(vps_id=_VPS_ID + 1, state="running", actions_lock="unlocked", ipv4=_IPV4),
            },
            public_key_ids={},
            zone_id="zone1",
        )

        actions = [step.action for step in plan(cfg, StackState(), observed)]

        self.assertEqual(actions.count(Action.ENSURE_ORIGIN_CERT), 1)
        self.assertEqual(actions.count(Action.PUSH_CONFIG), 2)

    def test_unchanged_applied_rev_skips_push_and_rebuild(self) -> None:
        actions = [step.action for step in plan(_config(), _converged_state(), _converged_observed())]

        self.assertNotIn(Action.PUSH_CONFIG, actions)
        self.assertNotIn(Action.REBUILD, actions)

    def test_changed_applied_rev_replans_push_and_rebuild_only(self) -> None:
        state = _converged_state(rev="old-rev")

        actions = [step.action for step in plan(_config(), state, _converged_observed())]

        self.assertEqual(actions, [Action.PUSH_CONFIG, Action.REBUILD])

    def test_drifted_dns_record_replans_only_the_dns_step(self) -> None:
        observed = replace(_converged_observed(), record_matches=False)

        actions = [step.action for step in plan(_config(), _converged_state(), observed)]

        self.assertEqual(actions, [Action.UPSERT_DNS])

    def test_firewall_detached_from_a_node_replans_only_the_firewall_step(self) -> None:
        observed = _converged_observed()
        detached = {"a": replace(observed.nodes["a"], firewall_group_id=None)}
        observed = replace(observed, nodes=detached)

        actions = [step.action for step in plan(_config(), _converged_state(), observed)]

        self.assertEqual(actions, [Action.ENSURE_FIREWALL])

    def test_missing_hardware_file_replans_capture_even_when_state_says_captured(self) -> None:
        observed = replace(
            _converged_observed(),
            local=_local(has_origin_cert=True, pinned=(_IPV4,), captured=()),
        )

        actions = [step.action for step in plan(_config(), _converged_state(), observed)]

        self.assertEqual(actions, [Action.CAPTURE_HARDWARE])

    def test_steps_describe_themselves_in_plain_english(self) -> None:
        steps = plan(_config(), StackState(), _observed_fresh())

        for step in steps:
            self.assertTrue(step.description)
            self.assertNotIn("_", step.description, f"{step.action} leaks an identifier into its description")
        self.assertIn("node a", next(s for s in steps if s.action is Action.REBUILD).description)

    def test_plan_does_not_mutate_the_state_it_is_given(self) -> None:
        state = StackState()
        plan(_config(), state, _observed_fresh())

        self.assertEqual(state, StackState())


# --------------------------------------------------------------------------
# observe() -- GET only
# --------------------------------------------------------------------------


def _vm_body(*, state: str = "running", firewall_group_id=None) -> dict:
    return {
        "id": _VPS_ID,
        "state": state,
        "actions_lock": "unlocked",
        "firewall_group_id": firewall_group_id,
        "ipv4": [{"id": 1, "address": _IPV4}],
        "ipv6": [{"id": 2, "address": _IPV6}],
    }


def _cf(result, *, result_info=None) -> dict:
    body = {"success": True, "errors": [], "result": result}
    if result_info is not None:
        body["result_info"] = result_info
    return body


def _page(total_pages: int = 1) -> dict:
    return {"page": 1, "per_page": 20, "count": 1, "total_count": 1, "total_pages": total_pages}


def _script_observe(server: FakeServer, *, vm=None, keys=(), firewalls=(), records=()) -> None:
    server.script("GET", f"/api/vps/v1/virtual-machines/{_VPS_ID}", 200, vm or _vm_body())
    server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": list(keys), "meta": _meta(len(keys))})
    server.script("GET", "/api/vps/v1/firewall?page=1", 200, {"data": list(firewalls), "meta": _meta(len(firewalls))})
    server.script("GET", f"/zones?name={_DOMAIN}&page=1", 200, _cf([{"id": "zone1", "name": _DOMAIN}], result_info=_page()))
    server.script(
        "GET",
        f"/zones/zone1/dns_records?type=A&name={_DOMAIN}&page=1",
        200,
        _cf(list(records), result_info=_page()),
    )


def _meta(total: int) -> dict:
    return {"current_page": 1, "per_page": 20, "total": total}


class ObserveTests(unittest.TestCase):
    def test_observe_issues_only_get_requests(self) -> None:
        with FakeServer() as server:
            _script_observe(server)
            hostinger = HostingerClient("htok", base_url=server.url)
            cloudflare = CloudflareClient("ctok", base_url=server.url)

            observe(_config(), StackState(), hostinger, cloudflare, local=_local())

            methods = {request["method"] for request in server.requests}
            self.assertEqual(methods, {"GET"}, f"observe() must be read-only, saw {methods}")

    def test_observe_reads_addresses_firewall_keys_and_dns(self) -> None:
        firewall = {
            "id": 7,
            "name": firewall_name(_config()),
            "rules": [
                {"id": 1, "protocol": "TCP", "port": "22", "source": "any", "source_detail": "any"},
                {"id": 2, "protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"},
            ],
        }
        with FakeServer() as server:
            _script_observe(
                server,
                vm=_vm_body(firewall_group_id=7),
                keys=[{"id": 11, "name": "matt", "key": _KEY_MATT}],
                firewalls=[firewall],
                records=[{"id": "rec1", "type": "A", "name": _DOMAIN, "content": _IPV4, "proxied": True}],
            )
            hostinger = HostingerClient("htok", base_url=server.url)
            cloudflare = CloudflareClient("ctok", base_url=server.url)

            observed = observe(_config(), StackState(), hostinger, cloudflare, local=_local())

            self.assertEqual(observed.nodes["a"].ipv4, _IPV4)
            self.assertEqual(observed.nodes["a"].ipv6, _IPV6)
            self.assertEqual(observed.nodes["a"].firewall_group_id, 7)
            self.assertEqual(observed.public_key_ids, {"matt": 11})
            self.assertEqual(observed.firewall_id, 7)
            self.assertTrue(observed.firewall_rules_match)
            self.assertEqual(observed.zone_id, "zone1")
            self.assertEqual(observed.record_id, "rec1")
            self.assertTrue(observed.record_matches)

    def test_observe_skips_the_vm_lookup_for_a_node_that_does_not_exist_yet(self) -> None:
        cfg = _config(nodes={"a": Node(name="a", role="primary", vps_id=None)})
        with FakeServer() as server:
            server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("GET", "/api/vps/v1/firewall?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("GET", f"/zones?name={_DOMAIN}&page=1", 200, _cf([{"id": "zone1", "name": _DOMAIN}], result_info=_page()))
            server.script("GET", f"/zones/zone1/dns_records?type=A&name={_DOMAIN}&page=1", 200, _cf([], result_info=_page()))
            hostinger = HostingerClient("htok", base_url=server.url)
            cloudflare = CloudflareClient("ctok", base_url=server.url)

            observed = observe(cfg, StackState(), hostinger, cloudflare, local=_local())

            self.assertIsNone(observed.nodes["a"].vps_id)
            self.assertNotIn(
                f"/api/vps/v1/virtual-machines/{_VPS_ID}",
                [request["path"] for request in server.requests],
            )


# --------------------------------------------------------------------------
# apply() -- against fakes
# --------------------------------------------------------------------------


class Infra:
    """A scratch infra/ directory with the files a real project would have."""

    def __enter__(self) -> Path:
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name)
        (self.path / "keys").mkdir()
        (self.path / "keys" / "matt.pub").write_text(_KEY_MATT + "\n", encoding="utf-8")
        (self.path / "keys" / "kim.pub").write_text(_KEY_KIM + "\n", encoding="utf-8")
        (self.path / "stack.toml").write_text("project = \"acme\"\n", encoding="utf-8")
        (self.path / "flake.nix").write_text("{ }\n", encoding="utf-8")
        (self.path / "flake.lock").write_text(json.dumps(_LOCK), encoding="utf-8")
        (self.path / "secrets.age").write_text("age-ciphertext", encoding="utf-8")
        return self.path

    def __exit__(self, *exc_info: object) -> None:
        self._tmp.cleanup()


_LOCK = {
    "nodes": {
        "root": {"inputs": {"stack-base": "stack-base"}},
        "stack-base": {
            "locked": {"type": "github", "owner": "matiboy", "repo": "stack-base", "rev": "deadbeef" * 5},
            "original": {"type": "github", "owner": "matiboy", "repo": "stack-base"},
        },
    },
    "root": "root",
    "version": 7,
}


def _cp(argv, *, returncode=0, stdout="", stderr="") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


class FakeConnector:
    """Stands in for socket.create_connection: records addresses, never connects."""

    def __init__(self, *, refuse_first: int = 0) -> None:
        self.addresses: list[tuple] = []
        self._refusals = refuse_first

    def __call__(self, address, timeout=None):
        self.addresses.append(address)
        if self._refusals > 0:
            self._refusals -= 1
            raise OSError("connection refused")
        return _ClosedSocket()


class _ClosedSocket:
    def close(self) -> None:
        pass


def _context(
    infra_dir: Path,
    *,
    cfg: StackConfig | None = None,
    state: StackState | None = None,
    observed: Observed | None = None,
    server: FakeServer | None = None,
    runner: FakeRunner | None = None,
    popen: FakePopen | None = None,
    connector: Any = None,
    stackbase_src: str | None = None,
    isatty: bool = True,
    secrets: dict[str, str] | None = None,
) -> tuple[Context, list[str]]:
    lines: list[str] = []
    base_url = server.url if server is not None else "http://127.0.0.1:1"
    payload = secrets if secrets is not None else {"hostinger_token": "htok", "cloudflare_token": "ctok"}
    ctx = Context(
        infra_dir=infra_dir,
        cfg=cfg or _config(),
        state=state if state is not None else StackState(),
        secrets=payload,
        hostinger=HostingerClient(payload.get("hostinger_token", ""), base_url=base_url),
        cloudflare=CloudflareClient(payload.get("cloudflare_token", ""), base_url=base_url),
        observed=observed or _observed_fresh(),
        stackbase_src=stackbase_src,
        runner=runner or FakeRunner(),
        popen=popen or FakePopen(),
        connector=connector or FakeConnector(),
        out=lines.append,
        isatty=lambda: isatty,
    )
    return ctx, lines


class PurchaseGuardTests(unittest.TestCase):
    """The purchase guard is the one place stack-base can spend money."""

    def _purchase_context(self, infra_dir: Path, server: FakeServer, **kwargs):
        cfg = _config(nodes={"a": Node(name="a", role="primary", vps_id=None)})
        observed = Observed(local=_local(), nodes={"a": ObservedNode()}, public_key_ids={}, zone_id="zone1")
        return _context(infra_dir, cfg=cfg, observed=observed, server=server, **kwargs)

    def test_without_the_flag_it_refuses_and_names_the_flag(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            ctx, _ = self._purchase_context(infra_dir, server)

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.PURCHASE, "a")], ctx, allow_purchase=False)

            self.assertIn("--allow-purchase", str(caught.exception))
            self.assertEqual(server.requests, [])

    def test_with_the_flag_but_wrong_confirmation_it_refuses(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            ctx, _ = self._purchase_context(infra_dir, server)

            with self.assertRaises(StackError):
                apply([Step(Action.PURCHASE, "a")], ctx, allow_purchase=True, confirm=lambda _prompt: "yes")

            self.assertEqual(server.requests, [])

    def test_non_interactive_stdin_refuses_even_with_the_flag_and_right_text(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            ctx, _ = self._purchase_context(infra_dir, server, isatty=False)

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.PURCHASE, "a")], ctx, allow_purchase=True, confirm=lambda _p: "buy KVM 1 x1")

            self.assertIn("terminal", str(caught.exception))
            self.assertEqual(server.requests, [])

    def test_missing_price_item_refuses_before_prompting(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            cfg = _config(nodes={"a": Node(name="a", role="primary", vps_id=None)}, price_item=None)
            observed = Observed(local=_local(), nodes={"a": ObservedNode()}, public_key_ids={}, zone_id="zone1")
            ctx, _ = _context(infra_dir, cfg=cfg, observed=observed, server=server)
            prompts: list[str] = []

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.PURCHASE, "a")], ctx, allow_purchase=True,
                      confirm=lambda prompt: prompts.append(prompt) or "buy KVM 1 x1")

            self.assertIn("price_item", str(caught.exception))
            self.assertEqual(prompts, [])
            self.assertEqual(server.requests, [])

    def test_exact_confirmation_issues_exactly_one_purchase_post(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", "/api/vps/v1/templates", 200, [{"id": 1130, "name": "NixOS 26.05"}])
            server.script("GET", "/api/vps/v1/data-centers", 200, [{"id": 21, "name": "kul"}])
            server.script("POST", "/api/vps/v1/virtual-machines", 200, {"virtual_machine": {"id": 4242}})
            server.script("POST", "/api/vps/v1/public-keys/attach/4242", 200, {})
            state = StackState(hostinger=HostingerState(ssh_key_ids={"matt": 11, "kim": 12}))
            ctx, lines = self._purchase_context(infra_dir, server, state=state)
            prompts: list[str] = []

            def confirm(prompt: str) -> str:
                prompts.append(prompt)
                return "buy KVM 1 x1"

            apply([Step(Action.PURCHASE, "a")], ctx, allow_purchase=True, confirm=confirm)

            purchases = [r for r in server.requests if r["method"] == "POST" and r["path"] == "/api/vps/v1/virtual-machines"]
            self.assertEqual(len(purchases), 1)
            self.assertIn("buy KVM 1 x1", prompts[0])
            self.assertEqual(ctx.state.nodes["a"].vps_id, 4242)
            self.assertTrue(any("4242" in line for line in lines))

    def test_purchase_sends_the_first_admin_key_inline_and_the_rest_as_ids(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", "/api/vps/v1/templates", 200, [{"id": 1130, "name": "NixOS 26.05"}])
            server.script("GET", "/api/vps/v1/data-centers", 200, [{"id": 21, "name": "kul"}])
            server.script("POST", "/api/vps/v1/virtual-machines", 200, {"virtual_machine": {"id": 4242}})
            server.script("POST", "/api/vps/v1/public-keys/attach/4242", 200, {})
            state = StackState(hostinger=HostingerState(ssh_key_ids={"matt": 11, "kim": 12}))
            ctx, _ = self._purchase_context(infra_dir, server, state=state)

            apply([Step(Action.PURCHASE, "a")], ctx, allow_purchase=True, confirm=lambda _p: "buy KVM 1 x1")

            body = next(r["body"] for r in server.requests if r["path"] == "/api/vps/v1/virtual-machines")
            self.assertEqual(body["setup"]["public_key"], {"name": "matt", "key": _KEY_MATT})
            self.assertEqual(body["item_id"], "kvm1-price-item")
            self.assertEqual(body["setup"]["hostname"], hostname_for(_config(), "a"))
            attach = next(r for r in server.requests if r["path"] == "/api/vps/v1/public-keys/attach/4242")
            self.assertEqual(attach["body"], {"ids": [12]})


class ApplyStepTests(unittest.TestCase):
    def test_ensure_keys_registers_every_admin_and_records_the_ids(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("POST", "/api/vps/v1/public-keys", 200, {"id": 11})
            server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("POST", "/api/vps/v1/public-keys", 200, {"id": 12})
            ctx, _ = _context(infra_dir, server=server)

            apply([Step(Action.ENSURE_KEYS)], ctx, allow_purchase=False)

            self.assertEqual(ctx.state.hostinger.ssh_key_ids, {"matt": 11, "kim": 12})

    def test_setup_sends_the_inline_key_and_the_remaining_key_ids(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", "/api/vps/v1/templates", 200, [{"id": 1130, "name": "NixOS 26.05"}])
            server.script("GET", "/api/vps/v1/data-centers", 200, [{"id": 21, "name": "kul"}])
            server.script("POST", f"/api/vps/v1/virtual-machines/{_VPS_ID}/setup", 200, {})
            server.script("POST", f"/api/vps/v1/public-keys/attach/{_VPS_ID}", 200, {})
            state = StackState(hostinger=HostingerState(ssh_key_ids={"matt": 11, "kim": 12}))
            ctx, _ = _context(infra_dir, state=state, server=server)

            apply([Step(Action.SETUP, "a")], ctx, allow_purchase=False)

            body = next(r["body"] for r in server.requests if r["path"].endswith("/setup"))
            self.assertEqual(body["public_key"], {"name": "matt", "key": _KEY_MATT})
            self.assertEqual(body["template_id"], 1130)
            self.assertEqual(body["data_center_id"], 21)
            attach = next(r for r in server.requests if "attach" in r["path"])
            self.assertEqual(attach["body"], {"ids": [12]})

    def test_wait_running_records_both_addresses_and_waits_for_sshd(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", f"/api/vps/v1/virtual-machines/{_VPS_ID}", 200, _vm_body())
            # Hostinger reports "running" a little before sshd is listening,
            # so the first probe is refused and the step must keep waiting.
            connector = FakeConnector(refuse_first=1)
            ctx, _ = _context(infra_dir, server=server, connector=connector)

            apply([Step(Action.WAIT_RUNNING, "a")], ctx, allow_purchase=False)

            self.assertEqual(ctx.state.nodes["a"].ipv4, _IPV4)
            self.assertEqual(ctx.state.nodes["a"].ipv6, _IPV6)
            self.assertEqual(connector.addresses, [(_IPV4, 22), (_IPV4, 22)])

    def test_ensure_firewall_opens_22_and_443_and_activates_it_on_the_node(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", "/api/vps/v1/firewall?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("POST", "/api/vps/v1/firewall", 200, {"id": 7, "name": "stackbase-acme", "rules": []})
            server.script("POST", "/api/vps/v1/firewall/7/rules", 200, {})
            server.script("POST", "/api/vps/v1/firewall/7/rules", 200, {})
            server.script("POST", f"/api/vps/v1/firewall/7/activate/{_VPS_ID}", 200, {})
            state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4)})
            ctx, _ = _context(infra_dir, state=state, server=server)

            apply([Step(Action.ENSURE_FIREWALL, "a")], ctx, allow_purchase=False)

            rules = [r["body"] for r in server.requests if r["path"] == "/api/vps/v1/firewall/7/rules"]
            self.assertEqual({rule["port"] for rule in rules}, {"22", "443"})
            self.assertTrue(all(rule["protocol"] == "TCP" and rule["source"] == "any" for rule in rules))
            self.assertEqual(ctx.state.hostinger.firewall_id, 7)
            self.assertIn(f"/api/vps/v1/firewall/7/activate/{_VPS_ID}", [r["path"] for r in server.requests])

    def test_capture_hardware_writes_the_nodes_nix_files_locally(self) -> None:
        listing = "configuration.nix\nhardware-configuration.nix\n"

        def handler(argv, kwargs):
            joined = " ".join(argv)
            if "/etc/nixos" in joined and "basename" in joined:
                return _cp(argv, stdout=listing)
            if "cat --" in joined and "hardware-configuration.nix" in joined:
                return _cp(argv, stdout=b"{ fileSystems.\"/\" = {}; }\n")
            if "cat --" in joined and "configuration.nix" in joined:
                return _cp(argv, stdout=b"{ }\n")
            return None

        with Infra() as infra_dir:
            state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)})
            ctx, _ = _context(infra_dir, state=state, runner=FakeRunner(handler=handler))

            apply([Step(Action.CAPTURE_HARDWARE, "a")], ctx, allow_purchase=False)

            captured = infra_dir / "nodes" / "a" / "hardware-configuration.nix"
            self.assertTrue(captured.exists())
            self.assertIn("fileSystems", captured.read_text(encoding="utf-8"))
            self.assertTrue((infra_dir / "nodes" / "a" / "configuration.nix").exists())
            self.assertTrue(ctx.state.nodes["a"].hardware_captured)

    def test_capture_hardware_fails_clearly_without_a_hardware_configuration(self) -> None:
        def handler(argv, kwargs):
            if "basename" in " ".join(argv):
                return _cp(argv, stdout="configuration.nix\n")
            return None

        with Infra() as infra_dir:
            state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4)})
            ctx, _ = _context(infra_dir, state=state, runner=FakeRunner(handler=handler))

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.CAPTURE_HARDWARE, "a")], ctx, allow_purchase=False)

            self.assertIn("hardware-configuration.nix", str(caught.exception))


class OriginCertTests(unittest.TestCase):
    _OPENSSL_STDOUT = _KEY_PEM + _CERT_PEM.replace("CERTIFICATE", "CERTIFICATE REQUEST")

    def _runner(self) -> FakeRunner:
        def handler(argv, kwargs):
            if argv[0] == "openssl":
                return _cp(argv, stdout=self._OPENSSL_STDOUT)
            return None

        return FakeRunner(handler=handler)

    def test_it_generates_the_key_and_csr_in_one_subprocess_and_never_writes_the_key_to_disk(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("POST", "/certificates", 200, _cf({"certificate": _CERT_PEM}))
            runner = self._runner()
            ctx, _ = _context(infra_dir, server=server, runner=runner)
            saved: list[dict[str, str]] = []
            with mock.patch("stackbase.steps.save_secrets", lambda _dir, data: saved.append(dict(data))):
                apply([Step(Action.ENSURE_ORIGIN_CERT)], ctx, allow_purchase=False)

            openssl_calls = [call for call in runner.calls if call["argv"][0] == "openssl"]
            self.assertEqual(len(openssl_calls), 1)
            self.assertIn(f"/CN={_DOMAIN}", openssl_calls[0]["argv"])
            self.assertEqual(saved[-1]["origin_cert"], _CERT_PEM)
            self.assertEqual(saved[-1]["origin_key"], _KEY_PEM)
            self.assertEqual(ctx.secrets["origin_key"], _KEY_PEM)
            # Nothing but the (already-encrypted) secrets.age may exist in infra/.
            for path in infra_dir.rglob("*"):
                if path.is_file():
                    self.assertNotIn(_KEY_PEM.strip(), path.read_text(encoding="utf-8", errors="replace"))

    def test_the_csr_is_sent_to_cloudflare(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("POST", "/certificates", 200, _cf({"certificate": _CERT_PEM}))
            ctx, _ = _context(infra_dir, server=server, runner=self._runner())
            with mock.patch("stackbase.steps.save_secrets", lambda _dir, _data: None):
                apply([Step(Action.ENSURE_ORIGIN_CERT)], ctx, allow_purchase=False)

            body = next(r["body"] for r in server.requests if r["path"] == "/certificates")
            self.assertIn("CERTIFICATE REQUEST", body["csr"])
            self.assertEqual(body["hostnames"], [_DOMAIN])


class PushConfigTests(unittest.TestCase):
    def _ctx(self, infra_dir: Path, **kwargs):
        state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)})
        secrets = {
            "hostinger_token": "htok",
            "cloudflare_token": "ctok",
            "origin_cert": _CERT_PEM,
            "origin_key": _KEY_PEM,
        }
        return _context(
            infra_dir,
            state=state,
            secrets=secrets,
            runner=FakeRunner(default=_cp(["ssh"], stdout="")),
            **kwargs,
        )

    def test_it_pushes_the_public_keys_but_never_the_encrypted_secrets(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir)

            apply([Step(Action.PUSH_CONFIG, "a")], ctx, allow_purchase=False)

            rsync = next(call for call in ctx.runner.calls if call["argv"][0] == "rsync")
            self.assertIn("--exclude=secrets.age", rsync["argv"])
            self.assertNotIn("--exclude=keys", rsync["argv"])
            self.assertNotIn("--exclude=keys/", rsync["argv"])
            self.assertTrue(rsync["argv"][-1].endswith(":/etc/nixos/stack"))

    def test_it_writes_the_cert_and_key_to_temp_names_and_moves_both_in_one_command(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir)

            apply([Step(Action.PUSH_CONFIG, "a")], ctx, allow_purchase=False)

            remote_commands = [call["argv"][-1] for call in ctx.runner.calls if call["argv"][0] == "ssh"]
            inputs = [call["kwargs"].get("input") for call in ctx.runner.calls if call["argv"][0] == "ssh"]
            self.assertIn(_KEY_PEM, inputs)
            self.assertIn(_CERT_PEM, inputs)

            # Nothing is written straight to the live paths: a reboot mid-push
            # must never leave one real file and one missing (the node's
            # placeholder-cert oneshot regenerates the pair if either is gone).
            live_write = re.compile(r">\s*/var/lib/stackbase/origin\.(?:key|crt)(?!\.new)")
            for command, payload in zip(remote_commands, inputs):
                self.assertIsNone(live_write.search(command), f"writes a live cert path directly: {command}")
                if payload is not None:
                    self.assertIn(".new", command)

            move = next(cmd for cmd in remote_commands if "mv " in cmd)
            self.assertLess(move.index("origin.key.new"), move.index("origin.crt.new"))
            self.assertEqual(move.count("mv "), 2)

    def test_it_reloads_nginx_only_when_nginx_is_running(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir)

            apply([Step(Action.PUSH_CONFIG, "a")], ctx, allow_purchase=False)

            remote = " ".join(call["argv"][-1] for call in ctx.runner.calls if call["argv"][0] == "ssh")
            self.assertIn("is-active", remote)
            self.assertIn("reload nginx", remote)

    def test_dev_mode_also_pushes_the_local_stack_base_checkout(self) -> None:
        with Infra() as infra_dir, TemporaryDirectory() as src:
            ctx, _ = self._ctx(infra_dir, stackbase_src=src)

            apply([Step(Action.PUSH_CONFIG, "a")], ctx, allow_purchase=False)

            targets = [call["argv"][-1] for call in ctx.runner.calls if call["argv"][0] == "rsync"]
            self.assertTrue(any(target.endswith(":/etc/nixos/stack-base") for target in targets))
            src_rsync = next(c for c in ctx.runner.calls if c["argv"][0] == "rsync" and c["argv"][-1].endswith("stack-base"))
            self.assertIn("--exclude=.git", src_rsync["argv"])
            self.assertIn("--exclude=.superpowers", src_rsync["argv"])


class RebuildTests(unittest.TestCase):
    def _ctx(self, infra_dir: Path, popen: FakePopen, **kwargs):
        state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)})
        kwargs.setdefault("runner", FakeRunner(default=_cp(["ssh"], stdout="")))
        return _context(infra_dir, state=state, popen=popen, **kwargs)

    def test_it_tests_then_probes_then_switches_and_records_the_rev(self) -> None:
        popen = FakePopen()
        popen.script(0, "building...\n")
        popen.script(0, "switching...\n")
        with Infra() as infra_dir:
            ctx, lines = self._ctx(infra_dir, popen)

            apply([Step(Action.REBUILD, "a")], ctx, allow_purchase=False)

            commands = popen.argv_strings()
            self.assertEqual(len(commands), 2)
            self.assertIn("nixos-rebuild test --flake /etc/nixos/stack#a", commands[0])
            self.assertIn("nixos-rebuild switch --flake /etc/nixos/stack#a", commands[1])
            probes = [c["argv"][-1] for c in ctx.runner.calls if c["argv"][0] == "ssh"]
            self.assertIn("true", probes)
            # The fingerprint is computed from the tree as it was pushed,
            # not from whatever the run happened to be planned against.
            self.assertEqual(ctx.state.nodes["a"].applied_rev, compute_rev(infra_dir))
            self.assertTrue(any("building..." in line for line in lines))

    def test_it_aborts_before_switch_when_the_post_test_probe_fails(self) -> None:
        popen = FakePopen()
        popen.script(0, "building...\n")
        with Infra() as infra_dir:
            runner = FakeRunner(default=_cp(["ssh"], returncode=255, stderr="connection timed out"))
            ctx, _ = self._ctx(infra_dir, popen, runner=runner)

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.REBUILD, "a")], ctx, allow_purchase=False)

            self.assertIn("reboot", str(caught.exception).lower())
            self.assertEqual(len(popen.calls), 1, "switch must never run after a failed probe")
            self.assertIsNone(ctx.state.nodes["a"].applied_rev)

    def test_it_does_not_record_the_rev_when_switch_fails(self) -> None:
        popen = FakePopen()
        popen.script(0, "building...\n")
        popen.script(1, "error: build failed\n")
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, popen)

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.REBUILD, "a")], ctx, allow_purchase=False)

            self.assertIn("build failed", str(caught.exception))
            self.assertIsNone(ctx.state.nodes["a"].applied_rev)

    def test_dev_mode_overrides_the_stack_base_input_on_both_commands(self) -> None:
        popen = FakePopen()
        popen.script(0, "")
        popen.script(0, "")
        with Infra() as infra_dir, TemporaryDirectory() as src:
            ctx, _ = self._ctx(infra_dir, popen, stackbase_src=src)

            apply([Step(Action.REBUILD, "a")], ctx, allow_purchase=False)

            for command in popen.argv_strings():
                self.assertIn("--override-input stack-base path:/etc/nixos/stack-base", command)

    def test_every_streamed_line_is_redacted(self) -> None:
        popen = FakePopen()
        popen.script(0, "warning: token ctok leaked into the build log\n")
        popen.script(0, "")
        with Infra() as infra_dir:
            ctx, lines = self._ctx(infra_dir, popen)

            apply([Step(Action.REBUILD, "a")], ctx, allow_purchase=False)

            self.assertTrue(any("REDACTED" in line for line in lines))
            self.assertFalse(any("ctok" in line for line in lines))


class ConvergenceAfterAFullRunTests(unittest.TestCase):
    def test_a_finished_run_leaves_the_node_up_to_date(self) -> None:
        """CAPTURE_HARDWARE writes into infra/ -- which is part of what gets pushed.

        If REBUILD recorded the fingerprint computed back when the run was
        planned, the tree would already have moved on by the time it was
        saved, and the very next run would push and rebuild again for
        nothing (minutes of waiting, and `up` never reporting converged).
        """

        def handler(argv, kwargs):
            joined = " ".join(argv)
            if "basename" in joined:
                return _cp(argv, stdout=f"{_HARDWARE}\n")
            if "cat --" in joined:
                return _cp(argv, stdout=b'{ fileSystems."/" = { }; }\n')
            return None

        popen = FakePopen()
        popen.script(0, "")
        popen.script(0, "")
        with Infra() as infra_dir:
            secrets = {
                "hostinger_token": "htok",
                "cloudflare_token": "ctok",
                "origin_cert": _CERT_PEM,
                "origin_key": _KEY_PEM,
            }
            state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)})
            observed = replace(_observed_fresh(), local=local_facts(infra_dir, secrets))
            ctx, _ = _context(
                infra_dir,
                state=state,
                secrets=secrets,
                observed=observed,
                popen=popen,
                runner=FakeRunner(handler=handler, default=_cp(["ssh"], stdout="")),
            )

            apply(
                [
                    Step(Action.CAPTURE_HARDWARE, "a"),
                    Step(Action.PUSH_CONFIG, "a"),
                    Step(Action.REBUILD, "a"),
                ],
                ctx,
                allow_purchase=False,
            )

            after = local_facts(infra_dir, secrets)
            self.assertEqual(ctx.state.nodes["a"].applied_rev, after.desired_rev)
            # ...which is what makes the next run report nothing to do.
            converged = _converged_state(rev=ctx.state.nodes["a"].applied_rev)
            self.assertEqual(plan(_config(), converged, _converged_observed(rev=after.desired_rev)), [])


_HARDWARE = "hardware-configuration.nix"


class DnsTests(unittest.TestCase):
    def test_upsert_dns_points_the_domain_at_the_primary_node(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            server.script("GET", f"/zones/zone1/dns_records?type=A&name={_DOMAIN}&page=1", 200, _cf([], result_info=_page()))
            server.script("POST", "/zones/zone1/dns_records", 200, _cf({"id": "rec1"}))
            state = StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4)})
            ctx, _ = _context(infra_dir, state=state, server=server)

            apply([Step(Action.UPSERT_DNS, "a")], ctx, allow_purchase=False)

            body = next(r["body"] for r in server.requests if r["method"] == "POST")
            self.assertEqual(body, {"type": "A", "name": _DOMAIN, "content": _IPV4, "proxied": True})
            self.assertEqual(ctx.state.cloudflare.record_id, "rec1")
            self.assertEqual(ctx.state.cloudflare.zone_id, "zone1")

    def test_upsert_dns_fails_clearly_when_the_node_has_no_address_yet(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            ctx, _ = _context(infra_dir, server=server)

            with self.assertRaises(StackError) as caught:
                apply([Step(Action.UPSERT_DNS, "a")], ctx, allow_purchase=False)

            self.assertIn("address", str(caught.exception))


class ResumeTests(unittest.TestCase):
    def test_failure_at_step_n_keeps_state_through_n_minus_1_and_a_replan_resumes_there(self) -> None:
        with Infra() as infra_dir, FakeServer() as server:
            # ENSURE_KEYS succeeds; WAIT_RUNNING then fails (nothing scripted for the VM).
            server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("POST", "/api/vps/v1/public-keys", 200, {"id": 11})
            server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("POST", "/api/vps/v1/public-keys", 200, {"id": 12})
            server.script("GET", f"/api/vps/v1/virtual-machines/{_VPS_ID}", 500, {"message": "boom"})
            ctx, _ = _context(infra_dir, server=server)
            steps = [Step(Action.ENSURE_KEYS), Step(Action.WAIT_RUNNING, "a")]

            with self.assertRaises(StackError):
                apply(steps, ctx, allow_purchase=False)

            from stackbase.config import load_state

            saved = load_state(infra_dir)
            self.assertEqual(saved.hostinger.ssh_key_ids, {"matt": 11, "kim": 12})
            self.assertIsNone(saved.nodes.get("a", NodeState()).ipv4)

            replanned = plan(
                _config(),
                saved,
                Observed(
                    local=_local(),
                    nodes={"a": ObservedNode(vps_id=_VPS_ID, state="running", actions_lock="unlocked", ipv4=_IPV4)},
                    public_key_ids={"matt": 11, "kim": 12},
                    zone_id="zone1",
                ),
            )
            self.assertIs(replanned[0].action, Action.WAIT_RUNNING)


class OutputTests(unittest.TestCase):
    def test_every_emitted_line_is_redacted(self) -> None:
        with Infra() as infra_dir:
            ctx, lines = _context(infra_dir, secrets={"hostinger_token": "supersecret", "cloudflare_token": "ctok"})

            ctx.emit("token is supersecret")

            self.assertEqual(lines, ["token is ***REDACTED***"])

    def test_a_remote_failure_carrying_a_secret_is_redacted_on_the_error_line(self) -> None:
        from stackbase.__main__ import error_line

        error = StackError("command failed: echo supersecret", "stderr said supersecret")

        self.assertEqual(
            error_line(error, ["supersecret"]),
            "error: command failed: echo ***REDACTED*** — stderr said ***REDACTED***",
        )


class LocalFactsTests(unittest.TestCase):
    def test_the_rev_changes_when_a_pushed_file_changes(self) -> None:
        with Infra() as infra_dir:
            first = local_facts(infra_dir, {}).desired_rev
            (infra_dir / "stack.toml").write_text('project = "acme2"\n', encoding="utf-8")
            second = local_facts(infra_dir, {}).desired_rev

            self.assertNotEqual(first, second)

    def test_the_rev_ignores_the_state_file_and_the_known_hosts_file(self) -> None:
        with Infra() as infra_dir:
            first = local_facts(infra_dir, {}).desired_rev
            (infra_dir / "stack.state.json").write_text('{"version": 1}\n', encoding="utf-8")
            (infra_dir / "known_hosts").write_text("1.2.3.4 ssh-ed25519 AAAA\n", encoding="utf-8")

            self.assertEqual(local_facts(infra_dir, {}).desired_rev, first)

    def test_dev_mode_folds_the_local_checkout_into_the_rev(self) -> None:
        with Infra() as infra_dir, TemporaryDirectory() as src:
            (Path(src) / "a.py").write_text("x = 1\n", encoding="utf-8")
            first = local_facts(infra_dir, {}, stackbase_src=src).desired_rev
            (Path(src) / "a.py").write_text("x = 2\n", encoding="utf-8")
            second = local_facts(infra_dir, {}, stackbase_src=src).desired_rev

            self.assertNotEqual(first, second)
            self.assertNotEqual(first, local_facts(infra_dir, {}).desired_rev)

    def test_it_reads_the_pinned_hosts_the_captured_nodes_and_the_cert(self) -> None:
        with Infra() as infra_dir:
            (infra_dir / "known_hosts").write_text(f"{_IPV4} ssh-ed25519 AAAA\n", encoding="utf-8")
            (infra_dir / "nodes" / "a").mkdir(parents=True)
            (infra_dir / "nodes" / "a" / "hardware-configuration.nix").write_text("{ }\n", encoding="utf-8")

            local = local_facts(infra_dir, {"origin_cert": _CERT_PEM, "origin_key": _KEY_PEM})

            self.assertIn(_IPV4, local.pinned_hosts)
            self.assertIn("a", local.captured_nodes)
            self.assertTrue(local.has_origin_cert)

    def test_without_a_lock_file_or_a_local_checkout_it_explains_both_options(self) -> None:
        with Infra() as infra_dir:
            (infra_dir / "flake.lock").unlink()

            with self.assertRaises(StackError) as caught:
                local_facts(infra_dir, {})

            message = str(caught.exception)
            self.assertIn("flake.lock", message)
            self.assertIn("STACKBASE_SRC", message)


if __name__ == "__main__":
    unittest.main()
