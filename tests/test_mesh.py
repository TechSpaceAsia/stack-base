"""Tests for stackbase.mesh: joining Cloudflare Mesh, laptop side.

The daemon itself is `nixos/mesh.nix` (evaluated in tests/test_template.py).
This is the part `./infra/up` plays: observing `warp-cli status` over root
SSH, planning ENSURE_MESH, and enrolling a node with the environment's
`mesh_connector_token` without it ever being in a local argv or a log line.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from stackbase.config import MeshConfig, NodeState, StackState
from stackbase.errors import StackError
from stackbase.mesh import MESH_TOKEN_KEY, mesh_connected, observe_mesh
from stackbase.reconcile import Action, ObservedNode, Step, apply, observe, plan, render_description
from tests.fakes import FakeRunner, FakeServer
from tests.test_reconcile import (
    _DOMAIN,
    _IPV4,
    _VPS_ID,
    Infra,
    _config,
    _context,
    _converged_observed,
    _converged_state,
    _cp,
    _local,
    _script_observe,
)
from stackbase.cloudflare import CloudflareClient
from stackbase.hostinger import HostingerClient
from stackbase.ssh import Ssh

_TOKEN = "eyJhbGciOi.mesh-connector-token_value-0123456789"
_STATUS_CMD = "warp-cli --accept-tos status"
_ENROL_CMD = 'set -eu; IFS= read -r token; exec warp-cli --accept-tos connector new "$token"'
_CONNECT_CMD = "warp-cli --accept-tos connect"
_IP_CMD = "ip -6 addr show CloudflareWARP"
_CONNECTED = "Status update: Connected\n"
_DISCONNECTED = "Status update: Disconnected. Reason: Manual Disconnection\n"

_ON = MeshConfig(enabled=True)


def _cfg(mesh: MeshConfig = _ON):
    return replace(_config(), mesh=mesh)


def _observed(connected: bool | None):
    base = _converged_observed()
    node = replace(base.nodes["a"], mesh_connected=connected)
    return replace(base, nodes={"a": node})


class MeshConfigTests(unittest.TestCase):
    def _load(self, toml: str):
        from tests.test_config import VALID_ED25519_KEY, TempInfraDir, load_config, write_key, write_toml

        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)
            return load_config(infra_dir)

    def test_mesh_defaults_off_and_parses(self) -> None:
        from tests.test_config import VALID_TOML

        self.assertEqual(self._load(VALID_TOML).mesh, MeshConfig(enabled=False))
        self.assertEqual(self._load(VALID_TOML + "\n[mesh]\nenabled = true\n").mesh, MeshConfig(enabled=True))

    def test_mesh_is_shared_not_per_environment(self) -> None:
        from tests.test_config import _TWO_ENVS

        config = self._load(_TWO_ENVS + "\n[mesh]\nenabled = true\n")
        self.assertTrue(config.mesh.enabled)
        with self.assertRaises(StackError) as raised:
            self._load(_TWO_ENVS.replace('domain = "acme.example.com"\n', 'domain = "acme.example.com"\nmesh = true\n'))
        self.assertIn("mesh", str(raised.exception))

    def test_unknown_mesh_keys_and_non_bool_enabled_are_errors(self) -> None:
        from tests.test_config import VALID_TOML

        for extra in ("[mesh]\nbogus = 1\n", '[mesh]\nenabled = "yes"\n'):
            with self.subTest(extra=extra), self.assertRaises(StackError):
                self._load(VALID_TOML + "\n" + extra)


class MeshStatusTests(unittest.TestCase):
    def test_only_a_plain_connected_status_counts(self) -> None:
        self.assertTrue(mesh_connected(_CONNECTED))
        for text in (_DISCONNECTED, "Status update: Connecting\n", "", "Unable to connect to the daemon\n"):
            with self.subTest(text=text):
                self.assertFalse(mesh_connected(text))

    def test_observe_mesh_treats_a_missing_warp_cli_as_not_connected(self) -> None:
        """Before the first rebuild there is no warp-cli at all."""
        ssh = Ssh("/nonexistent", _IPV4, runner=FakeRunner(default=_cp([], returncode=127, stderr="not found")))
        self.assertFalse(observe_mesh(ssh))

    def test_observe_mesh_reads_status_over_root_ssh(self) -> None:
        runner = FakeRunner(default=_cp([], stdout=_CONNECTED))
        self.assertTrue(observe_mesh(Ssh("/nonexistent", _IPV4, runner=runner)))
        self.assertEqual(runner.calls[0]["argv"][-1], _STATUS_CMD)
        self.assertIn(f"root@{_IPV4}", runner.calls[0]["argv"])


class MeshPlanTests(unittest.TestCase):
    def test_mesh_disabled_plans_nothing(self) -> None:
        for connected in (None, False):
            with self.subTest(connected=connected):
                steps = plan(_cfg(MeshConfig()), _converged_state(), _observed(connected))
                self.assertEqual(steps, [])

    def test_connected_node_plans_nothing(self) -> None:
        self.assertEqual(plan(_cfg(), _converged_state(), _observed(True)), [])

    def test_disconnected_node_plans_ensure_mesh(self) -> None:
        self.assertEqual(plan(_cfg(), _converged_state(), _observed(False)), [Step(Action.ENSURE_MESH, "a")])

    def test_an_unobservable_node_is_planned_too(self) -> None:
        self.assertEqual(plan(_cfg(), _converged_state(), _observed(None)), [Step(Action.ENSURE_MESH, "a")])

    def test_enrolment_follows_the_rebuild_that_installs_warp_cli(self) -> None:
        steps = plan(_cfg(), _converged_state(rev="old-rev"), _observed(False))
        self.assertEqual([s.action for s in steps], [Action.PUSH_CONFIG, Action.REBUILD, Action.ENSURE_MESH])

    def test_the_description_carries_no_secret(self) -> None:
        step = Step(Action.ENSURE_MESH, "a")
        self.assertEqual(step.description, "node a: joining Cloudflare Mesh")
        self.assertEqual(render_description(step, has_cloudflare_token=True), step.description)


class MeshObserveTests(unittest.TestCase):
    def _observe(self, cfg, state, local, factory):
        with FakeServer() as server:
            _script_observe(server)
            return observe(
                cfg, state, HostingerClient("htok", base_url=server.url),
                CloudflareClient("ctok", base_url=server.url), local=local, ssh_factory=factory,
            )

    def test_mesh_off_makes_no_ssh_call(self) -> None:
        calls: list[str] = []
        local = _local(pinned=(_IPV4,))
        observed = self._observe(_cfg(MeshConfig()), _converged_state(), local, calls.append)
        self.assertEqual(calls, [])
        self.assertIsNone(observed.nodes["a"].mesh_connected)

    def test_mesh_on_reads_each_pinned_node(self) -> None:
        seen: list[str] = []

        def factory(ip: str) -> Ssh:
            seen.append(ip)
            return Ssh("/nonexistent", ip, runner=FakeRunner(default=_cp([], stdout=_CONNECTED)))

        observed = self._observe(_cfg(), _converged_state(), _local(pinned=(_IPV4,)), factory)
        self.assertEqual(seen, [_IPV4])
        self.assertIs(observed.nodes["a"].mesh_connected, True)

    def test_an_unpinned_node_is_not_dialled(self) -> None:
        seen: list[str] = []
        observed = self._observe(_cfg(), _converged_state(), _local(), seen.append)
        self.assertEqual(seen, [])
        self.assertIsNone(observed.nodes["a"].mesh_connected)


class EnsureMeshTests(unittest.TestCase):
    def _ctx(self, infra_dir, *, secrets=None, statuses=(_CONNECTED,), enrol_rc=0, ip_out=None):
        remaining = list(statuses)

        def handler(argv, kwargs):
            if not argv or argv[0] != "ssh":
                return None
            cmd = argv[-1]
            if cmd == _STATUS_CMD:
                text = remaining.pop(0) if len(remaining) > 1 else remaining[0]
                return _cp(argv, stdout=text)
            if cmd == _ENROL_CMD:
                return _cp(argv, returncode=enrol_rc, stderr="token rejected\n" if enrol_rc else "")
            if cmd == _CONNECT_CMD:
                return _cp(argv)
            if cmd == _IP_CMD:
                return _cp(argv, stdout=ip_out if ip_out is not None else (
                    "5: CloudflareWARP: <POINTOPOINT> mtu 1280\n"
                    "    inet6 fd10:aaaa:bbbb::1234/128 scope global\n"
                    "    inet6 fe80::1/64 scope link\n"))
            return None

        payload = {"hostinger_token": "htok", "cloudflare_token": "ctok"}
        payload.update({MESH_TOKEN_KEY: _TOKEN} if secrets is None else secrets)
        ctx, lines = _context(
            infra_dir,
            cfg=_cfg(),
            state=StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)}),
            secrets=payload,
            runner=FakeRunner(handler=handler),
        )
        ctx.sleep = lambda seconds: None
        return ctx, lines

    def test_missing_token_names_secret_key(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, secrets={})
            with self.assertRaises(StackError) as raised:
                apply([Step(Action.ENSURE_MESH, "a")], ctx, allow_purchase=False)
            text = f"{raised.exception} {raised.exception.hint}"
            self.assertIn("mesh_connector_token", text)
            self.assertIn("README", text)
            self.assertIn("Mesh", text)
            self.assertEqual(ctx.runner.calls, [])

    def test_token_sent_on_stdin_not_argv(self) -> None:
        with Infra() as infra_dir:
            ctx, lines = self._ctx(infra_dir)

            apply([Step(Action.ENSURE_MESH, "a")], ctx, allow_purchase=False)

            commands = [c["argv"][-1] for c in ctx.runner.calls if c["argv"][0] == "ssh"]
            self.assertEqual(commands, [_ENROL_CMD, _CONNECT_CMD, _STATUS_CMD, _IP_CMD])
            enrol = ctx.runner.calls[0]
            self.assertEqual(enrol["kwargs"].get("input"), _TOKEN + "\n")
            for call in ctx.runner.calls:
                self.assertNotIn(_TOKEN, " ".join(call["argv"]))
            for line in lines:
                self.assertNotIn(_TOKEN, line)
            self.assertTrue(any("fd10:aaaa:bbbb::1234" in line for line in lines), lines)

    def test_it_polls_until_connected(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, statuses=(_DISCONNECTED, _DISCONNECTED, _CONNECTED))
            waits: list[float] = []
            ctx.sleep = waits.append
            apply([Step(Action.ENSURE_MESH, "a")], ctx, allow_purchase=False)
            self.assertEqual(len(waits), 2)

    def test_never_connecting_gives_up_after_sixty_seconds(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, statuses=(_DISCONNECTED,))
            waits: list[float] = []
            ctx.sleep = waits.append
            with self.assertRaises(StackError) as raised:
                apply([Step(Action.ENSURE_MESH, "a")], ctx, allow_purchase=False)
            self.assertEqual(sum(waits), 60)
            self.assertIn("Mesh", str(raised.exception))

    def test_a_failed_enrolment_still_tries_connect_then_reports_the_failure(self) -> None:
        """A node enrolled on an earlier run (but disconnected) makes
        `connector new` fail; connecting is what it needs."""
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, enrol_rc=1, statuses=(_DISCONNECTED,))
            ctx.sleep = lambda seconds: None
            with self.assertRaises(StackError) as raised:
                apply([Step(Action.ENSURE_MESH, "a")], ctx, allow_purchase=False)
            self.assertIn("token rejected", raised.exception.hint)
            self.assertNotIn(_TOKEN, str(raised.exception) + raised.exception.hint)
            self.assertIn(_CONNECT_CMD, [c["argv"][-1] for c in ctx.runner.calls])

    def test_an_odd_token_is_refused_before_any_ssh_call(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, secrets={MESH_TOKEN_KEY: "abc; rm -rf /"})
            with self.assertRaises(StackError) as raised:
                apply([Step(Action.ENSURE_MESH, "a")], ctx, allow_purchase=False)
            self.assertIn("mesh_connector_token", str(raised.exception))
            self.assertNotIn("rm -rf", str(raised.exception) + raised.exception.hint)
            self.assertEqual(ctx.runner.calls, [])


if __name__ == "__main__":
    unittest.main()
