"""Tests for stackbase.logs: Vector's R2 credentials file and its step.

The shipping itself runs entirely on the node (`nixos/logs.nix`, proved in
`tests/vm-logs.nix`). This is the laptop side: rendering
`/var/lib/stackbase/logs.env` from the environment's secrets, deciding when
ENSURE_LOGS_ENV is planned, and pushing it without the secret ever being in
argv or on the operator's disk.
"""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from stackbase.config import LogsConfig, NodeState, StackState, load_state, save_state
from stackbase.errors import StackError
from stackbase.logs import (
    LOGS_ENV_PATH,
    check_logs_credentials,
    logs_enabled,
    logs_env_content,
    logs_env_digest,
)
from stackbase.reconcile import Action, Step, apply, local_facts, plan, render_description
from tests.fakes import FakeRunner
from tests.test_reconcile import (
    _IPV4,
    _REV,
    _VPS_ID,
    Infra,
    _config,
    _context,
    _converged_observed,
    _converged_state,
    _cp,
)

_SECRET_VALUE = "s3cr3t-logs-example-value"

_LOGS_SECRETS = {
    "logs_access_key_id": "LOGSKEYEXAMPLE",
    "logs_secret_access_key": _SECRET_VALUE,
    "r2_endpoint": "https://abc123.r2.cloudflarestorage.com",
}


def _env(logs: LogsConfig):
    return replace(_config().env(None), logs=logs)


_ON = LogsConfig(bucket="acme-logs")


class LogsEnvContentTests(unittest.TestCase):
    def test_logs_env_renders_three_vars(self) -> None:
        self.assertEqual(
            logs_env_content(_LOGS_SECRETS),
            "AWS_ACCESS_KEY_ID=LOGSKEYEXAMPLE\n"
            f"AWS_SECRET_ACCESS_KEY={_SECRET_VALUE}\n"
            "LOGS_ENDPOINT=https://abc123.r2.cloudflarestorage.com\n",
        )
        self.assertEqual(LOGS_ENV_PATH, "/var/lib/stackbase/logs.env")

    def test_a_missing_or_empty_value_means_no_file_at_all(self) -> None:
        for key in _LOGS_SECRETS:
            with self.subTest(key=key):
                partial = {k: v for k, v in _LOGS_SECRETS.items() if k != key}
                self.assertIsNone(logs_env_content(partial))
                self.assertIsNone(logs_env_content({**_LOGS_SECRETS, key: ""}))

    def test_the_backup_keys_alone_are_not_logs_credentials(self) -> None:
        """Logs have their own R2 token: the backup one is never reused."""
        self.assertIsNone(
            logs_env_content(
                {"r2_access_key_id": "A", "r2_secret_access_key": "B", "r2_endpoint": "https://e.example"}
            )
        )

    def test_logs_env_rejects_shell_metacharacters(self) -> None:
        for bad in ("a$(id)", "a;id", "a`id`", "a b", "a'b", 'a"b', "a\\b", "a|b", "a\nEXTRA=1", "a\rb"):
            for key in _LOGS_SECRETS:
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(StackError) as caught:
                        logs_env_content({**_LOGS_SECRETS, key: bad})
                    text = f"{caught.exception} {caught.exception.hint}"
                    self.assertIn(key, text)
                    # Names the key, never any part of the value.
                    self.assertNotIn(bad, text)


class LogsEnabledTests(unittest.TestCase):
    def test_on_only_with_a_bucket_and_no_opt_out(self) -> None:
        self.assertFalse(logs_enabled(LogsConfig()))
        self.assertTrue(logs_enabled(LogsConfig(bucket="acme-logs")))
        self.assertTrue(logs_enabled(LogsConfig(enabled=True, bucket="acme-logs")))
        self.assertFalse(logs_enabled(LogsConfig(enabled=False, bucket="acme-logs")))


class CheckLogsCredentialsTests(unittest.TestCase):
    def test_logs_on_without_credentials_is_refused_naming_every_key(self) -> None:
        with self.assertRaises(StackError) as caught:
            check_logs_credentials(_env(_ON), None)
        text = f"{caught.exception} {caught.exception.hint}"
        for key in _LOGS_SECRETS:
            self.assertIn(key, text)
        self.assertIn("acme-logs", text)

    def test_logs_off_or_complete_credentials_pass(self) -> None:
        check_logs_credentials(_env(LogsConfig()), None)
        check_logs_credentials(_env(LogsConfig(enabled=False, bucket="acme-logs")), None)
        check_logs_credentials(_env(_ON), "sha")


class LogsEnvPlanTests(unittest.TestCase):
    def _observed(self, sha: str | None, *, rev: str = _REV):
        base = _converged_observed(rev=rev)
        return replace(base, local=replace(base.local, logs_env_sha=sha))

    def test_local_facts_digests_the_logs_credentials(self) -> None:
        with Infra() as infra_dir:
            self.assertIsNone(local_facts(infra_dir, {"hostinger_token": "h"}, env=_env(_ON)).logs_env_sha)
            sha = local_facts(infra_dir, _LOGS_SECRETS, env=_env(_ON)).logs_env_sha
        self.assertEqual(sha, logs_env_digest(logs_env_content(_LOGS_SECRETS) or ""))

    def test_without_logs_odd_logs_secrets_are_neither_validated_nor_rendered(self) -> None:
        """A project with no [logs] (or opted out) must not be broken by a
        stray logs_* value that would fail the allowlist."""
        odd = {**_LOGS_SECRETS, "logs_secret_access_key": "a$(id) b"}
        with Infra() as infra_dir:
            for env in (_env(LogsConfig()), _env(LogsConfig(enabled=False, bucket="acme-logs")), None):
                with self.subTest(env=env and env.logs):
                    self.assertIsNone(local_facts(infra_dir, odd, env=env).logs_env_sha)
            with self.assertRaises(StackError):
                local_facts(infra_dir, odd, env=_env(_ON))

    def test_no_logs_table_plans_nothing_even_with_credentials(self) -> None:
        """A project without [logs] plans exactly what it planned before."""
        steps = plan(_config(), _converged_state(), self._observed("sha"), env=_env(LogsConfig()))
        self.assertEqual(steps, [])

    def test_opted_out_logs_plan_nothing(self) -> None:
        env = _env(LogsConfig(enabled=False, bucket="acme-logs"))
        self.assertEqual(plan(_config(), _converged_state(), self._observed("sha"), env=env), [])

    def test_logs_on_with_credentials_and_no_recorded_sha_plans_the_step(self) -> None:
        steps = plan(_config(), _converged_state(), self._observed("sha"), env=_env(_ON))
        self.assertEqual(steps, [Step(Action.ENSURE_LOGS_ENV, "a")])

    def test_the_credentials_land_before_the_rebuild_that_starts_vector(self) -> None:
        """Vector refuses to start without ${LOGS_ENDPOINT}, and a unit that
        fails to start fails the whole `nixos-rebuild switch`."""
        steps = plan(_config(), _converged_state(rev="old-rev"), self._observed("sha"), env=_env(_ON))
        self.assertEqual(
            [s.action for s in steps], [Action.ENSURE_LOGS_ENV, Action.PUSH_CONFIG, Action.REBUILD]
        )

    def test_a_matching_recorded_sha_plans_nothing(self) -> None:
        state = _converged_state()
        state.nodes["a"].logs_env_sha = "sha"
        self.assertEqual(plan(_config(), state, self._observed("sha"), env=_env(_ON)), [])

    def test_the_step_description_carries_no_content(self) -> None:
        step = Step(Action.ENSURE_LOGS_ENV, "a")
        self.assertEqual(step.description, "node a: updating the log shipping credentials on the server")
        self.assertEqual(render_description(step, has_cloudflare_token=True), step.description)


class EnsureLogsEnvTests(unittest.TestCase):
    _DIR_CMD = "set -eu; install -d -m 0750 /var/lib/stackbase"
    _TMP_CMD = "set -eu; install -m 0600 -o root -g root /dev/null /var/lib/stackbase/logs.env.new"
    _CAT_CMD = "set -eu; cat > /var/lib/stackbase/logs.env.new"
    _MV_CMD = "set -eu; mv -f /var/lib/stackbase/logs.env.new /var/lib/stackbase/logs.env"
    _RESTART_CMD = "set -eu; if systemctl is-active --quiet vector.service; then systemctl restart vector.service; fi"
    _COMMANDS = (_DIR_CMD, _TMP_CMD, _CAT_CMD, _MV_CMD, _RESTART_CMD)

    def _ctx(self, infra_dir, *, failing: str | None = None, secrets=None, state=None):
        def handler(argv, kwargs):
            if not argv or argv[0] != "ssh" or argv[-1] not in self._COMMANDS:
                return None
            if argv[-1] == failing:
                return _cp(argv, returncode=1, stderr="no space left on device\n")
            return _cp(argv, returncode=0)

        return _context(
            infra_dir,
            state=state
            if state is not None
            else StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)}),
            secrets={"hostinger_token": "htok", "cloudflare_token": "ctok", **(secrets or _LOGS_SECRETS)},
            runner=FakeRunner(handler=handler),
            env=_env(_ON),
        )

    def test_pushes_root_only_through_stdin_then_restarts_a_running_vector(self) -> None:
        with Infra() as infra_dir:
            ctx, lines = self._ctx(infra_dir)

            apply([Step(Action.ENSURE_LOGS_ENV, "a")], ctx, allow_purchase=False)

            commands = [c["argv"][-1] for c in ctx.runner.calls if c["argv"][0] == "ssh"]
            self.assertEqual(commands, list(self._COMMANDS))
            cat_call = next(c for c in ctx.runner.calls if c["argv"][-1] == self._CAT_CMD)
            self.assertEqual(cat_call["kwargs"].get("input"), logs_env_content(_LOGS_SECRETS))
            for call in ctx.runner.calls:
                self.assertNotIn(_SECRET_VALUE, " ".join(call["argv"]))
            for line in lines:
                self.assertNotIn(_SECRET_VALUE, line)
            self.assertTrue(any("log shipping credentials updated" in line for line in lines), lines)
            self.assertEqual(
                ctx.state.nodes["a"].logs_env_sha, logs_env_digest(logs_env_content(_LOGS_SECRETS) or "")
            )
            on_disk = (infra_dir / "stack.state.json").read_text(encoding="utf-8")
            self.assertNotIn(_SECRET_VALUE, on_disk)

    def test_a_failing_mv_leaves_the_sha_unset(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, failing=self._MV_CMD)

            with self.assertRaises(StackError):
                apply([Step(Action.ENSURE_LOGS_ENV, "a")], ctx, allow_purchase=False)

            self.assertIsNone(ctx.state.nodes["a"].logs_env_sha)

    def test_incomplete_credentials_are_refused_before_any_ssh_call(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, secrets={"logs_access_key_id": "K"})
            with self.assertRaises(StackError):
                apply([Step(Action.ENSURE_LOGS_ENV, "a")], ctx, allow_purchase=False)
            self.assertEqual(ctx.runner.calls, [])


class LogsStateFileTests(unittest.TestCase):
    def test_an_unset_logs_sha_is_not_written_so_old_state_files_stay_byte_identical(self) -> None:
        with Infra() as infra_dir:
            env = _config().env(None)
            save_state(infra_dir, env, StackState(nodes={"a": NodeState(vps_id=1)}))
            node = json.loads((infra_dir / "stack.state.json").read_text(encoding="utf-8"))["nodes"]["a"]
            self.assertNotIn("logs_env_sha", node)

            save_state(infra_dir, env, StackState(nodes={"a": NodeState(vps_id=1, logs_env_sha="x")}))
            self.assertEqual(load_state(infra_dir, env).nodes["a"].logs_env_sha, "x")


if __name__ == "__main__":
    unittest.main()
