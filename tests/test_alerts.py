"""Tests for stackbase.alerts: the SMTP credentials file, its step, the
"no [alerts]" warning and `alert-test`.

The alerting itself runs entirely on the node (`nixos/alerts.nix`: a
top-level OnFailure= drop-in, a handler, nullmailer and the freshness
watchdog, proved in `tests/vm-alerts.nix`). This is the laptop side:
rendering `/var/lib/stackbase/alert.env` from the environment's smtp_*
secrets, deciding when ENSURE_ALERT_ENV is planned, and pushing it without
the password ever being in argv or on the operator's disk.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from stackbase.alerts import (
    ALERT_ENV_PATH,
    ALERT_TEST_COMMAND,
    alert_env_content,
    alert_env_digest,
    alerts_enabled,
    alerts_warning,
    check_alert_credentials,
    run_alert_test,
)
from stackbase.config import AlertsConfig, NodeState, StackState, load_state, save_state
from stackbase.errors import StackError
from stackbase.reconcile import Action, Step, apply, local_facts, plan, render_description
from tests.fakes import FakePopen, FakeRunner, FakeServer
from tests.test_cli import _AGE_AVAILABLE, _cli, _project, _script_observe
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

_PASSWORD = "s3cr3t-smtp-example-value"

_SMTP_SECRETS = {
    "smtp_host": "mail.example.org",
    "smtp_port": "465",
    "smtp_user": "server-a@example.org",
    "smtp_password": _PASSWORD,
    "smtp_from": "server-a@example.org",
}

_ON = AlertsConfig(to=["ops@example.org", "servers.acme@example.org"])


def _env(alerts: AlertsConfig):
    return replace(_config().env(None), alerts=alerts)


class AlertEnvContentTests(unittest.TestCase):
    def test_alert_env_renders_five_vars(self) -> None:
        self.assertEqual(
            alert_env_content(_SMTP_SECRETS),
            "SMTP_HOST=mail.example.org\n"
            "SMTP_PORT=465\n"
            "SMTP_USER=server-a@example.org\n"
            f"SMTP_PASSWORD={_PASSWORD}\n"
            "SMTP_FROM=server-a@example.org\n",
        )
        self.assertEqual(ALERT_ENV_PATH, "/var/lib/stackbase/alert.env")

    def test_a_missing_or_empty_value_means_no_file_at_all(self) -> None:
        for key in _SMTP_SECRETS:
            with self.subTest(key=key):
                partial = {k: v for k, v in _SMTP_SECRETS.items() if k != key}
                self.assertIsNone(alert_env_content(partial))
                self.assertIsNone(alert_env_content({**_SMTP_SECRETS, key: ""}))

    def test_the_allowlist_rejects_shell_metacharacters_naming_the_key_only(self) -> None:
        for bad in ("a$(id)", "a;id", "a`id`", "a b", "a'b", 'a"b', "a\\b", "a|b", "a\nEXTRA=1", "a\rb"):
            for key in _SMTP_SECRETS:
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(StackError) as caught:
                        alert_env_content({**_SMTP_SECRETS, key: bad})
                    text = f"{caught.exception} {caught.exception.hint}"
                    self.assertIn(key, text)
                    self.assertNotIn(bad, text)

    def test_the_port_is_a_number_and_the_from_an_address(self) -> None:
        for key, bad in (
            ("smtp_port", "smtps"),
            ("smtp_port", "0"),
            ("smtp_port", "70000"),
            ("smtp_from", "not-an-address"),
            ("smtp_host", "mail/example"),
        ):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(StackError) as caught:
                    alert_env_content({**_SMTP_SECRETS, key: bad})
                self.assertIn(key, str(caught.exception))


class AlertsEnabledTests(unittest.TestCase):
    def test_on_only_with_recipients(self) -> None:
        self.assertFalse(alerts_enabled(AlertsConfig()))
        self.assertFalse(alerts_enabled(AlertsConfig(to=[])))
        self.assertTrue(alerts_enabled(_ON))


class CheckAlertCredentialsTests(unittest.TestCase):
    def test_alerts_without_smtp_keys_are_refused_naming_every_key(self) -> None:
        with self.assertRaises(StackError) as caught:
            check_alert_credentials(_env(_ON), None)
        text = f"{caught.exception} {caught.exception.hint}"
        for key in _SMTP_SECRETS:
            self.assertIn(key, text)
        self.assertIn("secrets.age", text)

    def test_an_environment_names_its_own_secrets_file(self) -> None:
        env = replace(_env(_ON), name="staging")
        with self.assertRaises(StackError) as caught:
            check_alert_credentials(env, None)
        text = f"{caught.exception} {caught.exception.hint}"
        self.assertIn("secrets.staging.age", text)
        self.assertIn("--env staging", text)

    def test_no_alerts_or_complete_credentials_pass(self) -> None:
        check_alert_credentials(_env(AlertsConfig()), None)
        check_alert_credentials(_env(_ON), "sha")


class AlertsWarningTests(unittest.TestCase):
    def test_absent_alerts_warn_and_present_ones_do_not(self) -> None:
        warning = alerts_warning(_env(AlertsConfig()))
        self.assertIsNotNone(warning)
        assert warning is not None
        self.assertTrue(warning.startswith("! "))
        self.assertIn("[alerts]", warning)
        self.assertEqual(len(warning.splitlines()), 1)
        self.assertIsNone(alerts_warning(_env(_ON)))

    def test_an_environment_is_told_where_its_recipients_go(self) -> None:
        warning = alerts_warning(replace(_env(AlertsConfig()), name="staging")) or ""
        self.assertIn("staging", warning)


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class AlertsWarningCliTests(unittest.TestCase):
    def test_up_plan_without_alerts_warns_once_on_stderr(self) -> None:
        """Absent [alerts] is a warning, never a refusal -- and on stderr, so
        the plan on stdout stays byte-identical for today's projects."""
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            _script_observe(server)
            stdout, stderr = io.StringIO(), io.StringIO()

            with _cli(server, identity):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    main_argv = ["--infra-dir", str(infra_dir), "up", "--plan"]
                    from stackbase.__main__ import main

                    main(main_argv)

            warnings = [line for line in stderr.getvalue().splitlines() if "[alerts]" in line]
            self.assertEqual(len(warnings), 1, stderr.getvalue())
            self.assertNotIn("[alerts]", stdout.getvalue())
            self.assertIn("would do:", stdout.getvalue())

    def test_up_plan_with_alerts_and_no_smtp_keys_is_refused(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            with (infra_dir / "stack.toml").open("a", encoding="utf-8") as f:
                f.write('\n[alerts]\nto = ["ops@example.org"]\n')
            _script_observe(server)
            stderr = io.StringIO()

            with _cli(server, identity) as (ssh_class, execute):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                    from stackbase.__main__ import main

                    with self.assertRaises(SystemExit) as caught:
                        main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertEqual(caught.exception.code, 1)
            self.assertIn("smtp_password", stderr.getvalue())
            ssh_class.assert_not_called()
            execute.assert_not_called()


class AlertEnvPlanTests(unittest.TestCase):
    def _observed(self, sha: str | None, *, rev: str = _REV):
        base = _converged_observed(rev=rev)
        return replace(base, local=replace(base.local, alert_env_sha=sha))

    def test_local_facts_digests_the_smtp_credentials_only_when_alerts_are_on(self) -> None:
        odd = {**_SMTP_SECRETS, "smtp_password": "a$(id) b"}
        with Infra() as infra_dir:
            sha = local_facts(infra_dir, _SMTP_SECRETS, env=_env(_ON)).alert_env_sha
            self.assertEqual(sha, alert_env_digest(alert_env_content(_SMTP_SECRETS) or ""))
            self.assertIsNone(local_facts(infra_dir, {"hostinger_token": "h"}, env=_env(_ON)).alert_env_sha)
            # No [alerts]: a stray smtp_* value is neither validated nor rendered.
            for env in (_env(AlertsConfig()), None):
                self.assertIsNone(local_facts(infra_dir, odd, env=env).alert_env_sha)
            with self.assertRaises(StackError):
                local_facts(infra_dir, odd, env=_env(_ON))

    def test_no_alerts_table_plans_nothing_even_with_credentials(self) -> None:
        steps = plan(_config(), _converged_state(), self._observed("sha"), env=_env(AlertsConfig()))
        self.assertEqual(steps, [])

    def test_alerts_on_with_credentials_and_no_recorded_sha_plans_the_step(self) -> None:
        steps = plan(_config(), _converged_state(), self._observed("sha"), env=_env(_ON))
        self.assertEqual(steps, [Step(Action.ENSURE_ALERT_ENV, "a")])

    def test_the_credentials_land_before_the_rebuild_that_starts_nullmailer(self) -> None:
        """nullmailer's remotes are rendered from alert.env at start; without
        the file that unit fails, and a unit that fails fails the `switch`."""
        steps = plan(_config(), _converged_state(rev="old-rev"), self._observed("sha"), env=_env(_ON))
        self.assertEqual(
            [s.action for s in steps], [Action.ENSURE_ALERT_ENV, Action.PUSH_CONFIG, Action.REBUILD]
        )

    def test_a_matching_recorded_sha_plans_nothing(self) -> None:
        state = _converged_state()
        state.nodes["a"].alert_env_sha = "sha"
        self.assertEqual(plan(_config(), state, self._observed("sha"), env=_env(_ON)), [])

    def test_the_step_description_carries_no_content(self) -> None:
        step = Step(Action.ENSURE_ALERT_ENV, "a")
        self.assertEqual(step.description, "node a: updating the alert mail credentials on the server")
        self.assertEqual(render_description(step, has_cloudflare_token=True), step.description)


class EnsureAlertEnvTests(unittest.TestCase):
    _DIR_CMD = "set -eu; install -d -m 0750 /var/lib/stackbase"
    _TMP_CMD = "set -eu; install -m 0600 -o root -g root /dev/null /var/lib/stackbase/alert.env.new"
    _CAT_CMD = "set -eu; cat > /var/lib/stackbase/alert.env.new"
    _MV_CMD = "set -eu; mv -f /var/lib/stackbase/alert.env.new /var/lib/stackbase/alert.env"
    _RESTART_CMD = (
        "set -eu; if systemctl is-active --quiet stackbase-alert-remotes.service "
        "|| systemctl is-failed --quiet stackbase-alert-remotes.service; "
        "then systemctl restart stackbase-alert-remotes.service; fi"
    )
    _COMMANDS = (_DIR_CMD, _TMP_CMD, _CAT_CMD, _MV_CMD, _RESTART_CMD)

    def _ctx(self, infra_dir, *, failing: str | None = None, secrets=None):
        def handler(argv, kwargs):
            if not argv or argv[0] != "ssh" or argv[-1] not in self._COMMANDS:
                return None
            if argv[-1] == failing:
                return _cp(argv, returncode=1, stderr="no space left on device\n")
            return _cp(argv, returncode=0)

        return _context(
            infra_dir,
            state=StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)}),
            secrets={"hostinger_token": "htok", "cloudflare_token": "ctok", **(secrets or _SMTP_SECRETS)},
            runner=FakeRunner(handler=handler),
            env=_env(_ON),
        )

    def test_pushes_root_only_through_stdin_then_rerenders_the_relay(self) -> None:
        with Infra() as infra_dir:
            ctx, lines = self._ctx(infra_dir)

            apply([Step(Action.ENSURE_ALERT_ENV, "a")], ctx, allow_purchase=False)

            commands = [c["argv"][-1] for c in ctx.runner.calls if c["argv"][0] == "ssh"]
            self.assertEqual(commands, list(self._COMMANDS))
            cat_call = next(c for c in ctx.runner.calls if c["argv"][-1] == self._CAT_CMD)
            self.assertEqual(cat_call["kwargs"].get("input"), alert_env_content(_SMTP_SECRETS))
            for call in ctx.runner.calls:
                self.assertNotIn(_PASSWORD, " ".join(call["argv"]))
            for line in lines:
                self.assertNotIn(_PASSWORD, line)
            self.assertTrue(any("alert mail credentials updated" in line for line in lines), lines)
            self.assertEqual(
                ctx.state.nodes["a"].alert_env_sha, alert_env_digest(alert_env_content(_SMTP_SECRETS) or "")
            )
            on_disk = (infra_dir / "stack.state.json").read_text(encoding="utf-8")
            self.assertNotIn(_PASSWORD, on_disk)

    def test_a_failing_mv_leaves_the_sha_unset(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, failing=self._MV_CMD)

            with self.assertRaises(StackError):
                apply([Step(Action.ENSURE_ALERT_ENV, "a")], ctx, allow_purchase=False)

            self.assertIsNone(ctx.state.nodes["a"].alert_env_sha)

    def test_incomplete_credentials_are_refused_before_any_ssh_call(self) -> None:
        with Infra() as infra_dir:
            ctx, _ = self._ctx(infra_dir, secrets={"smtp_host": "mail.example.org"})
            with self.assertRaises(StackError):
                apply([Step(Action.ENSURE_ALERT_ENV, "a")], ctx, allow_purchase=False)
            self.assertEqual(ctx.runner.calls, [])


class AlertStateFileTests(unittest.TestCase):
    def test_an_unset_alert_sha_is_not_written_so_old_state_files_stay_byte_identical(self) -> None:
        with Infra() as infra_dir:
            env = _config().env(None)
            save_state(infra_dir, env, StackState(nodes={"a": NodeState(vps_id=1)}))
            node = json.loads((infra_dir / "stack.state.json").read_text(encoding="utf-8"))["nodes"]["a"]
            self.assertNotIn("alert_env_sha", node)

            save_state(infra_dir, env, StackState(nodes={"a": NodeState(vps_id=1, alert_env_sha="x")}))
            self.assertEqual(load_state(infra_dir, env).nodes["a"].alert_env_sha, "x")


_STACK_TOML = """\
project    = "acme"
domain     = "acme.example.com"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[backups]
enabled = false

[logs]
enabled = false

[alerts]
to = ["ops@example.org", "servers.acme@example.org"]

[nodes.a]
role   = "primary"
vps_id = 1

[nodes.b]
role = "replica"
vps_id = 2
"""


def _infra(tmp: Path, toml: str = _STACK_TOML) -> Path:
    infra_dir = tmp / "infra"
    (infra_dir / "keys").mkdir(parents=True)
    (infra_dir / "stack.toml").write_text(toml, encoding="utf-8")
    (infra_dir / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTemplateEval matt@laptop\n", encoding="utf-8"
    )
    (infra_dir / "stack.state.json").write_text(
        json.dumps({"version": 1, "nodes": {"a": {"ipv4": "1.2.3.4"}, "b": {"ipv4": "5.6.7.8"}}}),
        encoding="utf-8",
    )
    (infra_dir / "known_hosts").write_text("", encoding="utf-8")
    return infra_dir


class RunAlertTestTests(unittest.TestCase):
    def test_it_fails_a_unit_on_every_node_then_says_where_to_look(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="queued\n")
            popen.script(returncode=0, output="queued\n")
            lines: list[str] = []

            run_alert_test(infra_dir, runner=FakeRunner(), popen=popen, emit=lines.append)

            self.assertEqual([call["argv"][-1] for call in popen.calls], [ALERT_TEST_COMMAND] * 2)
            self.assertTrue(all("root@" in " ".join(call["argv"]) for call in popen.calls))
            self.assertEqual(lines[-1], "sent — check ops@example.org, servers.acme@example.org")

    def test_a_failed_handler_names_the_journal_command(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=1, output="the alert handler failed\n")

            with self.assertRaises(StackError) as caught:
                run_alert_test(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("journalctl", f"{caught.exception} {caught.exception.hint}")

    def test_a_project_without_alerts_says_so_before_any_ssh(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp), _STACK_TOML.replace(
                '[alerts]\nto = ["ops@example.org", "servers.acme@example.org"]\n', ""
            ))
            popen = FakePopen()

            with self.assertRaises(StackError) as caught:
                run_alert_test(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("[alerts]", f"{caught.exception} {caught.exception.hint}")
            self.assertEqual(popen.calls, [])

    def test_a_node_with_no_recorded_address_says_to_run_up_first(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            (infra_dir / "stack.state.json").write_text(json.dumps({"version": 1, "nodes": {}}), encoding="utf-8")
            popen = FakePopen()

            with self.assertRaises(StackError) as caught:
                run_alert_test(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("run `up` first", str(caught.exception))
            self.assertEqual(popen.calls, [])


if __name__ == "__main__":
    unittest.main()
