"""End-to-end tests for `python3 -m stackbase`, against fakes only.

These drive `main()` the way a terminal would -- a real `infra/` directory
with a real age-encrypted `secrets.age` -- with both REST APIs pointed at
`FakeServer`. They exist mainly to pin down two promises the rest of the
suite can only test in pieces: `--plan` writes nothing anywhere, and a
failure is one redacted line plus exit code 1.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.__main__ import _NO_CLOUDFLARE_WARNING, main
from stackbase.cloudflare import CloudflareClient
from stackbase.errors import StackError
from stackbase.hostinger import HostingerClient
from tests.fakes import FakeServer

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None

_DOMAIN = "acme.example.com"
_IPV4 = "1.2.3.4"
_VPS_ID = 1984476
_HOSTINGER_TOKEN = "hostinger-token-vcTb2Q"
_CLOUDFLARE_TOKEN = "cloudflare-token-9mKz1L"

_STACK_TOML = f"""\
project    = "acme"
domain     = "{_DOMAIN}"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[nodes.a]
role   = "primary"
vps_id = {_VPS_ID}
"""

_LOCK = {
    "nodes": {
        "root": {"inputs": {"stack-base": "stack-base"}},
        "stack-base": {
            "locked": {"type": "github", "owner": "matiboy", "repo": "stack-base", "rev": "c0ffee" * 6},
        },
    },
    "root": "root",
    "version": 7,
}


def _project(
    root: Path, *, cloudflare_token: str | None = _CLOUDFLARE_TOKEN, app_env: str | None = None
) -> tuple[Path, Path]:
    """Build an infra/ directory with a real encrypted secrets.age.

    `cloudflare_token=None` omits "cloudflare_token" from the secrets payload
    entirely (Task 7b: Cloudflare is optional -- absent, not just empty, is
    the normal way an operator would create secrets.age without one).

    `app_env`, when given, is stored as the "app_env" secret -- used to prove
    each individual app_env line VALUE is masked (via
    `reconcile.redaction_values`), not just the whole blob (P5, Fix round 1).

    Returns `(infra_dir, age_identity)`.
    """
    infra_dir = root / "infra"
    (infra_dir / "keys").mkdir(parents=True)
    (infra_dir / "stack.toml").write_text(_STACK_TOML, encoding="utf-8")
    (infra_dir / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForCliTests matt@laptop\n", encoding="utf-8"
    )
    (infra_dir / "flake.lock").write_text(json.dumps(_LOCK), encoding="utf-8")

    identity = root / "key.txt"
    subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True)
    public_key = subprocess.run(
        ["age-keygen", "-y", str(identity)], capture_output=True, text=True, check=True
    ).stdout.strip()
    (infra_dir / "age-recipients.txt").write_text(public_key + "\n", encoding="utf-8")

    secrets: dict[str, str] = {"hostinger_token": _HOSTINGER_TOKEN}
    if cloudflare_token is not None:
        secrets["cloudflare_token"] = cloudflare_token
    if app_env is not None:
        secrets["app_env"] = app_env
    payload = json.dumps(secrets)
    subprocess.run(
        ["age", "-R", str(infra_dir / "age-recipients.txt"), "-o", str(infra_dir / "secrets.age")],
        input=payload.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    return infra_dir, identity


def _meta(total: int) -> dict:
    return {"current_page": 1, "per_page": 20, "total": total}


def _cf(result, *, result_info=None) -> dict:
    body = {"success": True, "errors": [], "result": result}
    if result_info is not None:
        body["result_info"] = result_info
    return body


_PAGE = {"page": 1, "per_page": 20, "count": 1, "total_count": 1, "total_pages": 1}


def _script_observe(server: FakeServer) -> None:
    """A node that exists and is running, but nothing else set up yet."""
    server.script(
        "GET",
        f"/api/vps/v1/virtual-machines/{_VPS_ID}",
        200,
        {
            "id": _VPS_ID,
            "state": "running",
            "actions_lock": "unlocked",
            "firewall_group_id": None,
            "ipv4": [{"id": 1, "address": _IPV4}],
            "ipv6": None,
        },
    )
    server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
    server.script("GET", "/api/vps/v1/firewall?page=1", 200, {"data": [], "meta": _meta(0)})
    server.script("GET", f"/zones?name={_DOMAIN}&page=1", 200, _cf([{"id": "zone1", "name": _DOMAIN}], result_info=_PAGE))
    server.script("GET", f"/zones/zone1/dns_records?type=A&name={_DOMAIN}&page=1", 200, _cf([], result_info=_PAGE))


@contextlib.contextmanager
def _cli(server: FakeServer, identity: Path):
    """Point both clients at the fake server and watch for any step running."""
    with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
        os.environ.pop("STACKBASE_SRC", None)
        with (
            mock.patch("stackbase.__main__.HostingerClient", lambda token: HostingerClient(token, base_url=server.url)),
            mock.patch("stackbase.__main__.CloudflareClient", lambda token: CloudflareClient(token, base_url=server.url)),
            mock.patch("stackbase.reconcile.Ssh") as ssh_class,
            mock.patch("stackbase.steps.execute") as execute,
        ):
            yield ssh_class, execute


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class PlanTests(unittest.TestCase):
    def test_plan_issues_only_get_requests_and_runs_no_commands(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            _script_observe(server)
            stdout = io.StringIO()

            with _cli(server, identity) as (ssh_class, execute):
                with contextlib.redirect_stdout(stdout):
                    main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertEqual({request["method"] for request in server.requests}, {"GET"})
            ssh_class.assert_not_called()
            execute.assert_not_called()

    def test_plan_prints_numbered_plain_english_steps(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            _script_observe(server)
            stdout = io.StringIO()

            with _cli(server, identity):
                with contextlib.redirect_stdout(stdout):
                    main(["--infra-dir", str(infra_dir), "up", "--plan"])

            output = stdout.getvalue()
            self.assertIn("would do:", output)
            self.assertIn("1. registering the team's SSH keys with Hostinger", output)
            self.assertIn("node a: rebuilding NixOS", output)
            self.assertNotIn(_HOSTINGER_TOKEN, output)

    def test_plan_writes_nothing_to_the_infra_directory(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            _script_observe(server)
            before = {path: path.read_bytes() for path in infra_dir.rglob("*") if path.is_file()}

            with _cli(server, identity):
                with contextlib.redirect_stdout(io.StringIO()):
                    main(["--infra-dir", str(infra_dir), "up", "--plan"])

            after = {path: path.read_bytes() for path in infra_dir.rglob("*") if path.is_file()}
            self.assertEqual(after, before)


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class ConvergedStackTests(unittest.TestCase):
    """The headline guarantee: a stack that is already right does nothing."""

    def _converge(self, root: Path, identity: Path, infra_dir: Path) -> None:
        from stackbase.reconcile import local_facts

        (infra_dir / "known_hosts").write_text(f"{_IPV4} ssh-ed25519 AAAAhostkey\n", encoding="utf-8")
        (infra_dir / "nodes" / "a").mkdir(parents=True)
        (infra_dir / "nodes" / "a" / "hardware-configuration.nix").write_text("{ }\n", encoding="utf-8")

        payload = json.dumps(
            {
                "hostinger_token": _HOSTINGER_TOKEN,
                "cloudflare_token": _CLOUDFLARE_TOKEN,
                "origin_cert": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
                "origin_key": "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n",
            }
        )
        subprocess.run(
            ["age", "-R", str(infra_dir / "age-recipients.txt"), "-o", str(infra_dir / "secrets.age")],
            input=payload.encode("utf-8"),
            capture_output=True,
            check=True,
        )

        # stack.state.json and known_hosts are excluded from the rev on
        # purpose, so the rev can be computed before the state file exists.
        rev = local_facts(infra_dir, {}).desired_rev
        (infra_dir / "stack.state.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "nodes": {
                        "a": {
                            "vps_id": _VPS_ID,
                            "ipv4": _IPV4,
                            "ipv6": None,
                            "host_key_pinned": True,
                            "hardware_captured": True,
                            "applied_rev": rev,
                        }
                    },
                    "cloudflare": {"zone_id": "zone1", "record_id": "rec1"},
                    "hostinger": {"firewall_id": 7, "ssh_key_ids": {"matt": 11}},
                }
            ),
            encoding="utf-8",
        )

    def _script_converged(self, server: FakeServer, infra_dir: Path) -> None:
        server.script(
            "GET",
            f"/api/vps/v1/virtual-machines/{_VPS_ID}",
            200,
            {
                "id": _VPS_ID,
                "state": "running",
                "actions_lock": "unlocked",
                "firewall_group_id": 7,
                "ipv4": [{"id": 1, "address": _IPV4}],
                "ipv6": None,
            },
        )
        key = (infra_dir / "keys" / "matt.pub").read_text(encoding="utf-8").strip()
        server.script(
            "GET", "/api/vps/v1/public-keys?page=1", 200,
            {"data": [{"id": 11, "name": "matt", "key": key}], "meta": _meta(1)},
        )
        server.script(
            "GET", "/api/vps/v1/firewall?page=1", 200,
            {
                "data": [
                    {
                        "id": 7,
                        "name": "stackbase-acme",
                        "rules": [
                            {"id": 1, "protocol": "TCP", "port": "22", "source": "any", "source_detail": "any"},
                            {"id": 2, "protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"},
                        ],
                    }
                ],
                "meta": _meta(1),
            },
        )
        server.script("GET", f"/zones?name={_DOMAIN}&page=1", 200, _cf([{"id": "zone1", "name": _DOMAIN}], result_info=_PAGE))
        server.script(
            "GET", f"/zones/zone1/dns_records?type=A&name={_DOMAIN}&page=1", 200,
            _cf([{"id": "rec1", "type": "A", "name": _DOMAIN, "content": _IPV4, "proxied": True}], result_info=_PAGE),
        )

    def test_a_converged_stack_prints_nothing_to_do_and_exits_0(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            self._converge(Path(tmp), identity, infra_dir)
            self._script_converged(server, infra_dir)
            stdout = io.StringIO()

            # A missing cloudflare-ips.nix skips that check silently (Finding
            # i) -- keeps this test's "nothing to do" output exact regardless
            # of what the real snapshot file currently contains.
            #
            # check_infra_clean is mocked out here too: this test's infra_dir
            # is a bare TemporaryDirectory, not a git checkout, so the real
            # guard would print its "not inside a git repository" warning
            # line and break the exact "nothing to do" assertion below --
            # that guard is covered on its own in CheckInfraCleanTests and
            # AllowDirtyTests, not here.
            with (
                mock.patch(
                    "stackbase.reconcile._cloudflare_ips_path", return_value=Path(tmp) / "no-such-file.nix"
                ),
                mock.patch("stackbase.__main__.check_infra_clean"),
            ):
                with _cli(server, identity) as (ssh_class, execute):
                    with contextlib.redirect_stdout(stdout):
                        main(["--infra-dir", str(infra_dir), "up"])

            self.assertEqual(stdout.getvalue().strip(), "nothing to do")
            execute.assert_not_called()
            ssh_class.assert_not_called()
            self.assertEqual({request["method"] for request in server.requests}, {"GET"})


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class FailureTests(unittest.TestCase):
    def test_a_failure_is_one_redacted_line_and_exit_code_1(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            # Nothing scripted: the very first GET comes back 500, and the
            # fake echoes the token back in the body to prove it gets masked.
            server.script(
                "GET",
                f"/api/vps/v1/virtual-machines/{_VPS_ID}",
                500,
                {"message": f"token {_HOSTINGER_TOKEN} is unhappy"},
            )
            stderr = io.StringIO()

            with _cli(server, identity):
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                    main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertEqual(caught.exception.code, 1)
            line = stderr.getvalue().strip()
            self.assertEqual(len(line.splitlines()), 1, f"expected one line, got: {line}")
            self.assertTrue(line.startswith("error: "))
            self.assertIn(" — ", line)
            self.assertNotIn(_HOSTINGER_TOKEN, line)
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_debug_prints_a_traceback_but_never_a_secret(self) -> None:
        """--debug must not be a way to see the tokens in cleartext.

        A StackError routinely carries text that came back from somewhere
        else -- a remote command's stderr, an API error body -- and that text
        can contain a token. A redacted one-line summary is no use if the raw
        traceback printed just above it shows the same string unmasked.
        """
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            leaky = StackError(
                f"command failed on the node: echo {_HOSTINGER_TOKEN}",
                f"stderr said: {_HOSTINGER_TOKEN}",
            )
            stdout, stderr = io.StringIO(), io.StringIO()

            with _cli(server, identity):
                with mock.patch("stackbase.__main__.observe", side_effect=leaky):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "up", "--plan", "--debug"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertNotIn(_HOSTINGER_TOKEN, everything)
            self.assertIn("***REDACTED***", everything)

    def test_debug_redacts_the_traceback_of_the_api_failure_fixture_too(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            server.script(
                "GET",
                f"/api/vps/v1/virtual-machines/{_VPS_ID}",
                500,
                {"message": f"token {_HOSTINGER_TOKEN} is unhappy"},
            )
            stdout, stderr = io.StringIO(), io.StringIO()

            with _cli(server, identity):
                with (
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                    self.assertRaises(SystemExit),
                ):
                    main(["--infra-dir", str(infra_dir), "up", "--plan", "--debug"])

            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertNotIn(_HOSTINGER_TOKEN, everything)

    def test_an_unexpected_exception_is_one_redacted_line_without_debug(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            boom = RuntimeError(f"internal wobble involving {_CLOUDFLARE_TOKEN}")
            stdout, stderr = io.StringIO(), io.StringIO()

            with _cli(server, identity):
                with mock.patch("stackbase.__main__.observe", side_effect=boom):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(_CLOUDFLARE_TOKEN, everything)
            self.assertNotIn("Traceback", everything)
            line = stderr.getvalue().strip()
            self.assertEqual(len(line.splitlines()), 1, f"expected one line, got: {line}")
            self.assertIn("RuntimeError", line)
            self.assertIn("--debug", line)

    def test_an_unexpected_exception_with_debug_prints_a_redacted_traceback(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            boom = RuntimeError(f"internal wobble involving {_CLOUDFLARE_TOKEN}")
            stdout, stderr = io.StringIO(), io.StringIO()

            with _cli(server, identity):
                with mock.patch("stackbase.__main__.observe", side_effect=boom):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit),
                    ):
                        main(["--infra-dir", str(infra_dir), "up", "--plan", "--debug"])

            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertIn("RuntimeError", everything)
            self.assertNotIn(_CLOUDFLARE_TOKEN, everything)

    def test_an_unexpected_failure_before_the_secrets_load_still_reports_cleanly(self) -> None:
        """Nothing is known to redact yet -- that must not itself blow up."""
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            stderr = io.StringIO()

            with _cli(server, identity):
                with mock.patch("stackbase.__main__.load_config", side_effect=RuntimeError("early")):
                    with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                        main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertEqual(caught.exception.code, 1)
            self.assertIn("RuntimeError", stderr.getvalue())
            self.assertEqual(len(stderr.getvalue().strip().splitlines()), 1)

    def test_an_app_env_line_value_is_masked_on_the_final_error_line(self) -> None:
        """P5, Fix round 1: __main__.py must mask each app_env line VALUE, not
        just the whole app_env blob -- see reconcile.redaction_values.
        """
        app_env_secret = "sess-super-secret-value-1234"
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp), app_env=f"SESSION_SECRET={app_env_secret}\n")
            leaky = StackError(
                f"command failed on the node: echo {app_env_secret}",
                f"stderr said: {app_env_secret}",
            )
            stderr = io.StringIO()

            with _cli(server, identity):
                with mock.patch("stackbase.__main__.observe", side_effect=leaky):
                    with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                        main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertEqual(caught.exception.code, 1)
            line = stderr.getvalue().strip()
            self.assertEqual(len(line.splitlines()), 1, f"expected one line, got: {line}")
            self.assertNotIn(app_env_secret, line)
            self.assertIn("***REDACTED***", line)

    def test_an_app_env_line_value_is_masked_in_the_debug_traceback(self) -> None:
        app_env_secret = "sess-super-secret-value-5678"
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp), app_env=f"SESSION_SECRET={app_env_secret}\n")
            leaky = StackError(
                f"command failed on the node: echo {app_env_secret}",
                f"stderr said: {app_env_secret}",
            )
            stdout, stderr = io.StringIO(), io.StringIO()

            with _cli(server, identity):
                with mock.patch("stackbase.__main__.observe", side_effect=leaky):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "up", "--plan", "--debug"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertNotIn(app_env_secret, everything)
            self.assertIn("***REDACTED***", everything)

    def test_a_missing_secrets_file_names_the_command_that_creates_it(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp))
            (infra_dir / "secrets.age").unlink()
            stderr = io.StringIO()

            with _cli(server, identity):
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                    main(["--infra-dir", str(infra_dir), "up", "--plan"])

            self.assertIn("age -R", stderr.getvalue())
            self.assertIn("hostinger_token", stderr.getvalue())
            self.assertIn("optional", stderr.getvalue())


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class SecretsAndCiSetupFailureRedactionTests(unittest.TestCase):
    """F2, Fix round 1: `ci-setup` and `secrets ...` used to bypass the
    redaction net entirely -- neither fed the values it handled into the
    dict `error_line`/`_print_traceback` mask with, so a future failure (or
    a `--debug` traceback carrying `age`/`gh`/editor stderr) could print a
    secret unmasked. Each test injects a failure whose message echoes a
    sensitive value and asserts it never reaches stdout/stderr, with and
    without `--debug` (a traceback must still appear with `--debug`).
    """

    # -- secrets set: the NEW value, read from stdin but not yet saved ------

    def test_secrets_set_failure_masks_the_new_value_without_debug(self) -> None:
        new_value = "brand-new-cloudflare-token-zzz111"
        with TemporaryDirectory() as tmp:
            infra_dir, identity = _project(Path(tmp))
            stdout, stderr = io.StringIO(), io.StringIO()

            def boom(*_args: object, **_kwargs: object) -> None:
                raise StackError(f"failed to encrypt: {new_value}", f"age stderr said: {new_value}")

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
                with mock.patch("stackbase.secrets_cli.sys.stdin", io.StringIO(new_value)):
                    with mock.patch("stackbase.secrets_cli.save_secrets", side_effect=boom):
                        with (
                            contextlib.redirect_stdout(stdout),
                            contextlib.redirect_stderr(stderr),
                            self.assertRaises(SystemExit) as caught,
                        ):
                            main(["--infra-dir", str(infra_dir), "secrets", "set", "cloudflare_token"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(new_value, everything)
            self.assertIn("***REDACTED***", everything)

    def test_secrets_set_failure_masks_the_new_value_with_debug(self) -> None:
        new_value = "brand-new-cloudflare-token-yyy222"
        with TemporaryDirectory() as tmp:
            infra_dir, identity = _project(Path(tmp))
            stdout, stderr = io.StringIO(), io.StringIO()

            def boom(*_args: object, **_kwargs: object) -> None:
                raise StackError(f"failed to encrypt: {new_value}", f"age stderr said: {new_value}")

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
                with mock.patch("stackbase.secrets_cli.sys.stdin", io.StringIO(new_value)):
                    with mock.patch("stackbase.secrets_cli.save_secrets", side_effect=boom):
                        with (
                            contextlib.redirect_stdout(stdout),
                            contextlib.redirect_stderr(stderr),
                            self.assertRaises(SystemExit) as caught,
                        ):
                            main(["--infra-dir", str(infra_dir), "secrets", "set", "cloudflare_token", "--debug"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertNotIn(new_value, everything)
            self.assertIn("***REDACTED***", everything)

    # -- secrets edit: both the original bundle value and the edited value --

    def _fake_edit_key_leaking(self, original_value: str, new_value: str):
        def fake_edit_key(infra_dir: Path, key: str, *, emit, register_secret) -> None:  # noqa: ANN001
            register_secret(key, original_value)
            register_secret(key, new_value)
            raise StackError(
                f"the editor left something odd behind: {new_value}",
                f"the value used to be: {original_value}",
            )

        return fake_edit_key

    def test_secrets_edit_failure_masks_the_original_and_edited_value_without_debug(self) -> None:
        original_value, new_value = "old-cloudflare-secret-ppp999", "new-cloudflare-secret-qqq111"
        with TemporaryDirectory() as tmp:
            infra_dir, identity = _project(Path(tmp))
            stdout, stderr = io.StringIO(), io.StringIO()

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
                with mock.patch(
                    "stackbase.__main__.edit_key",
                    side_effect=self._fake_edit_key_leaking(original_value, new_value),
                ):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "secrets", "edit", "cloudflare_token"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(original_value, everything)
            self.assertNotIn(new_value, everything)
            self.assertIn("***REDACTED***", everything)

    def test_secrets_edit_failure_masks_the_original_and_edited_value_with_debug(self) -> None:
        original_value, new_value = "old-cloudflare-secret-rrr333", "new-cloudflare-secret-sss444"
        with TemporaryDirectory() as tmp:
            infra_dir, identity = _project(Path(tmp))
            stdout, stderr = io.StringIO(), io.StringIO()

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
                with mock.patch(
                    "stackbase.__main__.edit_key",
                    side_effect=self._fake_edit_key_leaking(original_value, new_value),
                ):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "secrets", "edit", "cloudflare_token", "--debug"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertNotIn(original_value, everything)
            self.assertNotIn(new_value, everything)
            self.assertIn("***REDACTED***", everything)

    # -- ci-setup: a private-key body line -----------------------------------

    def _fake_ci_setup_leaking(self, key_line: str):
        def fake_ci_setup(infra_dir: Path, *, rotate: bool, emit, register_secret) -> None:  # noqa: ANN001
            register_secret(key_line)
            raise StackError(
                f"gh secret set STACK_DEPLOY_KEY failed, stderr echoed: {key_line}",
                "check gh auth status",
            )

        return fake_ci_setup

    def test_ci_setup_failure_masks_a_private_key_body_line_without_debug(self) -> None:
        key_line = "MC4CAQAwBQYDK2VwBCIEIExampleKeyMaterialLeakLine"
        with TemporaryDirectory() as tmp:
            infra_dir, identity = _project(Path(tmp))
            stdout, stderr = io.StringIO(), io.StringIO()

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
                with mock.patch("stackbase.__main__.ci_setup", side_effect=self._fake_ci_setup_leaking(key_line)):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "ci-setup"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertNotIn(key_line, everything)
            self.assertIn("***REDACTED***", everything)

    def test_ci_setup_failure_masks_a_private_key_body_line_with_debug(self) -> None:
        key_line = "MC4CAQAwBQYDK2VwBCIEIAnotherExampleKeyMaterialLine"
        with TemporaryDirectory() as tmp:
            infra_dir, identity = _project(Path(tmp))
            stdout, stderr = io.StringIO(), io.StringIO()

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
                with mock.patch("stackbase.__main__.ci_setup", side_effect=self._fake_ci_setup_leaking(key_line)):
                    with (
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        main(["--infra-dir", str(infra_dir), "ci-setup", "--debug"])

            self.assertEqual(caught.exception.code, 1)
            everything = stdout.getvalue() + stderr.getvalue()
            self.assertIn("Traceback (most recent call last)", everything)
            self.assertNotIn(key_line, everything)
            self.assertIn("***REDACTED***", everything)


@contextlib.contextmanager
def _cli_no_cloudflare(server: FakeServer, identity: Path):
    """Like `_cli`, but also tracks whether CloudflareClient is ever constructed."""
    with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity)}, clear=False):
        os.environ.pop("STACKBASE_SRC", None)
        cloudflare_class = mock.MagicMock(side_effect=lambda token: CloudflareClient(token, base_url=server.url))
        with (
            mock.patch("stackbase.__main__.HostingerClient", lambda token: HostingerClient(token, base_url=server.url)),
            mock.patch("stackbase.__main__.CloudflareClient", cloudflare_class),
            mock.patch("stackbase.reconcile.Ssh") as ssh_class,
            mock.patch("stackbase.steps.execute") as execute,
        ):
            yield ssh_class, execute, cloudflare_class


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class CloudflareOptionalTests(unittest.TestCase):
    """Task 7b change 1, end-to-end: no cloudflare_token in secrets.age."""

    def test_plan_without_a_cloudflare_token_prints_the_warning_and_makes_no_cloudflare_request(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp), cloudflare_token=None)
            server.script(
                "GET",
                f"/api/vps/v1/virtual-machines/{_VPS_ID}",
                200,
                {
                    "id": _VPS_ID,
                    "state": "running",
                    "actions_lock": "unlocked",
                    "firewall_group_id": None,
                    "ipv4": [{"id": 1, "address": _IPV4}],
                    "ipv6": None,
                },
            )
            server.script("GET", "/api/vps/v1/public-keys?page=1", 200, {"data": [], "meta": _meta(0)})
            server.script("GET", "/api/vps/v1/firewall?page=1", 200, {"data": [], "meta": _meta(0)})
            stdout = io.StringIO()

            with _cli_no_cloudflare(server, identity) as (_ssh_class, _execute, cloudflare_class):
                with contextlib.redirect_stdout(stdout):
                    main(["--infra-dir", str(infra_dir), "up", "--plan"])

            cloudflare_class.assert_not_called()
            output = stdout.getvalue()
            self.assertIn(_NO_CLOUDFLARE_WARNING, output)
            self.assertIn("would do:", output)
            paths = [request["path"] for request in server.requests]
            self.assertFalse(
                any("/zones" in p or "dns_records" in p or "/ips" in p for p in paths),
                f"a Cloudflare endpoint was hit with no token: {paths}",
            )

    def test_a_converged_stack_without_cloudflare_prints_the_warning_then_nothing_to_do(self) -> None:
        with TemporaryDirectory() as tmp, FakeServer() as server:
            infra_dir, identity = _project(Path(tmp), cloudflare_token=None)
            (infra_dir / "known_hosts").write_text(f"{_IPV4} ssh-ed25519 AAAAhostkey\n", encoding="utf-8")
            (infra_dir / "nodes" / "a").mkdir(parents=True)
            (infra_dir / "nodes" / "a" / "hardware-configuration.nix").write_text("{ }\n", encoding="utf-8")

            from stackbase.reconcile import local_facts

            rev = local_facts(infra_dir, {}).desired_rev
            (infra_dir / "stack.state.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "nodes": {
                            "a": {
                                "vps_id": _VPS_ID,
                                "ipv4": _IPV4,
                                "ipv6": None,
                                "host_key_pinned": True,
                                "hardware_captured": True,
                                "applied_rev": rev,
                            }
                        },
                        "cloudflare": {"zone_id": None, "record_id": None},
                        "hostinger": {"firewall_id": 7, "ssh_key_ids": {"matt": 11}},
                    }
                ),
                encoding="utf-8",
            )

            server.script(
                "GET",
                f"/api/vps/v1/virtual-machines/{_VPS_ID}",
                200,
                {
                    "id": _VPS_ID,
                    "state": "running",
                    "actions_lock": "unlocked",
                    "firewall_group_id": 7,
                    "ipv4": [{"id": 1, "address": _IPV4}],
                    "ipv6": None,
                },
            )
            key = (infra_dir / "keys" / "matt.pub").read_text(encoding="utf-8").strip()
            server.script(
                "GET",
                "/api/vps/v1/public-keys?page=1",
                200,
                {"data": [{"id": 11, "name": "matt", "key": key}], "meta": _meta(1)},
            )
            server.script(
                "GET",
                "/api/vps/v1/firewall?page=1",
                200,
                {
                    "data": [
                        {
                            "id": 7,
                            "name": "stackbase-acme",
                            "rules": [
                                {"id": 1, "protocol": "TCP", "port": "22", "source": "any", "source_detail": "any"},
                                {"id": 2, "protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"},
                            ],
                        }
                    ],
                    "meta": _meta(1),
                },
            )
            stdout = io.StringIO()

            with _cli_no_cloudflare(server, identity) as (ssh_class, execute, cloudflare_class):
                with contextlib.redirect_stdout(stdout):
                    main(["--infra-dir", str(infra_dir), "up"])

            cloudflare_class.assert_not_called()
            execute.assert_not_called()
            ssh_class.assert_not_called()
            output = stdout.getvalue()
            self.assertIn(_NO_CLOUDFLARE_WARNING, output)
            self.assertTrue(output.strip().endswith("nothing to do"))
            self.assertEqual({request["method"] for request in server.requests}, {"GET"})


@unittest.skipUnless(_AGE_AVAILABLE, "age/age-keygen are not installed")
class SshCommandTests(unittest.TestCase):
    def test_it_execs_ssh_with_the_pinned_known_hosts_file(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir, _identity = _project(Path(tmp))
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {"a": {"vps_id": _VPS_ID, "ipv4": _IPV4}}}), encoding="utf-8"
            )

            with mock.patch("os.execvp") as execvp:
                main(["--infra-dir", str(infra_dir), "ssh", "a", "--", "systemctl", "status", "nginx"])

            argv = execvp.call_args[0][1]
            self.assertEqual(argv[0], "ssh")
            self.assertIn(f"UserKnownHostsFile={infra_dir / 'known_hosts'}", argv)
            self.assertEqual(argv[-4:], [f"root@{_IPV4}", "systemctl", "status", "nginx"])

    def test_an_unknown_node_lists_the_known_ones(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir, _identity = _project(Path(tmp))
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                main(["--infra-dir", str(infra_dir), "ssh", "nope"])

            self.assertIn("known nodes: a", stderr.getvalue())


class CiSetupAndSecretsWiringTests(unittest.TestCase):
    """`ci-setup` and `secrets ...` reach the right module function with the
    right arguments -- the argument-parsing/dispatch wiring in __main__.py,
    not the underlying logic (covered in test_ci.py/test_secrets_cli.py).
    """

    def test_ci_setup_dispatches_with_rotate(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()

            with mock.patch("stackbase.__main__.ci_setup") as ci_setup_mock:
                main(["--infra-dir", str(infra_dir), "ci-setup", "--rotate"])

            self.assertEqual(ci_setup_mock.call_args.args, (infra_dir,))
            self.assertEqual(ci_setup_mock.call_args.kwargs.get("rotate"), True)

    def test_ci_setup_without_rotate_defaults_to_false(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()

            with mock.patch("stackbase.__main__.ci_setup") as ci_setup_mock:
                main(["--infra-dir", str(infra_dir), "ci-setup"])

            self.assertEqual(ci_setup_mock.call_args.kwargs.get("rotate"), False)

    def test_secrets_keys_prints_each_name_on_its_own_line(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            stdout = io.StringIO()

            with mock.patch("stackbase.__main__.list_key_names", return_value=["a_key", "b_key"]):
                with contextlib.redirect_stdout(stdout):
                    main(["--infra-dir", str(infra_dir), "secrets", "keys"])

            self.assertEqual(stdout.getvalue().splitlines(), ["a_key", "b_key"])

    def test_secrets_set_dispatches_with_the_key_argument(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()

            with mock.patch("stackbase.__main__.set_key") as set_key_mock:
                main(["--infra-dir", str(infra_dir), "secrets", "set", "cloudflare_token"])

            self.assertEqual(set_key_mock.call_args.args, (infra_dir, "cloudflare_token"))

    def test_secrets_unset_dispatches_with_the_key_argument(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()

            with mock.patch("stackbase.__main__.unset_key") as unset_key_mock:
                main(["--infra-dir", str(infra_dir), "secrets", "unset", "cloudflare_token"])

            self.assertEqual(unset_key_mock.call_args.args, (infra_dir, "cloudflare_token"))

    def test_secrets_edit_dispatches_with_the_key_argument(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()

            with mock.patch("stackbase.__main__.edit_key") as edit_key_mock:
                main(["--infra-dir", str(infra_dir), "secrets", "edit", "app_env"])

            self.assertEqual(edit_key_mock.call_args.args, (infra_dir, "app_env"))


class DeployKeyCLIWiringTests(unittest.TestCase):
    def test_init_forwards_rotate(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.deploy_key_init") as init_mock:
                main(["--infra-dir", str(infra_dir), "deploy-key", "init", "--rotate"])

            self.assertEqual(init_mock.call_args.args[0], infra_dir)
            self.assertTrue(init_mock.call_args.kwargs["rotate"])

    def test_show_pub_is_wired(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.deploy_key_show_pub") as show_mock:
                main(["--infra-dir", str(infra_dir), "deploy-key", "show-pub"])

            show_mock.assert_called_once()


class BackupNowCLIWiringTests(unittest.TestCase):
    """`backup-now` reaches `backups.run_backup_now` with the node filter and
    a masking emit -- never the restricted `deploy` door (decision 9)."""

    def test_it_forwards_the_infra_dir_and_no_node_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.run_backup_now") as run_mock:
                main(["--infra-dir", str(infra_dir), "backup-now"])

            self.assertEqual(run_mock.call_args.args[0], infra_dir)
            self.assertIsNone(run_mock.call_args.kwargs["node"])
            self.assertTrue(callable(run_mock.call_args.kwargs["emit"]))

    def test_node_is_forwarded(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.run_backup_now") as run_mock:
                main(["--infra-dir", str(infra_dir), "backup-now", "--node", "b"])

            self.assertEqual(run_mock.call_args.kwargs["node"], "b")

    def test_a_failure_is_one_line_and_exit_1(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            stderr = io.StringIO()
            with (
                mock.patch(
                    "stackbase.__main__.run_backup_now",
                    side_effect=StackError("this project has no backup bucket", "add a [backups] section"),
                ),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit) as caught,
            ):
                main(["--infra-dir", str(infra_dir), "backup-now"])

            self.assertEqual(caught.exception.code, 1)
            self.assertEqual(len(stderr.getvalue().strip().splitlines()), 1)
            self.assertIn("no backup bucket", stderr.getvalue())


class AllowDirtyTests(unittest.TestCase):
    def test_up_checks_the_working_tree_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.check_infra_clean") as check_mock,
                mock.patch("stackbase.__main__.load_config"),
                mock.patch("stackbase.__main__.load_state"),
                mock.patch("stackbase.__main__.check_recipients_superset"),
                mock.patch("stackbase.__main__.load_secrets", return_value={"hostinger_token": "t"}),
                mock.patch("stackbase.__main__.observe"),
                mock.patch("stackbase.__main__.plan", return_value=[]),
                mock.patch("stackbase.__main__.local_facts"),
                mock.patch("stackbase.__main__.HostingerClient"),
            ):
                main(["--infra-dir", str(infra_dir), "up"])

            check_mock.assert_called_once()

    def test_allow_dirty_skips_the_check(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.check_infra_clean") as check_mock,
                mock.patch("stackbase.__main__.load_config"),
                mock.patch("stackbase.__main__.load_state"),
                mock.patch("stackbase.__main__.check_recipients_superset"),
                mock.patch("stackbase.__main__.load_secrets", return_value={"hostinger_token": "t"}),
                mock.patch("stackbase.__main__.observe"),
                mock.patch("stackbase.__main__.plan", return_value=[]),
                mock.patch("stackbase.__main__.local_facts"),
                mock.patch("stackbase.__main__.HostingerClient"),
            ):
                main(["--infra-dir", str(infra_dir), "up", "--allow-dirty"])

            check_mock.assert_not_called()

    def test_plan_never_checks_the_working_tree(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.check_infra_clean") as check_mock,
                mock.patch("stackbase.__main__.load_config"),
                mock.patch("stackbase.__main__.load_state"),
                mock.patch("stackbase.__main__.check_recipients_superset"),
                mock.patch("stackbase.__main__.load_secrets", return_value={"hostinger_token": "t"}),
                mock.patch("stackbase.__main__.observe"),
                mock.patch("stackbase.__main__.plan", return_value=[]),
                mock.patch("stackbase.__main__.local_facts"),
                mock.patch("stackbase.__main__.HostingerClient"),
            ):
                main(["--infra-dir", str(infra_dir), "up", "--plan"])

            check_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
