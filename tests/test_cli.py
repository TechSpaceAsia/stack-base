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

from stackbase.__main__ import main
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


def _project(root: Path) -> tuple[Path, Path]:
    """Build an infra/ directory with a real encrypted secrets.age.

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

    payload = json.dumps({"hostinger_token": _HOSTINGER_TOKEN, "cloudflare_token": _CLOUDFLARE_TOKEN})
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
            with mock.patch(
                "stackbase.reconcile._cloudflare_ips_path", return_value=Path(tmp) / "no-such-file.nix"
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


if __name__ == "__main__":
    unittest.main()
