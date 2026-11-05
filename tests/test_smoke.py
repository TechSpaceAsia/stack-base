"""`smoke`: every node serves the release, the public URL answers, and the
project's own `infra/smoke` passes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.__main__ import main
from stackbase.errors import StackError
from stackbase.smoke import check_public, run_project_script, run_smoke
from tests.fakes import FakePopen

_TOML = """project    = "acme"
domain     = "acme.example.com"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[nodes.a]
role   = "primary"
vps_id = 1

[nodes.b]
role   = "replica"
vps_id = 2
"""


def _project(root: Path, *, extra_toml: str = "") -> Path:
    infra_dir = root / "infra"
    (infra_dir / "keys").mkdir(parents=True)
    (infra_dir / "stack.toml").write_text(_TOML + extra_toml, encoding="utf-8")
    (infra_dir / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample matt@laptop\n", encoding="utf-8"
    )
    (infra_dir / "stack.state.json").write_text(
        json.dumps({"version": 1, "nodes": {"a": {"ipv4": "10.0.0.1"}, "b": {"ipv4": "10.0.0.2"}}}),
        encoding="utf-8",
    )
    return infra_dir


@contextlib.contextmanager
def _no_identity(*_args, **_kwargs):
    yield


class _Response:
    def __init__(self, status: int, url: str) -> None:
        self.status = status
        self._url = url

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class _Opener:
    """Answers each call with the next scripted result (a _Response or an exception)."""

    def __init__(self, *results: object) -> None:
        self.results = list(results)
        self.requests: list[object] = []

    def __call__(self, request, timeout):  # noqa: ANN001 - urllib's signature
        self.requests.append(request)
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


_URL = "https://acme.example.com/health"


class CheckPublicTests(unittest.TestCase):
    def test_a_200_at_the_same_url_passes_first_time(self) -> None:
        opener = _Opener(_Response(200, _URL))
        check_public(_URL, opener=opener, sleep=lambda _s: None)
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(opener.requests[0].get_header("User-agent").startswith("stack-base-smoke/"))

    def test_it_retries_until_the_edge_serves_the_release(self) -> None:
        sleeps: list[float] = []
        opener = _Opener(urllib.error.HTTPError(_URL, 502, "Bad Gateway", {}, None), _Response(200, _URL))
        check_public(_URL, opener=opener, sleep=sleeps.append, delay=3)
        self.assertEqual(sleeps, [3])

    def test_a_redirect_elsewhere_is_not_a_pass(self) -> None:
        opener = _Opener(*[_Response(200, "https://acme.example.com/login") for _ in range(2)])
        with self.assertRaises(StackError) as caught:
            check_public(_URL, opener=opener, sleep=lambda _s: None, tries=2)
        self.assertIn("redirected to https://acme.example.com/login", caught.exception.message)

    def test_it_gives_up_with_the_last_failure(self) -> None:
        opener = _Opener(*[urllib.error.URLError("Name or service not known") for _ in range(3)])
        with self.assertRaises(StackError) as caught:
            check_public(_URL, opener=opener, sleep=lambda _s: None, tries=3)
        self.assertIn("after 3 tries", caught.exception.message)
        self.assertIn("Name or service not known", caught.exception.message)


class ProjectScriptTests(unittest.TestCase):
    def _script(self, root: Path, body: str, *, executable: bool = True) -> Path:
        script = root / "infra" / "smoke"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        script.chmod(0o755 if executable else 0o644)
        return script

    def test_it_gets_the_url_version_and_env_and_runs_from_the_repo_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._script(root, 'printf "%s %s %s %s" "$SMOKE_BASE_URL" "$SMOKE_VERSION" "$SMOKE_ENV" "$PWD" > out\n')
            run_project_script(
                root, script, base_url="https://acme.example.com", version="v1.2.3", env_name="staging"
            )
            self.assertEqual(
                (root / "out").read_text(encoding="utf-8"),
                f"https://acme.example.com v1.2.3 staging {root.resolve()}",
            )

    def test_a_non_zero_exit_fails(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._script(root, "exit 4\n")
            with self.assertRaises(StackError) as caught:
                run_project_script(root, script, base_url="https://x", version="v1.0.0", env_name="")
            self.assertIn("failed (exit 4)", caught.exception.message)

    def test_a_script_that_is_not_executable_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._script(root, "exit 0\n", executable=False)
            with self.assertRaises(StackError) as caught:
                run_project_script(root, script, base_url="https://x", version="v1.0.0", env_name="")
            self.assertIn("chmod +x", caught.exception.hint)

    def test_a_script_that_hangs_is_stopped(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._script(root, "exit 0\n")

            def runner(*_args, **_kwargs):
                raise subprocess.TimeoutExpired(cmd=str(script), timeout=600)

            with self.assertRaises(StackError) as caught:
                run_project_script(root, script, base_url="https://x", version="v1.0.0", env_name="", runner=runner)
            self.assertIn("longer than 600s", caught.exception.message)


class RunSmokeTests(unittest.TestCase):
    def _run(self, infra_dir: Path, popen: FakePopen, opener: _Opener, **kwargs) -> list[str]:
        lines: list[str] = []
        with mock.patch("stackbase.smoke.deploy_identity", _no_identity):
            run_smoke(infra_dir, "v1.2.3", popen=popen, emit=lines.append, opener=opener, sleep=lambda _s: None, **kwargs)
        return lines

    def _popen(self, *outputs: str) -> FakePopen:
        popen = FakePopen()
        for output in outputs:
            popen.script(returncode=0, output=output)
        return popen

    def test_it_passes_when_every_node_serves_the_version_and_the_site_answers(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp))
            popen = self._popen("active=blue (v1.2.3)  idle=green (v1.2.2)\n", "active=green (v1.2.3)  idle=blue (-)\n")
            opener = _Opener(_Response(200, _URL))

            lines = self._run(infra_dir, popen, opener)

            self.assertEqual([call["argv"][-1] for call in popen.calls], ["status", "status"])
            self.assertEqual(opener.requests[0].full_url, _URL)
            self.assertEqual(lines[-1], "✓ smoke test passed: v1.2.3")

    def test_a_node_on_another_release_fails_before_the_public_check(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp))
            popen = self._popen("active=blue (v1.2.3)  idle=green (v1.2.2)\n", "active=green (v1.2.2)  idle=blue (-)\n")
            opener = _Opener()

            with self.assertRaises(StackError) as caught:
                self._run(infra_dir, popen, opener)

            self.assertIn("b serves v1.2.2", caught.exception.message)
            self.assertIn("./infra/up rollback", caught.exception.hint)
            self.assertIn("nothing was rolled back", caught.exception.hint)
            self.assertEqual(opener.requests, [])

    def test_a_node_with_no_release_is_named(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp))
            popen = self._popen("active=blue (v1.2.3)\n", "active=none (-)  idle=blue (-)\n")
            with self.assertRaises(StackError) as caught:
                self._run(infra_dir, popen, _Opener())
            self.assertIn("b serves nothing", caught.exception.message)

    def test_the_health_path_override_is_used(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp), extra_toml='\n[app]\nhealth_path = "/up"\n')
            popen = self._popen("active=blue (v1.2.3)\n", "active=blue (v1.2.3)\n")
            opener = _Opener(_Response(200, "https://acme.example.com/up"))
            self._run(infra_dir, popen, opener)
            self.assertEqual(opener.requests[0].full_url, "https://acme.example.com/up")

    def test_smoke_public_false_skips_the_public_check_and_says_so(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp), extra_toml="\n[app]\nsmoke_public = false\n")
            popen = self._popen("active=blue (v1.2.3)\n", "active=blue (v1.2.3)\n")
            opener = _Opener()
            lines = self._run(infra_dir, popen, opener)
            self.assertEqual(opener.requests, [])
            self.assertTrue(any("smoke_public = false" in line for line in lines))

    def test_the_project_script_runs_last_and_its_failure_fails_the_smoke_test(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp))
            script = infra_dir / "smoke"
            script.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            script.chmod(0o755)
            popen = self._popen("active=blue (v1.2.3)\n", "active=blue (v1.2.3)\n")
            with self.assertRaises(StackError) as caught:
                self._run(infra_dir, popen, _Opener(_Response(200, _URL)))
            self.assertIn("infra/smoke failed (exit 1)", caught.exception.message)

    def test_a_malformed_version_is_refused_before_any_ssh(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _project(Path(tmp))
            popen = FakePopen()
            with self.assertRaises(StackError):
                run_smoke(infra_dir, "1.2.3", popen=popen, emit=lambda _l: None, opener=_Opener())
            self.assertEqual(popen.calls, [])


class SmokeCliTests(unittest.TestCase):
    def test_smoke_forwards_version_and_env_and_never_decrypts_project_secrets(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.run_smoke") as run_smoke_mock,
                mock.patch("stackbase.__main__.load_secrets") as load_secrets_mock,
            ):
                main(["--infra-dir", str(infra_dir), "smoke", "v1.2.3"])

            load_secrets_mock.assert_not_called()
            self.assertEqual(run_smoke_mock.call_args.args[1], "v1.2.3")
            self.assertIsNone(run_smoke_mock.call_args.kwargs["env"])

    def test_smoke_takes_env_after_the_subcommand(self) -> None:
        parser_help = io.StringIO()
        with contextlib.redirect_stdout(parser_help), self.assertRaises(SystemExit):
            main(["smoke", "--help"])
        self.assertIn("--env", parser_help.getvalue())


if __name__ == "__main__":
    unittest.main()
