"""Tests for stackbase.ssh.Ssh, against a recording fake `runner`/`connector`/`sleep`/`clock`."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from stackbase.errors import StackError
from stackbase.ssh import Ssh
from tests.fakes import FakeRunner

_HOST = "1.2.3.4"
_KEYSCAN_LINE = f"{_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImatchbody\n"


def _cp_text(argv, *, returncode=0, stdout="", stderr="") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


def _cp_bytes(argv, *, returncode=0, stdout=b"", stderr=b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


class ConstructorValidationTests(unittest.TestCase):
    def test_rejects_dash_leading_host(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(StackError):
                Ssh(Path(tmp), "-oProxyCommand=evil")

    def test_rejects_host_with_whitespace(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(StackError):
                Ssh(Path(tmp), "1.2.3.4 extra")

    def test_rejects_empty_host(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(StackError):
                Ssh(Path(tmp), "")

    def test_rejects_dash_leading_user(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(StackError):
                Ssh(Path(tmp), _HOST, user="-oProxyCommand=evil")

    def test_rejects_uppercase_user(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(StackError):
                Ssh(Path(tmp), _HOST, user="Root")

    def test_accepts_ipv4_ipv6_and_hostname(self) -> None:
        with TemporaryDirectory() as tmp:
            Ssh(Path(tmp), "1.2.3.4")
            Ssh(Path(tmp), "2001:db8::1")
            Ssh(Path(tmp), "a.example.com")


class ArgvTests(unittest.TestCase):
    def test_argv_carries_batch_mode_and_connect_timeout_and_known_hosts(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            ssh = Ssh(infra_dir, _HOST)

            argv = ssh.argv()

            self.assertEqual(argv[0], "ssh")
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("ConnectTimeout=10", argv)
            self.assertIn(f"UserKnownHostsFile={infra_dir / 'known_hosts'}", argv)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertEqual(argv[-1], f"root@{_HOST}")

    def test_custom_user_is_used(self) -> None:
        with TemporaryDirectory() as tmp:
            ssh = Ssh(Path(tmp), _HOST, user="deploy")

            self.assertEqual(ssh.argv()[-1], f"deploy@{_HOST}")


class RunTests(unittest.TestCase):
    def test_run_appends_cmd_and_returns_completed_process(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["ssh"], returncode=0, stdout="hi\n", stderr=""))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            result = ssh.run("echo hi")

            self.assertEqual(result.stdout, "hi\n")
            call = runner.calls[0]
            self.assertEqual(call["argv"][0], "ssh")
            self.assertEqual(call["argv"][-1], "echo hi")
            self.assertIn("BatchMode=yes", call["argv"])
            self.assertIn("ConnectTimeout=10", call["argv"])
            self.assertTrue(call["kwargs"]["capture_output"])
            self.assertTrue(call["kwargs"]["text"])
            self.assertFalse(call["kwargs"]["check"])

    def test_check_true_raises_stack_error_with_stderr_tail_on_nonzero(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            stderr = "\n".join(f"line {i}" for i in range(1, 20))
            runner.script(_cp_text(["ssh"], returncode=1, stdout="", stderr=stderr))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            with self.assertRaises(StackError) as ctx:
                ssh.run("false")

            self.assertIn("line 19", ctx.exception.hint)
            self.assertNotIn("line 1\n", ctx.exception.hint)  # only the tail, not the whole log

    def test_check_false_does_not_raise_on_nonzero(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["ssh"], returncode=1, stdout="", stderr="boom"))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            result = ssh.run("false", check=False)

            self.assertEqual(result.returncode, 1)

    def test_input_is_passed_through(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["ssh"], returncode=0))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.run("cat > /tmp/x", input="payload")

            self.assertEqual(runner.calls[0]["kwargs"]["input"], "payload")

    def test_a_host_key_changed_banner_is_translated_to_the_pin_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            banner = (
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\n"
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                "Host key verification failed.\n"
            )
            runner.script(_cp_text(["ssh"], returncode=255, stdout="", stderr=banner))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            with self.assertRaises(StackError) as ctx:
                ssh.run("true")

            hint = ctx.exception.hint.lower()
            self.assertIn("reinstall", hint.replace("re-install", "reinstall"))
            self.assertIn("intercept", hint)

    def test_missing_ssh_binary_raises_stack_error_naming_package(self) -> None:
        with TemporaryDirectory() as tmp:
            def missing_runner(argv, **kwargs):
                raise FileNotFoundError(argv[0])

            ssh = Ssh(Path(tmp), _HOST, runner=missing_runner)

            with self.assertRaises(StackError) as ctx:
                ssh.run("true")

            self.assertIn("openssh", ctx.exception.hint.lower())


class FetchTests(unittest.TestCase):
    def test_fetch_uses_cat_with_quoted_path_and_returns_bytes(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_bytes(["ssh"], returncode=0, stdout=b"file contents"))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            result = ssh.fetch("/etc/nixos/configuration.nix")

            self.assertEqual(result, b"file contents")
            call = runner.calls[0]
            self.assertEqual(call["argv"][-1], "cat -- /etc/nixos/configuration.nix")
            self.assertNotIn("text", call["kwargs"])  # binary mode: text not requested

    def test_fetch_quotes_a_path_with_spaces(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_bytes(["ssh"], returncode=0, stdout=b"x"))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.fetch("/etc/has space/file")

            self.assertIn("'/etc/has space/file'", runner.calls[0]["argv"][-1])

    def test_fetch_raises_on_nonzero(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_bytes(["ssh"], returncode=1, stdout=b"", stderr=b"no such file"))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            with self.assertRaises(StackError) as ctx:
                ssh.fetch("/nope")

            self.assertIn("no such file", ctx.exception.hint)


class RsyncToTests(unittest.TestCase):
    def test_argv_carries_the_ssh_options_via_dash_e(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["rsync"], returncode=0))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.rsync_to("/local/infra", "/etc/nixos/stack")

            argv = runner.calls[0]["argv"]
            self.assertEqual(argv[0], "rsync")
            self.assertIn("-az", argv)
            self.assertIn("--delete", argv)
            self.assertEqual(argv[-2], "/local/infra/")
            self.assertEqual(argv[-1], f"root@{_HOST}:/etc/nixos/stack")
            e_index = argv.index("-e")
            ssh_cmd = argv[e_index + 1]
            self.assertIn("BatchMode=yes", ssh_cmd)
            self.assertIn("ConnectTimeout=10", ssh_cmd)
            self.assertIn("StrictHostKeyChecking=yes", ssh_cmd)

    def test_delete_false_omits_the_flag(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["rsync"], returncode=0))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.rsync_to("/local/infra", "/etc/nixos/stack", delete=False)

            self.assertNotIn("--delete", runner.calls[0]["argv"])

    def test_exclude_patterns_are_passed(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["rsync"], returncode=0))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.rsync_to("/local/infra", "/etc/nixos/stack", exclude=["secrets.age", "keys/"])

            argv = runner.calls[0]["argv"]
            self.assertIn("--exclude=secrets.age", argv)
            self.assertIn("--exclude=keys/", argv)

    def test_raises_on_nonzero(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["rsync"], returncode=23, stderr="rsync error: some files vanished"))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            with self.assertRaises(StackError) as ctx:
                ssh.rsync_to("/local/infra", "/etc/nixos/stack")

            self.assertIn("vanished", ctx.exception.hint)

    def test_local_dir_is_resolved_to_an_absolute_path(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["rsync"], returncode=0))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.rsync_to("relative/infra", "/etc/nixos/stack")

            source = runner.calls[0]["argv"][-2]
            self.assertTrue(os.path.isabs(source))
            self.assertTrue(source.endswith("/"))

    def test_dash_leading_local_dir_cannot_be_parsed_as_an_option(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            runner.script(_cp_text(["rsync"], returncode=0))
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            ssh.rsync_to("-rf", "/etc/nixos/stack")

            source = runner.calls[0]["argv"][-2]
            self.assertFalse(source.startswith("-"))
            self.assertTrue(os.path.isabs(source))

    def test_rejects_non_absolute_remote_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = FakeRunner()
            ssh = Ssh(Path(tmp), _HOST, runner=runner)

            with self.assertRaises(StackError):
                ssh.rsync_to("/local/infra", "etc/nixos/stack")

            self.assertEqual(runner.calls, [], "must validate before ever invoking rsync")

    def test_missing_rsync_binary_raises_stack_error_naming_package(self) -> None:
        with TemporaryDirectory() as tmp:
            def missing_runner(argv, **kwargs):
                raise FileNotFoundError(argv[0])

            ssh = Ssh(Path(tmp), _HOST, runner=missing_runner)

            with self.assertRaises(StackError) as ctx:
                ssh.rsync_to("/local/infra", "/etc/nixos/stack")

            self.assertIn("rsync", ctx.exception.hint.lower())


class PinHostKeyTests(unittest.TestCase):
    def test_appends_a_fresh_entry_and_creates_the_file_0644(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=_KEYSCAN_LINE))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            ssh.pin_host_key()

            known_hosts = infra_dir / "known_hosts"
            self.assertTrue(known_hosts.exists())
            content = known_hosts.read_text()
            self.assertEqual(content, f"{_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImatchbody\n")
            self.assertEqual(known_hosts.stat().st_mode & 0o777, 0o644)
            call = runner.calls[0]
            self.assertEqual(call["argv"], ["ssh-keyscan", "-t", "ed25519", "-T", "10", "--", _HOST])

    def test_keyscan_argv_has_double_dash_immediately_before_the_host(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=_KEYSCAN_LINE))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            ssh.pin_host_key()

            argv = runner.calls[0]["argv"]
            self.assertEqual(argv[-2:], ["--", _HOST])

    def test_ignores_comment_lines_from_keyscan_output(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            runner = FakeRunner()
            output = f"# comment line\n\n{_KEYSCAN_LINE}"
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=output))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            ssh.pin_host_key()

            content = (infra_dir / "known_hosts").read_text()
            self.assertEqual(content, f"{_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImatchbody\n")

    def test_idempotent_for_the_same_key(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            known_hosts = infra_dir / "known_hosts"
            known_hosts.write_text(f"{_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImatchbody\n")
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=_KEYSCAN_LINE))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            ssh.pin_host_key()  # must not raise, must not duplicate the line

            content = known_hosts.read_text()
            self.assertEqual(content, f"{_HOST} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImatchbody\n")

    def test_raises_on_changed_key_with_mitm_vs_reinstall_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            known_hosts = infra_dir / "known_hosts"
            known_hosts.write_text(f"{_HOST} ssh-ed25519 AAAAoldkeybodyDIFFERENT\n")
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=_KEYSCAN_LINE))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            with self.assertRaises(StackError) as ctx:
                ssh.pin_host_key()

            hint = ctx.exception.hint.lower()
            self.assertIn("reinstall", hint.replace("re-install", "reinstall"))
            self.assertIn("intercept", hint)
            # must not have overwritten the pinned entry
            self.assertEqual(known_hosts.read_text(), f"{_HOST} ssh-ed25519 AAAAoldkeybodyDIFFERENT\n")

    def test_empty_output_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=""))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            with self.assertRaises(StackError):
                ssh.pin_host_key()

    def test_garbage_output_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout="not a valid line at all\n"))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            with self.assertRaises(StackError):
                ssh.pin_host_key()

    def test_non_ed25519_key_type_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            runner = FakeRunner()
            runner.script(_cp_text(["ssh-keyscan"], returncode=0, stdout=f"{_HOST} ssh-rsa AAAAsomersakey\n"))
            ssh = Ssh(infra_dir, _HOST, runner=runner)

            with self.assertRaises(StackError):
                ssh.pin_host_key()

    def test_missing_ssh_keyscan_binary_raises_stack_error_naming_package(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)

            def missing_runner(argv, **kwargs):
                raise FileNotFoundError(argv[0])

            ssh = Ssh(infra_dir, _HOST, runner=missing_runner)

            with self.assertRaises(StackError) as ctx:
                ssh.pin_host_key()

            self.assertIn("openssh", ctx.exception.hint.lower())


class UnpinHostKeyTests(unittest.TestCase):
    def test_removes_the_line_for_this_host_only(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            known_hosts = infra_dir / "known_hosts"
            known_hosts.write_text(
                f"{_HOST} ssh-ed25519 AAAAoldkeybody\nother.host ssh-ed25519 AAAAotherkeybody\n",
                encoding="utf-8",
            )
            ssh = Ssh(infra_dir, _HOST)

            ssh.unpin_host_key()

            content = known_hosts.read_text()
            self.assertNotIn(_HOST, content)
            self.assertIn("other.host", content)

    def test_no_op_when_known_hosts_does_not_exist(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            ssh = Ssh(infra_dir, _HOST)

            ssh.unpin_host_key()  # must not raise

            self.assertFalse((infra_dir / "known_hosts").exists())

    def test_no_op_when_a_different_host_is_pinned(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            known_hosts = infra_dir / "known_hosts"
            original = "other.host ssh-ed25519 AAAAotherkeybody\n"
            known_hosts.write_text(original, encoding="utf-8")
            ssh = Ssh(infra_dir, _HOST)

            ssh.unpin_host_key()

            self.assertEqual(known_hosts.read_text(), original)


class WaitPortTests(unittest.TestCase):
    def test_returns_immediately_on_first_successful_connect(self) -> None:
        with TemporaryDirectory() as tmp:
            ssh = Ssh(Path(tmp), _HOST)
            connected = []

            class FakeSocket:
                def close(self) -> None:
                    pass

            def connector(address, timeout=None):
                connected.append(address)
                return FakeSocket()

            sleeps: list[float] = []
            ssh.wait_port(timeout=60, sleep=sleeps.append, clock=iter([0.0, 0.0]).__next__, connector=connector)

            self.assertEqual(connected, [(_HOST, 22)])
            self.assertEqual(sleeps, [])

    def test_retries_then_succeeds(self) -> None:
        with TemporaryDirectory() as tmp:
            ssh = Ssh(Path(tmp), _HOST)
            attempts = {"n": 0}

            class FakeSocket:
                def close(self) -> None:
                    pass

            def connector(address, timeout=None):
                attempts["n"] += 1
                if attempts["n"] < 3:
                    raise OSError("connection refused")
                return FakeSocket()

            sleeps: list[float] = []
            clock_values = iter([0.0, 1.0, 1.0, 2.0, 2.0])
            ssh.wait_port(timeout=60, sleep=sleeps.append, clock=lambda: next(clock_values), connector=connector)

            self.assertEqual(attempts["n"], 3)
            self.assertEqual(len(sleeps), 2)

    def test_times_out_with_hpanel_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            ssh = Ssh(Path(tmp), _HOST)

            def connector(address, timeout=None):
                raise OSError("connection refused")

            sleeps: list[float] = []
            clock_values = iter([0.0, 601.0])
            with self.assertRaises(StackError) as ctx:
                ssh.wait_port(timeout=600, sleep=sleeps.append, clock=lambda: next(clock_values), connector=connector)

            self.assertIn("hpanel", ctx.exception.hint.lower())


if __name__ == "__main__":
    unittest.main()
