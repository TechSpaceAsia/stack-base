"""Tests for stackbase.ramdir.private_ram_dir: a RAM-only scratch directory."""

from __future__ import annotations

import contextlib
import io
import os
import plistlib
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.errors import StackError
from stackbase.ramdir import private_ram_dir

_HAS_DEV_SHM = Path("/dev/shm").is_dir()


@unittest.skipUnless(_HAS_DEV_SHM, "/dev/shm is not available on this machine")
class DevShmTests(unittest.TestCase):
    def test_yields_a_fresh_0700_directory_under_dev_shm(self) -> None:
        with private_ram_dir() as directory:
            self.assertTrue(directory.is_dir())
            self.assertTrue(str(directory).startswith("/dev/shm/"))
            mode = directory.stat().st_mode & 0o777
            self.assertEqual(mode, 0o700)

    def test_the_directory_and_its_contents_are_removed_on_a_clean_exit(self) -> None:
        with private_ram_dir() as directory:
            (directory / "secret").write_text("shh", encoding="utf-8")

        self.assertFalse(directory.exists())

    def test_the_directory_is_removed_even_when_the_body_raises(self) -> None:
        captured: list[Path] = []

        with self.assertRaises(RuntimeError):
            with private_ram_dir() as directory:
                captured.append(directory)
                (directory / "secret").write_text("shh", encoding="utf-8")
                raise RuntimeError("boom")

        self.assertFalse(captured[0].exists())

    def test_the_directory_is_removed_on_keyboard_interrupt(self) -> None:
        captured: list[Path] = []

        with self.assertRaises(KeyboardInterrupt):
            with private_ram_dir() as directory:
                captured.append(directory)
                raise KeyboardInterrupt()

        self.assertFalse(captured[0].exists())

    def test_a_regular_file_is_zeroed_before_removal(self) -> None:
        """`_wipe` (the shared cleanup helper) zeroes a file's content before
        `shutil.rmtree` unlinks it -- intercept `rmtree` itself so the
        (already-zeroed) bytes can still be inspected afterwards.
        """
        from stackbase import ramdir as ramdir_module

        with TemporaryDirectory() as tmp:
            directory = Path(tmp) / "scratch"
            directory.mkdir(mode=0o700)
            secret = directory / "secret"
            secret.write_text("hello-world", encoding="utf-8")

            with mock.patch.object(ramdir_module.shutil, "rmtree") as rmtree:
                ramdir_module._wipe(directory)

            rmtree.assert_called_once_with(directory, ignore_errors=True)
            self.assertEqual(secret.read_bytes(), b"\x00" * len("hello-world"))


class NoRamAvailableTests(unittest.TestCase):
    def test_raises_a_clear_stackerror_when_neither_dev_shm_nor_xdg_runtime_dir_work(self) -> None:
        with mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")):
            with mock.patch("stackbase.ramdir._is_darwin", return_value=False):
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("XDG_RUNTIME_DIR", None)

                    with self.assertRaises(StackError) as caught:
                        with private_ram_dir():
                            pass

        message = str(caught.exception)
        self.assertIn("/dev/shm", message)
        self.assertIn("XDG_RUNTIME_DIR", message)

    def test_never_falls_back_to_a_disk_backed_tmp_dir(self) -> None:
        """Even with a plausible-looking TMPDIR set, no fallback happens."""
        with TemporaryDirectory() as tmp:
            with mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")):
                with mock.patch("stackbase.ramdir._is_darwin", return_value=False):
                    with mock.patch.dict(os.environ, {"TMPDIR": tmp}, clear=False):
                        os.environ.pop("XDG_RUNTIME_DIR", None)

                        with self.assertRaises(StackError):
                            with private_ram_dir():
                                pass

            self.assertEqual(list(Path(tmp).iterdir()), [])


class XdgRuntimeDirFallbackTests(unittest.TestCase):
    def test_a_correctly_permissioned_xdg_runtime_dir_is_used_when_dev_shm_is_absent(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            runtime_dir.mkdir(mode=0o700)
            os.chmod(runtime_dir, 0o700)  # mkdir's mode is filtered through the umask

            with mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")):
                with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_dir)}, clear=False):
                    with private_ram_dir() as directory:
                        self.assertTrue(str(directory).startswith(str(runtime_dir)))
                        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_a_group_or_world_readable_xdg_runtime_dir_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "runtime"
            runtime_dir.mkdir()
            os.chmod(runtime_dir, 0o755)

            with mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")):
                with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_dir)}, clear=False):
                    with self.assertRaises(StackError):
                        with private_ram_dir():
                            pass

    def test_a_missing_xdg_runtime_dir_path_is_refused_not_created(self) -> None:
        with TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "does-not-exist"

            with mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")):
                with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_dir)}, clear=False):
                    with self.assertRaises(StackError):
                        with private_ram_dir():
                            pass

            self.assertFalse(runtime_dir.exists())


class _FakeMacDiskTools:
    """A stand-in for `hdiutil` and `diskutil` that keeps a RAM disk's state in
    memory and backs the "mounted volume" with an ordinary directory under
    `volumes_root`. Records every argv it is asked to run.
    """

    def __init__(self, volumes_root: Path, *, owners_enforced_after_enable: bool = True) -> None:
        self.volumes_root = volumes_root
        self.owners_enforced_after_enable = owners_enforced_after_enable
        self.calls: list[list[str]] = []
        self.attached: dict[str, Path | None] = {}
        self.owners_enabled: set[str] = set()
        self._next = 7

    def __call__(self, argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        tool, *rest = argv
        if tool == "hdiutil" and rest[:2] == ["attach", "-nomount"]:
            device = f"/dev/disk{self._next}"
            self._next += 1
            self.attached[device] = None
            return subprocess.CompletedProcess(argv, 0, stdout=f"{device}\n", stderr="")
        if tool == "hdiutil" and rest[0] == "detach":
            device = rest[-1]
            if device not in self.attached:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="hdiutil: detach failed - No such file or directory")
            del self.attached[device]
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if tool == "diskutil" and rest[0] == "eraseVolume":
            _fs, name, device = rest[1:4]
            mount = self.volumes_root / name
            mount.mkdir()
            self.attached[device] = mount
            return subprocess.CompletedProcess(argv, 0, stdout="Finished erase", stderr="")
        if tool == "diskutil" and rest[:2] == ["info", "-plist"]:
            device = rest[2]
            mount = self.attached.get(device)
            info = {
                "DeviceIdentifier": device.rsplit("/", 1)[-1],
                "MountPoint": str(mount) if mount else "",
                "GlobalPermissionsEnabled": device in self.owners_enabled,
            }
            return subprocess.CompletedProcess(argv, 0, stdout=plistlib.dumps(info).decode("utf-8"), stderr="")
        if tool == "diskutil" and rest[0] == "enableOwnership":
            if not self.owners_enforced_after_enable:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Ownership can only be enabled by root")
            for device, mount in self.attached.items():
                if mount is not None and str(mount) == rest[1]:
                    self.owners_enabled.add(device)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected tool invocation: {argv}")


class DarwinRamDiskTests(unittest.TestCase):
    """On macOS (no /dev/shm, no $XDG_RUNTIME_DIR) stack-base makes its own RAM disk."""

    def _no_linux_ram(self) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")))
        stack.enter_context(mock.patch.dict(os.environ, {}, clear=False))
        os.environ.pop("XDG_RUNTIME_DIR", None)
        stack.enter_context(mock.patch("stackbase.ramdir._is_darwin", return_value=True))
        return stack

    def test_attaches_formats_uses_and_detaches_a_ram_disk(self) -> None:
        with TemporaryDirectory() as tmp:
            tools = _FakeMacDiskTools(Path(tmp))
            with self._no_linux_ram(), mock.patch("stackbase.ramdir._run", tools):
                with private_ram_dir() as directory:
                    self.assertTrue(directory.is_dir())
                    self.assertTrue(str(directory).startswith(tmp))
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(directory.parent.stat().st_mode & 0o777, 0o700)
                    (directory / "deploy_key").write_text("shh", encoding="utf-8")

            self.assertFalse(directory.exists())
            self.assertEqual(tools.attached, {}, "the RAM disk must be detached on the way out")
            self.assertEqual(tools.calls[0][:3], ["hdiutil", "attach", "-nomount"])
            self.assertTrue(tools.calls[0][3].startswith("ram://"))
            self.assertEqual(tools.calls[1][:3], ["diskutil", "eraseVolume", "HFS+"])
            self.assertEqual(tools.calls[-1][:2], ["hdiutil", "detach"])

    def test_turns_ownership_on_so_mode_0700_is_enforced(self) -> None:
        with TemporaryDirectory() as tmp:
            tools = _FakeMacDiskTools(Path(tmp))
            with self._no_linux_ram(), mock.patch("stackbase.ramdir._run", tools):
                with mock.patch("sys.stderr") as stderr:
                    with private_ram_dir():
                        pass

            self.assertIn(["diskutil", "enableOwnership", str(Path(tmp) / tools.calls[1][3])], tools.calls)
            stderr.write.assert_not_called()

    def test_still_runs_but_warns_once_when_ownership_cannot_be_enabled(self) -> None:
        with TemporaryDirectory() as tmp:
            tools = _FakeMacDiskTools(Path(tmp), owners_enforced_after_enable=False)
            with self._no_linux_ram(), mock.patch("stackbase.ramdir._run", tools):
                buffer = io.StringIO()
                with mock.patch("sys.stderr", buffer):
                    with private_ram_dir() as directory:
                        self.assertTrue(directory.is_dir())

            self.assertEqual(tools.attached, {})
            warnings = [line for line in buffer.getvalue().splitlines() if line.startswith("warning:")]
            self.assertEqual(len(warnings), 1)
            self.assertIn("ownership", warnings[0])

    def test_detaches_the_ram_disk_even_when_the_body_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            tools = _FakeMacDiskTools(Path(tmp))
            with self._no_linux_ram(), mock.patch("stackbase.ramdir._run", tools):
                with self.assertRaises(RuntimeError):
                    with private_ram_dir() as directory:
                        (directory / "secret").write_text("shh", encoding="utf-8")
                        raise RuntimeError("boom")

            self.assertFalse(directory.exists())
            self.assertEqual(tools.attached, {})

    def test_a_failing_hdiutil_is_a_stackerror_not_a_traceback(self) -> None:
        def broken(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="hdiutil: attach failed - Resource busy")

        with self._no_linux_ram(), mock.patch("stackbase.ramdir._run", broken):
            with self.assertRaises(StackError) as caught:
                with private_ram_dir():
                    pass

        self.assertIn("hdiutil", str(caught.exception))
        self.assertIn("Resource busy", str(caught.exception))

    def test_a_missing_hdiutil_is_a_stackerror_not_a_traceback(self) -> None:
        def missing(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError(2, "No such file or directory", argv[0])

        with self._no_linux_ram(), mock.patch("stackbase.ramdir._run", missing):
            with self.assertRaises(StackError):
                with private_ram_dir():
                    pass

    def test_a_linux_box_without_dev_shm_still_refuses_rather_than_trying_hdiutil(self) -> None:
        never = mock.Mock(side_effect=AssertionError("hdiutil must not be tried on Linux"))
        with mock.patch("stackbase.ramdir._DEV_SHM", Path("/does/not/exist")):
            with mock.patch("stackbase.ramdir._is_darwin", return_value=False):
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("XDG_RUNTIME_DIR", None)
                    with mock.patch("stackbase.ramdir._run", never):
                        with self.assertRaises(StackError):
                            with private_ram_dir():
                                pass
        never.assert_not_called()


if __name__ == "__main__":
    unittest.main()
