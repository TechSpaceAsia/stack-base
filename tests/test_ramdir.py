"""Tests for stackbase.ramdir.private_ram_dir: a RAM-only scratch directory."""

from __future__ import annotations

import os
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


if __name__ == "__main__":
    unittest.main()
