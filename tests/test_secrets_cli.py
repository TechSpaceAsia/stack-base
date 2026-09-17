"""Tests for stackbase.secrets_cli: `secrets keys|set|unset|edit`.

Round-trips through real `age` (like tests/test_secrets.py) -- these
subcommands exist specifically to avoid the old decrypt-the-whole-bundle-
to-/tmp flow, so the tests exercise the real encrypt/decrypt path rather
than mocking it away.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stackbase.errors import StackError
from stackbase.secrets import load_secrets, save_secrets
from stackbase.secrets_cli import (
    REQUIRED_KEY,
    edit_key,
    list_key_names,
    set_key,
    unset_key,
)

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None


class TempInfraDir:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        return self.path

    def __exit__(self, *exc_info: object) -> None:
        self._tmp.cleanup()


def _generate_age_identity(directory: Path) -> tuple[Path, str]:
    identity_path = directory / "key.txt"
    result = subprocess.run(["age-keygen", "-o", str(identity_path)], capture_output=True, check=True)
    stderr_text = result.stderr.decode("utf-8")
    public_key_line = next(line for line in stderr_text.splitlines() if line.startswith("Public key:"))
    return identity_path, public_key_line.split(":", 1)[1].strip()


class _FakeStdin(io.StringIO):
    """A non-TTY stdin stand-in -- `io.StringIO.isatty()` is already False."""


def _silent(_line: str) -> None:
    pass  # tests that don't need the printed outcome line


@unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed -- skipping secrets-cli round-trip tests")
class SecretsCliRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._identity_tmp = tempfile.TemporaryDirectory()
        self.identity_path, self.public_key = _generate_age_identity(Path(self._identity_tmp.name))
        self._env_patch = mock.patch.dict("os.environ", {"STACKBASE_AGE_IDENTITY": str(self.identity_path)})
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._identity_tmp.cleanup()

    def _infra(self, infra_dir: Path, initial: dict[str, str]) -> None:
        (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
        save_secrets(infra_dir, initial)

    # -- keys --------------------------------------------------------------

    def test_keys_lists_names_sorted_never_values(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"cloudflare_token": "ctok", "hostinger_token": "htok"})

            names = list_key_names(infra_dir)

            self.assertEqual(names, ["cloudflare_token", "hostinger_token"])

    # -- set -----------------------------------------------------------------

    def test_set_reads_the_value_from_stdin_and_saves_it(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})
            printed: list[str] = []

            set_key(infra_dir, "cloudflare_token", stdin=_FakeStdin("ctok-new"), emit=printed.append)

            self.assertEqual(load_secrets(infra_dir)["cloudflare_token"], "ctok-new")
            self.assertEqual(printed, ["cloudflare_token"])  # only the key name, never the value

    def test_set_refuses_an_interactive_tty_stdin_with_both_command_forms_in_the_hint(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})
            tty_stdin = mock.Mock()
            tty_stdin.isatty.return_value = True

            with mock.patch("stackbase.secrets_cli.sys.stdin", tty_stdin):
                with self.assertRaises(StackError) as caught:
                    set_key(infra_dir, "cloudflare_token")

            message = str(caught.exception)
            self.assertIn("printf '%s' \"$VALUE\" | ./infra/up secrets set cloudflare_token", message)
            self.assertIn("./infra/up secrets set cloudflare_token < file", message)

    def test_set_rejects_an_invalid_key_name(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})

            with self.assertRaises(StackError):
                set_key(infra_dir, "Not-Valid", stdin=_FakeStdin("x"))

    def test_set_validates_app_env_before_saving(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})

            with self.assertRaises(StackError) as caught:
                set_key(infra_dir, "app_env", stdin=_FakeStdin("not a key value line\n"))

            self.assertNotIn("not a key value line", str(caught.exception))
            self.assertNotIn("app_env", load_secrets(infra_dir))

    def test_set_normalises_app_env_to_one_trailing_newline(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})

            set_key(infra_dir, "app_env", stdin=_FakeStdin("A=1\n\n\n"), emit=_silent)

            self.assertEqual(load_secrets(infra_dir)["app_env"], "A=1\n")

    # -- unset -----------------------------------------------------------------

    def test_unset_removes_an_existing_key(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "ctok"})

            unset_key(infra_dir, "cloudflare_token", emit=_silent)

            self.assertNotIn("cloudflare_token", load_secrets(infra_dir))

    def test_unset_is_idempotent_for_an_absent_key(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})
            printed: list[str] = []

            unset_key(infra_dir, "cloudflare_token", emit=printed.append)

            self.assertEqual(load_secrets(infra_dir), {"hostinger_token": "htok"})
            self.assertTrue(any("not set" in line for line in printed))

    def test_unset_refuses_the_required_token_key(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {REQUIRED_KEY: "htok"})

            with self.assertRaises(StackError) as caught:
                unset_key(infra_dir, REQUIRED_KEY)

            self.assertIn(REQUIRED_KEY, str(caught.exception))
            self.assertEqual(load_secrets(infra_dir), {REQUIRED_KEY: "htok"})

    # -- edit -----------------------------------------------------------------

    def _edit_runner(self, new_content: str):
        def runner(argv, **kwargs):
            path = Path(argv[-1])
            path.write_text(new_content, encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0)

        return runner

    def test_edit_writes_only_the_one_key_to_a_ram_only_scratch_file(self) -> None:
        seen_paths: list[Path] = []

        def runner(argv, **kwargs):
            path = Path(argv[-1])
            seen_paths.append(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(encoding="utf-8"), "old-value")
            path.write_text("new-value", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0)

        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old-value"})

            edit_key(infra_dir, "cloudflare_token", runner=runner, emit=_silent)

            self.assertEqual(load_secrets(infra_dir)["cloudflare_token"], "new-value")
            self.assertEqual(load_secrets(infra_dir)["hostinger_token"], "htok")  # untouched
            self.assertFalse(seen_paths[0].exists())  # ramdir wiped afterwards

    def test_edit_saves_nothing_when_the_content_is_unchanged(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "same"})
            printed: list[str] = []

            with mock.patch("stackbase.secrets_cli.save_secrets") as save:
                edit_key(infra_dir, "cloudflare_token", runner=self._edit_runner("same"), emit=printed.append)

            save.assert_not_called()
            self.assertTrue(any("unchanged" in line for line in printed))

    def test_edit_validates_app_env_before_saving(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "app_env": "A=1\n"})

            with self.assertRaises(StackError):
                edit_key(infra_dir, "app_env", runner=self._edit_runner("not a key value line"), emit=_silent)

            self.assertEqual(load_secrets(infra_dir)["app_env"], "A=1\n")  # unchanged

    def test_edit_a_new_key_starts_from_empty_content(self) -> None:
        seen: list[str] = []

        def runner(argv, **kwargs):
            path = Path(argv[-1])
            seen.append(path.read_text(encoding="utf-8"))
            path.write_text("brand-new", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0)

        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})

            edit_key(infra_dir, "cloudflare_token", runner=runner, emit=_silent)

            self.assertEqual(seen, [""])
            self.assertEqual(load_secrets(infra_dir)["cloudflare_token"], "brand-new")

    def test_edit_raises_when_the_editor_exits_non_zero_and_saves_nothing(self) -> None:
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1)

        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "orig"})

            with self.assertRaises(StackError):
                edit_key(infra_dir, "cloudflare_token", runner=runner, emit=_silent)

            self.assertEqual(load_secrets(infra_dir)["cloudflare_token"], "orig")

    def test_edit_prints_the_editor_swap_file_note(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "same"})
            printed: list[str] = []

            edit_key(infra_dir, "cloudflare_token", runner=self._edit_runner("same"), emit=printed.append)

            self.assertTrue(any("noswapfile" in line for line in printed))

    # -- edit: $VISUAL/$EDITOR argv splitting (F1, Fix round 1) --------------

    def _capturing_runner(self, new_content: str, captured: list[list[str]]):
        def runner(argv, **kwargs):
            captured.append(list(argv))
            self.assertIsNot(kwargs.get("shell"), True)  # NEVER shell=True
            path = Path(argv[-1])
            path.write_text(new_content, encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0)

        return runner

    def test_edit_splits_a_multi_word_editor_into_argv_with_the_scratch_path_last(self) -> None:
        captured: list[list[str]] = []
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old"})

            with mock.patch.dict("os.environ", {"EDITOR": "code -w", "VISUAL": ""}):
                edit_key(
                    infra_dir, "cloudflare_token", runner=self._capturing_runner("new", captured), emit=_silent
                )

            self.assertEqual(len(captured), 1)
            argv = captured[0]
            self.assertEqual(argv[0], "code")
            self.assertEqual(argv[1], "-w")
            self.assertTrue(argv[-1].endswith("/cloudflare_token"))

    def test_edit_never_reaches_a_shell_even_with_shell_metacharacters_in_editor(self) -> None:
        """`EDITOR="vi; touch /tmp/x"` must be looked up as a literal binary
        named `vi;` -- never interpreted by a shell -- so the injected
        command never runs. shlex.split keeps the trailing `;` attached to
        the first token because it is not a shell.
        """
        captured: list[list[str]] = []
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old"})

            with mock.patch.dict("os.environ", {"EDITOR": "vi; touch /tmp/x", "VISUAL": ""}):
                edit_key(
                    infra_dir, "cloudflare_token", runner=self._capturing_runner("new", captured), emit=_silent
                )

            self.assertEqual(len(captured), 1)
            argv = captured[0]
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[0], "vi;")  # the metacharacter is inert, part of a (bogus) binary name
            self.assertIn("touch", argv)  # a literal argv element, not executed

    def test_edit_falls_through_an_empty_visual_to_editor(self) -> None:
        captured: list[list[str]] = []
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old"})

            with mock.patch.dict("os.environ", {"VISUAL": "   ", "EDITOR": "ed"}):
                edit_key(
                    infra_dir, "cloudflare_token", runner=self._capturing_runner("new", captured), emit=_silent
                )

            self.assertEqual(captured[0][0], "ed")

    def test_edit_raises_on_an_unparsable_editor_value_naming_the_variable(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old"})

            with mock.patch.dict("os.environ", {"EDITOR": 'vi "unterminated', "VISUAL": ""}):
                with self.assertRaises(StackError) as caught:
                    edit_key(infra_dir, "cloudflare_token", runner=self._edit_runner("new"), emit=_silent)

            self.assertIn("EDITOR", str(caught.exception))

    # -- edit: the scratch file is created at 0600 with no window (M1) -------

    def test_edit_creates_the_scratch_file_at_mode_0600_even_under_a_permissive_umask(self) -> None:
        seen_modes: list[int] = []

        def runner(argv, **kwargs):
            path = Path(argv[-1])
            seen_modes.append(path.stat().st_mode & 0o777)
            path.write_text("new", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0)

        old_umask = os.umask(0)  # permissive: proves the mode comes from os.open's own argument
        try:
            with TempInfraDir() as infra_dir:
                self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old"})

                edit_key(infra_dir, "cloudflare_token", runner=runner, emit=_silent)
        finally:
            os.umask(old_umask)

        self.assertEqual(seen_modes, [0o600])

    # -- register_secret: feeding the CLI's redaction net (F2, Fix round 1) --

    def test_set_registers_the_new_value_and_every_existing_bundle_value(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})
            registered: list[tuple[str, str]] = []

            set_key(
                infra_dir,
                "cloudflare_token",
                stdin=_FakeStdin("brand-new"),
                emit=_silent,
                register_secret=lambda k, v: registered.append((k, v)),
            )

            self.assertIn(("cloudflare_token", "brand-new"), registered)
            self.assertIn(("hostinger_token", "htok"), registered)

    def test_set_registers_the_new_value_before_saving_even_if_save_fails(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok"})
            registered: list[tuple[str, str]] = []

            with mock.patch("stackbase.secrets_cli.save_secrets", side_effect=StackError("boom", "boom")):
                with self.assertRaises(StackError):
                    set_key(
                        infra_dir,
                        "cloudflare_token",
                        stdin=_FakeStdin("brand-new"),
                        emit=_silent,
                        register_secret=lambda k, v: registered.append((k, v)),
                    )

            self.assertIn(("cloudflare_token", "brand-new"), registered)

    def test_unset_registers_every_existing_bundle_value(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "ctok"})
            registered: list[tuple[str, str]] = []

            unset_key(infra_dir, "cloudflare_token", emit=_silent, register_secret=lambda k, v: registered.append((k, v)))

            self.assertIn(("hostinger_token", "htok"), registered)
            self.assertIn(("cloudflare_token", "ctok"), registered)

    def test_edit_registers_the_original_bundle_value_and_the_edited_value(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old-value"})
            registered: list[tuple[str, str]] = []

            edit_key(
                infra_dir,
                "cloudflare_token",
                runner=self._edit_runner("new-value"),
                emit=_silent,
                register_secret=lambda k, v: registered.append((k, v)),
            )

            self.assertIn(("hostinger_token", "htok"), registered)
            self.assertIn(("cloudflare_token", "old-value"), registered)  # original, before the edit
            self.assertIn(("cloudflare_token", "new-value"), registered)  # the edited value

    def test_edit_registers_the_edited_value_before_saving_even_if_save_fails(self) -> None:
        with TempInfraDir() as infra_dir:
            self._infra(infra_dir, {"hostinger_token": "htok", "cloudflare_token": "old-value"})
            registered: list[tuple[str, str]] = []

            with mock.patch("stackbase.secrets_cli.save_secrets", side_effect=StackError("boom", "boom")):
                with self.assertRaises(StackError):
                    edit_key(
                        infra_dir,
                        "cloudflare_token",
                        runner=self._edit_runner("new-value"),
                        emit=_silent,
                        register_secret=lambda k, v: registered.append((k, v)),
                    )

            self.assertIn(("cloudflare_token", "new-value"), registered)


class ReadmeDocumentsTheSafeFlowTests(unittest.TestCase):
    """B1 (Fix round, Task 4): the README must no longer tell operators to
    decrypt the WHOLE secrets.age bundle to a plaintext file on disk.
    """

    _README = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")

    def test_the_old_decrypt_to_tmp_flow_is_gone(self) -> None:
        self.assertNotIn("/tmp/secrets.json", self._README)

    def test_the_new_subcommands_are_documented(self) -> None:
        for command in ("secrets keys", "secrets set", "secrets unset", "secrets edit"):
            self.assertIn(command, self._README)


if __name__ == "__main__":
    unittest.main()
