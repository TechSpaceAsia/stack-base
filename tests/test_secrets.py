"""Tests for stackbase.secrets: age decrypt/encrypt in memory, and redact()."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stackbase.errors import StackError
from stackbase.secrets import (
    DEPLOY_FILE,
    DEPLOY_KEY_NAME,
    SECRETS_FILE,
    check_recipients_superset,
    load_secrets,
    read_recipients,
    redact,
    register_private_key,
    save_secrets,
    write_public_key,
)

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None


class RedactTests(unittest.TestCase):
    def test_masks_all_given_values(self) -> None:
        text = "token=abc123 and other=zzz999"

        result = redact(text, ["abc123", "zzz999"])

        self.assertNotIn("abc123", result)
        self.assertNotIn("zzz999", result)

    def test_ignores_empty_values(self) -> None:
        result = redact("hello world", ["", "world"])

        self.assertEqual(result, "hello ***REDACTED***")

    def test_passes_through_text_with_no_matches(self) -> None:
        self.assertEqual(redact("nothing to see here", ["secret"]), "nothing to see here")

    def test_masks_repeated_occurrences(self) -> None:
        result = redact("tok tok tok", ["tok"])

        self.assertNotIn("tok", result)

    def test_masks_the_longest_value_first_so_overlapping_secrets_stay_hidden(self) -> None:
        # "abc" occurs inside the longer secret. Masking the short one first
        # would cut the long one into pieces that no longer match, leaving
        # most of the real secret on screen.
        result = redact("leaked: xxabcyy", ["abc", "xxabcyy"])

        self.assertEqual(result, "leaked: ***REDACTED***")

    def test_masking_does_not_depend_on_the_order_values_are_given(self) -> None:
        self.assertEqual(
            redact("leaked: xxabcyy", ["xxabcyy", "abc"]),
            redact("leaked: xxabcyy", ["abc", "xxabcyy"]),
        )


class TempInfraDir:
    """Context manager for a scratch infra/ directory."""

    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        return self.path

    def __exit__(self, *exc_info: object) -> None:
        self._tmp.cleanup()


def _generate_age_identity(directory: Path) -> tuple[Path, str]:
    """Generate a throwaway age identity in `directory`; returns (identity_path, public_key)."""
    identity_path = directory / "key.txt"
    result = subprocess.run(
        ["age-keygen", "-o", str(identity_path)],
        capture_output=True,
        check=True,
    )
    stderr_text = result.stderr.decode("utf-8")
    public_key_line = next(line for line in stderr_text.splitlines() if line.startswith("Public key:"))
    public_key = public_key_line.split(":", 1)[1].strip()
    return identity_path, public_key


@unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed -- skipping secrets round-trip tests")
class SecretsRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._identity_tmp = tempfile.TemporaryDirectory()
        self.identity_path, self.public_key = _generate_age_identity(Path(self._identity_tmp.name))

    def tearDown(self) -> None:
        self._identity_tmp.cleanup()

    def test_round_trips_through_save_and_load(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            data = {"hostinger_token": "tok_hostinger_123", "cloudflare_token": "tok_cloudflare_456"}

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, data)

                self.assertTrue((infra_dir / "secrets.age").exists())
                # plaintext must never touch disk: no file in infra_dir should contain a raw token
                for path in infra_dir.iterdir():
                    if path.name == "secrets.age":
                        continue
                    self.assertNotIn("tok_hostinger_123", path.read_text(encoding="utf-8"))

                loaded = load_secrets(infra_dir)

            self.assertEqual(loaded, data)

    def test_missing_secrets_file_raises_with_create_command_hint(self) -> None:
        with TempInfraDir() as infra_dir:
            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                with self.assertRaises(StackError) as ctx:
                    load_secrets(infra_dir)

            message = str(ctx.exception)
            self.assertIn("secrets.age", message)
            self.assertIn("age -R", message)
            # a create-command hint must use shell variables, never inline placeholders
            self.assertIn("HOSTINGER_TOKEN=<paste here>", message)
            self.assertIn("$HOSTINGER_TOKEN", message)
            # Task 7b: Cloudflare is optional -- the hint must say so, still
            # using the shell-variable style (never an inline placeholder).
            self.assertIn("CLOUDFLARE_TOKEN=<paste here, or leave empty>", message)
            self.assertIn("optional", message)

    def test_wrong_identity_raises_useful_hint(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, {"a": "b"})

            with tempfile.TemporaryDirectory() as other_identity_dir:
                other_identity_path, _ = _generate_age_identity(Path(other_identity_dir))

                with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(other_identity_path)}):
                    with self.assertRaises(StackError) as ctx:
                        load_secrets(infra_dir)

            message = str(ctx.exception).lower()
            self.assertIn("decrypt", message)
            self.assertIn("identity", message)

    def test_missing_recipients_file_raises_on_save(self) -> None:
        with TempInfraDir() as infra_dir:
            with self.assertRaises(StackError) as ctx:
                save_secrets(infra_dir, {"a": "b"})

            self.assertIn("age-recipients.txt", str(ctx.exception))

    # -- atomic save (M3, Fix round 1) ---------------------------------------

    def test_a_failing_age_leaves_the_original_file_byte_identical_and_no_temp_file_behind(self) -> None:
        """A REAL binary named `age` (a stub script on PATH, ahead of the real
        one) that actually writes to whatever `-o` names before exiting
        non-zero -- exercising the real "does age write straight onto
        secrets.age, or onto a temp file?" question, not just the return
        code. Against the OLD (pre-M1) code, `-o` names `secrets.age`
        directly, so this stub would truncate it with garbage even though
        `age` "failed" -- exactly the bug M3 fixes.
        """
        with TempInfraDir() as infra_dir, tempfile.TemporaryDirectory() as stub_bin_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, {"a": "b"})
            original_bytes = (infra_dir / "secrets.age").read_bytes()

            stub = Path(stub_bin_dir) / "age"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "args = sys.argv[1:]\n"
                "out = args[args.index('-o') + 1]\n"
                "with open(out, 'wb') as f:\n"
                "    f.write(b'GARBAGE-FROM-A-CRASHED-AGE-MID-WRITE')\n"
                "sys.exit(1)\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            new_path = f"{stub_bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"

            with mock.patch.dict(
                os.environ, {"PATH": new_path, "STACKBASE_AGE_IDENTITY": str(self.identity_path)}
            ):
                with self.assertRaises(StackError):
                    save_secrets(infra_dir, {"a": "c"})

            self.assertEqual(
                (infra_dir / "secrets.age").read_bytes(),
                original_bytes,
                "secrets.age was truncated by a failing age instead of only the temp file",
            )
            leftovers = list(infra_dir.glob("secrets.age.*.tmp"))
            self.assertEqual(leftovers, [], f"leftover temp files were not cleaned up: {leftovers}")

    def test_age_producing_no_output_is_a_failure_and_leaves_the_original_untouched(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, {"a": "b"})
            original_bytes = (infra_dir / "secrets.age").read_bytes()

            def empty_output_age(argv, *, input=None, capture_output=True, check=False, **kwargs):
                # Exits 0 but (bug, or a truncated write) produces nothing.
                return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

            with mock.patch("stackbase.secrets.subprocess.run", side_effect=empty_output_age):
                with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                    with self.assertRaises(StackError):
                        save_secrets(infra_dir, {"a": "c"})

            self.assertEqual((infra_dir / "secrets.age").read_bytes(), original_bytes)
            leftovers = list(infra_dir.glob("secrets.age.*.tmp"))
            self.assertEqual(leftovers, [])

    def test_a_successful_save_leaves_no_temp_file_behind(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, {"a": "b"})

            leftovers = list(infra_dir.glob("secrets.age.*.tmp"))
            self.assertEqual(leftovers, [])

    def test_the_temp_file_is_created_at_mode_0600_even_under_a_permissive_umask(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            seen_modes: list[int] = []
            real_run = subprocess.run

            def spying_run(argv, **kwargs):
                if argv[:1] == ["age"] and "-o" in argv:
                    tmp_path = Path(argv[argv.index("-o") + 1])
                    seen_modes.append(tmp_path.stat().st_mode & 0o777)
                return real_run(argv, **kwargs)

            old_umask = os.umask(0)
            try:
                with mock.patch("stackbase.secrets.subprocess.run", side_effect=spying_run):
                    with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                        save_secrets(infra_dir, {"a": "b"})
            finally:
                os.umask(old_umask)

            self.assertEqual(seen_modes, [0o600])


class ReadRecipientsTests(unittest.TestCase):
    def test_skips_comments_and_blank_lines(self) -> None:
        with TempInfraDir() as infra_dir:
            path = infra_dir / "age-recipients.txt"
            path.write_text("# who\n\nage1aaa\n  age1bbb  \n", encoding="utf-8")

            self.assertEqual(read_recipients(path), ["age1aaa", "age1bbb"])

    def test_a_missing_file_is_a_stack_error(self) -> None:
        with TempInfraDir() as infra_dir:
            with self.assertRaises(StackError) as ctx:
                read_recipients(infra_dir / "age-recipients.txt")

            self.assertIn("age-recipients.txt", str(ctx.exception))


class RecipientsSupersetTests(unittest.TestCase):
    def test_no_deploy_recipients_file_means_nothing_to_check(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text("age1aaa\n", encoding="utf-8")

            check_recipients_superset(infra_dir)  # must not raise

    def test_a_superset_passes(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text("age1aaa\nage1bbb\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.txt").write_text(
                "age1aaa\nage1bbb\nage1buildhost\n", encoding="utf-8"
            )

            check_recipients_superset(infra_dir)  # must not raise

    def test_a_missing_recipient_is_refused_and_named(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text("age1aaa\nage1bbb\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.txt").write_text("age1aaa\n", encoding="utf-8")

            with self.assertRaises(StackError) as ctx:
                check_recipients_superset(infra_dir)

            message = str(ctx.exception)
            self.assertIn("deploy-recipients.txt", message)
            self.assertIn("age1bbb", message)
            self.assertIn("deploy-key init --rotate", message)


class PublicKeyWriteTests(unittest.TestCase):
    def test_write_public_key_creates_the_parent_and_a_0644_file(self) -> None:
        with TempInfraDir() as infra_dir:
            path = infra_dir / "keys" / "deploy.pub"

            write_public_key(path, "ssh-ed25519 AAAA deploy@acme\n")

            self.assertEqual(path.read_text(encoding="utf-8"), "ssh-ed25519 AAAA deploy@acme\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)


class RegisterPrivateKeyTests(unittest.TestCase):
    def test_the_whole_key_and_every_body_line_are_registered(self) -> None:
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
        registered: list[str] = []

        register_private_key(key, registered.append)

        self.assertIn(key, registered)
        self.assertIn("b3BlbnNzaC1rZXktdjEAAAAA", registered)
        self.assertFalse(any(value.startswith("-----") for value in registered if value != key))


@unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed -- skipping secrets round-trip tests")
class DeployFileRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._identity_tmp = tempfile.TemporaryDirectory()
        self.identity_path, self.public_key = _generate_age_identity(Path(self._identity_tmp.name))

    def tearDown(self) -> None:
        self._identity_tmp.cleanup()

    def test_deploy_age_round_trips_against_its_own_recipients_file(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "deploy-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            payload = {DEPLOY_KEY_NAME: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"}

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, payload, file=DEPLOY_FILE)

                self.assertTrue((infra_dir / "deploy.age").exists())
                self.assertFalse((infra_dir / "secrets.age").exists())

                self.assertEqual(load_secrets(infra_dir, file=DEPLOY_FILE), payload)

    def test_a_missing_deploy_age_names_the_init_command(self) -> None:
        with TempInfraDir() as infra_dir:
            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                with self.assertRaises(StackError) as ctx:
                    load_secrets(infra_dir, file=DEPLOY_FILE)

            self.assertIn("deploy.age", str(ctx.exception))
            self.assertIn("./infra/up deploy-key init", str(ctx.exception))

    def test_saving_deploy_age_without_its_recipients_file_is_refused(self) -> None:
        with TempInfraDir() as infra_dir:
            with self.assertRaises(StackError) as ctx:
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: "x"}, file=DEPLOY_FILE)

            self.assertIn("deploy-recipients.txt", str(ctx.exception))

    def test_the_two_files_stay_independent(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, {"hostinger_token": "tok"}, file=SECRETS_FILE)
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: "key"}, file=DEPLOY_FILE)

                self.assertEqual(load_secrets(infra_dir), {"hostinger_token": "tok"})
                self.assertEqual(load_secrets(infra_dir, file=DEPLOY_FILE), {DEPLOY_KEY_NAME: "key"})


if __name__ == "__main__":
    unittest.main()
