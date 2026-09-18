"""Tests for stackbase.backups: the rclone credentials file and `backup-now`."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from stackbase.backups import (
    BACKUP_ENV_PATH,
    backup_env_content,
    backup_env_digest,
    check_backup_credentials,
    run_backup_now,
)
from stackbase.errors import StackError
from tests.fakes import FakePopen, FakeRunner

_STACK_TOML = """\
project    = "acme"
domain     = "acme.example.com"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[backups]
bucket = "acme-backups"

[nodes.a]
role   = "primary"
vps_id = 1

[nodes.b]
role = "replica"
vps_id = 2
"""

_FULL_SECRETS = {
    "r2_access_key_id": "AKIAEXAMPLE",
    "r2_secret_access_key": "s3cr3t-example",
    "r2_endpoint": "https://abc123.r2.cloudflarestorage.com",
}


def _infra(tmp: Path) -> Path:
    infra_dir = tmp / "infra"
    (infra_dir / "keys").mkdir(parents=True)
    (infra_dir / "stack.toml").write_text(_STACK_TOML, encoding="utf-8")
    (infra_dir / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTemplateEval matt@laptop\n", encoding="utf-8"
    )
    (infra_dir / "stack.state.json").write_text(
        json.dumps({"version": 1, "nodes": {"a": {"ipv4": "1.2.3.4"}, "b": {"ipv4": "5.6.7.8"}}}),
        encoding="utf-8",
    )
    (infra_dir / "known_hosts").write_text("", encoding="utf-8")
    return infra_dir


class BackupEnvContentTests(unittest.TestCase):
    def test_all_three_values_produce_the_rclone_env_config(self) -> None:
        self.assertEqual(
            backup_env_content(_FULL_SECRETS),
            "RCLONE_CONFIG_BACKUP_TYPE=s3\n"
            "RCLONE_CONFIG_BACKUP_PROVIDER=Cloudflare\n"
            "RCLONE_CONFIG_BACKUP_ACCESS_KEY_ID=AKIAEXAMPLE\n"
            "RCLONE_CONFIG_BACKUP_SECRET_ACCESS_KEY=s3cr3t-example\n"
            "RCLONE_CONFIG_BACKUP_ENDPOINT=https://abc123.r2.cloudflarestorage.com\n",
        )

    def test_a_missing_value_means_no_file_at_all(self) -> None:
        for key in _FULL_SECRETS:
            partial = {k: v for k, v in _FULL_SECRETS.items() if k != key}
            self.assertIsNone(backup_env_content(partial), key)

    def test_an_empty_value_means_no_file_at_all(self) -> None:
        self.assertIsNone(backup_env_content({**_FULL_SECRETS, "r2_endpoint": ""}))

    def test_no_r2_keys_at_all_means_no_file(self) -> None:
        self.assertIsNone(backup_env_content({"hostinger_token": "tok"}))

    def test_a_newline_in_a_value_is_refused_by_name_never_by_value(self) -> None:
        with self.assertRaises(StackError) as ctx:
            backup_env_content({**_FULL_SECRETS, "r2_access_key_id": "AKIA\nEVIL=1"})

        message = str(ctx.exception)
        self.assertIn("r2_access_key_id", message)
        self.assertNotIn("EVIL", message)

    def test_a_value_a_shell_would_reinterpret_is_refused(self) -> None:
        """Fix round 1, finding 1: the credentials file is read by systemd's
        EnvironmentFile parser (which substitutes nothing) AND has to reach
        `stackbase-backup-ls`'s environment on the node. Anything a shell
        would evaluate -- command substitution, a backtick, a separator, a
        quote, a backslash -- must never be written into it in the first
        place. One case per rejected class."""
        cases = {
            "command substitution": "AKIA$(id)",
            "parameter expansion": "AKIA${HOME}",
            "backtick": "AKIA`id`",
            "command separator": "AKIA;id",
            "background/and": "AKIA&id",
            "pipe": "AKIA|id",
            "redirect": "AKIA>/etc/shadow",
            "space": "AKIA EVIL",
            "tab": "AKIA\tEVIL",
            "single quote": "AKIA'x'",
            "double quote": 'AKIA"x"',
            "backslash": "AKIA\\x",
            "glob": "AKIA*",
            "comment": "AKIA#x",
        }
        for label, value in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(StackError) as ctx:
                    backup_env_content({**_FULL_SECRETS, "r2_access_key_id": value})

                message = str(ctx.exception)
                self.assertIn("r2_access_key_id", message)
                # The KEY and the allowed SHAPE -- never the value itself.
                self.assertNotIn(value, message)

    def test_every_r2_key_is_checked_not_just_the_first(self) -> None:
        for key in _FULL_SECRETS:
            with self.subTest(key=key):
                with self.assertRaises(StackError) as ctx:
                    backup_env_content({**_FULL_SECRETS, key: "value$(id)"})

                self.assertIn(key, str(ctx.exception))

    def test_a_realistic_credential_set_still_passes(self) -> None:
        """The guard must not cost an operator a legitimate credential: an
        AWS-style base64 secret (with `+`, `/` and a trailing `=`), a hex
        key id, and an endpoint URL carrying a port and a path."""
        realistic = {
            "r2_access_key_id": "0123456789abcdef0123456789abcdef",
            "r2_secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY=",
            "r2_endpoint": "https://abc123.r2.cloudflarestorage.com:443/acme",
        }

        content = backup_env_content(realistic)

        self.assertIn(
            "RCLONE_CONFIG_BACKUP_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY=\n", content
        )
        self.assertIn(
            "RCLONE_CONFIG_BACKUP_ENDPOINT=https://abc123.r2.cloudflarestorage.com:443/acme\n", content
        )

    def test_every_rendered_line_is_exactly_one_key_equals_value(self) -> None:
        """The point of both guards above: whatever the credentials are, the
        file can only ever be the five lines this function writes, and no
        line can carry whitespace a shell would split on."""
        content = backup_env_content(_FULL_SECRETS)

        lines = content.splitlines()
        self.assertEqual(len(lines), 5)
        for line in lines:
            self.assertRegex(line, r"^RCLONE_CONFIG_BACKUP_[A-Z_]+=\S*$")

    def test_the_digest_is_stable_and_content_addressed(self) -> None:
        content = backup_env_content(_FULL_SECRETS)
        self.assertEqual(backup_env_digest(content), backup_env_digest(content))
        self.assertNotEqual(
            backup_env_digest(content),
            backup_env_digest(backup_env_content({**_FULL_SECRETS, "r2_endpoint": "https://other/"})),
        )

    def test_the_env_path_is_root_only_stackbase_state(self) -> None:
        """Pinned here because nixos/backups.nix hard-codes the same path in
        its EnvironmentFile -- the two must never drift apart."""
        from stackbase.reconcile import REMOTE_CERT_DIR

        self.assertEqual(BACKUP_ENV_PATH, "/var/lib/stackbase/backup.env")
        # steps._ensure_backup_env builds the path from REMOTE_CERT_DIR
        # rather than from this constant, so tie the two together here --
        # otherwise the pin above could stay green while the step wrote
        # somewhere else entirely.
        self.assertEqual(BACKUP_ENV_PATH, f"{REMOTE_CERT_DIR}/backup.env")


class RunBackupNowTests(unittest.TestCase):
    def test_it_starts_the_unit_then_lists_the_bucket_on_every_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            for _ in range(4):
                popen.script(returncode=0, output="ok\n")

            run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            commands = [call["argv"][-1] for call in popen.calls]
            self.assertEqual(
                commands,
                [
                    "systemctl start stackbase-backup.service",
                    "stackbase-backup-ls",
                    "systemctl start stackbase-backup.service",
                    "stackbase-backup-ls",
                ],
            )
            self.assertTrue(all("root@" in " ".join(call["argv"]) for call in popen.calls))

    def test_a_failed_unit_names_the_journal_command(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=1, output="Job for stackbase-backup.service failed\n")

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("journalctl -u stackbase-backup", str(ctx.exception))

    def test_node_restricts_the_run_to_one_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            popen.script(returncode=0, output="ok\n")

            run_backup_now(infra_dir, node="b", runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertEqual(len(popen.calls), 2)
            self.assertTrue(all("5.6.7.8" in " ".join(call["argv"]) for call in popen.calls))

    def test_an_unknown_node_lists_the_known_ones(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, node="zz", runner=FakeRunner(), popen=FakePopen(), emit=lambda _l: None)

            self.assertIn("a, b", str(ctx.exception))

    def test_a_project_with_no_bucket_says_so_before_any_ssh(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            (infra_dir / "stack.toml").write_text(
                _STACK_TOML.replace('[backups]\nbucket = "acme-backups"\n', ""), encoding="utf-8"
            )
            popen = FakePopen()

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("[backups]", str(ctx.exception))
            self.assertEqual(popen.calls, [])

    def test_a_node_with_no_recorded_address_says_to_run_up_first(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {}}), encoding="utf-8"
            )
            popen = FakePopen()

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("run `up` first", str(ctx.exception))
            self.assertEqual(popen.calls, [])


class CheckBackupCredentialsTests(unittest.TestCase):
    """The pre-flight warning `up` prints when stack.toml's bucket turns the
    node's nightly timer on but secrets.age cannot make it work. Two
    independent gates (nixos/backups.nix's `enable`, and this module's
    all-or-nothing r2_* set) that nothing else compares."""

    def _warnings(self, bucket: str | None, backup_env_sha: str | None) -> list[str]:
        emitted: list[str] = []
        check_backup_credentials(bucket, backup_env_sha, emit=emitted.append)
        return emitted

    def test_a_bucket_with_no_credentials_warns_and_names_all_three_keys(self) -> None:
        lines = self._warnings("acme-backups", None)

        self.assertEqual(len(lines), 1)
        line = lines[0]
        self.assertIn("acme-backups", line)
        self.assertIn(BACKUP_ENV_PATH, line)
        for key in ("r2_access_key_id", "r2_secret_access_key", "r2_endpoint"):
            self.assertIn(key, line)

    def test_an_incomplete_credential_set_warns_the_same_way(self) -> None:
        # backup_env_content() is all-or-nothing, so two of the three keys
        # render as None -- the same `backup_env_sha is None` this sees.
        partial = backup_env_content({"r2_access_key_id": "AKIA", "r2_endpoint": "https://r2.example.com"})

        self.assertIsNone(partial)
        self.assertEqual(len(self._warnings("acme-backups", None)), 1)

    def test_a_bucket_with_a_complete_set_is_silent(self) -> None:
        content = backup_env_content(_FULL_SECRETS)

        self.assertIsNotNone(content)
        self.assertEqual(self._warnings("acme-backups", backup_env_digest(content or "")), [])

    def test_no_bucket_is_silent_even_with_no_credentials(self) -> None:
        # Backups are simply off -- nothing is installed on the node, so
        # there is nothing to warn about.
        self.assertEqual(self._warnings(None, None), [])
        self.assertEqual(self._warnings("", None), [])


if __name__ == "__main__":
    unittest.main()
