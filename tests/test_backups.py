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
        self.assertEqual(BACKUP_ENV_PATH, "/var/lib/stackbase/backup.env")


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


if __name__ == "__main__":
    unittest.main()
