"""Tests for stackbase.config: stack.toml -> StackConfig, stack.state.json <-> StackState."""

import json
import tempfile
import unittest
from pathlib import Path

from stackbase.config import (
    AlertsConfig,
    AppConfig,
    BackupsConfig,
    CloudflareState,
    Environment,
    FilesConfig,
    HostingerState,
    LogsConfig,
    Node,
    NodeState,
    StackState,
    load_config,
    load_state,
    save_state,
    state_path,
)
from stackbase.errors import StackError
from stackbase.secrets import DEPLOY_FILE, SECRETS_FILE, deploy_file, deploy_pub_path, secrets_file

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# The implicit environment of a single-environment project, as far as the
# state-file functions care: only its (empty) name decides the file name.
_IMPLICIT = Environment(name="", domain="acme.example.com", plan="KVM 1", price_item=None, nodes={})

VALID_TOML = """\
project = "acme"
domain = "acme.example.com"
owner = "octocat"
datacenter = "kul"
plan = "KVM 1"
admins = ["matt"]

[nodes.a]
role = "primary"
vps_id = 1984476

[nodes.b]
role = "replica"
"""

VALID_ED25519_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBoguskeydataherefortesting matt@example.com\n"

# A bucket line that is itself valid, for the [backups] tests that are about
# some OTHER field. Deliberately not a one-character name: `_BUCKET_RE`
# requires at least two, so a short placeholder would make those tests pass
# because the BUCKET was rejected, never reaching the field under test.
_VALID_BUCKET = 'bucket = "acme-backups"'


class TempInfraDir:
    """Context manager for a scratch infra/ directory with a stack.toml and keys/."""

    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        (self.path / "keys").mkdir()
        return self.path

    def __exit__(self, *exc_info: object) -> None:
        self._tmp.cleanup()


def write_toml(infra_dir: Path, content: str) -> None:
    (infra_dir / "stack.toml").write_text(content, encoding="utf-8")


def write_key(infra_dir: Path, admin: str, content: str) -> None:
    (infra_dir / "keys" / f"{admin}.pub").write_text(content, encoding="utf-8")


class LoadConfigTests(unittest.TestCase):
    def test_valid_file_loads(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(config.project, "acme")
            self.assertEqual(config.domain, "acme.example.com")
            self.assertEqual(config.owner, "octocat")
            self.assertEqual(config.datacenter, "kul")
            self.assertEqual(config.plan, "KVM 1")
            self.assertIsNone(config.price_item)
            self.assertTrue(config.auto_patch)
            self.assertEqual(config.admins, ["matt"])
            self.assertEqual(
                config.nodes,
                {
                    "a": Node(name="a", role="primary", vps_id=1984476),
                    "b": Node(name="b", role="replica", vps_id=None),
                },
            )
            self.assertEqual(config.admin_keys, {"matt": VALID_ED25519_KEY.strip()})

    def test_rejects_bad_project_name(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML.replace('project = "acme"', 'project = "1Acme_Bad"'))
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_rejects_a_node_name_that_could_reach_a_shell(self) -> None:
        """A node name becomes a hostname, a Nix attribute AND part of a remote command.

        `nixos-rebuild --flake /etc/nixos/stack#<node>` runs as root on the
        server, so an unvalidated TOML table key is a command-injection path
        (and `infra/nodes/<node>/` is a path-traversal one). Remote commands
        quote their arguments as well -- this is the first of the two layers.
        """
        for name in ('a; touch /tmp/pwned #', "../../etc", "A", "-a", "a b", "1a", "a" * 32):
            with self.subTest(name=name):
                toml = VALID_TOML.replace("[nodes.a]", f'[nodes."{name}"]')
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, toml)
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError) as caught:
                        load_config(infra_dir)

                    self.assertIn("node", str(caught.exception).lower())

    def test_accepts_ordinary_node_names(self) -> None:
        for name in ("a", "web", "db-2", "a" * 31):
            with self.subTest(name=name):
                toml = VALID_TOML.replace("[nodes.a]", f'[nodes."{name}"]')
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, toml)
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    self.assertIn(name, load_config(infra_dir).nodes)

    def test_rejects_a_domain_that_is_not_a_hostname(self) -> None:
        for domain in ("acme.example.com; rm -rf /", "-acme.example.com", "acme example.com", "acme", ""):
            with self.subTest(domain=domain):
                toml = VALID_TOML.replace('domain = "acme.example.com"', f'domain = "{domain}"')
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, toml)
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError):
                        load_config(infra_dir)

    def test_rejects_an_odd_datacenter_or_owner(self) -> None:
        for original, replacement in (
            ('datacenter = "kul"', 'datacenter = "kul; id"'),
            ('owner = "octocat"', 'owner = "octo cat"'),
        ):
            with self.subTest(replacement=replacement):
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, VALID_TOML.replace(original, replacement))
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError):
                        load_config(infra_dir)

    def test_rejects_zero_primaries(self) -> None:
        toml = VALID_TOML.replace('role = "primary"', 'role = "replica"')
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_rejects_two_primaries(self) -> None:
        toml = VALID_TOML.replace('role = "replica"', 'role = "primary"')
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_rejects_admin_without_pub_file(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            # deliberately do not write keys/matt.pub

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_rejects_pub_file_with_multiple_lines(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY + VALID_ED25519_KEY)

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_rejects_pub_file_with_wrong_key_type(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", "ecdsa-sha2-nistp256 AAAABogus matt@example.com\n")

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_accepts_sk_ssh_ed25519_key(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", "sk-ssh-ed25519@openssh.com AAAABogus matt@example.com\n")

            config = load_config(infra_dir)
            self.assertTrue(config.admin_keys["matt"].startswith("sk-ssh-ed25519@openssh.com"))

    def test_accepts_ssh_rsa_key(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", "ssh-rsa AAAABogus matt@example.com\n")

            config = load_config(infra_dir)
            self.assertTrue(config.admin_keys["matt"].startswith("ssh-rsa"))

    def test_rejects_a_bool_vps_id(self) -> None:
        # bool is a subclass of int in Python -- `vps_id = true` must not
        # silently become VPS id 1 (or `false` -> id 0).
        for literal in ("true", "false"):
            with self.subTest(literal=literal):
                toml = VALID_TOML.replace("vps_id = 1984476", f"vps_id = {literal}")
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, toml)
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError):
                        load_config(infra_dir)

    def test_vps_id_optional(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertIsNone(config.nodes["b"].vps_id)

    def test_app_table_is_absent_by_default(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(config.app, AppConfig())

    def test_app_table_is_parsed(self) -> None:
        with TempInfraDir() as infra_dir:
            toml = VALID_TOML + (
                "\n[app]\n"
                'binary = "stack_demo"\n'
                'health_path = "/healthz"\n'
                "health_tries = 45\n"
                "health_sleep = 3\n"
            )
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(
                config.app,
                AppConfig(binary="stack_demo", health_path="/healthz", health_tries=45, health_sleep=3),
            )

    def test_app_table_fields_are_all_optional(self) -> None:
        with TempInfraDir() as infra_dir:
            toml = VALID_TOML + '\n[app]\nbinary = "stack_demo"\n'
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(config.app.binary, "stack_demo")
            self.assertIsNone(config.app.health_path)
            self.assertIsNone(config.app.health_tries)
            self.assertIsNone(config.app.health_sleep)

    def test_app_binary_rejects_bad_characters(self) -> None:
        with TempInfraDir() as infra_dir:
            toml = VALID_TOML + '\n[app]\nbinary = "not a valid binary!"\n'
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError):
                load_config(infra_dir)

    def test_app_health_path_must_start_with_slash_and_have_no_whitespace(self) -> None:
        for bad in ("healthz", "/health check", ""):
            with self.subTest(bad=bad):
                with TempInfraDir() as infra_dir:
                    toml = VALID_TOML + f'\n[app]\nhealth_path = "{bad}"\n'
                    write_toml(infra_dir, toml)
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError):
                        load_config(infra_dir)

    def test_app_health_tries_and_sleep_reject_out_of_range_and_bool_values(self) -> None:
        for line in ("health_tries = 0", "health_tries = 301", "health_tries = true", "health_sleep = 0", "health_sleep = 61"):
            with self.subTest(line=line):
                with TempInfraDir() as infra_dir:
                    toml = VALID_TOML + f"\n[app]\n{line}\n"
                    write_toml(infra_dir, toml)
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError):
                        load_config(infra_dir)

    def test_app_table_rejects_unknown_keys(self) -> None:
        with TempInfraDir() as infra_dir:
            toml = VALID_TOML + '\n[app]\nbogus = "x"\n'
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError) as caught:
                load_config(infra_dir)

            self.assertIn("bogus", str(caught.exception))

    def test_backups_table_is_absent_by_default(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(config.backups, BackupsConfig())
            self.assertIsNone(config.backups.bucket)
            self.assertIsNone(config.backups.retention_days)
            self.assertIsNone(config.backups.extra_paths)
            self.assertIsNone(config.backups.on_calendar)

    def test_backups_table_is_parsed(self) -> None:
        with TempInfraDir() as infra_dir:
            toml = VALID_TOML + (
                "\n[backups]\n"
                'bucket = "acme-backups"\n'
                "retention_days = 14\n"
                'extra_paths = ["/var/lib/acme/uploads"]\n'
                'on_calendar = "04:30"\n'
            )
            write_toml(infra_dir, toml)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(
                config.backups,
                BackupsConfig(
                    bucket="acme-backups",
                    retention_days=14,
                    extra_paths=["/var/lib/acme/uploads"],
                    on_calendar="04:30",
                ),
            )

    def test_backups_table_fields_are_all_optional(self) -> None:
        """Naming a bucket is all it takes -- every other field keeps
        nixos/backups.nix's own module-level default."""
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML + '\n[backups]\nbucket = "acme-backups"\n')
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertEqual(config.backups.bucket, "acme-backups")
            self.assertIsNone(config.backups.retention_days)
            self.assertIsNone(config.backups.extra_paths)
            self.assertIsNone(config.backups.on_calendar)

    def test_backups_table_rejects_unknown_keys(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML + f'\n[backups]\n{_VALID_BUCKET}\nbogus = "x"\n')
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError) as caught:
                load_config(infra_dir)

            self.assertIn("bogus", str(caught.exception))

    def test_backups_bucket_rejects_shell_unsafe_and_empty_values(self) -> None:
        """The bucket is interpolated into an rclone remote path in a root
        shell on the node -- nothing with a space, a quote or a leading
        dash gets that far."""
        for bad in ('""', '"my bucket"', '"-flag"', '"a;rm -rf /"', '"a$(id)"'):
            with self.subTest(bad=bad):
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, VALID_TOML + f"\n[backups]\nbucket = {bad}\n")
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError):
                        load_config(infra_dir)

    def test_backups_bucket_rejects_a_dot_dot_path_segment(self) -> None:
        """Fix round 1, finding 3: the regex allows '.' and '/' so a bucket
        may carry a prefix -- which let '..' through. Against a real S3
        bucket keys are literal, but Task 6's VM subtest runs the same code
        with RCLONE_CONFIG_BACKUP_TYPE=local, where '..' escapes the remote's
        root and `rclone delete --min-age` follows it out."""
        for bad in ("a/../..", "../evil", "acme-backups/..", "a/./b", "a//b", "acme-backups/"):
            with self.subTest(bad=bad):
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, VALID_TOML + f'\n[backups]\nbucket = "{bad}"\n')
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError) as caught:
                        load_config(infra_dir)

                    self.assertIn("bucket", str(caught.exception))

    def test_backups_bucket_still_allows_a_plain_name_and_a_prefix(self) -> None:
        """The traversal guard must not cost a project its legitimate
        `<bucket>/<prefix>` layout."""
        for good in ("acme-backups", "acme-backups/prod", "acme.backups", "acme_backups-2"):
            with self.subTest(good=good):
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, VALID_TOML + f'\n[backups]\nbucket = "{good}"\n')
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    self.assertEqual(load_config(infra_dir).backups.bucket, good)

    def test_backups_retention_days_rejects_zero_and_out_of_range_values(self) -> None:
        """0 would mean `rclone delete --min-age 0d` -- "everything,
        including what was just written". It must never be expressible."""
        for line in ("retention_days = 0", "retention_days = -1", "retention_days = 3651", "retention_days = true"):
            with self.subTest(line=line):
                with TempInfraDir() as infra_dir:
                    write_toml(infra_dir, VALID_TOML + f"\n[backups]\n{_VALID_BUCKET}\n{line}\n")
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError) as caught:
                        load_config(infra_dir)

                    # Named explicitly so this cannot pass because the
                    # BUCKET was rejected first and retention never looked at.
                    self.assertIn("retention_days", str(caught.exception))

    def test_backups_extra_paths_must_be_absolute_with_no_whitespace_or_quotes(self) -> None:
        for bad in ('["relative/path"]', '["/a b"]', '["/a\'b"]', '["/a\\"b"]', "[1]", '"/not-a-list"'):
            with self.subTest(bad=bad):
                with TempInfraDir() as infra_dir:
                    write_toml(
                        infra_dir, VALID_TOML + f"\n[backups]\n{_VALID_BUCKET}\nextra_paths = {bad}\n"
                    )
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError) as caught:
                        load_config(infra_dir)

                    self.assertIn("extra_paths", str(caught.exception))

    def test_backups_on_calendar_must_be_a_24_hour_time(self) -> None:
        for bad in ("25:00", "3:00", "03:60", "daily", "03:00:00"):
            with self.subTest(bad=bad):
                with TempInfraDir() as infra_dir:
                    write_toml(
                        infra_dir, VALID_TOML + f'\n[backups]\n{_VALID_BUCKET}\non_calendar = "{bad}"\n'
                    )
                    write_key(infra_dir, "matt", VALID_ED25519_KEY)

                    with self.assertRaises(StackError) as caught:
                        load_config(infra_dir)

                    self.assertIn("on_calendar", str(caught.exception))


class StateRoundTripTests(unittest.TestCase):
    def test_missing_state_file_is_empty_state(self) -> None:
        with TempInfraDir() as infra_dir:
            state = load_state(infra_dir, _IMPLICIT)

            self.assertEqual(state, StackState())
            self.assertEqual(state.version, 1)
            self.assertEqual(state.nodes, {})
            self.assertEqual(state.cloudflare, CloudflareState())
            self.assertEqual(state.hostinger, HostingerState())

    def test_state_round_trips_byte_identically(self) -> None:
        state = StackState(
            version=1,
            nodes={
                "a": NodeState(
                    vps_id=1984476,
                    ipv4="1.2.3.4",
                    ipv6="::1",
                    host_key_pinned=True,
                    hardware_captured=True,
                    applied_rev="abc123",
                    app_env_sha="deadbeef" * 8,
                    backup_env_sha="feedface" * 8,
                ),
            },
            cloudflare=CloudflareState(zone_id="zone-1", record_id="record-1"),
            hostinger=HostingerState(firewall_id=1, ssh_key_ids={"matt": 1}),
        )

        with TempInfraDir() as infra_dir_a, TempInfraDir() as infra_dir_b:
            save_state(infra_dir_a, _IMPLICIT, state)
            first_bytes = (infra_dir_a / "stack.state.json").read_bytes()

            loaded = load_state(infra_dir_a, _IMPLICIT)
            self.assertEqual(loaded, state)

            save_state(infra_dir_b, _IMPLICIT, loaded)
            second_bytes = (infra_dir_b / "stack.state.json").read_bytes()

            self.assertEqual(first_bytes, second_bytes)
            self.assertTrue(first_bytes.endswith(b"\n"))
            self.assertFalse(first_bytes.endswith(b"\n\n"))

    def test_save_state_is_atomic_no_leftover_tmp_file(self) -> None:
        state = StackState()
        with TempInfraDir() as infra_dir:
            save_state(infra_dir, _IMPLICIT, state)

            names = {p.name for p in infra_dir.iterdir()}
            self.assertIn("stack.state.json", names)
            self.assertFalse(any(".tmp" in name for name in names if name != "stack.state.json"))

    def test_save_state_temp_file_name_includes_the_pid(self) -> None:
        """Two concurrent runs against the same infra/ must not share a temp file."""
        import os
        from unittest import mock

        state = StackState()
        seen_names: list[str] = []
        real_replace = os.replace

        def spy_replace(src, dst):
            seen_names.append(Path(src).name)
            return real_replace(src, dst)

        with TempInfraDir() as infra_dir:
            with mock.patch("stackbase.config.os.replace", side_effect=spy_replace):
                save_state(infra_dir, _IMPLICIT, state)

            self.assertEqual(len(seen_names), 1)
            self.assertIn(str(os.getpid()), seen_names[0])

    def test_load_state_rejects_unknown_top_level_key(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "bogus": True}), encoding="utf-8"
            )

            with self.assertRaises(StackError):
                load_state(infra_dir, _IMPLICIT)

    def test_load_state_rejects_unsupported_version(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 2}), encoding="utf-8"
            )

            with self.assertRaises(StackError):
                load_state(infra_dir, _IMPLICIT)

    def test_node_state_app_env_sha_defaults_to_none_for_older_state_files(self) -> None:
        """A stack.state.json written before this field existed has no
        'app_env_sha' key -- it must load as None, not error, and not be
        confused with "converged" (plan()'s `_needs_app_env` treats None the
        same as "never pushed")."""
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {"a": {"vps_id": 1}}}), encoding="utf-8"
            )

            state = load_state(infra_dir, _IMPLICIT)

            self.assertIsNone(state.nodes["a"].app_env_sha)

    def test_pending_subscription_id_round_trips_and_is_omitted_when_none(self) -> None:
        with TempInfraDir() as infra_dir:
            save_state(infra_dir, _IMPLICIT, StackState(nodes={"a": NodeState(pending_subscription_id="Azz353Uhl1xC54pR0")}))
            self.assertEqual(load_state(infra_dir, _IMPLICIT).nodes["a"].pending_subscription_id, "Azz353Uhl1xC54pR0")

            # Absent means None, and a node with no marker writes the same
            # bytes it always did (single-environment state files unchanged).
            save_state(infra_dir, _IMPLICIT, StackState(nodes={"a": NodeState(vps_id=1)}))
            raw = (infra_dir / "stack.state.json").read_text(encoding="utf-8")
            self.assertNotIn("pending_subscription_id", raw)
            self.assertIsNone(load_state(infra_dir, _IMPLICIT).nodes["a"].pending_subscription_id)

    def test_node_state_backup_env_sha_defaults_to_none_for_older_state_files(self) -> None:
        """Same contract as app_env_sha above: a state file written before
        backups existed must load, with None meaning "never pushed"."""
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {"a": {"vps_id": 1}}}), encoding="utf-8"
            )

            state = load_state(infra_dir, _IMPLICIT)

            self.assertIsNone(state.nodes["a"].backup_env_sha)

    def test_load_state_rejects_unknown_node_key(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {"a": {"bogus": True}}}), encoding="utf-8"
            )

            with self.assertRaises(StackError):
                load_state(infra_dir, _IMPLICIT)



def _envs_project(infra_dir: Path, toml: str | None = None) -> None:
    write_toml(infra_dir, toml if toml is not None else (_FIXTURES / "stack-envs.toml").read_text(encoding="utf-8"))
    write_key(infra_dir, "matt", VALID_ED25519_KEY)


_TWO_ENVS = """\
project = "acme"
owner = "octocat"
datacenter = "kul"
plan = "KVM 1"
admins = ["matt"]

[environments.staging]
domain = "staging.acme.example.com"
[environments.staging.nodes.a]
role = "primary"

[environments.production]
domain = "acme.example.com"
[environments.production.nodes.a]
role = "primary"
"""


class EnvironmentsTests(unittest.TestCase):
    def test_legacy_file_is_one_implicit_env(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            config = load_config(infra_dir)

            self.assertTrue(config.implicit_env)
            self.assertEqual(list(config.environments), [""])
            env = config.env(None)
            self.assertEqual(env.name, "")
            self.assertEqual(env.domain, "acme.example.com")
            self.assertEqual(env.plan, "KVM 1")
            self.assertEqual(env.nodes, config.nodes)
            self.assertEqual(env.backups, config.backups)
            self.assertEqual(state_path(infra_dir, env), infra_dir / "stack.state.json")
            # The very same descriptors as before environments existed.
            self.assertIs(secrets_file(env), SECRETS_FILE)
            self.assertIs(deploy_file(env), DEPLOY_FILE)
            self.assertEqual(secrets_file(env).name, "secrets.age")
            self.assertEqual(secrets_file(env).recipients_path(infra_dir), infra_dir / "age-recipients.txt")
            self.assertEqual(deploy_file(env).name, "deploy.age")
            self.assertEqual(deploy_pub_path(infra_dir, env), infra_dir / "keys" / "deploy.pub")

    def test_legacy_file_refuses_an_env_name(self) -> None:
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)

            with self.assertRaises(StackError) as caught:
                load_config(infra_dir).env("staging")

            self.assertIn("staging", str(caught.exception))
            self.assertIn("[environments]", str(caught.exception))

    def test_environments_fixture_parses_in_order_with_merged_sections(self) -> None:
        with TempInfraDir() as infra_dir:
            _envs_project(infra_dir)

            config = load_config(infra_dir)

            self.assertFalse(config.implicit_env)
            self.assertEqual(list(config.environments), ["staging", "production"])
            staging = config.env("staging")
            production = config.env("production")

            self.assertEqual(staging.domain, "staging.acme.example.com")
            self.assertEqual(staging.plan, "KVM 1")
            self.assertIsNone(staging.price_item)
            self.assertEqual(list(staging.nodes), ["a"])
            self.assertEqual(staging.nodes["a"], Node(name="a", role="primary", vps_id=1111111))
            self.assertEqual(
                staging.backups,
                BackupsConfig(bucket="acme-backups-staging", retention_days=30, on_calendar="03:00"),
            )
            self.assertEqual(staging.logs, LogsConfig(bucket="acme-logs-staging", retention_days=90))
            self.assertEqual(staging.alerts, AlertsConfig(to=["ops@example.com", "servers.acme.staging@example.com"]))
            self.assertEqual(staging.files, FilesConfig(bucket="acme-files-staging", lock_days=7))

            self.assertEqual(production.domain, "acme.example.com")
            self.assertEqual(production.plan, "KVM 2")
            self.assertEqual(production.price_item, "hostingercom-vps-kvm2-usd-1m")
            self.assertEqual(list(production.nodes), ["a", "b"])
            # Shared values, with only retention_days overridden.
            self.assertEqual(
                production.backups,
                BackupsConfig(bucket="acme-backups", retention_days=365, on_calendar="03:00"),
            )
            self.assertEqual(production.logs, LogsConfig(bucket="acme-logs", retention_days=90))
            self.assertEqual(production.alerts, AlertsConfig(to=["ops@example.com"]))
            self.assertEqual(production.files, FilesConfig(bucket="acme-files", lock_days=30))

    def test_envs_parse_overrides_only_allowed_keys(self) -> None:
        for extra, named in (
            ("app = {}", "app"),
            ('owner = "someone-else"', "owner"),
            ("auto_patch = false", "auto_patch"),
            ('backups.extra_paths = ["/srv"]', "backups.extra_paths"),
            ('backups.on_calendar = "04:00"', "backups.on_calendar"),
            ("backups.enabled = false", "backups.enabled"),
            ("logs.enabled = false", "logs.enabled"),
            ('alerts.cc = ["x@example.com"]', "alerts.cc"),
            ("files.versioning = true", "files.versioning"),
        ):
            with self.subTest(extra=extra):
                toml = _TWO_ENVS.replace(
                    '[environments.staging]\ndomain = "staging.acme.example.com"\n',
                    f'[environments.staging]\ndomain = "staging.acme.example.com"\n{extra}\n',
                )
                self.assertIn(extra, toml)
                with TempInfraDir() as infra_dir:
                    _envs_project(infra_dir, toml)

                    with self.assertRaises(StackError) as caught:
                        load_config(infra_dir)

                    self.assertIn(named, str(caught.exception))
                    self.assertIn("environments.staging", str(caught.exception))

    def test_nodes_and_environments_together_rejected(self) -> None:
        with TempInfraDir() as infra_dir:
            _envs_project(infra_dir, _TWO_ENVS + '\n[nodes.a]\nrole = "primary"\n')

            with self.assertRaises(StackError) as caught:
                load_config(infra_dir)

            self.assertIn("[nodes", str(caught.exception))
            self.assertIn("[environments", str(caught.exception))

    def test_an_environment_needs_a_domain_and_nodes(self) -> None:
        for broken, named in (
            (_TWO_ENVS.replace('domain = "staging.acme.example.com"\n', ""), "domain"),
            (_TWO_ENVS.replace('domain = "staging.acme.example.com"\n', 'domain = "not a domain"\n'), "domain"),
            (_TWO_ENVS.replace('[environments.staging.nodes.a]\nrole = "primary"\n', ""), "nodes"),
            (
                _TWO_ENVS.replace('[environments.staging.nodes.a]\nrole = "primary"\n',
                                  '[environments.staging.nodes.a]\nrole = "replica"\n'),
                "primary",
            ),
            (_TWO_ENVS.replace('plan = "KVM 1"\n', ""), "plan"),
        ):
            with self.subTest(named=named), TempInfraDir() as infra_dir:
                _envs_project(infra_dir, broken)

                with self.assertRaises(StackError) as caught:
                    load_config(infra_dir)

                self.assertIn(named, str(caught.exception))

    def test_a_per_environment_plan_stands_in_for_a_missing_shared_one(self) -> None:
        toml = _TWO_ENVS.replace('plan = "KVM 1"\n', "").replace(
            'domain = "staging.acme.example.com"\n', 'domain = "staging.acme.example.com"\nplan = "KVM 1"\n'
        ).replace('domain = "acme.example.com"\n', 'domain = "acme.example.com"\nplan = "KVM 2"\n')
        with TempInfraDir() as infra_dir:
            _envs_project(infra_dir, toml)

            config = load_config(infra_dir)

            self.assertEqual(config.env("staging").plan, "KVM 1")
            self.assertEqual(config.env("production").plan, "KVM 2")

    def test_env_name_pattern(self) -> None:
        for good in ("staging", "prod-eu", "qa-2", "p", "a234567890123456"):
            with self.subTest(good=good), TempInfraDir() as infra_dir:
                _envs_project(infra_dir, _TWO_ENVS.replace("environments.staging", f"environments.{good}"))
                self.assertIn(good, load_config(infra_dir).environments)
        for bad in ("Staging", "2nd", "-x", "a2345678901234567", '"a b"', '"a.b"', '"a;rm"', '"a_b"', '""'):
            with self.subTest(bad=bad), TempInfraDir() as infra_dir:
                _envs_project(infra_dir, _TWO_ENVS.replace("environments.staging", f"environments.{bad}"))
                with self.assertRaises(StackError) as caught:
                    load_config(infra_dir)
                self.assertIn("environment name", str(caught.exception))

    def test_two_environments_cannot_share_a_vps_or_a_domain(self) -> None:
        shared_vps = _TWO_ENVS.replace(
            '[environments.staging.nodes.a]\nrole = "primary"\n', '[environments.staging.nodes.a]\nrole = "primary"\nvps_id = 42\n'
        ).replace(
            '[environments.production.nodes.a]\nrole = "primary"\n',
            '[environments.production.nodes.a]\nrole = "primary"\nvps_id = 42\n',
        )
        shared_domain = _TWO_ENVS.replace('domain = "staging.acme.example.com"', 'domain = "ACME.example.com"')
        for toml, named in ((shared_vps, "42"), (shared_domain, "acme.example.com")):
            with self.subTest(named=named), TempInfraDir() as infra_dir:
                self.assertNotEqual(toml, _TWO_ENVS)
                _envs_project(infra_dir, toml)

                with self.assertRaises(StackError) as caught:
                    load_config(infra_dir)

                message = caught.exception.message
                self.assertIn("'staging'", message)
                self.assertIn("'production'", message)
                self.assertIn(named, message.lower())

    def test_a_vps_id_used_twice_within_one_environment_is_not_this_check(self) -> None:
        # Distinct ids across environments load fine.
        toml = _TWO_ENVS.replace(
            '[environments.staging.nodes.a]\nrole = "primary"\n', '[environments.staging.nodes.a]\nrole = "primary"\nvps_id = 1\n'
        ).replace(
            '[environments.production.nodes.a]\nrole = "primary"\n',
            '[environments.production.nodes.a]\nrole = "primary"\nvps_id = 2\n',
        )
        with TempInfraDir() as infra_dir:
            _envs_project(infra_dir, toml)
            self.assertEqual(load_config(infra_dir).env("production").nodes["a"].vps_id, 2)

    def test_an_empty_or_non_table_environments_key_is_an_error(self) -> None:
        legacy_body = VALID_TOML.split("[nodes.a]")[0]
        for value in ("environments = {}\n", 'environments = "staging"\n', "environments = []\n"):
            with self.subTest(value=value), TempInfraDir() as infra_dir:
                write_toml(infra_dir, legacy_body.replace('domain = "acme.example.com"\n', "") + value)
                write_key(infra_dir, "matt", VALID_ED25519_KEY)

                with self.assertRaises(StackError) as caught:
                    load_config(infra_dir)

                self.assertIn("[environments]", str(caught.exception))

    def test_env_selection_errors(self) -> None:
        with TempInfraDir() as infra_dir:
            _envs_project(infra_dir)
            config = load_config(infra_dir)

            with self.assertRaises(StackError) as caught:
                config.env(None)
            self.assertEqual(caught.exception.message, "this project has environments: staging, production")
            self.assertEqual(caught.exception.hint, "add --env <name>")

            with self.assertRaises(StackError) as caught:
                config.env("prod")
            self.assertIn("prod", caught.exception.message)
            self.assertIn("staging, production", str(caught.exception))

    def test_env_state_and_secrets_paths(self) -> None:
        with TempInfraDir() as infra_dir:
            _envs_project(infra_dir)
            staging = load_config(infra_dir).env("staging")

            self.assertEqual(state_path(infra_dir, staging), infra_dir / "stack.state.staging.json")
            self.assertEqual(secrets_file(staging).name, "secrets.staging.age")
            self.assertEqual(deploy_file(staging).name, "deploy.staging.age")
            self.assertEqual(deploy_pub_path(infra_dir, staging), infra_dir / "keys" / "deploy.staging.pub")

            # Recipients: the environment's own list when it has one, else the shared one.
            self.assertEqual(secrets_file(staging).recipients_path(infra_dir), infra_dir / "age-recipients.txt")
            self.assertEqual(deploy_file(staging).recipients_path(infra_dir), infra_dir / "deploy-recipients.txt")
            (infra_dir / "age-recipients.staging.txt").write_text("age1x\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.staging.txt").write_text("age1x\n", encoding="utf-8")
            self.assertEqual(
                secrets_file(staging).recipients_path(infra_dir), infra_dir / "age-recipients.staging.txt"
            )
            self.assertEqual(
                deploy_file(staging).recipients_path(infra_dir), infra_dir / "deploy-recipients.staging.txt"
            )

            # State round-trips per environment and never touches the other's file.
            save_state(infra_dir, staging, StackState(nodes={"a": NodeState(vps_id=1, pending_subscription_id="sub1")}))
            self.assertTrue((infra_dir / "stack.state.staging.json").exists())
            self.assertFalse((infra_dir / "stack.state.json").exists())
            self.assertFalse((infra_dir / "stack.state.production.json").exists())
            self.assertEqual(load_state(infra_dir, staging).nodes["a"].pending_subscription_id, "sub1")
            production = load_config(infra_dir).env("production")
            self.assertEqual(load_state(infra_dir, production), StackState())


class SectionTypesTests(unittest.TestCase):
    """[logs], [alerts], [files] and [backups].enabled: parsed and type-checked
    here; the policy checks on top of them belong to later tasks."""

    def _load(self, extra: str):
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML + "\n" + extra)
            write_key(infra_dir, "matt", VALID_ED25519_KEY)
            return load_config(infra_dir)

    def test_absent_sections_default_to_empty(self) -> None:
        config = self._load("")
        env = config.env(None)
        self.assertEqual(env.logs, LogsConfig())
        self.assertEqual(env.alerts, AlertsConfig())
        self.assertEqual(env.files, FilesConfig())
        self.assertIsNone(env.backups.enabled)
        self.assertEqual(AlertsConfig().to, [])

    def test_sections_parse(self) -> None:
        config = self._load(
            "[backups]\nenabled = false\n"
            '[logs]\nenabled = true\nbucket = "acme-logs"\nretention_days = 365\n'
            '[alerts]\nto = ["a@example.com", "b@example.com"]\n'
            '[files]\nbucket = "acme-files"\nlock_days = 30\n'
        )
        env = config.env(None)
        self.assertEqual(env.backups, BackupsConfig(enabled=False))
        self.assertEqual(env.logs, LogsConfig(enabled=True, bucket="acme-logs", retention_days=365))
        self.assertEqual(env.alerts, AlertsConfig(to=["a@example.com", "b@example.com"]))
        self.assertEqual(env.files, FilesConfig(bucket="acme-files", lock_days=30))

    def test_wrong_types_are_refused(self) -> None:
        for extra, named in (
            ('[backups]\nenabled = "no"\n', "enabled"),
            ('[logs]\nenabled = 1\n', "enabled"),
            ("[logs]\nbucket = 3\n", "bucket"),
            ('[logs]\nbucket = "a b"\n', "bucket"),
            ('[logs]\nretention_days = "90"\n', "retention_days"),
            ("[logs]\nretention_days = true\n", "retention_days"),
            ('[logs]\nbogus = 1\n', "bogus"),
            ('[alerts]\nto = "a@example.com"\n', "to"),
            ("[alerts]\nto = [1]\n", "to"),
            ('[alerts]\nto = [""]\n', "to"),
            ("[files]\nbucket = true\n", "bucket"),
            ('[files]\nlock_days = "30"\n', "lock_days"),
            ('[files]\nbogus = 1\n', "bogus"),
        ):
            with self.subTest(extra=extra):
                with self.assertRaises(StackError) as caught:
                    self._load(extra)
                self.assertIn(named, str(caught.exception))


class StackErrorFormattingTests(unittest.TestCase):
    def test_str_joins_message_and_hint(self) -> None:
        err = StackError("something broke", "check the thing")
        self.assertEqual(str(err), "something broke — check the thing")


if __name__ == "__main__":
    unittest.main()
