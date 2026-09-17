"""Tests for stackbase.config: stack.toml -> StackConfig, stack.state.json <-> StackState."""

import json
import tempfile
import unittest
from pathlib import Path

from stackbase.config import (
    CloudflareState,
    HostingerState,
    Node,
    NodeState,
    StackState,
    load_config,
    load_state,
    save_state,
)
from stackbase.errors import StackError

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


class StateRoundTripTests(unittest.TestCase):
    def test_missing_state_file_is_empty_state(self) -> None:
        with TempInfraDir() as infra_dir:
            state = load_state(infra_dir)

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
                ),
            },
            cloudflare=CloudflareState(zone_id="zone-1", record_id="record-1"),
            hostinger=HostingerState(firewall_id=1, ssh_key_ids={"matt": 1}),
        )

        with TempInfraDir() as infra_dir_a, TempInfraDir() as infra_dir_b:
            save_state(infra_dir_a, state)
            first_bytes = (infra_dir_a / "stack.state.json").read_bytes()

            loaded = load_state(infra_dir_a)
            self.assertEqual(loaded, state)

            save_state(infra_dir_b, loaded)
            second_bytes = (infra_dir_b / "stack.state.json").read_bytes()

            self.assertEqual(first_bytes, second_bytes)
            self.assertTrue(first_bytes.endswith(b"\n"))
            self.assertFalse(first_bytes.endswith(b"\n\n"))

    def test_save_state_is_atomic_no_leftover_tmp_file(self) -> None:
        state = StackState()
        with TempInfraDir() as infra_dir:
            save_state(infra_dir, state)

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
                save_state(infra_dir, state)

            self.assertEqual(len(seen_names), 1)
            self.assertIn(str(os.getpid()), seen_names[0])

    def test_load_state_rejects_unknown_top_level_key(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "bogus": True}), encoding="utf-8"
            )

            with self.assertRaises(StackError):
                load_state(infra_dir)

    def test_load_state_rejects_unsupported_version(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 2}), encoding="utf-8"
            )

            with self.assertRaises(StackError):
                load_state(infra_dir)

    def test_node_state_app_env_sha_defaults_to_none_for_older_state_files(self) -> None:
        """A stack.state.json written before this field existed has no
        'app_env_sha' key -- it must load as None, not error, and not be
        confused with "converged" (plan()'s `_needs_app_env` treats None the
        same as "never pushed")."""
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {"a": {"vps_id": 1}}}), encoding="utf-8"
            )

            state = load_state(infra_dir)

            self.assertIsNone(state.nodes["a"].app_env_sha)

    def test_load_state_rejects_unknown_node_key(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "stack.state.json").write_text(
                json.dumps({"version": 1, "nodes": {"a": {"bogus": True}}}), encoding="utf-8"
            )

            with self.assertRaises(StackError):
                load_state(infra_dir)


class StackErrorFormattingTests(unittest.TestCase):
    def test_str_joins_message_and_hint(self) -> None:
        err = StackError("something broke", "check the thing")
        self.assertEqual(str(err), "something broke — check the thing")


if __name__ == "__main__":
    unittest.main()
