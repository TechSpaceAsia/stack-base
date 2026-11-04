"""Tests for `templates/infra/` -- the files a consuming project gets.

`templates/infra/up` is exercised for real (as a subprocess, against a fake
stack-base checkout), and `templates/infra/flake.nix` is proved to actually
evaluate with `nix eval` -- a template that looks right but does not evaluate
would only be discovered on a live server. The Nix tests skip cleanly when
`nix` is not installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE_DIR = _REPO_ROOT / "templates" / "infra"
_NIX = shutil.which("nix")

_SAMPLE_STACK_TOML = """\
project    = "acme"
domain     = "acme.example.com"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[nodes.a]
role   = "primary"
vps_id = 1984476
"""

# The exact `nixos-generate-config --show-hardware-config` output captured
# from a real Hostinger VPS (task-8a-brief.md) -- it carries no
# boot.loader.* of its own, so evaluating the template with it only
# succeeds if the Hostinger provider module (nixos/providers/hostinger.nix)
# is what supplies the bootloader, which is the real situation on that box.
_HOSTINGER_HARDWARE = (_REPO_ROOT / "tests" / "fixtures" / "hostinger-hardware-configuration.nix").read_text(
    encoding="utf-8"
)

_EXTRA_NIX = """\
{ ... }:
{
  networking.domain = "set-by-extra-nix";
}
"""

# Proves extra.nix can still override a value the provider module sets with
# mkDefault (boot.loader.grub.device) -- the provider module must not use a
# priority extra.nix can't beat.
_EXTRA_NIX_OVERRIDES_GRUB_DEVICE = """\
{ ... }:
{
  boot.loader.grub.device = "/dev/sdz";
}
"""


_CONFD_HELLO = (_REPO_ROOT / "tests" / "fixtures" / "confd" / "hello.nix").read_text(encoding="utf-8")

_CONFD_SECOND = """\
{ ... }:
{
  environment.etc."stackbase-confd-second".text = "second\\n";
}
"""

# Decision 5 / fix round 1 controller-directed test: a conf.d module sets a
# SCALAR option plainly; extra.nix sets the SAME option with lib.mkForce and
# must win, exactly as it would against any other module -- conf.d being
# listed first in the module list decides concatenation order for
# LIST-valued options, not precedence for a scalar one.
_CONFD_SCALAR_DOMAIN = """\
{ ... }:
{
  networking.domain = "set-by-confd";
}
"""

_EXTRA_NIX_MKFORCE_DOMAIN = """\
{ lib, ... }:
{
  networking.domain = lib.mkForce "set-by-extra-mkforce";
}
"""


def _instantiate_template(directory: Path) -> None:
    """Lay out `directory` the way a real project's infra/ looks after setup."""
    shutil.copy(_TEMPLATE_DIR / "flake.nix", directory / "flake.nix")
    (directory / "stack.toml").write_text(_SAMPLE_STACK_TOML, encoding="utf-8")
    (directory / "keys").mkdir(exist_ok=True)
    (directory / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTemplateEval matt@laptop\n",
        encoding="utf-8",
    )
    (directory / "nodes" / "a").mkdir(parents=True, exist_ok=True)
    (directory / "nodes" / "a" / "hardware-configuration.nix").write_text(
        _HOSTINGER_HARDWARE, encoding="utf-8"
    )


def _nix_eval(directory: Path) -> dict:
    """Evaluate node "a" and return the facts the template is supposed to set."""
    apply_fn = (
        "node: {"
        " drvPath = node.config.system.build.toplevel.drvPath;"
        " hostName = node.config.networking.hostName;"
        " domain = node.config.networking.domain;"
        " project = node.config.stackbase.project;"
        " adminKeys = node.config.users.users.root.openssh.authorizedKeys.keys;"
        " grubDevice = node.config.boot.loader.grub.device;"
        " cloudInitEnable = node.config.services.cloud-init.enable;"
        " cloudInitNetworkEnable = node.config.services.cloud-init.network.enable;"
        " networkdEnable = node.config.systemd.network.enable;"
        " passwordAuthentication = node.config.services.openssh.settings.PasswordAuthentication;"
        " firewallPorts = node.config.networking.firewall.allowedTCPPorts;"
        " appBinary = node.config.stackbase.app.binary;"
        " appHealthPath = node.config.stackbase.app.healthPath;"
        " appHealthTries = node.config.stackbase.app.healthTries;"
        " appHealthSleep = node.config.stackbase.app.healthSleep;"
        " backupsEnable = node.config.stackbase.backups.enable;"
        " backupsBucket = node.config.stackbase.backups.bucket;"
        " backupsRetentionDays = node.config.stackbase.backups.retentionDays;"
        " backupsExtraPaths = node.config.stackbase.backups.extraPaths;"
        " backupsOnCalendar = node.config.stackbase.backups.onCalendar;"
        " }"
    )
    result = subprocess.run(
        [
            _NIX or "nix", "eval", "--json",
            # An explicit `path:` flakeref: without it nix walks up looking
            # for an enclosing git repository and tries to fetch that instead.
            f"path:{directory}#nixosConfigurations.a",
            "--apply", apply_fn,
            "--override-input", "stack-base", f"path:{_REPO_ROOT}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"nix eval failed:\n{result.stderr}")
    return json.loads(result.stdout)


def _eval_mk_node(apply_fn: str, *, provider: str | None = "OMIT", extra_config: str = "") -> subprocess.CompletedProcess:
    """Evaluate `stack-base`'s own `lib.mkNode` directly -- no on-disk
    template instantiation, no toplevel build -- for tests that only need
    one `config.*` (or error) fact out of it.

    `provider`: `"OMIT"` (the default) leaves the `provider` argument out of
    the call entirely, exercising `mkNode`'s own Nix-level default; any
    other Python value is rendered as the literal Nix `provider = <value>;`
    (so pass `'"hostinger"'`, `"null"`, or `'"bogus"'` -- already valid Nix
    source, not a Python string to be quoted again).
    """
    provider_line = "" if provider == "OMIT" else f"provider = {provider};"
    expr = (
        f'let flake = builtins.getFlake "path:{_REPO_ROOT}"; '
        f"node = flake.lib.mkNode {{ "
        f"{provider_line} "
        f"modules = [ {{ stackbase.project = \"t\"; stackbase.domain = \"t.example.com\"; {extra_config} }} ]; "
        f"}}; in {apply_fn}"
    )
    return subprocess.run(
        [_NIX or "nix", "eval", "--impure", "--json", "--expr", expr],
        capture_output=True,
        text=True,
        check=False,
    )


@unittest.skipIf(_NIX is None, "nix is not installed")
class TemplateFlakeEvaluatesTests(unittest.TestCase):
    """The template must build a real NixOS system from stack.toml alone."""

    def test_it_builds_one_node_per_stack_toml_entry(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = _nix_eval(directory)

            self.assertTrue(facts["drvPath"].endswith(".drv"))
            self.assertIn("nixos-system-a", facts["drvPath"])
            self.assertEqual(facts["hostName"], "a")
            self.assertEqual(facts["project"], "acme")
            self.assertTrue(any("ExampleKeyForTemplateEval" in key for key in facts["adminKeys"]))
            self.assertIn("\n", "".join(facts["adminKeys"]) + "\n")
            self.assertFalse(
                any(key.endswith("\n") for key in facts["adminKeys"]),
                "the trailing newline must be stripped off keys/<admin>.pub",
            )

    def test_the_hostinger_provider_module_supplies_boot_and_cloud_init_networking(self) -> None:
        """The generated hardware config (task-8a-brief.md) sets no
        boot.loader.* of its own -- these must all come from
        nixos/providers/hostinger.nix, and base.nix's sshd/firewall settings
        must win over anything cloud-init implies.
        """
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = _nix_eval(directory)

            self.assertEqual(facts["grubDevice"], "/dev/sda")
            self.assertTrue(facts["cloudInitEnable"])
            self.assertTrue(facts["cloudInitNetworkEnable"])
            self.assertTrue(facts["networkdEnable"])
            self.assertFalse(facts["passwordAuthentication"])
            self.assertEqual(facts["firewallPorts"], [22, 443])

    def test_an_extra_nix_beside_the_hardware_config_is_picked_up(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            self.assertNotEqual(_nix_eval(directory)["domain"], "set-by-extra-nix")

            (directory / "nodes" / "a" / "extra.nix").write_text(_EXTRA_NIX, encoding="utf-8")

            self.assertEqual(_nix_eval(directory)["domain"], "set-by-extra-nix")

    def test_app_table_is_absent_by_default_and_module_defaults_apply(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = _nix_eval(directory)

            self.assertEqual(facts["appBinary"], "acme")  # project "acme" -> default binary "acme"
            self.assertEqual(facts["appHealthPath"], "/health")
            self.assertEqual(facts["appHealthTries"], 30)
            self.assertEqual(facts["appHealthSleep"], 2)

    def test_app_table_fields_are_mapped_to_stackbase_app_options(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "stack.toml").write_text(
                _SAMPLE_STACK_TOML
                + '\n[app]\nbinary = "stack_demo"\nhealth_path = "/healthz"\nhealth_tries = 45\nhealth_sleep = 3\n',
                encoding="utf-8",
            )

            facts = _nix_eval(directory)

            self.assertEqual(facts["appBinary"], "stack_demo")
            self.assertEqual(facts["appHealthPath"], "/healthz")
            self.assertEqual(facts["appHealthTries"], 45)
            self.assertEqual(facts["appHealthSleep"], 3)

    def test_app_table_with_only_binary_set_leaves_health_options_at_their_default(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "stack.toml").write_text(
                _SAMPLE_STACK_TOML + '\n[app]\nbinary = "stack_demo"\n', encoding="utf-8"
            )

            facts = _nix_eval(directory)

            self.assertEqual(facts["appBinary"], "stack_demo")
            self.assertEqual(facts["appHealthPath"], "/health")
            self.assertEqual(facts["appHealthTries"], 30)
            self.assertEqual(facts["appHealthSleep"], 2)

    def test_no_backups_table_leaves_backups_off(self) -> None:
        """No bucket named, no nightly job -- and the module's own defaults
        are still what an operator would see if they turned it on."""
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = _nix_eval(directory)

            self.assertFalse(facts["backupsEnable"])
            self.assertEqual(facts["backupsBucket"], "")
            self.assertEqual(facts["backupsRetentionDays"], 30)
            self.assertEqual(facts["backupsExtraPaths"], [])
            self.assertEqual(facts["backupsOnCalendar"], "03:00")

    def test_backups_table_is_mapped_to_stackbase_backups_options(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "stack.toml").write_text(
                _SAMPLE_STACK_TOML
                + '\n[backups]\nbucket = "acme-backups"\nretention_days = 14\n'
                'extra_paths = ["/var/lib/acme/uploads"]\non_calendar = "04:30"\n',
                encoding="utf-8",
            )

            facts = _nix_eval(directory)

            self.assertTrue(facts["backupsEnable"])
            self.assertEqual(facts["backupsBucket"], "acme-backups")
            self.assertEqual(facts["backupsRetentionDays"], 14)
            self.assertEqual(facts["backupsExtraPaths"], ["/var/lib/acme/uploads"])
            self.assertEqual(facts["backupsOnCalendar"], "04:30")

    def test_naming_only_a_bucket_turns_backups_on_and_keeps_every_other_default(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "stack.toml").write_text(
                _SAMPLE_STACK_TOML + '\n[backups]\nbucket = "acme-backups"\n', encoding="utf-8"
            )

            facts = _nix_eval(directory)

            self.assertTrue(facts["backupsEnable"])
            self.assertEqual(facts["backupsRetentionDays"], 30)
            self.assertEqual(facts["backupsExtraPaths"], [])
            self.assertEqual(facts["backupsOnCalendar"], "03:00")

    def test_an_extra_nix_can_override_the_providers_mkdefault_grub_device(self) -> None:
        """The provider module must set boot.loader.grub.device with
        mkDefault, not a plain value -- otherwise a node whose disk genuinely
        differs (an operator override in extra.nix) could never win.
        """
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            self.assertEqual(_nix_eval(directory)["grubDevice"], "/dev/sda")

            (directory / "nodes" / "a" / "extra.nix").write_text(
                _EXTRA_NIX_OVERRIDES_GRUB_DEVICE, encoding="utf-8"
            )

            self.assertEqual(_nix_eval(directory)["grubDevice"], "/dev/sdz")



def _instantiate_envs_template(directory: Path) -> None:
    """The template laid out for tests/fixtures/stack-envs.toml: one
    hardware file per `<env>-<node>`, as CAPTURE_HARDWARE writes them."""
    _instantiate_template(directory)
    shutil.rmtree(directory / "nodes")
    shutil.copy(_REPO_ROOT / "tests" / "fixtures" / "stack-envs.toml", directory / "stack.toml")
    for name in ("staging-a", "production-a", "production-b"):
        (directory / "nodes" / name).mkdir(parents=True)
        (directory / "nodes" / name / "hardware-configuration.nix").write_text(_HOSTINGER_HARDWARE, encoding="utf-8")


def _nix_eval_attr(directory: Path, attr: str, apply_fn: str) -> Any:
    result = subprocess.run(
        [
            _NIX or "nix", "eval", "--json",
            f"path:{directory}#{attr}",
            "--apply", apply_fn,
            "--override-input", "stack-base", f"path:{_REPO_ROOT}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"nix eval failed:\n{result.stderr}")
    return json.loads(result.stdout)


_ENV_FACTS = (
    "node: {"
    " hostName = node.config.networking.hostName;"
    " environment = node.config.stackbase.environment;"
    " domain = node.config.stackbase.domain;"
    " backupsBucket = node.config.stackbase.backups.bucket;"
    " backupsRetentionDays = node.config.stackbase.backups.retentionDays;"
    " logsEnable = node.config.stackbase.logs.enable;"
    " logsBucket = node.config.stackbase.logs.bucket;"
    " vectorEnable = node.config.services.vector.enable;"
    " alertsTo = node.config.stackbase.alerts.to;"
    " nullmailerEnable = node.config.services.nullmailer.enable;"
    " deployKeys = node.config.stackbase.deploy.keys;"
    " }"
)


@unittest.skipIf(_NIX is None, "nix is not installed")
class TemplateEnvironmentsTests(unittest.TestCase):
    """One nixosConfigurations."<env>-<node>" per environment node, each
    with its environment's own domain, overrides and deploy key."""

    def test_one_configuration_per_environment_node(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_envs_template(directory)

            names = _nix_eval_attr(directory, "nixosConfigurations", "builtins.attrNames")

            self.assertEqual(sorted(names), ["production-a", "production-b", "staging-a"])

    def test_hostname_environment_and_overrides(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_envs_template(directory)
            (directory / "keys" / "deploy.staging.pub").write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAACIExampleStagingDeploy deploy@acme\n", encoding="utf-8"
            )

            staging = _nix_eval_attr(directory, 'nixosConfigurations."staging-a"', _ENV_FACTS)
            production = _nix_eval_attr(directory, 'nixosConfigurations."production-a"', _ENV_FACTS)

            self.assertEqual(staging["hostName"], "staging-a")
            self.assertEqual(staging["environment"], "staging")
            self.assertEqual(staging["domain"], "staging.acme.example.com")
            self.assertEqual(staging["backupsBucket"], "acme-backups-staging")
            self.assertEqual(staging["backupsRetentionDays"], 30)
            self.assertIn("deploy", staging["deployKeys"])

            self.assertEqual(production["hostName"], "production-a")
            self.assertEqual(production["environment"], "production")
            self.assertEqual(production["domain"], "acme.example.com")
            self.assertEqual(production["backupsBucket"], "acme-backups")
            self.assertEqual(production["backupsRetentionDays"], 365)
            # A staging deploy key cannot deploy production.
            self.assertNotIn("deploy", production["deployKeys"])

    def test_logs_bucket_env_override(self) -> None:
        """[environments.<env>] logs.bucket wins over the shared [logs] table,
        and naming a bucket is what turns Vector on."""
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_envs_template(directory)

            staging = _nix_eval_attr(directory, 'nixosConfigurations."staging-a"', _ENV_FACTS)
            production = _nix_eval_attr(directory, 'nixosConfigurations."production-a"', _ENV_FACTS)

            self.assertEqual(staging["logsBucket"], "acme-logs-staging")
            self.assertEqual(production["logsBucket"], "acme-logs")
            for facts in (staging, production):
                self.assertTrue(facts["logsEnable"])
                self.assertTrue(facts["vectorEnable"])

    def test_environment_opt_out_beats_the_shared_buckets(self) -> None:
        """staging sets backups.enabled / logs.enabled = false and no bucket
        of its own: it must evaluate to backups off and logs off despite the
        shared buckets, while production keeps both."""
        facts_fn = _ENV_FACTS[:-2] + " backupsEnable = node.config.stackbase.backups.enable; }"
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_envs_template(directory)
            toml = (directory / "stack.toml").read_text(encoding="utf-8")
            for line in ('backups.bucket = "acme-backups-staging"', 'logs.bucket = "acme-logs-staging"'):
                self.assertIn(line, toml)
            toml = toml.replace('backups.bucket = "acme-backups-staging"', "backups.enabled = false")
            toml = toml.replace('logs.bucket = "acme-logs-staging"', "logs.enabled = false")
            (directory / "stack.toml").write_text(toml, encoding="utf-8")

            staging = _nix_eval_attr(directory, 'nixosConfigurations."staging-a"', facts_fn)
            production = _nix_eval_attr(directory, 'nixosConfigurations."production-a"', facts_fn)

            self.assertFalse(staging["backupsEnable"])
            self.assertEqual(staging["backupsBucket"], "")
            self.assertFalse(staging["logsEnable"])
            self.assertFalse(staging["vectorEnable"])
            self.assertTrue(production["backupsEnable"])
            self.assertEqual(production["backupsBucket"], "acme-backups")
            self.assertTrue(production["logsEnable"])
            self.assertEqual(production["logsBucket"], "acme-logs")

    def test_logs_enabled_false_turns_vector_off_even_with_a_bucket(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "stack.toml").write_text(
                _SAMPLE_STACK_TOML + '\n[logs]\nenabled = false\nbucket = "acme-logs"\n', encoding="utf-8"
            )

            facts = _nix_eval_attr(directory, "nixosConfigurations.a", _ENV_FACTS)

            self.assertFalse(facts["logsEnable"])
            self.assertFalse(facts["vectorEnable"])

    def test_alerts_to_env_override(self) -> None:
        """[environments.<env>] alerts.to wins over the shared [alerts] table,
        and naming recipients is what turns nullmailer on."""
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_envs_template(directory)

            staging = _nix_eval_attr(directory, 'nixosConfigurations."staging-a"', _ENV_FACTS)
            production = _nix_eval_attr(directory, 'nixosConfigurations."production-a"', _ENV_FACTS)

            self.assertEqual(staging["alertsTo"], ["ops@example.com", "servers.acme.staging@example.com"])
            self.assertEqual(production["alertsTo"], ["ops@example.com"])
            for facts in (staging, production):
                self.assertTrue(facts["nullmailerEnable"])

    def test_mesh_enabled_turns_on_the_warp_connector(self) -> None:
        """[mesh] enabled = true -> headless cloudflare-warp, firewall closed,
        and only that one unfree package admitted."""
        facts_fn = (
            "node: { enable = node.config.services.cloudflare-warp.enable;"
            " openFirewall = node.config.services.cloudflare-warp.openFirewall;"
            " unit = node.config.systemd.services ? cloudflare-warp;"
            " warp = node.config.nixpkgs.config.allowUnfreePredicate { pname = \"cloudflare-warp\"; };"
            " version = node.config.services.cloudflare-warp.package.version;"
            " nft = node.config.systemd.services.cloudflare-warp.serviceConfig.BindReadOnlyPaths;"
            " other = node.config.nixpkgs.config.allowUnfreePredicate { pname = \"vscode\"; }; }"
        )
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "stack.toml").write_text(
                _SAMPLE_STACK_TOML + "\n[mesh]\nenabled = true\n", encoding="utf-8"
            )

            facts = _nix_eval_attr(directory, "nixosConfigurations.a", facts_fn)

            self.assertTrue(facts["enable"])
            self.assertFalse(facts["openFirewall"])
            self.assertTrue(facts["unit"])
            self.assertTrue(facts["warp"])
            # The 2026-10-20 certificate-chain hotfix build, not 26.05's 2026.3.
            version = tuple(int(part) for part in facts["version"].split("."))
            self.assertGreaterEqual(version, (2026, 8), facts["version"])
            self.assertTrue(any(m.endswith(":/usr/sbin/nft") for m in facts["nft"]), facts["nft"])
            self.assertFalse(facts["other"])

    def test_no_mesh_table_leaves_the_warp_connector_off(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = _nix_eval_attr(
                directory, "nixosConfigurations.a", "node: node.config.services.cloudflare-warp.enable"
            )

            self.assertFalse(facts)

    def test_a_legacy_project_has_an_empty_environment(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = _nix_eval_attr(directory, "nixosConfigurations.a", _ENV_FACTS)

            self.assertEqual(facts["hostName"], "a")
            self.assertEqual(facts["environment"], "")
            self.assertEqual(facts["domain"], "acme.example.com")
            # No [logs] table: no Vector, exactly as before logs existed.
            self.assertFalse(facts["logsEnable"])
            self.assertEqual(facts["logsBucket"], "")
            self.assertFalse(facts["vectorEnable"])
            # No [alerts] table: no nullmailer, no drop-in, no watchdog.
            self.assertEqual(facts["alertsTo"], [])
            self.assertFalse(facts["nullmailerEnable"])


@unittest.skipIf(_NIX is None, "nix is not installed")
class ConfdTests(unittest.TestCase):
    """infra/conf.d/*.nix applies to EVERY node; infra/nodes/<n>/extra.nix to one."""

    def _eval(self, directory: Path) -> dict:
        apply_fn = (
            "node: {"
            " marker = node.config.environment.etc ? \"stackbase-confd-marker\";"
            " second = node.config.environment.etc ? \"stackbase-confd-second\";"
            " }"
        )
        result = subprocess.run(
            [
                _NIX or "nix", "eval", "--json",
                f"path:{directory}#nixosConfigurations.a",
                "--apply", apply_fn,
                "--override-input", "stack-base", f"path:{_REPO_ROOT}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"nix eval failed:\n{result.stderr}")
        return json.loads(result.stdout)

    def test_no_confd_directory_still_evaluates(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            self.assertFalse(self._eval(directory)["marker"])

    def test_every_nix_file_in_confd_is_imported(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()
            (directory / "conf.d" / "hello.nix").write_text(_CONFD_HELLO, encoding="utf-8")
            (directory / "conf.d" / "second.nix").write_text(_CONFD_SECOND, encoding="utf-8")

            facts = self._eval(directory)

            self.assertTrue(facts["marker"])
            self.assertTrue(facts["second"])

    def test_a_non_nix_file_in_confd_is_ignored(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()
            (directory / "conf.d" / "notes.txt").write_text("not nix\n", encoding="utf-8")
            (directory / "conf.d" / "README.md").write_text("# not nix\n", encoding="utf-8")

            self.assertFalse(self._eval(directory)["marker"])

    def test_an_empty_confd_directory_is_fine(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()

            self.assertFalse(self._eval(directory)["marker"])

    def test_extra_nix_mkforce_wins_over_a_confd_plain_definition(self) -> None:
        """Decision 5: conf.d is listed before extra.nix so LIST-valued
        options concatenate project-wide-first, but that ordering alone
        does not decide precedence for a SCALAR option -- extra.nix must
        use lib.mkForce to win, exactly as it would against any other
        module. This only tests the "extra.nix + mkForce wins" half; two
        plain, conflicting definitions of the same scalar is standard
        NixOS module-system behaviour (an eval-time conflict) that
        stack-base does not implement and is out of scope here.

        Two-state, not one assertion (fix round 2): a lone `lib.mkForce`
        definition merges to its own value regardless of whether anything
        else defined the option at all, so asserting only the final value
        with BOTH files present cannot tell "extra.nix's mkForce beat
        conf.d's plain definition" apart from "conf.d was never loaded in
        the first place" (e.g. the `stack-base.lib.confdModules ./conf.d`
        wiring silently regressing). Step 1 (conf.d alone) proves conf.d is
        genuinely live in the module set -- a regression there fails step 1
        loudly, before step 2's mkForce assertion could paper over it.
        """
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()
            (directory / "conf.d" / "domain.nix").write_text(_CONFD_SCALAR_DOMAIN, encoding="utf-8")

            # Step 1 -- CONTROL: conf.d alone, no extra.nix yet. Proves the
            # conf.d module is actually wired into the module set.
            self.assertEqual(_nix_eval(directory)["domain"], "set-by-confd")

            # Step 2: extra.nix's lib.mkForce must now win over it.
            (directory / "nodes" / "a" / "extra.nix").write_text(
                _EXTRA_NIX_MKFORCE_DOMAIN, encoding="utf-8"
            )

            self.assertEqual(_nix_eval(directory)["domain"], "set-by-extra-mkforce")


@unittest.skipIf(_NIX is None, "nix is not installed")
class ProjectDeployKeyTests(unittest.TestCase):
    """Task 2: the project's ONE deploy key (`./infra/up deploy-key init`),
    layered on top of every admin key. It must reach stackbase.deploy.keys
    (so it can drive the SSH forced-command door) but never
    stackbase.admins itself -- root's and every admin's own authorized_keys
    must never contain it.
    """

    _DEPLOY_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAACIExampleDeployKey deploy@acme\n"

    def _eval(self, directory: Path) -> dict:
        apply_fn = (
            "node: {"
            " deployKeys = node.config.stackbase.deploy.keys;"
            " deployAuthorizedKeys = node.config.users.users.deploy.openssh.authorizedKeys.keys;"
            " rootKeys = node.config.users.users.root.openssh.authorizedKeys.keys;"
            " mattKeys = node.config.users.users.matt.openssh.authorizedKeys.keys;"
            " }"
        )
        result = subprocess.run(
            [
                _NIX or "nix", "eval", "--json",
                f"path:{directory}#nixosConfigurations.a",
                "--apply", apply_fn,
                "--override-input", "stack-base", f"path:{_REPO_ROOT}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"nix eval failed:\n{result.stderr}")
        return json.loads(result.stdout)

    def test_project_deploy_key_reaches_deploy_keys_but_never_admin_or_root_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "keys" / "deploy.pub").write_text(self._DEPLOY_PUB, encoding="utf-8")

            facts = self._eval(directory)

            self.assertIn("deploy", facts["deployKeys"])
            self.assertNotIn("ExampleDeployKey", "".join(facts["rootKeys"]))
            self.assertNotIn("ExampleDeployKey", "".join(facts["mattKeys"]))
            self.assertTrue(facts["deployAuthorizedKeys"], "expected at least one deploy authorized_keys line")
            self.assertTrue(
                all(line.startswith("restrict,command=") for line in facts["deployAuthorizedKeys"]),
                facts["deployAuthorizedKeys"],
            )

    def test_no_deploy_pub_file_means_no_project_deploy_key_and_evaluation_still_succeeds(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = self._eval(directory)

            self.assertNotIn("deploy", facts["deployKeys"])
            self.assertTrue(facts["deployAuthorizedKeys"], "admin keys should still reach the deploy door")
            self.assertTrue(
                all(line.startswith("restrict,command=") for line in facts["deployAuthorizedKeys"]),
                facts["deployAuthorizedKeys"],
            )


@unittest.skipIf(_NIX is None, "nix is not installed")
class VectorSettingsTests(unittest.TestCase):
    """nixos/logs.nix renders the approved Vector design verbatim (Brief D).
    The VM test (tests/vm-logs.nix) proves the behaviour; this pins the
    values, fast, so a drive-by edit to one of them is caught."""

    def _eval(self, apply_fn: str, extra: str = 'stackbase.logs.bucket = "acme-logs";') -> Any:
        result = _eval_mk_node(apply_fn, provider="null", extra_config=f"stackbase.admins.matt = \"k\"; {extra}")
        if result.returncode != 0:
            raise AssertionError(f"nix eval failed:\n{result.stderr}")
        return json.loads(result.stdout)

    def test_vector_settings_match_the_spec(self) -> None:
        settings = self._eval("node.config.services.vector.settings")

        self.assertEqual(settings["data_dir"], "/var/lib/vector")
        self.assertEqual(settings["api"], {"enabled": True, "address": "127.0.0.1:8686"})
        journal = settings["sources"]["journal"]
        self.assertEqual(journal["type"], "journald")
        self.assertIs(journal["current_boot_only"], False)
        self.assertIs(journal["since_now"], False)
        self.assertEqual(journal["exclude_units"], ["vector.service"])
        self.assertIs(journal["emit_cursor"], True)

        remap = settings["transforms"]["slim"]
        self.assertEqual(remap["inputs"], ["journal"])
        for field in ("timestamp", "host", "unit", "ident", "pid", "priority", "message", "boot_id", "cursor"):
            self.assertIn(f'"{field}"', remap["source"])
        self.assertIn("compact(", remap["source"])

        r2 = settings["sinks"]["r2"]
        self.assertEqual(r2["type"], "aws_s3")
        self.assertEqual(r2["bucket"], "acme-logs")
        self.assertEqual(r2["region"], "auto")
        self.assertEqual(r2["endpoint"], "${LOGS_ENDPOINT}")
        self.assertIs(r2["force_path_style"], True)
        self.assertEqual(r2["key_prefix"], "journal/{{ host }}/%Y/%m/%d/%H/")
        self.assertIs(r2["filename_append_uuid"], True)
        self.assertEqual(r2["filename_extension"], "ndjson.gz")
        self.assertEqual(r2["compression"], "gzip")
        self.assertEqual(r2["encoding"], {"codec": "json"})
        self.assertEqual(r2["framing"], {"method": "newline_delimited"})
        self.assertEqual(r2["batch"], {"timeout_secs": 15, "max_bytes": 67108864})
        self.assertEqual(r2["buffer"], {"type": "disk", "max_size": 1073741824, "when_full": "block"})
        self.assertEqual(r2["acknowledgements"], {"enabled": True})
        self.assertEqual(r2["request"], {"concurrency": "adaptive"})
        self.assertEqual(r2["healthcheck"], {"enabled": True})
        for forbidden in ("storage_class", "acl", "server_side_encryption", "ssekms_key_id", "grant_full_control"):
            self.assertNotIn(forbidden, r2)

        local = settings["sinks"]["local"]
        self.assertEqual(local["type"], "file")
        self.assertEqual(local["path"], "/var/log/vector/%Y-%m-%d/%H.ndjson")
        self.assertEqual(local["buffer"], {"type": "memory", "max_events": 10000, "when_full": "drop_newest"})

        self.assertEqual(settings["sources"]["vector_metrics"], {"type": "internal_metrics"})
        self.assertEqual(
            settings["sinks"]["metrics"],
            {"type": "prometheus_exporter", "inputs": ["vector_metrics"], "address": "127.0.0.1:9598"},
        )

    def test_the_unit_reads_the_credentials_file_and_the_local_copy_ages_out(self) -> None:
        facts = self._eval(
            "{"
            " env = node.config.systemd.services.vector.serviceConfig.EnvironmentFile;"
            " rw = node.config.systemd.services.vector.serviceConfig.ReadWritePaths;"
            " rules = node.config.systemd.tmpfiles.rules;"
            " journaldAccess = node.config.services.vector.journaldAccess;"
            " }"
        )
        self.assertEqual(facts["env"], "/var/lib/stackbase/logs.env")
        self.assertIn("/var/log/vector", facts["rw"])
        self.assertIn("d /var/log/vector 0750 vector vector 3d", facts["rules"])
        self.assertTrue(facts["journaldAccess"])

    def test_batch_seconds_and_buffer_bytes_are_options(self) -> None:
        r2 = self._eval(
            "node.config.services.vector.settings.sinks.r2",
            'stackbase.logs.bucket = "b2"; stackbase.logs.batchSeconds = 5; stackbase.logs.bufferBytes = 268435488;',
        )
        self.assertEqual(r2["batch"]["timeout_secs"], 5)
        self.assertEqual(r2["buffer"]["max_size"], 268435488)

    def test_journald_keeps_seven_days_and_syncs_every_five_seconds(self) -> None:
        conf = self._eval('node.config.environment.etc."systemd/journald.conf".text', "")
        for line in (
            "Storage=persistent",
            "Compress=yes",
            "SystemMaxUse=2G",
            "SystemKeepFree=4G",
            "SystemMaxFileSize=128M",
            "MaxRetentionSec=7day",
            "MaxFileSec=1day",
            "SyncIntervalSec=5s",
            "RateLimitBurst=10000",
            "ForwardToSyslog=no",
        ):
            self.assertIn(line, conf.splitlines())
        self.assertIn("RateLimitInterval=30s", conf.splitlines())
        self.assertNotIn("SystemMaxUse=500M", conf)
        self.assertNotIn("ForwardToSyslog=yes", conf)


@unittest.skipIf(_NIX is None, "nix is not installed")
class AlertsSettingsTests(unittest.TestCase):
    """nixos/alerts.nix wires the approved design (Brief F). The VM test
    (tests/vm-alerts.nix) proves the behaviour; this pins the wiring, fast."""

    _ON = 'stackbase.alerts.to = [ "ops@example.org" ];'

    def _eval(self, apply_fn: str, extra: str = _ON) -> Any:
        result = _eval_mk_node(apply_fn, provider="null", extra_config=f"stackbase.admins.matt = \"k\"; {extra}")
        if result.returncode != 0:
            raise AssertionError(f"nix eval failed:\n{result.stderr}")
        return json.loads(result.stdout)

    def test_no_recipients_means_no_mailer_no_drop_in_no_watchdog(self) -> None:
        facts = self._eval(
            "{"
            " nullmailer = node.config.services.nullmailer.enable;"
            " handler = node.config.systemd.services ? \"stackbase-alert@\";"
            " freshness = node.config.systemd.timers ? stackbase-freshness;"
            " packages = map (p: p.name) node.config.systemd.packages;"
            " }",
            "",
        )
        self.assertFalse(facts["nullmailer"])
        self.assertFalse(facts["handler"])
        self.assertFalse(facts["freshness"])
        self.assertNotIn("stackbase-alert-dropins", facts["packages"])

    def test_recipients_turn_on_the_whole_alert_path(self) -> None:
        facts = self._eval(
            "{"
            " nullmailer = node.config.services.nullmailer.enable;"
            " remotesFile = node.config.services.nullmailer.remotesFile;"
            " packages = map (p: p.name) node.config.systemd.packages;"
            " handlerStart = node.config.systemd.services.\"stackbase-alert@\".serviceConfig.ExecStart;"
            " remotesEnv = node.config.systemd.services.stackbase-alert-remotes.serviceConfig.EnvironmentFile;"
            " nullmailerRequires = node.config.systemd.services.nullmailer.requires;"
            " timer = node.config.systemd.timers.stackbase-freshness.timerConfig.OnCalendar;"
            " freshnessEnv = node.config.systemd.services.stackbase-freshness.environment;"
            " }"
        )
        self.assertTrue(facts["nullmailer"])
        self.assertEqual(facts["remotesFile"], "/run/stackbase-alert/remotes")
        self.assertIn("stackbase-alert-dropins", facts["packages"])
        self.assertTrue(facts["handlerStart"].endswith(" %i"), facts["handlerStart"])
        self.assertEqual(facts["remotesEnv"], "/var/lib/stackbase/alert.env")
        self.assertIn("stackbase-alert-remotes.service", facts["nullmailerRequires"])
        self.assertEqual(facts["timer"], "hourly")
        self.assertEqual(facts["freshnessEnv"]["GRACE_SECONDS"], "3600")
        self.assertEqual(facts["freshnessEnv"]["BUFFER_ALERT_BYTES"], "268435456")
        self.assertEqual(facts["freshnessEnv"]["BACKUP_MAX_AGE_SECONDS"], str(36 * 3600))
        self.assertEqual(facts["freshnessEnv"]["SENT_STALL_SECONDS"], str(2 * 3600))
        # Backups and logs are off on this node: neither check runs.
        self.assertEqual(facts["freshnessEnv"]["CHECK_BACKUPS"], "0")
        self.assertEqual(facts["freshnessEnv"]["CHECK_LOGS"], "0")

    def test_the_watchdog_checks_what_the_node_has(self) -> None:
        env = self._eval(
            "node.config.systemd.services.stackbase-freshness.environment",
            self._ON + ' stackbase.backups.bucket = "b"; stackbase.logs.bucket = "l";',
        )
        self.assertEqual(env["CHECK_BACKUPS"], "1")
        self.assertEqual(env["CHECK_LOGS"], "1")
        opted_out = self._eval(
            "node.config.systemd.services.stackbase-freshness.environment",
            self._ON + ' stackbase.backups.bucket = "b"; stackbase.backups.enable = false;',
        )
        self.assertEqual(opted_out["CHECK_BACKUPS"], "0")

    def test_a_recipient_must_be_one_address(self) -> None:
        """`to` lands in a To: header: a newline there would inject another header."""
        result = _eval_mk_node(
            "node.config.stackbase.alerts.to",
            provider="null",
            extra_config='stackbase.admins.matt = "k"; stackbase.alerts.to = [ "ops@example.org\\nBcc: x@evil.test" ];',
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stackbase.alerts.to", result.stderr)

    def test_the_subject_names_project_environment_and_host(self) -> None:
        """`[<project>/<env>/<hostname>]`, or `[<project>/<hostname>]` for a
        project without [environments]."""
        staging = self._eval(
            "node.config.stackbase.alerts.subjectLabel",
            self._ON + ' networking.hostName = "staging-a"; stackbase.environment = "staging";',
        )
        legacy = self._eval("node.config.stackbase.alerts.subjectLabel", self._ON + ' networking.hostName = "a";')
        self.assertEqual((staging, legacy), ("t/staging/staging-a", "t/a"))


@unittest.skipIf(_NIX is None, "nix is not installed")
class MkNodeProviderContractTests(unittest.TestCase):
    """`lib.mkNode`'s `provider` argument (review follow-up on task 8a):
    "hostinger" (the default) must include the Hostinger provider module,
    `null` must include none, and anything else must fail loudly rather
    than silently building a node with no provider module.
    """

    def test_unknown_provider_throws_naming_the_known_providers(self) -> None:
        result = _eval_mk_node(
            "node.config.services.cloud-init.enable", provider='"bogus"'
        )

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown provider 'bogus'", result.stderr)
        self.assertIn("hostinger", result.stderr)

    def test_provider_null_does_not_enable_cloud_init(self) -> None:
        result = _eval_mk_node(
            "node.config.services.cloud-init.enable", provider="null"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), False)

    def test_the_default_provider_enables_cloud_init(self) -> None:
        result = _eval_mk_node("node.config.services.cloud-init.enable")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), True)


@unittest.skipIf(_NIX is None, "nix is not installed")
class AdminKeyDeduplicationTests(unittest.TestCase):
    """Live finding on task 8a: a real box had the same key listed twice
    under one admin's own `/etc/ssh/authorized_keys.d/<name>`. base.nix now
    wraps both the per-admin list and root's aggregate list in `lib.unique`.
    """

    # `users.users.*` pulls in enough of the rest of the system (postgresql's
    # ensureUsers, rpcbind/nfs's fsType check, ...) that a root filesystem
    # must be defined even just to evaluate an authorizedKeys list.
    _SHARED_KEY_ADMINS = (
        'fileSystems."/" = { device = "/dev/vda1"; fsType = "ext4"; }; '
        'stackbase.admins = { matt = "ssh-ed25519 AAAAsharedkey shared@laptop"; '
        'kim = "ssh-ed25519 AAAAsharedkey shared@laptop"; };'
    )

    def test_roots_aggregate_list_has_no_duplicate_when_two_admins_share_a_key(self) -> None:
        result = _eval_mk_node(
            "node.config.users.users.root.openssh.authorizedKeys.keys",
            extra_config=self._SHARED_KEY_ADMINS,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        keys = json.loads(result.stdout)
        # Two admins, one shared key -- root still gets every *distinct*
        # admin key (one), never the same key twice.
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(keys), 1)

    def test_each_admins_own_list_has_no_duplicate(self) -> None:
        result = _eval_mk_node(
            "{ matt = node.config.users.users.matt.openssh.authorizedKeys.keys;"
            " kim = node.config.users.users.kim.openssh.authorizedKeys.keys; }",
            extra_config=self._SHARED_KEY_ADMINS,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads(result.stdout)
        for name, keys in facts.items():
            with self.subTest(admin=name):
                self.assertEqual(len(keys), len(set(keys)))
                self.assertEqual(len(keys), 1)


@unittest.skipIf(_NIX is None, "nix is not installed")
class ResolvedLlmnrMdnsTests(unittest.TestCase):
    """Live finding on task 8a: systemd-resolved was listening for LLMNR on
    0.0.0.0:5355/[::]:5355 -- firewalled, but pointless on a server.
    `tests/vm.nix`'s VM never enables resolved at all (it builds straight
    off baseModules, with no provider module to turn cloud-init/networkd on
    for it), so this is asserted via `nix eval` on a real `mkNode` config
    (default "hostinger" provider) rather than extending that VM test.
    """

    _WITH_ROOT_FS = 'fileSystems."/" = { device = "/dev/vda1"; fsType = "ext4"; };'

    def test_llmnr_and_multicast_dns_are_off_when_resolved_is_active(self) -> None:
        result = _eval_mk_node(
            "{ enable = node.config.services.resolved.enable;"
            " llmnr = node.config.services.resolved.settings.Resolve.LLMNR;"
            " mdns = node.config.services.resolved.settings.Resolve.MulticastDNS; }",
            extra_config=self._WITH_ROOT_FS,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads(result.stdout)
        self.assertTrue(facts["enable"], "resolved should be active via the default hostinger provider")
        self.assertEqual(facts["llmnr"], "no")
        self.assertEqual(facts["mdns"], "no")

    def test_setting_the_values_does_not_enable_resolved_on_its_own(self) -> None:
        result = _eval_mk_node(
            "node.config.services.resolved.enable",
            provider="null",
            extra_config=self._WITH_ROOT_FS,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), False)


class TemplateUpScriptTests(unittest.TestCase):
    """`infra/up` has to work on a machine with no Nix and no stack-base."""

    def _run_up(self, infra_dir: Path, *args: str, env_extra: dict[str, str] | None = None):
        env = {**os.environ, **(env_extra or {})}
        env.pop("STACKBASE_SRC", None)
        env.update(env_extra or {})
        return subprocess.run(
            ["python3", str(infra_dir / "up"), *args],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    def _infra_dir(self, tmp: str) -> Path:
        infra_dir = Path(tmp) / "infra"
        infra_dir.mkdir()
        shutil.copy(_TEMPLATE_DIR / "up", infra_dir / "up")
        return infra_dir

    def test_without_a_lock_file_or_a_local_checkout_it_explains_both_options(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)

            result = self._run_up(infra_dir, "up", "--plan")

            self.assertEqual(result.returncode, 1)
            self.assertIn("flake.lock", result.stderr)
            self.assertIn("STACKBASE_SRC", result.stderr)
            self.assertEqual(len(result.stderr.strip().splitlines()), 1, "failures are one line")

    def test_stackbase_src_runs_that_checkout_with_the_infra_dir_prepended(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            source = Path(tmp) / "stack-base"
            (source / "bin").mkdir(parents=True)
            (source / "bin" / "up").write_text(
                "import sys\nprint(' '.join(sys.argv[1:]))\n", encoding="utf-8"
            )

            result = self._run_up(infra_dir, "up", "--plan", env_extra={"STACKBASE_SRC": str(source)})

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"--infra-dir {infra_dir} up --plan")

    def _fake_echo_source(self, tmp: str) -> Path:
        source = Path(tmp) / "stack-base"
        (source / "bin").mkdir(parents=True)
        (source / "bin" / "up").write_text(
            "import sys\nprint(' '.join(sys.argv[1:]))\n", encoding="utf-8"
        )
        return source

    def test_the_documented_invocations_all_forward_to_the_up_subcommand(self) -> None:
        """`./infra/up`, `./infra/up --plan`, `./infra/up --allow-purchase` are the

        documented commands, but the CLI's subparsers are `required=True` --
        without `up` inserted, every one of these exits 2 with an argparse
        usage error and only `./infra/up ssh a` (which already names a real
        subcommand) works.
        """
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            source = self._fake_echo_source(tmp)

            cases = [
                ([], "up"),
                (["--plan"], "up --plan"),
                (["--allow-purchase"], "up --allow-purchase"),
                (["ssh", "a"], "ssh a"),
                (["up", "--plan"], "up --plan"),
            ]
            for args, expected_tail in cases:
                with self.subTest(args=args):
                    result = self._run_up(infra_dir, *args, env_extra={"STACKBASE_SRC": str(source)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), f"--infra-dir {infra_dir} {expected_tail}")

    def test_a_leading_env_flag_still_finds_or_inserts_the_subcommand(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            source = self._fake_echo_source(tmp)

            cases = [
                (["--env", "staging"], "--env staging up"),
                (["--env", "staging", "--plan"], "--env staging up --plan"),
                (["--env=staging", "--plan"], "--env=staging up --plan"),
                (["--env", "staging", "deploy", "v1.0.0"], "--env staging deploy v1.0.0"),
                (["--env", "production", "ssh", "a"], "--env production ssh a"),
                (["deploy", "v1.0.0", "--env", "staging"], "deploy v1.0.0 --env staging"),
                (["--plan", "--env", "staging"], "up --plan --env staging"),
            ]
            for args, expected_tail in cases:
                with self.subTest(args=args):
                    result = self._run_up(infra_dir, *args, env_extra={"STACKBASE_SRC": str(source)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), f"--infra-dir {infra_dir} {expected_tail}")

    def test_secrets_keys_reaches_the_subcommand_unchanged(self) -> None:
        """`secrets` doesn't start with '-', so `_with_implicit_up` must
        leave it alone -- `./infra/up secrets keys` must reach `secrets
        keys`, never `up secrets keys` (Task 4, B1).
        """
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            source = self._fake_echo_source(tmp)

            result = self._run_up(infra_dir, "secrets", "keys", env_extra={"STACKBASE_SRC": str(source)})

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"--infra-dir {infra_dir} secrets keys")

    def test_help_is_passed_through_without_inserting_up(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            source = self._fake_echo_source(tmp)

            result = self._run_up(infra_dir, "--help", env_extra={"STACKBASE_SRC": str(source)})

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"--infra-dir {infra_dir} --help")

    def test_a_bad_stackbase_src_says_so_in_one_line(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)

            result = self._run_up(infra_dir, "up", env_extra={"STACKBASE_SRC": str(Path(tmp) / "nope")})

            self.assertEqual(result.returncode, 1)
            self.assertIn("STACKBASE_SRC", result.stderr)
            self.assertEqual(len(result.stderr.strip().splitlines()), 1)

    def test_a_lock_file_without_a_stack_base_input_is_reported_clearly(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            (infra_dir / "flake.lock").write_text(
                json.dumps({"nodes": {"root": {"inputs": {}}}, "root": "root", "version": 7}),
                encoding="utf-8",
            )

            result = self._run_up(infra_dir, "up")

            self.assertEqual(result.returncode, 1)
            self.assertIn("stack-base", result.stderr)

    def test_a_flake_nix_without_a_recognizable_stack_base_input_falls_back_to_the_same_error(
        self,
    ) -> None:
        """No flake.lock AND flake.nix doesn't name a `github:` stack-base
        input (typo, different input name, a plain git URL) -- must still
        fail with the original one-line message, not a confusing git error.
        This never touches the network: the regex doesn't match, so
        `unlocked_stack_base` returns before any subprocess call.
        """
        with TemporaryDirectory() as tmp:
            infra_dir = self._infra_dir(tmp)
            (infra_dir / "flake.nix").write_text(
                'inputs.nixpkgs.url = "github:NixOS/nixpkgs";\n', encoding="utf-8"
            )

            result = self._run_up(infra_dir, "up", "--plan")

            self.assertEqual(result.returncode, 1)
            self.assertIn("flake.lock", result.stderr)
            self.assertIn("STACKBASE_SRC", result.stderr)
            self.assertEqual(len(result.stderr.strip().splitlines()), 1, "failures are one line")


class TemplateUpUnlockedResolutionTests(unittest.TestCase):
    """The first `./infra/up` on a freshly scaffolded project has no
    flake.lock yet -- `unlocked_stack_base` resolves the pinned ref straight
    from flake.nix instead. Exercised as a direct import (like
    `test_a_github_pinned_lock_resolves_to_the_public_repository` below) so
    `git ls-remote` can be mocked in-process; no network is ever touched.
    """

    def _load_module(self):
        import importlib.machinery
        import importlib.util

        loader = importlib.machinery.SourceFileLoader(
            "template_up_unlocked", str(_TEMPLATE_DIR / "up")
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def _write_flake(self, tmp: str, url: str) -> Path:
        flake_path = Path(tmp) / "flake.nix"
        flake_path.write_text(f'inputs.stack-base.url = "{url}";\n', encoding="utf-8")
        return flake_path

    def _ls_remote_result(self, stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")

    def test_a_ref_that_looks_like_a_git_flag_never_reaches_git(self) -> None:
        # flake.nix is project-controlled, but nothing parsed out of it may
        # become a git option: a ref of `--upload-pack=...` would otherwise
        # run an arbitrary command. The parser refuses the shape outright.
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            for url in (
                "github:ExampleOrg/example-stack/--upload-pack=touch${IFS}x",
                "github:-ExampleOrg/example-stack/v0.1.0",
                "github:ExampleOrg/example-stack/v0.1.0;id",
            ):
                flake_path = self._write_flake(tmp, url)
                with mock.patch.object(module.subprocess, "run") as run_mock:
                    self.assertIsNone(module.unlocked_stack_base(flake_path), url)
                run_mock.assert_not_called()

    def test_prefers_the_peeled_annotated_tag_object(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = self._write_flake(tmp, "github:ExampleOrg/example-stack/v0.1.0")
            fake_stdout = (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v0.1.0\n"
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v0.1.0^{}\n"
            )
            with mock.patch.object(
                module.subprocess, "run", return_value=self._ls_remote_result(fake_stdout)
            ) as run_mock:
                result = module.unlocked_stack_base(flake_path)

            self.assertEqual(
                result, ("https://github.com/ExampleOrg/example-stack.git", "b" * 40)
            )
            run_mock.assert_called_once_with(
                [
                    "git",
                    "ls-remote",
                    "--",
                    "https://github.com/ExampleOrg/example-stack.git",
                    "v0.1.0",
                    "refs/tags/v0.1.0",
                    "refs/tags/v0.1.0^{}",
                    "refs/heads/v0.1.0",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_an_unpeeled_ref_resolves_from_its_own_line(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = self._write_flake(tmp, "github:ExampleOrg/example-stack/main")
            fake_stdout = "cccccccccccccccccccccccccccccccccccccccc\trefs/heads/main\n"
            with mock.patch.object(
                module.subprocess, "run", return_value=self._ls_remote_result(fake_stdout)
            ):
                result = module.unlocked_stack_base(flake_path)

            self.assertEqual(
                result, ("https://github.com/ExampleOrg/example-stack.git", "c" * 40)
            )

    def test_a_ref_less_url_resolves_head(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = self._write_flake(tmp, "github:ExampleOrg/example-stack")
            fake_stdout = "dddddddddddddddddddddddddddddddddddddddd\tHEAD\n"
            with mock.patch.object(
                module.subprocess, "run", return_value=self._ls_remote_result(fake_stdout)
            ) as run_mock:
                result = module.unlocked_stack_base(flake_path)

            self.assertEqual(
                result, ("https://github.com/ExampleOrg/example-stack.git", "d" * 40)
            )
            self.assertEqual(run_mock.call_args[0][0][4], "HEAD")

    def test_a_failed_ls_remote_returns_none_so_the_caller_can_fall_back(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = self._write_flake(tmp, "github:ExampleOrg/example-stack/v9.9.9")
            with mock.patch.object(
                module.subprocess,
                "run",
                return_value=self._ls_remote_result("", returncode=128),
            ):
                result = module.unlocked_stack_base(flake_path)

            self.assertIsNone(result)

    def test_an_empty_ls_remote_returns_none(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = self._write_flake(tmp, "github:ExampleOrg/example-stack/v9.9.9")
            with mock.patch.object(
                module.subprocess, "run", return_value=self._ls_remote_result("")
            ):
                result = module.unlocked_stack_base(flake_path)

            self.assertIsNone(result)

    def test_no_matching_input_returns_none_without_touching_git(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = Path(tmp) / "flake.nix"
            flake_path.write_text('inputs.nixpkgs.url = "github:NixOS/nixpkgs";\n', encoding="utf-8")
            with mock.patch.object(module.subprocess, "run") as run_mock:
                result = module.unlocked_stack_base(flake_path)

            self.assertIsNone(result)
            run_mock.assert_not_called()

    def test_a_missing_flake_nix_returns_none_without_touching_git(self) -> None:
        module = self._load_module()
        with TemporaryDirectory() as tmp:
            flake_path = Path(tmp) / "flake.nix"  # never written
            with mock.patch.object(module.subprocess, "run") as run_mock:
                result = module.unlocked_stack_base(flake_path)

            self.assertIsNone(result)
            run_mock.assert_not_called()


class TemplateUpCacheTests(unittest.TestCase):
    """The cache holds code that gets executed -- it must be proved, not assumed.

    `~/.cache/stack-base/<rev>/bin/up` existing is not evidence that it came
    from the pinned repository, so every run verifies the checkout really is
    that commit and is unmodified. These tests fetch from a local git
    repository over a file:// URL -- no network.
    """

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self.infra_dir = self.root / "infra"
        self.infra_dir.mkdir()
        shutil.copy(_TEMPLATE_DIR / "up", self.infra_dir / "up")

        self.origin, self.rev = self._git_repo(self.root / "origin", "print('REAL')")
        (self.infra_dir / "flake.lock").write_text(
            json.dumps(
                {
                    "nodes": {
                        "root": {"inputs": {"stack-base": "stack-base"}},
                        "stack-base": {
                            "locked": {"type": "git", "url": self.origin.as_uri(), "rev": self.rev}
                        },
                    },
                    "root": "root",
                    "version": 7,
                }
            ),
            encoding="utf-8",
        )
        self.cache_home = self.root / "cache"

    def _git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(
            [
                "git", "-C", str(repo),
                "-c", "user.email=test@example.com",
                "-c", "user.name=Test",
                "-c", "commit.gpgsign=false",
                *args,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def _git_repo(self, path: Path, body: str) -> tuple[Path, str]:
        (path / "bin").mkdir(parents=True)
        (path / "bin" / "up").write_text(f"{body}\n", encoding="utf-8")
        subprocess.run(
            ["git", "init", "--quiet", "-b", "main", str(path)], capture_output=True, check=True
        )
        self._git(path, "add", "-A")
        self._git(path, "commit", "--quiet", "-m", "initial")
        return path, self._git(path, "rev-parse", "HEAD")

    def _run_up(self):
        env = {**os.environ, "XDG_CACHE_HOME": str(self.cache_home)}
        env.pop("STACKBASE_SRC", None)
        return subprocess.run(
            ["python3", str(self.infra_dir / "up"), "up", "--plan"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    @property
    def _checkout(self) -> Path:
        return self.cache_home / "stack-base" / self.rev

    def test_a_first_run_fetches_the_pinned_commit_and_runs_it(self) -> None:
        result = self._run_up()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REAL", result.stdout)
        self.assertTrue(self._checkout.exists())

    def test_the_cache_root_is_created_private(self) -> None:
        self._run_up()

        mode = (self.cache_home / "stack-base").stat().st_mode & 0o777
        self.assertEqual(mode, 0o700, f"cache root should be 0700, got {mode:o}")

    def test_a_poisoned_cache_entry_is_discarded_and_refetched(self) -> None:
        """A directory planted under the rev's name is not evidence of the rev."""
        # The cache root itself is left correctly private, so this test is
        # about the HEAD check and not about the permission check.
        (self.cache_home / "stack-base").mkdir(parents=True)
        (self.cache_home / "stack-base").chmod(0o700)
        _planted, planted_rev = self._git_repo(self._checkout, "print('PWNED')")
        self.assertNotEqual(planted_rev, self.rev)

        result = self._run_up()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("PWNED", result.stdout)
        self.assertIn("REAL", result.stdout)
        self.assertEqual(self._git(self._checkout, "rev-parse", "HEAD"), self.rev)

    def test_a_modified_cache_entry_is_discarded_and_refetched(self) -> None:
        self.assertEqual(self._run_up().returncode, 0)
        (self._checkout / "bin" / "up").write_text("print('TAMPERED')\n", encoding="utf-8")

        result = self._run_up()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("TAMPERED", result.stdout)
        self.assertIn("REAL", result.stdout)

    def test_an_added_file_in_the_cache_entry_is_discarded_and_refetched(self) -> None:
        self.assertEqual(self._run_up().returncode, 0)
        (self._checkout / "bin" / "sneaky.py").write_text("print('SNEAKY')\n", encoding="utf-8")

        result = self._run_up()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self._checkout / "bin" / "sneaky.py").exists())

    def test_a_group_writable_cache_root_is_refused(self) -> None:
        cache_root = self.cache_home / "stack-base"
        cache_root.mkdir(parents=True)
        cache_root.chmod(0o775)

        result = self._run_up()

        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(result.stderr.strip().splitlines()), 1, result.stderr)
        self.assertIn(str(cache_root), result.stderr)
        self.assertIn("700", result.stderr)

    def test_an_unfetchable_rev_fails_loudly_rather_than_running_anything(self) -> None:
        shutil.rmtree(self.origin)

        result = self._run_up()

        self.assertEqual(result.returncode, 1)
        self.assertNotIn("REAL", result.stdout)
        self.assertEqual(len(result.stderr.strip().splitlines()), 1, result.stderr)


class TemplateFilesTests(unittest.TestCase):
    def test_the_up_script_is_executable(self) -> None:
        self.assertTrue(os.access(_TEMPLATE_DIR / "up", os.X_OK))

    def test_the_recipients_file_carries_instructions_and_no_real_keys(self) -> None:
        text = (_TEMPLATE_DIR / "age-recipients.txt").read_text(encoding="utf-8")

        self.assertIn("age-keygen", text)
        real_keys = [
            line for line in text.splitlines() if line.strip().startswith("age1") and not line.startswith("#")
        ]
        self.assertEqual(real_keys, [], "the template must not ship a real recipient key")

    def test_the_deploy_recipients_file_carries_instructions_and_no_real_keys(self) -> None:
        text = (_TEMPLATE_DIR / "deploy-recipients.txt").read_text(encoding="utf-8")

        self.assertIn("superset", text)
        self.assertIn("age-recipients.txt", text)
        real_keys = [
            line for line in text.splitlines() if line.strip().startswith("age1") and not line.startswith("#")
        ]
        self.assertEqual(real_keys, [], "the template must not ship a real recipient key")

    def test_the_shipped_deploy_recipients_file_has_no_recipients_yet(self) -> None:
        """Ties the template's comment-only contract to
        `check_recipients_superset`'s empty-list skip (fix round 1) -- if
        either drifts on its own, a fresh project's first `up` breaks.
        """
        from stackbase.secrets import read_recipients

        self.assertEqual(read_recipients(_TEMPLATE_DIR / "deploy-recipients.txt"), [])

    def test_the_gitignore_hides_build_output_and_stray_key_material(self) -> None:
        entries = [
            line.strip()
            for line in (_TEMPLATE_DIR / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        self.assertEqual(
            entries,
            [
                "result",
                "*.age.*.tmp",
                "secrets/",
                "*.key",
                "id_ed25519*",
                "id_rsa*",
                "*.pem",
                "*.age.tmp",
            ],
        )

    def test_the_gitignore_never_hides_a_file_that_must_be_committed(self) -> None:
        """secrets.age, deploy.age and keys/*.pub are the whole point of the repo."""
        import fnmatch

        patterns = [
            line.strip()
            for line in (_TEMPLATE_DIR / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        must_commit = [
            "secrets.age",
            "deploy.age",
            "keys/matt.pub",
            "keys/deploy.pub",
            "age-recipients.txt",
            "deploy-recipients.txt",
            "stack.toml",
            "stack.state.json",
            "known_hosts",
            "flake.lock",
            "conf.d/hello.nix",
        ]

        for path in must_commit:
            for pattern in patterns:
                self.assertFalse(
                    fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern),
                    f"{path} must be committable, but .gitignore's '{pattern}' hides it",
                )

    def test_the_version_is_a_plain_semver_release(self) -> None:
        # The tag is `v` + this string; the template flake below must pin the
        # same release. Pre-release suffixes would break both.
        import stackbase

        self.assertRegex(stackbase.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_template_flake_pins_the_release_being_shipped(self) -> None:
        """`templates/infra/flake.nix`'s stack-base input must carry a
        `/vX.Y.Z` ref matching `stackbase.__version__` -- a release that
        forgets to bump the template's pin would otherwise ship silently.
        """
        import stackbase

        text = (_TEMPLATE_DIR / "flake.nix").read_text(encoding="utf-8")
        # Assembled at runtime, like the "one constant" test below, so this
        # file is not itself a hit for that test's scan.
        needle = "github:" + "TechSpaceAsia/stack-base" + f"/v{stackbase.__version__}"

        self.assertIn(f'inputs.stack-base.url = "{needle}";', text)

    def test_a_github_pinned_lock_resolves_to_the_public_repository(self) -> None:
        """The `up` wrapper must turn a github-type flake.lock node into the
        real clone URL. Network is never touched -- this only exercises the
        pure resolution step (Brief G).
        """
        import importlib.machinery
        import importlib.util

        # `templates/infra/up` has no .py extension, so
        # spec_from_file_location cannot pick a loader for it -- name the
        # source loader explicitly. Importing it only defines functions
        # (everything else is behind `if __name__ == "__main__"`).
        loader = importlib.machinery.SourceFileLoader("template_up", str(_TEMPLATE_DIR / "up"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)

        with TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "flake.lock"
            lock_path.write_text(
                json.dumps(
                    {
                        "nodes": {
                            "root": {"inputs": {"stack-base": "stack-base"}},
                            "stack-base": {
                                "locked": {
                                    "type": "github",
                                    "owner": "TechSpaceAsia",
                                    "repo": "stack-base",
                                    "rev": "a" * 40,
                                }
                            },
                        },
                        "root": "root",
                        "version": 7,
                    }
                ),
                encoding="utf-8",
            )

            url, rev = module.locked_stack_base(lock_path)

        self.assertEqual(url, "https://github.com/TechSpaceAsia/stack-base.git")
        self.assertEqual(rev, "a" * 40)

    def test_the_example_stack_toml_parses_and_covers_the_schema(self) -> None:
        import tomllib

        data = tomllib.loads((_TEMPLATE_DIR / "stack.toml.example").read_text(encoding="utf-8"))

        for key in ("project", "domain", "owner", "datacenter", "plan", "price_item", "auto_patch", "admins"):
            self.assertIn(key, data)
        self.assertEqual(data["nodes"]["a"]["role"], "primary")

        # [backups] is documented as a COMMENTED-OUT block: a project turns
        # backups on deliberately, by naming a bucket. If it ever stopped
        # being a comment, every new project would get a bucket called
        # "acme-backups" it does not own.
        text = (_TEMPLATE_DIR / "stack.toml.example").read_text(encoding="utf-8")
        self.assertNotIn("backups", data)
        self.assertIn("bucket", text)
        self.assertIn("retention_days", text)
        # Environments are opt-in too: documented, commented out.
        self.assertNotIn("environments", data)
        self.assertIn("# [environments.staging]", text)
        self.assertIn("# [environments.production.nodes.a]", text)

    def test_the_example_stack_toml_has_no_real_vps_id_and_still_loads(self) -> None:
        """The example must never carry a real Hostinger VPS id (Finding 7)."""
        from stackbase.config import load_config

        text = (_TEMPLATE_DIR / "stack.toml.example").read_text(encoding="utf-8")
        self.assertNotIn("vps_id = 1984476", text, "a real VPS id must not ship in the example")

        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            shutil.copy(_TEMPLATE_DIR / "stack.toml.example", infra_dir / "stack.toml")
            (infra_dir / "keys").mkdir()
            (infra_dir / "keys" / "your-name.pub").write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTemplateEval you@laptop\n",
                encoding="utf-8",
            )

            config = load_config(infra_dir)

            # The example ships with `vps_id` commented out (buy-a-server branch)
            # and `price_item` left blank -- both must round-trip cleanly.
            self.assertIsNone(config.nodes["a"].vps_id)
            self.assertIsNone(config.price_item)

    def test_the_upstream_flake_url_appears_only_in_the_template_and_the_readme(self) -> None:
        """The (unconfirmed) upstream URL is one constant, not a string scattered about."""
        # Assembled at runtime so that this file is not itself a hit.
        needle = "github:" + "TechSpaceAsia/stack-base"
        hits = []
        for path in _REPO_ROOT.rglob("*"):
            if not path.is_file() or ".git/" in path.as_posix() or "/.superpowers/" in path.as_posix():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if needle in text:
                hits.append(path.relative_to(_REPO_ROOT).as_posix())

        self.assertEqual(sorted(hits), ["README.md", "templates/infra/flake.nix"])


_CI_TEMPLATE = _REPO_ROOT / "templates" / "github" / "deploy-stack.yml"
_CHECKOUT_VERSION_COMMENT = re.compile(r"#\s*v(\d+)")


def _node20_violations(text: str) -> list[str]:
    """Non-comment lines that depend on something the self-hosted runner lacks.

    The runner ships only the node24 action runtime, so the built-in
    `hashFiles()` (hard-wired to node20), any `actions/cache` step, and a
    checkout pinned below v5 would all fail there.
    """
    violations = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "hashFiles(" in line:
            violations.append(line)
        if re.search(r"uses:\s*actions/cache", line):
            violations.append(line)
        if re.search(r"uses:\s*actions/checkout@", line):
            version = _CHECKOUT_VERSION_COMMENT.search(line)
            if version is None or int(version.group(1)) < 5:
                violations.append(line)
    return violations


def _ci_step_blocks(lines: list[str]) -> list[list[str]]:
    """Split the workflow's job steps: each block starts at a `      - ` item line."""
    starts = [i for i, line in enumerate(lines) if line.startswith("      - ")]
    return [lines[start : end] for start, end in zip(starts, starts[1:] + [len(lines)])]


def _ci_job_lines(text: str) -> dict[str, list[str]]:
    """The workflow's jobs, each as its own list of lines."""
    jobs: dict[str, list[str]] = {}
    current = None
    for line in text.split("\njobs:\n", 1)[1].splitlines():
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


class CiTemplateTests(unittest.TestCase):
    def test_ci_template_has_no_node20_dependencies(self) -> None:
        text = _CI_TEMPLATE.read_text(encoding="utf-8")

        self.assertEqual(_node20_violations(text), [])

    def test_node20_guard_flags_an_actions_cache_step(self) -> None:
        self.assertEqual(
            _node20_violations("      - uses: actions/cache@v4\n"),
            ["- uses: actions/cache@v4"],
        )

    def test_ci_template_preflight_lists_required_tools(self) -> None:
        jobs = _ci_job_lines(_CI_TEMPLATE.read_text(encoding="utf-8"))
        self.assertEqual(list(jobs), ["staging"])
        for name, lines in jobs.items():
            with self.subTest(job=name):
                self._assert_preflight_first(lines)

    def _assert_preflight_first(self, lines: list[str]) -> None:
        blocks = _ci_step_blocks(lines)
        preflight = [i for i, b in enumerate(blocks) if b[0].endswith("name: Check the runner has stack-base's tools")]
        checkout = [i for i, b in enumerate(blocks) if "uses: actions/checkout@" in b[0]]
        self.assertEqual(len(preflight), 1)
        self.assertEqual(len(checkout), 1)
        # Right after checkout: nothing else may run before the tools are known to exist.
        self.assertEqual(preflight[0], checkout[0] + 1)

        infra_up = [
            i
            for i, b in enumerate(blocks)
            if any(not line.strip().startswith("#") and "./infra/up" in line for line in b)
        ]
        self.assertTrue(infra_up)
        for i in infra_up:
            self.assertGreater(i, preflight[0])

        script = "\n".join(blocks[preflight[0]])
        for tool in ("python3", "rsync", "tailwindcss", "x86_64-unknown-linux-musl-gcc", "rustup", "git", "ssh"):
            self.assertIn(tool, script)


if __name__ == "__main__":
    unittest.main()
