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
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

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


@unittest.skipIf(_NIX is None, "nix is not installed")
class CiDeployKeyTests(unittest.TestCase):
    """Task 4: an optional GitHub Actions deploy key, `ci-deploy`, layered
    on top of every admin key. It must reach stackbase.deploy.keys (so it
    can drive the SSH forced-command door) but never stackbase.admins
    itself -- root's and every admin's own authorized_keys must never
    contain it.
    """

    _CI_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAACIExampleCiDeployKey ci-deploy@acme\n"

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

    def test_ci_deploy_key_reaches_deploy_keys_but_never_admin_or_root_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "keys" / "ci-deploy.pub").write_text(self._CI_PUB, encoding="utf-8")

            facts = self._eval(directory)

            self.assertIn("ci-deploy", facts["deployKeys"])
            self.assertNotIn("ExampleCiDeployKey", "".join(facts["rootKeys"]))
            self.assertNotIn("ExampleCiDeployKey", "".join(facts["mattKeys"]))
            self.assertTrue(facts["deployAuthorizedKeys"], "expected at least one deploy authorized_keys line")
            self.assertTrue(
                all(line.startswith("restrict,command=") for line in facts["deployAuthorizedKeys"]),
                facts["deployAuthorizedKeys"],
            )

    def test_no_ci_deploy_pub_file_means_no_ci_deploy_key_and_evaluation_still_succeeds(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            facts = self._eval(directory)

            self.assertNotIn("ci-deploy", facts["deployKeys"])
            self.assertTrue(facts["deployAuthorizedKeys"], "admin keys should still reach the deploy door")
            self.assertTrue(
                all(line.startswith("restrict,command=") for line in facts["deployAuthorizedKeys"]),
                facts["deployAuthorizedKeys"],
            )


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

    def test_the_gitignore_only_hides_build_output(self) -> None:
        entries = [
            line.strip()
            for line in (_TEMPLATE_DIR / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        self.assertEqual(entries, ["result"])

    def test_the_example_stack_toml_parses_and_covers_the_schema(self) -> None:
        import tomllib

        data = tomllib.loads((_TEMPLATE_DIR / "stack.toml.example").read_text(encoding="utf-8"))

        for key in ("project", "domain", "owner", "datacenter", "plan", "price_item", "auto_patch", "admins"):
            self.assertIn(key, data)
        self.assertEqual(data["nodes"]["a"]["role"], "primary")

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
        needle = "github:" + "matiboy/stack-base"
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


if __name__ == "__main__":
    unittest.main()
