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

# Enough of a hardware-configuration.nix to make the module system happy:
# a root filesystem and a boot loader device.
_FAKE_HARDWARE = """\
{ ... }:
{
  fileSystems."/" = { device = "/dev/vda1"; fsType = "ext4"; };
  boot.loader.grub.device = "/dev/vda";
}
"""

_EXTRA_NIX = """\
{ ... }:
{
  networking.domain = "set-by-extra-nix";
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
    (directory / "nodes" / "a" / "hardware-configuration.nix").write_text(_FAKE_HARDWARE, encoding="utf-8")


def _nix_eval(directory: Path) -> dict:
    """Evaluate node "a" and return the facts the template is supposed to set."""
    apply_fn = (
        "node: {"
        " drvPath = node.config.system.build.toplevel.drvPath;"
        " hostName = node.config.networking.hostName;"
        " domain = node.config.networking.domain;"
        " project = node.config.stackbase.project;"
        " adminKeys = node.config.users.users.root.openssh.authorizedKeys.keys;"
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

    def test_an_extra_nix_beside_the_hardware_config_is_picked_up(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            self.assertNotEqual(_nix_eval(directory)["domain"], "set-by-extra-nix")

            (directory / "nodes" / "a" / "extra.nix").write_text(_EXTRA_NIX, encoding="utf-8")

            self.assertEqual(_nix_eval(directory)["domain"], "set-by-extra-nix")


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
