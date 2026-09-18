"""Tests for stackbase.release: verify_version, build, package, ship/rollback/status.

`VerifyVersionTests`/`TagCommitTimestampTests`/`ReleaseWorktreeTests` use real
temporary git repositories (cheap, no network) -- the whole point of those
functions is to inspect a real tag/worktree, so faking `git` would test
nothing. Everything downstream of a checked-out worktree (`build`, `package`,
`ship`, `rollback_nodes`, `status_nodes`) is tested against
`tests.fakes.FakeRunner`/`FakePopen` -- no real cargo build, no real network,
no real server, ever.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.config import AppConfig, Node, NodeState, StackConfig, StackState
from stackbase.errors import StackError
from stackbase.release import (
    MUSL_CC_ENV,
    MUSL_GCC,
    MUSL_LINKER_ENV,
    Project,
    build,
    cargo_target_dir,
    deploy_identity,
    package,
    project_from_cargo_toml,
    release_worktree,
    rollback_nodes,
    run_deploy,
    run_status,
    ship,
    status_nodes,
    tag_commit_timestamp,
    validate_version_format,
    verify_version,
)
from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, save_secrets
from stackbase.__main__ import main
from tests.fakes import FakePopen, FakeRunner
from tests.test_secrets import _generate_age_identity

_SHA = "a" * 64
# The deploy-key tests round-trip through real `age`/`age-keygen` (the same
# philosophy as tests/test_secrets.py: faking the crypto would test nothing);
# they are skipped rather than failed where those binaries are absent.
_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None

# `build()` (Task 7) now honours an already-set $CARGO_TARGET_DIR to find
# where cargo actually wrote the binary. A developer machine may have that
# variable set globally in its shell profile for an unrelated project --
# every test in this module that drives `build()` with a FAKE `popen`
# (which never actually invokes cargo, so nothing is ever written under
# such a directory) needs a clean slate, or the binary-not-produced check
# fails for a reason that has nothing to do with what the test is checking.
# Stripped once here, for the whole module, rather than in every individual
# test that happens to call build().
_SAVED_CARGO_TARGET_DIR: str | None = None


def setUpModule() -> None:
    global _SAVED_CARGO_TARGET_DIR
    _SAVED_CARGO_TARGET_DIR = os.environ.pop("CARGO_TARGET_DIR", None)


def tearDownModule() -> None:
    if _SAVED_CARGO_TARGET_DIR is not None:
        os.environ["CARGO_TARGET_DIR"] = _SAVED_CARGO_TARGET_DIR
_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _cp(*, returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["ssh"], returncode=returncode, stdout=stdout, stderr=stderr)


def _run_git(repo_dir: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        env=_GIT_ENV,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {args} failed: {result.stderr}")


def _init_repo(
    root: Path,
    *,
    cargo_version: str = "1.4.2",
    tag: str | None = "v1.4.2",
    package_name: str = "stack-demo",
    with_binary: bool = False,
) -> Path:
    """A throwaway git repo with a committed Cargo.toml, optionally tagged.

    `with_binary=True` also commits a dummy file at the exact path
    `build()` expects cargo to have produced
    (`target/x86_64-unknown-linux-musl/release/<binary>`) -- unrealistic for
    a real project, but it means a REAL `git worktree add` checkout of the
    tag already contains that file, so a test can drive the full
    `run_deploy` path with a FAKE `popen` for cargo (which never touches the
    filesystem) while `build()`'s own "was the binary actually produced"
    check still finds something real.
    """
    repo_dir = root / "repo"
    repo_dir.mkdir()
    _run_git(repo_dir, "init", "-q")
    (repo_dir / "Cargo.toml").write_text(
        f'[package]\nname = "{package_name}"\nversion = "{cargo_version}"\nedition = "2021"\n',
        encoding="utf-8",
    )
    _run_git(repo_dir, "add", "Cargo.toml")
    if with_binary:
        binary_name = package_name.replace("-", "_")
        binary_dir = repo_dir / "target" / "x86_64-unknown-linux-musl" / "release"
        binary_dir.mkdir(parents=True)
        (binary_dir / binary_name).write_bytes(b"#!/bin/sh\necho pretend-binary\n")
        _run_git(repo_dir, "add", "-f", str((binary_dir / binary_name).relative_to(repo_dir)))
    _run_git(repo_dir, "commit", "-q", "-m", "initial")
    if tag:
        _run_git(repo_dir, "tag", tag)
    return repo_dir


def _cfg(roles: dict[str, str], *, project: str = "acme", app_binary: str | None = None) -> StackConfig:
    return StackConfig(
        project=project,
        domain="acme.example.com",
        owner="matt",
        datacenter="kul",
        plan="KVM 1",
        price_item=None,
        auto_patch=True,
        admins=["matt"],
        nodes={name: Node(name=name, role=role, vps_id=1) for name, role in roles.items()},
        admin_keys={"matt": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample matt@laptop"},
        app=AppConfig(binary=app_binary),
    )


def _state(ips: dict[str, str]) -> StackState:
    return StackState(nodes={name: NodeState(ipv4=ip) for name, ip in ips.items()})


# --------------------------------------------------------------------------
# Version verification
# --------------------------------------------------------------------------


class ValidateVersionFormatTests(unittest.TestCase):
    def test_accepts_a_well_formed_version(self) -> None:
        validate_version_format("v1.4.2")
        validate_version_format("v0.0.0")

    def test_rejects_missing_v_prefix(self) -> None:
        with self.assertRaises(StackError):
            validate_version_format("1.4.2")

    def test_rejects_leading_zeros(self) -> None:
        with self.assertRaises(StackError):
            validate_version_format("v1.04.2")

    def test_rejects_a_pre_release_suffix(self) -> None:
        with self.assertRaises(StackError):
            validate_version_format("v1.4.2-rc1")

    def test_rejects_a_trailing_newline(self) -> None:
        """M3: re.fullmatch, not .match -- Python's `$` alone still allows
        one trailing newline after the last real character, so `.match()`
        would silently accept "v1.2.3\\n"."""
        with self.assertRaises(StackError):
            validate_version_format("v1.4.2\n")


class VersionRegexMatchesTheEngineTests(unittest.TestCase):
    """M3: release.py's own version grammar must be the exact literal
    substituted into nixos/deploy.nix's `versionRegex` binding (itself the
    one source of truth for both stack-deploy.sh's VERSION_GREP and
    stack-deploy-ssh.sh's VERSION_RE, per Fix round 1 F3) -- extracted from
    the real deploy.nix source, not retyped by hand, so a future edit to one
    and not the other is caught here rather than only live, on a server.
    """

    def test_python_version_regex_is_identical_to_deploy_nix_versionregex(self) -> None:
        import re as _re

        from stackbase.release import _VERSION_RE

        deploy_nix = (
            Path(__file__).resolve().parent.parent / "nixos" / "deploy.nix"
        ).read_text(encoding="utf-8")
        match = _re.search(r'versionRegex = "((?:[^"\\]|\\.)*)";', deploy_nix)
        self.assertIsNotNone(match, "could not find `versionRegex = \"...\";` in nixos/deploy.nix")
        # The Nix string literal escapes each backslash ("\\." in the source
        # -> the two characters \ and . in the resulting string); undo that
        # one layer of escaping the same way Nix's own string parser would,
        # to get the literal regex text.
        nix_literal = match.group(1).replace('\\"', '"').replace("\\\\", "\\")
        self.assertEqual(_VERSION_RE.pattern, nix_literal)


class VerifyVersionTests(unittest.TestCase):
    def test_rejects_bad_format_before_any_subprocess_call(self) -> None:
        def boom(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("must not touch a subprocess for a malformed version")

        with self.assertRaises(StackError):
            verify_version(Path("/nonexistent"), "1.4.2", runner=boom)  # missing 'v'

    def test_missing_tag_names_the_create_command(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), tag=None)
            with self.assertRaises(StackError) as ctx:
                verify_version(repo_dir, "v1.4.2")
            self.assertIn("git tag v1.4.2", str(ctx.exception))

    def test_tag_cargo_version_mismatch_is_rejected_with_a_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.4.1", tag="v1.4.2")
            with self.assertRaises(StackError) as ctx:
                verify_version(repo_dir, "v1.4.2")
            self.assertIn("1.4.1", str(ctx.exception))
            self.assertIn("1.4.2", ctx.exception.hint)

    def test_tag_matching_cargo_version_passes(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.4.2", tag="v1.4.2")
            verify_version(repo_dir, "v1.4.2")  # must not raise

    def test_checks_the_tagged_commit_not_a_dirty_working_tree(self) -> None:
        """A working tree that differs from the tag must not fool this."""
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.4.2", tag="v1.4.2")
            # Dirty the working tree AFTER tagging -- never committed, never re-tagged.
            (repo_dir / "Cargo.toml").write_text(
                '[package]\nname = "stack-demo"\nversion = "9.9.9"\nedition = "2021"\n',
                encoding="utf-8",
            )
            verify_version(repo_dir, "v1.4.2")  # still passes: checks the TAG, not the working tree


class TagCommitTimestampTests(unittest.TestCase):
    def test_returns_the_tagged_commits_own_timestamp(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp))
            expected = subprocess.run(
                ["git", "log", "-1", "--format=%ct", "v1.4.2"],
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(tag_commit_timestamp(repo_dir, "v1.4.2"), int(expected))


class ReleaseWorktreeTests(unittest.TestCase):
    def test_yields_a_worktree_checked_out_at_the_tag(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.4.2", tag="v1.4.2")
            with release_worktree(repo_dir, "v1.4.2") as worktree:
                self.assertTrue(worktree.is_dir())
                self.assertIn('version = "1.4.2"', (worktree / "Cargo.toml").read_text(encoding="utf-8"))

    def test_worktree_is_removed_after_the_with_block_exits(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp))
            with release_worktree(repo_dir, "v1.4.2") as worktree:
                captured = worktree
            self.assertFalse(captured.exists())
            listing = subprocess.run(
                ["git", "worktree", "list"], cwd=str(repo_dir), capture_output=True, text=True
            ).stdout
            self.assertNotIn(str(captured), listing)

    def test_worktree_is_removed_even_when_the_body_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp))
            captured: Path | None = None
            with self.assertRaises(RuntimeError):
                with release_worktree(repo_dir, "v1.4.2") as worktree:
                    captured = worktree
                    raise RuntimeError("build blew up")
            assert captured is not None
            self.assertFalse(captured.exists())


class ProjectFromCargoTomlTests(unittest.TestCase):
    def test_binary_name_defaults_to_dashes_replaced_with_underscores(self) -> None:
        # project="stack-demo" -> server default "stack_demo", matching the
        # Cargo-derived name -- no [app].binary override needed.
        cfg = _cfg({"a": "primary"}, project="stack-demo")
        project = project_from_cargo_toml({"package": {"name": "stack-demo", "version": "1.0.0"}}, cfg)
        self.assertEqual(project, Project(version="1.0.0", binary="stack_demo"))

    def test_explicit_bin_name_wins_over_the_package_name(self) -> None:
        cfg = _cfg({"a": "primary"}, project="server")
        data = {"package": {"name": "stack-demo", "version": "1.0.0"}, "bin": [{"name": "server"}]}
        self.assertEqual(project_from_cargo_toml(data, cfg).binary, "server")

    def test_missing_package_table_raises(self) -> None:
        with self.assertRaises(StackError):
            project_from_cargo_toml({}, _cfg({"a": "primary"}))

    def test_app_binary_override_always_wins_no_matter_what_cargo_says(self) -> None:
        """I6: [app].binary short-circuits everything else -- it's not even
        compared against Cargo.toml's own name/[[bin]] entries."""
        cfg = _cfg({"a": "primary"}, project="acme", app_binary="custom_bin")
        data = {"package": {"name": "totally-different", "version": "1.0.0"}, "bin": [{"name": "yet-another"}]}
        project = project_from_cargo_toml(data, cfg)
        self.assertEqual(project, Project(version="1.0.0", binary="custom_bin"))

    def test_several_bin_entries_with_no_override_requires_a_choice(self) -> None:
        """I6: ambiguous -- must not silently take the first [[bin]] entry."""
        cfg = _cfg({"a": "primary"}, project="acme")
        data = {
            "package": {"name": "acme", "version": "1.0.0"},
            "bin": [{"name": "acme"}, {"name": "acme-worker"}],
        }
        with self.assertRaises(StackError) as caught:
            project_from_cargo_toml(data, cfg)

        message = str(caught.exception)
        self.assertIn("[app]", message)
        self.assertIn("acme", message)
        self.assertIn("acme-worker", message)

    def test_a_cargo_derived_name_that_does_not_match_the_server_default_is_refused_before_building(self) -> None:
        """I6: deploying a binary under a name the server's systemd unit
        isn't looking for would just 502 forever -- caught here instead."""
        cfg = _cfg({"a": "primary"}, project="acme")
        data = {"package": {"name": "stack-demo", "version": "1.0.0"}}

        with self.assertRaises(StackError) as caught:
            project_from_cargo_toml(data, cfg)

        message = str(caught.exception)
        self.assertIn("stack_demo", message)
        self.assertIn("acme", message)
        self.assertIn("[app] binary", message)
        self.assertIn("./infra/up", message)


# --------------------------------------------------------------------------
# build()
# --------------------------------------------------------------------------


def _worktree(
    tmp: Path, *, with_package_json_css: bool = False, with_tailwind: bool = False, binary: str = "stack_demo"
) -> Path:
    worktree = tmp / "worktree"
    release_dir = worktree / "target" / "x86_64-unknown-linux-musl" / "release"
    release_dir.mkdir(parents=True)
    (release_dir / binary).write_bytes(b"pretend-elf-binary")
    (worktree / "static" / "css").mkdir(parents=True)
    (worktree / "static" / "css" / "output.css").write_text("body{}", encoding="utf-8")
    if with_package_json_css:
        (worktree / "package.json").write_text(
            json.dumps({"scripts": {"build:css": "tailwindcss -i x -o y"}}), encoding="utf-8"
        )
    if with_tailwind:
        (worktree / "tools").mkdir(parents=True, exist_ok=True)
        (worktree / "tools" / "tailwindcss").write_bytes(b"#!/bin/sh\n")
    return worktree


class BuildTests(unittest.TestCase):
    def test_success_with_no_css_tool_skips_and_assembles_the_bundle(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="Compiling stack-demo\nFinished release\n")
            emitted: list[str] = []
            project = Project(version="1.0.0", binary="stack_demo")

            bundle_dir = build(worktree, project, work_dir=Path(tmp), popen=popen, emit=emitted.append)

            self.assertTrue((bundle_dir / "stack_demo").is_file())
            self.assertEqual((bundle_dir / "stack_demo").stat().st_mode & 0o777, 0o755)
            self.assertTrue((bundle_dir / "static" / "css" / "output.css").is_file())
            self.assertFalse((bundle_dir / "migrations").exists())
            self.assertFalse((bundle_dir / "config").exists())
            self.assertTrue(any("no CSS build step" in line for line in emitted))

            cargo_call = popen.calls[0]
            self.assertIn("--target", cargo_call["argv"])
            self.assertIn("x86_64-unknown-linux-musl", cargo_call["argv"])
            self.assertEqual(cargo_call["kwargs"]["env"]["RUSTFLAGS"], "-C target-feature=+crt-static")
            self.assertEqual(cargo_call["kwargs"]["stdin"], subprocess.DEVNULL)

    def test_an_operator_set_rustflags_is_appended_to_not_overwritten(self) -> None:
        """Minor e, Fix round 1: -C target-feature=+crt-static must not clobber
        a RUSTFLAGS the operator already set (a linker override, a lint
        allow-list, ...).
        """
        with TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"RUSTFLAGS": "-D warnings"}):
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)

            cargo_call = popen.calls[0]
            self.assertEqual(cargo_call["kwargs"]["env"]["RUSTFLAGS"], "-D warnings -C target-feature=+crt-static")

    def test_migrations_and_config_are_bundled_when_present(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            (worktree / "migrations").mkdir()
            (worktree / "migrations" / "001_initial.sql").write_text("-- sql", encoding="utf-8")
            (worktree / "config").mkdir()
            (worktree / "config" / "app.toml").write_text("[x]\n", encoding="utf-8")
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            bundle_dir = build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)

            self.assertTrue((bundle_dir / "migrations" / "001_initial.sql").is_file())
            self.assertTrue((bundle_dir / "config" / "app.toml").is_file())

    def test_runs_npm_ci_and_build_css_when_package_json_has_the_script(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp), with_package_json_css=True)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=0, output="npm ci ok\n")
            popen.script(returncode=0, output="npm run build:css ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)

            argvs = [" ".join(call["argv"]) for call in popen.calls]
            self.assertIn("npm ci", argvs)
            self.assertIn("npm run build:css", argvs)

    def test_runs_tools_tailwindcss_when_no_package_json_script(self) -> None:
        # Deterministic regardless of whether the test machine happens to
        # have a real `tailwindcss` on PATH -- TailwindOnPathTests below
        # covers that case explicitly; this one is about tools/tailwindcss.
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp), with_tailwind=True)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=0, output="tailwind ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(Path(tmp) / "empty")}, clear=True):
                build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)

            tailwind_call = popen.calls[1]
            self.assertTrue(tailwind_call["argv"][0].endswith("tools/tailwindcss"))
            self.assertEqual(
                tailwind_call["argv"][1:],
                ["-i", "src/templates/input.css", "-o", "static/css/output.css", "--minify"],
            )

    def test_missing_musl_target_gets_a_specific_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(
                returncode=101,
                output="error[E0463]: can't find crate for `core`\n"
                "note: the `x86_64-unknown-linux-musl` target may not be installed\n",
            )
            project = Project(version="1.0.0", binary="stack_demo")

            with self.assertRaises(StackError) as ctx:
                build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)
            self.assertIn("rustup target add x86_64-unknown-linux-musl", ctx.exception.hint)

    def test_missing_musl_gcc_gets_a_specific_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=101, output="error: linker `musl-gcc` not found\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with self.assertRaises(StackError) as ctx:
                build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)
            self.assertIn("musl-tools", ctx.exception.hint)

    def test_missing_cargo_binary_names_rustup(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))

            def missing_popen(argv: list[str], **_kwargs: object) -> None:
                raise FileNotFoundError(argv[0])

            project = Project(version="1.0.0", binary="stack_demo")
            with self.assertRaises(StackError) as ctx:
                build(worktree, project, work_dir=Path(tmp), popen=missing_popen, emit=lambda _line: None)
            self.assertIn("rustup.rs", ctx.exception.hint)

    def test_binary_not_produced_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = Path(tmp) / "worktree"
            (worktree / "target" / "x86_64-unknown-linux-musl" / "release").mkdir(parents=True)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with self.assertRaises(StackError) as ctx:
                build(worktree, project, work_dir=Path(tmp), popen=popen, emit=lambda _line: None)
            self.assertIn("stack_demo", str(ctx.exception))

    def test_streams_cargo_output_line_by_line(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="line1\nline2\n")
            emitted: list[str] = []
            project = Project(version="1.0.0", binary="stack_demo")

            build(worktree, project, work_dir=Path(tmp), popen=popen, emit=emitted.append)

            self.assertIn("line1", emitted)
            self.assertIn("line2", emitted)


def _fake_musl_gcc(tmp: Path) -> Path:
    """A directory containing an executable x86_64-unknown-linux-musl-gcc."""
    bin_dir = tmp / "toolchain"
    bin_dir.mkdir()
    gcc = bin_dir / MUSL_GCC
    gcc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gcc.chmod(0o755)
    return bin_dir


class MuslToolchainTests(unittest.TestCase):
    def test_a_cross_gcc_on_path_is_wired_into_both_variables(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            bin_dir = _fake_musl_gcc(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env_without = {
                key: value
                for key, value in os.environ.items()
                if key not in (MUSL_CC_ENV, MUSL_LINKER_ENV)
            }
            env_without["PATH"] = str(bin_dir)
            with mock.patch.dict(os.environ, env_without, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            env = popen.calls[0]["kwargs"]["env"]
            self.assertEqual(env[MUSL_CC_ENV], str(bin_dir / MUSL_GCC))
            self.assertEqual(env[MUSL_LINKER_ENV], str(bin_dir / MUSL_GCC))

    def test_no_cross_gcc_on_path_changes_nothing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env_without = {
                key: value
                for key, value in os.environ.items()
                if key not in (MUSL_CC_ENV, MUSL_LINKER_ENV)
            }
            env_without["PATH"] = str(root / "empty")
            with mock.patch.dict(os.environ, env_without, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            env = popen.calls[0]["kwargs"]["env"]
            self.assertNotIn(MUSL_CC_ENV, env)
            self.assertNotIn(MUSL_LINKER_ENV, env)

    def test_an_operator_set_variable_is_never_overwritten(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            bin_dir = _fake_musl_gcc(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env = {**os.environ, "PATH": str(bin_dir), MUSL_CC_ENV: "/usr/bin/my-own-cc"}
            env.pop(MUSL_LINKER_ENV, None)
            with mock.patch.dict(os.environ, env, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            call_env = popen.calls[0]["kwargs"]["env"]
            self.assertEqual(call_env[MUSL_CC_ENV], "/usr/bin/my-own-cc")
            self.assertNotIn(MUSL_LINKER_ENV, call_env)


class CargoTargetDirTests(unittest.TestCase):
    def test_it_is_under_xdg_cache_home_and_named_for_the_project(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/cache"}, clear=False):
            os.environ.pop("CARGO_TARGET_DIR", None)

            self.assertEqual(cargo_target_dir("acme"), Path("/cache/stack-base/target/acme"))

    def test_an_operator_set_cargo_target_dir_wins(self) -> None:
        with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": "/somewhere"}, clear=False):
            self.assertIsNone(cargo_target_dir("acme"))

    def test_build_uses_the_persistent_dir_and_finds_the_binary_there(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            # The binary must be found under the TARGET dir, not under the
            # throwaway worktree -- a stale copy there would mask the bug.
            shutil.rmtree(worktree / "target")
            target_root = root / "cache" / "stack-base" / "target" / "acme"
            release_dir = target_root / "x86_64-unknown-linux-musl" / "release"
            release_dir.mkdir(parents=True)
            (release_dir / "stack_demo").write_bytes(b"pretend-elf-binary")
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env = {**os.environ, "XDG_CACHE_HOME": str(root / "cache")}
            env.pop("CARGO_TARGET_DIR", None)
            with mock.patch.dict(os.environ, env, clear=True):
                bundle_dir = build(
                    worktree, project, work_dir=root, project_slug="acme", popen=popen, emit=lambda _l: None
                )

            self.assertEqual(popen.calls[0]["kwargs"]["env"]["CARGO_TARGET_DIR"], str(target_root))
            self.assertTrue((bundle_dir / "stack_demo").is_file())

    def test_without_a_project_slug_the_worktree_target_is_used(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env = {key: value for key, value in os.environ.items() if key != "CARGO_TARGET_DIR"}
            with mock.patch.dict(os.environ, env, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            self.assertNotIn("CARGO_TARGET_DIR", popen.calls[0]["kwargs"]["env"])

    def test_a_slug_with_a_path_separator_is_refused(self) -> None:
        """`project_slug` becomes a single path segment under the cache root
        -- a value containing '/' could otherwise escape it. `cfg.project` is
        already constrained by config.py's _PROJECT_RE at stack.toml load
        time, so this can't fire via run_deploy; it's a second, independent
        guard on cargo_target_dir's own public contract.
        """
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/cache"}, clear=False):
            os.environ.pop("CARGO_TARGET_DIR", None)
            with self.assertRaises(StackError):
                cargo_target_dir("../../etc")
            with self.assertRaises(StackError):
                cargo_target_dir("acme/../../etc")

    def test_a_slug_that_is_dot_dot_is_refused(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/cache"}, clear=False):
            os.environ.pop("CARGO_TARGET_DIR", None)
            with self.assertRaises(StackError):
                cargo_target_dir("..")

    def test_a_slug_with_a_leading_hyphen_is_refused(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/cache"}, clear=False):
            os.environ.pop("CARGO_TARGET_DIR", None)
            with self.assertRaises(StackError):
                cargo_target_dir("-rf")


class TailwindOnPathTests(unittest.TestCase):
    def _fake_tailwind(self, tmp: Path) -> Path:
        bin_dir = tmp / "tw"
        bin_dir.mkdir()
        binary = bin_dir / "tailwindcss"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        return bin_dir

    def test_tailwindcss_on_path_is_preferred_over_the_downloaded_binary(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root, with_tailwind=True)
            bin_dir = self._fake_tailwind(root)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=0, output="tailwind ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(bin_dir)}, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            tailwind_call = popen.calls[1]
            self.assertEqual(tailwind_call["argv"][0], str(bin_dir / "tailwindcss"))
            self.assertEqual(
                tailwind_call["argv"][1:],
                ["-i", "src/templates/input.css", "-o", "static/css/output.css", "--minify"],
            )

    def test_a_failing_css_build_names_both_ways_to_get_tailwind(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root, with_tailwind=True)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=1, output="tailwind blew up\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(root / "empty")}, clear=True):
                with self.assertRaises(StackError) as ctx:
                    build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            hint = str(ctx.exception)
            self.assertIn("tailwindcss on PATH", hint)
            self.assertIn("tools/install-tailwindcss.sh", hint)

    def test_the_skip_message_names_all_three_ways(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            emitted: list[str] = []
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(root / "empty")}, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=emitted.append)

            skip = next(line for line in emitted if "no CSS build step" in line)
            self.assertIn("build:css", skip)
            self.assertIn("tailwindcss on PATH", skip)
            self.assertIn("tools/tailwindcss", skip)


# --------------------------------------------------------------------------
# package()
# --------------------------------------------------------------------------


class PackageTests(unittest.TestCase):
    def _bundle(self, tmp: Path) -> Path:
        bundle_dir = tmp / "bundle"
        (bundle_dir / "static" / "css").mkdir(parents=True)
        (bundle_dir / "stack_demo").write_bytes(b"binary-bytes")
        (bundle_dir / "static" / "css" / "output.css").write_text("body{}", encoding="utf-8")
        return bundle_dir

    def test_two_runs_produce_identical_sha256(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle_dir = self._bundle(Path(tmp))
            _, sha1 = package(bundle_dir, "v1.0.0", 1_700_000_000, binary_name="stack_demo", output_dir=Path(tmp) / "out1")
            _, sha2 = package(bundle_dir, "v1.0.0", 1_700_000_000, binary_name="stack_demo", output_dir=Path(tmp) / "out2")
            self.assertEqual(sha1, sha2)

    def test_returned_sha256_matches_the_tarball_bytes(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle_dir = self._bundle(Path(tmp))
            tar_path, sha = package(bundle_dir, "v1.0.0", 0, binary_name="stack_demo")
            self.assertEqual(sha, hashlib.sha256(tar_path.read_bytes()).hexdigest())

    def test_refuses_a_symlink_in_the_bundle(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "bundle"
            bundle_dir.mkdir()
            (bundle_dir / "stack_demo").write_bytes(b"bin")
            outside = Path(tmp) / "outside.txt"
            outside.write_text("x", encoding="utf-8")
            (bundle_dir / "sneaky").symlink_to(outside)

            with self.assertRaises(StackError) as ctx:
                package(bundle_dir, "v1.0.0", 0, binary_name="stack_demo")
            self.assertIn("symlink", str(ctx.exception))

    def test_refuses_a_symlinked_directory(self) -> None:
        """Minor b, Fix round 1: a symlinked DIRECTORY, not just a symlinked file."""
        with TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "bundle"
            bundle_dir.mkdir()
            (bundle_dir / "stack_demo").write_bytes(b"bin")
            real_dir = Path(tmp) / "outside-dir"
            (real_dir / "nested.txt").parent.mkdir(parents=True)
            (real_dir / "nested.txt").write_text("x", encoding="utf-8")
            (bundle_dir / "static").symlink_to(real_dir, target_is_directory=True)

            with self.assertRaises(StackError) as ctx:
                package(bundle_dir, "v1.0.0", 0, binary_name="stack_demo")
            self.assertIn("symlink", str(ctx.exception))

    def test_refuses_a_non_regular_file(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "bundle"
            bundle_dir.mkdir()
            (bundle_dir / "stack_demo").write_bytes(b"bin")
            fifo_path = bundle_dir / "a-fifo"
            os.mkfifo(fifo_path)
            with self.assertRaises(StackError):
                package(bundle_dir, "v1.0.0", 0, binary_name="stack_demo")

    def test_member_names_have_no_leading_dot_slash_no_absolute_no_dotdot(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle_dir = self._bundle(Path(tmp))
            tar_path, _ = package(bundle_dir, "v1.0.0", 0, binary_name="stack_demo")
            with tarfile.open(tar_path, "r:gz") as tar:
                names = tar.getnames()
            self.assertTrue(names)
            for name in names:
                self.assertFalse(name.startswith("./"), name)
                self.assertFalse(name.startswith("/"), name)
                self.assertNotIn("..", name.split("/"), name)
                self.assertNotIn("\\", name)

    def test_modes_uid_gid_and_mtime_are_normalised(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle_dir = self._bundle(Path(tmp))
            # A real, weird local mtime on disk -- must not leak into the tarball.
            os.utime(bundle_dir / "stack_demo", (1000, 1000))
            fixed_mtime = 1_700_000_000
            tar_path, _ = package(bundle_dir, "v1.0.0", fixed_mtime, binary_name="stack_demo")

            with tarfile.open(tar_path, "r:gz") as tar:
                members = {m.name: m for m in tar.getmembers()}

            binary = members["stack_demo"]
            self.assertEqual(binary.mode, 0o755)
            self.assertEqual(binary.mtime, fixed_mtime)
            self.assertEqual(binary.uid, 0)
            self.assertEqual(binary.gid, 0)
            self.assertEqual(binary.uname, "")
            self.assertEqual(binary.gname, "")

            css = members["static/css/output.css"]
            self.assertEqual(css.mode, 0o644)
            self.assertEqual(css.mtime, fixed_mtime)

            directory = members["static"]
            self.assertTrue(directory.isdir())
            self.assertEqual(directory.mode, 0o755)
            self.assertEqual(directory.mtime, fixed_mtime)

    def test_gzip_wrapper_itself_has_mtime_zero(self) -> None:
        import gzip

        with TemporaryDirectory() as tmp:
            bundle_dir = self._bundle(Path(tmp))
            tar_path, _ = package(bundle_dir, "v1.0.0", 1_700_000_000, binary_name="stack_demo")
            with gzip.GzipFile(tar_path, "rb") as gz:
                gz.read(1)  # force the header to be parsed
                self.assertEqual(gz.mtime, 0)

    def test_pinned_pax_format_emits_no_extended_headers_for_a_normal_bundle(self) -> None:
        """Minor a, Fix round 1: format is pinned to PAX_FORMAT explicitly, but
        a normal bundle (short ascii names, uid/gid forced to 0) must never
        actually need an extended header block -- that would break byte
        determinism between two otherwise-identical runs.
        """
        with TemporaryDirectory() as tmp:
            bundle_dir = self._bundle(Path(tmp))
            tar_path, _ = package(bundle_dir, "v1.0.0", 1_700_000_000, binary_name="stack_demo")

            with tarfile.open(tar_path, "r:gz") as tar:
                self.assertEqual(tar.format, tarfile.PAX_FORMAT)
                members = tar.getmembers()
                self.assertTrue(members)
                for member in members:
                    self.assertEqual(member.pax_headers, {}, f"unexpected PAX extended header on {member.name!r}")


# --------------------------------------------------------------------------
# ship()
# --------------------------------------------------------------------------


class ShipTests(unittest.TestCase):
    def _tarball(self, tmp: Path) -> Path:
        tarball = Path(tmp) / "v1.0.0.tar.gz"
        tarball.write_bytes(b"pretend-tarball-bytes")
        return tarball

    def test_order_is_replicas_then_primary_and_uploads_then_deploys(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            popen = FakePopen()
            for _ in range(4):
                popen.script(returncode=0, output="✓ ok\n")
            for _ in range(2):
                popen.script(returncode=0, output="active=blue (v1.0.0)  idle=green (-)\n")
            emitted: list[str] = []

            results = ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=emitted.append)

            self.assertEqual(results, {"b": "v1.0.0", "a": "v1.0.0"})
            hosts = [call["argv"][-2] for call in popen.calls[:4]]
            self.assertEqual(hosts, ["deploy@10.0.0.2", "deploy@10.0.0.2", "deploy@10.0.0.1", "deploy@10.0.0.1"])
            cmds = [call["argv"][-1] for call in popen.calls[:4]]
            self.assertEqual(cmds[0], f"upload v1.0.0 {_SHA}")
            self.assertEqual(cmds[1], "deploy v1.0.0")
            self.assertEqual(cmds[2], f"upload v1.0.0 {_SHA}")
            self.assertEqual(cmds[3], "deploy v1.0.0")
            # the summary's own colors calls, one per node touched.
            summary_hosts = {call["argv"][-2] for call in popen.calls[4:]}
            self.assertEqual(summary_hosts, {"deploy@10.0.0.1", "deploy@10.0.0.2"})

    def test_node_filter_restricts_to_one_node_and_notes_the_others_untouched(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")
            emitted: list[str] = []

            results = ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, node="b", popen=popen, emit=emitted.append)

            self.assertEqual(results, {"b": "v1.0.0"})
            self.assertEqual(len(popen.calls), 3)
            self.assertTrue(all(call["argv"][-2] == "deploy@10.0.0.2" for call in popen.calls))
            # minor c, Fix round 1: --node tells the operator how many OTHER
            # configured nodes this run never touched.
            self.assertTrue(any("1 other configured node" in line and "not touched" in line for line in emitted))

    def test_unknown_node_raises_and_lists_known_names(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", Path("/nonexistent.tar.gz"), _SHA, node="nope")
            self.assertIn("known nodes", str(ctx.exception))

    def test_upload_exit_0_with_already_uploaded_message_continues_to_deploy(self) -> None:
        """P1, Fix round 1: control flow is the upload's EXIT CODE alone (0 =
        proceed) -- the door's own "already uploaded (same content)" line is
        only ever echoed for display via `emit`, never matched for control
        flow (the old "already exists" substring match is gone entirely).
        """
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=0, output="release v1.0.0 is already uploaded (same content)\n")
            popen.script(returncode=0, output="✓ traffic switched to blue\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")
            emitted: list[str] = []

            results = ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=emitted.append)

            self.assertEqual(results, {"a": "v1.0.0"})
            self.assertTrue(any("already uploaded (same content)" in line for line in emitted))
            # deploy WAS reached (not skipped) -- its own line shows up too.
            self.assertTrue(any("traffic switched to blue" in line for line in emitted))

    def test_upload_exit_4_raises_and_never_reaches_deploy(self) -> None:
        """P1, Fix round 1: exit 4 means the version already exists on the
        node with DIFFERENT content -- refused, distinctly from a lock (3)
        or a generic failure (any other non-zero).
        """
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(
                returncode=4,
                output="✗ release v1.0.0 already exists with different content -- a published version "
                "must never change; bump the version instead\n",
            )
            popen.script(returncode=0, output="active=blue (v0.9.0)\n")  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)

            self.assertIn("node a already has v1.0.0 with different content", str(ctx.exception))
            self.assertIn("bump", ctx.exception.hint)
            # only the upload ran -- deploy was never reached.
            self.assertEqual(len(popen.calls), 2)  # upload + summary colors call
            self.assertEqual(popen.calls[0]["argv"][-1], f"upload v1.0.0 {_SHA}")

    def test_upload_generic_failure_stops_before_deploy(self) -> None:
        """P4, Fix round 1: after P1, ANY upload exit other than 0 must stop
        the rollout -- not just the two now-special-cased codes (3, 4).
        """
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=1, output="✗ sha256 mismatch for /tmp/x: expected aaa, got bbb\n")
            popen.script(returncode=0, output="active=blue (v0.9.0)\n")  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)

            self.assertIn("uploading v1.0.0 to node a failed (exit 1)", str(ctx.exception))
            self.assertEqual(len(popen.calls), 2)  # upload + summary colors call -- deploy never ran
            self.assertEqual(popen.calls[0]["argv"][-1], f"upload v1.0.0 {_SHA}")

    def test_upload_lock_held_raises_another_deploy_is_running(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=3, output="✗ another deploy is already in progress (lock held)\n")
            popen.script(returncode=0, output="active=blue (v0.9.0)\n")  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)
            self.assertIn("another deploy is running on a", str(ctx.exception))

    def test_deploy_lock_held_raises_another_deploy_is_running(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ unpacked v1.0.0\n")
            popen.script(returncode=3, output="✗ another deploy is already in progress (lock held)\n")
            popen.script(returncode=0, output="active=blue (v0.9.0)\n")  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)
            self.assertIn("another deploy is running on a", str(ctx.exception))

    def test_first_failure_stops_further_nodes_and_summary_names_versions(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary", "b": "replica", "c": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2", "c": "10.0.0.3"})
            popen = FakePopen()
            # order is b, c, a (replicas first) -- b fails at the deploy step.
            popen.script(returncode=0, output="✓ unpacked v1.0.0\n")  # b upload
            popen.script(returncode=1, output="✗ blue failed the health check\n")  # b deploy
            popen.script(returncode=0, output="active=blue (v1.0.0)  idle=green (-)\n")  # summary b
            popen.script(returncode=0, output="active=blue (v0.9.0)  idle=green (-)\n")  # summary c
            popen.script(returncode=0, output="active=blue (v0.9.0)  idle=green (-)\n")  # summary a
            emitted: list[str] = []

            with self.assertRaises(StackError):
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=emitted.append)

            # c and a were never touched -- only b's upload+deploy ran before the failure.
            touched_hosts = {call["argv"][-2] for call in popen.calls[:2]}
            self.assertEqual(touched_hosts, {"deploy@10.0.0.2"})
            summary_text = "\n".join(emitted)
            self.assertIn("v1.0.0", summary_text)
            self.assertIn("v0.9.0", summary_text)

    def test_host_key_changed_during_deploy_yields_the_pin_hint(self) -> None:
        """P3, Fix round 1: ship's own `deploy` step used to call
        `ssh.run(..., check=False)`, which -- like `run()` generally --
        never surfaced the host-key hint when check=False. The unified
        `run_stream` surfaces it unconditionally.
        """
        from stackbase.ssh import HOST_KEY_CHANGED_MARKER

        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ unpacked v1.0.0\n")  # upload
            popen.script(returncode=255, output=f"@@@ {HOST_KEY_CHANGED_MARKER} @@@\n")  # deploy
            popen.script(returncode=0, output="active=blue (v0.9.0)\n")  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)
            self.assertIn("does not match the pinned entry", str(ctx.exception))

    def test_ssh_argv_uses_deploy_user_and_the_pinned_known_hosts(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)

            upload_call = popen.calls[0]
            self.assertIn("BatchMode=yes", upload_call["argv"])
            self.assertIn(f"UserKnownHostsFile={infra_dir / 'known_hosts'}", upload_call["argv"])
            self.assertEqual(upload_call["argv"][-2], "deploy@10.0.0.1")

    def test_tarball_is_streamed_as_stdin_not_devnull(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, popen=popen, emit=lambda _l: None)

            upload_kwargs = popen.calls[0]["kwargs"]
            self.assertTrue(hasattr(upload_kwargs["stdin"], "read"))
            # the deploy call (not an upload) must NOT relay any local stdin.
            deploy_kwargs = popen.calls[1]["kwargs"]
            self.assertIs(deploy_kwargs["stdin"], subprocess.DEVNULL)


# --------------------------------------------------------------------------
# rollback_nodes() / status_nodes()
# --------------------------------------------------------------------------


class RollbackNodesTests(unittest.TestCase):
    def test_order_is_primary_then_replicas(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica", "c": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2", "c": "10.0.0.3"})
            popen = FakePopen()
            for _ in range(3):
                popen.script(returncode=0, output="✓ rollback complete\n")

            rollback_nodes(infra_dir, cfg, state, popen=popen, emit=lambda _l: None)

            hosts = [call["argv"][-2] for call in popen.calls]
            self.assertEqual(hosts, ["deploy@10.0.0.1", "deploy@10.0.0.2", "deploy@10.0.0.3"])
            self.assertTrue(all(call["argv"][-1] == "rollback" for call in popen.calls))

    def test_node_filter_restricts_to_one_node_and_notes_the_others_untouched(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ rollback complete\n")
            emitted: list[str] = []

            rollback_nodes(infra_dir, cfg, state, node="b", popen=popen, emit=emitted.append)

            self.assertEqual(len(popen.calls), 1)
            self.assertEqual(popen.calls[0]["argv"][-2], "deploy@10.0.0.2")
            self.assertTrue(any("1 other configured node" in line and "not touched" in line for line in emitted))

    def test_unknown_node_raises_and_lists_known_names(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})

            with self.assertRaises(StackError) as ctx:
                rollback_nodes(infra_dir, cfg, state, node="nope", popen=FakePopen(), emit=lambda _l: None)
            self.assertIn("known nodes", str(ctx.exception))

    def test_host_key_changed_yields_the_pin_hint(self) -> None:
        """P3, Fix round 1: rollback/status/deploy must ALL surface the same
        reinstall-vs-interception hint on a host-key change -- previously
        only run()/fetch()/rsync_to() did, and rollback/status bypassed it
        entirely via the old hand-rolled `_stream_ssh`.
        """
        from stackbase.ssh import HOST_KEY_CHANGED_MARKER

        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=255, output=f"@@@ {HOST_KEY_CHANGED_MARKER} @@@\n")

            with self.assertRaises(StackError) as ctx:
                rollback_nodes(infra_dir, cfg, state, popen=popen, emit=lambda _l: None)
            self.assertIn("does not match the pinned entry", str(ctx.exception))

    def test_lock_held_raises_another_deploy_is_running(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=3, output="✗ another deploy is already in progress\n")

            with self.assertRaises(StackError) as ctx:
                rollback_nodes(infra_dir, cfg, state, popen=popen, emit=lambda _l: None)
            self.assertIn("another deploy is running on a", str(ctx.exception))


class StatusNodesTests(unittest.TestCase):
    def test_runs_status_once_per_selected_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            popen = FakePopen()
            popen.script(returncode=0, output="active=blue (v1.0.0)  idle=green (-)\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)  idle=green (-)\n")
            emitted: list[str] = []

            status_nodes(infra_dir, cfg, state, popen=popen, emit=emitted.append)

            self.assertEqual(len(popen.calls), 2)
            self.assertTrue(all(call["argv"][-1] == "status" for call in popen.calls))
            self.assertTrue(any("v1.0.0" in line for line in emitted))

    def test_node_filter_restricts_to_one_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            popen = FakePopen()
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            status_nodes(infra_dir, cfg, state, node="a", popen=popen, emit=lambda _l: None)

            self.assertEqual(len(popen.calls), 1)
            self.assertEqual(popen.calls[0]["argv"][-2], "deploy@10.0.0.1")

    def test_host_key_changed_yields_the_pin_hint(self) -> None:
        from stackbase.ssh import HOST_KEY_CHANGED_MARKER

        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            popen = FakePopen()
            popen.script(returncode=255, output=f"@@@ {HOST_KEY_CHANGED_MARKER} @@@\n")

            with self.assertRaises(StackError) as ctx:
                status_nodes(infra_dir, cfg, state, popen=popen, emit=lambda _l: None)
            self.assertIn("does not match the pinned entry", str(ctx.exception))


# --------------------------------------------------------------------------
# run_deploy(): --skip-build validation and wiring
# --------------------------------------------------------------------------


class RunDeploySkipBuildTests(unittest.TestCase):
    def _project(self, root: Path) -> Path:
        infra_dir = root / "infra"
        (infra_dir / "keys").mkdir(parents=True)
        (infra_dir / "stack.toml").write_text(
            '\n'.join(
                [
                    'project    = "acme"',
                    'domain     = "acme.example.com"',
                    'owner      = "matt"',
                    'datacenter = "kul"',
                    'plan       = "KVM 1"',
                    'admins     = ["matt"]',
                    "",
                    "[nodes.a]",
                    'role   = "primary"',
                    "vps_id = 1",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (infra_dir / "keys" / "matt.pub").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample matt@laptop\n", encoding="utf-8"
        )
        (infra_dir / "stack.state.json").write_text(
            json.dumps({"version": 1, "nodes": {"a": {"ipv4": "10.0.0.1"}}}), encoding="utf-8"
        )
        return infra_dir

    def test_skip_build_without_tarball_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._project(Path(tmp))
            with self.assertRaises(StackError) as ctx:
                run_deploy(infra_dir, "v1.0.0", skip_build=True, runner=FakeRunner())
            self.assertIn("--tarball", str(ctx.exception))

    def test_tarball_without_skip_build_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._project(Path(tmp))
            with self.assertRaises(StackError) as ctx:
                run_deploy(infra_dir, "v1.0.0", tarball_path="/tmp/x.tar.gz", runner=FakeRunner())
            self.assertIn("--skip-build", str(ctx.exception))

    def test_skip_build_computes_sha256_and_ships_the_given_tarball(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = self._project(Path(tmp))
            tarball = Path(tmp) / "prebuilt.tar.gz"
            tarball.write_bytes(b"a prebuilt release archive")
            expected_sha = hashlib.sha256(tarball.read_bytes()).hexdigest()

            popen = FakePopen()
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            run_deploy(infra_dir, "v1.0.0", skip_build=True, tarball_path=str(tarball), popen=popen, emit=lambda _l: None)

            upload_cmd = popen.calls[0]["argv"][-1]
            self.assertEqual(upload_cmd, f"upload v1.0.0 {expected_sha}")

    def test_skip_build_never_touches_git(self) -> None:
        """No tag/Cargo.toml check when a prebuilt tarball is supplied -- see run_deploy's docstring."""
        with TemporaryDirectory() as tmp:
            infra_dir = self._project(Path(tmp))
            tarball = Path(tmp) / "prebuilt.tar.gz"
            tarball.write_bytes(b"bytes")

            def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
                raise AssertionError(f"skip_build must never call the runner (git or otherwise): {argv}")

            popen = FakePopen()
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            run_deploy(
                infra_dir, "v1.0.0", skip_build=True, tarball_path=str(tarball), runner=runner, popen=popen, emit=lambda _l: None
            )

    def test_skip_build_never_creates_a_work_dir_and_never_touches_the_operator_tarball(self) -> None:
        """P2, Fix round 1: the operator's own --tarball file must never be
        deleted or moved -- no private work dir is created for this path at
        all.
        """
        with TemporaryDirectory() as tmp:
            infra_dir = self._project(Path(tmp))
            tarball = Path(tmp) / "prebuilt.tar.gz"
            original_bytes = b"a prebuilt release archive"
            tarball.write_bytes(original_bytes)

            popen = FakePopen()
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            def failing_mkdtemp(*_args: object, **_kwargs: object) -> str:
                raise AssertionError("skip_build must never create a private work dir")

            with mock.patch("stackbase.release.tempfile.mkdtemp", side_effect=failing_mkdtemp):
                run_deploy(infra_dir, "v1.0.0", skip_build=True, tarball_path=str(tarball), popen=popen, emit=lambda _l: None)

            self.assertTrue(tarball.is_file())
            self.assertEqual(tarball.read_bytes(), original_bytes)


# --------------------------------------------------------------------------
# run_deploy(): P2, Fix round 1 -- the private per-run work dir
# --------------------------------------------------------------------------


class RunDeployWorkDirTests(unittest.TestCase):
    """The full (non-skip-build) `run_deploy` path, against a REAL git repo
    (cheap -- matches this file's own stated philosophy) but a FAKE `popen`
    for both cargo and every ssh call, so no real cargo/ssh ever runs.

    `run_deploy` always passes `project_slug=cfg.project` (Task 7), so
    `build()` looks for the binary under the persistent per-project cache
    dir, not under the worktree -- `_seed_persistent_binary` pre-creates it
    there, under a `$XDG_CACHE_HOME` scoped to this test's own tmpdir (never
    the real developer home directory).
    """

    def _seed_persistent_binary(self, cache_home: Path, *, project: str = "acme", binary: str = "stack_demo") -> None:
        release_dir = cache_home / "stack-base" / "target" / project / "x86_64-unknown-linux-musl" / "release"
        release_dir.mkdir(parents=True)
        (release_dir / binary).write_bytes(b"#!/bin/sh\necho pretend-binary\n")

    def _infra(self, repo_dir: Path) -> Path:
        infra_dir = repo_dir / "infra"
        (infra_dir / "keys").mkdir(parents=True)
        (infra_dir / "stack.toml").write_text(
            "\n".join(
                [
                    'project    = "acme"',
                    'domain     = "acme.example.com"',
                    'owner      = "matt"',
                    'datacenter = "kul"',
                    'plan       = "KVM 1"',
                    'admins     = ["matt"]',
                    "",
                    "[nodes.a]",
                    'role   = "primary"',
                    "vps_id = 1",
                    "",
                    # I6: _init_repo's default package_name ("stack-demo",
                    # below) derives to binary "stack_demo", which does NOT
                    # match this project's own default ("acme" -> "acme") --
                    # exactly the mismatch project_from_cargo_toml now
                    # refuses without an override. These tests are about
                    # work-dir privacy/removal, not binary-name resolution
                    # (which has its own ProjectFromCargoTomlTests below),
                    # so the override is declared here once for every test
                    # sharing this fixture.
                    "[app]",
                    'binary = "stack_demo"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (infra_dir / "keys" / "matt.pub").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample matt@laptop\n", encoding="utf-8"
        )
        (infra_dir / "stack.state.json").write_text(
            json.dumps({"version": 1, "nodes": {"a": {"ipv4": "10.0.0.1"}}}), encoding="utf-8"
        )
        return infra_dir

    def _spy_mkdtemp(self):
        """Wraps the real `tempfile.mkdtemp` -- records every (path, mode-at-
        creation) it produces, so a test can find the "stackbase-release-"
        prefixed one and check both its mode and, after the run, that it no
        longer exists.
        """
        created: list[tuple[Path, int]] = []
        real_mkdtemp = tempfile.mkdtemp

        def spying(*args: object, **kwargs: object) -> str:
            path = real_mkdtemp(*args, **kwargs)
            created.append((Path(path), os.stat(path).st_mode & 0o777))
            return path

        return spying, created

    def test_work_dir_is_private_and_removed_on_success(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.0.0", tag="v1.0.0")
            infra_dir = self._infra(repo_dir)
            cache_home = Path(tmp) / "cache"
            self._seed_persistent_binary(cache_home)
            spying_mkdtemp, created = self._spy_mkdtemp()

            popen = FakePopen()
            popen.script(returncode=0, output="Compiling stack-demo\nFinished release\n")  # cargo build
            popen.script(returncode=0, output="✓ ok\n")  # upload
            popen.script(returncode=0, output="✓ ok\n")  # deploy
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")  # colors summary

            with mock.patch.dict(os.environ, {**os.environ, "XDG_CACHE_HOME": str(cache_home)}, clear=True):
                with mock.patch("stackbase.release.tempfile.mkdtemp", side_effect=spying_mkdtemp):
                    run_deploy(infra_dir, "v1.0.0", popen=popen, emit=lambda _l: None)

            work_dirs = [(p, mode) for p, mode in created if p.name.startswith("stackbase-release-")]
            self.assertEqual(len(work_dirs), 1, f"expected exactly one private work dir, got: {created}")
            work_dir, mode = work_dirs[0]
            self.assertEqual(mode, 0o700, f"expected the work dir to be private (0700), got {oct(mode)}")
            self.assertFalse(work_dir.exists(), "the private work dir must be removed after a successful run")

    def test_work_dir_is_removed_on_a_mid_ship_failure(self) -> None:
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.0.0", tag="v1.0.0")
            infra_dir = self._infra(repo_dir)
            cache_home = Path(tmp) / "cache"
            self._seed_persistent_binary(cache_home)
            spying_mkdtemp, created = self._spy_mkdtemp()

            popen = FakePopen()
            popen.script(returncode=0, output="Compiling stack-demo\nFinished release\n")  # cargo build
            popen.script(returncode=1, output="✗ sha256 mismatch\n")  # upload fails
            popen.script(returncode=0, output="active=blue (v0.9.0)\n")  # colors summary

            with mock.patch.dict(os.environ, {**os.environ, "XDG_CACHE_HOME": str(cache_home)}, clear=True):
                with mock.patch("stackbase.release.tempfile.mkdtemp", side_effect=spying_mkdtemp):
                    with self.assertRaises(StackError):
                        run_deploy(infra_dir, "v1.0.0", popen=popen, emit=lambda _l: None)

            work_dirs = [p for p, _mode in created if p.name.startswith("stackbase-release-")]
            self.assertEqual(len(work_dirs), 1)
            self.assertFalse(work_dirs[0].exists(), "the private work dir must be removed even after a ship failure")

    def test_tarball_is_not_written_directly_into_the_bundles_own_parent_outside_work_dir(self) -> None:
        """The finished tarball lives INSIDE the private work dir (a sibling
        of the bundle), never at a bare, predictable path in the shared
        system temp root -- P2's actual security-relevant point.
        """
        with TemporaryDirectory() as tmp:
            repo_dir = _init_repo(Path(tmp), cargo_version="1.0.0", tag="v1.0.0")
            infra_dir = self._infra(repo_dir)
            cache_home = Path(tmp) / "cache"
            self._seed_persistent_binary(cache_home)
            seen_tarball_dirs: list[Path] = []

            real_package = package
            bundle_was_a_sibling: list[bool] = []

            def spying_package(bundle_dir: Path, *args: object, **kwargs: object):
                tar_path, sha = real_package(bundle_dir, *args, **kwargs)
                # checked HERE, not after run_deploy() returns -- the private
                # work dir (this tarball's own parent) is removed in
                # run_deploy's `finally` before this test function regains
                # control.
                bundle_was_a_sibling.append(tar_path.parent == bundle_dir.parent)
                seen_tarball_dirs.append(tar_path.parent)
                return tar_path, sha

            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="✓ ok\n")
            popen.script(returncode=0, output="active=blue (v1.0.0)\n")

            with mock.patch.dict(os.environ, {**os.environ, "XDG_CACHE_HOME": str(cache_home)}, clear=True):
                with mock.patch("stackbase.release.package", side_effect=spying_package):
                    run_deploy(infra_dir, "v1.0.0", popen=popen, emit=lambda _l: None)

            self.assertEqual(len(seen_tarball_dirs), 1)
            self.assertEqual(bundle_was_a_sibling, [True])
            tarball_dir = seen_tarball_dirs[0]
            self.assertNotEqual(str(tarball_dir), str(Path(tempfile.gettempdir())))
            self.assertTrue(str(tarball_dir).startswith(str(Path(tempfile.gettempdir()))))


# --------------------------------------------------------------------------
# CLI wiring: deploy/rollback/status never call load_secrets
# --------------------------------------------------------------------------


class CLIWiringTests(unittest.TestCase):
    def test_deploy_never_calls_load_secrets_and_forwards_arguments(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.run_deploy") as run_deploy_mock,
                mock.patch("stackbase.__main__.load_secrets") as load_secrets_mock,
            ):
                main(["--infra-dir", str(infra_dir), "deploy", "v1.4.2", "--node", "a"])

            load_secrets_mock.assert_not_called()
            run_deploy_mock.assert_called_once()
            args, kwargs = run_deploy_mock.call_args
            self.assertEqual(args[0], infra_dir)
            self.assertEqual(args[1], "v1.4.2")
            self.assertEqual(kwargs["node"], "a")
            self.assertFalse(kwargs["skip_build"])
            self.assertIsNone(kwargs["tarball_path"])

    def test_deploy_skip_build_and_tarball_are_forwarded(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.run_deploy") as run_deploy_mock:
                main(
                    [
                        "--infra-dir",
                        str(infra_dir),
                        "deploy",
                        "v1.4.2",
                        "--skip-build",
                        "--tarball",
                        "/tmp/x.tar.gz",
                    ]
                )
            kwargs = run_deploy_mock.call_args.kwargs
            self.assertTrue(kwargs["skip_build"])
            self.assertEqual(kwargs["tarball_path"], "/tmp/x.tar.gz")

    def test_rollback_never_calls_load_secrets_and_forwards_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.run_rollback") as run_rollback_mock,
                mock.patch("stackbase.__main__.load_secrets") as load_secrets_mock,
            ):
                main(["--infra-dir", str(infra_dir), "rollback", "--node", "b"])

            load_secrets_mock.assert_not_called()
            run_rollback_mock.assert_called_once()
            self.assertEqual(run_rollback_mock.call_args.kwargs["node"], "b")

    def test_status_never_calls_load_secrets_and_forwards_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.run_status") as run_status_mock,
                mock.patch("stackbase.__main__.load_secrets") as load_secrets_mock,
            ):
                main(["--infra-dir", str(infra_dir), "status"])

            load_secrets_mock.assert_not_called()
            run_status_mock.assert_called_once()
            self.assertIsNone(run_status_mock.call_args.kwargs["node"])

    def test_deploy_failure_is_one_redacted_line_and_exit_code_1(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch(
                "stackbase.__main__.run_deploy", side_effect=StackError("boom", "check the release")
            ):
                import contextlib
                import io

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                    main(["--infra-dir", str(infra_dir), "deploy", "v1.0.0"])

            self.assertEqual(ctx.exception.code, 1)
            line = stderr.getvalue().strip()
            self.assertEqual(len(line.splitlines()), 1)
            self.assertTrue(line.startswith("error: boom"))


# --------------------------------------------------------------------------
# deploy_identity(): which SSH key a deploy offers, and where the plaintext lives
# --------------------------------------------------------------------------


_TEST_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


class DeployIdentityTests(unittest.TestCase):
    def test_an_explicit_env_identity_wins_and_nothing_is_decrypted(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            (infra_dir / "deploy.age").write_bytes(b"would-not-decrypt")
            emitted: list[str] = []

            with mock.patch.dict(os.environ, {"STACKBASE_SSH_IDENTITY": "/home/me/.ssh/id_ed25519"}):
                with deploy_identity(infra_dir, emit=emitted.append):
                    self.assertEqual(os.environ["STACKBASE_SSH_IDENTITY"], "/home/me/.ssh/id_ed25519")

            self.assertEqual(emitted, [])

    def test_no_project_key_warns_once_and_leaves_the_agent_path_alone(self) -> None:
        with TemporaryDirectory() as tmp:
            emitted: list[str] = []
            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}

            with mock.patch.dict(os.environ, env, clear=True):
                with deploy_identity(Path(tmp), emit=emitted.append):
                    self.assertNotIn("STACKBASE_SSH_IDENTITY", os.environ)

            self.assertEqual(len(emitted), 1)
            self.assertIn("deploy-key init", emitted[0])

    @unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed")
    def test_deploy_age_is_decrypted_into_a_ram_dir_for_the_duration_only(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            identity_path, public_key = _generate_age_identity(Path(tmp))
            (infra_dir / "deploy-recipients.txt").write_text(public_key + "\n", encoding="utf-8")
            seen: dict[str, str] = {}

            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}
            env["STACKBASE_AGE_IDENTITY"] = str(identity_path)
            with mock.patch.dict(os.environ, env, clear=True):
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: _TEST_PRIVATE_KEY}, file=DEPLOY_FILE)

                with deploy_identity(infra_dir, emit=lambda _line: None):
                    key_path = Path(os.environ["STACKBASE_SSH_IDENTITY"])
                    seen["path"] = str(key_path)
                    self.assertTrue(key_path.is_absolute())
                    self.assertEqual(key_path.read_text(encoding="utf-8"), _TEST_PRIVATE_KEY)
                    self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                    self.assertFalse(
                        str(key_path).startswith(str(infra_dir)),
                        "the plaintext key must never be written inside the project",
                    )

                self.assertNotIn("STACKBASE_SSH_IDENTITY", os.environ)

            self.assertFalse(Path(seen["path"]).exists(), "the RAM scratch file must be wiped on exit")

    @unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed")
    def test_the_private_key_is_registered_for_redaction(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            identity_path, public_key = _generate_age_identity(Path(tmp))
            (infra_dir / "deploy-recipients.txt").write_text(public_key + "\n", encoding="utf-8")
            registered: list[str] = []

            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}
            env["STACKBASE_AGE_IDENTITY"] = str(identity_path)
            with mock.patch.dict(os.environ, env, clear=True):
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: _TEST_PRIVATE_KEY}, file=DEPLOY_FILE)

                with deploy_identity(infra_dir, emit=lambda _line: None, register_secret=registered.append):
                    pass

            self.assertIn(_TEST_PRIVATE_KEY, registered)

    def test_a_missing_age_identity_is_explained_in_deploys_own_terms(self) -> None:
        """A project WITH a deploy key, on a machine that cannot decrypt it, is
        a misconfiguration and is refused loudly -- but the refusal must name
        both ways out, not just say "age identity not found".
        """
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            (infra_dir / "deploy.age").write_bytes(b"encrypted-to-someone-else")

            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}
            env["STACKBASE_AGE_IDENTITY"] = str(Path(tmp) / "no-such-identity.txt")
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(StackError) as ctx:
                    with deploy_identity(infra_dir, emit=lambda _line: None):
                        self.fail("the guarded block must never run without an identity")

            text = f"{ctx.exception.message} {ctx.exception.hint}"
            self.assertIn("deploy.age", text)
            self.assertIn("STACKBASE_AGE_IDENTITY", text)
            self.assertIn("STACKBASE_SSH_IDENTITY", text)
            # Not the bare age wording load_secrets would have produced.
            self.assertNotIn("age identity", ctx.exception.message)

    @unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed")
    def test_a_wrong_but_existing_identity_still_reports_a_decrypt_failure(self) -> None:
        """The missing-identity check must not swallow `load_secrets`' other
        failures: decrypting with the WRONG identity is a different problem and
        keeps its own message.
        """
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            owner_dir = Path(tmp) / "owner"
            owner_dir.mkdir()
            stranger_dir = Path(tmp) / "stranger"
            stranger_dir.mkdir()
            owner_identity, owner_public_key = _generate_age_identity(owner_dir)
            stranger_identity, _stranger_public_key = _generate_age_identity(stranger_dir)
            (infra_dir / "deploy-recipients.txt").write_text(owner_public_key + "\n", encoding="utf-8")

            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}
            env["STACKBASE_AGE_IDENTITY"] = str(owner_identity)
            with mock.patch.dict(os.environ, env, clear=True):
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: _TEST_PRIVATE_KEY}, file=DEPLOY_FILE)

            env["STACKBASE_AGE_IDENTITY"] = str(stranger_identity)
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(StackError) as ctx:
                    with deploy_identity(infra_dir, emit=lambda _line: None):
                        self.fail("the guarded block must never run when the key cannot be decrypted")

            self.assertIn("failed to decrypt", ctx.exception.message)
            self.assertNotIn("STACKBASE_SSH_IDENTITY", f"{ctx.exception.message} {ctx.exception.hint}")


class DeployIdentityIsUsedByTheCommandsTests(unittest.TestCase):
    def test_run_status_opens_the_identity_around_the_ssh_calls(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = RunDeploySkipBuildTests()._project(Path(tmp))
            order: list[str] = []

            @contextlib.contextmanager
            def fake_identity(*_args, **_kwargs):
                order.append("enter")
                yield
                order.append("exit")

            with (
                mock.patch("stackbase.release.deploy_identity", fake_identity),
                mock.patch("stackbase.release.status_nodes", side_effect=lambda *a, **k: order.append("status")),
            ):
                run_status(infra_dir, emit=lambda _line: None)

            self.assertEqual(order, ["enter", "status", "exit"])


if __name__ == "__main__":
    unittest.main()
