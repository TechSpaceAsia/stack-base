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

import hashlib
import json
import os
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.config import Node, NodeState, StackConfig, StackState
from stackbase.errors import StackError
from stackbase.release import (
    Project,
    build,
    package,
    project_from_cargo_toml,
    release_worktree,
    rollback_nodes,
    run_deploy,
    ship,
    status_nodes,
    tag_commit_timestamp,
    validate_version_format,
    verify_version,
)
from stackbase.__main__ import main
from tests.fakes import FakePopen, FakeRunner

_SHA = "a" * 64
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
) -> Path:
    """A throwaway git repo with a committed Cargo.toml, optionally tagged."""
    repo_dir = root / "repo"
    repo_dir.mkdir()
    _run_git(repo_dir, "init", "-q")
    (repo_dir / "Cargo.toml").write_text(
        f'[package]\nname = "{package_name}"\nversion = "{cargo_version}"\nedition = "2021"\n',
        encoding="utf-8",
    )
    _run_git(repo_dir, "add", "Cargo.toml")
    _run_git(repo_dir, "commit", "-q", "-m", "initial")
    if tag:
        _run_git(repo_dir, "tag", tag)
    return repo_dir


def _cfg(roles: dict[str, str]) -> StackConfig:
    return StackConfig(
        project="acme",
        domain="acme.example.com",
        owner="matt",
        datacenter="kul",
        plan="KVM 1",
        price_item=None,
        auto_patch=True,
        admins=["matt"],
        nodes={name: Node(name=name, role=role, vps_id=1) for name, role in roles.items()},
        admin_keys={"matt": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAExample matt@laptop"},
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
        project = project_from_cargo_toml({"package": {"name": "stack-demo", "version": "1.0.0"}})
        self.assertEqual(project, Project(version="1.0.0", binary="stack_demo"))

    def test_explicit_bin_name_wins_over_the_package_name(self) -> None:
        data = {"package": {"name": "stack-demo", "version": "1.0.0"}, "bin": [{"name": "server"}]}
        self.assertEqual(project_from_cargo_toml(data).binary, "server")

    def test_missing_package_table_raises(self) -> None:
        with self.assertRaises(StackError):
            project_from_cargo_toml({})


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

            bundle_dir = build(worktree, project, popen=popen, emit=emitted.append)

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

            bundle_dir = build(worktree, project, popen=popen, emit=lambda _line: None)

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

            build(worktree, project, popen=popen, emit=lambda _line: None)

            argvs = [" ".join(call["argv"]) for call in popen.calls]
            self.assertIn("npm ci", argvs)
            self.assertIn("npm run build:css", argvs)

    def test_runs_tools_tailwindcss_when_no_package_json_script(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp), with_tailwind=True)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=0, output="tailwind ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            build(worktree, project, popen=popen, emit=lambda _line: None)

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
                build(worktree, project, popen=popen, emit=lambda _line: None)
            self.assertIn("rustup target add x86_64-unknown-linux-musl", ctx.exception.hint)

    def test_missing_musl_gcc_gets_a_specific_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=101, output="error: linker `musl-gcc` not found\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with self.assertRaises(StackError) as ctx:
                build(worktree, project, popen=popen, emit=lambda _line: None)
            self.assertIn("musl-tools", ctx.exception.hint)

    def test_missing_cargo_binary_names_rustup(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))

            def missing_popen(argv: list[str], **_kwargs: object) -> None:
                raise FileNotFoundError(argv[0])

            project = Project(version="1.0.0", binary="stack_demo")
            with self.assertRaises(StackError) as ctx:
                build(worktree, project, popen=missing_popen, emit=lambda _line: None)
            self.assertIn("rustup.rs", ctx.exception.hint)

    def test_binary_not_produced_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = Path(tmp) / "worktree"
            (worktree / "target" / "x86_64-unknown-linux-musl" / "release").mkdir(parents=True)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with self.assertRaises(StackError) as ctx:
                build(worktree, project, popen=popen, emit=lambda _line: None)
            self.assertIn("stack_demo", str(ctx.exception))

    def test_streams_cargo_output_line_by_line(self) -> None:
        with TemporaryDirectory() as tmp:
            worktree = _worktree(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="line1\nline2\n")
            emitted: list[str] = []
            project = Project(version="1.0.0", binary="stack_demo")

            build(worktree, project, popen=popen, emit=emitted.append)

            self.assertIn("line1", emitted)
            self.assertIn("line2", emitted)


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
            runner = FakeRunner()
            for _ in range(4):
                runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            for _ in range(2):
                runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)  idle=green (-)\n"))
            emitted: list[str] = []

            results = ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=emitted.append)

            self.assertEqual(results, {"b": "v1.0.0", "a": "v1.0.0"})
            hosts = [call["argv"][-2] for call in runner.calls[:4]]
            self.assertEqual(hosts, ["deploy@10.0.0.2", "deploy@10.0.0.2", "deploy@10.0.0.1", "deploy@10.0.0.1"])
            cmds = [call["argv"][-1] for call in runner.calls[:4]]
            self.assertEqual(cmds[0], f"upload v1.0.0 {_SHA}")
            self.assertEqual(cmds[1], "deploy v1.0.0")
            self.assertEqual(cmds[2], f"upload v1.0.0 {_SHA}")
            self.assertEqual(cmds[3], "deploy v1.0.0")

    def test_node_filter_restricts_to_one_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            runner = FakeRunner()
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)\n"))

            results = ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, node="b", runner=runner, emit=lambda _l: None)

            self.assertEqual(results, {"b": "v1.0.0"})
            self.assertEqual(len(runner.calls), 3)
            self.assertTrue(all(call["argv"][-2] == "deploy@10.0.0.2" for call in runner.calls))

    def test_unknown_node_raises_and_lists_known_names(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", Path("/nonexistent.tar.gz"), _SHA, node="nope", runner=FakeRunner())
            self.assertIn("known nodes", str(ctx.exception))

    def test_already_uploaded_release_continues_to_deploy(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            runner = FakeRunner()
            runner.script(_cp(returncode=1, stderr="✗ release v1.0.0 already exists at /opt/acme/releases/v1.0.0; pass --force to overwrite\n"))
            runner.script(_cp(returncode=0, stdout="✓ traffic switched to blue\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)\n"))
            emitted: list[str] = []

            results = ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=emitted.append)

            self.assertEqual(results, {"a": "v1.0.0"})
            self.assertTrue(any("already uploaded" in line for line in emitted))

    def test_upload_lock_held_raises_another_deploy_is_running(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            runner = FakeRunner()
            runner.script(_cp(returncode=3, stderr="✗ another deploy is already in progress (lock held)\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v0.9.0)\n"))  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=lambda _l: None)
            self.assertIn("another deploy is running on a", str(ctx.exception))

    def test_deploy_lock_held_raises_another_deploy_is_running(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            runner = FakeRunner()
            runner.script(_cp(returncode=0, stdout="✓ unpacked v1.0.0\n"))
            runner.script(_cp(returncode=3, stderr="✗ another deploy is already in progress (lock held)\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v0.9.0)\n"))  # summary colors call

            with self.assertRaises(StackError) as ctx:
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=lambda _l: None)
            self.assertIn("another deploy is running on a", str(ctx.exception))

    def test_first_failure_stops_further_nodes_and_summary_names_versions(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary", "b": "replica", "c": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2", "c": "10.0.0.3"})
            runner = FakeRunner()
            # order is b, c, a (replicas first) -- b fails at the deploy step.
            runner.script(_cp(returncode=0, stdout="✓ unpacked v1.0.0\n"))  # b upload
            runner.script(_cp(returncode=1, stderr="✗ blue failed the health check\n"))  # b deploy
            runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)  idle=green (-)\n"))  # summary b
            runner.script(_cp(returncode=0, stdout="active=blue (v0.9.0)  idle=green (-)\n"))  # summary c
            runner.script(_cp(returncode=0, stdout="active=blue (v0.9.0)  idle=green (-)\n"))  # summary a
            emitted: list[str] = []

            with self.assertRaises(StackError):
                ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=emitted.append)

            # c and a were never touched -- only b's upload+deploy ran before the failure.
            touched_hosts = {call["argv"][-2] for call in runner.calls[:2]}
            self.assertEqual(touched_hosts, {"deploy@10.0.0.2"})
            summary_text = "\n".join(emitted)
            self.assertIn("v1.0.0", summary_text)
            self.assertIn("v0.9.0", summary_text)

    def test_ssh_argv_uses_deploy_user_and_the_pinned_known_hosts(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            runner = FakeRunner()
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)\n"))

            ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=lambda _l: None)

            upload_call = runner.calls[0]
            self.assertIn("BatchMode=yes", upload_call["argv"])
            self.assertIn(f"UserKnownHostsFile={infra_dir / 'known_hosts'}", upload_call["argv"])
            self.assertEqual(upload_call["argv"][-2], "deploy@10.0.0.1")

    def test_tarball_is_streamed_as_stdin_not_buffered_via_input(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            tarball = self._tarball(tmp)
            cfg = _cfg({"a": "primary"})
            state = _state({"a": "10.0.0.1"})
            runner = FakeRunner()
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)\n"))

            ship(infra_dir, cfg, state, "v1.0.0", tarball, _SHA, runner=runner, emit=lambda _l: None)

            upload_kwargs = runner.calls[0]["kwargs"]
            self.assertIn("stdin", upload_kwargs)
            self.assertTrue(hasattr(upload_kwargs["stdin"], "read"))
            self.assertNotIn("input", upload_kwargs)


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

    def test_node_filter_restricts_to_one_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})
            popen = FakePopen()
            popen.script(returncode=0, output="✓ rollback complete\n")

            rollback_nodes(infra_dir, cfg, state, node="b", popen=popen, emit=lambda _l: None)

            self.assertEqual(len(popen.calls), 1)
            self.assertEqual(popen.calls[0]["argv"][-2], "deploy@10.0.0.2")

    def test_unknown_node_raises_and_lists_known_names(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            cfg = _cfg({"a": "primary", "b": "replica"})
            state = _state({"a": "10.0.0.1", "b": "10.0.0.2"})

            with self.assertRaises(StackError) as ctx:
                rollback_nodes(infra_dir, cfg, state, node="nope", popen=FakePopen(), emit=lambda _l: None)
            self.assertIn("known nodes", str(ctx.exception))

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

            runner = FakeRunner()
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="✓ ok\n"))
            runner.script(_cp(returncode=0, stdout="active=blue (v1.0.0)\n"))

            run_deploy(infra_dir, "v1.0.0", skip_build=True, tarball_path=str(tarball), runner=runner, emit=lambda _l: None)

            upload_cmd = runner.calls[0]["argv"][-1]
            self.assertEqual(upload_cmd, f"upload v1.0.0 {expected_sha}")

    def test_skip_build_never_touches_git(self) -> None:
        """No tag/Cargo.toml check when a prebuilt tarball is supplied -- see run_deploy's docstring."""
        with TemporaryDirectory() as tmp:
            infra_dir = self._project(Path(tmp))
            tarball = Path(tmp) / "prebuilt.tar.gz"
            tarball.write_bytes(b"bytes")

            def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
                if argv[0] == "git":
                    raise AssertionError("skip_build must never touch git")
                return _cp(returncode=0, stdout="✓ ok\n")

            run_deploy(infra_dir, "v1.0.0", skip_build=True, tarball_path=str(tarball), runner=runner, emit=lambda _l: None)


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


if __name__ == "__main__":
    unittest.main()
