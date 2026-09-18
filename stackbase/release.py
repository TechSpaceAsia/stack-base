"""The laptop-side deploy caller: `deploy`, `rollback`, `status`.

The servers already run the whole engine (`nixos/deploy/stack-deploy.sh`,
Task 1/Plan 01) behind one restricted SSH door (`stack-deploy-ssh`, Task 2):
`upload <version> <sha256> | deploy <version> | rollback | status | colors |
releases`. This module is a thin caller on top of that door -- it builds a
release, packages it, and drives the door node by node. It holds no deploy
logic of its own: every actual decision (health checks, the blue/green swap,
retention, the lock) is the engine's.

Four stages:

- `verify_version` / `validate_version_format` -- the version string must be
  vMAJOR.MINOR.PATCH, the tag must exist, and the TAGGED commit's Cargo.toml
  (never the working tree) must carry that version.
- `release_worktree` / `build` -- check out the tag into a throwaway `git
  worktree`, build a static musl binary and the CSS bundle, mirroring
  platform-base's own CI recipe (`templates/project-files/.github/workflows/
  deploy.yml`), and assemble the on-server bundle layout.
- `package` -- write the bundle as a deterministic, engine-safe tarball
  (`nixos/deploy/stack-deploy.sh`'s `deploy_unpack_tarball` refuses absolute
  paths, `..` members, symlinks and non-regular members -- `package` never
  produces any of those in the first place).
- `ship` / `rollback_nodes` / `status_nodes` -- drive the SSH door, one node
  at a time, in the right order.

These commands need no API token and never decrypt `secrets.age`. They read
`stack.toml`, `stack.state.json` and `infra/known_hosts` -- plus, when the
project has one, `infra/deploy.age`, which needs the age identity. A
teammate whose only credential is an SSH key listed in
`stackbase.deploy.keys` still runs all three: they set
`$STACKBASE_SSH_IDENTITY`, or let their ssh-agent answer.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from stackbase.config import StackConfig, StackState, load_config, load_state
from stackbase.errors import StackError
from stackbase.ramdir import private_ram_dir
from stackbase.secrets import (
    DEPLOY_FILE,
    DEPLOY_KEY_NAME,
    _identity_path,
    load_secrets,
    register_private_key,
)
from stackbase.ssh import Ssh

# vMAJOR.MINOR.PATCH exactly -- no leading zeros, no pre-release/build
# suffix. The same grammar the SSH door validates server-side (Task 2's
# VERSION_RE/VERSION_GREP); checked here BEFORE any git or ssh call.
_VERSION_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

_DEPLOY_SSH_USER = "deploy"
_STREAM_TAIL_LINES = 20
_TAR_EXTENSIONS = ("static", "migrations", "config")

# NixOS ships the musl cross toolchain as `x86_64-unknown-linux-musl-gcc`,
# not as the `musl-gcc` wrapper cargo looks for by default on Debian-family
# distros -- so a `cargo build --target x86_64-unknown-linux-musl` there
# fails at link time with "linker `cc` not found" unless these two are
# set. This is exactly what obi's workflow does by hand.
MUSL_GCC = "x86_64-unknown-linux-musl-gcc"
MUSL_CC_ENV = "CC_x86_64_unknown_linux_musl"
MUSL_LINKER_ENV = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"

_MISSING_TOOL_HINTS: dict[str, str] = {
    "cargo": "install Rust: https://rustup.rs, then `rustup target add x86_64-unknown-linux-musl`",
    "npm": "install Node.js (npm ships with it): https://nodejs.org",
    "git": "install git",
    "ssh": "install openssh-client (e.g. `apt install openssh-client`, `brew install openssh`)",
}


# --------------------------------------------------------------------------
# Version verification
# --------------------------------------------------------------------------


def validate_version_format(version: str) -> None:
    """Reject anything that isn't exactly vMAJOR.MINOR.PATCH. No I/O.

    M3: `re.fullmatch`, not `.match` -- `$` alone still allows one trailing
    newline after the last real character (a Python `re` quirk: `$` matches
    at the end of the string OR just before a trailing "\\n"), so `.match()`
    would silently accept "v1.2.3\\n" as a valid version. `fullmatch`
    doesn't have that gap.
    """
    if not _VERSION_RE.fullmatch(version):
        raise StackError(
            f"invalid version '{version}'",
            "version must look like vMAJOR.MINOR.PATCH (e.g. v1.4.2) -- no leading zeros, "
            "no pre-release/build suffix",
        )


def verify_version(repo_dir: Path, version: str, *, runner: Any = subprocess.run) -> None:
    """The tag must exist, and the TAGGED commit's Cargo.toml must carry the same version.

    Checked in order: the version format itself (no subprocess at all), then
    that `refs/tags/<version>` exists, then that `git show
    <version>:Cargo.toml` parses and its `[package].version` matches. The
    working tree's own Cargo.toml is never consulted -- a dirty or
    out-of-sync working tree can't fool this, because the build itself later
    runs from a clean `git worktree add --detach` of the tag, not the working
    tree.
    """
    validate_version_format(version)

    tag_check = runner(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{version}"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if tag_check.returncode != 0:
        raise StackError(
            f"tag {version} does not exist",
            f"create it once Cargo.toml's version is right, then push it: "
            f"git tag {version} && git push origin {version}",
        )

    cargo_show = runner(
        ["git", "show", f"{version}:Cargo.toml"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if cargo_show.returncode != 0:
        raise StackError(
            f"tag {version} has no Cargo.toml at the repo root",
            f"check what {version} actually points at (git show {version} --stat) -- "
            "it must be a commit with a Cargo.toml at the repo root",
        )

    try:
        data = tomllib.loads(cargo_show.stdout or "")
    except tomllib.TOMLDecodeError as exc:
        raise StackError(f"Cargo.toml at tag {version} is not valid TOML", str(exc)) from exc

    package = data.get("package")
    cargo_version = package.get("version") if isinstance(package, dict) else None
    expected = version[1:]
    if cargo_version != expected:
        raise StackError(
            f"tag {version} does not match Cargo.toml's version at that tag ({cargo_version!r})",
            f'the commit tagged {version} must have [package].version = "{expected}" -- fix '
            f"Cargo.toml, commit it, then move the tag there: git tag -d {version} && "
            f"git tag {version} && git push --force origin {version} (only if this tag was never "
            "used for a real deploy)",
        )


def tag_commit_timestamp(repo_dir: Path, version: str, *, runner: Any = subprocess.run) -> int:
    """The tagged commit's author-date, as a unix timestamp -- the fixed mtime `package` embeds."""
    result = runner(
        ["git", "log", "-1", "--format=%ct", version],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout or "").strip()
    if result.returncode != 0 or not output:
        raise StackError(
            f"could not read the commit timestamp for tag {version}",
            "check that the tag exists and points at a real commit (git tag -l)",
        )
    try:
        return int(output)
    except ValueError as exc:
        raise StackError(
            f"git returned a non-numeric timestamp for tag {version}",
            "this looks like a bug in stack-base -- please report it",
        ) from exc


# --------------------------------------------------------------------------
# Build: checkout worktree, cargo + CSS, assemble the bundle
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Project:
    """What `build`/`package` need to know about the Rust project being released."""

    version: str
    binary: str


def read_project(worktree: Path, cfg: StackConfig) -> Project:
    """Read `[package].name`/`.version` (and an optional `[[bin]]` name) from the checked-out tag."""
    cargo_path = worktree / "Cargo.toml"
    if not cargo_path.is_file():
        raise StackError(f"{cargo_path} not found", "the checked-out tag has no Cargo.toml at its root")
    try:
        data = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise StackError(f"{cargo_path} is not valid TOML", str(exc)) from exc
    return project_from_cargo_toml(data, cfg)


def project_from_cargo_toml(data: dict[str, Any], cfg: StackConfig) -> Project:
    """Decide the release binary's name -- I6.

    `stack.toml`'s optional `[app].binary` always wins when set (the
    operator has already told the server about it too, via
    `templates/infra/flake.nix` mapping it into `stackbase.app.binary`).

    Otherwise, the binary name is derived from Cargo.toml exactly as before
    (an explicit single `[[bin]]` name, or the crate name with '-' -> '_'):
    several `[[bin]]` entries with no override is ambiguous and REQUIRES a
    choice rather than silently taking the first one, and a single derived
    name that does not match what the server would use by default
    (`stackbase.app.binary`'s own default, `project` slug with '-' -> '_')
    is refused BEFORE building -- deploying a binary under a name the
    server's systemd unit isn't looking for would just 502 forever.
    """
    package = data.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(
        package.get("version"), str
    ):
        raise StackError(
            "Cargo.toml is missing [package].name or [package].version",
            "add both to the crate's Cargo.toml",
        )
    name = package["name"]
    version = package["version"]

    if cfg.app.binary:
        return Project(version=version, binary=cfg.app.binary)

    candidates: list[str] = []
    bins = data.get("bin")
    if isinstance(bins, list) and bins:
        for entry in bins:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"]:
                candidates.append(entry["name"])

    if len(candidates) > 1:
        listed = ", ".join(candidates)
        raise StackError(
            "Cargo.toml declares several [[bin]] entries and stack.toml has no [app].binary",
            f'add [app] binary = "<name>" to stack.toml, choosing one of: {listed}',
        )

    binary = candidates[0] if candidates else name.replace("-", "_")
    expected = cfg.project.replace("-", "_")
    if binary != expected:
        raise StackError(
            f"the release binary '{binary}' does not match this server's default binary name '{expected}'",
            f'add [app] binary = "{binary}" to stack.toml and run ./infra/up first, then deploy',
        )

    return Project(version=version, binary=binary)


@contextlib.contextmanager
def release_worktree(repo_dir: Path, version: str, *, runner: Any = subprocess.run) -> Iterator[Path]:
    """Check out `version` into a throwaway `git worktree`, and always remove it afterwards.

    The build never runs against the working tree -- only against this clean,
    detached checkout of the tag -- so whatever the operator happens to have
    lying around uncommitted can never leak into a release. Removed in a
    `finally` (via `git worktree remove --force` + `git worktree prune`) even
    if the caller raises -- a failed build never leaves a stray worktree
    registered against the repo.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="stackbase-worktree-"))
    # `git worktree add` refuses to create INTO an already-existing
    # directory; hand it a path that doesn't exist yet, one level inside our
    # own throwaway tmp_dir, so `tmp_dir` itself is still ours to clean up
    # unconditionally afterwards.
    worktree_dir = tmp_dir / "src"
    try:
        result = runner(
            ["git", "worktree", "add", "--detach", str(worktree_dir), version],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise StackError(
                f"could not check out tag {version} into a worktree",
                _tail(result.stderr or "")
                or "check that the tag exists and that no other worktree already uses it",
            )
        yield worktree_dir
    finally:
        runner(
            ["git", "worktree", "remove", "--force", str(worktree_dir)],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        runner(
            ["git", "worktree", "prune"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        shutil.rmtree(tmp_dir, ignore_errors=True)


def cargo_target_dir(project_slug: str) -> Path | None:
    """The persistent cargo target directory for this project, or `None`.

    Every `deploy` builds in a FRESH `git worktree` (that is what makes a
    release reproducible), which means cargo starts from nothing every
    single time -- minutes of rebuilding dependencies that did not change.
    Pointing `CARGO_TARGET_DIR` at one stable per-project directory keeps
    the incremental cache across releases while the source tree stays
    clean and detached.

    `None` when the operator has already set `$CARGO_TARGET_DIR`: their
    choice wins, and `build` then leaves the variable exactly as it found
    it.

    `project_slug` ends up as a single path segment under the cache root, so
    it is checked the same way `package()`'s own `_validate_member_name`
    checks a tarball member name -- refusing an empty value, ".", "..", a
    path separator or a leading "-" (which a later shell/CLI invocation
    could otherwise read as an option) before it is ever used to build a
    path. In practice this can never fire via `run_deploy`: `project_slug`
    is `cfg.project`, already constrained to `[a-z][a-z0-9-]{1,30}` by
    config.py's `_PROJECT_RE` when `stack.toml` is loaded. This is a second,
    independent layer for `cargo_target_dir`'s own public contract -- it
    takes a bare string, not a validated `StackConfig`.
    """
    if os.environ.get("CARGO_TARGET_DIR"):
        return None
    if (
        not project_slug
        or project_slug in (".", "..")
        or "/" in project_slug
        or "\\" in project_slug
        or project_slug.startswith("-")
    ):
        raise StackError(
            f"invalid project slug for the build cache directory: {project_slug!r}",
            "this is a bug in stack-base -- please report it (project should already be validated "
            "when stack.toml is loaded)",
        )
    cache_home = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(cache_home) / "stack-base" / "target" / project_slug


def build(
    worktree: Path,
    project: Project,
    *,
    work_dir: Path,
    project_slug: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> Path:
    """Build the release bundle from an already-checked-out worktree.

    Mirrors platform-base's own CI recipe
    (`templates/project-files/.github/workflows/deploy.yml`): a static musl
    binary, then the Tailwind CSS build, bundled the same way the workflow
    does -- the binary at the top level, plus `static/`, `migrations/`,
    `config/` when present. Every subprocess is streamed to the terminal via
    `emit`, so a multi-minute cargo build doesn't look like a hang.

    `work_dir` is a PRIVATE, per-run directory the caller (`run_deploy`) owns
    and removes -- the bundle is created as a subdirectory of it
    (`work_dir/bundle`), never directly under the shared system temp root
    (Fix round 1, P2: the old `tempfile.mkdtemp(prefix="stackbase-bundle-")`
    here was never cleaned up, and `package()`'s own default output
    directory -- `bundle_dir.parent` -- landed the finished tarball straight
    in `/tmp` at a predictable, version-named path). Returns the bundle
    directory.
    """
    # Append to, never overwrite, an operator-set RUSTFLAGS (minor e, Fix
    # round 1) -- someone building on a machine that already needs its own
    # RUSTFLAGS (a linker override, a lint allow-list) would otherwise have
    # it silently discarded by this static-musl requirement.
    existing_rustflags = os.environ.get("RUSTFLAGS", "").strip()
    crt_static = "-C target-feature=+crt-static"
    rustflags = f"{existing_rustflags} {crt_static}" if existing_rustflags else crt_static
    env = {**os.environ, "RUSTFLAGS": rustflags}

    # Only when BOTH are unset: an operator who set one deliberately keeps
    # full control of the pair, rather than getting a half-overridden
    # toolchain that is harder to reason about than either choice alone.
    musl_gcc = shutil.which(MUSL_GCC)
    if musl_gcc and not env.get(MUSL_CC_ENV) and not env.get(MUSL_LINKER_ENV):
        env[MUSL_CC_ENV] = musl_gcc
        env[MUSL_LINKER_ENV] = musl_gcc
        emit(f"→ using {musl_gcc} as the musl C compiler and linker")

    # A persistent, per-project target directory (see `cargo_target_dir`).
    # Note the binary then lives THERE, not under the throwaway worktree --
    # which is also the bug this fixes for anyone who already had
    # $CARGO_TARGET_DIR set.
    if project_slug:
        target_dir = cargo_target_dir(project_slug)
        if target_dir is not None:
            target_dir.mkdir(parents=True, exist_ok=True)
            env["CARGO_TARGET_DIR"] = str(target_dir)
            emit(f"→ reusing the build cache at {target_dir}")

    emit("→ building the release binary (cargo build --release --target x86_64-unknown-linux-musl)")
    returncode, tail = _stream_local(
        ["cargo", "build", "--release", "--target", "x86_64-unknown-linux-musl"],
        cwd=worktree,
        env=env,
        popen=popen,
        emit=emit,
    )
    if returncode != 0:
        raise StackError(f"cargo build failed (exit {returncode})", _cargo_failure_hint(tail))

    _build_css(worktree, popen=popen, emit=emit)

    target_root = Path(env["CARGO_TARGET_DIR"]) if env.get("CARGO_TARGET_DIR") else worktree / "target"
    binary_path = target_root / "x86_64-unknown-linux-musl" / "release" / project.binary
    if not binary_path.is_file():
        raise StackError(
            f"cargo build succeeded but {binary_path} was not produced",
            f"check that [package].name (or a [[bin]] name) in Cargo.toml matches the expected "
            f"binary '{project.binary}'",
        )

    bundle_dir = work_dir / "bundle"
    bundle_dir.mkdir(parents=True)
    shutil.copy2(binary_path, bundle_dir / project.binary)
    (bundle_dir / project.binary).chmod(0o755)
    for extra in _TAR_EXTENSIONS:
        source = worktree / extra
        if source.is_dir():
            # symlinks=False: dereference any symlink in the source tree
            # rather than copying it as a symlink -- package() refuses
            # symlinks in the bundle outright (the server does too).
            shutil.copytree(source, bundle_dir / extra, symlinks=False)

    return bundle_dir


def _cargo_failure_hint(tail: list[str]) -> str:
    combined = "\n".join(tail)
    if "may not be installed" in combined or "error[E0463]" in combined:
        return "install the musl target: rustup target add x86_64-unknown-linux-musl"
    if "linker `cc` not found" in combined or "cannot find crt1.o" in combined:
        return (
            "no musl C compiler was found -- on NixOS put one on PATH "
            "(nix-shell -p pkgsCross.musl64.stdenv.cc), elsewhere install musl-tools "
            "(e.g. `apt install musl-tools`)"
        )
    if "musl-gcc" in combined:
        return "install musl-tools (e.g. `apt install musl-tools`) or the musl package for your distro"
    return _tail_hint(tail, "fix the build and re-run")


def _build_css(worktree: Path, *, popen: Any, emit: Callable[[str], None]) -> None:
    package_json = worktree / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        scripts = data.get("scripts")
        if isinstance(scripts, dict) and "build:css" in scripts:
            emit("→ building CSS (npm ci && npm run build:css)")
            returncode, tail = _stream_local(["npm", "ci"], cwd=worktree, popen=popen, emit=emit)
            if returncode != 0:
                raise StackError(f"npm ci failed (exit {returncode})", _tail_hint(tail, "fix package.json/package-lock.json and re-run"))
            returncode, tail = _stream_local(["npm", "run", "build:css"], cwd=worktree, popen=popen, emit=emit)
            if returncode != 0:
                raise StackError(f"npm run build:css failed (exit {returncode})", _tail_hint(tail, "fix the CSS build and re-run"))
            return

    # `tailwindcss` on PATH beats `tools/tailwindcss`: the downloaded
    # standalone binary is a patchelf-less glibc build that simply cannot
    # execute on NixOS, so a project that has both must use the one from
    # the environment.
    tailwind_on_path = shutil.which("tailwindcss")
    local_tailwind = worktree / "tools" / "tailwindcss"
    if tailwind_on_path:
        tailwind = tailwind_on_path
        label = "tailwindcss on PATH"
    elif local_tailwind.is_file():
        tailwind = str(local_tailwind)
        label = "tools/tailwindcss"
    else:
        emit(
            "! no CSS build step found (no package.json build:css script, no tailwindcss on PATH, "
            "no tools/tailwindcss) -- skipping"
        )
        return

    emit(f"→ building CSS ({label})")
    returncode, tail = _stream_local(
        [tailwind, "-i", "src/templates/input.css", "-o", "static/css/output.css", "--minify"],
        cwd=worktree,
        popen=popen,
        emit=emit,
    )
    if returncode != 0:
        raise StackError(
            f"the CSS build failed (exit {returncode})",
            _tail_hint(
                tail,
                f"stack-base used {tailwind} -- on NixOS, put tailwindcss on PATH "
                "(nix-shell -p tailwindcss); elsewhere ./tools/install-tailwindcss.sh downloads "
                "tools/tailwindcss",
            ),
        )


def _stream_local(
    argv: list[str],
    *,
    cwd: Path,
    popen: Any,
    emit: Callable[[str], None],
    env: dict[str, str] | None = None,
) -> tuple[int, list[str]]:
    """Run `argv` under `cwd`, echoing its output line by line as it arrives.

    Mirrors `steps.py`'s own `_stream` helper (same bufsize=1/stdin=DEVNULL/
    tail-deque shape), but that one is tied to a `reconcile.Context` and an
    `Ssh` -- this is the small local equivalent for a plain subprocess.
    """
    try:
        process = popen(
            argv,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            # A build can take minutes; without this, stray terminal input
            # in the meantime would be swallowed by the streamed process.
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except FileNotFoundError as exc:
        raise StackError(
            f"the '{argv[0]}' command was not found",
            _MISSING_TOOL_HINTS.get(argv[0], f"install {argv[0]}"),
        ) from exc

    tail: deque[str] = deque(maxlen=_STREAM_TAIL_LINES)
    with process:
        if process.stdout is not None:
            for line in process.stdout:
                line = line.rstrip("\n")
                emit(line)
                tail.append(line)
        returncode = process.wait()
    return returncode, list(tail)


# --------------------------------------------------------------------------
# Package: bundle -> deterministic, engine-safe tarball
# --------------------------------------------------------------------------


def package(
    bundle_dir: Path,
    version: str,
    mtime: int,
    *,
    binary_name: str,
    output_dir: Path | None = None,
) -> tuple[Path, str]:
    """Write `bundle_dir` into a deterministic, engine-safe tarball. Returns (path, sha256hex).

    Deterministic: members are visited in a fixed, sorted order and every
    member's uid/gid/uname/gname/mtime is normalised (mtime to the caller's
    `mtime`, e.g. the tag's commit timestamp -- never "now"), and the gzip
    wrapper itself is written with mtime=0 -- so packaging the same bundle
    twice produces byte-identical output, and therefore the same sha256.

    Engine-safe: refuses symlinks and non-regular members outright, and every
    member name is checked for an absolute path, a '..' segment or a
    backslash before being written -- `nixos/deploy/stack-deploy.sh`'s
    `deploy_unpack_tarball` refuses all of those server-side too; this
    refuses them before the tarball even exists.

    `output_dir`, when omitted, defaults to `bundle_dir.parent` -- a sibling
    of the bundle inside the caller's own private, per-run work dir (see
    `build`/`run_deploy`), never a bare fallback into the shared system temp
    root (Fix round 1, P2).
    """
    if output_dir is None:
        output_dir = bundle_dir.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    tar_path = output_dir / f"{version}.tar.gz"

    members = list(_bundle_members(bundle_dir))

    with tar_path.open("wb") as raw:
        # filename="": don't embed this temp path in the gzip header --
        # mtime=0: no timestamp either -- both are needed for byte-identical
        # output across two runs.
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            # format=PAX_FORMAT pinned explicitly (minor a, Fix round 1) --
            # it already matches tarfile's own DEFAULT_FORMAT today, but
            # pinning it means a future stdlib default change can never
            # silently change what byte-identical output means here. PAX
            # only emits an extended header block for a member whose
            # metadata doesn't fit the plain ustar fields (very long names,
            # huge sizes/uids); every member this function ever writes
            # (short ascii names, uid/gid forced to 0) fits, so no such
            # block is ever produced -- see PackageTests for the assertion.
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path, arcname in members:
                    _validate_member_name(arcname)
                    tarinfo = tar.gettarinfo(str(path), arcname=arcname)
                    tarinfo.uid = 0
                    tarinfo.gid = 0
                    tarinfo.uname = ""
                    tarinfo.gname = ""
                    tarinfo.mtime = mtime
                    if tarinfo.isdir():
                        tarinfo.mode = 0o755
                        tar.addfile(tarinfo)
                    else:
                        tarinfo.mode = 0o755 if arcname == binary_name else 0o644
                        with path.open("rb") as fh:
                            tar.addfile(tarinfo, fh)

    sha256 = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    return tar_path, sha256


def _bundle_members(bundle_dir: Path) -> Iterator[tuple[Path, str]]:
    """Every directory and regular file under `bundle_dir`, in a fixed sorted order.

    `followlinks=False`: a symlinked directory is never descended into.
    Every entry (directory or file) is checked with `is_symlink()` before
    being yielded, so a symlink is refused outright rather than silently
    resolved -- matching the server's own refusal.
    """
    for dirpath, dirnames, filenames in os.walk(bundle_dir, followlinks=False):
        dirnames.sort()
        filenames.sort()
        current = Path(dirpath)
        for name in dirnames:
            path = current / name
            if path.is_symlink():
                raise StackError(
                    f"bundle contains a symlink: {path}",
                    "remove it or replace it with a real directory before packaging",
                )
            yield path, path.relative_to(bundle_dir).as_posix()
        for name in filenames:
            path = current / name
            if path.is_symlink():
                raise StackError(
                    f"bundle contains a symlink: {path}",
                    "remove it or replace it with a real file before packaging",
                )
            if not path.is_file():
                raise StackError(
                    f"bundle contains a non-regular file: {path}",
                    "only regular files and directories may be packaged",
                )
            yield path, path.relative_to(bundle_dir).as_posix()


def _validate_member_name(name: str) -> None:
    if name.startswith("/"):
        raise StackError(f"tarball member has an absolute path: {name}", "this is a bug in stack-base -- please report it")
    if "\\" in name:
        raise StackError(f"tarball member name contains a backslash: {name}", "this is a bug in stack-base -- please report it")
    if any(part == ".." for part in name.split("/")):
        raise StackError(f"tarball member contains a '..' segment: {name}", "this is a bug in stack-base -- please report it")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# The SSH identity a deploy uses
# --------------------------------------------------------------------------

# Read by stackbase/ssh.py's own `_identity_options` -- setting it here
# makes every Ssh() built inside the `with` block offer exactly one key
# (`-i <path> -o IdentitiesOnly=yes`), which is also what keeps a
# multi-key ssh-agent from burning through the node's MaxAuthTries (I4).
_SSH_IDENTITY_ENV = "STACKBASE_SSH_IDENTITY"

_NO_PROJECT_KEY_WARNING = (
    "! no project deploy key found (infra/deploy.age) -- using whatever your ssh-agent offers; "
    "run `./infra/up deploy-key init` to create one"
)


@contextlib.contextmanager
def deploy_identity(
    infra_dir: Path,
    *,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> Iterator[None]:
    """Resolve which SSH key this deploy offers, in a fixed order.

    1. `$STACKBASE_SSH_IDENTITY` -- an explicit operator choice always wins,
       and nothing is decrypted.
    2. `infra/deploy.age` -- decrypted with the age identity
       (`$STACKBASE_AGE_IDENTITY`; on a build host a file identity, on a
       laptop usually a YubiKey) into a RAM-backed scratch file for the
       duration of this block, and pointed at by `$STACKBASE_SSH_IDENTITY`.
       The plaintext key NEVER exists outside `private_ram_dir()`, which is
       zeroed and removed on the way out -- success, failure or Ctrl-C.
    3. Neither -- fall through to whatever the operator's ssh-agent offers,
       with one warning line so a silent "Permission denied" later is not a
       mystery.

    Unlike everything else in this module, path 2 needs an age identity.
    That is deliberate (it is what lets a build host deploy with a key that
    unlocks nothing else); a teammate who only holds an SSH key still
    deploys via path 1 or 3. Path 3 is for a project with NO deploy key --
    once `deploy.age` exists, an operator who cannot decrypt it is refused
    rather than silently dropped back onto their ssh-agent.
    """
    if os.environ.get(_SSH_IDENTITY_ENV):
        yield
        return

    deploy_path = infra_dir / DEPLOY_FILE.name
    if not deploy_path.exists():
        emit(_NO_PROJECT_KEY_WARNING)
        yield
        return

    # A project that HAS a deploy key, on a machine that cannot decrypt it, is
    # a misconfiguration (the archetypal case: a build host whose file identity
    # is missing or wrong) -- it must fail loudly rather than quietly deploying
    # with whatever an ssh-agent happens to hold. `load_secrets` would say so
    # already, but in age's own terms ("age identity ... not found"), which
    # tells an operator halfway through a deploy neither what this has to do
    # with deploying nor that there is a way out that decrypts nothing.
    #
    # The check is done HERE rather than by catching `load_secrets`' StackError
    # and matching on its text: its other failures (a corrupt deploy.age, a
    # non-JSON payload, a decrypt against the wrong-but-present identity) are
    # genuinely different problems and must keep their own precise messages.
    # `_identity_path` is imported rather than re-derived so this pre-check can
    # never disagree with the resolution `load_secrets` itself performs.
    identity_path = _identity_path()
    if not identity_path.exists():
        raise StackError(
            f"this project has a deploy key ({deploy_path}) but this machine cannot decrypt it",
            f"the age identity {identity_path} does not exist -- either point "
            "$STACKBASE_AGE_IDENTITY at an identity listed in "
            f"infra/{DEPLOY_FILE.recipients_name}, or deploy without decrypting anything by "
            "pointing $STACKBASE_SSH_IDENTITY at an SSH private key whose public half is in "
            "stackbase.deploy.keys:\n"
            "STACKBASE_SSH_IDENTITY=<path to your SSH private key>\n"
            "./infra/up deploy <version>",
        )

    private_key = load_secrets(infra_dir, file=DEPLOY_FILE).get(DEPLOY_KEY_NAME)
    if not private_key:
        raise StackError(
            f"{deploy_path} has no '{DEPLOY_KEY_NAME}'",
            "re-create it with `./infra/up deploy-key init --rotate`",
        )
    register_private_key(private_key, register_secret)

    with private_ram_dir() as ramdir:
        key_path = ramdir / "deploy_key"
        # Created at 0600 atomically (O_CREAT|O_EXCL), never chmod'ed
        # afterwards: ssh refuses a group/world-readable private key, and a
        # window at a laxer mode is exactly what this avoids.
        fd = os.open(str(key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # ssh requires the trailing newline; ssh-keygen always writes
            # one, but a hand-edited deploy.age might not have it.
            handle.write(private_key if private_key.endswith("\n") else private_key + "\n")

        previous = os.environ.get(_SSH_IDENTITY_ENV)
        os.environ[_SSH_IDENTITY_ENV] = str(key_path)
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop(_SSH_IDENTITY_ENV, None)
            else:
                os.environ[_SSH_IDENTITY_ENV] = previous


# --------------------------------------------------------------------------
# Ship / rollback / status: drive the SSH door, node by node
# --------------------------------------------------------------------------


def _node_order(cfg: StackConfig, *, primary_first: bool) -> list[str]:
    """`cfg.nodes` in declaration order, split into primary/replicas and reordered.

    `ship` wants replicas first, primary last (a bad release is caught
    before the node serving traffic is touched); `rollback` wants the
    opposite (getting the traffic-serving node back is the priority).
    """
    primary_names = [name for name, node in cfg.nodes.items() if node.role == "primary"]
    replica_names = [name for name, node in cfg.nodes.items() if node.role != "primary"]
    if primary_first:
        return [*primary_names, *replica_names]
    return [*replica_names, *primary_names]


def _select_nodes(cfg: StackConfig, order: list[str], only: str | None) -> list[str]:
    if only is None:
        return order
    if only not in cfg.nodes:
        known = ", ".join(cfg.nodes) or "none"
        raise StackError(f"there is no node called '{only}' in stack.toml", f"known nodes: {known}")
    return [only]


def _emit_untouched_notice(cfg: StackConfig, only: str | None, emit: Callable[[str], None]) -> None:
    """With `--node`, tell the operator how many OTHER configured nodes this
    run never touched -- easy to miss otherwise, since a `--node`-filtered
    run's output looks identical in shape to an unfiltered one (minor c,
    Fix round 1).
    """
    if only is None:
        return
    other = len(cfg.nodes) - 1
    if other <= 0:
        return
    noun = "node" if other == 1 else "nodes"
    verb = "was" if other == 1 else "were"
    emit(f"i --node {only}: {other} other configured {noun} {verb} not touched")


def _node_ip(state: StackState, name: str) -> str:
    node_state = state.nodes.get(name)
    ip = node_state.ipv4 if node_state else None
    if not ip:
        raise StackError(
            f"stack-base does not know an address for node '{name}' yet",
            "run `up` first -- the address is recorded once the server is running",
        )
    return ip


def ship(
    infra_dir: Path,
    cfg: StackConfig,
    state: StackState,
    version: str,
    tarball: Path,
    sha256: str,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> dict[str, str]:
    """Upload and switch `version` on every selected node, replicas first, primary last.

    Per node: `upload <version> <sha256>` with the tarball streamed on
    stdin, then `deploy <version>`. Both go through `Ssh.run_stream` (the
    one streaming path to a node, `check=False`), so the door's own output
    (including an "already uploaded (same content)" info line) is echoed
    live via `emit` as it arrives -- there is nothing left here to
    re-print, and NO text is matched to decide what happens next (Fix
    round 1, P1): exit 0 always continues (whether the upload was fresh or
    the SAME content was already there), exit 3 means another deploy holds
    the node's lock, exit 4 means the version already exists on this node
    with DIFFERENT content (refused -- a published version must never
    change), and any other non-zero is a generic upload/deploy failure.
    Stops at the first failure and prints a summary of every selected
    node's current release (via `colors`) so the operator knows exactly
    what is live where.
    """
    order = _select_nodes(cfg, _node_order(cfg, primary_first=False), node)
    _emit_untouched_notice(cfg, node, emit)
    results: dict[str, str] = {}
    try:
        for name in order:
            ssh = Ssh(infra_dir, _node_ip(state, name), user=_DEPLOY_SSH_USER, runner=runner, popen=popen)

            emit(f"→ node {name}: uploading {version}")
            with tarball.open("rb") as fh:
                upload_rc, upload_tail = ssh.run_stream(
                    f"upload {version} {sha256}", stdin=fh, emit=emit, check=False
                )
            if upload_rc == 3:
                raise StackError(f"another deploy is running on {name}", "wait for it to finish, then re-run")
            if upload_rc == 4:
                raise StackError(
                    f"node {name} already has {version} with different content",
                    "a released version must never change -- create a new version (bump, tag) and deploy that",
                )
            if upload_rc != 0:
                raise StackError(
                    f"uploading {version} to node {name} failed (exit {upload_rc})",
                    _tail_hint(upload_tail, "fix the issue and re-run; nothing was switched on this node"),
                )

            emit(f"→ node {name}: switching traffic to {version}")
            deploy_rc, deploy_tail = ssh.run_stream(f"deploy {version}", emit=emit, check=False)
            if deploy_rc == 3:
                raise StackError(f"another deploy is running on {name}", "wait for it to finish, then re-run")
            if deploy_rc != 0:
                raise StackError(
                    f"deploying {version} to node {name} failed (exit {deploy_rc})",
                    _tail_hint(deploy_tail, "traffic on this node was not switched; fix the issue and re-run"),
                )
            results[name] = version
    finally:
        _print_summary(infra_dir, cfg, state, order, runner=runner, popen=popen, emit=emit)

    return results


def rollback_nodes(
    infra_dir: Path,
    cfg: StackConfig,
    state: StackState,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> None:
    """Run `rollback` on every selected node, primary first -- getting traffic back is the priority."""
    order = _select_nodes(cfg, _node_order(cfg, primary_first=True), node)
    _emit_untouched_notice(cfg, node, emit)
    for name in order:
        ssh = Ssh(infra_dir, _node_ip(state, name), user=_DEPLOY_SSH_USER, runner=runner, popen=popen)
        emit(f"→ node {name}: rollback")
        returncode, tail = ssh.run_stream("rollback", emit=emit, check=False)
        if returncode == 3:
            raise StackError(f"another deploy is running on {name}", "wait for it to finish, then re-run")
        if returncode != 0:
            raise StackError(
                f"rollback failed on node {name} (exit {returncode})",
                _tail_hint(tail, "fix the issue and re-run"),
            )


def status_nodes(
    infra_dir: Path,
    cfg: StackConfig,
    state: StackState,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> None:
    """Run `status` on every selected node, one ssh call each."""
    order = _select_nodes(cfg, _node_order(cfg, primary_first=True), node)
    _emit_untouched_notice(cfg, node, emit)
    for name in order:
        ssh = Ssh(infra_dir, _node_ip(state, name), user=_DEPLOY_SSH_USER, runner=runner, popen=popen)
        emit(f"node {name}:")
        returncode, tail = ssh.run_stream("status", emit=emit, check=False)
        if returncode != 0:
            raise StackError(
                f"status failed on node {name} (exit {returncode})",
                _tail_hint(tail, "check the output above"),
            )


def _print_summary(
    infra_dir: Path,
    cfg: StackConfig,
    state: StackState,
    nodes: list[str],
    *,
    runner: Any,
    popen: Any,
    emit: Callable[[str], None],
) -> None:
    """Print each selected node's current release (from `colors`), best-effort.

    Called whether `ship` succeeded or stopped at a failing node -- either
    way the operator needs to know exactly what is live on every node it
    touched, not just the one that failed. Goes through `Ssh.run_stream`
    like every other door call now (Fix round 1, P3) -- a host-key change
    surfaces the same reinstall-vs-interception hint here too, instead of a
    bare "could not read status".
    """
    emit("node status:")
    for name in nodes:
        try:
            ip = _node_ip(state, name)
        except StackError as exc:
            emit(f"  {name}: {exc}")
            continue
        try:
            ssh = Ssh(infra_dir, ip, user=_DEPLOY_SSH_USER, runner=runner, popen=popen)
            lines: list[str] = []
            returncode, _tail_lines = ssh.run_stream("colors", emit=lines.append, check=False)
        except StackError as exc:
            emit(f"  {name}: could not read status ({exc})")
            continue
        if returncode == 0:
            emit(f"  {name}: {' '.join(lines).strip()}")
        else:
            emit(f"  {name}: could not read status (exit {returncode})")


def _tail_hint(tail: list[str], advice: str) -> str:
    text = "\n".join(tail).strip()
    return f"{text}\n{advice}" if text else advice


def _tail(text: str, lines: int = 5) -> str:
    kept = [line for line in text.splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


# --------------------------------------------------------------------------
# Orchestration: what the CLI's `deploy`/`rollback`/`status` handlers call
# --------------------------------------------------------------------------


def run_deploy(
    infra_dir: Path,
    version: str,
    *,
    node: str | None = None,
    skip_build: bool = False,
    tarball_path: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> None:
    """`deploy <version>`: build (or reuse a prebuilt tarball), package, ship.

    Reads no API token and never decrypts `secrets.age`. The one secret this
    path can hold is the project's own SSH deploy key, resolved by
    `deploy_identity` around the ship phase only -- see its docstring.
    """
    if skip_build and not tarball_path:
        raise StackError("--skip-build requires --tarball PATH", "pass --tarball with the pre-built release archive")
    if tarball_path and not skip_build:
        raise StackError(
            "--tarball requires --skip-build",
            "pass --skip-build alongside --tarball, or drop --tarball to build from source",
        )

    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    repo_dir = infra_dir.parent

    if skip_build:
        # No private work dir is ever created on this path: the tarball is
        # the OPERATOR's own file (e.g. built by CI elsewhere), and it must
        # never be deleted or moved out from under them (Fix round 1, P2).
        validate_version_format(version)
        assert tarball_path is not None  # guarded above
        tarball = Path(tarball_path).expanduser()
        if not tarball.is_file():
            raise StackError(f"tarball not found: {tarball}", "check the --tarball path")
        sha256 = _sha256_file(tarball)
        with deploy_identity(infra_dir, emit=emit, register_secret=register_secret):
            ship(infra_dir, cfg, state, version, tarball, sha256, node=node, runner=runner, popen=popen, emit=emit)
        return

    # A private, per-run work dir (`tempfile.mkdtemp`'s own default mode,
    # 0700 -- readable/writable only by whoever is running this) holding
    # both the build's bundle directory and the packaged tarball. Removed
    # unconditionally in `finally` -- success, a build/ship failure, or
    # Ctrl-C -- so a release never leaves build artefacts (up to and
    # including the compiled binary) behind, and the tarball never lands at
    # a predictable, version-named path in the shared, world-writable /tmp
    # root (P2, Fix round 1).
    work_dir = Path(tempfile.mkdtemp(prefix="stackbase-release-"))
    try:
        verify_version(repo_dir, version, runner=runner)
        mtime = tag_commit_timestamp(repo_dir, version, runner=runner)
        with release_worktree(repo_dir, version, runner=runner) as worktree:
            project = read_project(worktree, cfg)
            bundle_dir = build(
                worktree,
                project,
                work_dir=work_dir,
                project_slug=cfg.project,
                runner=runner,
                popen=popen,
                emit=emit,
            )
            tarball, sha256 = package(bundle_dir, version, mtime, binary_name=project.binary)
        # Opened only now, not around the build: a cargo build can take many
        # minutes, and the decrypted key only needs to exist for the
        # upload/switch phase.
        with deploy_identity(infra_dir, emit=emit, register_secret=register_secret):
            ship(infra_dir, cfg, state, version, tarball, sha256, node=node, runner=runner, popen=popen, emit=emit)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_rollback(
    infra_dir: Path,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    with deploy_identity(infra_dir, emit=emit, register_secret=register_secret):
        rollback_nodes(infra_dir, cfg, state, node=node, runner=runner, popen=popen, emit=emit)


def run_status(
    infra_dir: Path,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    with deploy_identity(infra_dir, emit=emit, register_secret=register_secret):
        status_nodes(infra_dir, cfg, state, node=node, runner=runner, popen=popen, emit=emit)
