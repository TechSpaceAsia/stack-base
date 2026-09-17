"""`ci-setup`: provision an optional per-project GitHub Actions deploy key.

Every project already has one restricted SSH door
(`nixos/deploy/stack-deploy-ssh.sh`, Task 2): a fixed set of `deploy` user
accounts, each pinned via `restrict,command=...` to exactly six words
(`upload`/`deploy`/`rollback`/`status`/`colors`/`releases`). `ci-setup` adds
one more entry to that same door -- `ci-deploy` -- so GitHub Actions
(`templates/github/deploy-stack.yml`) can drive it too.

The private half of that key is generated once, on the operator's own
machine, held only in RAM (`stackbase.ramdir.private_ram_dir`), and piped
straight into a **repo-level** GitHub Actions secret (`STACK_DEPLOY_KEY`).
It is never written to this project's own disk, never committed, and never
logged. Repo-level, not organization-level: the owner's GitHub plan has no
org-level secrets/variables, so a repo secret is not a simplification here,
it's the only option. A leaked CI key can only ever reach the same six
door commands as any other `stackbase.deploy.keys` entry -- see the README.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from stackbase.config import load_config
from stackbase.errors import StackError
from stackbase.ramdir import private_ram_dir

SECRET_NAME = "STACK_DEPLOY_KEY"
PUB_KEY_FILENAME = "ci-deploy.pub"

_HTTPS_RE = re.compile(r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")
_SCP_RE = re.compile(r"^git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$")
_SSH_URL_RE = re.compile(r"^ssh://git@github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")

_MISSING_GH_HINT = "install the GitHub CLI (https://cli.github.com), then run `gh auth login`"
_WORKFLOW_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "github" / "deploy-stack.yml"


def parse_github_repo(remote_url: str) -> tuple[str, str]:
    """`(owner, repo)` out of an `origin` remote URL -- https, `git@`, or `ssh://` github.com only.

    Anything else (a different host, a malformed URL) raises -- ci-setup
    never guesses.
    """
    url = remote_url.strip()
    for pattern in (_HTTPS_RE, _SCP_RE, _SSH_URL_RE):
        match = pattern.match(url)
        if match:
            return match.group("owner"), match.group("repo")
    raise StackError(
        f"origin remote '{remote_url}' is not a github.com repository",
        "ci-setup only works against a github.com origin -- check `git remote get-url origin`",
    )


def _origin_url(repo_dir: Path, *, runner: Any) -> str:
    try:
        result = runner(
            ["git", "remote", "get-url", "origin"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise StackError("the 'git' command was not found", "install git") from exc
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise StackError(
            "could not read the git remote 'origin'",
            stderr or "run this from a git checkout with an 'origin' remote pointing at GitHub",
        )
    url = (result.stdout or "").strip()
    if not url:
        raise StackError(
            "the git remote 'origin' has no URL",
            "set one: git remote add origin git@github.com:<owner>/<repo>.git",
        )
    return url


def _require_gh(*, runner: Any) -> None:
    try:
        result = runner(["gh", "auth", "status"], capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise StackError("the 'gh' command was not found", _MISSING_GH_HINT) from exc
    if result.returncode != 0:
        raise StackError("gh is not authenticated", "run `gh auth login`, then re-run ci-setup")


def _write_pub_key_atomically(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp"
    tmp.write_text(content, encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(path)


def ci_setup(
    infra_dir: Path,
    *,
    rotate: bool = False,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
) -> None:
    """Generate (or, with `rotate=True`, replace) the CI deploy key.

    Refuses outright if `infra/keys/ci-deploy.pub` already exists and
    `rotate` is false -- ci-setup never silently overwrites a live key.
    Every check that can fail cheaply (repo detection, `gh` auth, an
    existing key) runs BEFORE `ssh-keygen` is ever invoked.
    """
    cfg = load_config(infra_dir)
    pub_path = infra_dir / "keys" / PUB_KEY_FILENAME
    if pub_path.exists() and not rotate:
        raise StackError(
            f"{pub_path} already exists",
            "pass --rotate to replace it -- the old key keeps working on the servers until you "
            "commit the new one and run ./infra/up",
        )

    repo_dir = infra_dir.parent
    owner, repo = parse_github_repo(_origin_url(repo_dir, runner=runner))
    repo_slug = f"{owner}/{repo}"

    _require_gh(runner=runner)

    with private_ram_dir() as ramdir:
        key_path = ramdir / "key"
        keygen = runner(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"ci-deploy@{cfg.project}",
                "-f",
                str(key_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if keygen.returncode != 0:
            stderr = (keygen.stderr or "").strip()
            raise StackError(
                "ssh-keygen failed while generating the CI deploy key",
                stderr or "check that ssh-keygen is installed",
            )

        pub_key_path = ramdir / "key.pub"
        if not key_path.is_file() or not pub_key_path.is_file():
            raise StackError(
                "ssh-keygen did not produce both key files",
                "this is a bug in stack-base -- please report it",
            )

        public_key = pub_key_path.read_text(encoding="utf-8").strip() + "\n"
        private_key_bytes = key_path.read_bytes()

        # The private key travels ONLY as this subprocess call's stdin
        # (`input=`) -- never as an argv element, never as an environment
        # variable, never written anywhere outside `ramdir` (which is wiped
        # unconditionally when this `with` block exits, success or not).
        secret_set = runner(
            ["gh", "secret", "set", SECRET_NAME, "--repo", repo_slug],
            input=private_key_bytes,
            capture_output=True,
            check=False,
        )
        if secret_set.returncode != 0:
            stderr = secret_set.stderr
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise StackError(
                f"gh secret set {SECRET_NAME} failed",
                (stderr or "").strip() or "check `gh auth status` and that you can push secrets to this repository",
            )

    # `ramdir` (and the private key it held) no longer exists past this
    # point -- everything below only ever handles the PUBLIC key.

    verify = runner(
        ["gh", "secret", "list", "--repo", repo_slug, "--json", "name", "-q", ".[].name"],
        capture_output=True,
        text=True,
        check=False,
    )
    names = [line.strip() for line in (verify.stdout or "").splitlines() if line.strip()]
    if verify.returncode != 0 or SECRET_NAME not in names:
        raise StackError(
            f"could not confirm {SECRET_NAME} exists on {repo_slug} after setting it",
            f"run `gh secret list --repo {repo_slug}` yourself to check",
        )

    _write_pub_key_atomically(pub_path, public_key)

    action = "rotated" if rotate else "created"
    emit(f"CI deploy key {action} for {repo_slug}.")
    emit("Next steps:")
    emit(f"  1. git add {pub_path} && git commit -m 'ci: {action} the CI deploy key'")
    emit("  2. ./infra/up                 # installs the key on every server")
    emit(f"  3. mkdir -p .github/workflows && cp {_WORKFLOW_TEMPLATE} .github/workflows/deploy-stack.yml")
    emit("     git add .github/workflows/deploy-stack.yml && git commit -m 'ci: add the deploy workflow'")
    if rotate:
        emit(f"  The OLD key keeps working until step 2 (./infra/up) above has actually run.")
    emit("To turn CI deploys back off:")
    emit(f"  rm {pub_path} && ./infra/up && gh secret delete {SECRET_NAME} --repo {repo_slug}")
