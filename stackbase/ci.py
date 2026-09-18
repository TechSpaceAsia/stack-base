"""`ci-setup`: push the project's ONE deploy key into GitHub Actions.

Every project already has one restricted SSH door
(`nixos/deploy/stack-deploy-ssh.sh`, Task 2): a fixed set of `deploy` user
accounts, each pinned via `restrict,command=...` to exactly six words
(`upload`/`deploy`/`rollback`/`status`/`colors`/`releases`). There is exactly
ONE project deploy key (Task 2) -- `infra/deploy.age`, created by
`./infra/up deploy-key init` -- used by you, by a build host, and by GitHub
Actions (`templates/github/deploy-stack.yml`) alike. `ci-setup` no longer
mints a separate key of its own; its whole job is to push whatever
`deploy.age` holds into a **repo-level** GitHub Actions secret
(`STACK_DEPLOY_KEY`), creating the key first via `deploy_key_init` if this
project does not have one yet.

The private key is never written to this project's own disk unencrypted,
never committed, and never logged -- it travels from `deploy.age` straight
into `gh secret set`'s stdin. Repo-level, not organization-level: the
owner's GitHub plan has no org-level secrets/variables, so a repo secret is
not a simplification here, it's the only option. A leaked CI key can only
ever reach the same six door commands as any other `stackbase.deploy.keys`
entry -- see the README.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from stackbase.errors import StackError
from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, load_secrets, register_private_key
from stackbase.secrets_cli import DEPLOY_PUB_FILENAME, deploy_key_init

SECRET_NAME = "STACK_DEPLOY_KEY"

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


def ci_setup(
    infra_dir: Path,
    *,
    rotate: bool = False,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> None:
    """Push the project's deploy key into the repo-level GitHub Actions secret.

    There is ONE project deploy key (`infra/deploy.age`, public half
    `infra/keys/deploy.pub`), used by CI and by humans alike -- ci-setup no
    longer mints a separate one. Absent, it is created here by
    `deploy_key_init`; `--rotate` forwards to `deploy_key_init(rotate=True)`,
    which replaces both halves.

    Repo-level, not organization-level: the owner's GitHub plan has no
    org-level secrets/variables, so a repo secret is not a simplification
    here, it's the only option. A leaked key can only ever reach the same
    six door commands as any other `stackbase.deploy.keys` entry -- see the
    README.

    Everything that can fail cheaply (repo detection, `gh` auth) runs BEFORE
    a key is generated. The private key is registered for redaction before
    the one call that could conceivably echo it back.
    """
    deploy_path = infra_dir / DEPLOY_FILE.name

    repo_dir = infra_dir.parent
    owner, repo = parse_github_repo(_origin_url(repo_dir, runner=runner))
    repo_slug = f"{owner}/{repo}"

    _require_gh(runner=runner)

    if rotate or not deploy_path.exists():
        deploy_key_init(infra_dir, rotate=rotate, runner=runner, emit=emit, register_secret=register_secret)

    private_key = load_secrets(infra_dir, file=DEPLOY_FILE).get(DEPLOY_KEY_NAME)
    if not private_key:
        raise StackError(
            f"{deploy_path} has no '{DEPLOY_KEY_NAME}'",
            "re-create it with `./infra/up deploy-key init --rotate`",
        )
    register_private_key(private_key, register_secret)

    # The private key travels ONLY as this subprocess call's stdin
    # (`input=`) -- never as an argv element, never as an environment
    # variable, never written anywhere on this machine's disk.
    secret_set = runner(
        ["gh", "secret", "set", SECRET_NAME, "--repo", repo_slug],
        input=private_key.encode("utf-8"),
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

    pub_path = infra_dir / "keys" / DEPLOY_PUB_FILENAME
    emit(f"{SECRET_NAME} on {repo_slug} now holds this project's deploy key.")
    emit("Next steps:")
    emit(f"  1. git add {deploy_path} {pub_path} && git commit -m 'ci: the project deploy key'")
    emit("  2. ./infra/up                 # installs the key on every server")
    emit(f"  3. mkdir -p .github/workflows && cp {_WORKFLOW_TEMPLATE} .github/workflows/deploy-stack.yml")
    emit("     git add .github/workflows/deploy-stack.yml && git commit -m 'ci: add the deploy workflow'")
    if rotate:
        # The GitHub secret was already replaced above, immediately -- not
        # step 2. Until step 1 is committed AND step 2 has installed the new
        # public half on every server, CI deploys fail outright (the runner
        # now offers the NEW private key; every server still only trusts the
        # OLD public one).
        emit("  CI deploys will FAIL (wrong key) until steps 1 and 2 above have both completed --")
        emit("  the GitHub secret was already replaced, just now.")
    emit("To turn CI deploys back off:")
    emit(f"  gh secret delete {SECRET_NAME} --repo {repo_slug}")
    emit("  (leave deploy.age and keys/deploy.pub in place -- they are also your own deploy key)")
