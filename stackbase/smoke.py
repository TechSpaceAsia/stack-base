"""`smoke`: prove a deployed release is really what an environment serves.

`./infra/up [--env <env>] smoke <version>` runs three checks, in order, and
stops at the first failure:

1. **Every node serves `version`.** The door's `status` command on each node
   names the active color's release; all of them must be `version`. This
   catches a `deploy` that stopped part-way, or a node someone rolled back.
2. **The public URL answers.** `https://<domain><health_path>` must return
   200, through the real front door (DNS, Cloudflare, TLS, nginx), without
   being redirected elsewhere. The deploy engine's own health check only
   ever asks the app over its local socket, so this is the first check that
   sees what a visitor sees. A fresh release can take a moment to show
   through the edge, so it is retried for a short while. A project with no
   public front door turns it off with `[app] smoke_public = false`.
3. **The project's own checks.** If `infra/smoke` exists, it must be
   executable, and it runs from the repository root with `SMOKE_BASE_URL`
   (`https://<domain>`), `SMOKE_VERSION` and `SMOKE_ENV` (the environment
   name, empty without environments) in its environment. Any non-zero exit
   fails the smoke test. This is where a project checks the pages and flows
   that matter to it.

The GitHub Actions template runs this after each deploy: production only
deploys once staging's smoke test has passed. A failure never rolls anything
back by itself; the hint names the rollback command.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from stackbase import __version__
from stackbase.config import Environment, StackState, load_config, load_state
from stackbase.errors import StackError
from stackbase.release import (
    _DEPLOY_SSH_USER,
    _node_ip,
    _node_order,
    _tail_hint,
    deploy_identity,
    validate_version_format,
)
from stackbase.secrets import deploy_file
from stackbase.ssh import Ssh

DEFAULT_HEALTH_PATH = "/health"
PROJECT_SCRIPT = "smoke"
PUBLIC_TRIES = 10
PUBLIC_DELAY_SECONDS = 3
PUBLIC_TIMEOUT_SECONDS = 10
SCRIPT_TIMEOUT_SECONDS = 600

# `status` prints "active=<color> (<version>)  idle=<color> (<version>)".
_ACTIVE_RE = re.compile(r"\bactive=\S+ \((?P<version>[^)\s]+)\)")


def _rollback_hint(env_name: str) -> str:
    env_flag = f" --env {env_name}" if env_name else ""
    return f"nothing was rolled back; to go back to the previous release: ./infra/up{env_flag} rollback"


def node_versions(
    infra_dir: Path,
    environment: Environment,
    state: StackState,
    *,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
) -> dict[str, str | None]:
    """Each node's active release, from the door's `status` (None if unreadable)."""
    found: dict[str, str | None] = {}
    for name in _node_order(environment.nodes, primary_first=True):
        ssh = Ssh(infra_dir, _node_ip(state, name), user=_DEPLOY_SSH_USER, runner=runner, popen=popen)
        lines: list[str] = []
        returncode, tail = ssh.run_stream("status", emit=lines.append, check=False)
        if returncode != 0:
            raise StackError(
                f"smoke: could not read the release on node {name} (exit {returncode})",
                _tail_hint(tail, "check the node with ./infra/up status"),
            )
        match = _ACTIVE_RE.search(" ".join(lines))
        found[name] = match.group("version") if match and match.group("version") != "-" else None
    return found


def check_public(
    url: str,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
    tries: int = PUBLIC_TRIES,
    delay: float = PUBLIC_DELAY_SECONDS,
) -> None:
    """GET `url` until it returns 200 at that same URL, or give up after `tries`."""
    last = "no response"
    for attempt in range(1, tries + 1):
        request = urllib.request.Request(url, headers={"User-Agent": f"stack-base-smoke/{__version__}"})
        try:
            with opener(request, timeout=PUBLIC_TIMEOUT_SECONDS) as response:
                status = response.status
                final_url = response.geturl()
            if status == 200 and final_url == url:
                return
            last = f"HTTP {status}" if final_url == url else f"redirected to {final_url}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            exc.close()
        except (urllib.error.URLError, OSError) as exc:
            last = str(getattr(exc, "reason", exc))
        if attempt < tries:
            sleep(delay)
    raise StackError(f"smoke: {url} did not answer 200 after {tries} tries (last: {last})", "")


def run_project_script(
    repo_dir: Path,
    script: Path,
    *,
    base_url: str,
    version: str,
    env_name: str,
    runner: Any = subprocess.run,
) -> None:
    """Run `infra/smoke` from the repository root; its output goes straight to the terminal."""
    if not os.access(script, os.X_OK):
        raise StackError(f"smoke: {script} is not executable", f"chmod +x {script} and commit it")
    child_env = dict(os.environ, SMOKE_BASE_URL=base_url, SMOKE_VERSION=version, SMOKE_ENV=env_name)
    try:
        result = runner([str(script)], cwd=repo_dir, env=child_env, check=False, timeout=SCRIPT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise StackError(f"smoke: {script} ran longer than {SCRIPT_TIMEOUT_SECONDS}s", "") from None
    if result.returncode != 0:
        raise StackError(f"smoke: {script} failed (exit {result.returncode})", "")


def run_smoke(
    infra_dir: Path,
    version: str,
    *,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
    env: str | None = None,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    validate_version_format(version)
    cfg = load_config(infra_dir)
    environment = cfg.env(env)
    state = load_state(infra_dir, environment)
    rollback = _rollback_hint(environment.name)
    where = f" ({environment.name})" if environment.name else ""

    try:
        with deploy_identity(infra_dir, emit=emit, register_secret=register_secret, file=deploy_file(environment)):
            versions = node_versions(infra_dir, environment, state, runner=runner, popen=popen)
        wrong = {name: found for name, found in versions.items() if found != version}
        if wrong:
            detail = ", ".join(f"{name} serves {found or 'nothing'}" for name, found in sorted(wrong.items()))
            raise StackError(f"smoke: not every node serves {version}: {detail}", "")
        emit(f"✓ every node serves {version}: {', '.join(versions)}")

        base_url = f"https://{environment.domain}"
        if cfg.app.smoke_public is False:
            emit("! [app] smoke_public = false: skipping the public URL check")
        else:
            url = base_url + (cfg.app.health_path or DEFAULT_HEALTH_PATH)
            check_public(url, opener=opener, sleep=sleep)
            emit(f"✓ {url} answers 200")

        script = infra_dir / PROJECT_SCRIPT
        if script.exists():
            emit(f"running {script.relative_to(infra_dir.parent)}")
            run_project_script(
                infra_dir.parent, script, base_url=base_url, version=version, env_name=environment.name, runner=runner
            )
            emit(f"✓ {script.relative_to(infra_dir.parent)} passed")
    except StackError as exc:
        hint = f"{exc.hint}\n{rollback}" if exc.hint else rollback
        raise StackError(exc.message, hint) from None
    emit(f"✓ smoke test passed{where}: {version}")
