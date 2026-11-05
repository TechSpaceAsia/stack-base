"""Failure email: the SMTP credentials file, laptop side, and `alert-test`.

The alerting runs entirely on the node (`nixos/alerts.nix`): a top-level
`service.d` drop-in gives every service `OnFailure=stackbase-alert@%N`, the
handler mails `[alerts] to` through nullmailer, and an hourly watchdog fails
-- and so mails -- when backups or log shipping go stale. This module renders
the one credentials file the node needs, `/var/lib/stackbase/alert.env`,
pushed by the ENSURE_ALERT_ENV step, decides whether alerts are on for an
environment, and drives `./infra/up alert-test`.

The SMTP settings are the environment's own `smtp_host`, `smtp_port`,
`smtp_user`, `smtp_password` and `smtp_from`. stack-base is public, so no
relay is baked in: a project names its own. The password never enters the
Nix store, which is world-readable; nullmailer's remotes file is rendered
from alert.env at service start into a 0600 runtime file.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from stackbase.config import AlertsConfig, Environment, load_config, load_state
from stackbase.errors import StackError
from stackbase.reconcile import SSH_USER
from stackbase.ssh import Ssh

ALERT_ENV_PATH = "/var/lib/stackbase/alert.env"

# The oneshot that renders nullmailer's remotes from alert.env. nullmailer
# is PartOf it, so restarting this one restarts both.
ALERT_REMOTES_UNIT = "stackbase-alert-remotes.service"

# Installed on the node by nixos/alerts.nix: fails a transient unit on
# purpose and waits for the handler to queue its email.
ALERT_TEST_COMMAND = "stackbase-alert-test"

# What each value may contain. An allowlist, as for backup.env: the values
# end up on one line of nullmailer's remotes file, where a space would start
# a new option, and nothing about an SMTP setting needs anything more.
# nixos/alerts.nix checks the same shapes again before rendering.
_CREDENTIAL = re.compile(r"^[A-Za-z0-9._:/+=@-]+$")
_CREDENTIAL_SHAPE = "letters, digits and any of . _ : / + = @ -"

# secrets keys -> alert.env variables, in the order written, each with its
# allowed shape and how to describe that shape in a refusal.
_ALERT_KEYS: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("smtp_host", "SMTP_HOST", re.compile(r"^[A-Za-z0-9.:-]+$"), "a host name: letters, digits, . : and -"),
    ("smtp_port", "SMTP_PORT", re.compile(r"^[0-9]{1,5}$"), "a port number from 1 to 65535"),
    ("smtp_user", "SMTP_USER", _CREDENTIAL, _CREDENTIAL_SHAPE),
    ("smtp_password", "SMTP_PASSWORD", _CREDENTIAL, _CREDENTIAL_SHAPE),
    (
        "smtp_from",
        "SMTP_FROM",
        re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$"),
        "one email address (letters, digits and . _ % + - around one @)",
    ),
)

ALERT_KEYS: tuple[str, ...] = tuple(key for key, _variable, _shape, _describe in _ALERT_KEYS)


def alerts_enabled(alerts: AlertsConfig) -> bool:
    """Alerts are on when the environment names at least one recipient."""
    return bool(alerts.to)


def _checked(key: str, value: str, shape: re.Pattern[str], describe: str) -> str:
    """`value` if it fits `shape`. A refusal names the KEY, never the value."""
    if "\n" in value or "\r" in value:
        raise StackError(
            f"the secret '{key}' contains a line break",
            f"SMTP settings are single-line values -- set it again with `./infra/up secrets set {key}`",
        )
    if not shape.match(value) or (key == "smtp_port" and not 1 <= int(value) <= 65535):
        raise StackError(
            f"the secret '{key}' contains whitespace, a character a shell would reinterpret, "
            "or is not the right shape",
            f"{key} must be {describe} -- set it again with `./infra/up secrets set {key}`, "
            "then run `up` again",
        )
    return value


def alert_env_content(secrets: dict[str, str]) -> str | None:
    """Render `/var/lib/stackbase/alert.env`, or `None` if any value is missing.

    All five or none, like `backup_env_content`: a half-filled file would
    let nullmailer start with a relay it can never log in to.
    """
    lines = []
    for key, variable, shape, describe in _ALERT_KEYS:
        value = secrets.get(key)
        if not value:
            return None
        lines.append(f"{variable}={_checked(key, value, shape, describe)}\n")
    return "".join(lines)


def alert_env_digest(content: str) -> str:
    """sha256 hex digest of an already-rendered alert.env."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _secrets_name(env: Environment) -> str:
    return "secrets.age" if env.implicit else f"secrets.{env.name}.age"


def _env_flag(env: Environment) -> str:
    return "" if env.implicit else f" --env {env.name}"


def check_alert_credentials(env: Environment, alert_env_sha: str | None) -> None:
    """Refuse when [alerts] names recipients but the SMTP settings are incomplete.

    A refusal, like logs: nullmailer's remotes are rendered from alert.env
    when it starts, so without the file the unit fails, and a unit that
    fails fails the whole `nixos-rebuild switch`. Under `--plan` too.
    """
    if not alerts_enabled(env.alerts) or alert_env_sha is not None:
        return
    keys = ", ".join(ALERT_KEYS)
    raise StackError(
        f"[alerts] sends to {', '.join(env.alerts.to)} but infra/{_secrets_name(env)} has no complete "
        "set of SMTP settings, so the servers could not send any mail",
        f"set all five of {keys} (`./infra/up{_env_flag(env)} secrets set <key>`; see the README's "
        '"Alerts" section) and run `up` again, or remove [alerts] to leave failure email off',
    )


def alerts_warning(env: Environment) -> str | None:
    """The one line `up` prints when nobody would be told about a failure.

    A warning, not a refusal (Brief F): a project mid-setup must still be
    able to run `up`. `None` when [alerts] names recipients.
    """
    if alerts_enabled(env.alerts):
        return None
    where = "[alerts] to" if env.implicit else f"[alerts] to (or [environments.{env.name}] alerts.to)"
    return (
        f"! no [alerts] in stack.toml{'' if env.implicit else f' for {env.name}'} -- nobody is emailed "
        f"when a service on these servers fails. Set {where} and the smtp_* secrets "
        '(see the README\'s "Alerts" section).'
    )


def run_alert_test(
    infra_dir: Path,
    *,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
    env: str | None = None,
) -> None:
    """Fail a throwaway unit on every node, so each one mails `[alerts] to`.

    The node-side `stackbase-alert-test` returns once the handler has
    queued the message with nullmailer, so "sent" here means "accepted for
    delivery": a relay that is down right now delivers it when it is back.
    """
    cfg = load_config(infra_dir)
    environment = cfg.env(env)
    state = load_state(infra_dir, environment)
    env_flag = _env_flag(environment)

    if not alerts_enabled(environment.alerts):
        raise StackError(
            "this environment has no [alerts] recipients, so there is nobody to send a test to",
            'add [alerts] to = ["ops@example.com"] to stack.toml, set the smtp_* secrets and run '
            f"`./infra/up{env_flag}` first",
        )

    for name in environment.nodes:
        node_state = state.nodes.get(name)
        if not (node_state and node_state.ipv4):
            raise StackError(
                f"stack-base does not know an address for node '{name}' yet",
                "run `up` first -- the address is recorded once the server is running",
            )

    for name in environment.nodes:
        ipv4 = state.nodes[name].ipv4
        ssh = Ssh(infra_dir, ipv4 or "", user=SSH_USER, runner=runner, popen=popen)
        emit(f"→ node {name}: failing a test unit on purpose")
        returncode, _tail = ssh.run_stream(ALERT_TEST_COMMAND, emit=emit, check=False)
        if returncode != 0:
            raise StackError(
                f"the test alert was not queued on node {name} (exit {returncode})",
                f"read the node's own log: ./infra/up{env_flag} ssh {name} -- "
                "journalctl -u 'stackbase-alert@*' -u nullmailer -n 50",
            )

    emit(f"sent — check {', '.join(environment.alerts.to)}")
