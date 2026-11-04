"""Logs off-box: Vector's R2 credentials, laptop side.

The shipping runs entirely on the node (`nixos/logs.nix`: journald ->
Vector -> R2, with a disk buffer and end-to-end acknowledgements). This
module renders the one credentials file Vector needs,
`/var/lib/stackbase/logs.env`, pushed by the ENSURE_LOGS_ENV step, and
decides whether logs are on for an environment at all.

The credentials are the environment's own `logs_access_key_id` and
`logs_secret_access_key` -- a token scoped to the logs bucket, never the
backup one -- plus the shared `r2_endpoint`. They are rendered as the
variables Vector's AWS credential chain and its config interpolation read
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `LOGS_ENDPOINT`), so no key
ever enters the Nix store, which is world-readable.
"""

from __future__ import annotations

import hashlib

from stackbase.backups import checked_credential
from stackbase.config import Environment, LogsConfig
from stackbase.errors import StackError

LOGS_ENV_PATH = "/var/lib/stackbase/logs.env"

LOGS_UNIT = "vector.service"

# secrets keys -> the variables nixos/logs.nix's Vector reads, in the order
# they are written. Values are held to the same allowlist as backup.env's
# (`stackbase.backups.checked_credential`).
_LOGS_KEYS: tuple[tuple[str, str], ...] = (
    ("logs_access_key_id", "AWS_ACCESS_KEY_ID"),
    ("logs_secret_access_key", "AWS_SECRET_ACCESS_KEY"),
    ("r2_endpoint", "LOGS_ENDPOINT"),
)


def logs_enabled(logs: LogsConfig) -> bool:
    """Logs ship when the environment names a bucket and has not opted out.

    stackbase/config.py already refused a [logs] table with no bucket, so
    "no bucket" here can only mean "no [logs] table at all" -- which keeps
    such a project exactly as it was before logs existed.
    """
    return bool(logs.bucket) and logs.enabled is not False


def logs_env_content(secrets: dict[str, str]) -> str | None:
    """Render `/var/lib/stackbase/logs.env`, or `None` if any value is missing.

    All three or none, like `backup_env_content`. Each value must pass the
    shared credentials allowlist; a refusal names the KEY, never the value.
    """
    values = []
    for key, _variable in _LOGS_KEYS:
        value = secrets.get(key)
        if not value:
            return None
        values.append(checked_credential(key, value))
    return "".join(f"{variable}={value}\n" for (_key, variable), value in zip(_LOGS_KEYS, values))


def logs_env_digest(content: str) -> str:
    """sha256 hex digest of an already-rendered logs.env."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def check_logs_credentials(env: Environment, logs_env_sha: str | None) -> None:
    """Refuse when logs are on but the credentials are incomplete.

    A refusal, not a warning like `check_backup_credentials`: Vector's
    config reads `${LOGS_ENDPOINT}`, so without logs.env the unit cannot
    start, and a unit that fails to start fails the whole `nixos-rebuild
    switch` -- the server would be left half-deployed. Under `--plan` too:
    it is a statement about the configuration.
    """
    if not logs_enabled(env.logs) or logs_env_sha is not None:
        return
    keys = ", ".join(key for key, _variable in _LOGS_KEYS)
    where = "secrets.age" if env.implicit else f"secrets.{env.name}.age"
    env_flag = "" if env.implicit else f" --env {env.name}"
    raise StackError(
        f'[logs] bucket = "{env.logs.bucket}" is set but infra/{where} has no complete set of logs '
        "credentials, so Vector could not start on the servers",
        f"set all three of {keys} (`./infra/up{env_flag} secrets set <key>`; the access key pair is an "
        "R2 token scoped to the logs bucket) and run `up` again, or set `enabled = false` in [logs] "
        "to leave logs off",
    )
