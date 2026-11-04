"""Files in R2: the `STORAGE_*` block of the app's environment.

The bucket and its bucket-lock rule are ensured by `stackbase/r2.py`. This
module hands the app the bucket's address and its own credentials -- the
environment's `files_access_key_id` / `files_secret_access_key`, a token
scoped to the files bucket, never the backup or logs one -- plus the shared
`r2_endpoint`, rendered as plain `KEY=value` lines appended to the pushed
`app.env`.

They are deliberately NOT part of the `app_env` secret's digest (the
operator never wrote them there); `Local.files_env_sha` and
`NodeState.files_env_sha` track them separately, so rotating a files key
alone still re-pushes.
"""

from __future__ import annotations

import hashlib
import re

from stackbase.backups import checked_credential
from stackbase.config import Environment
from stackbase.errors import StackError
from stackbase.r2 import DEFAULT_FILES_LOCK_DAYS

# secrets keys the block needs, in the order they are reported when missing.
_FILES_KEYS = ("files_access_key_id", "files_secret_access_key", "r2_endpoint")

_STORAGE_LINE_RE = re.compile(r"^\s*(STORAGE_[A-Za-z0-9_]*)=")


def storage_env_lines(env: Environment, secrets: dict[str, str]) -> list[str]:
    """The `STORAGE_*` lines for `env`, or `[]` when it has no `[files]` bucket.

    Raises a StackError naming every missing secrets key when `[files]` is set
    but the credentials are incomplete (the app would start with no way to
    reach its bucket), and when `app_env` already sets a `STORAGE_*` variable
    (one owner per variable: which value won would depend on line order).
    """
    bucket = env.files.bucket
    if not bucket:
        return []
    where = "secrets.age" if env.implicit else f"secrets.{env.name}.age"
    env_flag = "" if env.implicit else f" --env {env.name}"

    missing = [key for key in _FILES_KEYS if not secrets.get(key)]
    if missing:
        raise StackError(
            f'[files] bucket = "{bucket}" is set but infra/{where} is missing {", ".join(missing)}, '
            "so the app could not reach its bucket",
            f"set {' and '.join(missing)} (`./infra/up{env_flag} secrets set <key>`; the access key pair "
            "is an R2 token scoped to the files bucket) and run `up` again",
        )

    for line in secrets.get("app_env", "").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _STORAGE_LINE_RE.match(line)
        if match:
            raise StackError(
                f"infra/{where}'s 'app_env' sets {match.group(1)}, which stack-base owns once "
                "[files] is configured",
                "remove every STORAGE_* line from app_env (stack-base writes them from [files] and the "
                "files_* secrets), or remove the [files] table to manage them yourself",
            )

    access_key = checked_credential("files_access_key_id", secrets["files_access_key_id"])
    secret_key = checked_credential("files_secret_access_key", secrets["files_secret_access_key"])
    endpoint = checked_credential("r2_endpoint", secrets["r2_endpoint"])
    return [
        f"STORAGE_BUCKET={bucket}",
        f"STORAGE_ENDPOINT={endpoint}",
        "STORAGE_REGION=auto",
        f"STORAGE_ACCESS_KEY_ID={access_key}",
        f"STORAGE_SECRET_ACCESS_KEY={secret_key}",
        f"STORAGE_LOCK_DAYS={env.files.lock_days or DEFAULT_FILES_LOCK_DAYS}",
    ]


def storage_env_block(lines: list[str]) -> str:
    """The lines as appended to app.env (empty when there are none)."""
    return "".join(f"{line}\n" for line in lines)


def files_env_digest(block: str) -> str:
    """sha256 hex digest of an already-rendered STORAGE_* block."""
    return hashlib.sha256(block.encode("utf-8")).hexdigest()
