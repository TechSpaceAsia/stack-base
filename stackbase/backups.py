"""Off-box backups: the node's rclone credentials, and `backup-now`.

The backup itself runs entirely on the node (`nixos/backups.nix`:
`pg_dump`/`tar` -> `zstd` -> `age` -> `rclone`, on a timer). This module is
the laptop side of it: it renders the one credentials file the node needs
(`/var/lib/stackbase/backup.env`, pushed by the ENSURE_BACKUP_ENV step) and
drives an on-demand run over SSH.

The credentials come from `secrets.age`'s `r2_access_key_id`,
`r2_secret_access_key` and `r2_endpoint`, and are rendered in rclone's
env-config form -- `RCLONE_CONFIG_<REMOTE>_<SETTING>` -- so the remote
named "backup" exists without any rclone.conf, and nothing sensitive is
ever in the Nix store or in a unit file.

Unlike `release.py`, this talks to the node as `root` through stack-base's
own SSH path, not through the restricted `deploy` door: starting a systemd
unit is not one of that door's six words, and never should be.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from stackbase.config import load_config, load_state
from stackbase.errors import StackError
from stackbase.reconcile import SSH_USER
from stackbase.ssh import Ssh

BACKUP_ENV_PATH = "/var/lib/stackbase/backup.env"

BACKUP_UNIT = "stackbase-backup.service"

# The command nixos/backups.nix installs alongside the unit -- lists what
# actually landed in the bucket, using the same credentials file.
BACKUP_LS_COMMAND = "stackbase-backup-ls"

# secrets.age keys -> rclone env-config variables, in the order they are
# written. The remote is literally called "backup", which is what
# nixos/backups.nix's own `backup:<bucket>/...` paths refer to.
_R2_KEYS: tuple[tuple[str, str], ...] = (
    ("r2_access_key_id", "RCLONE_CONFIG_BACKUP_ACCESS_KEY_ID"),
    ("r2_secret_access_key", "RCLONE_CONFIG_BACKUP_SECRET_ACCESS_KEY"),
    ("r2_endpoint", "RCLONE_CONFIG_BACKUP_ENDPOINT"),
)

# What a credential VALUE is allowed to contain. An allowlist, not a list of
# banned metacharacters: the file is read two ways on the node, and only one
# of them is a parser.
#
#   - the unit reads it with systemd's `EnvironmentFile`, which does no
#     substitution at all -- safe either way;
#   - `stackbase-backup-ls` (the `./infra/up backup-now` path) has to get the
#     same variables into its own environment, and any shell-level way of
#     doing that (`source`, `. file`, `eval`) evaluates the line. A value of
#     `a$(id)`, `a;id` or `` a`id` `` would then RUN as root.
#
# nixos/backups.nix now parses the file without a shell (see its
# `stackbase-backup-ls`), so this is the second of two layers rather than the
# only one -- but a guard that depends on a shell script elsewhere staying
# written a particular way is not a guard. Banning a handful of characters
# would also be a game of whack-a-mole (`$`, backtick, quote, backslash,
# `;`, `&`, `|`, `<`, `>`, `(`, `)`, `#`, glob characters, ...); an allowlist
# is finite and auditable.
#
# The set is what a real S3/R2 credential is actually made of: an access key
# id and secret are base64/hex (`+`, `/`, `=` appear in AWS-style secrets),
# and the endpoint is an https URL. None of them ever contains whitespace or
# a shell metacharacter.
_VALUE_RE = re.compile(r"^[A-Za-z0-9._:/+=@-]+$")

_VALUE_SHAPE = "letters, digits and any of . _ : / + = @ -"


def backup_env_content(secrets: dict[str, str]) -> str | None:
    """Render `/var/lib/stackbase/backup.env`, or `None` if R2 isn't configured.

    All three values or none: a half-filled credentials file would let the
    unit start and fail every night. Absent, no step is planned and nothing
    on the node is removed -- same contract as `app_env`.

    Every value is held to `_VALUE_RE`. A line break would smuggle an extra
    `KEY=value` line into a root-owned EnvironmentFile; anything else outside
    the allowlist (whitespace, `$`, a backtick, a quote, a backslash, `;`,
    ...) would be re-interpreted by any shell that ever evaluated the file.
    Both are refused, naming the KEY and the allowed SHAPE -- never any part
    of the value (the global "secrets are never echoed" rule).
    """
    values = []
    for key, _variable in _R2_KEYS:
        value = secrets.get(key)
        if not value:
            return None
        # Kept as its own message: a line break is the one case whose
        # consequence is injection into the FILE (a second KEY=value line
        # that systemd itself would honour), not just into a shell.
        if "\n" in value or "\r" in value:
            raise StackError(
                f"infra/secrets.age's '{key}' contains a line break",
                f"R2 credentials are single-line values -- re-issue it and set it with "
                f"`./infra/up secrets set {key}`, then run `up` again",
            )
        if not _VALUE_RE.match(value):
            raise StackError(
                f"infra/secrets.age's '{key}' contains whitespace or a character a shell "
                "would reinterpret",
                f"an R2 access key, secret and endpoint contain only {_VALUE_SHAPE} -- this "
                f"one does not, so re-issue it in the Cloudflare dashboard and set it with "
                f"`./infra/up secrets set {key}`, then run `up` again",
            )
        values.append(value)

    lines = ["RCLONE_CONFIG_BACKUP_TYPE=s3", "RCLONE_CONFIG_BACKUP_PROVIDER=Cloudflare"]
    lines.extend(f"{variable}={value}" for (_key, variable), value in zip(_R2_KEYS, values))
    return "\n".join(lines) + "\n"


def backup_env_digest(content: str) -> str:
    """sha256 hex digest of an already-rendered backup.env."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# Only for the warning below: nixos/backups.nix's own `on_calendar` default.
# A project that overrode it fails at its own hour instead, which changes
# nothing about what the operator has to do.
_NIGHTLY_TIME = "03:00 UTC"


def check_backup_credentials(bucket: str | None, backup_env_sha: str | None, *, emit: Callable[[str], None]) -> None:
    """Warn when a bucket is named but no credentials will be pushed.

    The two halves of "backups are on" are decided in two different places
    and nothing else compares them: `nixos/backups.nix` turns the timer on
    because stack.toml named a bucket, while the ENSURE_BACKUP_ENV step
    pushes credentials only when all three `r2_*` keys are in secrets.age
    (`backup_env_content` is all-or-nothing on purpose). Name the bucket and
    forget the keys -- or set two of the three -- and the node ends up with
    an installed timer that fails at 03:00 every night with "no credentials
    in /var/lib/stackbase/backup.env", while `up` itself says nothing at all.

    A warning, not a `StackError`: an operator mid-setup (bucket created,
    R2 token not issued yet) must still be able to run `up` for everything
    else. The line names all three keys because the failure mode that gets
    reported is usually "I set the ones I had".
    """
    if not bucket or backup_env_sha is not None:
        return
    keys = ", ".join(key for key, _variable in _R2_KEYS)
    emit(
        f"! [backups] bucket = \"{bucket}\" is set but infra/secrets.age has no complete set of "
        f"R2 credentials, so nothing is pushed -- the nightly backup timer is still installed on "
        f"every node and will fail at {_NIGHTLY_TIME} with \"no credentials in {BACKUP_ENV_PATH}\". "
        f"Set all three of {keys} (`./infra/up secrets set <key>`) and run `up` again, or remove "
        "`bucket` from stack.toml's [backups] table to leave backups off."
    )


def run_backup_now(
    infra_dir: Path,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> None:
    """Run the backup unit on every selected node now, then list the bucket.

    Streams both commands so a multi-minute dump does not look like a hang.
    Stops at the first node whose unit fails -- an unnoticed failing backup
    is the whole thing this command exists to prevent.
    """
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)

    if not cfg.backups.bucket:
        raise StackError(
            "this project has no backup bucket",
            'add a [backups] section to stack.toml with bucket = "<name>" and run `./infra/up` first',
        )

    if node is None:
        names = list(cfg.nodes)
    elif node in cfg.nodes:
        names = [node]
    else:
        known = ", ".join(cfg.nodes) or "none"
        raise StackError(f"there is no node called '{node}' in stack.toml", f"known nodes: {known}")

    for name in names:
        node_state = state.nodes.get(name)
        ipv4 = node_state.ipv4 if node_state else None
        if not ipv4:
            raise StackError(
                f"stack-base does not know an address for node '{name}' yet",
                "run `up` first -- the address is recorded once the server is running",
            )
        ssh = Ssh(infra_dir, ipv4, user=SSH_USER, runner=runner, popen=popen)

        emit(f"→ node {name}: running {BACKUP_UNIT}")
        returncode, _tail = ssh.run_stream(f"systemctl start {BACKUP_UNIT}", emit=emit, check=False)
        if returncode != 0:
            # The journal command is named unconditionally, not as a
            # fallback for an empty tail: `systemctl start` on a oneshot
            # says only "Job for ... failed", never why, and that one line
            # was already streamed through `emit` above. Repeating it as
            # the hint would tell the operator nothing they have not just
            # read; the journal is the only place the backup script's own
            # message (bad credentials, missing recipients file, ...) is.
            raise StackError(
                f"the backup unit failed on node {name} (exit {returncode})",
                f"read the node's own log: ./infra/up ssh {name} -- journalctl -u stackbase-backup -n 50",
            )

        emit(f"→ node {name}: contents of backup:{cfg.backups.bucket}")
        returncode, tail = ssh.run_stream(BACKUP_LS_COMMAND, emit=emit, check=False)
        if returncode != 0:
            raise StackError(
                f"could not list the backup bucket from node {name} (exit {returncode})",
                "\n".join(tail).strip() or "check the node's /var/lib/stackbase/backup.env and rclone access",
            )
