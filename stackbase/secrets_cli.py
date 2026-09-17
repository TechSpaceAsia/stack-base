"""`secrets keys|set|unset|edit` -- the safe way to touch `infra/secrets.age`.

The old documented flow was `age -d ... > /tmp/secrets.json; $EDITOR ...;
age -R ... ; rm -f /tmp/secrets.json` -- which, for the seconds between the
first and last of those commands, holds the WHOLE decrypted bundle (every
API token, the origin TLS key, all of app_env) in plaintext on disk. These
four subcommands replace that: none of them ever writes more than one key's
value to disk, and only ever to a RAM-backed scratch directory
(`stackbase.ramdir.private_ram_dir`) that is wiped on the way out.

Every one of these needs the age identity the same way `up` does (they go
through `stackbase.secrets.load_secrets`/`save_secrets`, same as
everything else that touches `secrets.age`), and none of them ever prints a
value -- only key names, counts, and outcomes reach stdout/stderr.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from stackbase.errors import StackError
from stackbase.ramdir import private_ram_dir
from stackbase.reconcile import validate_app_env
from stackbase.secrets import load_secrets, save_secrets

KEY_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")

# The one secret `up` cannot run without -- see `__main__.py`'s `_token()`.
# `unset` refuses to remove it; there is nothing stopping `set` from
# replacing its value.
REQUIRED_KEY = "hostinger_token"

_EDITOR_HINT = (
    "your editor's own swap/backup files are its business, not stack-base's -- for vim, consider "
    ":set noswapfile nobackup noundofile"
)


def _validate_key_name(key: str) -> None:
    if not KEY_NAME_RE.match(key):
        raise StackError(
            f"invalid secret key name '{key}'",
            "key names must match ^[a-z][a-z0-9_]{0,40}$ -- lowercase letters, digits and "
            "underscores, starting with a letter",
        )


def _editor_argv(scratch: Path) -> list[str]:
    """The argv to launch the configured editor on `scratch`.

    Tries `$VISUAL` then `$EDITOR`, each split with `shlex.split` (NEVER
    `shell=True` -- the result is exec'd as a literal argv list, so shell
    metacharacters in the value are inert, not a command-injection vector).
    An unset or whitespace-only value falls through to the next candidate;
    a value that fails to parse (e.g. an unbalanced quote) raises a
    `StackError` naming the variable, not its content -- the raw value could
    itself contain something not meant to be echoed verbatim. Neither
    variable usable -> `vi`, unsplit (never fails to parse).
    """
    for var in ("VISUAL", "EDITOR"):
        raw = os.environ.get(var)
        if raw is None or not raw.strip():
            continue
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            raise StackError(
                f"${var} could not be parsed as a command",
                f"check for an unbalanced quote (or similar) in ${var}",
            ) from exc
        if not parts:
            continue
        return [*parts, str(scratch)]
    return ["vi", str(scratch)]


def _stdin_hint(key: str) -> str:
    return (
        f"pass the value on stdin -- e.g. printf '%s' \"$VALUE\" | ./infra/up secrets set {key}, "
        f"or ./infra/up secrets set {key} < file"
    )


def _noop_register(_key: str, _value: str) -> None:
    pass


def list_key_names(infra_dir: Path) -> list[str]:
    """Every key currently in secrets.age, sorted. Names only -- never values."""
    secrets = load_secrets(infra_dir)
    return sorted(secrets)


def set_key(
    infra_dir: Path,
    key: str,
    *,
    stdin: Any = None,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str, str], None] = _noop_register,
) -> None:
    """Set `key`'s value, read whole from `stdin` (defaults to `sys.stdin`).

    Refuses an interactive terminal -- piping or redirecting is the only
    way this is safe to script; a bare TTY prompt makes it too easy to end
    up with a secret sitting in shell history instead. "app_env" is
    validated (`reconcile.validate_app_env`) before it is ever saved -- the
    same check `up` performs -- so a malformed app_env is caught here, not
    on the next `up`. Only the key name is ever printed -- not its length,
    not any part of its value.

    `register_secret(key, value)` feeds the CLI's own redaction net (F2, Fix
    round 1) -- the caller wires this to the same dict `error_line`/
    `_print_traceback` mask with. The NEW value is registered as soon as it
    is read, before it is validated or saved (it is not in the decrypted
    bundle yet, so nothing upstream would otherwise know to mask it); every
    existing bundle value is registered right after decryption, in case a
    later failure echoes one of those instead.
    """
    _validate_key_name(key)
    source = stdin if stdin is not None else sys.stdin
    if source is sys.stdin and source.isatty():
        raise StackError(f"refusing to read '{key}'s value from a terminal", _stdin_hint(key))

    value = source.read()
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    register_secret(key, value)

    secrets = load_secrets(infra_dir)
    for existing_key, existing_value in secrets.items():
        register_secret(existing_key, existing_value)

    if key == "app_env":
        value = validate_app_env(value)
        register_secret(key, value)

    secrets[key] = value
    save_secrets(infra_dir, secrets)
    emit(key)


def unset_key(
    infra_dir: Path,
    key: str,
    *,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str, str], None] = _noop_register,
) -> None:
    """Remove `key`. Refuses the required token key outright.

    Registers every existing bundle value for redaction right after
    decryption (F2, Fix round 1) -- a failure from `save_secrets` could
    otherwise echo one of the remaining secrets unmasked.
    """
    _validate_key_name(key)
    if key == REQUIRED_KEY:
        raise StackError(
            f"'{key}' is required -- up cannot run without it",
            f"set a new value instead of unsetting it: ./infra/up secrets set {key}",
        )

    secrets = load_secrets(infra_dir)
    for existing_key, existing_value in secrets.items():
        register_secret(existing_key, existing_value)

    if key not in secrets:
        emit(f"{key}: was not set, nothing to do")
        return

    del secrets[key]
    save_secrets(infra_dir, secrets)
    emit(f"{key}: removed")


def edit_key(
    infra_dir: Path,
    key: str,
    *,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str, str], None] = _noop_register,
) -> None:
    """Edit `key`'s value in `$VISUAL`/`$EDITOR`/`vi`, via a RAM-only scratch file.

    The scratch file holds ONLY this one key's value -- never the whole
    secrets bundle -- created directly at mode 0600 (M1, Fix round 1: no
    window at a laxer mode between creation and a later `chmod`), inside
    `private_ram_dir()`. If the editor leaves the content unchanged, nothing
    is re-encrypted.

    `register_secret(key, value)` feeds the CLI's own redaction net (F2, Fix
    round 1), the same way `set_key` does: every existing bundle value right
    after decryption, and the freshly-edited value as soon as it is read
    back -- before it is validated or saved.
    """
    _validate_key_name(key)
    secrets = load_secrets(infra_dir)
    for existing_key, existing_value in secrets.items():
        register_secret(existing_key, existing_value)
    original = secrets.get(key, "")

    with private_ram_dir() as ramdir:
        scratch = ramdir / key
        fd = os.open(str(scratch), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(original)

        argv = _editor_argv(scratch)
        try:
            result = runner(argv, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, check=False)
        except FileNotFoundError as exc:
            raise StackError(
                f"the editor '{argv[0]}' was not found",
                "set $EDITOR (or $VISUAL) to an installed editor",
            ) from exc
        if getattr(result, "returncode", 0) != 0:
            raise StackError(
                f"the editor exited with an error while editing '{key}'",
                "nothing was saved -- run the command again",
            )

        edited = scratch.read_text(encoding="utf-8")

    register_secret(key, edited)

    emit(f"note: {_EDITOR_HINT}")

    if edited == original:
        emit(f"{key}: unchanged, nothing saved")
        return

    if key == "app_env":
        edited = validate_app_env(edited)
        register_secret(key, edited)

    secrets[key] = edited
    save_secrets(infra_dir, secrets)
    emit(f"{key}: saved")
