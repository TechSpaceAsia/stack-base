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

from stackbase.config import load_config
from stackbase.errors import StackError
from stackbase.ramdir import private_ram_dir
from stackbase.reconcile import validate_app_env
from stackbase.secrets import (
    DEPLOY_FILE,
    DEPLOY_KEY_NAME,
    check_recipients_superset,
    load_secrets,
    read_recipients,
    register_private_key,
    save_secrets,
    write_public_key,
)

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


# The PUBLIC half of the project's deploy key, committed like any other
# key under infra/keys/. The private half only ever exists inside
# infra/deploy.age (encrypted) and, for the seconds a command needs it, in
# a RAM-backed scratch directory.
DEPLOY_PUB_FILENAME = "deploy.pub"


def _noop_register_value(_value: str) -> None:
    pass


def deploy_key_init(
    infra_dir: Path,
    *,
    rotate: bool = False,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = _noop_register_value,
) -> None:
    """Generate the project's ONE SSH deploy key: `deploy.age` + `keys/deploy.pub`.

    The private half is generated inside `private_ram_dir()` (never a real
    disk), encrypted straight into `infra/deploy.age` against
    `infra/deploy-recipients.txt`, and then the RAM directory is wiped.
    The public half is written to `infra/keys/deploy.pub`, which the
    project's flake reads into `stackbase.deploy.keys` -- that is what
    installs it on every server.

    Refuses outright when `deploy.age` already exists unless `rotate` is
    set: replacing a live key is a sequence (commit, `up`, `ci-setup`), not
    a side effect of a mistyped command.

    `register_secret(value)` feeds the CLI's own redaction net (the same
    mechanism `ci_setup` uses) -- the private key is registered the moment
    it is read, before anything else can echo it.
    """
    cfg = load_config(infra_dir)
    deploy_path = infra_dir / DEPLOY_FILE.name
    pub_path = infra_dir / "keys" / DEPLOY_PUB_FILENAME

    if deploy_path.exists() and not rotate:
        raise StackError(
            f"{deploy_path} already exists",
            "pass --rotate to replace it -- the old key keeps working on the servers until you "
            "commit the new infra/keys/deploy.pub and run ./infra/up",
        )

    recipients_path = infra_dir / DEPLOY_FILE.recipients_name
    if not recipients_path.exists():
        raise StackError(
            f"{recipients_path} not found",
            "create infra/deploy-recipients.txt with one age public key per line -- it must list "
            "every recipient of infra/age-recipients.txt, plus any build host that deploys",
        )
    # The template ships deploy-recipients.txt present but comment-only (no
    # keys yet) -- caught here, by name, before save_secrets ever shells out
    # to `age -R` (which would otherwise fail with a bare "no recipients"
    # error that names no file and offers no next step).
    if not read_recipients(recipients_path):
        raise StackError(
            f"{recipients_path} lists no recipients yet",
            "add at least your own age public key (the same one that is in infra/age-recipients.txt) "
            "to infra/deploy-recipients.txt before initialising the deploy key",
        )
    # Checked BEFORE ssh-keygen runs: a key encrypted to a list that has
    # already drifted would lock an admin out the moment it is committed.
    check_recipients_superset(infra_dir)

    with private_ram_dir() as ramdir:
        key_path = ramdir / "deploy_key"
        keygen = runner(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"deploy@{cfg.project}", "-f", str(key_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if keygen.returncode != 0:
            raise StackError(
                "ssh-keygen failed while generating the project deploy key",
                (keygen.stderr or "").strip() or "check that ssh-keygen is installed",
            )

        pub_key_path = ramdir / "deploy_key.pub"
        if not key_path.is_file() or not pub_key_path.is_file():
            raise StackError(
                "ssh-keygen did not produce both key files",
                "this is a bug in stack-base -- please report it",
            )

        private_key = key_path.read_text(encoding="utf-8")
        register_private_key(private_key, register_secret)
        public_key = pub_key_path.read_text(encoding="utf-8").strip() + "\n"

        save_secrets(infra_dir, {DEPLOY_KEY_NAME: private_key}, file=DEPLOY_FILE)

    # Past this point the RAM directory (and the private key it held) is
    # gone -- only the PUBLIC key is still in hand.
    write_public_key(pub_path, public_key)

    action = "rotated" if rotate else "created"
    emit(f"project deploy key {action}: {deploy_path} (encrypted) and {pub_path} (public).")
    emit("Next steps:")
    emit(f"  1. git add {deploy_path} {pub_path} && git commit -m 'deploy: {action} the project deploy key'")
    emit("  2. ./infra/up                 # installs the key on every server")
    emit("  3. ./infra/up ci-setup        # only if GitHub Actions deploys this project")
    if rotate:
        emit("  Deploys using the OLD key (CI, and any build host) FAIL until steps 1-3 are done.")


def deploy_key_show_pub(infra_dir: Path, *, emit: Callable[[str], None] = print) -> None:
    """Print the deploy key's PUBLIC half -- never touches deploy.age."""
    pub_path = infra_dir / "keys" / DEPLOY_PUB_FILENAME
    if not pub_path.is_file():
        raise StackError(
            f"{pub_path} not found",
            "run `./infra/up deploy-key init` first -- it writes the public half there",
        )
    emit(pub_path.read_text(encoding="utf-8").strip())
