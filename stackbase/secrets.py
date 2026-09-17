"""Secrets: age-encrypted JSON at rest, plus redaction for logs/errors.

`infra/secrets.age` holds a single JSON object (Hostinger token, Cloudflare
token, origin cert key, ...) encrypted with `age` against the recipients
listed in `infra/age-recipients.txt`. Plaintext only ever exists in memory:
it is never written to disk and never logged. Any text that might contain a
secret value should be passed through `redact()` before it is printed or
folded into an exception message.

A teammate may hold several age identities (some hardware/YubiKey-backed via
an age plugin) -- `$STACKBASE_AGE_IDENTITY` can name any identity file. This
module never inspects or parses it; it is passed straight to `age -i`.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Iterable

from stackbase.errors import StackError

_DEFAULT_IDENTITY = Path.home() / ".age" / "key.txt"
_SECRETS_FILENAME = "secrets.age"
_RECIPIENTS_FILENAME = "age-recipients.txt"
_REDACTED = "***REDACTED***"


def redact(text: str, values: Iterable[str]) -> str:
    """Replace every occurrence of each non-empty value in `values` with a mask.

    Empty strings are skipped -- replacing "" would otherwise insert the mask
    between every character of `text`.
    """
    for value in values:
        if value:
            text = text.replace(value, _REDACTED)
    return text


def _identity_path() -> Path:
    override = os.environ.get("STACKBASE_AGE_IDENTITY")
    return Path(override) if override else _DEFAULT_IDENTITY


def _run_age(args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(["age", *args], input=input_bytes, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise StackError(
            "the 'age' command was not found",
            "install age (e.g. `apt install age`, `brew install age`, or see https://age-encryption.org)",
        ) from exc


def load_secrets(infra_dir: Path) -> dict[str, str]:
    """Decrypt `<infra_dir>/secrets.age` with the configured age identity.

    Returns the decrypted payload as a flat `{"key": "value"}` object. A
    missing `secrets.age` raises a `StackError` whose hint is the exact
    command to create one.
    """
    secrets_path = infra_dir / _SECRETS_FILENAME
    recipients_path = infra_dir / _RECIPIENTS_FILENAME

    if not secrets_path.exists():
        raise StackError(
            f"{secrets_path} not found",
            "create it with:\n"
            "HOSTINGER_TOKEN=<paste here>\n"
            "CLOUDFLARE_TOKEN=<paste here>\n"
            "ORIGIN_CERT_KEY=<paste here>\n"
            'printf \'{"hostinger_token": "%s", "cloudflare_token": "%s", "origin_cert_key": "%s"}\' '
            '"$HOSTINGER_TOKEN" "$CLOUDFLARE_TOKEN" "$ORIGIN_CERT_KEY" '
            f"| age -R {recipients_path} -o {secrets_path}",
        )

    identity_path = _identity_path()
    if not identity_path.exists():
        raise StackError(
            f"age identity {identity_path} not found",
            "set $STACKBASE_AGE_IDENTITY to your age identity file (any identity, including a "
            "YubiKey-backed plugin identity), or create ~/.age/key.txt",
        )

    result = _run_age(["-d", "-i", str(identity_path), str(secrets_path)])
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        detail = f" ({stderr})" if stderr else ""
        raise StackError(
            f"failed to decrypt {secrets_path}",
            f"check that {identity_path} is the right identity and is a recipient of {secrets_path}{detail}",
        )

    try:
        data = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StackError(
            f"{secrets_path} did not decrypt to valid JSON",
            "re-create secrets.age from a flat JSON object -- it may have been corrupted or encrypted "
            "from something else",
        ) from exc

    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise StackError(
            f"{secrets_path} did not decrypt to a flat JSON object of strings",
            're-create secrets.age from a JSON object like {"hostinger_token": "...", ...} with no nesting',
        )

    return data


def save_secrets(infra_dir: Path, data: dict[str, str]) -> None:
    """Encrypt `data` as JSON to `<infra_dir>/secrets.age`; plaintext never touches disk."""
    recipients_path = infra_dir / _RECIPIENTS_FILENAME
    secrets_path = infra_dir / _SECRETS_FILENAME

    if not recipients_path.exists():
        raise StackError(
            f"{recipients_path} not found",
            "create infra/age-recipients.txt with one age public key per line "
            "(one per admin who should be able to decrypt secrets.age)",
        )

    payload = json.dumps(data).encode("utf-8")
    result = _run_age(["-R", str(recipients_path), "-o", str(secrets_path)], input_bytes=payload)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise StackError(
            f"failed to encrypt secrets to {secrets_path}",
            stderr or f"check that {recipients_path} contains valid age public keys",
        )
