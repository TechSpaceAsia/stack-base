"""stack.toml -> StackConfig; stack.state.json <-> StackState.

`stack.toml` is the human-edited declaration of what a project's stack
should look like. `stack.state.json` is the machine-written record of what
stack-base has actually observed/done -- it is never hand-edited, so
load_state is strict: any unknown key or unsupported version is treated as
corruption (a typo or a hand edit) and raises rather than silently ignoring
it.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from stackbase.errors import StackError

_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}$")

# A node name is not just a label: it becomes the machine's hostname, a Nix
# attribute name (`nixosConfigurations.<node>`), a directory under
# `infra/nodes/`, and part of a command that runs as root on the server
# (`nixos-rebuild --flake /etc/nixos/stack#<node>`). It arrives as a TOML
# table key, which may contain literally anything -- `[nodes."a; rm -rf /"]`
# is perfectly valid TOML. Holding it to the same shape as a project name
# closes the command-injection and path-traversal paths at the door, and is
# what a hostname and a Nix attribute name want anyway. Remote commands quote
# their arguments as well; this is the first of those two layers.
_NODE_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")

# A DNS name: dot-separated labels of letters, digits and hyphens, no leading
# or trailing hyphen within a label, and at least two labels (a single-label
# "acme" has no Cloudflare zone to be found under).
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")

# Deliberately conservative: neither of these has any business containing a
# space, a quote or a shell metacharacter.
_DATACENTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,30}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}$")

_ALLOWED_KEY_TYPES = frozenset({"ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ssh-rsa"})
_VALID_ROLES = frozenset({"primary", "replica"})

# I6: the optional [app] table in stack.toml. Mirrors nixos/deploy.nix's
# own stackbase.app.binary validation shape (executable-name-safe
# characters only); health_tries/health_sleep ranges match that module's
# app.healthTries/app.healthSleep option types (1..300 / 1..60).
_APP_BINARY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

# The [backups] table. `bucket` is an R2/S3 bucket name (or, in the VM
# test, a local directory) -- conservative on purpose: it is interpolated
# into an rclone remote path on the node. `on_calendar` is a 24h HH:MM,
# expanded to "*-*-* HH:MM:00" by the module.
_BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,127}$")
_ON_CALENDAR_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")


# --------------------------------------------------------------------------
# stack.toml -> StackConfig
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Node:
    name: str
    role: str
    vps_id: int | None = None


@dataclass(frozen=True)
class AppConfig:
    """The optional `[app]` table -- overrides for what `nixos/deploy.nix`
    would otherwise default (`binary`/`health_path`) or a project would
    otherwise never be able to set at all from stack.toml
    (`health_tries`/`health_sleep`, I3's declarative knobs). Every field is
    `None` when the project never set it -- callers (release.py,
    templates/infra/flake.nix) fall back to their own defaults in that case.
    """

    binary: str | None = None
    health_path: str | None = None
    health_tries: int | None = None
    health_sleep: int | None = None


@dataclass(frozen=True)
class BackupsConfig:
    """The optional `[backups]` table -- overrides for nixos/backups.nix's
    own `stackbase.backups.*` defaults. Every field is `None` when the
    project never set it, so an unset field keeps the module's default.
    No bucket at all means backups are off (the module's `enable` defaults
    to "a bucket is set").
    """

    bucket: str | None = None
    retention_days: int | None = None
    extra_paths: list[str] | None = None
    on_calendar: str | None = None


@dataclass(frozen=True)
class StackConfig:
    project: str
    domain: str
    owner: str
    datacenter: str
    plan: str
    price_item: str | None
    auto_patch: bool
    admins: list[str]
    nodes: dict[str, Node]
    admin_keys: dict[str, str]
    app: AppConfig = field(default_factory=AppConfig)
    backups: BackupsConfig = field(default_factory=BackupsConfig)


def load_config(infra_dir: Path) -> StackConfig:
    """Read and validate `<infra_dir>/stack.toml` (plus `keys/<admin>.pub`)."""
    toml_path = infra_dir / "stack.toml"
    if not toml_path.exists():
        raise StackError(f"{toml_path} not found", "create infra/stack.toml")

    try:
        with toml_path.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise StackError(f"{toml_path} is not valid TOML", str(e)) from e

    project = _require_str(data, "project", toml_path)
    if not _PROJECT_RE.match(project):
        raise StackError(
            f"invalid project name '{project}'",
            "project must match [a-z][a-z0-9-]{1,30}",
        )

    domain = _checked(
        _require_str(data, "domain", toml_path),
        _DOMAIN_RE,
        "domain",
        "domain must be a DNS name like 'acme.example.com' -- letters, digits, '-' and '.', "
        "with at least two parts",
    )
    owner = _checked(
        _require_str(data, "owner", toml_path),
        _OWNER_RE,
        "owner",
        "owner must be a plain account handle -- letters, digits, '.', '_' or '-', no spaces",
    )
    datacenter = _checked(
        _require_str(data, "datacenter", toml_path),
        _DATACENTER_RE,
        "datacenter",
        "datacenter must be a short code like 'kul' -- letters, digits and '-' only",
    )
    plan = _require_str(data, "plan", toml_path)
    price_item = _optional_price_item(data, toml_path)
    auto_patch = _optional_bool(data, "auto_patch", True, toml_path)
    admins = _require_str_list(data, "admins", toml_path)
    nodes = _parse_nodes(data, toml_path)
    admin_keys = _load_admin_keys(admins, infra_dir)
    app = _parse_app(data, toml_path)
    backups = _parse_backups(data, toml_path)

    return StackConfig(
        project=project,
        domain=domain,
        owner=owner,
        datacenter=datacenter,
        plan=plan,
        price_item=price_item,
        auto_patch=auto_patch,
        admins=admins,
        nodes=nodes,
        admin_keys=admin_keys,
        app=app,
        backups=backups,
    )


def _require_str(data: dict[str, Any], key: str, toml_path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise StackError(
            f"{toml_path} is missing '{key}'",
            f"add a non-empty '{key} = \"...\"' key",
        )
    return value


def _checked(value: str, pattern: re.Pattern[str], key: str, hint: str) -> str:
    if not pattern.match(value):
        raise StackError(f"invalid '{key}' value {value!r} in stack.toml", hint)
    return value


def _require_str_list(data: dict[str, Any], key: str, toml_path: Path) -> list[str]:
    value = data.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise StackError(
            f"{toml_path} has an invalid '{key}'",
            f"'{key}' must be a non-empty list of non-empty strings",
        )
    return list(value)


def _optional_price_item(data: dict[str, Any], toml_path: Path) -> str | None:
    value = data.get("price_item")
    if value is None:
        return None
    if not isinstance(value, str):
        raise StackError(
            f"{toml_path} has an invalid 'price_item'",
            "price_item must be a string",
        )
    return value if value != "" else None


def _optional_bool(data: dict[str, Any], key: str, default: bool, toml_path: Path) -> bool:
    if key not in data:
        return default
    value = data[key]
    if not isinstance(value, bool):
        raise StackError(f"{toml_path} has an invalid '{key}'", f"'{key}' must be true or false")
    return value


def _parse_nodes(data: dict[str, Any], toml_path: Path) -> dict[str, Node]:
    nodes_raw = data.get("nodes")
    if not isinstance(nodes_raw, dict) or not nodes_raw:
        raise StackError(
            f"{toml_path} has no nodes",
            "define at least one [nodes.<name>] section",
        )

    nodes: dict[str, Node] = {}
    primary_count = 0
    for name, raw in nodes_raw.items():
        if not _NODE_RE.match(name):
            raise StackError(
                f"invalid node name '{name}' in {toml_path}",
                "a node name becomes the server's hostname, so it must start with a lowercase "
                "letter and contain only lowercase letters, digits and '-' (at most 31 "
                "characters) -- e.g. [nodes.a] or [nodes.web-2]",
            )

        if not isinstance(raw, dict):
            raise StackError(
                f"invalid node '{name}' in {toml_path}",
                f"[nodes.{name}] must be a table with 'role' (and optional 'vps_id')",
            )

        role = raw.get("role")
        if role not in _VALID_ROLES:
            raise StackError(
                f"invalid role for node '{name}'",
                "role must be 'primary' or 'replica'",
            )
        if role == "primary":
            primary_count += 1

        vps_id = raw.get("vps_id")
        # bool is a subclass of int in Python, so `vps_id = true` would
        # otherwise sail through as VPS id 1 (and `false` as id 0).
        if vps_id is not None and (isinstance(vps_id, bool) or not isinstance(vps_id, int)):
            raise StackError(
                f"invalid vps_id for node '{name}'",
                "vps_id must be an integer, or omitted if the node needs to be purchased",
            )

        nodes[name] = Node(name=name, role=role, vps_id=vps_id)

    if primary_count != 1:
        raise StackError(
            f"expected exactly one primary node, found {primary_count}",
            'set role = "primary" on exactly one [nodes.*] section',
        )

    return nodes


def _parse_app(data: dict[str, Any], toml_path: Path) -> AppConfig:
    raw = data.get("app")
    if raw is None:
        return AppConfig()
    if not isinstance(raw, dict):
        raise StackError(
            f"{toml_path} has an invalid '[app]' table",
            "[app] must be a table, e.g. [app]\\nbinary = \"my_app\"",
        )
    _reject_unknown_keys(raw, AppConfig, f"{toml_path} [app]")

    binary = raw.get("binary")
    if binary is not None:
        if not isinstance(binary, str) or not _APP_BINARY_RE.match(binary):
            raise StackError(
                f"{toml_path} has an invalid [app].binary {binary!r}",
                "binary must match ^[A-Za-z0-9_.-]{1,64}$ -- letters, digits, '_', '.' or '-'",
            )

    health_path = raw.get("health_path")
    if health_path is not None:
        if (
            not isinstance(health_path, str)
            or not health_path.startswith("/")
            or any(ch.isspace() for ch in health_path)
        ):
            raise StackError(
                f"{toml_path} has an invalid [app].health_path {health_path!r}",
                "health_path must start with '/' and contain no whitespace",
            )

    health_tries = _optional_ranged_int(raw, "health_tries", 1, 300, toml_path)
    health_sleep = _optional_ranged_int(raw, "health_sleep", 1, 60, toml_path)

    return AppConfig(binary=binary, health_path=health_path, health_tries=health_tries, health_sleep=health_sleep)


def _optional_ranged_int(
    data: dict[str, Any], key: str, low: int, high: int, toml_path: Path, *, table: str = "app"
) -> int | None:
    """One optional, range-checked integer out of `[<table>]`.

    `table` only names the table in the message -- it defaults to "app"
    because that is where this started, and `[backups]` passes its own so
    an operator reading `[backups].retention_days must be...` is not sent
    looking at the wrong section.
    """
    value = data.get(key)
    if value is None:
        return None
    # bool is a subclass of int in Python -- same trap as vps_id above.
    if isinstance(value, bool) or not isinstance(value, int) or not (low <= value <= high):
        raise StackError(
            f"{toml_path} has an invalid [{table}].{key} {value!r}",
            f"[{table}].{key} must be an integer between {low} and {high}",
        )
    return value


def _parse_backups(data: dict[str, Any], toml_path: Path) -> BackupsConfig:
    raw = data.get("backups")
    if raw is None:
        return BackupsConfig()
    if not isinstance(raw, dict):
        raise StackError(
            f"{toml_path} has an invalid '[backups]' table",
            '[backups] must be a table, e.g. [backups]\\nbucket = "acme-backups"',
        )
    _reject_unknown_keys(raw, BackupsConfig, f"{toml_path} [backups]")

    bucket = raw.get("bucket")
    if bucket is not None:
        if not isinstance(bucket, str) or not _BUCKET_RE.match(bucket):
            raise StackError(
                f"{toml_path} has an invalid [backups].bucket {bucket!r}",
                "bucket must match ^[A-Za-z0-9][A-Za-z0-9._/-]{1,127}$ -- the R2 bucket's name",
            )
        # `.` and `/` are allowed, because a bucket may legitimately carry a
        # prefix ("acme-backups/prod") -- which lets ".." through the regex
        # above. Against a real S3 bucket that is inert (keys are literal
        # strings, not paths), but the rclone remote is configured entirely
        # from backup.env, and with RCLONE_CONFIG_BACKUP_TYPE=local -- how
        # the VM test exercises the whole pipeline -- a ".." segment walks
        # OUT of the remote's root, taking `rclone delete --min-age` with it.
        # An empty or "." segment is not traversal, but it is never what
        # anyone meant either, so the whole shape is refused in one place.
        if any(segment in ("", ".", "..") for segment in bucket.split("/")):
            raise StackError(
                f"{toml_path} has an invalid [backups].bucket {bucket!r}",
                'a bucket may carry a prefix ("acme-backups/prod") but no empty, "." or ".." '
                'path segment -- ".." would let the nightly prune delete outside the project\'s '
                "own prefix",
            )

    # 1 at the bottom, deliberately: the node deletes with `rclone delete
    # --min-age <retention_days>d`, and a retention of 0 would mean "every
    # object, including the one just written". 3650 (ten years) at the top
    # is an obvious-typo guard, not a policy.
    retention_days = _optional_ranged_int(raw, "retention_days", 1, 3650, toml_path, table="backups")

    extra_paths = raw.get("extra_paths")
    if extra_paths is not None:
        if not isinstance(extra_paths, list) or not all(isinstance(item, str) for item in extra_paths):
            raise StackError(
                f"{toml_path} has an invalid [backups].extra_paths",
                'extra_paths must be a list of absolute paths, e.g. ["/var/lib/acme/uploads"]',
            )
        for item in extra_paths:
            # Interpolated into a root shell command on the node. The
            # module quotes it too; this is the first of those two layers.
            if not item.startswith("/") or any(ch.isspace() for ch in item) or '"' in item or "'" in item:
                raise StackError(
                    f"{toml_path} has an invalid [backups].extra_paths entry {item!r}",
                    "each entry must be an absolute path with no whitespace or quotes",
                )
        extra_paths = list(extra_paths)

    on_calendar = raw.get("on_calendar")
    if on_calendar is not None and (not isinstance(on_calendar, str) or not _ON_CALENDAR_RE.match(on_calendar)):
        raise StackError(
            f"{toml_path} has an invalid [backups].on_calendar {on_calendar!r}",
            'on_calendar must be a 24-hour UTC time like "03:00"',
        )

    return BackupsConfig(
        bucket=bucket, retention_days=retention_days, extra_paths=extra_paths, on_calendar=on_calendar
    )


def _load_admin_keys(admins: list[str], infra_dir: Path) -> dict[str, str]:
    admin_keys: dict[str, str] = {}
    for admin in admins:
        key_path = infra_dir / "keys" / f"{admin}.pub"
        admin_keys[admin] = _load_pub_key(admin, key_path)
    return admin_keys


def _load_pub_key(admin: str, key_path: Path) -> str:
    if not key_path.exists():
        raise StackError(
            f"missing SSH key for admin '{admin}'",
            f"create {key_path} (a public key, e.g. via ssh-keygen)",
        )

    lines = [line.strip() for line in key_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise StackError(
            f"{key_path} must contain exactly one key",
            f"found {len(lines)} non-blank line(s); it must be a single public key line",
        )

    line = lines[0]
    key_type = line.split(" ", 1)[0]
    if key_type not in _ALLOWED_KEY_TYPES:
        raise StackError(
            f"{key_path} has an unsupported key type '{key_type}'",
            f"key must start with one of: {', '.join(sorted(_ALLOWED_KEY_TYPES))}",
        )

    return line


# --------------------------------------------------------------------------
# stack.state.json <-> StackState
# --------------------------------------------------------------------------


@dataclass
class NodeState:
    vps_id: int | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    host_key_pinned: bool = False
    hardware_captured: bool = False
    applied_rev: str | None = None
    # sha256 of the app_env content (from secrets.age) most recently pushed
    # to this node's /var/lib/stackbase/app.env. None until the first push.
    app_env_sha: str | None = None
    # sha256 of the backup.env content (from secrets.age's r2_* keys) most
    # recently pushed to this node. None until the first push.
    backup_env_sha: str | None = None


@dataclass
class CloudflareState:
    zone_id: str | None = None
    record_id: str | None = None


@dataclass
class HostingerState:
    firewall_id: int | None = None
    ssh_key_ids: dict[str, int] = field(default_factory=dict)


@dataclass
class StackState:
    version: int = 1
    nodes: dict[str, NodeState] = field(default_factory=dict)
    cloudflare: CloudflareState = field(default_factory=CloudflareState)
    hostinger: HostingerState = field(default_factory=HostingerState)


_STATE_FILENAME = "stack.state.json"


def load_state(infra_dir: Path) -> StackState:
    """Load `<infra_dir>/stack.state.json`. A missing file yields an empty state."""
    state_path = infra_dir / _STATE_FILENAME
    if not state_path.exists():
        return StackState()

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise StackError(f"{state_path} is not valid JSON", str(e)) from e

    return _state_from_dict(data, state_path)


def save_state(infra_dir: Path, state: StackState) -> None:
    """Atomically write `state` to `<infra_dir>/stack.state.json`."""
    state_path = infra_dir / _STATE_FILENAME
    text = json.dumps(asdict(state), indent=2, sort_keys=True) + "\n"

    # pid-suffixed, like ssh.py's known_hosts temp file: two concurrent runs
    # against the same infra/ (unusual, but not impossible) must not step on
    # each other's temp file.
    tmp_path = state_path.with_name(f".{state_path.name}.tmp{os.getpid()}")
    tmp_path.write_text(text, encoding="utf-8")
    os.replace(tmp_path, state_path)


def _known_keys(cls: type) -> set[str]:
    return {f.name for f in fields(cls)}


def _reject_unknown_keys(raw: dict[str, Any], cls: type, label: str) -> None:
    unknown = set(raw) - _known_keys(cls)
    if unknown:
        raise StackError(
            f"unknown key(s) in {label}: {', '.join(sorted(unknown))}",
            "remove the unrecognised key(s) or fix a typo -- stack.state.json is machine-written",
        )


def _state_from_dict(data: Any, state_path: Path) -> StackState:
    if not isinstance(data, dict):
        raise StackError(f"{state_path} must be a JSON object", "fix the file or delete it to start fresh")

    _reject_unknown_keys(data, StackState, str(state_path))

    version = data.get("version", 1)
    if version != 1:
        raise StackError(
            f"unsupported {state_path} version {version!r}",
            "only version 1 is supported",
        )

    nodes_raw = data.get("nodes", {})
    if not isinstance(nodes_raw, dict):
        raise StackError(f"{state_path} 'nodes' must be an object", "fix the file or delete it to start fresh")
    nodes = {
        name: _dataclass_from_dict(NodeState, raw, f"{state_path} nodes.{name}")
        for name, raw in nodes_raw.items()
    }

    cloudflare = _dataclass_from_dict(CloudflareState, data.get("cloudflare", {}), f"{state_path} cloudflare")
    hostinger = _dataclass_from_dict(HostingerState, data.get("hostinger", {}), f"{state_path} hostinger")

    return StackState(version=version, nodes=nodes, cloudflare=cloudflare, hostinger=hostinger)


def _dataclass_from_dict(cls: type, raw: Any, label: str) -> Any:
    if not isinstance(raw, dict):
        raise StackError(f"{label} must be an object", "fix the file or delete it to start fresh")
    _reject_unknown_keys(raw, cls, label)
    return cls(**raw)
