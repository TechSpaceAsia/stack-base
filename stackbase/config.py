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


# --------------------------------------------------------------------------
# stack.toml -> StackConfig
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Node:
    name: str
    role: str
    vps_id: int | None = None


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
