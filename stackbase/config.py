"""stack.toml -> StackConfig; stack.state[.<env>].json <-> StackState.

`stack.toml` is the human-edited declaration of what a project's stack
should look like. `stack.state.json` is the machine-written record of what
stack-base has actually observed/done -- it is never hand-edited, so
load_state is strict: any unknown key or unsupported version is treated as
corruption (a typo or a hand edit) and raises rather than silently ignoring
it.

A `stack.toml` may declare `[environments.<env>]` tables (staging and
production, typically). Each environment is its own set of servers with its
own state file, secrets and deploy key; everything outside those tables is
shared, so the environments match by construction. A file with no
`[environments]` is one implicit environment named "" -- today's format,
whose files and plans stay exactly what they were.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import asdict, dataclass, field, fields, replace
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

# An environment name becomes part of a file name (stack.state.<env>.json,
# secrets.<env>.age), a NixOS hostname and flake attribute (`<env>-<node>`,
# which must stay a valid hostname label next to a 31-character node name),
# and a GitHub secret name. Short, lowercase, no dots or underscores.
_ENV_RE = re.compile(r"^[a-z][a-z0-9-]{0,15}$")

# What an [environments.<env>] table may hold. Anything else is shared, and
# setting it per environment is an error: staging and production must not
# drift apart on anything but servers, domain, buckets and recipients.
_ENV_KEYS = frozenset({"domain", "nodes", "plan", "price_item", "backups", "logs", "alerts", "files"})
_ENV_SECTION_KEYS: dict[str, frozenset[str]] = {
    "backups": frozenset({"bucket", "retention_days"}),
    "logs": frozenset({"bucket", "retention_days"}),
    "alerts": frozenset({"to"}),
    "files": frozenset({"bucket", "lock_days"}),
}


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
    # `false` is the explicit opt-out from backups; `None` when unset.
    enabled: bool | None = None


@dataclass(frozen=True)
class LogsConfig:
    """The optional `[logs]` table: where the node's journal is shipped.
    Every field is `None` when the project never set it."""

    enabled: bool | None = None
    bucket: str | None = None
    retention_days: int | None = None


@dataclass(frozen=True)
class AlertsConfig:
    """The optional `[alerts]` table: who is mailed when a service fails."""

    to: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FilesConfig:
    """The optional `[files]` table: the app's uploaded files in R2."""

    bucket: str | None = None
    lock_days: int | None = None


@dataclass(frozen=True)
class Environment:
    """One environment: its own servers, domain, state, secrets and buckets.

    `name` is "" for the implicit environment of a file with no
    `[environments]`, which is what keeps that file's paths and names
    exactly what they were before environments existed. The four section
    tables are the shared ones with this environment's overrides merged in.
    """

    name: str
    domain: str
    plan: str
    price_item: str | None
    nodes: dict[str, Node]
    backups: BackupsConfig = field(default_factory=BackupsConfig)
    logs: LogsConfig = field(default_factory=LogsConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    files: FilesConfig = field(default_factory=FilesConfig)

    @property
    def implicit(self) -> bool:
        return self.name == ""


@dataclass(frozen=True)
class StackConfig:
    """The whole of stack.toml.

    `domain`, `plan`, `price_item`, `nodes` and the four section tables are
    the TOP-LEVEL values. In a single-environment file they are that one
    environment's; with `[environments]`, `nodes` is empty, `domain`/`plan`
    are only whatever shared value the file set (possibly ""), and anything
    per server must be read off `env(name)` instead.
    """

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
    logs: LogsConfig = field(default_factory=LogsConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    files: FilesConfig = field(default_factory=FilesConfig)
    environments: dict[str, Environment] = field(default_factory=dict)
    implicit_env: bool = True

    def __post_init__(self) -> None:
        # A single-environment config is always exactly one environment,
        # built from the top-level values -- whether it came from
        # load_config or was constructed directly.
        if self.implicit_env and not self.environments:
            implicit = Environment(
                name="",
                domain=self.domain,
                plan=self.plan,
                price_item=self.price_item,
                nodes=self.nodes,
                backups=self.backups,
                logs=self.logs,
                alerts=self.alerts,
                files=self.files,
            )
            object.__setattr__(self, "environments", {"": implicit})

    def env(self, name: str | None) -> Environment:
        """The selected environment. There is no default once a project has
        environments: a forgotten `--env` must never land on production."""
        if self.implicit_env:
            if name is None:
                return self.environments[""]
            raise StackError(
                f"there is no environment called '{name}' -- this project has no [environments] in stack.toml",
                "drop --env, or add [environments.<name>] tables to stack.toml",
            )
        listed = ", ".join(self.environments)
        if name is None:
            raise StackError(f"this project has environments: {listed}", "add --env <name>")
        if name not in self.environments:
            raise StackError(
                f"there is no environment called '{name}' in stack.toml",
                f"valid environments: {listed} -- pass one of them with --env",
            )
        return self.environments[name]


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

    environments_raw = data.get("environments")
    if environments_raw is not None and "nodes" in data:
        raise StackError(
            f"{toml_path} has both top-level [nodes.*] and [environments.*]",
            "with environments, every server belongs to one: move each [nodes.<n>] to "
            "[environments.<env>.nodes.<n>]",
        )

    # With environments, every environment names its own domain and the
    # shared one is optional (validated when present, never used for a
    # server).
    if environments_raw is None or "domain" in data:
        domain = _checked_domain(_require_str(data, "domain", toml_path), "domain")
    else:
        domain = ""
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
    if environments_raw is None or "plan" in data:
        plan = _require_str(data, "plan", toml_path)
    else:
        plan = ""
    price_item = _optional_price_item(data, toml_path)
    auto_patch = _optional_bool(data, "auto_patch", True, toml_path)
    admins = _require_str_list(data, "admins", toml_path)
    nodes = _parse_nodes(data, toml_path) if environments_raw is None else {}
    admin_keys = _load_admin_keys(admins, infra_dir)
    app = _parse_app(data, toml_path)
    backups = _parse_backups(data, toml_path)
    logs = _parse_logs(data, toml_path)
    alerts = _parse_alerts(data, toml_path)
    files = _parse_files(data, toml_path)

    environments: dict[str, Environment] = {}
    if environments_raw is not None:
        shared = Environment(
            name="", domain=domain, plan=plan, price_item=price_item, nodes={},
            backups=backups, logs=logs, alerts=alerts, files=files,
        )
        environments = _parse_environments(environments_raw, shared, toml_path)

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
        logs=logs,
        alerts=alerts,
        files=files,
        environments=environments,
        implicit_env=environments_raw is None,
    )


def environment_names(infra_dir: Path) -> list[str]:
    """The `[environments.*]` names in stack.toml, or [] -- without validating
    anything else.

    The CLI asks this before deciding whether `--env` is required, so a
    command that never needed a valid stack.toml (setting the first secret
    of a brand-new project, say) keeps working on a single-environment
    project. A missing or unreadable file is "no environments": the command
    itself then reports whatever is wrong, as it always has.
    """
    try:
        with (infra_dir / "stack.toml").open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    environments = data.get("environments")
    return list(environments) if isinstance(environments, dict) else []


def _checked_domain(value: str, key: str) -> str:
    return _checked(
        value,
        _DOMAIN_RE,
        key,
        f"{key} must be a DNS name like 'acme.example.com' -- letters, digits, '-' and '.', "
        "with at least two parts",
    )


def _parse_environments(raw: Any, shared: Environment, toml_path: Path) -> dict[str, Environment]:
    if not isinstance(raw, dict) or not raw:
        raise StackError(
            f"{toml_path} has an empty or invalid [environments]",
            "define at least one [environments.<env>] table with a domain and its nodes, or remove "
            "[environments] for a single-environment project",
        )
    environments: dict[str, Environment] = {}
    for name, table in raw.items():
        if not _ENV_RE.match(name):
            raise StackError(
                f"invalid environment name '{name}' in {toml_path}",
                "an environment name becomes part of file names, hostnames and GitHub secret names, so "
                "it must start with a lowercase letter and contain only lowercase letters, digits and "
                "'-' (at most 16 characters) -- e.g. [environments.staging]",
            )
        label = f"environments.{name}"
        if not isinstance(table, dict):
            raise StackError(f"invalid [{label}] in {toml_path}", f"[{label}] must be a table")
        unknown = sorted(set(table) - _ENV_KEYS)
        for section, allowed in _ENV_SECTION_KEYS.items():
            value = table.get(section)
            if value is None:
                continue
            if not isinstance(value, dict):
                raise StackError(
                    f"{toml_path} has an invalid [{label}.{section}]",
                    f"[{label}.{section}] must be a table",
                )
            unknown += [f"{section}.{key}" for key in sorted(set(value) - allowed)]
        if unknown:
            raise StackError(
                f"[{label}] in {toml_path} sets {', '.join(unknown)}, which every environment shares",
                "an environment may only set domain, nodes, plan, price_item, backups.bucket, "
                "backups.retention_days, logs.bucket, logs.retention_days, alerts.to, files.bucket and "
                "files.lock_days -- set anything else once, outside [environments], so staging and "
                "production cannot drift apart",
            )

        if not isinstance(table.get("domain"), str) or not table["domain"].strip():
            raise StackError(f"[{label}] in {toml_path} is missing 'domain'", f'add domain = "..." to [{label}]')
        domain = _checked_domain(table["domain"], f"{label}.domain")
        nodes = _parse_nodes(table, toml_path, label=f"{label}.nodes")

        plan = shared.plan
        if "plan" in table:
            plan = _require_str(table, "plan", toml_path)
        if not plan:
            raise StackError(
                f"{toml_path} has no 'plan' for environment '{name}'",
                f'add a shared plan = "..." key, or plan = "..." in [{label}]',
            )
        price_item = _optional_price_item(table, toml_path) if "price_item" in table else shared.price_item

        environments[name] = Environment(
            name=name,
            domain=domain,
            plan=plan,
            price_item=price_item,
            nodes=nodes,
            backups=_merge(shared.backups, _parse_backups(table, toml_path, table=f"{label}.backups"),
                           table.get("backups")),
            logs=_merge(shared.logs, _parse_logs(table, toml_path, table=f"{label}.logs"), table.get("logs")),
            alerts=_merge(shared.alerts, _parse_alerts(table, toml_path, table=f"{label}.alerts"),
                          table.get("alerts")),
            files=_merge(shared.files, _parse_files(table, toml_path, table=f"{label}.files"),
                         table.get("files")),
        )
    return environments


def _merge(shared: Any, override: Any, raw: dict[str, Any] | None) -> Any:
    """`shared` with every key the environment's table actually set replaced
    by its (already validated) value from `override`."""
    if not raw:
        return shared
    return replace(shared, **{key: getattr(override, key) for key in raw})


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


def _parse_nodes(data: dict[str, Any], toml_path: Path, *, label: str = "nodes") -> dict[str, Node]:
    """`[<label>.<n>]` tables. `label` is "nodes" for a single-environment
    file and "environments.<env>.nodes" for an environment's own servers."""
    nodes_raw = data.get("nodes")
    if not isinstance(nodes_raw, dict) or not nodes_raw:
        raise StackError(
            f"{toml_path} has no nodes" + ("" if label == "nodes" else f" in [{label.rsplit('.', 1)[0]}]"),
            f"define at least one [{label}.<name>] section",
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
                f"[{label}.{name}] must be a table with 'role' (and optional 'vps_id')",
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
            f'set role = "primary" on exactly one [{label}.*] section',
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


def _parse_backups(data: dict[str, Any], toml_path: Path, *, table: str = "backups") -> BackupsConfig:
    raw = data.get("backups")
    if raw is None:
        return BackupsConfig()
    if not isinstance(raw, dict):
        raise StackError(
            f"{toml_path} has an invalid '[{table}]' table",
            f'[{table}] must be a table, e.g. [{table}]\\nbucket = "acme-backups"',
        )
    _reject_unknown_keys(raw, BackupsConfig, f"{toml_path} [{table}]")

    bucket = _optional_bucket(raw, toml_path, table)
    if bucket is not None:
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
                f"{toml_path} has an invalid [{table}].bucket {bucket!r}",
                'a bucket may carry a prefix ("acme-backups/prod") but no empty, "." or ".." '
                'path segment -- ".." would let the nightly prune delete outside the project\'s '
                "own prefix",
            )

    # 1 at the bottom, deliberately: the node deletes with `rclone delete
    # --min-age <retention_days>d`, and a retention of 0 would mean "every
    # object, including the one just written". 3650 (ten years) at the top
    # is an obvious-typo guard, not a policy.
    retention_days = _optional_ranged_int(raw, "retention_days", 1, 3650, toml_path, table=table)

    extra_paths = raw.get("extra_paths")
    if extra_paths is not None:
        if not isinstance(extra_paths, list) or not all(isinstance(item, str) for item in extra_paths):
            raise StackError(
                f"{toml_path} has an invalid [{table}].extra_paths",
                'extra_paths must be a list of absolute paths, e.g. ["/var/lib/acme/uploads"]',
            )
        for item in extra_paths:
            # Interpolated into a root shell command on the node. The
            # module quotes it too; this is the first of those two layers.
            if not item.startswith("/") or any(ch.isspace() for ch in item) or '"' in item or "'" in item:
                raise StackError(
                    f"{toml_path} has an invalid [{table}].extra_paths entry {item!r}",
                    "each entry must be an absolute path with no whitespace or quotes",
                )
        extra_paths = list(extra_paths)

    on_calendar = raw.get("on_calendar")
    if on_calendar is not None and (not isinstance(on_calendar, str) or not _ON_CALENDAR_RE.match(on_calendar)):
        raise StackError(
            f"{toml_path} has an invalid [{table}].on_calendar {on_calendar!r}",
            'on_calendar must be a 24-hour UTC time like "03:00"',
        )

    enabled = _optional_section_bool(raw, "enabled", toml_path, table)

    return BackupsConfig(
        bucket=bucket,
        retention_days=retention_days,
        extra_paths=extra_paths,
        on_calendar=on_calendar,
        enabled=enabled,
    )


def _section(data: dict[str, Any], key: str, cls: type, toml_path: Path, table: str) -> dict[str, Any] | None:
    raw = data.get(key)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise StackError(f"{toml_path} has an invalid '[{table}]' table", f"[{table}] must be a table")
    _reject_unknown_keys(raw, cls, f"{toml_path} [{table}]")
    return raw


def _optional_bucket(raw: dict[str, Any], toml_path: Path, table: str) -> str | None:
    bucket = raw.get("bucket")
    if bucket is not None and (not isinstance(bucket, str) or not _BUCKET_RE.match(bucket)):
        raise StackError(
            f"{toml_path} has an invalid [{table}].bucket {bucket!r}",
            "bucket must match ^[A-Za-z0-9][A-Za-z0-9._/-]{1,127}$ -- the R2 bucket's name",
        )
    return bucket


def _optional_section_bool(raw: dict[str, Any], key: str, toml_path: Path, table: str) -> bool | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, bool):
        raise StackError(
            f"{toml_path} has an invalid [{table}].{key} {value!r}", f"[{table}].{key} must be true or false"
        )
    return value


def _optional_int(raw: dict[str, Any], key: str, toml_path: Path, table: str) -> int | None:
    """Type only: the range each of these may take is its consumer's to check."""
    value = raw.get(key)
    # bool is a subclass of int in Python -- same trap as vps_id above.
    if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
        raise StackError(
            f"{toml_path} has an invalid [{table}].{key} {value!r}", f"[{table}].{key} must be an integer"
        )
    return value


def _parse_logs(data: dict[str, Any], toml_path: Path, *, table: str = "logs") -> LogsConfig:
    raw = _section(data, "logs", LogsConfig, toml_path, table)
    if raw is None:
        return LogsConfig()
    return LogsConfig(
        enabled=_optional_section_bool(raw, "enabled", toml_path, table),
        bucket=_optional_bucket(raw, toml_path, table),
        retention_days=_optional_int(raw, "retention_days", toml_path, table),
    )


def _parse_alerts(data: dict[str, Any], toml_path: Path, *, table: str = "alerts") -> AlertsConfig:
    raw = _section(data, "alerts", AlertsConfig, toml_path, table)
    if raw is None:
        return AlertsConfig()
    to = raw.get("to", [])
    # Type only, plus no whitespace: each entry ends up on a mail command
    # line on the node. Whether it is a deliverable address is not checked.
    if not isinstance(to, list) or not all(
        isinstance(item, str) and item and not any(ch.isspace() for ch in item) for item in to
    ):
        raise StackError(
            f"{toml_path} has an invalid [{table}].to",
            f'[{table}].to must be a list of email addresses, e.g. to = ["ops@example.com"]',
        )
    return AlertsConfig(to=list(to))


def _parse_files(data: dict[str, Any], toml_path: Path, *, table: str = "files") -> FilesConfig:
    raw = _section(data, "files", FilesConfig, toml_path, table)
    if raw is None:
        return FilesConfig()
    return FilesConfig(
        bucket=_optional_bucket(raw, toml_path, table),
        lock_days=_optional_int(raw, "lock_days", toml_path, table),
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
    # Set when a purchase answered HTTP 202 (payment still processing): the
    # subscription id the VM-to-be will carry. While set, the node is never
    # purchased again; it is adopted by this id once the VM shows up, and
    # ADOPT clears it.
    pending_subscription_id: str | None = None


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


def state_path(infra_dir: Path, env: Environment) -> Path:
    """`stack.state.json` for the implicit environment, else `stack.state.<env>.json`."""
    if env.implicit:
        return infra_dir / _STATE_FILENAME
    return infra_dir / f"stack.state.{env.name}.json"


def load_state(infra_dir: Path, env: Environment) -> StackState:
    """Load the environment's state file. A missing file yields an empty state."""
    state_path_ = state_path(infra_dir, env)
    return _load_state_file(state_path_)


def _load_state_file(state_path: Path) -> StackState:
    if not state_path.exists():
        return StackState()

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise StackError(f"{state_path} is not valid JSON", str(e)) from e

    return _state_from_dict(data, state_path)


def save_state(infra_dir: Path, env: Environment, state: StackState) -> None:
    """Atomically write `state` to the environment's state file."""
    state_path_ = state_path(infra_dir, env)
    _save_state_file(state_path_, state)


def _save_state_file(state_path: Path, state: StackState) -> None:
    payload = asdict(state)
    # An unset marker is omitted so a state file that never saw a 202 purchase
    # is byte-identical to what earlier versions wrote.
    for node in payload["nodes"].values():
        if node.get("pending_subscription_id") is None:
            node.pop("pending_subscription_id", None)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"

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
