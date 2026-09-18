"""The reconciler: look at the world, decide what to do, then do it.

Three phases, deliberately kept apart:

- `observe()` reads. It issues **GET requests only** -- that is what makes
  `up --plan` safe to run against production at any time.
- `plan()` decides. It is **pure**: given the config, the recorded state and
  what `observe()` saw, it returns an ordered list of `Step`s and touches
  nothing. Every step is check-then-act, so a converged stack plans `[]` and
  a run that failed half way through re-plans exactly the remainder.
- `apply()` acts. It runs the steps in order, saving `stack.state.json`
  after each one, so an interrupted run never loses what it already did.

Facts that only exist at apply time (a node's IP address, which is only
known after `WAIT_RUNNING`) are NOT baked into the plan: a step carries the
node's *name* and looks the address up in state when it runs.

The step executors themselves live in `stackbase/steps.py` -- this module is
the decision logic, that one is the doing.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

from stackbase.cloudflare import CloudflareClient
from stackbase.config import Node, NodeState, StackConfig, StackState, save_state
from stackbase.errors import StackError
from stackbase.hostinger import HostingerClient
from stackbase.secrets import redact
from stackbase.ssh import Ssh

# nixos/cloudflare-ips.nix, located relative to this package -- present in
# stack-base's own checkout (whether run from $STACKBASE_SRC or the cached
# pinned rev), never shipped into a consuming project's infra/.
_CLOUDFLARE_IPS_NIX = Path(__file__).resolve().parent.parent / "nixos" / "cloudflare-ips.nix"
_CIDR_RE = re.compile(r'"([0-9A-Fa-f:.]+/\d+)"')

# The node is reached as root: the NixOS base module keeps key-only root
# login and gives root every admin's key, because the very first rebuild
# happens before any admin account exists on the box.
SSH_USER = "root"

REMOTE_CONFIG_DIR = "/etc/nixos/stack"
REMOTE_SRC_DIR = "/etc/nixos/stack-base"
REMOTE_CERT_DIR = "/var/lib/stackbase"

# Everything under infra/ is pushed to the node except these. `secrets.age`
# must never leave the operator's machine; `keys/*.pub` MUST be pushed -- the
# node's flake reads them to build its admin accounts. `known_hosts` is the
# operator's own trust store, not node configuration (pushing it would also
# make every newly pinned node look like a config change to every other one).
#
# "secrets.age*" (M6, a glob, not just the exact name): secrets.py's own
# save_secrets() writes through a same-directory temp file
# "secrets.age.<pid>.tmp" before the atomic rename -- a crash mid-save could
# leave one of those behind, and it must never reach the node or feed the
# tree digest either. `tree_files`/`_tree_digest` below match every entry
# here with `fnmatch`, not exact string equality, so a glob pattern excludes
# what it looks like it excludes.
PUSH_EXCLUDES = ("secrets.age*", ".git", "__pycache__", "known_hosts", "result")

# In dev mode the local stack-base checkout is pushed too, minus its own
# working clutter.
SRC_EXCLUDES = (".git", ".superpowers", "__pycache__", "result")

# stack.state.json is pushed (it costs nothing and keeps the node's copy of
# infra/ complete) but deliberately does not feed the applied-rev hash: it
# changes on every single step, and a rebuild per state write would be absurd.
_REV_SKIP = ("stack.state.json",)


class Action(Enum):
    """Every kind of work the reconciler can do.

    There is deliberately no member for deleting, destroying or cancelling
    anything -- `tests/test_no_delete.py` asserts that, so a future
    "CANCEL_VM" can never be added by accident.
    """

    PURCHASE = "purchase"
    ADOPT = "adopt"
    SETUP = "setup"
    WAIT_RUNNING = "wait_running"
    ENSURE_KEYS = "ensure_keys"
    ENSURE_FIREWALL = "ensure_firewall"
    PIN_HOST_KEY = "pin_host_key"
    CAPTURE_HARDWARE = "capture_hardware"
    ENSURE_ORIGIN_CERT = "ensure_origin_cert"
    PUSH_CONFIG = "push_config"
    REBUILD = "rebuild"
    ENSURE_APP_ENV = "ensure_app_env"
    UPSERT_DNS = "upsert_dns"


# What each step is doing, in the words of someone who does not run
# infrastructure for a living. These are printed verbatim by `--plan`.
_DOING: dict[Action, str] = {
    Action.PURCHASE: "buying and setting up a new virtual machine",
    Action.ADOPT: "adopting an existing virtual machine already found in Hostinger",
    Action.SETUP: "installing NixOS on the virtual machine",
    Action.WAIT_RUNNING: "waiting for the server to come up",
    Action.ENSURE_KEYS: "registering the team's SSH keys with Hostinger",
    Action.ENSURE_FIREWALL: "applying the firewall (SSH and HTTPS only)",
    Action.PIN_HOST_KEY: "remembering the server's SSH fingerprint",
    Action.CAPTURE_HARDWARE: "copying the server's disk and boot settings into infra/nodes",
    Action.ENSURE_ORIGIN_CERT: "creating the Cloudflare origin certificate",
    Action.PUSH_CONFIG: "uploading the configuration and the origin certificate",
    Action.REBUILD: "rebuilding NixOS (this can take a few minutes)",
    Action.ENSURE_APP_ENV: "updating the application's environment file",
    Action.UPSERT_DNS: "pointing the domain at the server in Cloudflare",
}

# Steps worth announcing before they start, because the operator would
# otherwise watch a still terminal for minutes wondering if it hung.
_SLOW = frozenset(
    {Action.PURCHASE, Action.SETUP, Action.WAIT_RUNNING, Action.PUSH_CONFIG, Action.REBUILD}
)


@dataclass(frozen=True)
class Step:
    """One unit of work, optionally scoped to a node."""

    action: Action
    node: str | None = None

    @property
    def description(self) -> str:
        doing = _DOING[self.action]
        return f"node {self.node}: {doing}" if self.node else doing

    @property
    def is_slow(self) -> bool:
        return self.action in _SLOW


def render_description(step: Step, *, has_cloudflare_token: bool) -> str:
    """The text `--plan` and `apply()`'s progress line print for one step.

    Identical to `step.description`, except for PUSH_CONFIG with no
    Cloudflare token: `plan()` never plans ENSURE_ORIGIN_CERT in that case
    (Task 7b), so PUSH_CONFIG never actually has an origin certificate to
    upload either -- see `steps.py::_push_config`'s own no-token wording,
    which this matches.
    """
    if step.action is Action.PUSH_CONFIG and not has_cloudflare_token:
        doing = "uploading the configuration"
        return f"node {step.node}: {doing}" if step.node else doing
    return step.description


# --------------------------------------------------------------------------
# Local facts
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Local:
    """What the operator's own machine knows, with no network involved."""

    desired_rev: str
    has_origin_cert: bool
    pinned_hosts: frozenset[str]
    captured_nodes: frozenset[str]
    # True when `secrets.age` decrypted to a non-empty "cloudflare_token".
    # Cloudflare is optional (Task 7b): with no token, `observe()` is never
    # given a `CloudflareClient` and `plan()` must not emit ENSURE_ORIGIN_CERT
    # or UPSERT_DNS. Defaults to True so every existing caller that builds a
    # `Local` without naming this field keeps today's (token-present)
    # behaviour byte-for-byte.
    has_cloudflare_token: bool = True
    # sha256 of the validated, normalised "app_env" secret, or None when
    # secrets.age has no "app_env" key at all. `plan()` compares this against
    # each node's recorded `NodeState.app_env_sha` -- see `_needs_app_env`.
    # Computed here (not inside `plan()`) so `plan()` stays pure and never
    # reads `secrets` itself; validated here too, so a malformed app_env
    # fails fast (one plain-English line, nothing echoed) on every `up`
    # invocation, `--plan` included, rather than surfacing later at push time.
    app_env_sha: str | None = None


def local_facts(infra_dir: Path, secrets: dict[str, str], *, stackbase_src: str | None = None) -> Local:
    """Gather everything `plan()` needs that lives on the operator's disk.

    `desired_rev` is the fingerprint a node records once it has successfully
    rebuilt -- see `compute_rev`.
    """
    app_env_raw = secrets.get("app_env")
    return Local(
        desired_rev=compute_rev(infra_dir, stackbase_src=stackbase_src),
        has_origin_cert=bool(secrets.get("origin_cert")) and bool(secrets.get("origin_key")),
        pinned_hosts=_pinned_hosts(infra_dir / "known_hosts"),
        captured_nodes=_captured_nodes(infra_dir / "nodes"),
        has_cloudflare_token=bool(secrets.get("cloudflare_token")),
        app_env_sha=app_env_digest(validate_app_env(app_env_raw)) if app_env_raw else None,
    )


_APP_ENV_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")

# I1: keys the systemd unit template (nixos/deploy.nix) sets itself, per
# color, and that an app_env line must never be allowed to override.
# SOCKET_PATH is the one that actually matters today (the whole blue/green
# split depends on each color listening on its own socket -- a stray
# `SOCKET_PATH=...` line would otherwise silently collapse both colors onto
# one path); this stays a set, not a single constant, so a future reserved
# key can be added here without touching the check itself. Enforced here so
# every caller (secrets set/edit, and the push-time check in
# reconcile.local_facts) rejects it before it ever reaches a node -- the
# unit's own `env SOCKET_PATH=...` in its ExecStart is the belt-and-braces
# second layer (nixos/deploy.nix), for the case a value already on a node
# predates this check.
_APP_ENV_RESERVED_KEYS = frozenset({"SOCKET_PATH"})

# Any individual app_env VALUE shorter than this is not masked from output --
# short strings (a port number, "true", a single digit) are too likely to
# appear incidentally in unrelated text, and masking them would make normal
# output unreadable for no real protection.
_APP_ENV_MIN_REDACT_LEN = 8


def validate_app_env(raw: str) -> str:
    """Validate the "app_env" secret and normalise it to one trailing newline.

    Every non-blank, non-comment ("#") line must look like `NAME=value`
    (`NAME` starting with a letter or underscore). Raises `StackError` on any
    violation -- the message names the problem, never the offending line or
    any part of its content, per the global "secrets are never echoed" rule.
    """
    if "\x00" in raw:
        raise StackError(
            "infra/secrets.age's 'app_env' contains a NUL byte",
            "app_env must be plain KEY=value lines, one per line -- fix it and re-encrypt secrets.age",
        )
    for line_number, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _APP_ENV_LINE_RE.match(stripped)
        if not match:
            # The line NUMBER is safe to name -- the content never is (per
            # the global "secrets are never echoed" rule).
            raise StackError(
                f"infra/secrets.age's 'app_env' has a line that is not KEY=value (line {line_number})",
                "every non-blank, non-comment line must look like NAME=value (NAME starting with "
                "a letter or underscore) -- fix it and re-encrypt secrets.age",
            )
        key = match.group(1)
        if key in _APP_ENV_RESERVED_KEYS:
            # Name the KEY (never the value -- per the global "secrets are
            # never echoed" rule, and the key name itself isn't secret).
            raise StackError(
                f"infra/secrets.age's 'app_env' sets '{key}' (line {line_number}), which is reserved",
                f"'{key}' is set by the systemd unit itself, per color -- remove this line from "
                "app_env and re-encrypt secrets.age",
            )
    return raw.rstrip("\n") + "\n"


def app_env_digest(normalized_app_env: str) -> str:
    """sha256 hex digest of an already-`validate_app_env`-normalised string."""
    return hashlib.sha256(normalized_app_env.encode("utf-8")).hexdigest()


def _app_env_secret_values(raw: str) -> list[str]:
    """Every individual VALUE inside "app_env" worth masking from output.

    Parsed leniently (never raises): this feeds `redact()`, not validation,
    and a still-malformed app_env deserves whatever protection can be
    salvaged from it, not an exception on top of the one `validate_app_env`
    will already raise elsewhere.
    """
    values = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        value = stripped.split("=", 1)[1]
        if len(value) >= _APP_ENV_MIN_REDACT_LEN:
            values.append(value)
    return values


def redaction_values(secrets: dict[str, str]) -> list[str]:
    """Every string that must never appear in printed output.

    Every top-level secret value (Hostinger/Cloudflare tokens, the origin
    certificate key, the whole "app_env" blob, ...) plus -- because app_env
    is itself a bundle of KEY=value secrets -- each individual value inside
    it (see `_app_env_secret_values`). `Context.secret_values` (used by
    every `ctx.emit()` call during `apply()`) is built from this; the CLI's
    own top-level error/traceback/--plan printing in `stackbase/__main__.py`
    currently masks only via a plain `list(secrets.values())` and would need
    to switch to this function to get the same per-value app_env coverage.
    """
    values = [value for value in secrets.values() if value]
    values.extend(_app_env_secret_values(secrets.get("app_env") or ""))
    return values


def compute_rev(infra_dir: Path, *, stackbase_src: str | None = None) -> str:
    """The fingerprint of everything a node would be given.

    A hash over every file that would be pushed, combined with the stack-base
    version in play (the locked rev from `infra/flake.lock`, or -- in dev
    mode -- a hash of the local checkout, which changes as you edit it). A
    node whose recorded `applied_rev` equals it needs no push and no rebuild.

    It is recomputed when the rebuild records it, not reused from planning
    time: `CAPTURE_HARDWARE` writes into `infra/` mid-run, so the tree that
    actually gets pushed is not always the tree the run was planned against.

    This hashes all of `infra/` as one tree, not per-node -- so capturing
    node b's hardware (which writes into `infra/nodes/b/`) changes the rev
    for every node, including node a. That triggers a harmless no-op rebuild
    on node a the next time it runs (its own configuration hasn't actually
    changed), which is the price of a single project-wide fingerprint rather
    than per-node bookkeeping.
    """
    digest = hashlib.sha256()
    digest.update(_tree_digest(infra_dir, PUSH_EXCLUDES, skip=_REV_SKIP).encode("utf-8"))
    if stackbase_src:
        digest.update(b"src:")
        digest.update(_tree_digest(Path(stackbase_src), SRC_EXCLUDES).encode("utf-8"))
    else:
        digest.update(b"lock:")
        digest.update(locked_stack_base_rev(infra_dir).encode("utf-8"))
    return digest.hexdigest()


def locked_stack_base_rev(infra_dir: Path) -> str:
    """The stack-base commit pinned by `infra/flake.lock`."""
    lock_path = infra_dir / "flake.lock"
    if not lock_path.exists():
        raise StackError(
            f"{lock_path} is missing and $STACKBASE_SRC is not set",
            "commit an infra/flake.lock (stack-base writes one for you after the first successful "
            "rebuild), or set $STACKBASE_SRC to a local stack-base checkout to run against that",
        )
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StackError(f"{lock_path} is not valid JSON", str(exc)) from exc

    rev = _locked_rev_from(lock)
    if rev is None:
        raise StackError(
            f"{lock_path} does not pin a 'stack-base' input",
            "re-create the lock file, or set $STACKBASE_SRC to a local stack-base checkout",
        )
    return rev


def _locked_rev_from(lock: dict[str, Any]) -> str | None:
    nodes = lock.get("nodes")
    if not isinstance(nodes, dict):
        return None
    root = nodes.get(lock.get("root", "root"))
    ref = root.get("inputs", {}).get("stack-base") if isinstance(root, dict) else None
    if isinstance(ref, list):
        ref = ref[0] if ref else None
    node = nodes.get(ref) if isinstance(ref, str) else None
    if not isinstance(node, dict):
        node = nodes.get("stack-base")
    locked = node.get("locked") if isinstance(node, dict) else None
    rev = locked.get("rev") if isinstance(locked, dict) else None
    return rev if isinstance(rev, str) else None


def tree_files(root: Path, excludes: Iterable[str]) -> list[Path]:
    """Every file under `root` that is not inside (or named) an excluded entry.

    Each `excludes` entry is matched with `fnmatch` (M6), not exact string
    equality -- every entry today is a plain literal name (no glob
    metacharacters), for which `fnmatch` behaves identically to exact
    equality, except for `PUSH_EXCLUDES`' "secrets.age*", which is
    deliberately a glob so it also catches `secrets.py`'s own
    "secrets.age.<pid>.tmp" write-ahead temp file.
    """
    patterns = list(excludes)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if not _matches_any_exclude(name, patterns))
        for name in sorted(filenames):
            if not _matches_any_exclude(name, patterns):
                found.append(Path(dirpath) / name)
    return found


def _matches_any_exclude(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _tree_digest(root: Path, excludes: Iterable[str], *, skip: Iterable[str] = ()) -> str:
    skipped = set(skip)
    digest = hashlib.sha256()
    for path in tree_files(root, excludes):
        relative = path.relative_to(root).as_posix()
        if relative in skipped:
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        except OSError:
            # A file that vanished between the walk and the read can't be
            # pushed either -- treat it as absent rather than crashing.
            continue
    return digest.hexdigest()


def _pinned_hosts(known_hosts: Path) -> frozenset[str]:
    if not known_hosts.exists():
        return frozenset()
    hosts = set()
    for line in known_hosts.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            hosts.add(stripped.split()[0])
    return frozenset(hosts)


def _captured_nodes(nodes_dir: Path) -> frozenset[str]:
    if not nodes_dir.is_dir():
        return frozenset()
    return frozenset(
        child.name for child in nodes_dir.iterdir() if (child / "hardware-configuration.nix").exists()
    )


# --------------------------------------------------------------------------
# The working-tree guard
# --------------------------------------------------------------------------

# Paths under infra/ that stack-base WRITES ITSELF during a run. A
# modification to any of these is expected mid-run (CAPTURE_HARDWARE,
# _fetch_lock_file, save_state, pin_host_key, deploy-key init), never an
# operator's half-finished edit -- matched with fnmatch, relative to the
# infra directory.
TOOL_WRITTEN_PATHS = (
    "nodes/*/hardware-configuration.nix",
    "flake.lock",
    "stack.state.json",
    "known_hosts",
    "keys/*.pub",
    "*.age",
)

_DIRTY_SUFFIX = ".nix"
_DIRTY_NAMES = ("stack.toml",)


def check_infra_clean(
    infra_dir: Path,
    *,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
) -> None:
    """Refuse to push a working tree nobody has committed.

    What `up` puts on a server is the working tree, not HEAD: `_push_config`
    rsyncs `infra/` as it is on disk. That is convenient while iterating and
    dangerous afterwards -- an uncommitted `conf.d/*.nix` or a locally-edited
    `stack.toml` produces a server nobody else can reproduce, and the next
    teammate's `up` silently reverts it.

    Only files that change what a node BUILDS are considered: `*.nix`
    anywhere under infra/, and `stack.toml`. Everything stack-base writes
    itself (`TOOL_WRITTEN_PATHS`) is exempt, because a run legitimately
    modifies those while it is in flight.

    Not a git checkout at all (or no git installed) -- warn once and
    proceed: stack-base works fine without version control, it just cannot
    make this particular promise.
    """
    repo_dir = infra_dir.parent
    try:
        result = runner(
            # --untracked-files=all: WITHOUT it, git collapses a directory
            # that has NO tracked file at all into one record ("?? infra/
            # conf.d/" -- trailing slash, no filename) instead of listing
            # each file inside it. `_dirty_infra_paths` below would then
            # read an empty path and drop the record, silently missing a
            # project's very first conf.d module -- exactly the scenario
            # this whole check exists to catch. -uall forces git to always
            # list every untracked file individually, never a directory.
            [
                "git", "-C", str(repo_dir), "status", "--porcelain",
                "--untracked-files=all", "-z", "--", str(infra_dir),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        emit("! git was not found -- skipping the check for uncommitted changes under infra/")
        return

    if result.returncode != 0:
        emit("! infra/ is not inside a git repository -- skipping the check for uncommitted changes")
        return

    offenders = sorted(_dirty_infra_paths(result.stdout or "", repo_dir=repo_dir, infra_dir=infra_dir))
    if not offenders:
        return

    raise StackError(
        f"infra/ has uncommitted changes that would be pushed to the servers: {', '.join(offenders)}",
        "what `up` pushes is your WORKING TREE, not the last commit -- commit them first so the "
        "next person's run reproduces this server, or re-run with --allow-dirty",
    )


def _dirty_infra_paths(porcelain_z: str, *, repo_dir: Path, infra_dir: Path) -> set[str]:
    """Paths from `git status --porcelain -z` that stack-base did not write itself.

    `-z` output is NUL-separated `XY <path>` records with NO quoting or
    escaping (unlike the default, where a path with a space or a non-ASCII
    byte comes back quoted). A rename or copy record (`R`/`C`) is followed
    by ONE extra field holding the source path -- consumed here, so its
    first two characters are never mistaken for a status code.
    """
    fields = deque(field for field in porcelain_z.split("\0") if field)
    dirty: set[str] = set()
    while fields:
        record = fields.popleft()
        status, path = record[:2], record[3:]
        if status[:1] in ("R", "C") and fields:
            fields.popleft()  # the rename/copy SOURCE path
        if not path:
            continue
        name = path.rsplit("/", 1)[-1]
        if not (name.endswith(_DIRTY_SUFFIX) or name in _DIRTY_NAMES):
            continue
        try:
            relative = (repo_dir / path).relative_to(infra_dir).as_posix()
        except ValueError:
            continue  # not under infra/ after all
        if not any(fnmatch.fnmatch(relative, pattern) for pattern in TOOL_WRITTEN_PATHS):
            dirty.add(relative)
    return dirty


# --------------------------------------------------------------------------
# Observation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservedNode:
    vps_id: int | None = None
    state: str | None = None
    actions_lock: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    firewall_group_id: int | None = None
    # True when `vps_id` was not found in stack.toml/state.json but was
    # discovered on Hostinger by hostname -- see `_find_adoptable_vms`. This
    # is what tells `plan()` to emit ADOPT instead of PURCHASE.
    adopted: bool = False


@dataclass(frozen=True)
class Observed:
    local: Local
    nodes: dict[str, ObservedNode]
    public_key_ids: dict[str, int]
    firewall_id: int | None = None
    firewall_rules_match: bool = False
    zone_id: str | None = None
    zone_name: str | None = None
    record_id: str | None = None
    record_matches: bool = False
    # GET-only, informational: differences between Cloudflare's live edge
    # ranges and the snapshot in nixos/cloudflare-ips.nix. Never fatal --
    # see `_cloudflare_ip_warnings`.
    cloudflare_ip_warnings: list[str] = field(default_factory=list)


def firewall_name(cfg: StackConfig) -> str:
    """One firewall per project, shared by all of its nodes."""
    return f"stackbase-{cfg.project}"


def desired_firewall_rules() -> list[dict[str, str]]:
    """SSH and HTTPS from anywhere -- nothing else reaches the box.

    443 is open to the world at the Hostinger edge on purpose: nginx on the
    node refuses any connection whose real TCP peer is not a Cloudflare
    address (nixos/app-host.nix), and that list is ~20 CIDRs that Cloudflare
    changes without notice. Mirroring it into two places would mean a stale
    copy locking us out of our own origin.
    """
    return [
        {"protocol": "TCP", "port": "22", "source": "any", "source_detail": "any"},
        {"protocol": "TCP", "port": "443", "source": "any", "source_detail": "any"},
    ]


def hostname_for(cfg: StackConfig, node: str) -> str:
    """The hostname Hostinger records for a node -- must be an FQDN.

    Learned live (L5): the OpenAPI doc's example `hostname` happens to be an
    FQDN but states no pattern requiring one, so a short `<project>-<node>`
    form (the original design here) went unnoticed until a real setup call
    rejected it with "Wrong hostname FQDN format". Verified live:
    `<project>-<node>.<domain>` is accepted (e.g.
    `stack-demo-a.stack-demo.techspace.asia`).

    This is the Hostinger-side hostname only, used for setup/purchase and
    for matching an already-existing VM during ADOPT (`_find_adoptable_vms`
    below). It is unrelated to the NixOS `networking.hostName` the template
    flake sets from the node's bare table key (e.g. "a") -- that stays
    short and is not changed by this.
    """
    return f"{cfg.project}-{node}.{cfg.domain}"


def primary_node(cfg: StackConfig) -> str:
    """The node the public domain points at. `load_config` guarantees exactly one."""
    for name, node in cfg.nodes.items():
        if node.role == "primary":
            return name
    raise StackError(
        "no primary node is defined",
        'set role = "primary" on exactly one [nodes.*] section in stack.toml',
    )


def _cloudflare_ips_path() -> Path:
    """A seam for tests -- production always wants `_CLOUDFLARE_IPS_NIX`."""
    return _CLOUDFLARE_IPS_NIX


def _snapshot_cloudflare_ranges() -> frozenset[str] | None:
    """The CIDRs currently baked into nixos/cloudflare-ips.nix, or `None` if missing."""
    path = _cloudflare_ips_path()
    if not path.exists():
        return None
    return frozenset(_CIDR_RE.findall(path.read_text(encoding="utf-8")))


def _cloudflare_ip_warnings(cloudflare: CloudflareClient) -> list[str]:
    """Compare Cloudflare's live edge ranges against nixos/cloudflare-ips.nix.

    GET-only and never fatal: nginx's allow-list (app-host.nix) is built from
    the static snapshot, so if Cloudflare has changed its published ranges
    since the snapshot was last updated, visitors arriving via a brand new
    range would get a 403 until stack-base is updated -- worth a loud
    warning, never worth failing the run over. A missing snapshot file (e.g.
    running against a stripped-down checkout) or a failed fetch both skip
    silently/with-a-warning rather than raise.
    """
    snapshot = _snapshot_cloudflare_ranges()
    if snapshot is None:
        return []

    try:
        live_v4, live_v6 = cloudflare.ip_ranges()
    except StackError as exc:
        return [
            f"could not fetch Cloudflare's current IP ranges to check against "
            f"nixos/cloudflare-ips.nix ({exc}) -- skipping the check this run"
        ]

    live = frozenset(live_v4) | frozenset(live_v6)
    if live == snapshot:
        return []

    added = sorted(live - snapshot)
    removed = sorted(snapshot - live)
    parts = []
    if added:
        parts.append(f"added: {', '.join(added)}")
    if removed:
        parts.append(f"removed: {', '.join(removed)}")
    return [
        "Cloudflare's published edge IP ranges have changed since nixos/cloudflare-ips.nix was "
        f"last updated ({'; '.join(parts)}) -- visitors arriving via a new range will get 403 "
        "until stack-base's nginx allow-list is updated"
    ]


def observe(
    cfg: StackConfig,
    state: StackState,
    hostinger: HostingerClient,
    cloudflare: CloudflareClient | None,
    *,
    local: Local,
) -> Observed:
    """Read the current state of the world. GET requests only.

    `local` carries the facts that come from the operator's own disk (see
    `local_facts`); it is passed in rather than gathered here so that
    `observe` stays purely the network-reading half.

    `cloudflare` is `None` when `secrets.age` has no Cloudflare token (Task
    7b: Cloudflare is optional). In that case NOT ONE Cloudflare request is
    made -- no zone lookup, no A-record lookup, no `/ips` range check -- and
    the Cloudflare-shaped fields on the returned `Observed` are left at their
    "nothing configured yet" defaults.
    """
    unresolved_nodes = [
        name
        for name, node in cfg.nodes.items()
        if node.vps_id is None and (state.nodes.get(name) is None or state.nodes[name].vps_id is None)
    ]
    adoptable = _find_adoptable_vms(hostinger, cfg, unresolved_nodes) if unresolved_nodes else {}

    nodes: dict[str, ObservedNode] = {}
    for name, node in cfg.nodes.items():
        nodes[name] = _observe_node(node, state.nodes.get(name), hostinger, adopt_vps_id=adoptable.get(name))

    public_key_ids = _observe_public_keys(cfg, hostinger)
    firewall = _find_named(hostinger.list_firewalls(), firewall_name(cfg))
    firewall_id = firewall.get("id") if firewall else None
    rules_match = bool(firewall) and _rule_keys(firewall.get("rules") or []) == _rule_keys(desired_firewall_rules())

    if cloudflare is None:
        zone_id = zone_name = record_id = None
        record_matches = False
        cloudflare_ip_warnings: list[str] = []
    else:
        zone_id, zone_name = cloudflare.zone_for(cfg.domain)
        expected_ip = _expected_primary_ip(cfg, state, nodes)
        record_id, record_matches = _observe_record(cloudflare, zone_id, cfg.domain, expected_ip)
        cloudflare_ip_warnings = _cloudflare_ip_warnings(cloudflare)

    return Observed(
        local=local,
        nodes=nodes,
        public_key_ids=public_key_ids,
        firewall_id=firewall_id,
        firewall_rules_match=rules_match,
        zone_id=zone_id,
        zone_name=zone_name,
        record_id=record_id,
        record_matches=record_matches,
        cloudflare_ip_warnings=cloudflare_ip_warnings,
    )


def _find_adoptable_vms(
    hostinger: HostingerClient, cfg: StackConfig, node_names: list[str]
) -> dict[str, int]:
    """For nodes with no `vps_id` anywhere, look for an already-existing
    Hostinger VM whose hostname matches what stack-base would have named it
    (`hostname_for`) -- most often the result of a PURCHASE whose response
    was lost (network error, killed run, ...) after the charge already went
    through. Exactly one match makes that node adoptable, so `plan()` can
    emit ADOPT instead of PURCHASE. More than one match is ambiguous --
    stack-base will not guess which one belongs to this project, and raises
    (this is still a GET-only read, not a write).
    """
    wanted = {hostname_for(cfg, name): name for name in node_names}
    if not wanted:
        return {}

    by_hostname: dict[str, list[int]] = {}
    for vm in hostinger.list_vms():
        hostname = vm.get("hostname")
        vps_id = vm.get("id")
        if isinstance(hostname, str) and isinstance(vps_id, int) and hostname in wanted:
            by_hostname.setdefault(hostname, []).append(vps_id)

    found: dict[str, int] = {}
    for hostname, ids in by_hostname.items():
        name = wanted[hostname]
        if len(ids) > 1:
            raise StackError(
                f"found {len(ids)} existing virtual machines named '{hostname}' in Hostinger",
                f"put the right one's id in stack.toml as vps_id for node '{name}' -- stack-base "
                "will not guess which one to adopt",
            )
        found[name] = ids[0]
    return found


def _observe_node(
    node: Node,
    node_state: NodeState | None,
    hostinger: HostingerClient,
    *,
    adopt_vps_id: int | None = None,
) -> ObservedNode:
    vps_id = node.vps_id or (node_state.vps_id if node_state else None)
    if vps_id is None:
        if adopt_vps_id is None:
            return ObservedNode()
        vm = hostinger.get_vm(adopt_vps_id)
        return ObservedNode(
            vps_id=adopt_vps_id,
            state=vm.get("state"),
            actions_lock=vm.get("actions_lock"),
            ipv4=first_address(vm.get("ipv4")),
            ipv6=first_address(vm.get("ipv6")),
            firewall_group_id=vm.get("firewall_group_id"),
            adopted=True,
        )
    vm = hostinger.get_vm(vps_id)
    return ObservedNode(
        vps_id=vps_id,
        state=vm.get("state"),
        actions_lock=vm.get("actions_lock"),
        ipv4=first_address(vm.get("ipv4")),
        ipv6=first_address(vm.get("ipv6")),
        firewall_group_id=vm.get("firewall_group_id"),
    )


def _observe_public_keys(cfg: StackConfig, hostinger: HostingerClient) -> dict[str, int]:
    registered = {
        key["key"].strip(): key["id"]
        for key in hostinger.list_public_keys()
        if isinstance(key.get("key"), str) and "id" in key
    }
    found: dict[str, int] = {}
    for admin, key in cfg.admin_keys.items():
        key_id = registered.get(key.strip())
        if key_id is not None:
            found[admin] = key_id
    return found


def _observe_record(
    cloudflare: CloudflareClient, zone_id: str, domain: str, expected_ip: str | None
) -> tuple[str | None, bool]:
    records = cloudflare.find_a_records(zone_id, domain)
    if len(records) != 1:
        # Zero means "create it"; more than one is ambiguous and
        # `upsert_a_record` refuses to guess -- either way, not converged.
        return None, False
    record = records[0]
    matches = bool(expected_ip) and record.get("content") == expected_ip and record.get("proxied") is True
    return record.get("id"), matches


def _expected_primary_ip(
    cfg: StackConfig, state: StackState, nodes: dict[str, ObservedNode]
) -> str | None:
    name = primary_node(cfg)
    observed = nodes.get(name)
    if observed and observed.ipv4:
        return observed.ipv4
    node_state = state.nodes.get(name)
    return node_state.ipv4 if node_state else None


def first_address(addresses: Any) -> str | None:
    """`[{"id": 1, "address": "1.2.3.4"}]` -> `"1.2.3.4"`."""
    if not isinstance(addresses, list):
        return None
    for entry in addresses:
        if isinstance(entry, dict) and isinstance(entry.get("address"), str):
            return entry["address"]
    return None


def _find_named(items: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for item in items:
        if item.get("name") == name:
            return item
    return None


def _rule_keys(rules: list[dict[str, Any]]) -> set[tuple[str, str, str, str]]:
    return {
        (
            str(rule.get("protocol")),
            str(rule.get("port")),
            str(rule.get("source", "any")),
            str(rule.get("source_detail", rule.get("source", "any"))),
        )
        for rule in rules
        if isinstance(rule, dict)
    }


# --------------------------------------------------------------------------
# Planning -- pure
# --------------------------------------------------------------------------


def plan(cfg: StackConfig, state: StackState, observed: Observed) -> list[Step]:
    """Decide what still has to happen. No I/O, no mutation, no surprises.

    Ordering: every node is fully provisioned (bought/installed, running,
    firewalled, pinned, hardware captured) before anything is deployed, the
    origin certificate is created once for the whole stack, then each node is
    pushed and rebuilt, and only at the very end does DNS point the domain at
    the primary node -- so the name never resolves to a box that isn't
    serving yet.
    """
    steps: list[Step] = []

    if not _keys_converged(cfg, state, observed):
        steps.append(Step(Action.ENSURE_KEYS))

    for name, node in cfg.nodes.items():
        steps.extend(_provisioning_steps(state, observed, name, node))

    # Cloudflare is optional (Task 7b): with no token, `observed.local` says
    # so and neither the origin cert nor DNS is ever planned -- the node
    # keeps its self-signed placeholder cert and is reachable by IP/SSH only.
    has_cloudflare = observed.local.has_cloudflare_token
    cert_pending = has_cloudflare and not observed.local.has_origin_cert
    if cert_pending:
        steps.append(Step(Action.ENSURE_ORIGIN_CERT))

    for name in cfg.nodes:
        if _needs_deploy(state, observed, name, cert_pending):
            steps.append(Step(Action.PUSH_CONFIG, name))
            steps.append(Step(Action.REBUILD, name))
        # After REBUILD for this node (when one was just planned): the
        # <project> group and the app@<color> units only exist once the node
        # has rebuilt at least once. Absent "app_env" secret (app_env_sha is
        # None) plans nothing and removes nothing -- see `_needs_app_env`.
        if _needs_app_env(state, observed, name):
            steps.append(Step(Action.ENSURE_APP_ENV, name))

    if has_cloudflare and not _dns_converged(state, observed):
        steps.append(Step(Action.UPSERT_DNS, primary_node(cfg)))

    return steps


def _keys_converged(cfg: StackConfig, state: StackState, observed: Observed) -> bool:
    return all(
        observed.public_key_ids.get(admin) is not None
        and state.hostinger.ssh_key_ids.get(admin) == observed.public_key_ids.get(admin)
        for admin in cfg.admins
    )


def _provisioning_steps(state: StackState, observed: Observed, name: str, node: Node) -> list[Step]:
    node_state = state.nodes.get(name) or NodeState()
    seen = observed.nodes.get(name) or ObservedNode()
    steps: list[Step] = []
    # True whenever SETUP gets planned for this node below (whether it's a
    # known vps_id whose VM is back in state "initial", or a just-adopted
    # one that was never installed). A SETUP stack-base performs itself
    # reinstalls the box: the host key WILL change and any previously
    # captured hardware files describe a machine that no longer exists, so
    # both PIN_HOST_KEY and CAPTURE_HARDWARE must be planned in the same
    # run regardless of what the (now-stale) "already converged" checks
    # below would otherwise conclude. See `steps._setup`, which unpins the
    # host key and clears `hardware_captured` for exactly this reason.
    setup_planned = False

    vps_id = node.vps_id or node_state.vps_id
    if vps_id is None:
        if seen.adopted and seen.vps_id is not None:
            # A vps_id turned up under this node's expected hostname (most
            # likely a PURCHASE whose response never made it back) -- record
            # it rather than buying a second server.
            steps.append(Step(Action.ADOPT, name))
            if seen.state == "initial":
                # The adopted VM was never installed. Plan SETUP (and
                # everything after it) in this same run rather than ADOPT +
                # a bare WAIT_RUNNING, which would sit out the 15-minute
                # running timeout waiting for a state transition that will
                # never happen without SETUP.
                steps.append(Step(Action.SETUP, name))
                setup_planned = True
        else:
            steps.append(Step(Action.PURCHASE, name))
    elif seen.state == "initial":
        steps.append(Step(Action.SETUP, name))
        setup_planned = True

    running = seen.state == "running" and seen.actions_lock == "unlocked"
    if steps or not running or not node_state.ipv4 or node_state.ipv4 != seen.ipv4:
        steps.append(Step(Action.WAIT_RUNNING, name))

    if (
        observed.firewall_id is None
        or not observed.firewall_rules_match
        or state.hostinger.firewall_id != observed.firewall_id
        or seen.firewall_group_id != observed.firewall_id
    ):
        steps.append(Step(Action.ENSURE_FIREWALL, name))

    # PIN_HOST_KEY is replanned when: it was never pinned; the recorded IP
    # isn't in known_hosts; the OBSERVED IP differs from the recorded one
    # (the server moved -- a new IP means a host key that was never pinned
    # for that address); the observed IP itself isn't in known_hosts yet;
    # or SETUP was just planned (a reinstall we caused invalidates whatever
    # was pinned before, even if it still looks valid by every other check).
    ip_drifted = bool(seen.ipv4) and seen.ipv4 != node_state.ipv4
    known_ips = {ip for ip in (node_state.ipv4, seen.ipv4) if ip}
    if (
        not node_state.host_key_pinned
        or ip_drifted
        or setup_planned
        or any(ip not in observed.local.pinned_hosts for ip in known_ips)
    ):
        steps.append(Step(Action.PIN_HOST_KEY, name))

    if not node_state.hardware_captured or setup_planned or name not in observed.local.captured_nodes:
        steps.append(Step(Action.CAPTURE_HARDWARE, name))

    return steps


def _needs_deploy(state: StackState, observed: Observed, name: str, cert_pending: bool) -> bool:
    node_state = state.nodes.get(name) or NodeState()
    return cert_pending or node_state.applied_rev != observed.local.desired_rev


def _needs_app_env(state: StackState, observed: Observed, name: str) -> bool:
    """True when secrets.age has an "app_env" whose sha differs from what
    this node last had pushed. `app_env_sha is None` means no "app_env" key
    at all -- deliberately not a step, and deliberately not a removal (see
    `Local.app_env_sha`'s docstring and the README's "app_env" section)."""
    desired = observed.local.app_env_sha
    if desired is None:
        return False
    node_state = state.nodes.get(name) or NodeState()
    return node_state.app_env_sha != desired


def _dns_converged(state: StackState, observed: Observed) -> bool:
    return bool(
        state.cloudflare.zone_id
        and state.cloudflare.record_id
        and observed.record_matches
        and state.cloudflare.record_id == observed.record_id
    )


# --------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------


@dataclass
class Context:
    """Everything a step executor needs, with every side effect injectable.

    `runner`/`popen` are the subprocess entry points (ssh, rsync, openssl,
    and the streamed nixos-rebuild); `connector` opens the TCP probe that
    waits for sshd; `out` is where operator-facing lines go; `isatty`
    answers "is a human watching?" for the purchase confirmation. Tests
    replace all of them, which is why nothing in this package ever has to
    reach a real server to be exercised.
    """

    infra_dir: Path
    cfg: StackConfig
    state: StackState
    secrets: dict[str, str]
    hostinger: HostingerClient
    cloudflare: CloudflareClient | None
    observed: Observed
    stackbase_src: str | None = None
    runner: Any = subprocess.run
    popen: Any = subprocess.Popen
    connector: Any = socket.create_connection
    out: Callable[[str], None] = print
    isatty: Callable[[], bool] = field(default=lambda: sys.stdin.isatty())

    @property
    def local(self) -> Local:
        return self.observed.local

    @property
    def secret_values(self) -> list[str]:
        return redaction_values(self.secrets)

    def emit(self, line: str) -> None:
        """Print one line, with every known secret masked out first."""
        self.out(redact(line, self.secret_values))

    def node_state(self, name: str) -> NodeState:
        """The recorded state for `name`, created empty on first use."""
        return self.state.nodes.setdefault(name, NodeState())

    def ssh(self, name: str) -> Ssh:
        """A fresh Ssh for `name`. Each call is a new connection, by design."""
        ipv4 = self.node_state(name).ipv4
        if not ipv4:
            raise StackError(
                f"node {name} has no known IP address yet",
                "run `up` again -- the address is recorded once the server is running",
            )
        return Ssh(self.infra_dir, ipv4, user=SSH_USER, runner=self.runner)


def apply(
    steps: list[Step],
    ctx: Context,
    *,
    allow_purchase: bool,
    confirm: Callable[[str], str] = input,
) -> StackState:
    """Run `steps` in order, saving state after each one that succeeds.

    Anything that would spend money is gated first, before a single request
    goes out: if the run is not authorised to buy, it fails having changed
    nothing at all.
    """
    from stackbase import steps as step_executors  # deferred: steps.py imports this module

    purchases = [step for step in steps if step.action is Action.PURCHASE]
    if purchases:
        _authorise_purchase(ctx, purchases, allow_purchase=allow_purchase, confirm=confirm)

    for step in steps:
        if step.is_slow:
            ctx.emit(f"→ {render_description(step, has_cloudflare_token=ctx.local.has_cloudflare_token)}…")
        message = step_executors.execute(ctx, step)
        save_state(ctx.infra_dir, ctx.state)
        ctx.emit(f"✓ {message}")

    return ctx.state


def _authorise_purchase(
    ctx: Context,
    purchases: list[Step],
    *,
    allow_purchase: bool,
    confirm: Callable[[str], str],
) -> None:
    """Both gates on spending money: the flag, and a human typing the words.

    Asked once for the whole run, which is why the phrase carries a count.
    Nothing here issues a request, so a refusal leaves the account untouched.
    """
    names = ", ".join(step.node or "?" for step in purchases)
    count = len(purchases)

    if not allow_purchase:
        raise StackError(
            f"node(s) {names} have no vps_id, so a server would have to be bought",
            "re-run with --allow-purchase if you really want to buy one (stack-base can never "
            "cancel a server -- do that in hPanel)",
        )

    if not ctx.cfg.price_item:
        raise StackError(
            "buying a server needs a price_item in stack.toml",
            "copy the Hostinger catalog price-item id (e.g. hostingercom-vps-kvm1-usd-1m) into "
            "price_item, or set vps_id on the node if you already own the server",
        )

    if not ctx.isatty():
        raise StackError(
            "buying a server needs a confirmation typed at a terminal",
            "run this by hand in a terminal -- stack-base will not spend money from a script or CI job",
        )

    phrase = f"buy {ctx.cfg.plan} x{count}"
    ctx.emit(f"About to buy {count} x {ctx.cfg.plan} from Hostinger for node(s) {names}.")
    ctx.emit("This charges the account on file and cannot be undone by stack-base.")
    answer = confirm(f"Type exactly '{phrase}' to go ahead: ")
    if answer.strip() != phrase:
        raise StackError(
            "the purchase was not confirmed, so nothing was bought",
            f"re-run and type exactly: {phrase}",
        )
