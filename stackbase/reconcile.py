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

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
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
PUSH_EXCLUDES = ("secrets.age", ".git", "__pycache__", "known_hosts", "result")

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


def local_facts(infra_dir: Path, secrets: dict[str, str], *, stackbase_src: str | None = None) -> Local:
    """Gather everything `plan()` needs that lives on the operator's disk.

    `desired_rev` is the fingerprint a node records once it has successfully
    rebuilt -- see `compute_rev`.
    """
    return Local(
        desired_rev=compute_rev(infra_dir, stackbase_src=stackbase_src),
        has_origin_cert=bool(secrets.get("origin_cert")) and bool(secrets.get("origin_key")),
        pinned_hosts=_pinned_hosts(infra_dir / "known_hosts"),
        captured_nodes=_captured_nodes(infra_dir / "nodes"),
        has_cloudflare_token=bool(secrets.get("cloudflare_token")),
    )


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
    """Every file under `root` that is not inside (or named) an excluded entry."""
    banned = set(excludes)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in banned)
        for name in sorted(filenames):
            if name not in banned:
                found.append(Path(dirpath) / name)
    return found


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
        return [value for value in self.secrets.values() if value]

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
            ctx.emit(f"→ {step.description}…")
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
