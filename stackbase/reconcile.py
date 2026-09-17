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
    """The hostname Hostinger records for a node.

    The VPS setup API puts no pattern on `hostname` (its example is an FQDN
    but nothing requires one), so this is the short, readable
    `<project>-<node>` rather than a fake FQDN that would then disagree with
    the real DNS name Cloudflare serves.
    """
    return f"{cfg.project}-{node}"


def primary_node(cfg: StackConfig) -> str:
    """The node the public domain points at. `load_config` guarantees exactly one."""
    for name, node in cfg.nodes.items():
        if node.role == "primary":
            return name
    raise StackError(
        "no primary node is defined",
        'set role = "primary" on exactly one [nodes.*] section in stack.toml',
    )


def observe(
    cfg: StackConfig,
    state: StackState,
    hostinger: HostingerClient,
    cloudflare: CloudflareClient,
    *,
    local: Local,
) -> Observed:
    """Read the current state of the world. GET requests only.

    `local` carries the facts that come from the operator's own disk (see
    `local_facts`); it is passed in rather than gathered here so that
    `observe` stays purely the network-reading half.
    """
    nodes: dict[str, ObservedNode] = {}
    for name, node in cfg.nodes.items():
        nodes[name] = _observe_node(node, state.nodes.get(name), hostinger)

    public_key_ids = _observe_public_keys(cfg, hostinger)
    firewall = _find_named(hostinger.list_firewalls(), firewall_name(cfg))
    firewall_id = firewall.get("id") if firewall else None
    rules_match = bool(firewall) and _rule_keys(firewall.get("rules") or []) == _rule_keys(desired_firewall_rules())

    zone_id, zone_name = cloudflare.zone_for(cfg.domain)
    expected_ip = _expected_primary_ip(cfg, state, nodes)
    record_id, record_matches = _observe_record(cloudflare, zone_id, cfg.domain, expected_ip)

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
    )


def _observe_node(node: Node, node_state: NodeState | None, hostinger: HostingerClient) -> ObservedNode:
    vps_id = node.vps_id or (node_state.vps_id if node_state else None)
    if vps_id is None:
        return ObservedNode()
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

    cert_pending = not observed.local.has_origin_cert
    if cert_pending:
        steps.append(Step(Action.ENSURE_ORIGIN_CERT))

    for name in cfg.nodes:
        if _needs_deploy(state, observed, name, cert_pending):
            steps.append(Step(Action.PUSH_CONFIG, name))
            steps.append(Step(Action.REBUILD, name))

    if not _dns_converged(state, observed):
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

    vps_id = node.vps_id or node_state.vps_id
    if vps_id is None:
        steps.append(Step(Action.PURCHASE, name))
    elif seen.state == "initial":
        steps.append(Step(Action.SETUP, name))

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

    if not node_state.host_key_pinned or (
        node_state.ipv4 and node_state.ipv4 not in observed.local.pinned_hosts
    ):
        steps.append(Step(Action.PIN_HOST_KEY, name))

    if not node_state.hardware_captured or name not in observed.local.captured_nodes:
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
    cloudflare: CloudflareClient
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
