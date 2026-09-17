"""Step executors: the half of the reconciler that actually changes things.

One function per `reconcile.Action`, each taking `(ctx, step)` and returning
the one line the operator sees when it succeeds. Every one of them is
check-then-act (or delegates to a client method that is), so re-running after
a failure converges rather than duplicating work.

Two rules run through all of them:

- **Secrets never touch the disk in plaintext.** The origin private key is
  generated on stdout, held in memory, encrypted back into `secrets.age`, and
  written to the node over an ssh stdin pipe. It is never a local file, never
  a command-line argument, and never printed.
- **Nothing is ever deleted.** No executor cancels a server, removes a DNS
  record or drops a firewall. The only destructive verbs here are rsync's
  `--delete` inside `/etc/nixos/stack` (a directory stack-base owns outright)
  and `mv` over a certificate stack-base itself wrote.
"""

from __future__ import annotations

import re
import subprocess
from collections import deque
from typing import Callable

from stackbase.errors import StackError
from stackbase.reconcile import (
    PUSH_EXCLUDES,
    REMOTE_CERT_DIR,
    REMOTE_CONFIG_DIR,
    REMOTE_SRC_DIR,
    SRC_EXCLUDES,
    Action,
    Context,
    Step,
    compute_rev,
    desired_firewall_rules,
    firewall_name,
    first_address,
    hostname_for,
    primary_node,
)
from stackbase.secrets import save_secrets
from stackbase.ssh import Ssh

_HPANEL = "check the virtual machine in hPanel (https://hpanel.hostinger.com/)"
_STREAM_TAIL_LINES = 20

# `[ -e "$f" ]` guards the case where the glob matches nothing (the shell
# then leaves the pattern itself in `$f`); the trailing `true` keeps that
# guard's non-zero status from failing the whole command.
_LIST_NIX_FILES = 'for f in /etc/nixos/*.nix; do [ -e "$f" ] && basename "$f"; done; true'

_HARDWARE_FILE = "hardware-configuration.nix"


def execute(ctx: Context, step: Step) -> str:
    """Run one step and return the line describing what it did."""
    executor = _EXECUTORS.get(step.action)
    if executor is None:  # pragma: no cover - every Action is in the table
        raise StackError(
            f"no executor for step '{step.action.value}'",
            "this is a bug in stack-base -- please report it",
        )
    return executor(ctx, step)


# --------------------------------------------------------------------------
# Hostinger: buy, install, wait, keys, firewall
# --------------------------------------------------------------------------


def _purchase(ctx: Context, step: Step) -> str:
    node = _node(step)
    inline_key, extra_ids = _admin_keys(ctx)
    vps_id, warnings = ctx.hostinger.purchase_vm(
        price_item=ctx.cfg.price_item or "",
        template_id=ctx.hostinger.template_id("NixOS"),
        data_center_id=ctx.hostinger.data_center_id(ctx.cfg.datacenter),
        hostname=hostname_for(ctx.cfg, node),
        public_key=inline_key,
        public_key_ids=extra_ids,
    )
    _warn(ctx, warnings)
    ctx.node_state(node).vps_id = vps_id
    return f"node {node}: bought and installed virtual machine {vps_id}"


def _setup(ctx: Context, step: Step) -> str:
    node = _node(step)
    vps_id = _vps_id(ctx, node)
    inline_key, extra_ids = _admin_keys(ctx)
    warnings = ctx.hostinger.setup_vm(
        vps_id,
        template_id=ctx.hostinger.template_id("NixOS"),
        data_center_id=ctx.hostinger.data_center_id(ctx.cfg.datacenter),
        hostname=hostname_for(ctx.cfg, node),
        public_key=inline_key,
        public_key_ids=extra_ids,
    )
    _warn(ctx, warnings)
    ctx.node_state(node).vps_id = vps_id
    return f"node {node}: NixOS installed on virtual machine {vps_id}"


def _wait_running(ctx: Context, step: Step) -> str:
    node = _node(step)
    vps_id = _vps_id(ctx, node)
    vm = ctx.hostinger.wait_running(vps_id)

    node_state = ctx.node_state(node)
    node_state.vps_id = vps_id
    node_state.ipv4 = first_address(vm.get("ipv4"))
    node_state.ipv6 = first_address(vm.get("ipv6"))
    if not node_state.ipv4:
        raise StackError(
            f"virtual machine {vps_id} is running but has no IPv4 address",
            _HPANEL + " -- stack-base needs an IPv4 address to reach it",
        )

    # Hostinger calls a VM "running" as soon as it has booted, which is a
    # little before sshd is accepting connections. Every step after this one
    # talks SSH, so wait for the port here rather than letting the next step
    # fail on a box that was simply 20 seconds from ready.
    ctx.ssh(node).wait_port(connector=ctx.connector)
    return f"node {node}: running at {node_state.ipv4}, accepting SSH"


def _ensure_keys(ctx: Context, _step: Step) -> str:
    for admin in ctx.cfg.admins:
        key_id = ctx.hostinger.ensure_public_key(admin, ctx.cfg.admin_keys[admin])
        ctx.state.hostinger.ssh_key_ids[admin] = key_id
    listed = ", ".join(ctx.cfg.admins)
    return f"SSH keys registered with Hostinger for {listed}"


def _ensure_firewall(ctx: Context, step: Step) -> str:
    node = _node(step)
    firewall_id = ctx.hostinger.ensure_firewall(firewall_name(ctx.cfg), desired_firewall_rules())
    ctx.state.hostinger.firewall_id = firewall_id
    ctx.hostinger.activate_firewall(firewall_id, _vps_id(ctx, node))
    return f"node {node}: firewall up to date (SSH and HTTPS only)"


def _admin_keys(ctx: Context) -> tuple[tuple[str, str], list[int]]:
    """The first admin's key to send inline, plus ids for everyone else's.

    Hostinger's setup/purchase body takes exactly one inline key, and that is
    the one the OS installer itself writes -- the only login that does not
    depend on a follow-up API call landing. The rest are attached afterwards
    by id, which is allowed to fail without losing the machine.
    """
    admins = ctx.cfg.admins
    if not admins:
        raise StackError(
            "stack.toml lists no admins",
            "add at least one name to `admins` and a matching infra/keys/<name>.pub",
        )
    first = admins[0]
    inline = (first, ctx.cfg.admin_keys[first])
    registered = ctx.state.hostinger.ssh_key_ids
    extras = [registered[admin] for admin in admins[1:] if admin in registered]
    return inline, extras


def _warn(ctx: Context, warnings: list[str]) -> None:
    for warning in warnings:
        ctx.emit(f"! {warning}")


# --------------------------------------------------------------------------
# SSH: pin the host key, capture the hardware config
# --------------------------------------------------------------------------


def _pin_host_key(ctx: Context, step: Step) -> str:
    node = _node(step)
    ctx.ssh(node).pin_host_key()
    ctx.node_state(node).host_key_pinned = True
    return f"node {node}: SSH fingerprint recorded in infra/known_hosts"


def _capture_hardware(ctx: Context, step: Step) -> str:
    """Copy the node's own `/etc/nixos/*.nix` into `infra/nodes/<node>/`.

    Only `hardware-configuration.nix` is imported by the project's flake, but
    the provider's `configuration.nix` is kept alongside it: it is the only
    record of any boot/network settings the image needed, and folding those
    into `nodes/<node>/extra.nix` is how an operator would fix a node that
    won't boot after the first rebuild.
    """
    node = _node(step)
    ssh = ctx.ssh(node)
    listing = ssh.run(_LIST_NIX_FILES)
    names = [
        line.strip()
        for line in (listing.stdout or "").splitlines()
        if line.strip().endswith(".nix") and "/" not in line.strip()
    ]
    if _HARDWARE_FILE not in names:
        raise StackError(
            f"node {node} has no /etc/nixos/{_HARDWARE_FILE}",
            "stack-base needs the provider's disk and boot settings -- check that the VPS really "
            "is running NixOS (reinstall it from hPanel with the NixOS template if not)",
        )

    destination = ctx.infra_dir / "nodes" / node
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        (destination / name).write_bytes(ssh.fetch(f"/etc/nixos/{name}"))

    ctx.node_state(node).hardware_captured = True
    return f"node {node}: disk and boot settings saved to infra/nodes/{node}/ (commit them)"


# --------------------------------------------------------------------------
# Cloudflare: origin certificate and DNS
# --------------------------------------------------------------------------


def _ensure_origin_cert(ctx: Context, _step: Step) -> str:
    """Mint the origin certificate nginx serves, without the key ever hitting disk.

    One `openssl req` produces the private key and the certificate request on
    the same stdout; both are split apart in memory. The key goes straight
    into `secrets.age` (encrypted) and, at push time, into an ssh stdin pipe.
    """
    domain = ctx.cfg.domain
    key_pem, csr_pem = _generate_key_and_csr(ctx, domain)
    cert_pem = ctx.cloudflare.create_origin_cert([domain], csr_pem)

    # Recorded in ctx.secrets *before* saving, so that from this moment on
    # every printed line and every error message masks the new key too.
    ctx.secrets["origin_cert"] = cert_pem
    ctx.secrets["origin_key"] = key_pem
    save_secrets(ctx.infra_dir, ctx.secrets)
    return f"origin certificate for {domain} created and stored in infra/secrets.age"


def _generate_key_and_csr(ctx: Context, domain: str) -> tuple[str, str]:
    argv = [
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", f"/CN={domain}",
        "-keyout", "/dev/stdout",
        "-out", "/dev/stdout",
    ]
    try:
        result = ctx.runner(argv, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise StackError(
            "the 'openssl' command was not found",
            "install openssl (e.g. `apt install openssl`, `brew install openssl`)",
        ) from exc

    if result.returncode != 0:
        raise StackError(
            "could not generate the certificate's private key",
            _tail(result.stderr or "") or "openssl failed with no output -- re-run with --debug",
        )

    stdout = result.stdout or ""
    key_pem = _extract_pem(stdout, "PRIVATE KEY")
    csr_pem = _extract_pem(stdout, "CERTIFICATE REQUEST")
    if key_pem is None or csr_pem is None:
        raise StackError(
            "openssl did not return both a private key and a certificate request",
            "check that `openssl req` works on this machine -- re-run with --debug for details",
        )
    return key_pem, csr_pem


def _extract_pem(text: str, label: str) -> str | None:
    pattern = re.compile(
        rf"-----BEGIN (?:[A-Z0-9 ]+ )?{label}-----.*?-----END (?:[A-Z0-9 ]+ )?{label}-----\n?",
        re.DOTALL,
    )
    match = pattern.search(text)
    return match.group(0) if match else None


def _upsert_dns(ctx: Context, step: Step) -> str:
    node = step.node or primary_node(ctx.cfg)
    ipv4 = ctx.node_state(node).ipv4
    if not ipv4:
        raise StackError(
            f"node {node} has no IP address to point {ctx.cfg.domain} at",
            "run `up` again -- the address is recorded once the server is running",
        )

    zone_id = ctx.observed.zone_id or ctx.cloudflare.zone_for(ctx.cfg.domain)[0]
    record_id = ctx.cloudflare.upsert_a_record(zone_id, ctx.cfg.domain, ipv4, proxied=True)
    ctx.state.cloudflare.zone_id = zone_id
    ctx.state.cloudflare.record_id = record_id
    return f"{ctx.cfg.domain} now points at node {node} ({ipv4}), proxied by Cloudflare"


# --------------------------------------------------------------------------
# Deploy: push the configuration, rebuild NixOS
# --------------------------------------------------------------------------


def _push_config(ctx: Context, step: Step) -> str:
    node = _node(step)
    ssh = ctx.ssh(node)

    ssh.rsync_to(ctx.infra_dir, REMOTE_CONFIG_DIR, delete=True, exclude=list(PUSH_EXCLUDES))
    if ctx.stackbase_src:
        ssh.rsync_to(ctx.stackbase_src, REMOTE_SRC_DIR, delete=True, exclude=list(SRC_EXCLUDES))

    _push_origin_cert(ctx, ssh)
    return f"node {node}: configuration and origin certificate uploaded"


def _push_origin_cert(ctx: Context, ssh: Ssh) -> None:
    """Write the certificate pair, then swap both into place in one command.

    The node runs a oneshot that regenerates a self-signed placeholder pair
    whenever EITHER `origin.crt` or `origin.key` is missing, so the two files
    must never be observably out of step: they are written under `.new` names
    with their final owner and mode, and a single remote command moves the
    key and then the certificate into place. A reboot at any instant during
    this sees either both placeholders or both real files.
    """
    cert = ctx.secrets.get("origin_cert")
    key = ctx.secrets.get("origin_key")
    if not cert or not key:
        raise StackError(
            "the origin certificate is missing from infra/secrets.age",
            "run `up` again -- stack-base creates the certificate before pushing it",
        )

    ssh.run(f"set -eu; install -d -m 0750 {REMOTE_CERT_DIR}; {_chgrp(REMOTE_CERT_DIR)}")
    ssh.run(_write_pem_command("origin.key.new", "0640"), input=key)
    ssh.run(_write_pem_command("origin.crt.new", "0644"), input=cert)
    ssh.run(
        f"set -eu; mv {REMOTE_CERT_DIR}/origin.key.new {REMOTE_CERT_DIR}/origin.key; "
        f"mv {REMOTE_CERT_DIR}/origin.crt.new {REMOTE_CERT_DIR}/origin.crt; "
        "if systemctl is-active --quiet nginx; then systemctl reload nginx; fi"
    )


def _write_pem_command(filename: str, mode: str) -> str:
    path = f"{REMOTE_CERT_DIR}/{filename}"
    # umask 077 first: the file must never be world-readable even for the
    # instant between creation and chmod.
    return f"set -eu; umask 077; cat > {path}; {_chgrp(path)}; chmod {mode} {path}"


def _chgrp(path: str) -> str:
    # On a freshly installed node the first push happens before nginx has
    # ever been built, so the nginx group does not exist yet. Failing to set
    # the group is harmless (nginx's master process reads the key as root)
    # and the next run fixes it, so this must not abort the push.
    return f"chgrp nginx {path} 2>/dev/null || true"


def _rebuild(ctx: Context, step: Step) -> str:
    """Test the new configuration, prove SSH still works, and only then switch.

    `nixos-rebuild test` activates the configuration without making it the
    boot default. If that activation breaks networking or sshd, a reboot
    brings the old configuration back. So between `test` and `switch` we open
    a brand new connection and run `true`: if that fails, the configuration
    is locking us out and `switch` -- which would make it permanent -- is
    never issued.
    """
    node = _node(step)
    ssh = ctx.ssh(node)
    override = f" --override-input stack-base path:{REMOTE_SRC_DIR}" if ctx.stackbase_src else ""
    command = f"nixos-rebuild {{mode}} --flake {REMOTE_CONFIG_DIR}#{node}{override}"

    returncode, tail = _stream(ctx, ssh, command.format(mode="test"))
    if returncode != 0:
        raise StackError(
            f"node {node}: the new configuration failed to build or activate",
            _tail_hint(tail, "fix the configuration in infra/ and run `up` again -- nothing was made permanent"),
        )

    probe = ctx.ssh(node).run("true", check=False)  # a NEW connection, on purpose
    if probe.returncode != 0:
        raise StackError(
            f"node {node} stopped answering SSH after the new configuration was activated",
            "reboot the VPS from hPanel to return to the previous config, then fix the "
            "configuration in infra/ and run `up` again -- the change was NOT made permanent",
        )

    returncode, tail = _stream(ctx, ssh, command.format(mode="switch"))
    if returncode != 0:
        raise StackError(
            f"node {node}: making the new configuration permanent failed",
            _tail_hint(tail, "the node is still running the tested configuration -- fix infra/ and run `up` again"),
        )

    # Recomputed here rather than reused from planning time: CAPTURE_HARDWARE
    # writes into infra/ earlier in the same run, so the tree that was just
    # pushed is not necessarily the tree the run was planned against. And
    # recorded BEFORE the lock file is fetched: if that fetch changes
    # infra/flake.lock, the node genuinely is out of date again, and the next
    # run should say so rather than call a stale node converged.
    ctx.node_state(node).applied_rev = compute_rev(ctx.infra_dir, stackbase_src=ctx.stackbase_src)
    if ctx.stackbase_src:
        _fetch_lock_file(ctx, ssh)
    return f"node {node}: NixOS rebuilt and switched"


def _stream(ctx: Context, ssh: Ssh, command: str) -> tuple[int, list[str]]:
    """Run `command` on the node, echoing its output line by line as it arrives.

    A rebuild takes minutes; a silent terminal looks like a hang. Every line
    goes through `ctx.emit`, so build output that happens to contain a token
    is masked before the operator (or their scrollback) ever sees it.
    """
    argv = [*ssh.argv(), command]
    try:
        # bufsize=1 is line buffering: without it the output arrives in 8KB
        # bursts, which for a ten-minute build means ten minutes of nothing
        # followed by a wall of text.
        process = ctx.popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
    except FileNotFoundError as exc:
        raise StackError(
            "the 'ssh' command was not found",
            "install openssh-client (e.g. `apt install openssh-client`, `brew install openssh`)",
        ) from exc

    tail: deque[str] = deque(maxlen=_STREAM_TAIL_LINES)
    with process:
        if process.stdout is not None:
            for line in process.stdout:
                line = line.rstrip("\n")
                ctx.emit(line)
                tail.append(line)
        returncode = process.wait()
    return returncode, list(tail)


def _fetch_lock_file(ctx: Context, ssh: Ssh) -> None:
    """Bring the node's `flake.lock` home so it can be committed.

    Dev mode runs against a local checkout, so the operator may have no Nix
    at all and no way to write a lock file themselves. If the node has one,
    it belongs in the repository. If it doesn't -- which is the normal case
    when the inputs were overridden -- say so and move on; it is not a
    failure of the deploy that just succeeded.
    """
    try:
        raw = ssh.fetch(f"{REMOTE_CONFIG_DIR}/flake.lock")
    except StackError:
        raw = b""
    if not raw.strip():
        ctx.emit("! the node did not produce a flake.lock (expected in dev mode) -- infra/flake.lock unchanged")
        return
    (ctx.infra_dir / "flake.lock").write_bytes(raw)
    ctx.emit("✓ infra/flake.lock updated from the node -- commit it")


def _tail_hint(tail: list[str], advice: str) -> str:
    text = "\n".join(tail).strip()
    return f"{text}\n{advice}" if text else advice


def _tail(text: str, lines: int = 5) -> str:
    kept = [line for line in text.splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _node(step: Step) -> str:
    if not step.node:
        raise StackError(
            f"step '{step.action.value}' is missing a node name",
            "this is a bug in stack-base -- please report it",
        )
    return step.node


def _vps_id(ctx: Context, node: str) -> int:
    configured = ctx.cfg.nodes[node].vps_id if node in ctx.cfg.nodes else None
    vps_id = configured or ctx.node_state(node).vps_id
    if vps_id is None:
        raise StackError(
            f"node {node} has no virtual machine yet",
            "run `up --allow-purchase` to buy one, or set its vps_id in stack.toml if you "
            "already own the server",
        )
    return vps_id


_EXECUTORS: dict[Action, Callable[[Context, Step], str]] = {
    Action.PURCHASE: _purchase,
    Action.SETUP: _setup,
    Action.WAIT_RUNNING: _wait_running,
    Action.ENSURE_KEYS: _ensure_keys,
    Action.ENSURE_FIREWALL: _ensure_firewall,
    Action.PIN_HOST_KEY: _pin_host_key,
    Action.CAPTURE_HARDWARE: _capture_hardware,
    Action.ENSURE_ORIGIN_CERT: _ensure_origin_cert,
    Action.PUSH_CONFIG: _push_config,
    Action.REBUILD: _rebuild,
    Action.UPSERT_DNS: _upsert_dns,
}
