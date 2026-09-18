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
import shlex
import subprocess
from collections import deque
from typing import Callable

from stackbase.backups import backup_env_content, backup_env_digest
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
    app_env_digest,
    compute_rev,
    desired_firewall_rules,
    firewall_name,
    first_address,
    hostname_for,
    primary_node,
    validate_app_env,
)
from stackbase.secrets import save_secrets
from stackbase.ssh import HOST_KEY_CHANGED_MARKER, Ssh, host_key_mismatch_hint

_HPANEL = "check the virtual machine in hPanel (https://hpanel.hostinger.com/)"
_STREAM_TAIL_LINES = 20

# `[ -e "$f" ]` guards the case where the glob matches nothing (the shell
# then leaves the pattern itself in `$f`); the trailing `true` keeps that
# guard's non-zero status from failing the whole command.
_LIST_NIX_FILES = 'for f in /etc/nixos/*.nix; do [ -e "$f" ] && basename "$f"; done; true'

_HARDWARE_FILE = "hardware-configuration.nix"

# Hostinger's NixOS image ships with an EMPTY /etc/nixos (see
# task-8a-brief.md) -- there is nothing to fetch on a node that has never
# been rebuilt with stack-base yet. `nixos-generate-config` is the tool
# NixOS itself ships for exactly this: it prints a hardware-configuration.nix
# derived from the running machine's disks/CPU, with no side effects.
_GENERATE_HARDWARE_CMD = "nixos-generate-config --show-hardware-config"


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


def _adopt(ctx: Context, step: Step) -> str:
    """Record a vps_id `observe()` already found under this node's hostname.

    Non-destructive: this never talks to Hostinger. `observe()` (GET-only)
    already did the lookup and put the vps_id on `ctx.observed.nodes[node]`
    -- ADOPT's only job is to persist it to state instead of buying a second
    server for the same node.
    """
    node = _node(step)
    observed = ctx.observed.nodes.get(node)
    vps_id = observed.vps_id if observed else None
    if vps_id is None:
        raise StackError(
            f"node {node} has no adoptable virtual machine on record",
            "this is a bug in stack-base -- please report it",
        )
    hostname = hostname_for(ctx.cfg, node)
    ctx.emit(
        f"! found an existing server {vps_id} named {hostname} -- adopting it instead of buying another"
    )
    ctx.node_state(node).vps_id = vps_id
    return f"node {node}: adopted existing virtual machine {vps_id} ({hostname})"


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
    node_state = ctx.node_state(node)
    node_state.vps_id = vps_id
    if node_state.host_key_pinned:
        # stack-base itself just reinstalled this machine, so its host key
        # is about to change for a reason stack-base caused -- clear the
        # stale pin here rather than forcing the reinstall-vs-interception
        # decision onto the operator the next time something touches ssh
        # (that decision only belongs to a change stack-base did NOT cause).
        if node_state.ipv4:
            ctx.ssh(node).unpin_host_key()
        node_state.host_key_pinned = False
    # Same reasoning for the hardware files: a reinstall means whatever
    # `infra/nodes/<node>/` holds now describes a machine that no longer
    # exists. `plan()` always plans CAPTURE_HARDWARE alongside SETUP (see
    # `reconcile._provisioning_steps`), but clearing the flag here too keeps
    # this step honest on its own, independent of that caller.
    node_state.hardware_captured = False
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
    """Save the node's disk/CPU facts to `infra/nodes/<node>/`.

    Only `hardware-configuration.nix` is imported by the project's flake. If
    `/etc/nixos` already has one (a provider whose image ships a populated
    `/etc/nixos`, or a node stack-base has already rebuilt at least once),
    today's behaviour is unchanged: fetch every `*.nix` file listed there,
    keeping any sibling `configuration.nix` around as a record.

    Hostinger's own image ships with an EMPTY `/etc/nixos` (see
    task-8a-brief.md) -- nothing to fetch there. In that case, generate the
    hardware facts on the node with `nixos-generate-config
    --show-hardware-config` instead; the boot/network settings that a
    populated `/etc/nixos`'s `configuration.nix` would otherwise have carried
    are supplied declaratively by the provider module
    (`nixos/providers/hostinger.nix`) instead.
    """
    node = _node(step)
    ssh = ctx.ssh(node)
    listing = ssh.run(_LIST_NIX_FILES)
    names = [
        line.strip()
        for line in (listing.stdout or "").splitlines()
        if line.strip().endswith(".nix") and "/" not in line.strip()
    ]

    destination = ctx.infra_dir / "nodes" / node
    destination.mkdir(parents=True, exist_ok=True)

    if _HARDWARE_FILE in names:
        for name in names:
            (destination / name).write_bytes(ssh.fetch(f"/etc/nixos/{name}"))
    else:
        result = ssh.run(_GENERATE_HARDWARE_CMD, check=False)
        output = result.stdout or ""
        if result.returncode != 0 or not output.strip() or "fileSystems" not in output:
            raise StackError(
                f"node {node}: `{_GENERATE_HARDWARE_CMD}` produced no usable hardware-configuration.nix",
                "check that the VPS is really running NixOS (reinstall it from hPanel with the "
                "NixOS template if not)",
            )
        (destination / _HARDWARE_FILE).write_text(output, encoding="utf-8")

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
    try:
        save_secrets(ctx.infra_dir, ctx.secrets)
    except StackError as exc:
        # Cloudflare has already issued the certificate by this point -- a
        # failure to save it locally does not un-issue it. Say so, so the
        # operator doesn't go looking for a cert that silently vanished.
        raise StackError(
            exc.message,
            f"{exc.hint} -- a Cloudflare origin certificate for {domain} was just issued and is "
            "now orphaned (it was never saved to secrets.age); running `up` again will issue a "
            "fresh one, and the orphaned certificate can be revoked in the Cloudflare dashboard -> "
            "SSL/TLS -> Origin Server",
        ) from exc
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

    # Cloudflare is optional (Task 7b). With no token there is no origin
    # cert to push -- `plan()` never plans ENSURE_ORIGIN_CERT in that case
    # either -- so the node just keeps the self-signed placeholder cert its
    # own NixOS module generates.
    if not ctx.secrets.get("cloudflare_token"):
        return f"node {node}: configuration uploaded (no Cloudflare token -- keeping the self-signed placeholder cert)"

    _push_origin_cert(ctx, ssh)
    return f"node {node}: configuration and origin certificate uploaded"


def _push_origin_cert(ctx: Context, ssh: Ssh) -> None:
    """Write the certificate pair, then swap both into place in one command.

    The node runs a oneshot that regenerates a self-signed placeholder pair
    whenever EITHER `origin.crt` or `origin.key` is missing, so the two files
    must never be observably out of step: they are written under `.new` names
    with their final owner and mode, and a single remote command moves the
    key and then the certificate into place. This is two `mv`s, not one --
    a reboot in the narrow window between them would see the new key paired
    with the old certificate (or, on the very first push, a missing
    certificate), so "atomic" here means "as good as two sequential renames
    get", not a guarantee against every possible timing.
    """
    cert = ctx.secrets.get("origin_cert")
    key = ctx.secrets.get("origin_key")
    if not cert or not key:
        raise StackError(
            "the origin certificate is missing from infra/secrets.age",
            "run `up` again -- stack-base creates the certificate before pushing it",
        )

    ssh.run(
        f"set -eu; install -d -m 0750 {shlex.quote(REMOTE_CERT_DIR)}; {_chgrp(REMOTE_CERT_DIR)}"
    )
    ssh.run(_write_pem_command("origin.key.new", "0640"), input=key)
    ssh.run(_write_pem_command("origin.crt.new", "0644"), input=cert)
    ssh.run(
        "set -eu; "
        f"mv {_cert_path('origin.key.new')} {_cert_path('origin.key')}; "
        f"mv {_cert_path('origin.crt.new')} {_cert_path('origin.crt')}; "
        "if systemctl is-active --quiet nginx; then systemctl reload nginx; fi"
    )


def _cert_path(filename: str) -> str:
    return shlex.quote(f"{REMOTE_CERT_DIR}/{filename}")


def _write_pem_command(filename: str, mode: str) -> str:
    path = _cert_path(filename)
    # umask 077 first: the file must never be world-readable even for the
    # instant between creation and chmod.
    return (
        f"set -eu; umask 077; cat > {path}; "
        f"{_chgrp(f'{REMOTE_CERT_DIR}/{filename}')}; chmod {mode} {path}"
    )


def _chgrp(path: str) -> str:
    """Give `path` to the nginx group, failing the step if that cannot be done.

    nginx must be able to read the private key, so a chgrp that fails is not
    something to shrug at: under the enclosing `set -eu` this aborts the push.

    The one legitimate reason for the group to be absent is that the node has
    never been rebuilt -- the nginx group comes into existence with the nginx
    package, and the first push necessarily happens before the first rebuild.
    That case is tested for explicitly and announced on stderr, rather than
    being hidden inside a blanket `|| true` that would swallow a genuine
    permission error too. Left at root:root 0640 the key is strictly more
    private than intended, and nginx's master process reads its certificates
    as root before dropping to the nginx user, so that first rebuild still
    comes up; the next push corrects the group.
    """
    return (
        "if getent group nginx >/dev/null 2>&1; "
        f"then chgrp nginx {shlex.quote(path)}; "
        "else echo 'stackbase: no nginx group yet (this node has never been rebuilt) "
        "- leaving the certificate owned by root' >&2; fi"
    )


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

    returncode, tail = _stream(ctx, ssh, _rebuild_command(ctx, node, "test"))
    if returncode != 0:
        if _tail_has_host_key_changed(tail):
            raise _host_key_mismatch_error(ctx, node)
        raise StackError(
            f"node {node}: the new configuration failed to build or activate",
            _tail_hint(tail, _test_failure_advice(node, tail)),
        )

    probe = ctx.ssh(node).run("true", check=False)  # a NEW connection, on purpose
    if probe.returncode != 0:
        if HOST_KEY_CHANGED_MARKER in (probe.stderr or ""):
            # This is a change stack-base did NOT cause (an operator-side
            # hPanel reinstall, say) -- the plain-English reinstall-vs-
            # interception hint belongs here, not a raw ssh stderr dump that
            # reads like the config itself locked the operator out.
            raise _host_key_mismatch_error(ctx, node)
        raise StackError(
            f"node {node} stopped answering SSH after the new configuration was activated",
            "reboot the VPS from hPanel to return to the previous config, then fix the "
            "configuration in infra/ and run `up` again -- the change was NOT made permanent",
        )

    returncode, tail = _stream(ctx, ssh, _rebuild_command(ctx, node, "switch"))
    if returncode != 0:
        if _tail_has_host_key_changed(tail):
            raise _host_key_mismatch_error(ctx, node)
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


def _tail_has_host_key_changed(tail: list[str]) -> bool:
    return any(HOST_KEY_CHANGED_MARKER in line for line in tail)


def _host_key_mismatch_error(ctx: Context, node: str) -> StackError:
    known_hosts = ctx.infra_dir / "known_hosts"
    ip = ctx.node_state(node).ipv4 or node
    return StackError(
        f"the SSH host key for {ip} does not match the pinned entry in {known_hosts}",
        host_key_mismatch_hint(known_hosts),
    )


_BOOT_GAP_MARKERS = ("boot.loader", "fileSystems")

_REBOOT_ADVICE = (
    "if the server is now unreachable, reboot it from hPanel -- the tested configuration is "
    "discarded on reboot"
)


def _test_failure_advice(node: str, tail: list[str]) -> str:
    """The advice half of the `nixos-rebuild test` failure hint.

    The Hostinger provider module (`nixos/providers/hostinger.nix`) supplies
    `boot.loader.*` and the cloud-init/networkd settings a node needs via
    `mkDefault`, so a first-run `boot.loader`/`fileSystems` gap should now be
    rare -- but a node whose disk or network genuinely differs from those
    defaults (a different provider image, a non-default disk layout) can
    still hit one. When the build output looks like that, point the operator
    at the one escape hatch every node has for exactly this:
    `infra/nodes/<node>/extra.nix`, loaded alongside the provider module's
    defaults and able to override any of them -- rather than the generic "go
    fix infra/" advice.

    Either way, the reboot instruction is appended unconditionally: a
    config that drops networking kills the streaming ssh connection with
    exit 255, landing on this exact path with the node now potentially
    unreachable and running the broken (but not yet permanent) config.
    """
    combined = "\n".join(tail)
    if any(marker in combined for marker in _BOOT_GAP_MARKERS):
        specific = (
            f"this looks like a first-run bootloader/network gap -- override the mismatched "
            f"boot.loader.*/networking.* option(s) in infra/nodes/{node}/extra.nix and run `up` again"
        )
    else:
        specific = "fix the configuration in infra/ and run `up` again -- nothing was made permanent"
    return f"{specific} -- {_REBOOT_ADVICE}"


def _rebuild_command(ctx: Context, node: str, mode: str) -> str:
    """`nixos-rebuild <mode> --flake /etc/nixos/stack#<node>`, safely quoted.

    This string is handed to a root shell on the node, and `node` is a
    stack.toml table key. `load_config` already constrains it, but the flake
    target is quoted here too -- one validation regex should not be the only
    thing standing between a config file and remote code execution. (Note
    there is no `str.format` here either: a brace in `node` would otherwise
    be a second interpolation nobody asked for.)
    """
    target = shlex.quote(f"{REMOTE_CONFIG_DIR}#{node}")
    override = (
        f" --override-input stack-base {shlex.quote(f'path:{REMOTE_SRC_DIR}')}"
        if ctx.stackbase_src
        else ""
    )
    return f"nixos-rebuild {mode} --flake {target}{override}"


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
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            # A rebuild can take minutes; without this, any stray input typed
            # at the terminal in the meantime would be swallowed by the
            # streamed ssh process instead of reaching the shell afterwards.
            stdin=subprocess.DEVNULL,
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


# --------------------------------------------------------------------------
# App environment: push app.env, restart the active color
# --------------------------------------------------------------------------

# Owned by the release engine (nixos/deploy.nix's `stateDir`,
# nixos/deploy/stack-deploy.sh's `ACTIVE_COLOR_FILE`) -- not
# `REMOTE_CERT_DIR`/`/var/lib/stackbase`, which is stack-base's own state.
_DEPLOY_STATE_DIR = "/var/lib/stackbase-deploy"
_ACTIVE_COLOR_FILE = f"{_DEPLOY_STATE_DIR}/active-color"
# Same lock stack-deploy.sh's own acquire_lock takes (nixos/deploy/
# stack-deploy.sh) -- M4: the env-only restart below must not race an
# in-progress blue/green swap that is mid-restart of this very unit.
_DEPLOY_LOCK_FILE = f"{_DEPLOY_STATE_DIR}/deploy.lock"
_VALID_COLORS = frozenset({"blue", "green"})

# Printed by the remote check command itself when active-color genuinely
# does not exist -- distinguishes "no release deployed yet" (legitimate,
# skip the restart) from every other failure (permission denied, an ssh
# hiccup, ...), which must NOT be read as "no release deployed yet" (Fix
# round, B2). Unlikely to collide with anything real; not secret, never
# masked.
_NO_ACTIVE_COLOR_MARKER = "__STACKBASE_NONE__"


def _ensure_app_env(ctx: Context, step: Step) -> str:
    """Push infra/secrets.age's "app_env" to /var/lib/stackbase/app.env, then
    restart the node's currently-active color (if any release has been
    deployed yet).

    Same model as `_push_origin_cert`: the content travels over an ssh stdin
    pipe only -- never a local file, never an argv -- into a temp name
    created with its final owner/mode (`root:<project> 0640`) BEFORE any
    content is written, then `mv -f`d into place.

    Unlike `_chgrp`'s nginx-group case, a missing `<project>` group here is a
    hard failure rather than a warn-and-continue: `plan()` only ever plans
    this step after REBUILD for the node (see `reconcile.plan`), which is
    what creates the group -- so a missing group this late means something
    else has already gone wrong.
    """
    node = _node(step)
    raw = ctx.secrets.get("app_env")
    if not raw:
        raise StackError(
            "infra/secrets.age has no 'app_env' to push",
            "this is a bug in stack-base -- please report it",
        )
    # Validated and normalised before any ssh call: a malformed app_env must
    # never open a connection, let alone reach the node -- and the message
    # never echoes any part of its content.
    normalized = validate_app_env(raw)

    project = ctx.cfg.project
    ssh = ctx.ssh(node)

    group = ssh.run(f"getent group {shlex.quote(project)}", check=False)
    if group.returncode != 0:
        raise StackError(
            f"node {node} has no '{project}' group yet",
            "this step is planned only after REBUILD for the node, which creates the group -- "
            "run `up` again once that has completed",
        )

    tmp_path = _cert_path("app.env.new")
    final_path = _cert_path("app.env")
    ssh.run(f"set -eu; install -m 0640 -o root -g {shlex.quote(project)} /dev/null {tmp_path}")
    ssh.run(f"set -eu; cat > {tmp_path}", input=normalized)
    ssh.run(f"set -eu; mv -f {tmp_path} {final_path}")

    # The restart runs BEFORE app_env_sha is saved (Fix round, B2): the old
    # order saved the digest right here, before the restart even ran, so a
    # restart that failed (or an ambiguous "can't tell" ssh/cat failure that
    # used to be silently read as "no release yet") still left the node
    # converged as far as stack-base's own state was concerned -- the next
    # `up` would see nothing to do and never retry. Now the digest is only
    # ever saved once the restart has genuinely succeeded or was legitimately
    # skipped (no release deployed yet); anything else raises, so a failure
    # here leaves state unchanged and the whole step (push + restart) retries
    # on the next `up`.
    color = _restart_active_color(ctx, ssh, node, project)
    ctx.node_state(node).app_env_sha = app_env_digest(normalized)

    if color:
        return f"node {node}: application environment updated, {color} restarted"
    return f"node {node}: application environment updated"


def _restart_active_color(ctx: Context, ssh: Ssh, node: str, project: str) -> str | None:
    """Restart the node's active color, if a release has ever been deployed.

    The blue/green swap belongs to a release deploy, not to an env-only
    change -- restarting the active color directly here is a brief blip, on
    purpose; a zero-downtime way to roll an env change out is to push it and
    then `deploy` (or re-deploy) a release.

    One remote command distinguishes "active-color genuinely does not exist
    yet" (legitimate -- no release has ever been deployed, so there is
    nothing to restart) from every other failure (permission denied, an ssh
    hiccup, ...): the OLD code treated ANY non-zero exit from `cat` the same
    way, silently swallowing a real failure as if it meant "no release yet"
    -- app_env_sha would then still get saved by the caller, and the restart
    would simply never be retried (Fix round, B2). A failure that isn't the
    file-missing case now raises instead.
    """
    quoted = shlex.quote(_ACTIVE_COLOR_FILE)
    check_cmd = f"if [ -e {quoted} ]; then cat -- {quoted}; else echo {_NO_ACTIVE_COLOR_MARKER}; fi"
    result = ssh.run(check_cmd, check=False)
    if result.returncode != 0:
        raise StackError(
            f"node {node}: could not check whether a release has been deployed yet (exit {result.returncode})",
            "check the node by hand (permissions, connectivity) -- app_env was pushed, but the "
            "currently active release was never restarted; re-run `up` once this is fixed to retry",
        )

    output = (result.stdout or "").strip()
    if output == _NO_ACTIVE_COLOR_MARKER:
        ctx.emit("! no release deployed yet — the new environment applies from the first deploy")
        return None

    color = output
    if color not in _VALID_COLORS:
        # Never interpolate an unvalidated remote string into a command --
        # `systemctl try-restart <garbage>@<garbage>.service` is exactly the
        # kind of thing this refuses to build.
        raise StackError(
            f"node {node}: {_ACTIVE_COLOR_FILE} does not contain 'blue' or 'green'",
            "check the file on the node by hand -- stack-base refuses to restart a service name "
            "it cannot validate",
        )

    unit = f"{project}@{color}.service"
    # M4: run the restart under the SAME deploy.lock stack-deploy.sh itself
    # takes, so this env-only restart can never race a blue/green swap
    # that's mid-restart of this very unit. `flock -w 300` (not `-n`): a
    # deploy in progress is expected to finish in well under 5 minutes, so
    # waiting is the right behaviour here -- unlike stack-deploy.sh's own
    # acquire_lock, which refuses immediately (exit 3) because a second
    # concurrent DEPLOY is a caller mistake, not something to queue behind.
    # `flock` creates the lock file if it doesn't exist yet (running as
    # root here, same as every other steps.py ssh call -- see SSH_USER in
    # reconcile.py); if it truly doesn't exist, no release has ever been
    # deployed, and `_restart_active_color`'s caller already returned
    # before reaching here in that case (see the _NO_ACTIVE_COLOR_MARKER
    # branch above) -- so a missing lock file is never actually reached by
    # this line in practice.
    lock_cmd = f"flock -w 300 {shlex.quote(_DEPLOY_LOCK_FILE)} systemctl try-restart {shlex.quote(unit)}"
    ssh.run(lock_cmd)
    return color


# --------------------------------------------------------------------------
# Backup credentials: push backup.env, root-only
# --------------------------------------------------------------------------


def _ensure_backup_env(ctx: Context, step: Step) -> str:
    """Push the rclone credentials to /var/lib/stackbase/backup.env, 0600 root:root.

    Same model as `_ensure_app_env`: the content travels over an ssh stdin
    pipe only -- never a local file, never an argv -- into a temp name
    created with its final owner/mode BEFORE any content is written, then
    `mv -f`d into place. Root-only, unlike app.env: the app has no business
    reading the bucket's credentials, and neither has `deploy`.

    Nothing is restarted: the backup unit reads this file when the timer
    next fires (or when `./infra/up backup-now` runs it).
    """
    node = _node(step)
    content = backup_env_content(ctx.secrets)
    if not content:
        raise StackError(
            "infra/secrets.age has no complete set of R2 credentials to push",
            "this is a bug in stack-base -- please report it",
        )

    ssh = ctx.ssh(node)
    tmp_path = _cert_path("backup.env.new")
    final_path = _cert_path("backup.env")
    ssh.run(f"set -eu; install -d -m 0750 {shlex.quote(REMOTE_CERT_DIR)}")
    ssh.run(f"set -eu; install -m 0600 -o root -g root /dev/null {tmp_path}")
    ssh.run(f"set -eu; cat > {tmp_path}", input=content)
    ssh.run(f"set -eu; mv -f {tmp_path} {final_path}")

    # Recorded only after the final `mv -f` has succeeded: a failure any
    # earlier leaves state untouched, so the next `up` replans the step
    # rather than calling a node with no (or half-written) credentials
    # converged.
    ctx.node_state(node).backup_env_sha = backup_env_digest(content)
    return f"node {node}: backup credentials updated"


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
    Action.ADOPT: _adopt,
    Action.SETUP: _setup,
    Action.WAIT_RUNNING: _wait_running,
    Action.ENSURE_KEYS: _ensure_keys,
    Action.ENSURE_FIREWALL: _ensure_firewall,
    Action.PIN_HOST_KEY: _pin_host_key,
    Action.CAPTURE_HARDWARE: _capture_hardware,
    Action.ENSURE_ORIGIN_CERT: _ensure_origin_cert,
    Action.PUSH_CONFIG: _push_config,
    Action.REBUILD: _rebuild,
    Action.ENSURE_APP_ENV: _ensure_app_env,
    Action.ENSURE_BACKUP_ENV: _ensure_backup_env,
    Action.UPSERT_DNS: _upsert_dns,
}
