"""Cloudflare Mesh: joining a node, laptop side.

The daemon is `nixos/mesh.nix` (headless `cloudflare-warp`, firewall not
opened). This module is what `./infra/up` does around it: read
`warp-cli status` over root SSH, and enrol a node once with the
environment's `mesh_connector_token`.

Enrolment is once per node because the node remembers it: a run that
observes Connected plans nothing, so a rotated token is not pushed to a
node that is already in. The token is a bearer credential for the Mesh
account, so it never appears in a local argv, a log line or the state file.
It crosses to the node on ssh's stdin and is read into a shell variable.
`warp-cli connector new` only takes the token as an argument, so on the
node it is briefly visible in that one process's argv to root, which is
who can read the token file anyway. That is the single accepted exception
to the "no secret in argv" rule.
"""

from __future__ import annotations

import re

from stackbase.errors import StackError
from stackbase.ssh import Ssh

MESH_TOKEN_KEY = "mesh_connector_token"

STATUS_CMD = "warp-cli --accept-tos status"
# `read` takes the token from stdin; `exec` leaves no wrapper shell behind.
ENROL_CMD = 'set -eu; IFS= read -r token; exec warp-cli --accept-tos connector new "$token"'
CONNECT_CMD = "warp-cli --accept-tos connect"
IP_CMD = "ip -6 addr show CloudflareWARP"

# How long the node gets to report Connected after `connect`.
CONNECT_WAIT_SECONDS = 60
CONNECT_POLL_SECONDS = 3

# A connector token is opaque base64/JWT-like text. Anything outside this
# set could not be a token, and is refused instead of reaching a shell.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=:@-]+$")
_CONNECTED_RE = re.compile(r"\bConnected\b")
# Mesh gives each node a global-scope address on the CloudflareWARP interface.
_INET6_RE = re.compile(r"^\s*inet6\s+([0-9a-fA-F:]+)/\d+\s+scope\s+global", re.MULTILINE)


def mesh_connected(status: str) -> bool:
    """True when `warp-cli status` output says Connected (not Disconnected
    or Connecting, which `\\b` tells apart)."""
    return bool(_CONNECTED_RE.search(status))


def observe_mesh(ssh: Ssh) -> bool:
    """Whether the node is on Mesh right now.

    Any failure counts as "no": before the first rebuild there is no
    warp-cli, and a node that cannot be reached cannot be enrolled either,
    which is the same plan.
    """
    result = ssh.run(STATUS_CMD, check=False)
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    return result.returncode == 0 and mesh_connected(stdout)


def connector_token(secrets: dict[str, str], secrets_name: str, env_flag: str) -> str:
    """The environment's connector token, checked, or a StackError naming the key."""
    token = secrets.get(MESH_TOKEN_KEY, "")
    if not token:
        raise StackError(
            f"[mesh] is enabled but infra/{secrets_name} has no '{MESH_TOKEN_KEY}', so the servers cannot join Mesh",
            f"create a node in the Cloudflare dashboard, copy its token and run "
            f"`./infra/up{env_flag} secrets set {MESH_TOKEN_KEY}` (see the README's \"Mesh\" section), "
            "or set enabled = false in [mesh]",
        )
    if not _TOKEN_RE.match(token):
        raise StackError(
            f"infra/{secrets_name}'s '{MESH_TOKEN_KEY}' contains whitespace or a character a connector token never has",
            f"copy the token again from the Cloudflare dashboard and set it with "
            f"`./infra/up{env_flag} secrets set {MESH_TOKEN_KEY}` (see the README's \"Mesh\" section)",
        )
    return token


def mesh_ipv6(ip_output: str) -> str | None:
    """The node's Mesh address from `ip -6 addr show CloudflareWARP`."""
    match = _INET6_RE.search(ip_output)
    return match.group(1) if match else None
