"""Ssh: first contact, host-key pinning, remote commands, and rsync for one node.

Every `ssh`/`rsync` invocation this module builds carries `-o BatchMode=yes`
(never prompt for a password -- password auth is disabled on the node
anyway) and `-o ConnectTimeout=10`, plus -- per the Global Constraints --
`-o UserKnownHostsFile=<infra_dir>/known_hosts -o StrictHostKeyChecking=yes`.
That known_hosts file starts empty; `pin_host_key()` is what populates it
(and only on first contact), so `run`/`fetch`/`rsync_to` naturally refuse to
talk to a host whose key hasn't been pinned yet -- there is no separate
"insecure" mode.

All subprocess invocation goes through the injected `runner` (defaulting to
`subprocess.run`), so tests never shell out or touch the network.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from stackbase.errors import StackError

_KEY_TYPE = "ssh-ed25519"
_WAIT_POLL_SECONDS = 5
_STDERR_TAIL_LINES = 5
_HPANEL_STATUS_HINT = "check the VPS's status in hPanel (https://hpanel.hostinger.com/)"

# Conservative allowlist: IPv4, IPv6, or a DNS hostname -- letters, digits,
# '.', '-', ':'. Must not start with '-' (a leading dash would let a
# malicious/mistyped host string be parsed by ssh/ssh-keyscan/rsync as an
# option rather than a hostname -- "option smuggling").
_HOST_RE = re.compile(r"^(?!-)[A-Za-z0-9.:-]+$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]*$")

_MISSING_BINARY_HINTS: dict[str, str] = {
    "ssh": "install openssh-client (e.g. `apt install openssh-client`, `brew install openssh`)",
    "ssh-keyscan": "install openssh-client (e.g. `apt install openssh-client`) -- ssh-keyscan ships with it",
    "rsync": "install rsync (e.g. `apt install rsync`, `brew install rsync`)",
}


class Ssh:
    """First-contact, key-pinning, remote-command, and rsync interface to one node.

    `known_hosts` lives at `<infra_dir>/known_hosts` -- a per-project file,
    never the operator's own `~/.ssh/known_hosts`, so a stack-base run can
    never trust (or pollute) keys pinned for anything else.
    """

    def __init__(self, infra_dir: str | Path, host: str, user: str = "root", runner: Any = subprocess.run) -> None:
        if not host or not _HOST_RE.match(host):
            raise StackError(
                f"invalid SSH host '{host}'",
                "host must be a non-empty IPv4/IPv6 address or DNS hostname (letters, digits, "
                "'.', '-', ':') and must not start with '-'",
            )
        if not user or not _USER_RE.match(user):
            raise StackError(
                f"invalid SSH user '{user}'",
                "user must match [a-z_][a-z0-9_-]* -- lowercase letters, digits, '_' or '-', "
                "starting with a letter or underscore",
            )
        self._infra_dir = Path(infra_dir)
        self._known_hosts = self._infra_dir / "known_hosts"
        self.host = host
        self.user = user
        self._runner = runner

    # -- Waiting for the node to come up --------------------------------

    def wait_port(
        self,
        timeout: float = 600,
        *,
        sleep: Any = time.sleep,
        clock: Any = time.monotonic,
        connector: Any = socket.create_connection,
    ) -> None:
        """Poll TCP port 22 until it accepts a connection, or raise after `timeout` seconds.

        `sleep`/`clock` are injectable (keyword-only, defaulted to the real
        `time.sleep`/`time.monotonic`) purely so tests can exercise a
        timeout without actually waiting.
        """
        deadline = clock() + timeout
        while True:
            try:
                sock = connector((self.host, 22), timeout=_WAIT_POLL_SECONDS)
            except OSError:
                pass
            else:
                sock.close()
                return
            if clock() >= deadline:
                raise StackError(
                    f"port 22 on {self.host} did not become reachable within {timeout:.0f}s",
                    f"{_HPANEL_STATUS_HINT} -- the VPS may still be booting or being provisioned",
                )
            sleep(_WAIT_POLL_SECONDS)

    # -- Host key pinning -------------------------------------------------

    def pin_host_key(self) -> None:
        """Scan the host's ed25519 key and pin it into `<infra_dir>/known_hosts`.

        No-ops if an entry for this host with the SAME key already exists.
        Raises if an entry exists with a DIFFERENT key -- that could mean
        the server was reinstalled (the fix: remove the stale line and
        re-run) or that the connection is being intercepted (the fix: stop
        and investigate) -- the hint spells out both so the operator isn't
        left guessing which one applies.
        """
        # "--" tells ssh-keyscan's getopt-based parser that everything after
        # it is a positional hostname, never an option -- defense in depth
        # alongside the host-format validation in __init__.
        argv = ["ssh-keyscan", "-t", "ed25519", "-T", "10", "--", self.host]
        result = self._exec(argv, text=True)
        if result.returncode != 0:
            stderr = result.stderr if isinstance(result.stderr, str) else ""
            raise StackError(
                f"ssh-keyscan failed for {self.host} (exit {result.returncode})",
                _tail(stderr) or "check that the host is reachable on port 22",
            )

        key = _parse_ed25519_key(result.stdout if isinstance(result.stdout, str) else "")
        if key is None:
            raise StackError(
                f"ssh-keyscan returned no usable ed25519 host key for {self.host}",
                "check that the host is reachable on port 22 and running sshd -- ssh-keyscan "
                "returned no ssh-ed25519 line to pin",
            )
        host_field, key_type, key_body = key
        self._pin_key(host_field, key_type, key_body)

    def _pin_key(self, host_field: str, key_type: str, key_body: str) -> None:
        path = self._known_hosts
        existing_lines: list[str] = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

        for line in existing_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 3 and parts[0] == host_field and parts[1] == _KEY_TYPE:
                if parts[2] == key_body:
                    return  # already pinned with this exact key -- no-op
                raise StackError(
                    f"the SSH host key for {host_field} does not match the pinned entry in {path}",
                    "if the server was reinstalled, remove the old line for this host from "
                    f"{path} and re-run; otherwise someone may be intercepting the connection -- "
                    "stop and investigate before proceeding",
                )

        new_line = f"{host_field} {key_type} {key_body}"
        content = "\n".join([*existing_lines, new_line]) + "\n"

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.parent / f".{path.name}.tmp{os.getpid()}"
        tmp_path.write_text(content, encoding="utf-8")
        tmp_path.chmod(0o644)
        os.replace(tmp_path, path)  # atomic: known_hosts is never seen half-written

    # -- Remote commands -----------------------------------------------------

    def run(self, cmd: str, *, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
        """Run `cmd` on the node over ssh. Returns the (text-mode, captured) CompletedProcess.

        `check=True` (the default) raises `StackError` -- including the last
        few lines of stderr -- on a non-zero exit; `check=False` returns the
        CompletedProcess regardless of exit status, same as `subprocess.run`.
        """
        argv = self._ssh_argv(cmd)
        result = self._exec(argv, text=True, input_data=input)
        if check and result.returncode != 0:
            stderr = result.stderr if isinstance(result.stderr, str) else ""
            raise StackError(
                f"command failed on {self.host} (exit {result.returncode}): {cmd}",
                _tail(stderr) or "no stderr output was captured -- re-run with --debug for the full command",
            )
        return result

    def fetch(self, remote_path: str) -> bytes:
        """Read `remote_path` on the node and return its raw bytes."""
        cmd = f"cat -- {shlex.quote(remote_path)}"
        argv = self._ssh_argv(cmd)
        result = self._exec(argv, text=False)
        if result.returncode != 0:
            stderr = result.stderr
            stderr_text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else str(stderr or "")
            raise StackError(
                f"failed to fetch {remote_path} from {self.host} (exit {result.returncode})",
                _tail(stderr_text) or "no stderr output was captured",
            )
        return result.stdout if isinstance(result.stdout, bytes) else b""

    def rsync_to(self, local_dir: str | Path, remote_dir: str, *, delete: bool = True, exclude: list[str] = ()) -> None:
        """Sync the contents of `local_dir` to `remote_dir` on the node.

        `delete=True` (the default) passes `--delete`, so `remote_dir`
        converges to exactly `local_dir`'s contents. `exclude` patterns are
        passed through as `--exclude=<pattern>` (the reconciler uses this to
        keep `secrets.age`/`keys/` off the wire).

        `local_dir` is resolved to an absolute path before being handed to
        rsync -- a relative, dash-leading path (e.g. "-rf") would otherwise
        be parsed as an option rather than a source directory. `remote_dir`
        must already be absolute; rsync's destination arg is always
        "user@host:<remote_dir>" so it can't itself be parsed as an option,
        but a relative remote path is ambiguous (relative to whatever the
        remote shell's cwd happens to be) and stack-base never wants that.
        """
        if not str(remote_dir).startswith("/"):
            raise StackError(
                f"remote_dir '{remote_dir}' must be an absolute path",
                "pass an absolute path (e.g. '/etc/nixos/stack') -- a relative remote path "
                "depends on the remote shell's working directory",
            )
        ssh_cmd = shlex.join(["ssh", *self._ssh_options()])
        local = os.path.abspath(local_dir)
        if not local.endswith("/"):
            local += "/"

        argv = ["rsync", "-az"]
        if delete:
            argv.append("--delete")
        argv.extend(f"--exclude={pattern}" for pattern in exclude)
        argv.extend(["-e", ssh_cmd, local, f"{self.user}@{self.host}:{remote_dir}"])

        result = self._exec(argv, text=True)
        if result.returncode != 0:
            stderr = result.stderr if isinstance(result.stderr, str) else ""
            raise StackError(
                f"rsync to {self.host}:{remote_dir} failed (exit {result.returncode})",
                _tail(stderr) or "no stderr output was captured",
            )

    def argv(self) -> list[str]:
        """The base ssh argv (no trailing command) -- for `ssh <node>` to `os.execvp`."""
        return self._ssh_argv()

    # -- Internals -----------------------------------------------------------

    def _ssh_options(self) -> list[str]:
        return [
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", f"UserKnownHostsFile={self._known_hosts}",
            "-o", "StrictHostKeyChecking=yes",
        ]

    def _ssh_argv(self, *extra: str) -> list[str]:
        return ["ssh", *self._ssh_options(), f"{self.user}@{self.host}", *extra]

    def _exec(self, argv: list[str], *, text: bool, input_data: Any = None) -> subprocess.CompletedProcess:
        try:
            if text:
                return self._runner(argv, capture_output=True, text=True, input=input_data, check=False)
            return self._runner(argv, capture_output=True, input=input_data, check=False)
        except FileNotFoundError as exc:
            binary = argv[0]
            raise StackError(
                f"the '{binary}' command was not found",
                _MISSING_BINARY_HINTS.get(binary, f"install {binary}"),
            ) from exc


def _parse_ed25519_key(output: str) -> tuple[str, str, str] | None:
    """First non-comment `ssh-keyscan` line whose key type is `ssh-ed25519` -> `(host, type, body)`."""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 3 and parts[1] == _KEY_TYPE:
            return parts[0], parts[1], parts[2]
    return None


def _tail(text: str, lines: int = _STDERR_TAIL_LINES) -> str:
    non_empty = [line for line in text.splitlines() if line.strip()]
    return "\n".join(non_empty[-lines:])
