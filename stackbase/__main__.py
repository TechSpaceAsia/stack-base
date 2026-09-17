"""The `stack-base` command line: `up` and `ssh`.

    python3 -m stackbase [--infra-dir DIR] up [--plan] [--allow-purchase] [--debug]
    python3 -m stackbase [--infra-dir DIR] ssh <node> [-- command ...]

Two promises this file keeps, on top of parsing arguments:

- **`--plan` is safe anywhere.** It observes (GET requests only) and prints
  what it would do. It never runs a step, so it never opens an ssh
  connection or issues a write to either API.
- **Failures are one line.** Every expected failure is a `StackError` with a
  message and a hint; it is printed as `error: <message> — <hint>` with every
  known secret masked, and the process exits 1. A traceback appears only
  with `--debug`, which is for whoever is working on stack-base itself.
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path

from stackbase.cloudflare import CloudflareClient
from stackbase.config import load_config, load_state
from stackbase.errors import StackError
from stackbase.hostinger import HostingerClient
from stackbase.reconcile import Context, Step, apply, local_facts, observe, plan
from stackbase.secrets import load_secrets, redact

_DEFAULT_INFRA_DIR = "./infra"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stack-base",
        description="Turn infra/stack.toml into running, hardened servers.",
    )
    parser.add_argument(
        "--infra-dir",
        default=_DEFAULT_INFRA_DIR,
        help=f"the project's infra directory (default: {_DEFAULT_INFRA_DIR})",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    up = commands.add_parser("up", help="make the servers match infra/stack.toml")
    up.add_argument("--plan", action="store_true", help="show what would happen, change nothing")
    up.add_argument("--allow-purchase", action="store_true", help="allow buying a server (still asks you to confirm)")
    up.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    shell = commands.add_parser("ssh", help="open a shell on a node (or run one command there)")
    shell.add_argument("node", help="the node name from stack.toml")
    shell.add_argument("rest", nargs=argparse.REMAINDER, help="optional command to run, after --")
    shell.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    infra_dir = Path(args.infra_dir).expanduser()
    debug = bool(getattr(args, "debug", False))

    # Shared with the error handler by reference: once a step adds the origin
    # key to it, even a failure message is masked.
    secrets: dict[str, str] = {}

    try:
        if args.command == "up":
            _up(args, infra_dir, secrets)
        else:
            _ssh(args, infra_dir)
    except StackError as error:
        if debug:
            traceback.print_exc()
        print(error_line(error, list(secrets.values())), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("error: interrupted — nothing further was changed", file=sys.stderr)
        raise SystemExit(1)


def error_line(error: StackError, secret_values: list[str]) -> str:
    """The single plain-English failure line, with every secret masked."""
    return redact(f"error: {error}", secret_values)


def _up(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    secrets.update(load_secrets(infra_dir))

    hostinger = HostingerClient(_token(secrets, "hostinger_token", "Hostinger"))
    cloudflare = CloudflareClient(_token(secrets, "cloudflare_token", "Cloudflare"))

    stackbase_src = os.environ.get("STACKBASE_SRC") or None
    local = local_facts(infra_dir, secrets, stackbase_src=stackbase_src)
    observed = observe(cfg, state, hostinger, cloudflare, local=local)
    steps = plan(cfg, state, observed)

    if args.plan:
        _print_plan(steps, secrets)
        return

    if not steps:
        print("nothing to do")
        return

    ctx = Context(
        infra_dir=infra_dir,
        cfg=cfg,
        state=state,
        secrets=secrets,
        hostinger=hostinger,
        cloudflare=cloudflare,
        observed=observed,
        stackbase_src=stackbase_src,
    )
    apply(steps, ctx, allow_purchase=args.allow_purchase)
    print("done")


def _print_plan(steps: list[Step], secrets: dict[str, str]) -> None:
    if not steps:
        print("nothing to do")
        return
    values = list(secrets.values())
    print("would do:")
    for number, step in enumerate(steps, start=1):
        print(redact(f"  {number}. {step.description}", values))


def _ssh(args: argparse.Namespace, infra_dir: Path) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    if args.node not in cfg.nodes:
        known = ", ".join(cfg.nodes) or "none"
        raise StackError(
            f"there is no node called '{args.node}' in stack.toml",
            f"known nodes: {known}",
        )

    ctx = Context(
        infra_dir=infra_dir,
        cfg=cfg,
        state=state,
        secrets={},
        hostinger=HostingerClient(""),
        cloudflare=CloudflareClient(""),
        observed=None,  # type: ignore[arg-type] - `ssh` never observes
    )
    ssh = ctx.ssh(args.node)

    command = list(args.rest)
    if command and command[0] == "--":
        command = command[1:]

    argv = [*ssh.argv(), *command]
    os.execvp(argv[0], argv)


def _token(secrets: dict[str, str], key: str, label: str) -> str:
    token = secrets.get(key)
    if not token:
        raise StackError(
            f"infra/secrets.age has no '{key}'",
            f"re-create secrets.age including your {label} API token as '{key}'",
        )
    return token


if __name__ == "__main__":
    main()
