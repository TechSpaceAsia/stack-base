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
from typing import Callable

from stackbase.backups import check_backup_credentials, run_backup_now
from stackbase.ci import ci_setup
from stackbase.cloudflare import CloudflareClient
from stackbase.config import load_config, load_state
from stackbase.errors import StackError
from stackbase.hostinger import HostingerClient
from stackbase.reconcile import (
    SSH_USER,
    Context,
    Step,
    apply,
    check_infra_clean,
    local_facts,
    observe,
    plan,
    redaction_values,
    render_description,
)
from stackbase.release import run_deploy, run_rollback, run_status
from stackbase.secrets import check_recipients_superset, load_secrets, redact
from stackbase.secrets_cli import deploy_key_init, deploy_key_show_pub, edit_key, list_key_names, set_key, unset_key
from stackbase.ssh import Ssh

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
    up.add_argument(
        "--allow-dirty",
        action="store_true",
        help="push infra/ even with uncommitted *.nix or stack.toml changes",
    )
    up.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    shell = commands.add_parser("ssh", help="open a shell on a node (or run one command there)")
    shell.add_argument("node", help="the node name from stack.toml")
    shell.add_argument("rest", nargs=argparse.REMAINDER, help="optional command to run, after --")
    shell.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    deploy = commands.add_parser("deploy", help="build, package and ship a release to every node")
    deploy.add_argument("version", help="release version, e.g. v1.4.2")
    deploy.add_argument("--node", help="restrict to one node")
    deploy.add_argument("--skip-build", action="store_true", help="skip the build -- use --tarball instead")
    deploy.add_argument("--tarball", help="a pre-built release tarball (requires --skip-build)")
    deploy.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    rollback = commands.add_parser("rollback", help="swap traffic back to each node's previous release")
    rollback.add_argument("--node", help="restrict to one node")
    rollback.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    status = commands.add_parser("status", help="show each node's active/idle release")
    status.add_argument("--node", help="restrict to one node")
    status.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    backup_now_p = commands.add_parser("backup-now", help="run the backup on every node now and list the bucket")
    backup_now_p.add_argument("--node", help="restrict to one node")
    backup_now_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    ci_setup_p = commands.add_parser(
        "ci-setup", help="provision an optional GitHub Actions deploy key for this project"
    )
    ci_setup_p.add_argument("--rotate", action="store_true", help="replace an existing CI deploy key")
    ci_setup_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    deploy_key_p = commands.add_parser(
        "deploy-key", help="the project's SSH deploy key -- used by you, by a build host, and by CI"
    )
    deploy_key_sub = deploy_key_p.add_subparsers(dest="deploy_key_command", required=True)

    deploy_key_init_p = deploy_key_sub.add_parser(
        "init", help="generate it in RAM: writes infra/deploy.age and infra/keys/deploy.pub"
    )
    deploy_key_init_p.add_argument("--rotate", action="store_true", help="replace an existing deploy key")
    deploy_key_init_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    deploy_key_show_p = deploy_key_sub.add_parser("show-pub", help="print the deploy key's public half")
    deploy_key_show_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    secrets_p = commands.add_parser(
        "secrets", help="manage infra/secrets.age one key at a time -- never to disk unencrypted"
    )
    secrets_sub = secrets_p.add_subparsers(dest="secrets_command", required=True)

    secrets_keys_p = secrets_sub.add_parser("keys", help="list secret key names (never values)")
    secrets_keys_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    secrets_set_p = secrets_sub.add_parser("set", help="set one key's value, read from stdin")
    secrets_set_p.add_argument("key", help="the secret's name (e.g. hostinger_token, app_env)")
    secrets_set_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    secrets_unset_p = secrets_sub.add_parser("unset", help="remove one key")
    secrets_unset_p.add_argument("key", help="the secret's name")
    secrets_unset_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    secrets_edit_p = secrets_sub.add_parser(
        "edit", help="edit one key's value in $VISUAL/$EDITOR/vi, via a RAM-only scratch file"
    )
    secrets_edit_p.add_argument("key", help="the secret's name")
    secrets_edit_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

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
        elif args.command == "ssh":
            _ssh(args, infra_dir)
        elif args.command == "deploy":
            _deploy(args, infra_dir, secrets)
        elif args.command == "rollback":
            _rollback(args, infra_dir, secrets)
        elif args.command == "status":
            _status(args, infra_dir, secrets)
        elif args.command == "backup-now":
            _backup_now(args, infra_dir, secrets)
        elif args.command == "ci-setup":
            _ci_setup(args, infra_dir, secrets)
        elif args.command == "deploy-key":
            _deploy_key(args, infra_dir, secrets)
        elif args.command == "secrets":
            _secrets(args, infra_dir, secrets)
        else:
            # argparse's subparsers are `required=True`, so this is
            # unreachable in practice -- but an explicit branch that fails
            # loudly beats a bare `else` silently routing an unrecognised
            # command to whichever handler happened to be listed last
            # (minor d, Fix round 1).
            raise StackError(
                f"unknown command '{args.command}'",
                "this is a bug in stack-base -- please report it",
            )
    except StackError as error:
        _print_traceback(debug, secrets)
        print(error_line(error, redaction_values(secrets)), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("error: interrupted — nothing further was changed", file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:  # noqa: BLE001 - deliberate last line of defence
        # A bug in stack-base, not a user error. Python's own excepthook
        # would print an unredacted traceback, so it must never be what
        # handles this.
        _print_traceback(debug, secrets)
        print(
            redact(
                f"error: unexpected failure ({type(error).__name__}) — this is a bug in "
                "stack-base; re-run with --debug and report it",
                redaction_values(secrets),
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)


def _print_traceback(debug: bool, secrets: dict[str, str]) -> None:
    """With `--debug`, print the traceback -- masked.

    `traceback.print_exc()` writes straight to stderr, which would put the
    exception's own text there unmasked: a StackError routinely carries a
    remote command's stderr or an API error body, and either can contain a
    token. `--debug` is for diagnosing stack-base, not for reading the
    account's secrets in cleartext, and formatting the traceback to a string
    first is the only way to get `redact()` in between.

    `secrets` is read at call time on purpose: whatever has been decrypted by
    the moment of the failure is masked, and a failure before that point
    (nothing known to mask yet) still prints normally.

    Masks via `redaction_values()` (P5, Fix round 1), not a plain
    `list(secrets.values())` -- the latter only knows the "app_env" secret as
    one whole blob, so an individual app_env line's VALUE (e.g. a session
    secret echoed inside a remote command's stderr) would slip through
    unmasked even though `Context.secret_values` already protects it on
    every `ctx.emit()` line during `apply()`.
    """
    if debug:
        print(redact(traceback.format_exc(), redaction_values(secrets)), file=sys.stderr, end="")


def error_line(error: StackError, secret_values: list[str]) -> str:
    """The single plain-English failure line, with every secret masked."""
    return redact(f"error: {error}", secret_values)


_NO_CLOUDFLARE_WARNING = (
    "! no Cloudflare token in secrets.age — skipping DNS and the TLS origin certificate; "
    "the server will be reachable by IP/SSH only. Add cloudflare_token later and run up again."
)


def _up(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    # Before anything reaches the network: a deploy-recipients.txt that has
    # drifted behind age-recipients.txt means an admin who can read every
    # project secret can no longer decrypt the deploy key -- caught here,
    # once, rather than at their next failed deploy. This one runs
    # unconditionally (even under --plan) because it is a correctness check
    # on the secrets setup itself, not on what would be pushed.
    check_recipients_superset(infra_dir)
    # `--plan` changes nothing, so it never has to be clean. Otherwise:
    # what gets pushed is the working tree, so refuse to push one nobody
    # has committed unless the operator says so explicitly. Placed second
    # (after the recipients check, before secrets are even loaded): both
    # are cheap, local, no-network checks, so ordering doesn't affect
    # speed -- but this one is about what `up` is about to DO (push a
    # tree), so it reads naturally as the second half of "is it safe to
    # proceed" right before secrets.update() commits to actually running.
    if not args.plan and not args.allow_dirty:
        check_infra_clean(infra_dir, emit=_emit_plain)
    secrets.update(load_secrets(infra_dir))

    hostinger = HostingerClient(_token(secrets, "hostinger_token", "Hostinger"))

    # Cloudflare is optional (Task 7b): with no token, no CloudflareClient is
    # ever constructed, observe() makes no Cloudflare request, and plan()
    # skips the origin cert and DNS entirely -- see reconcile.py.
    cloudflare_token = secrets.get("cloudflare_token")
    if cloudflare_token:
        cloudflare = CloudflareClient(cloudflare_token)
    else:
        cloudflare = None
        print(redact(_NO_CLOUDFLARE_WARNING, redaction_values(secrets)))

    stackbase_src = os.environ.get("STACKBASE_SRC") or None
    local = local_facts(infra_dir, secrets, stackbase_src=stackbase_src)
    # stack.toml's bucket is what turns the node's nightly timer ON;
    # secrets.age's three r2_* keys are what make it able to run. Nothing
    # else compares them, so an incomplete pair is silent here and loud at
    # 03:00 -- say so now, next to the other pre-flight warnings. Emitted
    # under `--plan` too: it is a statement about the configuration, not
    # about what this particular run is going to push.
    check_backup_credentials(cfg.backups.bucket, local.backup_env_sha, emit=_emit_masked(secrets))
    observed = observe(cfg, state, hostinger, cloudflare, local=local)
    for warning in observed.cloudflare_ip_warnings:
        print(redact(f"! {warning}", redaction_values(secrets)))
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
    values = redaction_values(secrets)
    has_cloudflare_token = bool(secrets.get("cloudflare_token"))
    print("would do:")
    for number, step in enumerate(steps, start=1):
        description = render_description(step, has_cloudflare_token=has_cloudflare_token)
        print(redact(f"  {number}. {description}", values))


def _ssh(args: argparse.Namespace, infra_dir: Path) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    if args.node not in cfg.nodes:
        known = ", ".join(cfg.nodes) or "none"
        raise StackError(
            f"there is no node called '{args.node}' in stack.toml",
            f"known nodes: {known}",
        )

    node_state = state.nodes.get(args.node)
    ipv4 = node_state.ipv4 if node_state else None
    if not ipv4:
        raise StackError(
            f"stack-base does not know an address for node '{args.node}' yet",
            "run `up` first -- the address is recorded once the server is running",
        )
    ssh = Ssh(infra_dir, ipv4, user=SSH_USER)

    command = list(args.rest)
    if command and command[0] == "--":
        command = command[1:]

    argv = [*ssh.argv(), *command]
    os.execvp(argv[0], argv)


def _emit_plain(line: str) -> None:
    """The print path for output emitted by a command that holds no secret.

    What is left here is `up`'s dirty-tree check, `deploy-key show-pub` (a
    public half) and the `secrets` subcommands, which hand their own
    `register_secret` to the functions that hold a value and print only
    already-safe lines of their own. Still routed through `redact()` with an
    empty value list -- a no-op -- so every printed line goes through the
    same masking path as the rest of the CLI. Anything that can hold a
    secret for the duration of a command (`deploy`, `rollback`, `status`,
    `backup-now`, `up`, and the two commands that generate or push the
    project deploy key) uses `_emit_masked` instead.
    """
    print(redact(line, []))


def _emit_masked(secrets: dict[str, str]) -> Callable[[str], None]:
    """A print that masks every value registered so far.

    `deploy`/`rollback`/`status` can now hold one secret -- the project's
    SSH deploy key, decrypted into RAM by `release.deploy_identity` -- so
    their output goes through the same masking path as the rest of the CLI
    rather than `_emit_plain`'s empty value list.
    """

    def emit(line: str) -> None:
        print(redact(line, redaction_values(secrets)))

    return emit


def _deploy(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_deploy(
        infra_dir,
        args.version,
        node=args.node,
        skip_build=args.skip_build,
        tarball_path=args.tarball,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )


def _rollback(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_rollback(
        infra_dir,
        node=args.node,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )


def _status(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_status(
        infra_dir,
        node=args.node,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )


def _backup_now(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    """Run the node's backup unit now, then list what landed in the bucket.

    `secrets` is empty here -- nothing is decrypted for this command, which
    only starts a unit as root -- but the emit still goes through
    `_emit_masked` rather than `_emit_plain`: the streamed output is the
    node's own, and the masking path should not depend on today's happening
    to have nothing to mask.
    """
    run_backup_now(infra_dir, node=args.node, emit=_emit_masked(secrets))


def _secret_register_counter(secrets: dict[str, str]) -> Callable[[str], None]:
    """A `register_secret(value)` callback that feeds `secrets` (F2, Fix
    round 1) -- the same dict `error_line`/`_print_traceback` redact with,
    populated incrementally the way `_up` populates it in one shot via
    `secrets.update(load_secrets(...))`.

    Each call gets its OWN synthetic dict key (`_secret_N`), never the
    value's semantic name (e.g. "cloudflare_token") -- `edit_key` registers
    BOTH the original bundle value and the freshly-edited value for the
    same key name, and a plain `secrets[key] = value` would let the second
    call silently overwrite (and so un-mask) the first. `redaction_values()`
    only reads `.values()`, so the key itself carries no meaning.
    """
    counter = [0]

    def register(value: str) -> None:
        if not value:
            return
        counter[0] += 1
        secrets[f"_secret_{counter[0]}"] = value

    return register


def _ci_setup(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    # `_emit_masked`, not `_emit_plain`: from the moment `register_secret`
    # fires, this command HOLDS the project's private deploy key. Nothing it
    # prints today can carry it, so this is belt-and-braces -- but the same
    # dict is what masks the error paths, and a future line that quotes a
    # generated key would otherwise print it in full.
    ci_setup(
        infra_dir,
        rotate=args.rotate,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )


def _deploy_key(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    if args.deploy_key_command == "init":
        # Masked for the same reason as `ci-setup` above: this is the
        # command that GENERATES the private deploy key. `show-pub` below
        # stays plain -- it only ever holds a public half.
        deploy_key_init(
            infra_dir,
            rotate=args.rotate,
            emit=_emit_masked(secrets),
            register_secret=_secret_register_counter(secrets),
        )
    elif args.deploy_key_command == "show-pub":
        deploy_key_show_pub(infra_dir, emit=_emit_plain)
    else:
        # deploy_key_sub is required=True, so this is unreachable in
        # practice -- an explicit branch beats a bare `else` doing nothing.
        raise StackError(
            f"unknown deploy-key command '{args.deploy_key_command}'",
            "this is a bug in stack-base -- please report it",
        )


def _secrets(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    register_one = _secret_register_counter(secrets)

    def register_secret(_key: str, value: str) -> None:
        register_one(value)

    if args.secrets_command == "keys":
        for name in list_key_names(infra_dir):
            _emit_plain(name)
    elif args.secrets_command == "set":
        set_key(infra_dir, args.key, emit=_emit_plain, register_secret=register_secret)
    elif args.secrets_command == "unset":
        unset_key(infra_dir, args.key, emit=_emit_plain, register_secret=register_secret)
    elif args.secrets_command == "edit":
        edit_key(infra_dir, args.key, emit=_emit_plain, register_secret=register_secret)
    else:
        # secrets_sub is required=True, so this is unreachable in practice --
        # an explicit branch beats a bare `else` silently doing nothing.
        raise StackError(
            f"unknown secrets command '{args.secrets_command}'",
            "this is a bug in stack-base -- please report it",
        )


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
