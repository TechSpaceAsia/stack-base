# stack-base — Plan 02: blue/green deploy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> Lean plan (interfaces + named test cases, not full code) — design agreed with the owner in conversation; implementers write the code; **Interfaces** blocks are binding. Builds on Plan 01 (`docs/plan-01-stack-up.md`), which must be merged first.

**Goal:** One on-box engine (`stack-deploy`) does health-checked blue/green releases with SemVer retention and rollback; a laptop command and an optional GitHub Actions workflow are thin callers of that same engine through one restricted SSH door.

**Architecture:** Two instances of a systemd template unit (`<project>@blue`, `<project>@green`) each serve on their own unix socket; nginx proxies to `/run/<project>/app.sock`, a symlink the engine flips atomically — no nginx reload, no nginx privileges. A `deploy` user reachable only through an SSH forced command accepts `upload | deploy | rollback | status`. Modelled on `boost/infra/host-native/deploy/boost-deploy.sh` (same subcommand names and state file idea) so the team recognises it.

**Tech Stack:** Bash packaged with `pkgs.writeShellApplication` (shellcheck at build time), NixOS module + VM test, Python stdlib callers in `stackbase/`, `gh` CLI for the repo secret.

## Global Constraints

- All Plan 01 Global Constraints still apply (stdlib-only Python, one-line plain-English failures, secrets never on disk/in logs, shell-variable style in user-facing snippets).
- Versions are `vMAJOR.MINOR.PATCH` exactly (`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`); anything else is rejected before touching disk. No pre-release/build suffixes.
- Retention: keep the **5 highest by SemVer order** (numeric per component, not lexical, not by mtime) plus any release a color currently links to. Never delete a linked release.
- State file `/var/lib/stackbase/active-color` contains exactly `blue` or `green` + newline; written atomically (tmp + `mv -T`) AFTER the socket symlink flip succeeds.
- Swap = atomic symlink replace (`ln -s … tmp && mv -T tmp /run/<project>/app.sock`). nginx is never reloaded or restarted by a deploy.
- Old color is stopped after `drainSeconds` (default 60) following a successful swap. Exactly one color runs in steady state.
- Health check: HTTP GET `healthPath` (default `/health`) over the idle color's unix socket; 30 tries, 2 s apart; only 2xx counts as healthy. A failed health check stops the idle color, leaves the active color and symlink untouched, exits non-zero.
- One deploy at a time: the engine holds `flock` on `/var/lib/stackbase/deploy.lock`; a second invocation fails immediately with a clear message.
- The `deploy` user has no shell access: every authorized key carries `restrict,command="…stack-deploy-ssh"`. Its only privilege is `systemctl start|stop|restart <project>@blue.service` and `…@green.service` (exact unit names, no wildcards).
- Uploaded tarballs are verified against a caller-supplied sha256 before unpacking; unpacking refuses absolute paths and `..` members.
- The CI private key exists only in GitHub (repo-level secret `STACK_DEPLOY_KEY`) — never in the repo, never in `secrets.age`, never on the operator's persistent disk. Org-level secrets/variables are not available on the owner's GitHub plan and must not be used.
- Migrations run at app startup, so the README and the engine's output must state: migrations must be additive (expand → migrate → contract in a later release).

## File Structure

```
nixos/deploy.nix                 module: template units, dirs, deploy user, forced command, sudo rule, packages
nixos/deploy/stack-deploy.sh     the engine (subcommands below)
nixos/deploy/stack-deploy-ssh.sh forced-command dispatcher (parses $SSH_ORIGINAL_COMMAND)
tests/vm-deploy.nix              VM test: deploy, swap, failed health, rollback, prune, lock, forced command
stackbase/release.py             laptop caller: verify tag, build, package, upload, deploy per node
stackbase/ci.py                  ci-setup: keygen in RAM, gh secret set, write keys/ci-deploy.pub
stackbase/__main__.py            (modify) add `deploy`, `rollback`, `status`, `ci-setup` subcommands
stackbase/steps.py|reconcile.py  (modify) ENSURE_APP_ENV step
templates/infra/flake.nix        (modify) pass deploy keys (admins + ci-deploy.pub if present)
templates/github/deploy-stack.yml  workflow template for derived projects
tests/test_release.py tests/test_ci.py
```

On-box layout (created by `deploy.nix` via tmpfiles, owner `deploy`, group = app group):

```
/opt/<project>/releases/<version>/     unpacked release (binary + static/ …)
/opt/<project>/blue/current -> ../releases/<version>      (same for green)
/var/lib/stackbase/active-color        blue|green
/var/lib/stackbase/app.env             EnvironmentFile for the app (0640 root:<app group>)
/var/lib/stackbase/incoming/           uploads land here
/run/<project>/app-blue.sock, app-green.sock, app.sock -> app-<active>.sock
```

---

### Task 1: Engine + NixOS module + VM test

**Files:** Create `nixos/deploy.nix`, `nixos/deploy/stack-deploy.sh`, `tests/vm-deploy.nix`; modify `flake.nix` (add `nixosModules.deploy`, include it in `default` and `lib.mkNode`, add `checks.x86_64-linux.vm-deploy`).

**Interfaces — Produces:**
- Options: `stackbase.app.binary` (str, default = project with `-`→`_`), `stackbase.app.healthPath` (str, default `/health`), `stackbase.deploy.drainSeconds` (int, default 60), `stackbase.deploy.keep` (int, default 5), `stackbase.deploy.keys` (attrsOf str, name → public key; consumed by Task 2).
- Template unit `<project>@.service`: `User=<project>`, `WorkingDirectory=/opt/<project>/%i/current`, `ExecStart=/opt/<project>/%i/current/<binary>`, `EnvironmentFile=-/var/lib/stackbase/app.env`, `Environment=SOCKET_PATH=/run/<project>/app-%i.sock`, `RuntimeDirectory` shared and preserved, `Restart=on-failure`, standard hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, …). NOT `wantedBy` multi-user directly — a small `stackbase-app-boot.service` starts the unit for the color named in `active-color` at boot and recreates the `app.sock` symlink (since `/run` is wiped on reboot).
- `stack-deploy` subcommands: `status`, `colors` (prints `active=<c> idle=<c>`), `deploy <version> [--force]` (expects `/opt/<project>/releases/<version>/` already unpacked OR `--tarball <path> --sha256 <hex>`), `rollback`, `prune [keep]`, `releases` (SemVer-sorted list, marks linked ones). Exit codes: 0 ok, 1 failure, 2 usage, 3 lock held.
- First-ever deploy (no `active-color` yet): idle color = blue; swap creates the symlink and state file.
- `rollback`: target = the idle color's still-linked release; refuses with a clear message if the idle color has no release; otherwise identical path to deploy (start → health → flip → drain-stop).

- [ ] VM test first (`tests/vm-deploy.nix`), using a tiny fake app (a Python `http.server` on the unix socket from `$SOCKET_PATH` answering `/health` 200 and `/version` with its version; a variant that answers 500) packaged as release dirs/tarballs `v1.0.0`, `v1.1.0`, `v1.2.0-broken`… Cases: first deploy goes live on blue; second deploy goes live on green and blue is stopped after drain (use `drainSeconds = 2` in the test); requests through nginx during the swap never see a 502 (loop `curl` in the background across the swap, assert zero failures); broken release ⇒ non-zero exit, active color + symlink + state file unchanged, idle unit stopped; `rollback` returns to the previous version; `prune` with 7 releases `v1.0.0 … v1.10.0` keeps the right five by SemVer (`v1.10.0` outranks `v1.9.0`) and never deletes a linked one; invalid version string rejected; second concurrent `deploy` exits 3; reboot ⇒ the active color comes back and `/version` is served again.
- [ ] Implement until `nix flake check` is green; commit.

### Task 2: Restricted SSH door

**Files:** Create `nixos/deploy/stack-deploy-ssh.sh`; modify `nixos/deploy.nix`, `tests/vm-deploy.nix`.

**Interfaces — Produces:**
- `deploy` system user, home `/var/lib/stackbase/deploy-home`, no password; `authorized_keys` generated from `stackbase.deploy.keys`, each line prefixed `restrict,command="<store path>/bin/stack-deploy-ssh"`. `AllowUsers` from Plan 01's base module must now include `deploy`.
- Protocol (`$SSH_ORIGINAL_COMMAND`, split safely — no `eval`, no word-splitting of untrusted input into a shell): `upload <version> <sha256>` (reads tarball from stdin into `incoming/<version>.tar.gz`, size cap 500 MB, verifies sha256, unpacks into `releases/<version>/`, refuses to overwrite an existing release), `deploy <version>`, `rollback`, `status`, `colors`, `releases`. Anything else ⇒ exit 2 with the usage line. No PTY, no port forwarding (covered by `restrict`).
- sudo rule: `deploy` may run exactly `systemctl start|stop|restart <project>@blue.service|<project>@green.service` with NOPASSWD.

- [ ] VM test cases: from a client machine holding a key in `stackbase.deploy.keys`: `ssh deploy@node status` works; `ssh deploy@node bash`, `ssh deploy@node 'status; id'`, `ssh -t`, `scp`, and `ssh -L` are all refused or confined to the dispatcher; `upload` with a wrong sha256 leaves nothing in `releases/`; a tarball containing `../evil` or an absolute path is rejected; full upload → deploy → status round-trip over ssh succeeds; `sudo systemctl restart nginx` as `deploy` is denied.
- [ ] Green `nix flake check`; commit.

### Task 3: Laptop caller

**Files:** Create `stackbase/release.py`, `tests/test_release.py`; modify `stackbase/__main__.py`.

**Interfaces — Produces:**
- CLI: `deploy <version> [--node NAME] [--skip-build --tarball PATH]`, `rollback [--node NAME]`, `status`.
- `release.verify_version(repo_dir, version)` — tag exists, tag == `v` + `Cargo.toml` `[package].version`, working tree state irrelevant because the build uses a clean `git worktree add --detach <tmp> <tag>`.
- `release.build(worktree, project) -> Path` — follows the recipe in platform-base's `templates/project-files/.github/workflows/deploy.yml` (static musl target, Tailwind CSS build, same bundle contents/layout); read that file and mirror it; every subprocess streamed to the terminal.
- `release.package(bundle_dir, version) -> tuple[Path, str]` (tarball path, sha256) — deterministic member order, no absolute paths.
- `release.ship(cfg, state, version, tarball, sha256, *, nodes)` — per node, sequentially, replicas before primary: `ssh deploy@<ip> upload …` with the tarball on stdin, then `deploy …`; stop at the first failing node and say which nodes are on which version.

- [ ] Tests first (FakeRunner; temp git repos for version checks): tag/Cargo mismatch rejected with a hint; non-SemVer rejected; packaging is deterministic and path-safe; ship order replicas→primary; first failure stops the run and the summary names per-node versions; ssh argv uses user `deploy` and the pinned `known_hosts`.
- [ ] Fail → implement → pass → commit.

### Task 4: CI path — `ci-setup` + workflow template

**Files:** Create `stackbase/ci.py`, `tests/test_ci.py`, `templates/github/deploy-stack.yml`; modify `stackbase/__main__.py`, `templates/infra/flake.nix`, `README.md`.

**Interfaces — Produces:**
- CLI `ci-setup [--rotate]`: determines the GitHub repo from `git remote get-url origin`; `ssh-keygen -t ed25519 -N "" -C "ci-deploy@<project>"` into a `0700` temp dir under `/dev/shm` (fallback: `$XDG_RUNTIME_DIR`; refuse to fall back to a disk-backed tmp) removed in a `finally`; writes `infra/keys/ci-deploy.pub`; pipes the private key on stdin to `gh secret set STACK_DEPLOY_KEY --repo <owner/repo>`; prints next steps (`commit the .pub`, `./infra/up`, copy the workflow). Refuses if `ci-deploy.pub` exists unless `--rotate`. Missing/unauthenticated `gh` ⇒ StackError with the `gh auth login` hint.
- `templates/infra/flake.nix`: `stackbase.deploy.keys` = every admin key + `ci-deploy` when `./keys/ci-deploy.pub` exists. `ci-deploy.pub` must NOT become an admin/root key — assert this in a `nix eval` test.
- `deploy-stack.yml`: `on: push: tags: ['v*']`; verifies tag == Cargo.toml version; builds with the same recipe as `release.build`; reads node IPs from committed `infra/stack.state.json` and host keys from committed `infra/known_hosts` (`StrictHostKeyChecking=yes`); uses only `secrets.STACK_DEPLOY_KEY` (repo-level); writes the key to `$RUNNER_TEMP` with `umask 077` and deletes it in an `if: always()` step; uploads then deploys replicas→primary; prints `status` at the end. No third-party actions beyond `actions/checkout` and the Rust toolchain/cache actions already used by platform-base's existing workflow, pinned by commit SHA.

- [ ] Tests first: private key bytes never appear in any argv, log line or file outside the RAM dir (assert via FakeRunner recordings and a temp-dir scan); `--rotate` semantics; repo parsing for https and ssh remotes; refusal without `/dev/shm`-class storage; workflow YAML parses and references no `vars.`/org-level context and exactly one secret.
- [ ] Fail → implement → pass → commit.

### Task 5: App environment file

**Files:** Modify `stackbase/reconcile.py` (or `steps.py`), `tests/test_reconcile.py`, `README.md`, `templates/infra/stack.toml.example`.

**Interfaces — Produces:** `Action.ENSURE_APP_ENV` — when `secrets.age` has an `app_env` key (multi-line `KEY=value` text), push it to `/var/lib/stackbase/app.env` atomically (tmp + `mv`, `0640 root:<project>`), only when its sha256 differs from `state.nodes[n].app_env_sha`; then `systemctl try-restart <project>@<active>` . README documents the minimum keys a platform-base app needs (`DATABASE_URL=postgres:///<project>`, session/CSRF secrets, OAuth settings) using shell-variable style for fill-ins.

- [ ] Tests first: absent key ⇒ no step; changed content ⇒ push + restart of the active color only; unchanged ⇒ no step; content never printed.
- [ ] Fail → implement → pass → commit.

### Task 6 (platform-base repo, separate branch): rollback-safe migrations + template wiring

**Files (in `/home/matiboy/code/techspace/platform-base`):** Modify `src/main.rs` (migrator: `.set_ignore_missing(true)`), `CHANGELOG.md` (`### Fixed` under `## [Unreleased]`), `CLAUDE.md` (one line: standalone stacks live in stack-base; migrations must be additive for blue/green), `.claude/skills/new-platform` (offer to copy `templates/infra/` from stack-base).

- [ ] `sqlx::migrate!("./migrations")` has no builder for this — construct the `Migrator`, call `set_ignore_missing(true)`, then `.run(&pool)`; no `.unwrap()`/`.expect()` (repo rule); `cargo check` + `cargo clippy -- -D warnings` + `cargo test` green; never edit an existing migration file.
- [ ] Commit on a feature branch in platform-base; do not push.

### Task 7: Live acceptance (dispatcher-run, needs the owner)

- [ ] On the Plan 01 acceptance node: deploy a hello-world platform-base build `v0.1.0`, then `v0.1.1`; verify zero failed requests across the swap through Cloudflare, `rollback`, prune; run `ci-setup` against a scratch repo and confirm the workflow deploys with only the repo-level secret.
