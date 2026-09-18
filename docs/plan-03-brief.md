# Plan 03 brief — "operability": two-file secrets, conf.d, backups, NixOS build host, CI runner

Decisions agreed with Matt on 2026-09-18. This brief is the spec the plan
argues from. Plans 01/02 (`docs/plan-01-stack-up.md`, `docs/plan-02-deploy.md`)
are shipped on `main`; this plan builds on them without changing their
contracts unless stated here.

## A. Two secrets files, two recipient sets

Today `infra/secrets.age` (recipients `infra/age-recipients.txt`) holds
everything. Split:

| File | Recipients file | Contents |
|---|---|---|
| `infra/secrets.age` (unchanged) | `infra/age-recipients.txt` | `hostinger_token`, `cloudflare_token`, `app_env`, and new `r2_access_key_id`, `r2_secret_access_key`, `r2_endpoint` |
| `infra/deploy.age` (new) | `infra/deploy-recipients.txt` (new; MUST be a superset of `age-recipients.txt` — `up` checks and refuses otherwise) | exactly one value: `deploy_ssh_key` = an OpenSSH ed25519 private key (PEM text) |

Why: `deploy` only needs the SSH key. A build host (nixos-ollama) gets its
own file identity listed ONLY in `deploy-recipients.txt`, so compromising it
yields "can push a release through the restricted door" and nothing else.

Commands (extend `stackbase/secrets_cli.py`; reuse `secrets.py` machinery —
generalise `load_secrets/save_secrets` over a file name + recipients file):

- `./infra/up deploy-key init` — generate the key in RAM only
  (`ramdir.private_ram_dir`, like `ci.py` does), write `infra/deploy.age`,
  and write the PUBLIC half to `infra/keys/deploy.pub` (committed). Refuses
  if `deploy.age` exists (`--rotate` replaces both and prints a reminder to
  run `./infra/up` then `ci-setup` again).
- `./infra/up deploy-key show-pub` — prints the public half (from `deploy.pub`).
- `./infra/up ci-setup` — CHANGE: no longer generates its own key. It
  requires `deploy.age` (runs `deploy-key init` if absent), decrypts it to
  RAM, and pushes the private key as the repo-level GitHub secret
  `STACK_DEPLOY_KEY` exactly as today. One project key, used by CI and by
  humans. Remove the old separate CI key path (`ciDeployKeys` in the
  template flake reads `infra/keys/deploy.pub` now; keep the attr name or
  rename — plan decides, README follows).
- `./infra/up deploy …` — SSH identity resolution order: (1)
  `STACKBASE_SSH_IDENTITY` if set; (2) `infra/deploy.age` decrypted to a
  RAM dir for the duration of the command; (3) the existing ssh-agent path,
  with a one-line warning that no project key was found. Plaintext never
  touches disk outside the RAM dir.
- The age identity for decrypting either file is the existing
  `STACKBASE_AGE_IDENTITY` mechanism (`secrets._identity_path`); document
  that on a build host it is a file identity, on laptops it may be a YubiKey.
- The template flake's `stackbase.deploy.keys` = admins ∪ {deploy.pub}.
  `admins` keep opening the deploy door (a YubiKey laptop can always deploy).

Guards + docs:
- `templates/infra/.gitignore` gains: `secrets/`, `*.key`, `id_ed25519*`,
  `id_rsa*`, `*.pem`, `*.age.tmp` (keep the existing entries).
- README: a new "Things to watch" section: (1) the tool NEVER decrypts to
  disk — never run `age -d` by hand into the repo; (2) `conf.d` files have
  full NixOS power (can `mkForce` past hardening) — control is code review /
  the upcoming repo-wide quality checker; (3) what you push is your working
  tree (see B).

## B. `infra/conf.d/` — project-wide NixOS modules

- Template flake: every `infra/conf.d/*.nix` is imported on EVERY node
  (`builtins.readDir` + `hasSuffix ".nix"` filter). Missing directory = no
  modules. `infra/nodes/<name>/extra.nix` stays for single-node quirks.
- `up` refuses to push when `git status --porcelain -- infra/` lists any
  modified/untracked `*.nix` or `stack.toml`, EXCEPT files the tool itself
  writes (`nodes/*/hardware-configuration.nix`, `flake.lock`,
  `stack.state.json`, `known_hosts`, `keys/*.pub`, `*.age`). Override:
  `--allow-dirty`. Not a git repo → warn once, proceed.
- VM test: a `conf.d/hello.nix` that adds a marker file; assert it exists.

## C. `stackbase.backups` — base module, every server

Model: `~/code/techspace/hanskraft/nixos/service.nix` lines ~200–320
(pg_dump → zstd → age → rclone to R2, prune by age; uploads tar the same
way). Make it generic in `nixos/backups.nix`:

Options: `enable` (default = bucket set), `bucket`, `retentionDays` (30),
`extraPaths` ([]), `recipientsFile` (default `infra/age-recipients.txt` as
shipped to the node under `/etc/nixos/stack/`), `onCalendar` ("03:00" UTC).
`stack.toml`:
```toml
[backups]
bucket = "hanskraft-backups"
retention_days = 30
extra_paths = ["/var/lib/hanskraft/uploads"]
```
Runtime: `stackbase-backup.service` + `.timer`, runs as root. For the
project's DB: `pg_dump` (peer, as postgres) | zstd | `age -R recipients`
→ `backup:<bucket>/db/<project>_<UTC stamp>.sql.zst.age`. Each extra path:
`tar -C path -cf - . | zstd | age` → `backup:<bucket>/files/<basename>_<stamp>.tar.zst.age`.
Then `rclone delete --min-age <retention>d` on both prefixes. Credentials:
root-only `/var/lib/stackbase/backup.env` (0600) written by a new `up` step
from `r2_access_key_id` / `r2_secret_access_key` / `r2_endpoint`, using
rclone's env-config form (`RCLONE_CONFIG_BACKUP_TYPE=s3`,
`RCLONE_CONFIG_BACKUP_PROVIDER=Cloudflare`, `..._ACCESS_KEY_ID`,
`..._SECRET_ACCESS_KEY`, `..._ENDPOINT`). No secrets in the Nix store.
`RCLONE_CONFIG_BACKUP_TYPE=local` must also work (VM test: bucket = a
directory; assert an `.age` file appears and decrypts with the test
identity to a valid dump).
- `./infra/up backup-now` — runs the unit on each node over SSH and prints
  `rclone lsl backup:<bucket>` afterwards.
- README: "Restore" — `age -d` + `zstd -d` + `psql`, and the files variant.

## D. Building on NixOS (`stackbase/release.py`)

- If `CC_x86_64_unknown_linux_musl` / `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER`
  are unset and `x86_64-unknown-linux-musl-gcc` is on PATH, set both to it
  (this is what obi's workflow does by hand). Keep the existing `musl-gcc`
  behaviour on other distros.
- Persistent incremental builds: unless `CARGO_TARGET_DIR` is set, use
  `${XDG_CACHE_HOME:-~/.cache}/stack-base/target/<project>`. The worktree
  stays clean/detached as today; only the target dir persists.
- Tailwind: prefer `tailwindcss` on PATH over `tools/tailwindcss` (the
  downloaded standalone binary cannot run on NixOS). Error hint lists both.

## E. CI template

`templates/github/deploy-stack.yml`: `runs-on: [self-hosted, x86_64-linux]`;
drop the `apt-get install musl-tools` step (NixOS runner has the cross
compiler); keep `rustup target add x86_64-unknown-linux-musl`. Comment
explains self-hosted minutes are free and where the runner lives.

## F. Cosmetic

`status` before the first release prints "✗ invalid color: none" above the
correct output — make `none` a valid "no release yet" state.

## G. Release

Bump `stackbase.__version__` to `0.1.0`; the plan's last task tags
`v0.1.0` (tag only — Matt pushes/decides). The `infra/up` wrapper's
GitHub fetch of a pinned tag must work against the real public repo
`TechSpaceAsia/stack-base` (add/keep a test that only mocks the network).

## Out of scope (separate work, not in this plan)

nixos-ollama host changes (`release` user, toolchain, cleanup timer) live in
platform-base and are done by the controller; hanskraft's `infra/`; Cloudflare.

## Global constraints (carry into the plan)

- stdlib-only Python 3.11+, tests via `python3 -m unittest discover -s tests`.
- NixOS modules must keep `nix flake check` and both VM checks
  (`tests/vm.nix`, `tests/vm-deploy.nix`) green; new behaviour gets VM
  subtests where it runs on the node.
- No plaintext secret ever written outside `ramdir.private_ram_dir`.
- Every user-facing change is documented in README.md in the same task.
- Match existing code style/comment density (see `stackbase/ci.py`).
