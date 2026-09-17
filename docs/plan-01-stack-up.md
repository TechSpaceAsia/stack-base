# stack-base — Plan 01: "stack up" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> This plan is deliberately lean (interfaces + named test cases, not full code) — the design was agreed in conversation and the owner asked to economise on planner tokens. Implementers write the code; the **Interfaces** blocks are binding.

**Goal:** One command (`./infra/up`) takes a project's `infra/stack.toml` from "VPS ids (or nothing)" to hardened NixOS nodes serving over a proxied Cloudflare hostname — safe to re-run, never able to cancel a server.

**Architecture:** A stdlib-only Python package (`stackbase/`) reconciles a declarative `stack.toml` against the Hostinger and Cloudflare REST APIs, then pushes a flake-pinned NixOS config to each node over SSH and rebuilds *on the node*. Machine-written facts (vps ids, IPs, applied version) live in a committed `infra/stack.state.json`, never in the human-edited TOML. Projects pin one stack-base revision via `flake.lock`; a tiny bootstrap fetches that exact revision and runs it, so scripts and Nix modules always match.

**Tech Stack:** Python ≥ 3.11 stdlib only (`tomllib`, `urllib`, `json`, `subprocess`, `unittest`, `http.server` for fakes). System tools: `ssh`, `rsync`, `ssh-keyscan`, `age`, `git`. Nix flakes on the node (NixOS 26.05). No OpenTofu, no pip dependencies.

**Out of scope (later plans):** 02 blue/green deploy + 5-release retention; 03 Postgres WAL archiving/PITR; 04 replica + fenced auto-failover; `doctor`; release-notification workflow; auto-patch timer.

## Global Constraints

- Python: **stdlib only**. No `requests`, no `pytest` — tests are `unittest`, run with `python3 -m unittest discover -s tests -v`.
- **No delete path.** No code may issue `DELETE` against `/api/vps/v1/virtual-machines*` or `/api/billing/*`. A test enforces this by scanning the client source and the `Action` enum.
- **Purchasing** requires BOTH the `--allow-purchase` flag AND a typed confirmation of the exact string `buy <plan> x<count>`; non-TTY stdin ⇒ refuse.
- Secrets (Hostinger token, Cloudflare token, origin cert key) exist only in memory and in `infra/secrets.age`. Never written plaintext to disk, never logged; any log line passes through `redact()`.
- Every network call: 30 s timeout, max 4 retries with exponential backoff, honours `Retry-After` on HTTP 429.
- Every failure ends the run with exit code 1 and ONE plain-English line: what failed + what to check. No tracebacks unless `--debug`.
- Every step is check-then-act: a re-run after any failure must converge; a run against a converged stack prints `nothing to do` and exits 0.
- SSH always uses `-o UserKnownHostsFile=infra/known_hosts -o StrictHostKeyChecking=yes` after first contact. Host keys are pinned on first contact only.
- NixOS: sshd key-only, `PermitRootLogin prohibit-password`, `AllowUsers` = admins; nginx 443 reachable only from Cloudflare ranges; Postgres socket-only (`listen_addresses = ''`), peer auth. sshd listen address is ONE module option (`stackbase.ssh.listenAddresses`).
- Shell snippets shown to users use shell variables for fill-ins, never inline placeholders.
- Commit after each task. Commit messages end with `Co-Authored-By: Claude <model> <noreply@anthropic.com>` as supplied by the dispatcher.

## File Structure

```
stack-base/
  README.md                       operator guide, written for non-infra teammates
  flake.nix  flake.lock           exports nixosModules.{base,appHost,postgres} + lib.mkNode
  bin/up                          entrypoint: `python3 -m stackbase` with repo on sys.path
  stackbase/
    __main__.py                   argparse CLI: up [--plan] [--allow-purchase] [--debug], ssh <node>
    config.py                     stack.toml → StackConfig; stack.state.json ↔ StackState
    secrets.py                    age decrypt/encrypt in memory; redact()
    http.py                       request(): timeout, retries, 429 backoff, JSON, ApiError
    hostinger.py                  HostingerClient
    cloudflare.py                 CloudflareClient
    ssh.py                        wait/pin/run/rsync
    reconcile.py                  observe() → plan() → apply(); Action enum
    errors.py                     StackError(message, hint)
  nixos/
    base.nix  app-host.nix  postgres.nix  cloudflare-ips.nix
  templates/infra/                copied into a project by /new-platform
    up  stack.toml.example  flake.nix  age-recipients.txt  .gitignore
  tests/
    fakes.py                      FakeHostinger / FakeCloudflare (http.server in a thread)
    test_config.py test_secrets.py test_http.py test_hostinger.py
    test_cloudflare.py test_ssh.py test_reconcile.py test_no_delete.py
    vm.nix                        NixOS VM test
  docs/vendor/hostinger-openapi.json   reference copy of the API spec
```

`stack.toml` schema (all keys required unless noted):

```toml
project    = "acme"                 # [a-z][a-z0-9-]{1,30}
domain     = "acme.example.com"     # FQDN; its Cloudflare zone is found by longest-suffix match
owner      = "github-handle"
datacenter = "kul"                  # Hostinger data-centre name
plan       = "KVM 1"                # informational; purchase uses price_item below
price_item = ""                     # optional; Hostinger catalog price-item id, required only to purchase
auto_patch = true                   # optional, default true (consumed by a later plan)
admins     = ["matt"]               # each needs infra/keys/<name>.pub

[nodes.a]
role   = "primary"                  # exactly one primary; others "replica"
vps_id = 1984476                    # optional; absent ⇒ node must be purchased
```

`stack.state.json`: `{"version": 1, "nodes": {"a": {"vps_id": 1984476, "ipv4": "…", "ipv6": "…", "host_key_pinned": true, "hardware_captured": true, "applied_rev": "…"}}, "cloudflare": {"zone_id": "…", "record_id": "…"}, "hostinger": {"firewall_id": 1, "ssh_key_ids": {"matt": 1}}}`

---

### Task 1: Scaffold, errors, config model

**Files:** Create `bin/up`, `stackbase/{__init__,errors,config}.py`, `tests/test_config.py`, `.gitignore`, `README.md` (stub heading only).

**Interfaces — Produces:**
- `errors.StackError(message: str, hint: str)`; `str(e)` → `"<message> — <hint>"`.
- `config.Node(name: str, role: str, vps_id: int | None)`
- `config.StackConfig(project, domain, owner, datacenter, plan, price_item: str | None, auto_patch: bool, admins: list[str], nodes: dict[str, Node], admin_keys: dict[str, str])`
- `config.load_config(infra_dir: Path) -> StackConfig` — reads `stack.toml` and `keys/<admin>.pub`; raises `StackError` on any violation.
- `config.StackState` (dataclass mirroring the JSON above, all fields defaulted); `load_state(infra_dir) -> StackState` (missing file ⇒ empty state); `save_state(infra_dir, state)` — atomic write (tmp + `os.replace`), sorted keys, trailing newline.

- [ ] Tests first (`test_config.py`): valid file loads; rejects bad project name; rejects zero or two primaries; rejects admin without `.pub` file; rejects a `.pub` that is not a single `ssh-ed25519`/`sk-ssh-ed25519@openssh.com`/`ssh-rsa` line; `vps_id` optional; state round-trips byte-identically; missing state file ⇒ empty state.
- [ ] Run, confirm they fail; implement; run, confirm pass; commit.

### Task 2: HTTP core + secrets

**Files:** Create `stackbase/{http,secrets}.py`, `tests/{fakes,test_http,test_secrets}.py`.

**Interfaces — Produces:**
- `http.ApiError(StackError)` with `.status: int`, `.body: str`.
- `http.request(method, url, *, token, json_body=None, timeout=30, retries=4, sleep=time.sleep) -> dict | list` — Bearer auth, JSON in/out, retries on 429/502/503/504 and `URLError`, honours `Retry-After`, never retries other 4xx. `method == "DELETE"` is allowed here (Cloudflare/firewall rules need it); the VM guard lives in Task 3.
- `secrets.redact(text: str, values: Iterable[str]) -> str`
- `secrets.load_secrets(infra_dir) -> dict[str, str]` — runs `age -d` with identity from `$STACKBASE_AGE_IDENTITY` or `~/.age/key.txt`; payload is a JSON object. Missing `secrets.age` ⇒ `StackError` whose hint shows the exact create command.
- `secrets.save_secrets(infra_dir, data)` — pipes JSON to `age -R infra/age-recipients.txt -o infra/secrets.age` via stdin; plaintext never touches disk.
- `fakes.FakeServer` — context manager starting `http.server` on port 0 in a thread; `.url`, `.requests` (recorded method/path/body), `.script(method, path, status, body, headers=None)` queueing responses.

- [ ] Tests first: 429 with `Retry-After: 2` sleeps 2 then succeeds; 4 consecutive 503 ⇒ `ApiError`; 400 not retried; token never appears in `str(ApiError)`; secrets round-trip using a throwaway `age-keygen` identity in a temp dir (skip test if `age` missing); `redact` masks all values.
- [ ] Fail → implement → pass → commit.

### Task 3: Hostinger client

**Files:** Create `stackbase/hostinger.py`, `tests/test_hostinger.py`, `tests/test_no_delete.py`, `docs/vendor/hostinger-openapi.json`.

- [ ] First: download the official OpenAPI document from `https://github.com/hostinger/api` (raw `openapi.json`) into `docs/vendor/`. **Every path, field name and response shape below must be checked against it; where this plan disagrees with the spec, the spec wins — note the difference in the commit message.**

**Interfaces — Produces** `HostingerClient(token, base_url="https://developers.hostinger.com")`:
- `list_vms() -> list[dict]`, `get_vm(vps_id) -> dict` (keys used downstream: `id`, `state`, `ipv4[].address`, `ipv6[].address`, `actions_lock`)
- `data_center_id(name: str) -> int`, `template_id(name_prefix="NixOS") -> int` (highest version wins; `StackError` if none)
- `ensure_public_key(name, key) -> int` (list, match by key body, create if absent)
- `setup_vm(vps_id, *, template_id, data_center_id, hostname, public_key_ids: list[int]) -> None` — a random 32-char password is generated, sent, and discarded (key-only access; password login is disabled by NixOS config).
- `purchase_vm(*, price_item, template_id, data_center_id, hostname, public_key_ids) -> int` (returns new vps id)
- `wait_running(vps_id, timeout=900, poll=10, sleep=time.sleep) -> dict` — until `state == "running"` and `actions_lock == "unlocked"`.
- `ensure_firewall(name, rules: list[dict]) -> int` and `activate_firewall(firewall_id, vps_id)` — rules are diffed by (protocol, port, source); rule deletes ARE permitted (firewall rules only).

- [ ] Tests first (against `FakeServer`): each method hits the right path/body; `ensure_public_key` is idempotent; `wait_running` times out with a hint naming hPanel; `ensure_firewall` adds missing + removes stale rules and is a no-op when equal.
- [ ] `test_no_delete.py`: parse `stackbase/hostinger.py` with `ast`; fail if any string literal containing `virtual-machines` or `billing` is used in a call whose method argument is `"DELETE"`; fail if `reconcile.Action` (when present) has a member whose name contains `DELETE`, `DESTROY` or `CANCEL`.
- [ ] Fail → implement → pass → commit.

### Task 4: Cloudflare client

**Files:** Create `stackbase/cloudflare.py`, `tests/test_cloudflare.py`.

**Interfaces — Produces** `CloudflareClient(token, base_url="https://api.cloudflare.com/client/v4")`:
- `zone_for(domain) -> tuple[str, str]` (zone_id, zone_name) — longest-suffix match over `GET /zones?name=`.
- `upsert_a_record(zone_id, name, ipv4, *, proxied=True) -> str` (record id; no-op if already equal)
- `ip_ranges() -> tuple[list[str], list[str]]` (v4, v6 from `GET /ips`)
- `create_origin_cert(hostnames: list[str], csr_pem: str, days=5475) -> str` (PEM) via `POST /certificates`.

- [ ] Tests first: suffix match picks `example.com` for `a.b.example.com`; upsert creates, updates on IP change, no-ops when equal; API `success:false` ⇒ `ApiError` carrying Cloudflare's message.
- [ ] Fail → implement → pass → commit.

### Task 5: SSH layer

**Files:** Create `stackbase/ssh.py`, `tests/test_ssh.py`.

**Interfaces — Produces** `Ssh(infra_dir, host, user="root", runner=subprocess.run)`:
- `wait_port(timeout=600)`; `pin_host_key()` (ssh-keyscan ed25519 → append to `infra/known_hosts`; refuses if an entry for the host already exists with a DIFFERENT key — hint explains MITM vs. re-install); `run(cmd: str, *, check=True, input=None) -> CompletedProcess`; `rsync_to(local_dir, remote_dir, *, delete=True)`; `fetch(remote_path) -> bytes`; `argv() -> list[str]` (for the `ssh <node>` CLI subcommand to `os.execvp`).

- [ ] Tests first (inject `runner`): every ssh/rsync argv carries both `-o` options from Global Constraints; `pin_host_key` appends once, is idempotent for same key, raises on changed key.
- [ ] Fail → implement → pass → commit.

### Task 6: NixOS modules + flake + VM test

**Files:** Create `flake.nix`, `nixos/{base,app-host,postgres,cloudflare-ips}.nix`, `tests/vm.nix`.

**Interfaces — Produces:**
- `nixosModules.base` — options under `stackbase.*`: `project` (str), `admins` (attrsOf str: name → pubkey), `ssh.listenAddresses` (listOf str, default `[]` = all). Config: admin users in `wheel` with passwordless sudo, sshd per Global Constraints plus `MaxAuthTries 3` and `PerSourcePenalties`, fail2ban, journald `SystemMaxUse=500M`, `nix.settings.experimental-features = [ "nix-command" "flakes" ]`, weekly nix GC, firewall allowing only 22 + 443.
- `nixosModules.appHost` — nginx with recommended TLS/proxy settings; vhost `stackbase.domain` using cert/key at `/var/lib/stackbase/origin.{crt,key}`; `allow` for every Cloudflare range (from `cloudflare-ips.nix`, a plain attrset `{ v4 = [..]; v6 = [..]; }`) then `deny all`; `real_ip` from `CF-Connecting-IP`; proxies to `unix:/run/<project>/app.sock`; until an app is deployed, serves a static "stack is up" page on a `/__stack` location so acceptance can be verified.
- `nixosModules.postgres` — PostgreSQL 16, `listen_addresses = ''`, peer auth only, database + role named `stackbase.project`.
- `lib.mkNode { system ? "x86_64-linux", modules }` → `nixosSystem` importing all three modules.
- Input: `nixpkgs` = `github:NixOS/nixpkgs/nixos-26.05`.

- [ ] `tests/vm.nix` (wired as `checks.x86_64-linux.vm`): boots a node; asserts sshd `PasswordAuthentication no` (`sshd -T`); `curl` from a non-Cloudflare source to 443 gets 403; `ss -ltn` shows no `:5432`; `sudo -u postgres psql -c 'select 1'` works; `/__stack` returns 200 when the request comes from an allowed range.
- [ ] Run `nix flake check`; implement until green; commit including `flake.lock`.

### Task 7: Reconciler + CLI + project template

**Files:** Create `stackbase/{reconcile,__main__}.py`, `tests/test_reconcile.py`, `templates/infra/*`, flesh out `README.md`.

**Interfaces — Consumes** everything from Tasks 1–6. **Produces:**
- `reconcile.Action` enum: `PURCHASE, SETUP, WAIT_RUNNING, ENSURE_KEYS, ENSURE_FIREWALL, PIN_HOST_KEY, CAPTURE_HARDWARE, ENSURE_ORIGIN_CERT, PUSH_CONFIG, REBUILD, UPSERT_DNS`.
- `observe(cfg, state, hostinger, cloudflare) -> Observed`; `plan(cfg, state, observed) -> list[Step]` — **pure**, no I/O; `apply(steps, ctx, *, allow_purchase, confirm=input) -> StackState`, saving state after every successful step.
- `CAPTURE_HARDWARE`: `fetch` the node's `/etc/nixos/*.nix` into `infra/nodes/<name>/` (first contact only). `PUSH_CONFIG`: rsync `infra/` (excluding `secrets.age`, `keys/`) to `/etc/nixos/stack/`; write origin cert + key to `/var/lib/stackbase/` over ssh stdin, mode 0600. `REBUILD`: `nixos-rebuild test --flake /etc/nixos/stack#<node>` → open a NEW ssh connection and run `true` → only then `nixos-rebuild switch`; on failure of the probe, hint says "reboot the VPS from hPanel to return to the previous config".
- `templates/infra/up`: reads the stack-base rev from `infra/flake.lock`, `git fetch`es it into `~/.cache/stack-base/<rev>` (URL from `flake.lock`, overridable with `$STACKBASE_SRC` pointing at a local checkout), then `exec`s `bin/up` there with `--infra-dir`.
- `templates/infra/flake.nix`: `inputs.stack-base`; one `nixosConfigurations.<node>` per entry, generated from `stack.toml` via `builtins.fromTOML` + `stack.state.json`, importing `./nodes/<name>/hardware-configuration.nix`.

- [ ] Tests first (`test_reconcile.py`, pure `plan()` plus `apply()` against fakes): fresh node with `vps_id` in `initial` ⇒ `[ENSURE_KEYS, SETUP, WAIT_RUNNING, ENSURE_FIREWALL, PIN_HOST_KEY, CAPTURE_HARDWARE, ENSURE_ORIGIN_CERT, PUSH_CONFIG, REBUILD, UPSERT_DNS]`; converged stack ⇒ `[]`; node without `vps_id` and no flag ⇒ `StackError` mentioning `--allow-purchase`; with flag but wrong typed confirmation ⇒ refuses, zero purchase requests recorded; non-TTY ⇒ refuses; failure at step N leaves state saved through N-1 and a re-plan resumes at N; `--plan` performs zero non-GET requests.
- [ ] Fail → implement → pass; run full suite + `nix flake check`; commit.

### Task 8: Live acceptance (dispatcher-run, needs the owner)

- [ ] In a scratch project dir: `stack.toml` with `nodes.a.vps_id = 1984476`, `keys/matt.pub`, `secrets.age` holding the Hostinger + Cloudflare tokens.
- [ ] `./infra/up --plan` → review with the owner → `./infra/up`.
- [ ] Verify: `curl -sS https://$DOMAIN/__stack` returns 200 via Cloudflare; direct-to-origin 443 is refused; `ssh` with password auth is refused; second `./infra/up` prints `nothing to do`.
- [ ] Record what the Hostinger NixOS template actually ships (bootloader, network config, whether the API key landed for root) in `README.md`; fix Task 6/7 assumptions if they were wrong.
