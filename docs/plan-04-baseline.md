# stack-base — Plan 04: the standard-server baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every stack-base server, by default, keeps its database backed up, archives its logs off-box hourly with per-project retention, and emails someone when either stops working — plus the four first-run fixes from Amalan Setar's 21 Oct report.

**Architecture:** Three new node modules reuse the backups pipeline's shape (`… | zstd | age -R <project recipients> | rclone` to the project's bucket, credentials from a 0600 env file pushed by `./infra/up`, never in the Nix store): `nixos/logs.nix` archives closed journald segments hourly to `logs/<host>/` with read-back verification and in-script retention; `nixos/mesh.nix` joins Cloudflare Mesh; `nixos/alerts.nix` installs nullmailer (relaying over Mesh), an `OnFailure=` template unit and a freshness watchdog. `./infra/up` refuses to run without backups unless explicitly opted out. On the laptop side, the Hostinger purchase path records the 202 reply's `subscription_id` and adopts by it.

**Tech Stack:** stdlib-only Python 3.11+ (`unittest`), NixOS modules + `pkgs.writeShellApplication`, `pkgs.testers.runNixOSTest`, `age`, `rclone`, `zstd`, `nullmailer`, `cloudflare-warp`.

**Spec:** this document's "Brief" section (agreed with Matt, 2026-11-03). Plans 01–03 are shipped; this plan does not change their contracts except where the Brief says so.

## Brief (decisions agreed 2026-11-03)

- stack-base is THE standard for project servers going forward. ops-01 (mail) and the old shared host are out of scope.
- **A. Hostinger 202.** Docs (`docs/vendor/hostinger-openapi.json`, `POST /api/vps/v1/virtual-machines`) say a 202 means payment is processing and the VM was *not* set up; its body (`Billing.V1.Order.PaymentProcessingResource`) carries `subscription_id` (nullable string — "use it to find the product once the order completes"), and every `VirtualMachineResource` carries `subscription_id`. Record it as a pending purchase; adopt by it; never purchase for a node with a pending marker. Before relying on it, confirm with one read-only `GET /api/vps/v1/virtual-machines` that live VMs include `subscription_id` (Amalan's 2081685 is a known 202-born VM). No live purchase is made to test this.
- **B. CI regression guard.** `templates/github/deploy-stack.yml` must never use `hashFiles(` or an action that needs node20 (`actions/cache`, anything pinned below checkout v5).
- **C. Runner preflight.** First step of the template workflow checks `python3 rsync tailwindcss x86_64-unknown-linux-musl-gcc rustup git ssh` and fails with one line naming every missing tool.
- **D. Logs.** Hourly; whole native journal segments (restore = `journalctl --file`); one project per server, so retention per project = `[logs] retention_days` in that project's `stack.toml` (default 90; OBI sets 365). Uses `[backups].bucket` under `logs/`. Encrypted with the project's age recipients like backups (no extra machinery; restore needs an admin's age identity). Local journald: 7 days, `MaxFileSec=1h`, existing `SystemMaxUse=500M`.
- **E. Backups required.** `./infra/up` (apply and `--plan`) refuses when `stack.toml` has no `[backups].bucket`, unless `[backups] enabled = false`, which prints a warning on every run. Same for logs (`[logs] enabled = false`). **← confirm with Matt (alternative: auto-enable).**
- **F. Alerts.** `[alerts] to = [...]` in `stack.toml` (ours: `ops-alerts@techspace.org.uk` + `servers.<project>.<env>@techspace.org.uk`). SMTP from `secrets.age`: `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from` (stack-base is public, so nothing TechSpace-specific is baked in; ours = `mail.techspace.org.uk:465` reached over Mesh, one SMTP-only Stalwart principal per server, restricted to its own sender and exact recipients — same model as `docs/infra/company-ops-fleet-mail.md` in platform-base). Delivery through **nullmailer** (durable queue: an alert raised while Mesh or ops-01 is down is delivered when it returns). Alerts on failure of backup or logs units, and an hourly watchdog (backup ≤ 36 h old, logs ≤ 3 h). At most one email per failing unit per 6 h. If `[alerts]` is absent, `up` warns (does not refuse).
- **H. Mesh (decided 2026-11-03: stack-base servers are on Cloudflare Mesh).** New `[mesh]` table; `enabled = true` installs headless `cloudflare-warp` (module shape from platform-base `nixos/cloudflare-mesh.nix`, firewall not opened) and `./infra/up` enrols the node once with `mesh_connector_token` from `secrets.age`, then verifies `warp-cli status` is Connected. stack-base stays generic (Mesh off unless `[mesh]` says so); platform-base's `install-stack-infra.sh` pre-fills `[mesh] enabled = true` so every TechSpace project gets it. The Cloudflare side (node token per server, include-only MASQUE device profile) is an operator step in the README. Moving SSH to Mesh-only is out of scope.
- **G. platform-base `install-stack-infra.sh`** must fail if its `project`/`binary` substitution into `stack.toml` did not happen (tracked as Task 8, done in the platform-base repo), and pre-fill `[mesh] enabled = true`.
- Release as **v0.2.0** (E is a behaviour change for existing projects: a project without `[backups]` must add it or opt out after upgrading).

## Global Constraints

- stdlib-only Python 3.11+. Suite: `python3 -m unittest discover -s tests` from the repo root. Nix: `nix flake check` (runs `tests/vm.nix`, `tests/vm-deploy.nix`).
- No plaintext secret outside `stackbase.ramdir.private_ram_dir()`; no secret value in argv, env of a subprocess, logs or output.
- Credentials files on the node are written by `./infra/up` steps, 0600 root:root, under `/var/lib/stackbase/`, values validated against an allowlist exactly like `stackbase/backups.py`'s `_R2_KEYS` handling; read by systemd `EnvironmentFile`, never `source`d.
- Every expected failure is `StackError(message, hint)`.
- Every user-facing change is documented in `README.md` in the same task.
- Match existing style: comments explain why; refusals say what to do instead.
- Nothing deletes a server, DNS record, firewall or release; `tests/test_no_delete.py` stays green. The only deletes allowed are `rclone delete --min-age Nd` on this script's own literal prefix (`logs/`), with `N` from an `ints.positive` option.
- User-facing snippets use shell variables for fill-ins.
- One accepted exception to "no secret in argv": `warp-cli connector new` takes the enrolment token only as an argument. It runs once, on the node, as root, fed from stdin by `sh -c 'warp-cli connector new "$(cat)"'` so it never appears in the laptop's argv or the SSH command line; documented in the code comment.

## Review Focus

1. **Upload succeeds, read-back fails** (R2 hiccup): the spool must survive and be retried next hour; no receipt written. Test in Task 4 (`test_readback_mismatch_keeps_spool`, VM subtest).
2. **Server off for days, then back:** the first run must upload every closed segment still on disk, oldest first, without tripping the 3 h watchdog email before it has had a chance to run. Task 5 watchdog runs `After=` the logs unit and the alert has a grace check (`test_watchdog_grace_after_boot`).
3. **Journal vacuumed a segment between enumeration and open:** fail visibly (alert), never silently skip. Task 4 (`test_vanished_segment_fails`).
4. **Existing project upgrading to v0.2.0 with no `[backups]`:** the refusal message must say exactly the two ways forward (`bucket = …` or `enabled = false`). Task 6 (`test_up_refuses_without_backups_names_both_options`).
5. **`subscription_id` missing or null on live VMs:** adoption must then fall back to today's refusal with a hint naming the pending subscription id, never to purchasing. Task 1 (`test_pending_without_matching_vm_never_purchases`).

---

### Task 1: Hostinger 202 → pending purchase, adopt by subscription

**Files:** Modify `stackbase/hostinger.py:295-350` (`purchase_vm`), `stackbase/reconcile.py:794-827` (`_find_adoptable_vms`) and its plan/observe callers, `stackbase/config.py` (state: `NodeState.pending_subscription_id: str | None`), `stackbase/steps.py` (purchase step writes state). Tests: `tests/test_hostinger.py`, `tests/test_reconcile.py`, fixtures in `tests/fixtures/`.

**Interfaces:**
- `HostingerClient.purchase_vm(...) -> PurchaseResult` where `@dataclass PurchaseResult: vps_id: int | None; subscription_id: str | None; warnings: list[str]`. 200 → `vps_id` set. 202 → `vps_id=None`, `subscription_id` from body. 202 without a usable `subscription_id` → today's `StackError` unchanged.
- `stack.state.json` node entry gains `"pending_subscription_id"`; `load_state`/`save_state` round-trip it; absent = `None`.
- `_find_adoptable_vms(hostinger, cfg, node_names, pending: dict[str, str]) -> dict[str, int]`: a node with a pending id matches ONLY the VM whose `subscription_id` equals it (hostname ignored); others keep hostname matching.
- Plan: a node with `pending_subscription_id` and no matching VM yields a new `Action.WAIT_PURCHASE` (never `PURCHASE`); its apply prints `error: purchase for node 'a' (subscription <id>) is still processing — re-run ./infra/up in a few minutes; if it never appears, find the VM in hPanel and set vps_id in stack.toml`. On ADOPT the marker is cleared and the existing setup path runs (sets the hostname).

- [ ] **Step 0: Live read-only check.** With an operator's token: `GET /api/vps/v1/virtual-machines`, confirm each VM object has `subscription_id`. Record the result (field present / absent, no values) in this plan's ledger. If absent, stop and report to Matt.
- [ ] **Step 1: Tests:** `test_purchase_202_returns_subscription_id` (fake 202 body `{"id":2957086,"subscription_id":"Azz353Uhl1xC54pR0","status":"payment_initiated"}` — the spec types it as a nullable string and describes it as "use it to find the product once the order completes"; null → today's StackError), `test_pending_marker_persisted_after_202`, `test_adopts_by_subscription_id_ignoring_hostname` (VM `srv2081685.hstgr.cloud`, matching subscription → ADOPT), `test_pending_without_matching_vm_never_purchases` (→ WAIT_PURCHASE, no PURCHASE in plan), `test_adopt_clears_pending_marker`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run the whole suite → PASS. README: "If a purchase says payment is processing".
- [ ] **Step 5: Commit** `hostinger: remember a 202 purchase's subscription and adopt by it`.

### Task 2: CI template guard

**Files:** Modify `tests/test_template.py`.

- [ ] **Step 1:** `test_ci_template_has_no_node20_dependencies`: read `templates/github/deploy-stack.yml`; assert `"hashFiles("` not in any non-comment line; assert no `uses:` line references `actions/cache`; every `uses: actions/checkout@` is pinned with a `# v5` (or higher) comment. Comment lines (stripped line starting `#`) are ignored, so the explanatory comment at line ~99 stays.
- [ ] **Step 2:** Run → PASS on current template; temporarily add `- uses: actions/cache@v4` to a copy in the test via a helper that checks a string → FAIL (the helper `_node20_violations(text) -> list[str]` is what's tested on both).
- [ ] **Step 3: Commit** `test: keep the CI template free of node20-only actions`.

### Task 3: Runner preflight step

**Files:** Modify `templates/github/deploy-stack.yml` (first step after checkout), `tests/test_template.py`, `README.md`.

- [ ] **Step 1:** Test `test_ci_template_preflight_lists_required_tools`: the step named `Check the runner has stack-base's tools` exists before any step that runs `./infra/up`, and its script mentions each of `python3 rsync tailwindcss x86_64-unknown-linux-musl-gcc rustup git ssh`.
- [ ] **Step 2:** Implement as a bash loop collecting `missing+=("$t")` for `! command -v "$t"`, then `echo "::error::this runner is missing: ${missing[*]} — use the production runner or add them to its extraPackages"; exit 1`.
- [ ] **Step 3:** Run → PASS. **Step 4: Commit** `ci template: fail fast when the runner lacks deploy tools`.

### Task 4: `nixos/logs.nix` — hourly verified journal archive

**Files:** Create `nixos/logs.nix`; modify the repo-root `flake.nix` (add to base modules), `templates/infra/flake.nix` (map `[logs]` → `stackbase.logs.*`), `stackbase/config.py` (`LogsConfig: enabled: bool | None, retention_days: int | None`, `_parse_logs`), `nixos/base.nix` (journald: add `MaxRetentionSec=7day`, `MaxFileSec=1h`), `tests/vm.nix`, `tests/test_config.py`, `tests/test_template.py`, `README.md`.

**Interfaces:**
- Options `stackbase.logs = { enable (bool, default = backups bucket != ""), retentionDays (ints.positive, 90), onCalendar ("hourly"), maxAgeHours (ints.positive, 3) }`. Bucket and credentials: `stackbase.backups.bucket` and `/var/lib/stackbase/backup.env` (same rclone remote `backup`).
- Unit `stackbase-logs.service` (+ `.timer`, `Persistent=true`, `RandomizedDelaySec=5m`), `Nice=10`, `IOSchedulingClass=idle`, `StateDirectory=stackbase-logs`.
- Script (`writeShellApplication`) per run: `journalctl --sync && journalctl --rotate`; for each `/var/log/journal/*/*@*.journal` sorted, id = sha256 of the path relative to `/var/log/journal`, skip if `receipts/<id>` exists; open-then-stream `zstd -19 -T1 | age -R <recipients>` into `spool/<id>.journal.zst.age.partial`, rename; `rclone copyto` to `backup:$BUCKET/logs/<hostname>/<UTC date of segment mtime>/<id>.journal.zst.age`; `rclone cat` it back and compare sha256 with the spool; on match write `receipts/<id>` and delete spool, else exit 1 leaving the spool. Spools from earlier runs are uploaded first. Then `rclone delete --min-age <retentionDays>d backup:$BUCKET/logs/<hostname>/`, delete receipts whose segment no longer exists, write `last-success` (epoch seconds).
- Free-space guard: refuse if free space on `/var/lib` < 512 MiB + 2× segment size.

- [ ] **Step 1: Tests.** `test_config.py`: `[logs] retention_days = 365` parses; `retention_days = 0` → StackError; unknown key → StackError. `test_template.py` (nix eval): `[logs] retention_days = 365` lands in `stackbase.logs.retentionDays`. `tests/vm.nix` subtests (local S3 via the existing VM backups fixture): `test_logs_uploads_closed_segment` (after `systemctl start stackbase-logs`, exactly one object under `logs/node/`; decrypting with the test identity and `journalctl --file` lists a message logged earlier with `logger stackbase-logs-probe`), `test_logs_second_run_uploads_nothing_new`, `test_readback_mismatch_keeps_spool` (make the fixture's read return wrong bytes → unit fails, spool kept, no receipt), `test_vanished_segment_fails` (remove a segment between enumeration and open via a test hook env var `STACKBASE_LOGS_TEST_PAUSE` — only honoured when the module's `testHooks` option is true; default false).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** `python3 -m unittest discover -s tests` and `nix flake check` → PASS.
- [ ] **Step 5:** README: "Logs" section — what's archived, layout, retention, restore: `rclone cat … | age -d -i "$AGE_IDENTITY" | zstd -d > seg.journal && journalctl --file seg.journal`.
- [ ] **Step 6: Commit** `logs: archive closed journal segments hourly to the backup bucket`.

### Task 5: `nixos/mesh.nix` — join Cloudflare Mesh

**Files:** Create `nixos/mesh.nix`, `stackbase/mesh.py` (laptop side: `ENSURE_MESH` step); modify repo-root `flake.nix` (module list), `templates/infra/flake.nix` (`[mesh]` → `stackbase.mesh.enable`), `stackbase/config.py` (`MeshConfig: enabled: bool`), `stackbase/reconcile.py` (`Action.ENSURE_MESH`), `stackbase/steps.py`, `tests/test_mesh.py`, `tests/test_template.py`, `README.md`.

**Interfaces:**
- Option `stackbase.mesh.enable` (bool, default false). When true: `services.cloudflare-warp = { enable = true; package = pkgs.cloudflare-warp.override { headless = true; }; openFirewall = false; }` plus the `/usr/sbin/nft` bind mount from platform-base's module (check whether the pinned nixpkgs still needs it; keep it only if so). `nixpkgs.config.allowUnfreePredicate` admits only `cloudflare-warp`.
- Observe: `warp-cli --accept-tos status` over root SSH → `connected: bool`. Plan: `[mesh] enabled` and not connected → `ENSURE_MESH`. Apply: needs `mesh_connector_token` in secrets.age (else `StackError` naming the key and the README section); enrol via stdin as in Global Constraints, `warp-cli --accept-tos connect`, poll status ≤ 60 s.
- `./infra/up` output after apply prints the node's Mesh IPv6 (`ip -6 addr show CloudflareWARP`) so the operator can record it.

- [ ] **Step 1: Tests** (`test_mesh.py`, fake SSH from `tests/fakes.py`): `test_mesh_disabled_plans_nothing`, `test_connected_node_plans_nothing`, `test_disconnected_node_plans_ensure_mesh`, `test_missing_token_names_secret_key`, `test_token_sent_on_stdin_not_argv` (assert the token string appears in no recorded argv). Template eval: `[mesh] enabled = true` → `services.cloudflare-warp.enable == true`. VM: build-only check that the module evaluates and the unit exists (no live enrolment in CI).
- [ ] **Step 2–4:** FAIL → implement → suite + `nix flake check` PASS.
- [ ] **Step 5:** README "Mesh": Cloudflare dashboard steps (create node, copy token, include-only MASQUE device profile), `./infra/up secrets set mesh_connector_token`, verify.
- [ ] **Step 6: Commit** `mesh: join Cloudflare Mesh when [mesh] enabled`.

### Task 6: `nixos/alerts.nix` — email on failure (over Mesh)

**Files:** Create `nixos/alerts.nix`; create `stackbase/alerts.py` (laptop side: `ENSURE_ALERT_ENV` step + `alert-test` command, modelled on `stackbase/backups.py`); modify `stackbase/reconcile.py` (`Action.ENSURE_ALERT_ENV`), `stackbase/steps.py`, `stackbase/__main__.py` (`alert-test`), `stackbase/config.py` (`AlertsConfig: to: list[str]`, each matching a simple `local@domain` regex), `templates/infra/flake.nix`, `tests/test_alerts.py`, `tests/vm.nix`, `README.md`.

**Interfaces:**
- secrets.age keys `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from` → `/var/lib/stackbase/alert.env` (0600) as `SMTP_HOST=…` etc.; allowlist-validated like `_R2_KEYS`.
- Options `stackbase.alerts = { to (listOf str, []), intervalHours (ints.positive, 6) }`. When `to != []`: `services.nullmailer` (remotes file rendered at service start from `/var/lib/stackbase/alert.env` into a 0600 runtime file, never the Nix store — same approach as platform-base `nixos/company-ops-mail-sender.nix`; `--port=465 --tls --auth-login`, CA bundle verified), and `stackbase-alert@.service` (`%i` = failing unit) that queues the message with `sendmail -t`, Subject `[<project>/<hostname>] <unit> FAILED`, body = `journalctl -u <unit> -n 50`; rate limit via `/var/lib/stackbase-alert/<unit>` timestamp. `onFailure = [ "stackbase-alert@%n.service" ]` on `stackbase-backup`, `stackbase-logs`, `stackbase-freshness`.
- `stackbase-freshness.service` (+ hourly timer, `After=stackbase-logs.service`): fails if logs `last-success` older than `logs.maxAgeHours`, or newest backup marker older than 36 h; skips (exit 0) while system uptime < `maxAgeHours`.
- `./infra/up alert-test` starts `stackbase-alert@alert-test.service` on each node over the root SSH path and prints "sent — check <to>".

- [ ] **Step 1: Tests:** `test_alerts.py`: env rendering, allowlist rejects `a$(id)`, missing smtp keys with `[alerts]` set → StackError naming the keys; `[alerts]` absent → plan warns once. VM: `test_alert_sent_on_unit_failure` (fixture SMTP sink in the VM receives one mail after forcing `stackbase-logs` to fail), `test_alert_queued_while_relay_down` (sink stopped → message stays in nullmailer's queue; sink started → delivered), `test_alert_rate_limited` (second failure within 6 h → no second mail), `test_watchdog_grace_after_boot`.
- [ ] **Step 2–4:** FAIL → implement → suite + `nix flake check` PASS. Backups module writes `/var/lib/stackbase-backup/last-success` on success (small change to `nixos/backups.nix`).
- [ ] **Step 5: Commit** `alerts: email when backups or log archiving stop working`.

### Task 7: Backups and logs on unless explicitly opted out

**Files:** Modify `stackbase/config.py` (`BackupsConfig.enabled: bool | None`), `stackbase/reconcile.py` (plan-time check), `stackbase/__init__.py` + `templates/infra/flake.nix` (version → `0.2.0`, kept equal per the existing test), `templates/infra/stack.toml.example` (uncomment `[backups]` and add `[logs]`/`[alerts]`/`[mesh]` sections with comments), `tests/test_config.py`, `tests/test_reconcile.py`, `README.md` (upgrade note for v0.2.0), `CHANGELOG`/release notes if the repo has them.

- [ ] **Step 1: Tests:** `test_up_refuses_without_backups_names_both_options` (no `[backups]` → `StackError` whose hint contains both `bucket = ` and `enabled = false`), `test_backups_opt_out_warns` (`enabled = false` → plan proceeds and output contains the warning), `test_logs_follow_backups` (no bucket + backups opted out → logs off, warning mentions logs too), `test_enabled_false_with_bucket_is_an_error`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `up: require backups (or an explicit opt-out); release v0.2.0`. Do NOT tag or push; Matt cuts the release.

### Task 8 (platform-base repo): verify the stack.toml substitution, pre-fill Mesh

**Files:** `~/code/techspace/platform-base/.claude/skills/new-platform/scripts/install-stack-infra.sh:113-120`.

- [ ] After the `sed`, `grep -qx "project = \"${CRATE_KEBAB}\"" "$STACK_TOML" && grep -qx "binary = \"${CRATE_NAME}\"" "$STACK_TOML"` or `rm "$STACK_TOML"` and exit 1 with `install-stack-infra.sh: stack.toml.example no longer has the expected project/[app] lines — update the sed in this script`.
- [ ] Also append `[mesh]\nenabled = true` to the generated `stack.toml` (TechSpace projects are always on Mesh), and include it in the same verification.
- [ ] Verify by running the script against a scratch target with the real example (passes) and a doctored example with the `# binary` line removed (fails, no stack.toml left).
- [ ] Commit on a platform-base branch (no changelog: internal tooling).
