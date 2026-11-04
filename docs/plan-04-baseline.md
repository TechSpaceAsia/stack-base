# stack-base — Plan 04: the standard-server baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stack-base project is a best-practice pair of matching environments, staging and production. Each has its own servers, database backups, logs streamed to R2, uploaded files in R2 under a bucket lock, Cloudflare Mesh, and email when anything fails. The plan also carries the four first-run fixes from Amalan Setar's 21 Oct report.

**Architecture:**
- **Environments.** `stack.toml` gains `[environments.<env>]` tables. They carry only what is allowed to differ (servers, domain, buckets, alert recipients). Everything else is shared, so staging and production match by construction. State and secrets are kept per environment, so staging never holds production secrets.
- **Laptop side (`./infra/up`).** A new Cloudflare account client ensures the R2 buckets, the lifecycle rule for logs and the bucket lock for files.
- **Node side, four new modules:**
  - `nixos/logs.nix` runs Vector: journald → trimmed NDJSON → gzip → R2, with a disk buffer and end-to-end acknowledgements, plus a 3-day plain-text local copy for `rg`.
  - `nixos/mesh.nix` joins Cloudflare Mesh.
  - `nixos/alerts.nix` installs nullmailer (over Mesh) and a top-level `service.d` drop-in that mails any failed service.
  - `nixos/files.nix` hands the app its R2 media credentials.
- **Backups.** `./infra/up` refuses to run without backups unless the project explicitly opts out.

**Tech Stack:** stdlib-only Python 3.11+ (`unittest`); NixOS modules, `pkgs.writeShellApplication` and `pkgs.testers.runNixOSTest`; Vector (`services.vector`); `nullmailer`, `cloudflare-warp`, `age`, `rclone`, `zstd`; the Cloudflare v4 API (R2 buckets, lifecycle, lock).

**Spec:** this document's "Brief" section, agreed with Matt on 2026-11-03/04. The logs design follows the Vector architecture Matt approved on 2026-11-04, kept in platform-base's conversation record; its exact settings are copied into Brief D below. Plans 01–03 are shipped, and this plan changes their contracts only where the Brief says so.

## Brief (decisions agreed 2026-11-03/04)

- stack-base is THE standard for project servers going forward. A project is "best practice" when it has:
  - matching staging and production;
  - a backed-up database;
  - logs off-box;
  - files in R2 (preferred) or backed up from disk;
  - Mesh;
  - failure email.

  ops-01 (mail) and the old shared host are out of scope; platform-base handles them.
- **A. Hostinger 202.** What the docs say (`docs/vendor/hostinger-openapi.json`, `POST /api/vps/v1/virtual-machines`):
  - A 202 means payment is processing and the VM was *not* set up.
  - Its body (`Billing.V1.Order.PaymentProcessingResource`) carries `subscription_id`. That's a nullable string, described as "use it to find the product once the order completes".
  - Every `VirtualMachineResource` carries `subscription_id`.

  What stack-base does: record a pending purchase, adopt by `subscription_id`, and never purchase for a node that has a pending marker. Before relying on this, confirm with one read-only `GET /api/vps/v1/virtual-machines` that live VMs include `subscription_id`; Amalan's 2081685 is a known 202-born VM. No live purchase is made to test this.
- **B. CI regression guard.** `templates/github/deploy-stack.yml` must never use `hashFiles(` or an action that needs node20 (`actions/cache`, or anything pinned below checkout v5).
- **C. Runner preflight.** The first step of the template workflow checks for `python3 rsync tailwindcss x86_64-unknown-linux-musl-gcc rustup git ssh`, and fails with one line naming every missing tool.
- **I. Environments.**
  - **Format.** `stack.toml` may have `[environments.<env>]` tables (names match `^[a-z][a-z0-9-]{0,15}$`). Each holds:
    - `domain`, required;
    - `[environments.<env>.nodes.<n>]`, required, same shape as today's `[nodes.<n>]`;
    - `plan` / `price_item`, optional overrides;
    - optional `backups.bucket`, `backups.retention_days`, `logs.bucket`, `logs.retention_days`, `alerts.to`, `files.bucket` and `files.lock_days`.

    Any other key inside an environment is an error: parity is the point. Top-level `[nodes]` together with `[environments]` is an error.
  - **No `[environments]` means one implicit environment.** The files stay `stack.state.json` and `secrets.age`, and every command works without `--env`. Existing projects such as Amalan need no change.
  - **`--env <name>` is required once environments exist.** It applies to every command that touches servers or per-environment secrets (`up`, `--plan`, `deploy`, `rollback`, `status`, `ssh`, `backup-now`, `alert-test`, `secrets`, `deploy-key`, `ci-setup`). There is no default, so a typo or a forgotten flag never touches production. Without it, the command fails with a `StackError` listing the environment names.
  - **Per-environment files:** `stack.state.<env>.json`, `secrets.<env>.age` (recipients `age-recipients.<env>.txt` if present, else `age-recipients.txt`), and `deploy.<env>.age` with `keys/deploy.<env>.pub`. A staging deploy key cannot deploy production.
  - **Naming:** the NixOS hostname and the flake attribute are `<env>-<node>` (e.g. `staging-a`). The Hostinger FQDN is `<node>.<env domain>`. The node module gets `stackbase.environment = "<env>"`, which alert subjects use.
  - **CI template:** a tag push deploys **staging**. Production is a `workflow_dispatch` that takes the tag and deploys the *same* release to production, using a GitHub Environment named `production` so reviewers can be required. Secrets are `STACK_DEPLOY_KEY_STAGING` and `STACK_DEPLOY_KEY_PRODUCTION`.
- **D. Logs — Vector** (replaces the earlier hourly segment upload; no age encryption for logs, decided 2026-11-04).
  - **journald** (`nixos/base.nix`): `Storage=persistent`, `Compress=yes`, `SystemMaxUse=2G`, `SystemKeepFree=4G`, `SystemMaxFileSize=128M`, `MaxRetentionSec=7day`, `MaxFileSec=1day`, `SyncIntervalSec=5s`, `RateLimitIntervalSec=30s`, `RateLimitBurst=10000`, `ForwardToSyslog=no`. Seven days of local journal is the longest R2 outage survivable without loss. `SyncIntervalSec=5s` (default 5 min) bounds what a power loss can take from the local journal.
  - **Vector, source:** journald with `current_boot_only = false`, `since_now = false`, `exclude_units = ["vector.service"]`.
  - **Vector, remap:** keep only `timestamp host unit ident pid priority message boot_id cursor` (`compact` drops nulls). `unit` = `_SYSTEMD_UNIT`, `ident` = `SYSLOG_IDENTIFIER`, `cursor` = `__CURSOR`, kept so at-least-once duplicates can be removed.
  - **Vector, R2 sink:**
    - `aws_s3`, `region = "auto"`, `force_path_style = true`;
    - `key_prefix = "journal/{{ host }}/%Y/%m/%d/%H/"`, `filename_append_uuid = true`, `filename_extension = "ndjson.gz"`, `compression = "gzip"`, JSON + newline-delimited;
    - `batch.timeout_secs = 15`, `batch.max_bytes = 67108864`. The off-host copy is what survives losing the server, so the batch timeout is the loss window; 15 s costs ~170k uploads per server per month (decided 2026-11-04; multipart uploads rejected: parts are invisible until completed and must be ≥5 MiB);
    - disk buffer `max_size = 1073741824`, `when_full = "block"`; `acknowledgements.enabled = true`; `request.concurrency = "adaptive"`; healthcheck on.
    - Never set `storage_class`, ACLs or server-side encryption options.
  - **Vector, local sink:** `file`, `/var/log/vector/%Y-%m-%d/%H.ndjson`, memory buffer `max_events = 10000`, `when_full = "drop_newest"`, so a full local disk never blocks R2. tmpfiles `d /var/log/vector 0750 vector vector 3d`.
  - **Vector, metrics:** `internal_metrics` → `prometheus_exporter` on `127.0.0.1:9598`. The API is on `127.0.0.1:8686`.
  - **Bucket and credentials:** the per-environment `[logs] bucket` (required while logs are on) with its own R2 keys, `logs_access_key_id` and `logs_secret_access_key` in the environment's secrets (endpoint `r2_endpoint`). They go to `/var/lib/stackbase/logs.env` (0600) as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `LOGS_ENDPOINT`, read through `EnvironmentFile`. The config references `${LOGS_ENDPOINT}`, which Vector interpolates; the key values never enter the Nix store.
  - **Retention** is an R2 lifecycle rule (id `stackbase-logs`, prefix `journal/`, delete after `retention_days`, default 90; OBI sets 365). `./infra/up` ensures it through the Cloudflare API. The node never deletes logs.
- **E. Backups required (confirmed 2026-11-04).** In each environment, `./infra/up` (apply and `--plan`) refuses when there is no `[backups].bucket`, unless `[backups] enabled = false`, which then prints a warning on every run. The same applies to logs (`[logs] enabled = false`).
- **F. Alerts.**
  - **Recipients:** `[alerts] to = [...]`, per environment. Ours: `ops-alerts@techspace.org.uk` + `servers.<project>.<env>@techspace.org.uk`.
  - **SMTP settings,** from the environment's secrets: `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from`. stack-base is public, so nothing TechSpace-specific is baked in. Ours: `mail.techspace.org.uk:465` over Mesh, with one SMTP-only Stalwart principal per server, as in platform-base `docs/infra/company-ops-fleet-mail.md`.
  - **Delivery** is through nullmailer, so an alert raised while Mesh or the relay is down is queued and delivered later.
  - **Scope:** **any** failed service is mailed. The mechanism is a top-level `service.d` drop-in (`OnFailure=stackbase-alert@%N.service`), with a same-named empty drop-in under `stackbase-alert@.service.d/` to mask it for the handler itself. This is the pattern proven live in platform-base `nixos/unit-failure-mail.nix`; port its handler, including the "build the message whole, then truncate" fix.
  - **Rate limit:** at most one email per unit per 6 h.
  - **Freshness watchdog,** hourly. It fails if:
    - the newest backup success is older than 36 h;
    - `vector.service` is not active;
    - the R2 sink's `vector_buffer_byte_size` is over 256 MiB, meaning R2 has been unreachable for a while;
    - `vector_component_sent_events_total` for the R2 sink has not increased in 2 h, unless no events were received either.

    It skips (exits 0) while uptime is under 1 h.
  - If `[alerts]` is absent, `up` warns but does not refuse.
- **H. Mesh** (decided 2026-11-03: stack-base servers are on Cloudflare Mesh).
  - **Config:** a new `[mesh]` table, shared by all environments. `enabled = true` installs headless `cloudflare-warp`, using the module shape from platform-base `nixos/cloudflare-mesh.nix`, with the firewall not opened.
  - **Enrolment:** `./infra/up` enrols each node once with `mesh_connector_token` from the environment's secrets, then verifies `warp-cli status` shows Connected.
  - **Defaults:** Mesh stays off unless `[mesh]` says otherwise. platform-base pre-fills `enabled = true`.
  - **Out of scope:** SSH over Mesh only.
- **J. Files in R2 (preferred over disk), with a bucket lock.**
  - **Config:** `[files] bucket` (+ `lock_days`, default 30), per environment. Credentials: `files_access_key_id` and `files_secret_access_key` in the environment's secrets.
  - **`./infra/up`** ensures the bucket exists and has a bucket-lock rule (id `stackbase-files`, prefix `""`, condition Age `lock_days × 86400` s). It leaves other rules on that bucket untouched.
  - **App environment:** the release engine adds `STORAGE_BUCKET`, `STORAGE_ENDPOINT`, `STORAGE_REGION=auto`, `STORAGE_ACCESS_KEY_ID`, `STORAGE_SECRET_ACCESS_KEY` and `STORAGE_LOCK_DAYS` to the app's environment, next to `app_env`.
  - **The lock forbids deleting AND overwriting** for `lock_days`. Apps must therefore write unique keys and treat a refused delete as "delete later". The platform-base side of that is a separate plan (see Task 11).
  - `[backups].extra_paths` stays for apps that still write files to disk.
- **K. Cloudflare account access.** New secrets `cloudflare_account_id` plus a token with "Workers R2 Storage: Edit". The existing DNS token may simply carry that scope, but the README says which one is required. The R2 API is used only to create buckets, set lifecycle rules and set lock rules. Never to delete a bucket or object, or to remove another rule.
- **G. platform-base `install-stack-infra.sh`** must fail if its `project`/`binary` substitution into `stack.toml` did not happen. It also pre-fills `[mesh] enabled = true` and a `staging` + `production` environment skeleton.
- Release as **v0.2.0**. E is a behaviour change: a project without `[backups]` must add it or opt out after upgrading. Environments are opt-in, so existing single-environment projects keep working.

## Global Constraints

- stdlib-only Python 3.11+. Suite: `python3 -m unittest discover -s tests` from the repo root. Nix: `nix flake check` (runs `tests/vm.nix` and `tests/vm-deploy.nix`, plus new VM tests named per task).
- No plaintext secret outside `stackbase.ramdir.private_ram_dir()`. No secret value in argv, in a subprocess's environment, in logs or in output.
- Credentials files on the node are written by `./infra/up` steps: 0600 root:root (or owned by the unit's user where the unit needs it, as with Vector), under `/var/lib/stackbase/`. Values are validated against an allowlist exactly like `stackbase/backups.py`'s `_R2_KEYS` handling. They are read by systemd `EnvironmentFile`, never `source`d.
- Every expected failure is `StackError(message, hint)`.
- Every user-facing change is documented in `README.md` in the same task.
- Match the existing style: comments explain why; refusals say what to do instead.
- Nothing deletes a server, DNS record, firewall, release, bucket, object or lifecycle/lock rule. `tests/test_no_delete.py` stays green and is extended to the R2 client (no `DELETE` method, ever). Log expiry happens only through the R2 lifecycle rule.
- User-facing snippets use shell variables for fill-ins.
- One accepted exception to "no secret in argv": `warp-cli connector new` takes the enrolment token only as an argument. It runs once, on the node, as root, fed from stdin by `sh -c 'warp-cli connector new "$(cat)"'`, so it never appears in the laptop's argv or on the SSH command line. The code comment documents this.
- A single-environment `stack.toml` (today's format) must produce byte-identical plans and file paths before and after this plan. Tasks 4 onwards keep `tests/fixtures` for the legacy format green.

## Review Focus

1. **`--env` forgotten in a multi-environment project:** every server-touching command refuses and lists the environments. Nothing ever falls back to the first or only one. Task 4 (`test_multi_env_requires_env_flag_for_every_command`).
2. **R2 down for hours:** Vector's disk buffer fills to its limit, the source blocks, and no line is lost. Once R2 returns, everything drains. The watchdog emails during the outage, once per 6 h. Task 6 VM subtest (`test_logs_survive_s3_outage`) and Task 8 (`test_watchdog_alerts_on_buffer_growth`).
3. **A full local disk under `/var/log/vector`:** the local copy drops lines, and R2 shipping carries on. Task 6 (`test_local_sink_full_does_not_block_r2`).
4. **Existing project upgrading to v0.2.0 with no `[backups]`:** the refusal must name exactly the two ways forward (`bucket = …` or `enabled = false`). Task 10 (`test_up_refuses_without_backups_names_both_options`).
5. **A bucket that already has someone else's lock or lifecycle rules:** `./infra/up` adds or updates only its own rule id and keeps the rest byte-for-byte. Task 5 (`test_lock_update_preserves_foreign_rules`).

---

### Task 1: Hostinger 202 → pending purchase, adopt by subscription

**Files:** Modify `stackbase/hostinger.py:295-350` (`purchase_vm`), `stackbase/reconcile.py:794-827` (`_find_adoptable_vms`) and its plan/observe callers, `stackbase/config.py` (state: `NodeState.pending_subscription_id: str | None`), and `stackbase/steps.py` (the purchase step writes state). Tests: `tests/test_hostinger.py`, `tests/test_reconcile.py`, fixtures in `tests/fixtures/`.

**Interfaces:**
- `HostingerClient.purchase_vm(...) -> PurchaseResult`, where `@dataclass PurchaseResult: vps_id: int | None; subscription_id: str | None; warnings: list[str]`.
  - 200 → `vps_id` set.
  - 202 → `vps_id=None`, `subscription_id` from the body.
  - 202 without a usable `subscription_id` → today's `StackError`, unchanged.
- The node entry in the state file gains `"pending_subscription_id"`. `load_state`/`save_state` round-trip it; absent means `None`.
- `_find_adoptable_vms(hostinger, cfg, node_names, pending: dict[str, str]) -> dict[str, int]`: a node with a pending id matches ONLY the VM whose `subscription_id` equals it, ignoring hostname. Other nodes keep hostname matching.
- Plan: a node with `pending_subscription_id` and no matching VM yields a new `Action.WAIT_PURCHASE`, never `PURCHASE`. Its apply prints `error: purchase for node 'a' (subscription <id>) is still processing — re-run ./infra/up in a few minutes; if it never appears, find the VM in hPanel and set vps_id in stack.toml`. On ADOPT, the marker is cleared and the existing setup path runs (it sets the hostname).

- [ ] **Step 0: Live read-only check.** With an operator's token, call `GET /api/vps/v1/virtual-machines` and confirm each VM object has `subscription_id`. Record in this plan's ledger only whether the field is present, no values. If it's absent, stop and report to Matt.
- [ ] **Step 1: Tests:**
  - `test_purchase_202_returns_subscription_id`: fake 202 body `{"id":2957086,"subscription_id":"Azz353Uhl1xC54pR0","status":"payment_initiated"}`; a null `subscription_id` → today's StackError.
  - `test_pending_marker_persisted_after_202`
  - `test_adopts_by_subscription_id_ignoring_hostname`: VM `srv2081685.hstgr.cloud` with a matching subscription → ADOPT.
  - `test_pending_without_matching_vm_never_purchases`: → WAIT_PURCHASE, no PURCHASE in the plan.
  - `test_adopt_clears_pending_marker`
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run the whole suite → PASS. Add a README section "If a purchase says payment is processing".
- [ ] **Step 5: Commit** `hostinger: remember a 202 purchase's subscription and adopt by it`.

### Task 2: CI template guard

**Files:** Modify `tests/test_template.py`.

- [ ] **Step 1:** Write `test_ci_template_has_no_node20_dependencies`. It reads `templates/github/deploy-stack.yml` and asserts:
  - `"hashFiles("` appears in no non-comment line;
  - no `uses:` line references `actions/cache`;
  - every `uses: actions/checkout@` is pinned with a `# v5` (or higher) comment.

  Comment lines (stripped line starting with `#`) are ignored.
- [ ] **Step 2:** The helper `_node20_violations(text) -> list[str]` is tested twice: it passes on the current template and fails on a string containing `- uses: actions/cache@v4`.
- [ ] **Step 3: Commit** `test: keep the CI template free of node20-only actions`.

### Task 3: Runner preflight step

**Files:** Modify `templates/github/deploy-stack.yml` (first step after checkout), `tests/test_template.py`, `README.md`.

- [ ] **Step 1:** Write `test_ci_template_preflight_lists_required_tools`: a step named `Check the runner has stack-base's tools` comes before any step that runs `./infra/up`, and its script mentions each of `python3 rsync tailwindcss x86_64-unknown-linux-musl-gcc rustup git ssh`.
- [ ] **Step 2:** Implement it as a bash loop that collects `missing+=("$t")` for each `! command -v "$t"`, then `echo "::error::this runner is missing: ${missing[*]} — use the production runner or add them to its extraPackages"; exit 1`.
- [ ] **Step 3:** Run → PASS. **Step 4: Commit** `ci template: fail fast when the runner lacks deploy tools`.

### Task 4: Environments

**Files:** Modify:
- `stackbase/config.py`: `Environment`, `load_config` → environments, per-environment state paths;
- `stackbase/secrets.py`: `SecretsFile` per environment;
- `stackbase/__main__.py`: global `--env`;
- `stackbase/reconcile.py`: `hostname_for`, plan output header;
- `stackbase/release.py` and `stackbase/ci.py`: per-environment deploy key and secret names;
- `templates/infra/flake.nix`: one `nixosConfigurations."<env>-<node>"` per environment node;
- `templates/github/deploy-stack.yml`: tag → staging, `workflow_dispatch` → production;
- `templates/infra/stack.toml.example`: environments example;
- `README.md`.

Tests: `tests/test_config.py`, `tests/test_cli.py`, `tests/test_reconcile.py`, `tests/test_template.py`, `tests/test_ci.py`, and new fixtures `tests/fixtures/stack-envs.toml`.

**Interfaces:**
- `@dataclass(frozen=True) Environment: name: str; domain: str; plan: str; price_item: str | None; nodes: dict[str, Node]; backups: BackupsConfig; logs: LogsConfig; alerts: AlertsConfig; files: FilesConfig`.
- This task defines and parses all four section types, including validation, the shared-vs-override merge and the per-environment override whitelist: `BackupsConfig` (existing, + `enabled: bool | None`), `LogsConfig(enabled: bool | None, bucket: str | None, retention_days: int | None)`, `AlertsConfig(to: list[str])` and `FilesConfig(bucket: str | None, lock_days: int | None)`. Tasks 6, 8, 9 and 10 consume them; they do not redefine them.
- `StackConfig` gains `environments: dict[str, Environment]` (insertion order kept) and `implicit_env: bool`. Legacy files yield exactly one environment, named `""` with `implicit_env=True`, built from the top-level keys.
- `StackConfig.env(name: str | None) -> Environment` returns the selected environment. `None` is accepted only when `implicit_env`; otherwise it raises `StackError("this project has environments: staging, production", "add --env <name>")`. An unknown name → `StackError` listing the valid names.
- `state_path(infra_dir, env: Environment) -> Path` → `stack.state.json` for the implicit environment, else `stack.state.<name>.json`. `load_state(infra_dir, env)` and `save_state(infra_dir, env, state)` take the environment.
- `secrets_file(env: Environment) -> SecretsFile`; `deploy_file(env: Environment) -> SecretsFile`. Recipients fall back as in Brief I.
- `hostname_for(cfg, env, node) -> str` = `f"{node}.{env.domain}"` (legacy: unchanged output). `nixos_name(env, node) -> str` = `node` (legacy) or `f"{env.name}-{node}"`.
- The CLI accepts `--env` before or after the subcommand and threads `Environment` everywhere `cfg`/`state` were used.
- The flake template's node module sets `networking.hostName = nixos_name` and `stackbase.environment = <env name or "">`. Per-environment overrides are merged over the shared tables, using the same field mapping as today.
- CI: `ci-setup --env staging` writes repo secret `STACK_DEPLOY_KEY_STAGING`. With `--env production` it writes `STACK_DEPLOY_KEY_PRODUCTION` and prints how to create the GitHub Environment `production`.

- [ ] **Step 1: Tests (config):**
  - `test_envs_parse_overrides_only_allowed_keys`: `[environments.staging] app = {}` → StackError naming `app`.
  - `test_nodes_and_environments_together_rejected`
  - `test_legacy_file_is_one_implicit_env`, which also asserts the paths `stack.state.json` and `secrets.age`.
  - `test_env_state_and_secrets_paths`: `stack.state.staging.json`, `secrets.staging.age`, recipients fallback.
  - `test_env_name_pattern`
- [ ] **Step 2: Tests (CLI):** `test_multi_env_requires_env_flag_for_every_command` iterates the command list in Brief I; each one, without `--env`, raises with a hint containing `--env`. Also `test_unknown_env_lists_valid`.
- [ ] **Step 3: Tests (reconcile, template, CI):**
  - `test_hostname_uses_env_domain`
  - `test_legacy_plan_output_unchanged`: golden comparison against today's plan text for `tests/fixtures/stack.toml`.
  - Nix eval: the environments fixture yields attributes `staging-a` and `production-a`, with `networking.hostName` and `stackbase.environment` set, and a staging `backups.bucket` override applied.
  - `test_ci_template_tag_deploys_staging_dispatch_deploys_production`: the job reads `STACK_DEPLOY_KEY_STAGING` on tag and `STACK_DEPLOY_KEY_PRODUCTION` under `environment: production`.
- [ ] **Step 4:** Run → FAIL. **Step 5:** Implement. **Step 6:** Suite + `nix flake check` → PASS.
- [ ] **Step 7:** README: a new section "Staging and production" (format, `--env`, files per environment, promoting a tag to production); the example in `stack.toml.example`.
- [ ] **Step 8: Commit** `environments: staging and production from one stack.toml`.

### Task 5: Cloudflare R2 account client

**Files:** Create `stackbase/r2.py`, `tests/test_r2.py`, and fixtures `tests/fixtures/r2_*.json`. Modify `stackbase/reconcile.py` (`Action.ENSURE_R2_BUCKET`, `Action.ENSURE_R2_LIFECYCLE`, `Action.ENSURE_R2_LOCK`), `stackbase/steps.py`, `tests/test_no_delete.py` and `README.md` (token scope, `cloudflare_account_id`).

**Interfaces:**
- `R2Account(token: str, account_id: str, base_url=...)`, built on `stackbase/http.py` like `cloudflare.py`, with these methods:
  - `bucket_exists(name) -> bool`
  - `create_bucket(name) -> None`
  - `get_lifecycle(name) -> list[dict]` / `put_lifecycle(name, rules: list[dict]) -> None`
  - `get_lock(name) -> list[dict]` / `put_lock(name, rules: list[dict]) -> None`

  There is no method that deletes anything.
- Pure helpers:
  - `merge_rule(rules: list[dict], rule: dict) -> list[dict]` replaces the rule with the same `id`, or appends it, and leaves every other rule untouched.
  - `logs_lifecycle_rule(days: int) -> dict` (id `stackbase-logs`, prefix `journal/`, delete after `days`).
  - `files_lock_rule(days: int) -> dict` (id `stackbase-files`, prefix `""`, Age `days*86400`).
- Plan: for every bucket named in the selected environment, plan an ENSURE step when the bucket is missing or its own rule differs. `--plan` shows the exact rule change.

- [ ] **Step 0: Confirm the API shape.** Fetch Cloudflare's current API reference for R2 buckets, bucket lifecycle and bucket lock. Record in this plan's ledger the paths, the body shape and the field names (`conditions`/`condition`, `maxAgeSeconds`, `deleteObjectsTransition`, …). Write the fixtures from that reference, not from memory. If bucket lock is not in the public API, stop and report to Matt.
- [ ] **Step 1: Tests:**
  - `test_merge_rule_replaces_own_id_only`
  - `test_lock_update_preserves_foreign_rules`
  - `test_missing_bucket_plans_create`
  - `test_in_sync_bucket_plans_nothing`
  - `test_missing_account_id_names_secret`
  - `test_no_delete.py` extended: `r2.py` contains no `"DELETE"`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `r2: ensure buckets, the logs lifecycle rule and the files lock`.

### Task 6: `nixos/logs.nix` — Vector to R2 (Brief D)

**Files:** Create `nixos/logs.nix`, `stackbase/logs.py` (laptop side: `ENSURE_LOGS_ENV`, modelled on `stackbase/backups.py`) and `tests/vm-logs.nix` (registered in `flake.nix` checks). Modify the repo-root `flake.nix` (module list), `nixos/base.nix` (the journald block from Brief D replaces `SystemMaxUse=500M`), `templates/infra/flake.nix` (`[logs]` → `stackbase.logs.*`), `stackbase/reconcile.py`, `stackbase/steps.py`, `tests/test_config.py`, `tests/test_logs.py`, `tests/test_template.py` and `README.md`.

**Interfaces:**
- Options `stackbase.logs = { enable (bool); bucket (str); bufferBytes (ints.positive, 1073741824); batchSeconds (ints.positive, 15); localDays (ints.positive, 3) }`. Retention is not a node option; Task 5 owns it.
- `services.vector = { enable = true; journaldAccess = true; settings = <Brief D, values from options>; }`. `systemd.services.vector.serviceConfig.EnvironmentFile = "/var/lib/stackbase/logs.env"`, with `ReadWritePaths` for `/var/log/vector`. Unfree packages: none.
- `logs_env_content(secrets: dict[str, str]) -> str | None` renders `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `LOGS_ENDPOINT` from `logs_access_key_id`, `logs_secret_access_key` and `r2_endpoint`, using the same allowlist as `_R2_KEYS`.

- [ ] **Step 1: Tests (Python):**
  - `test_logs_env_renders_three_vars`
  - `test_logs_env_rejects_shell_metacharacters`
  - `test_logs_on_without_bucket_is_an_error`
  - `test_logs_bucket_env_override`
- [ ] **Step 2: Tests (VM, `tests/vm-logs.nix`).** Node with `services.minio` as the S3 target, bucket created in `testScript`, and Vector pointed at it with `force_path_style`. Subtests:
  - `test_logs_reach_s3`: `logger -t probe <uuid>`; within `batchSeconds` (set to 5 in the test) an object exists under `journal/<host>/`, and `zcat -f` of it contains the uuid with `unit`/`ident`/`cursor` fields and no `_CMDLINE`.
  - `test_logs_survive_s3_outage`: stop minio, log 1000 probes, restart Vector (proves the disk buffer), start minio, and all 1000 arrive.
  - `test_local_sink_full_does_not_block_r2`: mount a 1 MiB tmpfs on `/var/log/vector` and fill it; probes still reach S3.
  - `test_vector_own_logs_excluded`
- [ ] **Step 3–5:** FAIL → implement → suite + `nix flake check` PASS.
- [ ] **Step 6:** README "Logs":
  - what's shipped and when (≤ ~15 s; what a destroyed server can lose);
  - the key layout;
  - searching: `aws s3 cp … - | zcat -f | rg`, local `rg /var/log/vector`, `journalctl` for 7 days;
  - the outage tolerance (7 days), at-least-once delivery and dedupe by `cursor`;
  - retention through the lifecycle rule;
  - the validation commands from the approved design (`vector validate`, `vector tap`, `vector top`, the metrics `curl`).
- [ ] **Step 7: Commit** `logs: stream the journal to R2 with Vector`.

### Task 7: `nixos/mesh.nix` — join Cloudflare Mesh

**Files:** Create `nixos/mesh.nix` and `stackbase/mesh.py` (laptop side: the `ENSURE_MESH` step). Modify the repo-root `flake.nix` (module list), `templates/infra/flake.nix` (`[mesh]` → `stackbase.mesh.enable`), `stackbase/config.py` (`MeshConfig: enabled: bool`), `stackbase/reconcile.py` (`Action.ENSURE_MESH`), `stackbase/steps.py`, `tests/test_mesh.py`, `tests/test_template.py` and `README.md`.

**Interfaces:**
- Option `stackbase.mesh.enable` (bool, default false). When true: `services.cloudflare-warp = { enable = true; package = pkgs.cloudflare-warp.override { headless = true; }; openFirewall = false; }`, plus the `/usr/sbin/nft` bind mount from platform-base's module (check whether the pinned nixpkgs still needs it; keep it only if so). `nixpkgs.config.allowUnfreePredicate` admits only `cloudflare-warp`.
- Observe: `warp-cli --accept-tos status` over root SSH → `connected: bool`. Plan: `[mesh] enabled` and not connected → `ENSURE_MESH`.
- Apply needs `mesh_connector_token` in the environment's secrets; without it, raise a `StackError` naming the key and the README section. Enrol via stdin as in Global Constraints, run `warp-cli --accept-tos connect`, and poll the status for up to 60 s.
- After apply, `./infra/up` prints the node's Mesh IPv6 (`ip -6 addr show CloudflareWARP`).

- [ ] **Step 1: Tests** (`test_mesh.py`, fake SSH from `tests/fakes.py`):
  - `test_mesh_disabled_plans_nothing`
  - `test_connected_node_plans_nothing`
  - `test_disconnected_node_plans_ensure_mesh`
  - `test_missing_token_names_secret_key`
  - `test_token_sent_on_stdin_not_argv`

  Template eval: `[mesh] enabled = true` → `services.cloudflare-warp.enable == true`. VM: a build-only check that the module evaluates.
- [ ] **Step 2–4:** FAIL → implement → suite + `nix flake check` PASS.
- [ ] **Step 5:** README "Mesh": the Cloudflare dashboard steps (create a node, copy its token, include-only MASQUE device profile), then `./infra/up --env <env> secrets set mesh_connector_token`, then verify.
- [ ] **Step 6: Commit** `mesh: join Cloudflare Mesh when [mesh] enabled`.

### Task 8: `nixos/alerts.nix` — email on any failed service (Brief F)

**Files:** Create `nixos/alerts.nix` and `stackbase/alerts.py` (the `ENSURE_ALERT_ENV` step + an `alert-test` command). Modify `stackbase/reconcile.py`, `stackbase/steps.py`, `stackbase/__main__.py`, `templates/infra/flake.nix`, `nixos/backups.nix` (write `/var/lib/stackbase-backup/last-success` on success), `tests/test_alerts.py`, `tests/vm-alerts.nix` and `README.md`.

**Interfaces:**
- Secrets keys `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password` and `smtp_from` → `/var/lib/stackbase/alert.env` (0600), with an allowlist like `_R2_KEYS`.
- Options `stackbase.alerts = { to (listOf str, []); intervalHours (ints.positive, 6) }`. When `to != []`:
  - nullmailer, with its remotes file rendered at service start from `alert.env` into a 0600 runtime file (`--port=465 --tls --auth-login`, CA bundle verified), as in platform-base `nixos/company-ops-mail-sender.nix`;
  - the top-level drop-in package and the masking drop-in, as in platform-base `nixos/unit-failure-mail.nix`;
  - `stackbase-alert@.service` with Subject `[<project>/<env>/<hostname>] <unit> failed`. The body is `systemctl status` plus the last 60 journal lines, truncated to 64 KiB after being built.
- `stackbase-freshness.service` + an hourly timer, with the checks in Brief F (metrics from `127.0.0.1:9598`).
- `./infra/up --env <env> alert-test` starts a deliberately failing transient unit on each node and prints `sent — check <to>`.

- [ ] **Step 1: Tests:**
  - `test_alerts.py`: env rendering; the allowlist rejects `a$(id)`; with `[alerts]` set and SMTP keys missing → a StackError naming the keys; with `[alerts]` absent → the plan warns once.
  - VM (an SMTP sink in the VM):
    - `test_any_failed_unit_mails` (a transient `false` unit);
    - `test_handler_failure_does_not_recurse` (`systemctl show stackbase-alert@x.service -p OnFailure` is empty);
    - `test_alert_queued_while_relay_down`;
    - `test_alert_rate_limited`;
    - `test_watchdog_alerts_on_buffer_growth` (stop the minio from Task 6's fixture, wait for the buffer to pass a test threshold set low);
    - `test_watchdog_grace_after_boot`.
- [ ] **Step 2–4:** FAIL → implement → suite + `nix flake check` PASS.
- [ ] **Step 5: Commit** `alerts: email when any service fails, over nullmailer`.

### Task 9: Files in R2 under a bucket lock (Brief J)

**Files:** Create `stackbase/files.py` (renders the `STORAGE_*` block). Modify `stackbase/config.py` (`FilesConfig.lock_days` range check 1–3650), `stackbase/reconcile.py` (adds the files bucket to Task 5's ENSURE steps), `stackbase/release.py` / the app-env push (append the `STORAGE_*` lines, kept out of the `app_env` digest so changing them alone still re-pushes), `templates/infra/stack.toml.example`, `tests/test_files.py` and `README.md`.

**Interfaces:**
- `storage_env_lines(env: Environment, secrets: dict[str, str]) -> list[str]`. It returns `[]` when `[files]` is absent, and raises a StackError naming the missing keys when `[files]` is set but the credentials are incomplete.
- A `STORAGE_*` key already present in `app_env` → StackError: one owner per variable.

- [ ] **Step 1: Tests:**
  - `test_no_files_section_adds_nothing`
  - `test_files_lines_rendered_with_lock_days`
  - `test_incomplete_files_credentials_named`
  - `test_app_env_storage_collision_rejected`
  - `test_files_bucket_planned_with_lock_rule` (uses Task 5's fake)
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** README "Uploaded files in R2":
  - why R2 rather than disk;
  - the bucket lock and its consequences (unique keys; deletes refused for `lock_days`; GDPR deletes are queued and finish when the lock expires);
  - a pointer to platform-base's storage backend.
- [ ] **Step 6: Commit** `files: give the app an R2 media bucket under a bucket lock`.

### Task 10: Backups and logs on unless explicitly opted out; v0.2.0

**Files:** Modify `stackbase/reconcile.py` (plan-time check, per environment), `stackbase/__init__.py` + `templates/infra/flake.nix` (version → `0.2.0`, kept equal per the existing test), `templates/infra/stack.toml.example` (all new sections, commented), `tests/test_config.py`, `tests/test_reconcile.py` and `README.md` (an upgrade note for v0.2.0).

- [ ] **Step 1: Tests:**
  - `test_up_refuses_without_backups_names_both_options`
  - `test_backups_opt_out_warns`
  - `test_logs_opt_out_warns`
  - `test_enabled_false_with_bucket_is_an_error`
  - `test_check_runs_per_environment` (staging opted out, production not → only staging warns)
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `up: require backups and logs (or an explicit opt-out); release v0.2.0`. Do NOT tag or push; Matt cuts the release.

### Task 11 (platform-base repo): new-platform pre-fill, and the R2 storage backend plan

**Files:** `~/code/techspace/platform-base/.claude/skills/new-platform/scripts/install-stack-infra.sh:113-120`; `~/code/techspace/platform-base/docs/superpowers/plans/2026-11-04-r2-storage-backend.md` (new plan, written, not executed).

- [ ] **Step 1:** After the `sed`, check `grep -qx "project = \"${CRATE_KEBAB}\"" "$STACK_TOML" && grep -qx "binary = \"${CRATE_NAME}\"" "$STACK_TOML"`. If either check fails, `rm "$STACK_TOML"` and exit 1 with `install-stack-infra.sh: stack.toml.example no longer has the expected project/[app] lines — update the sed in this script`.
- [ ] **Step 2:** Append to the generated file:
  - `[mesh] enabled = true`;
  - `[environments.staging]` and `[environments.production]` skeletons (domain `staging.<domain>` / `<domain>`, one node `a` each);
  - per-environment `[alerts] to = ["ops-alerts@techspace.org.uk", "servers.<project>.<env>@techspace.org.uk"]`.

  Include them in the same verification.
- [ ] **Step 3:** Verify by running the script against a scratch target with the real example (passes) and against a doctored example with the `# binary` line removed (fails, and no stack.toml is left behind).
- [ ] **Step 4:** Write the platform-base storage plan. It covers:
  - implementing `S3Storage` in `src/storage/` (SigV4 over the existing `reqwest` + `hmac` + `sha2`; no AWS SDK) against the `STORAGE_*` variables from Brief J, selected in `from_env()`;
  - unique keys (UUID-prefixed);
  - a `storage_pending_deletes` table plus a daily worker job that retries refused deletes after `STORAGE_LOCK_DAYS`;
  - the feedback and file routes (`src/routes/feedback.rs`, `src/routes/files.rs`) moving to it with no behaviour change on `LocalStorage`.
- [ ] **Step 5:** Commit on platform-base master (`feedback_push_direct_no_pr`): no changelog for the script; the plan doc on its own.
