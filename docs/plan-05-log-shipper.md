# Fleet Log Shipper (replace Vector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every server ships its journal to R2 with one small, tested script on a one-minute timer instead of Vector, in stack-base (NixOS) and on Boost's Debian production host.

**Architecture:** `nixos/log-shipper.py` (Python stdlib only) reads the journal after a saved cursor with `journalctl -o json`, keeps the same nine fields Vector kept, writes one gzipped NDJSON object per event-hour, uploads it with `rclone`, reads it back to verify, and only then saves the new cursor. A systemd timer runs it every minute. The object layout and fields are unchanged, so existing archives and the README's search commands keep working. The watchdog checks the script's last-success stamp instead of Vector's metrics.

**Tech Stack:** Python 3 stdlib, journalctl, rclone (S3 backend, provider Cloudflare), NixOS module + systemd timer, unittest, NixOS VM test with MinIO, an opt-in test against real R2.

**Spec:** decided in conversation with Matt, 2026-11-16/17 (platform-base session); recorded here.
- Why not Vector: from 0.46 its S3 sink sends two checksums and R2 rejects every upload (vectordotdev/vector#23029, open). 0.55 failed live on boost-prod on 2026-11-17 while its healthcheck passed; 0.45.0 works but is a February 2025 build. stack-base ships 0.55 from nixpkgs, so its nodes are very likely not shipping today. Its VM test uses MinIO, which cannot catch this.
- Own script, fleet standard, lives in stack-base; Boost (Debian) installs the same file.
- Loss window: one minute is acceptable (Matt accepted the upload cost; there are no quiet servers).
- Retention stays the bucket's lifecycle rule; the node never deletes a log object.
- Bucket and retention stay in code (stack-base `r2.py` for stacks, `boost/infra host-native/log-shipper/apply-bucket` for Boost). Tokens are created by hand, one per server, scoped to its bucket.

## Global Constraints

- Shipper is one file, `nixos/log-shipper.py`, Python 3 stdlib only, no third-party imports; external commands: `journalctl`, `rclone`.
- Object key: `journal/<host>/<YYYY>/<MM>/<DD>/<HH>/<first-event-unix-seconds>-<uuid4>.ndjson.gz`, hour from the event's UTC timestamp, `<host>` = `socket.gethostname()` short name. One object per event-hour per run.
- Each line is one JSON object with exactly these keys when present (absent ones omitted): `timestamp`, `host`, `unit`, `ident`, `pid`, `priority`, `message`, `boot_id`, `cursor`, plus `CONTAINER_NAME`, `CONTAINER_ID`, `IMAGE_NAME` when the entry has them. Mapping: `_SOURCE_REALTIME_TIMESTAMP` else `__REALTIME_TIMESTAMP` → `timestamp` as `YYYY-MM-DDTHH:MM:SS.ffffffZ`; `_HOSTNAME` → `host`; `_SYSTEMD_UNIT` → `unit`; `SYSLOG_IDENTIFIER` → `ident`; `_PID` → `pid`; `PRIORITY` → `priority`; `MESSAGE` → `message`; `_BOOT_ID` → `boot_id`; `__CURSOR` → `cursor`. All values strings, as journald gives them.
- Credentials: the existing `/var/lib/stackbase/logs.env` keys `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `LOGS_ENDPOINT` — unchanged, so `stackbase/logs.py`'s laptop side and every project's secrets stay as they are. rclone is configured only through environment variables (`RCLONE_CONFIG_LOGS_TYPE=s3`, `_PROVIDER=Cloudflare`, `_ENV_AUTH=true`, `_ENDPOINT=$LOGS_ENDPOINT`, `_NO_CHECK_BUCKET=true`); no rclone config file. Never print a credential.
- The cursor file is written only after the object's read-back sha256 matches; write it atomically (temp + fsync + rename + dir fsync).
- State directory `/var/lib/stackbase-logs`: `cursor`, `pending/` (spooled objects not yet verified), `last-success` (unix seconds, written at the end of a run with nothing left to send).
- A run ships at most `MAX_OBJECT_BYTES = 64 MiB` (uncompressed NDJSON) per object and loops until caught up or `MAX_RUN_SECONDS = 240` have passed.
- The shipper's own unit (`stackbase-logs.service`) is excluded from what it ships.
- Default interval 60 s (`OnUnitInactiveSec=60s`, `OnBootSec=60s`, `AccuracySec=5s`); option `stackbase.logs.intervalSeconds`.
- Removed options `stackbase.logs.bufferBytes`, `batchSeconds`, `localDays`, `stackbase.alerts.bufferAlertBytes` go through `lib.mkRemovedOptionModule` with a message pointing at this change. The local plain-text copy under `/var/log/vector` is dropped (the journal keeps 7 days on the node).
- Version `0.3.0` in `stackbase/__init__.py` and `templates/infra/flake.nix`; tag `v0.3.0` per the stack-base release procedure (Matt authorised tagging).

## Review Focus

1. **Upload fails midway or read-back mismatches:** the cursor must not move; the spooled object is retried first next run; nothing is lost or skipped. (Task 1 tests.)
2. **Journal rotated past the saved cursor** (cursor no longer exists): `journalctl --after-cursor` errors or restarts — the script must fall back to the oldest available entry, log a warning naming the gap, and keep going, not wedge forever. (Task 1 test `test_cursor_gone_restarts_from_oldest`.)
3. **Non-UTF-8 or binary `MESSAGE`** (journalctl prints a list of byte values): decoded with replacement, never crashes the run. (Task 1 test.)
4. **Real R2, not MinIO:** the exact rclone invocation must upload, read back and delete under `journal/_probe/` against a real R2 bucket before release. (Task 4.)
5. **Backfill on first start / after a long outage:** a 4 GB journal must drain over several runs without exceeding `MAX_RUN_SECONDS` per run or holding the whole backlog in memory. (Task 1 test `test_large_backlog_is_split_and_resumed`.)

---

### Task 1: The shipper script

**Files:**
- Create: `nixos/log-shipper.py`
- Create: `tests/test_log_shipper.py`

**Interfaces:**
- Produces (module-level, loaded by tests via `importlib.machinery.SourceFileLoader`):
  - `slim(entry: dict) -> dict` — the field mapping in Global Constraints.
  - `object_key(host: str, first: dict, uid: str) -> str`
  - `@dataclass Config(state: Path, bucket: str, host: str, exclude_unit: str, max_object_bytes: int, max_run_seconds: float)`; `Config.from_env()` reads `LOGS_BUCKET` (required), `LOGS_STATE` (default `/var/lib/stackbase-logs`), `LOGS_HOST` (default short hostname), `LOGS_EXCLUDE_UNIT` (default `stackbase-logs.service`).
  - `run(cfg: Config, now: Callable[[], float] = time.monotonic) -> int` — returns the number of objects uploaded; raises on any upload/verify failure after leaving state consistent.
  - `main() -> None`; exit 0 on success, 1 on failure (so OnFailure mails it).
- rclone remote name is `logs`; destination `logs:<bucket>/<key>`; upload with `rclone rcat`, read back with `rclone cat`.

- [ ] **Step 1: Write failing tests** in `tests/test_log_shipper.py` (unittest, like the rest of `tests/`). Fakes on `PATH` in a temp dir: `journalctl` replays a JSON-lines fixture honouring `--after-cursor`, `--output=json`, and records argv; `rclone` stores `rcat` stdin under `tmp/r2/<key>` and serves `cat` from there, with env switches to fail `rcat` or corrupt `cat`.
  - `test_slim_maps_nine_fields_and_container_fields` — input with all journald fields plus `_CMDLINE`; output keys exactly the nine plus `CONTAINER_NAME`; `timestamp == "2026-11-17T04:00:02.760172Z"` from `__REALTIME_TIMESTAMP="1794888002760172"`; `_SOURCE_REALTIME_TIMESTAMP` wins when present.
  - `test_binary_message_is_decoded_with_replacement` — `MESSAGE=[104,105,255]` → `"hi�"`.
  - `test_ships_new_entries_and_saves_cursor` — 3 entries in one hour → one object at `journal/test-host/2026/11/17/04/1794888002-<uuid>.ndjson.gz`, gunzipped lines == slimmed entries, `cursor` file == last `__CURSOR`, `last-success` written.
  - `test_entries_split_by_event_hour` — entries in 04:59 and 05:00 → two objects in `.../04/` and `.../05/`.
  - `test_second_run_sends_only_new_entries` — journalctl called with `--after-cursor=<saved>`.
  - `test_failed_upload_keeps_cursor_and_spool` — rcat fails → exit/raise, cursor unchanged, one file in `pending/`; next run with rcat working uploads the spooled object first, then advances.
  - `test_readback_mismatch_keeps_cursor` — corrupt `cat` → raise, no cursor change, spool kept.
  - `test_own_unit_is_excluded` — entry with `_SYSTEMD_UNIT=stackbase-logs.service` not shipped (cursor still advances past it).
  - `test_cursor_gone_restarts_from_oldest` — fake journalctl exits 1 with "Failed to seek to cursor" for an unknown cursor → script logs a warning containing "cursor no longer in the journal", ships from the oldest entry, saves a new cursor.
  - `test_large_backlog_is_split_and_resumed` — `max_object_bytes=1000`, 50 entries → several objects; with `now` advancing past `max_run_seconds` after the first object, run stops, cursor equals the last entry of the first object; next run continues.
  - `test_nothing_new_writes_last_success_only` — no entries → no rclone call, `last-success` updated.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_log_shipper -v` → errors (file missing).
- [ ] **Step 3: Implement** `nixos/log-shipper.py`. Read journalctl stdout line by line (stream, never the whole backlog); group consecutive entries by event-hour; spool each group to `pending/<key-with-slashes-as-%2F>.ndjson.gz` with fsync; upload, read back, compare sha256, delete spool, then save the cursor of the group's last entry. Pending spools from an earlier run are uploaded before reading the journal. journalctl args: `--output=json --no-pager --after-cursor=<c>` (or none when no cursor, which reads the oldest entry first); never `--boot`.
- [ ] **Step 4: Run** the tests → all pass; `python3 -m py_compile nixos/log-shipper.py`.
- [ ] **Step 5: Commit** `log-shipper: journal to R2 with a stdlib script (cursor after verified upload)`.

### Task 2: NixOS module and laptop side

**Files:**
- Modify: `nixos/logs.nix` (rewrite: Vector out; `stackbase-logs.service` oneshot + `stackbase-logs.timer`)
- Modify: `stackbase/logs.py` (`LOGS_UNIT = "stackbase-logs.service"`; docstrings), `stackbase/steps.py` (`_ensure_logs_env` restart line: restart nothing — the next timer run reads the new file; keep writing it before the rebuild)
- Modify: `tests/test_logs.py`, `tests/test_template.py` (`vectorEnable` → `logsTimerEnable = node.config.systemd.timers.stackbase-logs.enable or false` and the same assertions)

**Interfaces:**
- Consumes: `nixos/log-shipper.py` from Task 1 and its env vars.
- Produces: units `stackbase-logs.service` / `.timer`; option `stackbase.logs.intervalSeconds` (default 60); state dir `/var/lib/stackbase-logs`; stamp `/var/lib/stackbase-logs/last-success` (Task 3 reads it).

- [ ] **Step 1:** Update the tests first (`test_logs.py` restart expectation, `test_template.py` facts) → run `python3 -m unittest discover -s tests` → those fail.
- [ ] **Step 2:** Rewrite `nixos/logs.nix`: keep `enable` and `bucket` options and their assertion; add `intervalSeconds`; `mkRemovedOptionModule` for `bufferBytes`, `batchSeconds`, `localDays` ("replaced by the stackbase-logs timer in v0.3.0; see README Logs"). Service: `Type=oneshot`, `ExecStart=${pkgs.python3}/bin/python3 ${./log-shipper.py}`, `path = [ pkgs.systemd pkgs.rclone ]`, `EnvironmentFile=/var/lib/stackbase/logs.env`, `Environment` for `LOGS_BUCKET` and the rclone settings in Global Constraints, `StateDirectory=stackbase-logs` (0700), `SupplementaryGroups=systemd-journal`, `DynamicUser=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `TimeoutStartSec=300`, `Nice=10`, `IOSchedulingClass=idle`. Timer per Global Constraints. Header comment rewritten: what is shipped, loss window = interval, why not Vector (issue link).
- [ ] **Step 3:** Run the unit suite → pass; `nix build .#checks.x86_64-linux.vm -L` (or the flake's eval checks) still builds.
- [ ] **Step 4: Commit** `logs: ship with the stackbase-logs timer instead of Vector`.

### Task 3: Watchdog freshness for logs

**Files:**
- Modify: `nixos/alerts.nix` (the `CHECK_LOGS` block; remove `bufferAlertBytes` via `mkRemovedOptionModule`; add `stackbase.alerts.logsMaxAgeSeconds`, default 900)
- Modify: `tests/vm-alerts.nix`, `tests/test_alerts.py` if it covers the block

**Interfaces:**
- Consumes: `/var/lib/stackbase-logs/last-success` (Task 2); before the first success, count from `/var/lib/stackbase-logs/enabled-at` created by tmpfiles, exactly like the backups block's fail-closed pattern.

- [ ] **Step 1:** Rewrite the vm-alerts logs scenario first: stop the timer, set `last-success` to now − 1000 s → watchdog fails with a line starting `logs: no log upload has succeeded since`; restore → passes. Remove the Vector metrics scenarios.
- [ ] **Step 2:** Implement: `logs: <what> at <time>, more than <N> min ago -- see journalctl -u stackbase-logs`.
- [ ] **Step 3: Run** `nix build .#checks.x86_64-linux.vm-alerts -L` → passes.
- [ ] **Step 4: Commit** `alerts: logs freshness from the shipper's stamp`.

### Task 4: End-to-end proof (VM + real R2)

**Files:**
- Modify: `tests/vm-logs.nix` (rewrite for the timer: entries arrive within two intervals with the nine fields; MinIO outage → nothing lost after it returns; restart mid-backlog → no gap, duplicates only by cursor; own unit not shipped)
- Create: `tests/test_log_shipper_r2.py` — skipped unless `STACKBASE_R2_TEST_ENDPOINT`, `_BUCKET`, `_ACCESS_KEY_ID`, `_SECRET_ACCESS_KEY` are set; runs the real script (fake journalctl, real rclone) against the bucket with `LOGS_HOST=_probe`, asserts the object lists and reads back, then deletes everything under `journal/_probe/`.

- [ ] **Step 1:** Rewrite `vm-logs.nix`; run `nix build .#checks.x86_64-linux.vm-logs -L` → passes.
- [ ] **Step 2:** Write the R2 test; run without env → skipped.
- [ ] **Step 3: Operator-assisted live run (controller, not implementer):** with the `boost-logs` key from Matt's local bundle (`~/boost-log-shipper-bundle/r2.env`, mapped to the `STACKBASE_R2_TEST_*` names in the shell, never printed or written elsewhere), run the R2 test → passes, and `journal/_probe/` is empty afterwards.
- [ ] **Step 4: Commit** `tests: log shipper end to end (VM) and against real R2 (opt-in)`.

### Task 5: Docs and release v0.3.0

**Files:**
- Modify: `README.md` (Logs section: what is shipped and when — one-minute timer; outages — the cursor only moves after a verified upload, the journal's 7 days are the buffer; checking it works — `systemctl list-timers stackbase-logs`, `journalctl -u stackbase-logs`, `cat /var/lib/stackbase-logs/last-success`; drop Vector, `/var/log/vector`, metrics, `vector top/tap`; keep key layout and search commands)
- Modify: `stackbase/__init__.py`, `templates/infra/flake.nix` (`0.3.0`)

- [ ] **Step 1:** Update README and versions; `grep -rn -i vector README.md nixos stackbase templates` → only the "why not Vector" note remains.
- [ ] **Step 2:** Full suite `python3 -m unittest discover -s tests` and all VM checks → pass.
- [ ] **Step 3: Commit** `v0.3.0: log shipper replaces Vector`; controller tags `v0.3.0` (annotated, on main), pushes, bumps platform-base `STACK_BASE_TAG` in `.claude/skills/new-platform/scripts/install-stack-infra.sh` and runs its `tests/install_stack_infra_test.sh`.

### Task 6: Boost production moves from Vector to the script

**Files (in `/home/matiboy/code/boost/infra`):**
- Modify: `host-native/log-shipper/install` (rewrite: apt `rclone python3`; install `log-shipper.py` copied from stack-base `v0.3.0` with its sha256 checked in the installer; `stackbase-logs.service` + `.timer` equivalent to Task 2's, `EnvironmentFile=/etc/stackbase-logs/logs.env`; seed `/var/lib/stackbase-logs/cursor` from Vector's checkpoint `/var/lib/vector/journal/checkpoint.txt` (Vector names it after the source id, `journal`) if present so nothing is re-sent or skipped; then stop, disable and purge Vector and its apt repo/pin/keyring; run the service once and require exit 0 and an object under `journal/boost-app-26/` newer than the start)
- Delete: `host-native/log-shipper/vector.yaml`, `vector.test.yaml`
- Modify: `host-native/log-shipper/README.md`
- Keep: `apply-bucket`, `r2-bucket.json` (unchanged)

- [ ] **Step 1:** Rewrite installer + README; `bash -n` and shellcheck clean; check the checkpoint path on the host read-only first (`ssh boost-prod 'sudo -n ls /var/lib/vector' ` may be denied — then make seeding conditional and note it).
- [ ] **Step 2: Commit** in boost/infra `Log shipper: stack-base's script replaces Vector`.
- [ ] **Step 3: Operator step (Matt):** stage the bundle (controller) and run `ssh -t boost-prod 'sudo ~/log-shipper-bundle/install'`.
- [ ] **Step 4:** Controller verifies new objects under `journal/boost-app-26/`, no gap around the switch (newest Vector object's last cursor precedes the first script object's first cursor), then removes the staged bundle.
