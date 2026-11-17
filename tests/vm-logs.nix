# NixOS VM test wired as `checks.x86_64-linux.vm-logs` in flake.nix. Boots
# one stackbase node with nixos/logs.nix shipping its journal to a MinIO
# bucket on the same machine (tests/minio.nix, standing in for R2), and
# proves the properties the design rests on: entries arrive within two
# timer intervals, slimmed to the nine fields; an S3 outage loses nothing
# once the bucket is back; a run killed mid-upload leaves no gap, and any
# duplicate is the same journal entry (same cursor); the shipper does not
# ship its own logs.
#
# MinIO cannot catch an R2-only rejection (what retired Vector); that is
# tests/test_log_shipper_r2.py's job, against a real bucket.
#
# Iterate on it alone with:
#   nix build .#checks.x86_64-linux.vm-logs -L
{ self, pkgs, lib }:

let
  minio = import ./minio.nix { inherit pkgs; };

  adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBDGmdzpEogrHBnAP+a1MKjbV+D9E9nQOVx8m2wcmt3 vm-test-admin";

  bucket = "logs";
  # Shorter than production's 60 s so the test does not idle; the
  # behaviour under test does not depend on the value.
  interval = 5;
in
pkgs.testers.runNixOSTest {
  name = "stackbase-vm-logs";

  nodes.node =
    { ... }:
    {
      imports = [
        self.nixosModules.base
        self.nixosModules.logs
        minio.module
      ];

      stackbase.project = "teststack";
      stackbase.admins.deploy = adminKey;

      stackbase.logs.bucket = bucket;
      stackbase.logs.intervalSeconds = interval;

      # What `./infra/up`'s ENSURE_LOGS_ENV puts on a real node: the same
      # path, owner and mode, written before the shipper first runs.
      systemd.services.stackbase-test-logs-env = {
        wantedBy = [ "multi-user.target" ];
        before = [ "stackbase-logs.service" ];
        requiredBy = [ "stackbase-logs.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          install -d -m 0750 /var/lib/stackbase
          install -m 0600 -o root -g root ${pkgs.writeText "logs.env" minio.logsEnv} /var/lib/stackbase/logs.env
        '';
      };

      environment.systemPackages = [
        pkgs.gzip
        # Every event in the bucket, one JSON object per line.
        (pkgs.writeShellScriptBin "dump-journal" ''
          rm -rf /tmp/dl && mkdir -p /tmp/dl
          s3 cp --recursive s3/${bucket}/journal/ /tmp/dl/ >/dev/null 2>&1 || true
          find /tmp/dl -type f -name '*.ndjson.gz' -exec zcat {} +
        '')
        # Like dump-journal, prefixed with the object key: "<key>\t<line>".
        (pkgs.writeShellScriptBin "dump-journal-keys" ''
          rm -rf /tmp/dlk && mkdir -p /tmp/dlk
          s3 cp --recursive s3/${bucket}/journal/ /tmp/dlk/ >/dev/null 2>&1 || true
          cd /tmp/dlk && find . -type f -name '*.ndjson.gz' | while read -r f; do
            zcat "$f" | sed "s|^|journal/''${f#./}\t|"
          done
        '')
      ];
      virtualisation.diskSize = 4096;
    };

  testScript = ''
    import json
    import re
    import time
    import uuid
    from datetime import datetime, timezone

    start_all()
    node.wait_for_unit("multi-user.target")
    ${minio.createBucket "node" bucket}
    node.wait_for_unit("stackbase-logs.timer")

    INTERVAL = ${toString interval}
    STATE = "/var/lib/stackbase-logs"
    KEEP = {"timestamp", "host", "unit", "ident", "pid", "priority", "message", "boot_id", "cursor"}
    NAME = re.compile(r"(\d+)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\.ndjson\.gz")


    def keys():
        out = node.succeed("s3 ls --recursive --json s3/${bucket}/ || true")
        return [json.loads(line)["key"] for line in out.splitlines() if line.strip().startswith("{")]


    def events():
        out = node.succeed("dump-journal || true")
        return [json.loads(line) for line in out.splitlines() if line.strip()]


    def wait_all(want, what, timeout=300):
        """Until every message in `want` is in the bucket; returns the events."""
        deadline = time.monotonic() + timeout
        while True:
            evs = events()
            got = want & {e.get("message") for e in evs}
            if got == want:
                return evs
            assert time.monotonic() < deadline, f"only {len(got)} of {len(want)} {what} arrived"
            time.sleep(INTERVAL)


    def assert_no_gap_and_dup_by_cursor(evs, want, what):
        cursors = {}
        for e in evs:
            if e.get("message") in want:
                cursors.setdefault(e["message"], set()).add(e["cursor"])
        assert set(cursors) == want, f"{len(want - set(cursors))} {what} missing"
        # A message shipped twice must be the same journal entry twice.
        bad = {m: c for m, c in cursors.items() if len(c) != 1}
        assert not bad, f"{what} with more than one cursor: {list(bad.items())[:3]}"
        dups = sum(1 for e in evs if e.get("message") in want) - len(want)
        print(f"{len(want)} {what}: none missing, {dups} duplicate line(s), all same-cursor")


    with subtest("test_logs_reach_s3"):
        # Let the first (boot) run finish, so the probe is timed against a
        # steady timer, as on a running server.
        node.wait_until_succeeds(f"test -s {STATE}/last-success", timeout=120)
        probe = str(uuid.uuid4())
        started = time.monotonic()
        node.succeed(f"logger -t probe {probe}")
        # Two intervals, plus the timer's 5 s AccuracySec and one run.
        # Not grep -q: the driver runs with pipefail, and zcat's SIGPIPE
        # would fail the match it found.
        node.wait_until_succeeds(f"dump-journal | grep {probe} >/dev/null", timeout=2 * INTERVAL + 15)
        print(f"probe reached the bucket after {time.monotonic() - started:.1f}s (interval {INTERVAL}s)")

        layout = [k for k in keys() if k.startswith("journal/node/")]
        assert layout, keys()
        for key in layout:
            # journal/<host>/%Y/%m/%d/%H/<first-event-unix-seconds>-<uuid4>.ndjson.gz
            parts = key.split("/")
            assert len(parts) == 7, key
            assert all(p.isdigit() for p in parts[2:6]), key
            m = NAME.fullmatch(parts[6])
            assert m, key
            # The hour directory is the UTC hour of the first event's seconds.
            hour = datetime.fromtimestamp(int(m.group(1)), timezone.utc).strftime("%Y/%m/%d/%H")
            assert "/".join(parts[2:6]) == hour, key

        rows = node.succeed(f"dump-journal-keys | grep {probe}").strip().splitlines()
        key, line = rows[0].split("\t", 1)
        event = json.loads(line)
        assert set(event) == KEEP, sorted(set(event) ^ KEEP)
        assert all(isinstance(v, str) for v in event.values()), event
        assert event["message"] == probe, event
        assert event["ident"] == "probe", event
        assert event["unit"], event
        assert event["cursor"].startswith("s="), event
        assert event["host"] == "node", event
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", event["timestamp"]), event
        # The probe's object sits under the probe's own UTC hour.
        assert key.split("/")[2:6] == [event["timestamp"][0:4], event["timestamp"][5:7], event["timestamp"][8:10], event["timestamp"][11:13]], (key, event)

    with subtest("test_shipper_own_logs_excluded"):
        # The shipper does log under its own unit ("shipped N object(s)")...
        node.succeed("test -n \"$(journalctl _SYSTEMD_UNIT=stackbase-logs.service --no-pager -o cat)\"")
        # ...and none of it reaches the bucket.
        evs = events()
        units = {e.get("unit") for e in evs}
        assert "stackbase-logs.service" not in units, units
        assert not [e for e in evs if (e.get("message") or "").startswith("log-shipper:")]

    with subtest("credentials file, user and state are as designed"):
        node.succeed("test \"$(stat -c '%U:%G %a' /var/lib/stackbase/logs.env)\" = 'root:root 600'")
        node.succeed("test \"$(systemctl show -p User --value stackbase-logs.service)\" = stackbase-logs")
        node.succeed(f"test \"$(stat -c '%U %G %a' {STATE})\" = 'stackbase-logs stackbase-logs 700'")
        node.succeed(f"test -s {STATE}/cursor")

    with subtest("test_logs_survive_s3_outage"):
        tag = f"outage-{uuid.uuid4()}"
        node.succeed("systemctl stop minio.service")
        failed_before = int(node.succeed(
            "journalctl -u stackbase-logs.service -o cat --no-pager | grep -c '^log-shipper: failed: ' || true"
        ).strip())
        node.succeed(f"for i in $(seq 1 1000); do logger -t outage {tag}-$i; done")
        # At least one run reads them, fails to upload, and keeps them
        # spooled with the cursor unmoved.
        node.wait_until_succeeds(
            "test $(journalctl -u stackbase-logs.service -o cat --no-pager "
            f"| grep -c '^log-shipper: failed: ' || true) -gt {failed_before}",
            timeout=120,
        )
        node.succeed(f"test -n \"$(ls -A {STATE}/pending)\"")
        # Runs keep failing for a few intervals; nothing moves meanwhile.
        time.sleep(3 * INTERVAL)
        cursor = node.succeed(f"cat {STATE}/cursor").strip()
        logged = node.succeed(f"journalctl -t outage -o cat --no-pager | grep -c '^{tag}-' || true").strip()
        assert logged == "1000", f"journal has {logged} of the probes"
        after = node.succeed(
            f"journalctl -t outage -o cat --no-pager --after-cursor='{cursor}' | grep -c '^{tag}-' || true"
        ).strip()
        assert after == "1000", f"the cursor moved past {1000 - int(after)} unshipped probes"

        node.succeed("systemctl start minio.service")
        node.wait_for_open_port(${toString minio.port})
        want = {f"{tag}-{i}" for i in range(1, 1001)}
        evs = wait_all(want, "outage probes")
        assert_no_gap_and_dup_by_cursor(evs, want, "outage probes")
        node.wait_until_succeeds(f"test -z \"$(ls -A {STATE}/pending)\"", timeout=60)

    with subtest("test_restart_mid_backlog_no_gap"):
        # Freeze MinIO: connections are accepted but never answered, so a
        # run hangs inside its upload -- then kill that run outright, the
        # way a crash or an OOM kill would.
        tag = f"restart-{uuid.uuid4()}"
        node.succeed("systemctl kill -s SIGSTOP minio.service")
        node.succeed(f"for i in $(seq 1 1000); do logger -t restart {tag}-$i; done")
        node.wait_until_succeeds(
            "test \"$(systemctl show -p ActiveState --value stackbase-logs.service)\" = activating "
            f"&& pgrep -u stackbase-logs rclone && test -n \"$(ls -A {STATE}/pending)\"",
            timeout=120,
        )
        time.sleep(2)
        node.succeed("systemctl kill -s SIGKILL stackbase-logs.service")
        node.wait_until_succeeds(
            "test \"$(systemctl show -p ActiveState --value stackbase-logs.service)\" != activating",
            timeout=30,
        )
        print("killed a run mid-upload; pending: " + node.succeed(f"ls -A {STATE}/pending").strip())

        node.succeed("systemctl kill -s SIGCONT minio.service")
        want = {f"{tag}-{i}" for i in range(1, 1001)}
        evs = wait_all(want, "restart probes")
        assert_no_gap_and_dup_by_cursor(evs, want, "restart probes")
        node.wait_until_succeeds(f"test -z \"$(ls -A {STATE}/pending)\"", timeout=120)
  '';
}
