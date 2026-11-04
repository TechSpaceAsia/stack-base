# NixOS VM test wired as `checks.x86_64-linux.vm-logs` in flake.nix. Boots
# one stackbase node with nixos/logs.nix shipping its journal to a MinIO
# bucket on the same machine (tests/minio.nix, standing in for R2), and
# proves the properties the design rests on: entries arrive within one
# batch, slimmed to nine fields; an S3 outage plus a Vector restart loses
# nothing; a full local disk never holds up the bucket; Vector does not
# ship its own logs.
#
# Iterate on it alone with:
#   nix build .#checks.x86_64-linux.vm-logs -L
{ self, pkgs, lib }:

let
  minio = import ./minio.nix { inherit pkgs; };

  adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBDGmdzpEogrHBnAP+a1MKjbV+D9E9nQOVx8m2wcmt3 vm-test-admin";

  bucket = "logs";
  # Shorter than production's 15 s so the test does not idle; the
  # behaviour under test does not depend on the value.
  batchSeconds = 5;
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
      stackbase.logs.batchSeconds = batchSeconds;

      # What `./infra/up`'s ENSURE_LOGS_ENV puts on a real node: the same
      # path, owner and mode, written before Vector first starts.
      systemd.services.stackbase-test-logs-env = {
        wantedBy = [ "multi-user.target" ];
        before = [ "vector.service" ];
        requiredBy = [ "vector.service" ];
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
        pkgs.curl
        pkgs.gzip
        # Every event in the bucket, one JSON object per line, decompressed
        # whichever way an object was stored (zcat -f passes plain through).
        (pkgs.writeShellScriptBin "dump-journal" ''
          rm -rf /tmp/dl && mkdir -p /tmp/dl
          s3 cp --recursive s3/${bucket}/journal/ /tmp/dl/ >/dev/null 2>&1 || true
          find /tmp/dl -type f -name '*.ndjson.gz' -exec zcat -f {} +
        '')
      ];
      virtualisation.diskSize = 4096;
    };

  testScript = ''
    import json
    import time
    import uuid

    start_all()
    node.wait_for_unit("multi-user.target")
    ${minio.createBucket "node" bucket}
    node.wait_for_unit("vector.service")
    node.wait_for_open_port(9598)

    KEEP = {"timestamp", "host", "unit", "ident", "pid", "priority", "message", "boot_id", "cursor"}


    def keys():
        out = node.succeed("s3 ls --recursive --json s3/${bucket}/ || true")
        return [json.loads(line)["key"] for line in out.splitlines() if line.strip().startswith("{")]


    def events():
        out = node.succeed("dump-journal || true")
        return [json.loads(line) for line in out.splitlines() if line.strip()]


    def messages():
        return {e.get("message") for e in events()}


    with subtest("test_logs_reach_s3"):
        probe = str(uuid.uuid4())
        started = time.monotonic()
        node.succeed(f"logger -t probe {probe}")
        node.wait_until_succeeds(f"dump-journal | grep -q {probe}", timeout=${toString (batchSeconds * 4)})
        print(f"probe reached the bucket after {time.monotonic() - started:.1f}s (batch {${toString batchSeconds}}s)")

        layout = [k for k in keys() if k.startswith("journal/node/")]
        assert layout, keys()
        for key in layout:
            # journal/<host>/%Y/%m/%d/%H/<uuid>.ndjson.gz
            parts = key.split("/")
            assert len(parts) == 7 and parts[-1].endswith(".ndjson.gz"), key
            assert all(p.isdigit() for p in parts[2:6]), key

        found = [e for e in events() if e.get("message") == probe]
        assert found, "probe not in any object"
        event = found[0]
        assert event["ident"] == "probe", event
        assert event["unit"], event
        assert event["cursor"].startswith("s="), event
        assert event["host"] == "node", event
        assert set(event) <= KEEP, sorted(set(event) - KEEP)
        assert "_CMDLINE" not in event, event

    with subtest("the plain-text local copy has the probe too"):
        node.succeed(f"grep -rq {probe} /var/log/vector/")
        node.succeed("test \"$(stat -c '%U %a' /var/log/vector)\" = 'vector 750'")

    with subtest("test_vector_own_logs_excluded"):
        # Vector does log (its start-up lines at least) -- they just stay home.
        node.succeed("test -n \"$(journalctl -u vector.service --no-pager -o cat)\"")
        shipped_units = {e.get("unit") for e in events()}
        assert "vector.service" not in shipped_units, shipped_units

    with subtest("credentials file, user, metrics and API are as designed"):
        node.succeed("test \"$(stat -c '%U:%G %a' /var/lib/stackbase/logs.env)\" = 'root:root 600'")
        node.succeed("test \"$(systemctl show -p User --value vector.service)\" = vector")
        metrics = node.succeed("curl -sf http://127.0.0.1:9598/metrics")
        assert "vector_component_sent_events_total" in metrics, metrics[:400]
        assert "vector_buffer_byte_size" in metrics, metrics[:400]
        node.succeed("curl -sf http://127.0.0.1:8686/health")
        # Neither listens beyond loopback.
        node.fail("ss -ltnH | grep -E ':(9598|8686) ' | grep -v 127.0.0.1")

    with subtest("test_logs_survive_s3_outage"):
        tag = f"outage-{uuid.uuid4()}"
        node.succeed("systemctl stop minio.service")
        node.succeed(f"for i in $(seq 1 1000); do logger -t outage {tag}-$i; done")
        # Let Vector read them and fail at least one upload, so they sit in
        # its disk buffer rather than only in the journal...
        time.sleep(${toString (batchSeconds * 3)})
        # The disk buffer, not the journal, must be what brings them back:
        # there is data under data_dir's buffer for the R2 sink, and the
        # journald source's checkpoint (<data_dir>/<source id>/checkpoint.txt
        # in Vector 0.55) is already past every probe -- so a re-read of the
        # journal after the restart would not include a single one of them.
        node.succeed("find /var/lib/vector/buffer -type f -size +1k | grep -q .")
        checkpoint = "/var/lib/vector/journal/checkpoint.txt"
        node.succeed(f"test -s {checkpoint}")
        print("journald checkpoint: " + node.succeed(f"cat {checkpoint}").strip())
        # A real cursor in this journal, so the --after-cursor count below
        # cannot be 0 merely because journalctl rejected the cursor.
        node.succeed(f"journalctl --no-pager -n 1 --cursor=\"$(cat {checkpoint})\" >/dev/null")
        logged = node.succeed(f"journalctl -t outage -o cat --no-pager | grep -c '^{tag}-' || true").strip()
        assert logged == "1000", f"journal has {logged} of the probes before the restart"
        after = node.succeed(
            f"journalctl -t outage -o cat --no-pager --after-cursor=\"$(cat {checkpoint})\" "
            f"| grep -c '^{tag}-' || true"
        ).strip()
        print(f"probes in the journal after the checkpoint: {after}")
        assert after == "0", f"{after} probes are still ahead of the checkpoint"
        # And remove them from the journal altogether, so nothing but the
        # buffer could possibly deliver them.
        node.succeed("journalctl --rotate && journalctl --vacuum-time=1s")
        gone = node.succeed(f"journalctl -t outage -o cat --no-pager | grep -c '^{tag}-' || true").strip()
        print(f"probes left in the journal after vacuum: {gone}")
        assert gone == "0", f"{gone} probes survived the vacuum"
        # ...then restart it while the bucket is still unreachable: whatever
        # was buffered must survive the restart.
        node.succeed("systemctl restart vector.service")
        node.wait_for_unit("vector.service")
        node.succeed("systemctl start minio.service")
        node.wait_for_open_port(${toString minio.port})

        want = {f"{tag}-{i}" for i in range(1, 1001)}
        deadline = time.monotonic() + 300
        while True:
            got = want & messages()
            if got == want:
                break
            assert time.monotonic() < deadline, f"only {len(got)} of 1000 arrived"
            time.sleep(5)
        print("all 1000 outage probes arrived")

    with subtest("test_local_sink_full_does_not_block_r2"):
        node.succeed("systemctl stop vector.service")
        node.succeed(
            "mount -t tmpfs -o size=1m,mode=0750,uid=$(id -u vector),gid=$(id -g vector) tmpfs /var/log/vector"
        )
        node.succeed("dd if=/dev/zero of=/var/log/vector/fill bs=4k 2>/dev/null || true")
        node.succeed("test \"$(df --output=avail /var/log/vector | tail -1 | tr -d ' ')\" = 0")
        node.succeed("systemctl start vector.service")
        node.wait_for_unit("vector.service")

        full = f"full-{uuid.uuid4()}"
        node.succeed(f"for i in $(seq 1 200); do logger -t full {full}-$i; done")
        want = {f"{full}-{i}" for i in range(1, 201)}
        deadline = time.monotonic() + 120
        while True:
            got = want & messages()
            if got == want:
                break
            assert time.monotonic() < deadline, f"only {len(got)} of 200 arrived with the local disk full"
            time.sleep(5)
        node.fail(f"grep -rq {full} /var/log/vector/")

        node.succeed("systemctl stop vector.service && umount /var/log/vector && systemctl start vector.service")
        node.wait_for_unit("vector.service")
  '';
}
