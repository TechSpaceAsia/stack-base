# NixOS VM test wired as `checks.x86_64-linux.vm-alerts` in flake.nix. Boots
# one stackbase node with nixos/alerts.nix mailing a Mailpit sink on the same
# machine, over implicit TLS with a certificate from a test CA the node
# trusts -- the same `--tls`, CA-verified path a real relay is reached by.
# It proves: any failed unit mails, the handler cannot recurse, mail raised
# while the relay is down is queued and delivered later, one mail per unit
# per interval, and the freshness watchdog's grace, log-shipping and backup
# checks. The shipper really runs against MinIO, so the stamp the watchdog
# reads is the one stackbase-logs.service writes.
#
# Iterate on it alone with:
#   nix build .#checks.x86_64-linux.vm-alerts -L
{ self, pkgs, lib }:

let
  minio = import ./minio.nix { inherit pkgs; };

  adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBDGmdzpEogrHBnAP+a1MKjbV+D9E9nQOVx8m2wcmt3 vm-test-admin";

  smtpHost = "mail.test";
  # Not 465 on purpose: the port comes from smtp_port, and this proves it
  # is honoured (Mailpit runs unprivileged).
  smtpPort = 1465;
  smtpUser = "staging-node@mail.test";
  smtpPassword = "vm-test-smtp-password";
  smtpFrom = "staging-node@mail.test";
  recipients = [ "ops@example.test" "servers.teststack.staging@example.test" ];

  # A throwaway CA and a server certificate for mail.test, signed by it.
  # Test-only, and in the world-readable store on purpose: they protect
  # nothing.
  certs = pkgs.runCommand "stackbase-test-smtp-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=stackbase-test-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -keyout ca.key -out $out/ca.crt 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj /CN=${smtpHost} -keyout $out/server.key -out server.csr 2>/dev/null
    printf 'subjectAltName=DNS:${smtpHost}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext
    openssl x509 -req -in server.csr -CA $out/ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile ext -out $out/server.crt 2>/dev/null
  '';

  # Only these credentials are accepted, so a delivered mail proves the
  # relay was logged in to with exactly what alert.env holds.
  authFile = pkgs.writeText "mailpit-auth" "${smtpUser}:${smtpPassword}\n";

  # What `./infra/up`'s ENSURE_ALERT_ENV puts on a real node.
  alertEnv = pkgs.writeText "alert.env" ''
    SMTP_HOST=${smtpHost}
    SMTP_PORT=${toString smtpPort}
    SMTP_USER=${smtpUser}
    SMTP_PASSWORD=${smtpPassword}
    SMTP_FROM=${smtpFrom}
  '';
in
pkgs.testers.runNixOSTest {
  name = "stackbase-vm-alerts";

  nodes.node =
    { ... }:
    {
      imports = [
        self.nixosModules.base
        self.nixosModules.backups
        self.nixosModules.logs
        self.nixosModules.alerts
        minio.module
      ];

      networking.hostName = "staging-node";
      stackbase.project = "teststack";
      stackbase.environment = "staging";
      stackbase.admins.deploy = adminKey;

      stackbase.alerts.to = recipients;
      # Retry quickly once the relay is back; production waits 60 s.
      stackbase.alerts.retrySeconds = 3;
      stackbase.alerts.maxRetrySeconds = 6;

      stackbase.logs.bucket = "logs";
      # The watchdog's backup check needs backups configured; the unit
      # itself never runs here.
      stackbase.backups.bucket = "unused";
      # The backup script names pg_dump's package; Postgres itself is not
      # needed, as the unit never runs.
      services.postgresql.package = pkgs.postgresql;

      networking.hosts."127.0.0.1" = [ smtpHost ];
      security.pki.certificateFiles = [ "${certs}/ca.crt" ];

      services.mailpit.instances.sink = {
        smtp = "127.0.0.1:${toString smtpPort}";
        listen = "127.0.0.1:8025";
        smtp-tls-cert = "${certs}/server.crt";
        smtp-tls-key = "${certs}/server.key";
        # Implicit TLS, like a port-465 submissions relay.
        smtp-require-tls = true;
        smtp-auth-file = "${authFile}";
      };

      systemd.services.stackbase-test-env-files = {
        wantedBy = [ "multi-user.target" ];
        before = [ "stackbase-logs.service" "stackbase-alert-remotes.service" ];
        requiredBy = [ "stackbase-logs.service" "stackbase-alert-remotes.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          install -d -m 0750 /var/lib/stackbase
          install -m 0600 -o root -g root ${pkgs.writeText "logs.env" minio.logsEnv} /var/lib/stackbase/logs.env
          install -m 0600 -o root -g root ${alertEnv} /var/lib/stackbase/alert.env
        '';
      };

      environment.systemPackages = [ pkgs.curl pkgs.jq ];
      virtualisation.diskSize = 4096;
    };

  testScript = ''
    import json
    import time

    start_all()
    node.wait_for_unit("multi-user.target")
    ${minio.createBucket "node" "logs"}
    node.wait_for_unit("stackbase-logs.timer")
    node.wait_for_unit("nullmailer.service")
    node.wait_for_unit("mailpit-sink.service")
    node.wait_for_open_port(${toString smtpPort})
    node.wait_for_open_port(8025)

    LABEL = "teststack/staging/staging-node"


    def mails():
        out = node.succeed("curl -sf 'http://127.0.0.1:8025/api/v1/messages?limit=500'")
        return json.loads(out).get("messages") or []


    def subjects():
        return [m["Subject"] for m in mails()]


    def wait_for_mail(subject, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            for m in mails():
                if m["Subject"] == subject:
                    return m
            assert time.monotonic() < deadline, f"no mail '{subject}' in {subjects()}"
            time.sleep(1)


    def body(message):
        out = node.succeed(f"curl -sf http://127.0.0.1:8025/api/v1/message/{message['ID']}")
        return json.loads(out)["Text"]


    def wait_handler_done(unit):
        """Until the handler for `unit` has run to the end (mailed or not)."""
        node.wait_until_succeeds(
            f"journalctl -u stackbase-alert@{unit}.service -o cat --no-pager "
            "| grep -E '^(mailed failure|.* already mailed within)'",
            timeout=60,
        )


    with subtest("the relay settings are rendered root-only, from alert.env"):
        node.succeed("test \"$(stat -c '%U %a' /run/stackbase-alert/remotes)\" = 'nullmailer 600'")
        node.succeed("grep -q -- '--port=${toString smtpPort} --tls --auth-login' /run/stackbase-alert/remotes")
        node.succeed("grep -q -- '--x509cafile=/etc/ssl/certs/ca-certificates.crt' /run/stackbase-alert/remotes")
        # The password is in no other file under /etc/nullmailer (only the
        # remotes symlink points at it), and not in the running nullmailer's
        # environment.
        node.fail("grep -rqs ${smtpPassword} /etc/nullmailer/ --exclude=remotes")
        node.fail("tr '\\0' '\\n' < /proc/$(systemctl show -p MainPID --value nullmailer)/environ | grep -q ${smtpPassword}")

    with subtest("test_any_failed_unit_mails"):
        node.succeed("systemd-run --unit=boom ${pkgs.coreutils}/bin/false")
        message = wait_for_mail(f"[{LABEL}] boom.service failed")
        assert sorted(a["Address"] for a in message["To"]) == sorted(${builtins.toJSON recipients}), message["To"]
        assert message["From"]["Address"] == "${smtpFrom}", message["From"]
        text = body(message)
        assert "boom.service failed on" in text, text
        assert "--- last 60 journal lines ---" in text, text

    with subtest("test_handler_failure_does_not_recurse"):
        # Every other service carries the drop-in...
        out = node.succeed("systemctl show -p OnFailure nullmailer.service").strip()
        assert out == "OnFailure=stackbase-alert@nullmailer.service", out
        # ...and the handler itself does not.
        out = node.succeed("systemctl show -p OnFailure stackbase-alert@x.service").strip()
        assert out == "OnFailure=", out
        # And it is never start-limited, so a burst of failures cannot
        # silence the next real one.
        out = node.succeed("systemctl show -p StartLimitIntervalUSec stackbase-alert@x.service").strip()
        assert out == "StartLimitIntervalUSec=0", out

    with subtest("test_alert_queued_while_relay_down"):
        node.succeed("systemctl stop mailpit-sink.service")
        node.succeed("systemd-run --unit=queued ${pkgs.coreutils}/bin/false")
        wait_handler_done("queued")
        # Accepted by nullmailer, on disk, waiting for the relay.
        node.wait_until_succeeds("test -n \"$(ls -A /var/spool/nullmailer/queue)\"", timeout=30)
        # Mailpit keeps nothing across the restart, so only a retry from
        # the queue can put this mail in it.
        node.succeed("systemctl start mailpit-sink.service")
        node.wait_for_open_port(${toString smtpPort})
        wait_for_mail(f"[{LABEL}] queued.service failed", timeout=120)
        node.wait_until_succeeds("test -z \"$(ls -A /var/spool/nullmailer/queue)\"", timeout=30)

    with subtest("test_alert_rate_limited"):
        node.succeed("systemd-run --unit=flappy ${pkgs.coreutils}/bin/false")
        wait_for_mail(f"[{LABEL}] flappy.service failed")
        node.succeed("systemctl reset-failed flappy.service")
        node.succeed("systemd-run --unit=flappy ${pkgs.coreutils}/bin/false")
        node.wait_until_succeeds(
            "journalctl -u stackbase-alert@flappy.service -o cat --no-pager | grep -q 'already mailed within 6h'",
            timeout=60,
        )
        node.wait_until_succeeds("test -z \"$(ls -A /var/spool/nullmailer/queue)\"", timeout=30)
        time.sleep(5)
        count = subjects().count(f"[{LABEL}] flappy.service failed")
        assert count == 1, f"{count} mails for flappy"

    with subtest("alert-test's node command queues a mail and says so"):
        out = node.succeed("stackbase-alert-test")
        assert "is queued for" in out, out
        node.wait_until_succeeds(
            f"curl -sf 'http://127.0.0.1:8025/api/v1/messages?limit=500' | jq -r '.messages[].Subject' "
            f"| grep -q '^\\[{LABEL}\\] stackbase-alert-test-.*\\.service failed$'",
            timeout=60,
        )

    FRESHNESS = f"[{LABEL}] stackbase-freshness.service failed"


    def run_freshness():
        """Start the watchdog once; True if it passed. reset-failed first, so
        systemd's start limit never decides the outcome."""
        node.succeed("systemctl reset-failed stackbase-freshness.service || true")
        return node.execute("systemctl start stackbase-freshness.service")[0] == 0


    def wait_freshness_mail(text, timeout=60):
        """Until a watchdog mail whose body contains `text` arrives."""
        deadline = time.monotonic() + timeout
        while True:
            for m in mails():
                if m["Subject"] == FRESHNESS and text in body(m):
                    return
            assert time.monotonic() < deadline, f"no watchdog mail saying '{text}'"
            time.sleep(1)


    def override(**env):
        lines = "".join(f"Environment={k}={v}\\n" for k, v in env.items())
        node.succeed(
            "mkdir -p /run/systemd/system/stackbase-freshness.service.d && "
            f"printf '[Service]\\n{lines}' > /run/systemd/system/stackbase-freshness.service.d/no-grace.conf && "
            "systemctl daemon-reload"
        )


    LOGS = "/var/lib/stackbase-logs"


    def stop_shipper():
        """No shipper run from here on until start_shipper(): the stamps the
        test writes are then the only ones."""
        node.succeed("systemctl stop stackbase-logs.timer")
        node.wait_until_succeeds(
            "test \"$(systemctl show -p ActiveState --value stackbase-logs.service)\" != activating"
        )


    def start_shipper():
        node.succeed("systemctl start stackbase-logs.timer")


    def logs_stamp(age_seconds):
        node.succeed(f"echo $(( $(date +%s) - {age_seconds} )) > {LOGS}/last-success")


    def allow_another_mail():
        node.succeed("rm -f /var/lib/stackbase-alert/stackbase-freshness.service")


    def last_problem(prefix):
        """The watchdog's newest '✗ <prefix>...' line, from its journal."""
        out = node.succeed(
            f"journalctl -u stackbase-freshness -o cat --no-pager | grep '^✗ {prefix}' | tail -1"
        ).strip()
        assert out, f"no watchdog line starting '✗ {prefix}'"
        return out


    with subtest("the shipper writes the stamp the watchdog reads"):
        # Created at boot by tmpfiles, with the StateDirectory's owner and
        # mode, so neither corrects the other.
        node.succeed(f"test \"$(stat -c '%U %G %a' {LOGS})\" = 'stackbase-logs stackbase-logs 700'")
        node.succeed(f"test \"$(stat -c '%U %G %a' {LOGS}/enabled-at)\" = 'stackbase-logs stackbase-logs 600'")
        # The timer's first run (60 s after boot) ships and stamps.
        node.wait_until_succeeds(f"test -s {LOGS}/last-success", timeout=240)
        node.fail("systemctl is-failed --quiet stackbase-logs.service")

    with subtest("test_watchdog_grace_after_boot"):
        # Something it would flag -- and it still passes, being inside the
        # first hour after boot.
        stop_shipper()
        logs_stamp(1000)
        assert run_freshness(), "the watchdog failed inside the grace"
        node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | grep -q 'inside the 3600s grace'")
        time.sleep(3)
        assert FRESHNESS not in subjects(), subjects()
        logs_stamp(0)

    # From here the watchdog checks: what the grace would otherwise hide.
    override(GRACE_SECONDS=0)

    with subtest("the watchdog passes on a fresh node"):
        assert run_freshness(), node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | tail -5")

    with subtest("test_watchdog_alerts_on_stale_logs"):
        # The shipper's last success 1000 s ago, past the 900 s default.
        logs_stamp(1000)
        allow_another_mail()
        assert not run_freshness(), "the watchdog passed with no log upload for 1000 s"
        line = last_problem("logs: ")
        assert line.startswith("✗ logs: no log upload has succeeded since "), line
        assert line.endswith(", more than 15 min ago -- see journalctl -u stackbase-logs"), line
        wait_freshness_mail("logs: no log upload has succeeded since")
        # Restored, it passes again...
        logs_stamp(0)
        assert run_freshness(), "the watchdog failed with a fresh log stamp"
        # ...and so it does after a real shipper run from a stale stamp:
        # the stamp the shipper writes is the one the watchdog reads.
        logs_stamp(1000)
        node.succeed("systemctl start stackbase-logs.service")
        assert run_freshness(), node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | tail -5")

    with subtest("test_watchdog_logs_clock_fails_closed"):
        # Neither stamp: the watchdog starts the clock now (with the
        # shipper's owner and mode) instead of staying silent forever...
        node.succeed(f"rm -f {LOGS}/last-success {LOGS}/enabled-at")
        assert run_freshness(), "the watchdog failed with the logs clock just started"
        node.succeed(f"test \"$(stat -c '%U %G %a' {LOGS}/enabled-at)\" = 'stackbase-logs stackbase-logs 600'")
        node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | grep -q 'no log upload stamp yet: counting from now'")
        # ...and 16 min later, with still no success, it says so.
        node.succeed(f"touch -d '16 minutes ago' {LOGS}/enabled-at")
        allow_another_mail()
        assert not run_freshness(), "the watchdog passed with no log upload in 16 min"
        line = last_problem("logs: ")
        assert line.startswith("✗ logs: no log upload has succeeded yet; log shipping was turned on at "), line
        assert line.endswith(", more than 15 min ago -- see journalctl -u stackbase-logs"), line
        wait_freshness_mail("logs: no log upload has succeeded yet")
        logs_stamp(0)

    with subtest("the watchdog alerts on a stale backup"):
        assert run_freshness(), node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | tail -5")
        # Make the newest success 37 h old, and allow another mail.
        node.succeed("echo $(( $(date +%s) - 37 * 3600 )) > /var/lib/stackbase-backup/last-success")
        allow_another_mail()
        before = subjects().count(FRESHNESS)
        assert not run_freshness(), "the watchdog passed with a 37 h old backup"
        node.wait_until_succeeds(
            f"test $(curl -sf 'http://127.0.0.1:8025/api/v1/messages?limit=500' | jq '[.messages[] | select(.Subject == \"{FRESHNESS}\")] | length') -gt {before}",
            timeout=60,
        )
        newest = next(m for m in mails() if m["Subject"] == FRESHNESS)
        assert "backups: the newest successful backup" in body(newest), body(newest)

    with subtest("test_watchdog_backup_clock_fails_closed"):
        # Neither stamp: the watchdog starts the clock now instead of staying
        # silent forever...
        node.succeed("rm -f /var/lib/stackbase-backup/last-success /var/lib/stackbase-backup/enabled-at")
        assert run_freshness(), node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | tail -5")
        node.succeed("test -e /var/lib/stackbase-backup/enabled-at")
        node.succeed("journalctl -u stackbase-freshness -o cat --no-pager | grep -q 'no backup stamp yet: counting from now'")
        # ...and 36 h later, with still no success, it says so.
        node.succeed("touch -d '37 hours ago' /var/lib/stackbase-backup/enabled-at")
        allow_another_mail()
        assert not run_freshness(), "the watchdog passed with no backup in 37 h"
        wait_freshness_mail("no backup has succeeded yet")
        start_shipper()
  '';
}
