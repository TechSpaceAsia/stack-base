# Failure email: ANY failed systemd service on the node is mailed to
# stack.toml's [alerts] to, at most once per unit per `intervalHours`, and an
# hourly watchdog fails (and so mails) when backups or log shipping go stale.
#
# Ported from platform-base's nixos/unit-failure-mail.nix (proven live) and
# nixos/company-ops-mail-sender.nix:
#
# How: one top-level drop-in (`service.d/`) adds
#     OnFailure=stackbase-alert@%N.service
# to EVERY service on the node -- the project's own, stack-base's, nixpkgs'
# and any added later. Nothing is enumerated, so nothing can be forgotten.
# The handler itself is excluded by a same-named, empty drop-in in its own
# `stackbase-alert@.service.d/`, which masks the top-level one (the
# documented systemd pattern, systemd.unit(5) "top-level drop-ins") -- the
# only thing standing between a failing handler and infinite recursion.
#
# Delivery is nullmailer, which queues on disk and retries: an alert raised
# while the relay (or Mesh, on the way to it) is down is delayed, never
# lost. The relay's settings come from /var/lib/stackbase/alert.env, written
# by `./infra/up`'s ENSURE_ALERT_ENV step from the environment's smtp_*
# secrets and read here only through systemd's EnvironmentFile, by a root
# oneshot that renders nullmailer's remotes into a 0600 runtime file. The
# password never enters the Nix store, and never enters the long-running
# nullmailer daemon's environment either.
#
# Rate limit: at most one email per unit per `intervalHours`. A unit that
# keeps failing mails four times a day, not ninety-six. The stamp is written
# only after sendmail accepted (queued) the message, so a failed submission
# is retried on the unit's next failure.
#
# Not covered: a unit with Restart=always that crash-loops and later comes
# back never enters `failed`, so OnFailure= never fires; and a dead node
# sends nothing at all. Those need an outside observer.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase.alerts;
  enabled = cfg.to != [ ];

  alertEnvFile = "/var/lib/stackbase/alert.env";
  runtimeDir = "/run/stackbase-alert";
  stateDir = "/var/lib/stackbase-alert";
  dropInName = "10-stackbase-alert.conf";
  nullmailerUser = config.services.nullmailer.user;
  nullmailerGroup = config.services.nullmailer.group;

  hostName = config.networking.hostName;
  label = lib.concatStringsSep "/"
    ([ config.stackbase.project ]
      ++ lib.optional (config.stackbase.environment != "") config.stackbase.environment
      ++ [ hostName ]);

  handler = pkgs.writeShellScript "stackbase-alert" ''
    set -euo pipefail
    unit="$1.service"
    stamp=${stateDir}/"$unit"
    now=$(date +%s)
    interval=$(( ${toString cfg.intervalHours} * 3600 ))

    if [ -r "$stamp" ]; then
      last=$(cat "$stamp" 2>/dev/null || echo 0)
      if [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < interval )); then
        echo "$unit failed again; already mailed within ${toString cfg.intervalHours}h, not mailing"
        exit 0
      fi
    fi

    # Not a secret (it is the envelope sender), rendered next to the
    # remotes by stackbase-alert-remotes from alert.env.
    from=$(cat ${runtimeDir}/from 2>/dev/null || true)

    # Built whole, then truncated: piping straight into `head -c` would
    # SIGPIPE the writer on a long journal and, under pipefail, fail the
    # alert.
    message=$({
      if [ -n "$from" ]; then printf 'From: %s\n' "$from"; fi
      printf 'To: %s\n' ${lib.escapeShellArg (lib.concatStringsSep ", " cfg.to)}
      printf 'Subject: [%s] %s failed\n' ${lib.escapeShellArg label} "$unit"
      printf 'Content-Type: text/plain; charset=utf-8\n'
      printf '\n'
      printf '%s failed on %s at %s.\n' "$unit" ${lib.escapeShellArg label} "$(date -Is)"
      printf 'Further failures of this unit are not mailed for %s hours.\n\n' ${toString cfg.intervalHours}
      systemctl status --no-pager --lines=0 "$unit" 2>&1 || true
      printf '\n--- last %s journal lines ---\n' ${toString cfg.journalLines}
      journalctl --unit="$unit" --lines=${toString cfg.journalLines} --no-pager --output=short-iso 2>&1 || true
    })
    printf '%s\n' "''${message:0:65536}" | /run/wrappers/bin/sendmail -t

    printf '%s\n' "$now" > "$stamp.new"
    mv -f "$stamp.new" "$stamp"
    echo "mailed failure of $unit"
  '';

  dropIns = pkgs.runCommand "stackbase-alert-dropins" { } ''
    mkdir -p $out/etc/systemd/system/service.d $out/etc/systemd/system/stackbase-alert@.service.d
    cat > $out/etc/systemd/system/service.d/${dropInName} <<'EOF'
    [Unit]
    OnFailure=stackbase-alert@%N.service
    EOF
    # Same file name, more specific directory: masks the line above for the
    # handler itself. Without this a failing handler triggers itself forever.
    : > $out/etc/systemd/system/stackbase-alert@.service.d/${dropInName}
  '';

  # Root, so it can read nothing but what systemd hands it: alert.env
  # arrives as environment variables through EnvironmentFile (never
  # sourced), and the values are checked against the same shapes
  # stackbase/alerts.py enforces before they are written to one line of the
  # remotes file, where a space would start a new nullmailer option.
  renderRemotes = pkgs.writeShellScript "stackbase-alert-remotes" ''
    set -euo pipefail
    check() {
      if [[ ! "$2" =~ $3 ]]; then
        echo "stackbase-alert-remotes: $1 in ${alertEnvFile} is missing or has an unexpected shape -- set smtp_* in the environment's secrets and run ./infra/up" >&2
        exit 1
      fi
    }
    check SMTP_HOST "''${SMTP_HOST:-}" '^[A-Za-z0-9.:-]+$'
    check SMTP_PORT "''${SMTP_PORT:-}" '^[0-9]{1,5}$'
    check SMTP_USER "''${SMTP_USER:-}" '^[A-Za-z0-9._:/+=@-]+$'
    check SMTP_PASSWORD "''${SMTP_PASSWORD:-}" '^[A-Za-z0-9._:/+=@-]+$'
    check SMTP_FROM "''${SMTP_FROM:-}" '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$'

    umask 077
    chgrp ${nullmailerGroup} ${runtimeDir}
    chmod 0750 ${runtimeDir}
    # Implicit TLS (--tls, port from smtp_port: 465 for a submissions
    # relay), the certificate verified against the system CA bundle.
    printf '%s smtp --port=%s --tls --auth-login --user=%s --pass=%s --x509cafile=%s\n' \
      "$SMTP_HOST" "$SMTP_PORT" "$SMTP_USER" "$SMTP_PASSWORD" /etc/ssl/certs/ca-certificates.crt \
      > ${runtimeDir}/remotes.new
    chown ${nullmailerUser}:${nullmailerGroup} ${runtimeDir}/remotes.new
    mv -f ${runtimeDir}/remotes.new ${runtimeDir}/remotes

    # The envelope sender, for nullmailer's allmailfrom and the handler's
    # From: header. Readable by nullmailer's setuid sendmail, not by anyone.
    printf '%s\n' "$SMTP_FROM" > ${runtimeDir}/from.new
    chgrp ${nullmailerGroup} ${runtimeDir}/from.new
    chmod 0640 ${runtimeDir}/from.new
    mv -f ${runtimeDir}/from.new ${runtimeDir}/from
  '';

  # `./infra/up alert-test` runs this as root over SSH: fail a throwaway
  # transient unit, then wait for the handler's stamp, which it writes only
  # once sendmail has queued the message.
  alertTest = pkgs.writeShellApplication {
    name = "stackbase-alert-test";
    runtimeInputs = [ pkgs.coreutils pkgs.systemd ];
    text = ''
      unit="stackbase-alert-test-$(date +%Y%m%d%H%M%S)-$$"
      handler="stackbase-alert@$unit.service"
      systemd-run --quiet --unit="$unit" --description="stack-base alert test (fails on purpose)" ${pkgs.coreutils}/bin/false
      for _ in $(seq 1 60); do
        if [ -e ${stateDir}/"$unit.service" ]; then
          echo "the failure of $unit.service is queued for ${lib.concatStringsSep ", " cfg.to}"
          exit 0
        fi
        if systemctl is-failed --quiet "$handler"; then
          echo "the alert handler failed -- journalctl -u $handler" >&2
          exit 1
        fi
        sleep 1
      done
      echo "no alert was queued within 60 s -- journalctl -u $handler -u nullmailer" >&2
      exit 1
    '';
  };

  # Hourly. Fails (exit 1, so the drop-in mails it) on anything stale;
  # exits 0 inside the grace after boot, while Vector and the first backup
  # are still catching up. Tunables arrive as environment variables so the
  # unit file shows exactly what is being enforced.
  freshness = pkgs.writeShellApplication {
    name = "stackbase-freshness";
    runtimeInputs = [ pkgs.coreutils pkgs.curl pkgs.gawk pkgs.systemd ];
    text = ''
      uptime=$(cut -d. -f1 /proc/uptime)
      if (( uptime < GRACE_SECONDS )); then
        echo "up ''${uptime}s, inside the ''${GRACE_SECONDS}s grace after boot -- not checking yet"
        exit 0
      fi

      now=$(date +%s)
      problems=()

      if [ "$CHECK_BACKUPS" = 1 ]; then
        # last-success is written by the backup unit when it completes;
        # before the first one, the age is counted from when backups were
        # turned on (enabled-at, created once by tmpfiles).
        if [ -r /var/lib/stackbase-backup/last-success ]; then
          last=$(cat /var/lib/stackbase-backup/last-success)
          what="the newest successful backup"
        else
          last=$(stat -c %Y /var/lib/stackbase-backup/enabled-at 2>/dev/null || echo "$now")
          what="no backup has succeeded yet; backups were turned on"
        fi
        if [[ ! "$last" =~ ^[0-9]+$ ]]; then last=0; fi
        if (( now - last > BACKUP_MAX_AGE_SECONDS )); then
          problems+=("backups: $what at $(date -u -d "@$last" -Is), more than $(( BACKUP_MAX_AGE_SECONDS / 3600 )) h ago -- see journalctl -u stackbase-backup")
        fi
      fi

      if [ "$CHECK_LOGS" = 1 ]; then
        if ! systemctl is-active --quiet vector.service; then
          problems+=("logs: vector.service is not active -- see journalctl -u vector")
        elif ! metrics=$(curl -sf --max-time 10 http://127.0.0.1:9598/metrics); then
          problems+=("logs: could not read Vector's metrics on 127.0.0.1:9598")
        else
          # The R2 sink's series only (component_id="r2"), summed over
          # whatever other labels they carry. The value is the first field
          # after the closing brace of the label set.
          metric() {
            printf '%s\n' "$metrics" | awk -v name="$1" '
              index($0, name "{") == 1 && index($0, "component_id=\"r2\"") {
                line = $0; sub(/^[^}]*\} */, "", line); split(line, f, " "); sum += f[1]
              }
              END { printf "%.0f\n", sum + 0 }'
          }
          buffered=$(metric vector_buffer_byte_size)
          sent=$(metric vector_component_sent_events_total)
          received=$(metric vector_component_received_events_total)

          if (( buffered > BUFFER_ALERT_BYTES )); then
            problems+=("logs: $buffered bytes are waiting in Vector's R2 buffer (alert above $BUFFER_ALERT_BYTES) -- R2 has been unreachable for a while; see journalctl -u vector")
          fi

          # Counters reset when Vector restarts, so a sample is only
          # compared with one taken at least SENT_STALL_SECONDS ago in the
          # same run of Vector (neither counter went down).
          samples=/var/lib/stackbase-freshness/r2-samples
          touch "$samples"
          old=$(awk -v cutoff=$(( now - SENT_STALL_SECONDS )) '$1 <= cutoff { line = $0 } END { print line }' "$samples")
          if [ -n "$old" ]; then
            read -r old_ts old_sent old_received <<<"$old"
            if (( sent == old_sent && received > old_received )); then
              problems+=("logs: Vector has sent nothing to R2 since $(date -u -d "@$old_ts" -Is) although $(( received - old_received )) events came in -- see journalctl -u vector")
            fi
          fi
          { awk -v keep=$(( now - 2 * SENT_STALL_SECONDS )) '$1 >= keep' "$samples"; echo "$now $sent $received"; } > "$samples.new"
          mv -f "$samples.new" "$samples"
        fi
      fi

      if (( ''${#problems[@]} > 0 )); then
        for problem in "''${problems[@]}"; do echo "✗ $problem" >&2; done
        exit 1
      fi
      echo "✓ backups and log shipping are fresh"
    '';
  };
in
{
  options.stackbase.alerts = {
    to = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Who is mailed when any service on the node fails (stack.toml's
        [alerts] to). Empty (the default) turns the whole alert path off:
        no nullmailer, no drop-in, no watchdog.
      '';
    };

    intervalHours = lib.mkOption {
      type = lib.types.ints.positive;
      default = 6;
      description = "At most one email per failing unit per this many hours.";
    };

    journalLines = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "Journal lines of the failed unit included in the email.";
    };

    bufferAlertBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 268435456;
      description = ''
        The watchdog fails when Vector's R2 disk buffer holds more than this:
        R2 has then been unreachable for a while. Lowered only by the VM test.
      '';
    };

    graceSeconds = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 3600;
      description = "The watchdog checks nothing while the node has been up for less than this.";
    };

    retrySeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "nullmailer's first retry after a failed delivery; it doubles up to maxRetrySeconds.";
    };

    maxRetrySeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 900;
      description = "Longest nullmailer waits between delivery attempts while mail is queued.";
    };

    subjectLabel = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = label;
      defaultText = lib.literalExpression ''"<project>/<environment>/<hostName>", or "<project>/<hostName>" without an environment'';
      description = "What alert subjects carry in brackets. Derived; not settable.";
    };
  };

  config = lib.mkIf enabled {
    assertions = [
      {
        assertion = cfg.maxRetrySeconds >= cfg.retrySeconds;
        message = "stackbase.alerts.maxRetrySeconds must be at least retrySeconds.";
      }
    ];

    services.nullmailer = {
      enable = true;
      setSendmail = true;
      # A runtime path, never a file in the Nix store (it holds the password).
      remotesFile = "${runtimeDir}/remotes";
      config = {
        me = hostName;
        defaulthost = hostName;
        # Mail to root and friends goes where the alerts go.
        adminaddr = lib.concatStringsSep "," cfg.to;
        doublebounceto = builtins.head cfg.to;
        pausetime = cfg.retrySeconds;
        maxpause = cfg.maxRetrySeconds;
        sendtimeout = 120;
      };
    };
    # The envelope sender comes from smtp_from, a runtime value, so it is a
    # runtime symlink like the remotes file.
    environment.etc."nullmailer/allmailfrom".source = "${runtimeDir}/from";

    systemd.services.stackbase-alert-remotes = {
      description = "Render nullmailer's relay settings from ${alertEnvFile}";
      wantedBy = [ "multi-user.target" ];
      before = [ "nullmailer.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Required, not "-": without it there is no relay, and saying so
        # here beats a nullmailer that queues forever.
        EnvironmentFile = alertEnvFile;
        ExecStart = renderRemotes;
        RuntimeDirectory = "stackbase-alert";
        RuntimeDirectoryMode = "0750";
        UMask = "0077";
      };
    };

    systemd.services.nullmailer = {
      wants = [ "network-online.target" ];
      after = [ "network-online.target" "stackbase-alert-remotes.service" ];
      requires = [ "stackbase-alert-remotes.service" ];
      # Re-rendering the remotes (ENSURE_ALERT_ENV after a rotation)
      # restarts nullmailer with them.
      partOf = [ "stackbase-alert-remotes.service" ];
      serviceConfig = {
        RestartSec = "10s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/spool/nullmailer" ];
        RestrictSUIDSGID = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
      };
    };

    systemd.packages = [ dropIns ];

    systemd.services."stackbase-alert@" = {
      description = "Email the failure of %i.service to [alerts] to";
      path = [ pkgs.coreutils pkgs.systemd ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${handler} %i";
        StateDirectory = "stackbase-alert";
        StateDirectoryMode = "0700";
        UMask = "0077";
        TimeoutStartSec = "2min";
      };
    };

    systemd.services.stackbase-freshness = {
      description = "Fail when backups or log shipping have gone stale";
      environment = {
        GRACE_SECONDS = toString cfg.graceSeconds;
        BACKUP_MAX_AGE_SECONDS = toString (36 * 3600);
        BUFFER_ALERT_BYTES = toString cfg.bufferAlertBytes;
        SENT_STALL_SECONDS = toString (2 * 3600);
        # Only what this node has: backups opted out, or logs off, are not
        # checked at all.
        CHECK_BACKUPS = if config.stackbase.backups.enable or false then "1" else "0";
        CHECK_LOGS = if config.stackbase.logs.enable or false then "1" else "0";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${freshness}/bin/stackbase-freshness";
        StateDirectory = "stackbase-freshness";
        StateDirectoryMode = "0700";
      };
    };

    systemd.timers.stackbase-freshness = {
      wantedBy = [ "timers.target" ];
      timerConfig.OnCalendar = "hourly";
    };

    environment.systemPackages = [ alertTest ];
  };
}
