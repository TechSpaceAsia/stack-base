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
    # Nothing below needs it: keep it out of every later child's environment.
    unset SMTP_PASSWORD
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
          # The test unit has done its job; do not leave it listed as failed.
          systemctl reset-failed "$unit.service" || true
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
  # exits 0 inside the grace after boot, while log shipping and the first
  # backup are still catching up. Tunables arrive as environment variables so the
  # unit file shows exactly what is being enforced.
  freshness = pkgs.writeShellApplication {
    name = "stackbase-freshness";
    runtimeInputs = [ pkgs.coreutils ];
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
        # turned on (enabled-at, created once by tmpfiles). Fail closed: if
        # neither exists, enabled-at is created now, so the clock starts
        # here and a node that never backs up is reported 36 h later --
        # never silent forever.
        if [ -r /var/lib/stackbase-backup/last-success ]; then
          last=$(cat /var/lib/stackbase-backup/last-success)
          what="the newest successful backup"
        else
          if [ ! -e /var/lib/stackbase-backup/enabled-at ]; then
            mkdir -p /var/lib/stackbase-backup
            touch /var/lib/stackbase-backup/enabled-at
            echo "no backup stamp yet: counting from now ($(date -u -Is))"
          fi
          last=$(stat -c %Y /var/lib/stackbase-backup/enabled-at)
          what="no backup has succeeded yet; backups were turned on"
        fi
        if [[ ! "$last" =~ ^[0-9]+$ ]]; then last=0; fi
        if (( now - last > BACKUP_MAX_AGE_SECONDS )); then
          problems+=("backups: $what at $(date -u -d "@$last" -Is), more than $(( BACKUP_MAX_AGE_SECONDS / 3600 )) h ago -- see journalctl -u stackbase-backup")
        fi
      fi

      if [ "$CHECK_LOGS" = 1 ]; then
        # The same clock as backups, from the shipper's own stamp:
        # stackbase-logs.service writes last-success at the end of every run
        # that exits 0, so it ages only while runs fail (or never start).
        # Before the first success the age counts from enabled-at (tmpfiles,
        # nixos/logs.nix), and fails closed the same way: no stamp at all
        # starts the clock now. The directory is the unit's 0700
        # StateDirectory, owned by its user -- this watchdog reads it as root.
        logs=/var/lib/stackbase-logs
        if [ -r "$logs/last-success" ]; then
          last=$(cat "$logs/last-success")
          if [[ ! "$last" =~ ^[0-9]+$ ]]; then last=0; fi
          what="no log upload has succeeded since $(date -u -d "@$last" -Is)"
        else
          if [ ! -e "$logs/enabled-at" ]; then
            install -d -m 0700 -o stackbase-logs -g stackbase-logs "$logs"
            install -m 0600 -o stackbase-logs -g stackbase-logs /dev/null "$logs/enabled-at"
            echo "no log upload stamp yet: counting from now ($(date -u -Is))"
          fi
          last=$(stat -c %Y "$logs/enabled-at")
          what="no log upload has succeeded yet; log shipping was turned on at $(date -u -d "@$last" -Is)"
        fi
        if (( now - last > LOGS_MAX_AGE_SECONDS )); then
          problems+=("logs: $what, more than $(( LOGS_MAX_AGE_SECONDS / 60 )) min ago -- see journalctl -u stackbase-logs")
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
  imports = [
    (lib.mkRemovedOptionModule [ "stackbase" "alerts" "bufferAlertBytes" ]
      "Vector was replaced by the stackbase-logs timer in v0.3.0; the watchdog now checks the shipper's last-success stamp (stackbase.alerts.logsMaxAgeSeconds). See README Logs.")
  ];

  options.stackbase.alerts = {
    to = lib.mkOption {
      # One address each, the same shape as smtp_from: these land in a To:
      # header, where a newline would inject another header.
      type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+");
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

    logsMaxAgeSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 900;
      description = ''
        The watchdog fails when the log shipper has not completed a run for
        longer than this (15 min: fifteen missed one-minute runs, so a
        brief R2 outage or a slow catch-up is not mailed).
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
      # Never start-limited: a unit failing many times in a few seconds
      # would otherwise trip systemd's default limit (5 starts in 10 s) on
      # its handler, and the next failure -- possibly a different one, after
      # the stamp expired -- would go unmailed with 'start-limit-hit'. The
      # handler limits itself (one mail per unit per intervalHours) and
      # exits at once when it has nothing to send.
      startLimitIntervalSec = 0;
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
        LOGS_MAX_AGE_SECONDS = toString cfg.logsMaxAgeSeconds;
        # Only what this node has: backups opted out, or logs off, are not
        # checked at all.
        CHECK_BACKUPS = if config.stackbase.backups.enable or false then "1" else "0";
        CHECK_LOGS = if config.stackbase.logs.enable or false then "1" else "0";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${freshness}/bin/stackbase-freshness";
      };
    };

    systemd.timers.stackbase-freshness = {
      wantedBy = [ "timers.target" ];
      timerConfig.OnCalendar = "hourly";
    };

    environment.systemPackages = [ alertTest ];
  };
}
