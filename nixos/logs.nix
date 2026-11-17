# Logs off-box: the node's journal shipped to an S3-compatible bucket
# (Cloudflare R2) by nixos/log-shipper.py, a stdlib Python script run by a
# systemd timer every `intervalSeconds` (60 s).
#
#   stackbase-logs.timer -> stackbase-logs.service (oneshot)
#     journalctl -o json after the saved cursor -> nine fields per entry
#     -> one gzipped NDJSON object per event-hour -> rclone rcat
#     -> rclone cat + sha256 compare -> only then the cursor moves
#
# Objects land under `journal/<host>/%Y/%m/%d/%H/`, with the same fields
# Vector wrote, so older archives and the README's search commands keep
# working. Delivery is at-least-once: every line keeps its journal `cursor`
# so duplicates can be removed.
#
# What survives losing the server is what reached the bucket, so the timer
# interval is the loss window. Nothing else is lost to an R2 outage shorter
# than the local journal's 7 days (base.nix) -- provided the journal does
# not hit its SystemMaxUse=2G / SystemKeepFree=4G caps first: journald then
# drops its oldest files, shipped or not. The script detects a cursor that
# was rotated away and fails loudly rather than skipping silently.
#
# Why not Vector (what this module ran until v0.3.0): from 0.46 its S3 sink
# sends two checksums and R2 rejects every upload
# (https://github.com/vectordotdev/vector/issues/23029), while its
# healthcheck still passes -- 0.55 failed exactly like that on a live host.
# The VM test used MinIO, which cannot catch it. The script reads every
# object back before it moves the cursor, so a silently rejected upload can
# never be mistaken for a shipped one.
#
# Credentials come from /var/lib/stackbase/logs.env (written by
# `./infra/up`'s ENSURE_LOGS_ENV step from the environment's logs_* secrets
# and r2_endpoint) through systemd's EnvironmentFile, read by PID 1 before
# the unit drops to its user. rclone is configured purely from the
# environment (remote `logs`, RCLONE_CONFIG_LOGS_*): the key pair through
# its AWS env-auth, the endpoint exported by the small wrapper below --
# systemd does not expand variables inside Environment=. No key value ever
# enters the Nix store, which is world-readable.
#
# Retention is NOT here: the bucket's lifecycle rule (stackbase/r2.py)
# expires `journal/`. The node never deletes a log object.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase.logs;

  logsEnvFile = "/var/lib/stackbase/logs.env";
  stateDir = "/var/lib/stackbase-logs";
  unitName = "stackbase-logs";
  interval = "${toString cfg.intervalSeconds}s";

  removedMessage = "Vector was replaced by the stackbase-logs timer in v0.3.0; see README Logs.";

  # Exports the one rclone setting that has to come from logs.env, then
  # runs its arguments. Fails (and so the unit fails and alerts) when
  # logs.env lacks the endpoint, instead of rclone guessing AWS.
  withEndpoint = pkgs.writeShellApplication {
    name = "stackbase-logs-with-endpoint";
    text = ''
      : "''${LOGS_ENDPOINT:?LOGS_ENDPOINT is not set -- see ${logsEnvFile}}"
      export RCLONE_CONFIG_LOGS_ENDPOINT="$LOGS_ENDPOINT"
      exec "$@"
    '';
  };
in
{
  imports = [
    (lib.mkRemovedOptionModule [ "stackbase" "logs" "bufferBytes" ] removedMessage)
    (lib.mkRemovedOptionModule [ "stackbase" "logs" "batchSeconds" ] removedMessage)
    (lib.mkRemovedOptionModule [ "stackbase" "logs" "localDays" ] removedMessage)
  ];

  options.stackbase.logs = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = cfg.bucket != "";
      defaultText = lib.literalExpression ''config.stackbase.logs.bucket != ""'';
      description = ''
        Whether to ship the journal to R2. Defaults to "a bucket is
        configured", so a project turns logs on by naming a bucket in
        stack.toml's [logs] table, and `enabled = false` there turns them off.
      '';
    };

    bucket = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = ''
        The R2 bucket objects are written to, under
        `journal/<host>/%Y/%m/%d/%H/`. Its retention is the bucket's
        lifecycle rule, which `./infra/up` manages -- not a node option.
      '';
    };

    intervalSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = ''
        Seconds between the end of one shipper run and the start of the
        next (and after boot before the first) -- and so roughly the most a
        destroyed server can lose.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.bucket != "";
        message = "stackbase.logs.enable is on but stackbase.logs.bucket is empty -- set a bucket in stack.toml's [logs] table";
      }
    ];

    # A static user rather than DynamicUser: /var/lib/stackbase-logs must be
    # a real directory with a stable owner, which other units (the alert
    # watchdog reads `last-success`) can rely on between runs. logs.env stays
    # root:root 0600: systemd reads an EnvironmentFile as PID 1, before
    # dropping to this user, so the script never opens it itself.
    users.users.${unitName} = {
      isSystemUser = true;
      group = unitName;
    };
    users.groups.${unitName} = { };

    systemd.services.${unitName} = {
      description = "Ship the journal to R2";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = [ pkgs.systemd pkgs.rclone ];
      environment = {
        LOGS_BUCKET = cfg.bucket;
        LOGS_STATE = stateDir;
        LOGS_EXCLUDE_UNIT = "${unitName}.service";
        RCLONE_CONFIG = "/dev/null";
        RCLONE_CONFIG_LOGS_TYPE = "s3";
        RCLONE_CONFIG_LOGS_PROVIDER = "Cloudflare";
        RCLONE_CONFIG_LOGS_ENV_AUTH = "true";
        RCLONE_CONFIG_LOGS_REGION = "auto";
        RCLONE_CONFIG_LOGS_NO_CHECK_BUCKET = "true";
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${withEndpoint}/bin/stackbase-logs-with-endpoint ${pkgs.python3}/bin/python3 ${./log-shipper.py}";
        # Required, not "-": the ENSURE_LOGS_ENV step pushes it before the
        # rebuild that installs this unit.
        EnvironmentFile = logsEnvFile;
        User = unitName;
        Group = unitName;
        SupplementaryGroups = [ "systemd-journal" ];
        StateDirectory = unitName;
        StateDirectoryMode = "0700";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        # The script's 240 s run budget is checked only between objects, so
        # one 64 MiB upload plus read-back can run past it.
        TimeoutStartSec = 600;
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };

    # enabled-at: when shipping was turned on, which the alert watchdog
    # (nixos/alerts.nix) counts from until the first `last-success`.
    # Created once, never touched again. The directory line repeats the
    # unit's StateDirectory owner and mode exactly, so tmpfiles and systemd
    # never correct each other.
    systemd.tmpfiles.rules = [
      "d ${stateDir} 0700 ${unitName} ${unitName} -"
      "f ${stateDir}/enabled-at 0600 ${unitName} ${unitName} -"
    ];

    systemd.timers.${unitName} = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = interval;
        OnUnitInactiveSec = interval;
        AccuracySec = "5s";
      };
    };
  };
}
