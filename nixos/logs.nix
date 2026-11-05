# Logs off-box: the node's journal streamed to an S3-compatible bucket
# (Cloudflare R2) by Vector, plus a short plain-text local copy.
#
#   journald -> remap (nine fields) -> aws_s3  (disk buffer, end-to-end acks)
#                                   -> file    /var/log/vector, 3 days
#
# What survives losing the server is what reached the bucket, so the R2
# sink's batch timeout (`batchSeconds`, 15 s) is the loss window. Nothing
# else is lost to an R2 outage shorter than the local journal's 7 days
# (base.nix) -- provided the journal does not hit its SystemMaxUse=2G /
# SystemKeepFree=4G caps first, which a very chatty node can: journald then
# drops its oldest files, even ones Vector has not read yet. Vector's
# journald checkpoint only moves once an event is in the disk buffer, and
# the buffer blocks (rather than drops) when full, so the journal itself is
# the overflow. One more small window: the disk buffer acknowledges on
# write, not fsync, and journald syncs every 5 s, so a power cut can take
# the last few seconds. Delivery is at-least-once -- every event keeps its
# journal `cursor` so duplicates can be removed.
#
# After a restart Vector may log one "Invalid record from journald ...
# text=-- cursor: s=..." error. It is benign: that is journalctl's own
# --show-cursor trailer line, which Vector reads but is not an entry.
#
# Credentials come from /var/lib/stackbase/logs.env (written by
# `./infra/up`'s ENSURE_LOGS_ENV step from the environment's logs_* secrets
# and r2_endpoint) through systemd's EnvironmentFile. The config only says
# `${LOGS_ENDPOINT}`, which Vector interpolates at start-up, and the key
# pair is picked up by Vector's AWS credential chain -- no key value ever
# enters the Nix store, which is world-readable.
#
# Retention is NOT here: the bucket's lifecycle rule (stackbase/r2.py)
# expires `journal/`. The node never deletes a log object.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase.logs;

  logsEnvFile = "/var/lib/stackbase/logs.env";
  localDir = "/var/log/vector";
  dataDir = "/var/lib/vector";

  settings = {
    data_dir = dataDir;

    # Local only: `vector top` and `vector tap` talk to it.
    api = {
      enabled = true;
      address = "127.0.0.1:8686";
    };

    sources.journal = {
      type = "journald";
      # The whole persistent journal, from wherever the checkpoint in
      # data_dir says shipping stopped -- a reboot or a long outage must
      # not skip anything still on disk.
      current_boot_only = false;
      since_now = false;
      # Vector's own complaints about an unreachable bucket would otherwise
      # be shipped to that same bucket, feeding themselves.
      exclude_units = [ "vector.service" ];
      # Vector 0.55 drops __CURSOR unless asked; the remap below keeps it
      # so at-least-once duplicates can be removed downstream.
      emit_cursor = true;
    };

    sources.vector_metrics.type = "internal_metrics";

    # Keep only what a person searching logs needs. Everything else
    # journald attaches (_CMDLINE, _EXE, _CAP_EFFECTIVE, ...) stays on the
    # node. `compact` drops the fields a given entry does not have.
    transforms.slim = {
      type = "remap";
      inputs = [ "journal" ];
      source = ''
        . = compact({
          "timestamp": .timestamp,
          "host": .host,
          "unit": ._SYSTEMD_UNIT,
          "ident": .SYSLOG_IDENTIFIER,
          "pid": ._PID,
          "priority": .PRIORITY,
          "message": .message,
          "boot_id": ._BOOT_ID,
          "cursor": .__CURSOR
        })
      '';
    };

    sinks.r2 = {
      type = "aws_s3";
      inputs = [ "slim" ];
      inherit (cfg) bucket;
      region = "auto";
      endpoint = "\${LOGS_ENDPOINT}";
      force_path_style = true;
      key_prefix = "journal/{{ host }}/%Y/%m/%d/%H/";
      filename_append_uuid = true;
      filename_extension = "ndjson.gz";
      compression = "gzip";
      encoding.codec = "json";
      framing.method = "newline_delimited";
      # One object per batch, not multipart: parts stay invisible until the
      # upload completes and must each be >= 5 MiB, so a server lost
      # mid-upload would lose all of it. ~170k PUTs per server per month.
      batch = {
        timeout_secs = cfg.batchSeconds;
        max_bytes = 67108864;
      };
      buffer = {
        type = "disk";
        max_size = cfg.bufferBytes;
        when_full = "block";
      };
      acknowledgements.enabled = true;
      request.concurrency = "adaptive";
      healthcheck.enabled = true;
      # Deliberately no storage_class, ACL or server-side encryption
      # option: R2 rejects or ignores them, and the bucket decides.
    };

    # Best effort by design: a small memory buffer that drops when full, so
    # a full local disk (or a slow one) can never back-pressure the R2 sink.
    sinks.local = {
      type = "file";
      inputs = [ "slim" ];
      path = "${localDir}/%Y-%m-%d/%H.ndjson";
      encoding.codec = "json";
      framing.method = "newline_delimited";
      buffer = {
        type = "memory";
        max_events = 10000;
        when_full = "drop_newest";
      };
    };

    sinks.metrics = {
      type = "prometheus_exporter";
      inputs = [ "vector_metrics" ];
      address = "127.0.0.1:9598";
    };
  };

  # The nixpkgs module's own build-time `vector validate` cannot see
  # ${LOGS_ENDPOINT} and fails on it, so it is turned off and replaced by
  # this one, which supplies a dummy endpoint. It validates the MERGED
  # services.vector.settings -- the exact file the unit runs, including
  # anything infra/conf.d added -- so a typo in any option name still fails
  # the build, never the server.
  configFile = (pkgs.formats.toml { }).generate "vector.toml" config.services.vector.settings;
  validated = pkgs.runCommand "stackbase-vector-validate" { nativeBuildInputs = [ config.services.vector.package ]; } ''
    LOGS_ENDPOINT=https://validate.invalid vector validate --no-environment ${configFile}
    touch "$out"
  '';
in
{
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

    bufferBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1073741824;
      description = ''
        Size of Vector's on-disk buffer for the R2 sink. When it is full the
        sink blocks and the journal holds the rest, so this bounds disk use,
        not what an outage can lose. Vector refuses less than 256 MiB.
      '';
    };

    batchSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 15;
      description = ''
        Longest an event waits before its batch is uploaded -- and so the
        most a destroyed server can lose.
      '';
    };

    localDays = lib.mkOption {
      type = lib.types.ints.positive;
      default = 3;
      description = ''
        Days the plain-text local copy under ${localDir} is kept
        (systemd-tmpfiles ages it out).
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

    services.vector = {
      enable = true;
      journaldAccess = true;
      validateConfig = false;
      inherit settings;
    };

    system.checks = [ validated ];

    # Searching the plain-text local copy is the README's first suggestion
    # (`rg ... /var/log/vector`); the vector CLI itself (validate, top, tap)
    # comes with services.vector.
    environment.systemPackages = [ pkgs.ripgrep ];

    # A static user rather than the module's DynamicUser: the local copy's
    # directory is created and aged out by systemd-tmpfiles, which runs
    # before Vector does and must name an owner that exists at boot -- a
    # dynamic user only exists while its unit is running. logs.env stays
    # root:root 0600 all the same: systemd reads an EnvironmentFile as
    # PID 1, before dropping to this user, so Vector never opens it itself.
    users.users.vector = {
      isSystemUser = true;
      group = "vector";
    };
    users.groups.vector = { };

    systemd.tmpfiles.rules = [
      "d ${localDir} 0750 vector vector ${toString cfg.localDays}d"
    ];

    systemd.services.vector = {
      # The credentials file arrives before the rebuild that first starts
      # Vector (see the ENSURE_LOGS_ENV step), so it is required, not "-":
      # without it ${LOGS_ENDPOINT} is unset and Vector would not start.
      serviceConfig = {
        EnvironmentFile = logsEnvFile;
        DynamicUser = lib.mkForce false;
        User = "vector";
        Group = "vector";
        # What DynamicUser implied, kept: read-only system, with only the
        # buffer/checkpoint directory (StateDirectory) and the local copy
        # writable.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        # LogsDirectory as well as the tmpfiles rule: tmpfiles runs at boot,
        # but the first switch that turns logs on starts Vector straight
        # away, and a ReadWritePaths entry that does not exist yet fails the
        # unit. systemd creates (and chowns) this one before every start.
        LogsDirectory = "vector";
        LogsDirectoryMode = "0750";
        ReadWritePaths = [ localDir ];
      };
    };
  };
}
