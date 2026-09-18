# Off-box, age-encrypted backups for a stackbase node: the project's
# Postgres database plus any extra directories, streamed straight to an
# S3-compatible bucket (Cloudflare R2 by default).
#
# Modelled on hanskraft's own pg-backup/backup-uploads units
# (nixos/service.nix there), made generic and made to stream: nothing is
# ever written to a temp file, so a dump's plaintext never touches the
# node's disk at all.
#
#   pg_dump | zstd | age -R <recipients> | rclone rcat backup:<bucket>/db/...
#   tar     | zstd | age -R <recipients> | rclone rcat backup:<bucket>/files/...
#
# Reads `stackbase.project` from base.nix. Credentials come from
# /var/lib/stackbase/backup.env (0600 root:root), written by `./infra/up`
# from secrets.age's r2_* keys -- never from the Nix store, which is
# world-readable. Recipients come from the project's own
# infra/age-recipients.txt as pushed to /etc/nixos/stack/, so restoring a
# backup needs an age identity that never existed on the server.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase;
  backups = cfg.backups;

  backupEnvFile = "/var/lib/stackbase/backup.env";

  backupScript = pkgs.writeShellApplication {
    name = "stackbase-backup";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnutar
      pkgs.zstd
      pkgs.age
      # Two of the three recipients on a typical project are YubiKey
      # identities (age1yubikey1...); plain age shells out to this plugin
      # for those lines, so it has to be on PATH even to ENCRYPT.
      pkgs.age-plugin-yubikey
      pkgs.rclone
      pkgs.util-linux
      config.services.postgresql.package
    ];
    text = ''
      if [ -z "''${RCLONE_CONFIG_BACKUP_TYPE:-}" ]; then
        echo "stackbase-backup: no credentials in ${backupEnvFile} -- add r2_access_key_id, r2_secret_access_key and r2_endpoint to infra/secrets.age and run ./infra/up" >&2
        exit 1
      fi

      BUCKET=${lib.escapeShellArg backups.bucket}
      RECIPIENTS=${lib.escapeShellArg backups.recipientsFile}
      STAMP=$(date -u +%Y%m%dT%H%M%SZ)

      # Belt and braces for the one thing in here that DELETES: an empty
      # bucket would make every `backup:$BUCKET/<prefix>/` path below
      # collapse to the remote's root. The module's own assertion already
      # refuses to build in that case, so this can only fire if some future
      # edit removes it -- which is exactly when a deletion aimed at a
      # whole remote would be worst.
      if [ -z "$BUCKET" ]; then
        echo "stackbase-backup: no bucket configured -- refusing to run" >&2
        exit 1
      fi

      if [ ! -r "$RECIPIENTS" ]; then
        echo "stackbase-backup: no age recipients file at $RECIPIENTS -- refusing to write a backup nobody could decrypt" >&2
        exit 1
      fi

      prune_prefix() {
        # `$1` is one of this script's own two literal prefixes ("db",
        # "files") -- never anything from stack.toml, and never a bare
        # "$BUCKET/". `--min-age <retentionDays>d` comes from an
        # `ints.positive` option, so it can never be 0 ("everything,
        # including what was just written").
        local prefix="$1"
        # `rclone delete` on a prefix that does not exist yet is an error,
        # and a first-ever run legitimately has no files/ prefix.
        if rclone lsf "backup:$BUCKET/$prefix/" >/dev/null 2>&1; then
          rclone delete --min-age ${toString backups.retentionDays}d "backup:$BUCKET/$prefix/"
        fi
      }

      echo "→ ${cfg.project} database → backup:$BUCKET/db/${cfg.project}_$STAMP.sql.zst.age"
      runuser -u postgres -- pg_dump ${lib.escapeShellArg cfg.project} \
        | zstd -3 -q \
        | age -R "$RECIPIENTS" \
        | rclone rcat "backup:$BUCKET/db/${cfg.project}_$STAMP.sql.zst.age"

      # An ARRAY, not a bare word list: `extraPaths` defaults to [ ], and a
      # literal `for path in ; do` would not even parse.
      extra_paths=(${lib.escapeShellArgs backups.extraPaths})
      for path in ''${extra_paths[@]+"''${extra_paths[@]}"}; do
        if [ ! -d "$path" ]; then
          echo "i no directory at $path -- skipping"
          continue
        fi
        base=$(basename "$path")
        echo "→ $path → backup:$BUCKET/files/''${base}_$STAMP.tar.zst.age"
        tar -C "$path" -cf - . \
          | zstd -3 -q \
          | age -R "$RECIPIENTS" \
          | rclone rcat "backup:$BUCKET/files/''${base}_$STAMP.tar.zst.age"
      done

      echo "→ pruning anything older than ${toString backups.retentionDays} days"
      prune_prefix db
      prune_prefix files
      echo "✓ backup complete"
    '';
  };

  # Listing the bucket needs the same credentials the unit gets from its
  # EnvironmentFile -- `./infra/up backup-now` runs this as root right
  # after the unit, so an operator sees what actually landed.
  #
  # The credentials are READ, never SOURCED. `source`/`.` is full shell
  # evaluation of every line, so a value containing `$(...)`, a backtick or
  # a `;` would EXECUTE as root -- and unlike the unit above, which gets the
  # same file through systemd's `EnvironmentFile` (a parser that does no
  # substitution at all), this is a shell. `read -r` plus
  # `export "name=value"` sets each variable from data without ever
  # re-evaluating it. stackbase/backups.py also refuses to WRITE a value
  # containing anything a shell would reinterpret; this is the second of
  # those two layers, so neither one alone is what holds the line.
  backupLsScript = pkgs.writeShellApplication {
    name = "stackbase-backup-ls";
    runtimeInputs = [ pkgs.coreutils pkgs.rclone ];
    text = ''
      if [ ! -r ${backupEnvFile} ]; then
        echo "stackbase-backup-ls: no credentials in ${backupEnvFile}" >&2
        exit 1
      fi

      # Split on the FIRST '=' with parameter expansion, NOT with
      # `IFS='=' read -r name value`: that form silently drops a TRAILING
      # '=', and an AWS-style base64 secret routinely ends in one (verified
      # -- the secret came back one character short). `IFS=` on the read
      # keeps leading/trailing whitespace out of the value's way too.
      while IFS= read -r line || [ -n "$line" ]; do
        name=''${line%%=*}
        value=''${line#*=}
        case "$name" in
          # Only this file's own rclone settings are ever exported: a stray
          # line could not set PATH, LD_PRELOAD or anything else that would
          # change what runs below.
          RCLONE_CONFIG_BACKUP_*) export "''${name}=''${value}" ;;
          *) ;;
        esac
      done < ${backupEnvFile}

      if [ -z "''${RCLONE_CONFIG_BACKUP_TYPE:-}" ]; then
        echo "stackbase-backup-ls: ${backupEnvFile} has no rclone settings in it" >&2
        exit 1
      fi

      rclone lsl ${lib.escapeShellArg "backup:${backups.bucket}"}
    '';
  };
in
{
  options.stackbase.backups = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = backups.bucket != "";
      defaultText = lib.literalExpression ''config.stackbase.backups.bucket != ""'';
      description = ''
        Whether to run nightly off-box backups. Defaults to "a bucket is
        configured", so a project turns backups on by naming a bucket in
        stack.toml's [backups] table and nothing else.
      '';
    };

    bucket = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = ''
        The destination bucket, used as `backup:<bucket>/...` against an
        rclone remote called "backup" that is configured entirely from
        environment variables in ${backupEnvFile}. With
        `RCLONE_CONFIG_BACKUP_TYPE=local` this is a directory path instead,
        which is how the VM test exercises the whole pipeline.
      '';
    };

    retentionDays = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = ''
        Objects older than this are deleted from both the `db/` and
        `files/` prefixes at the end of every run. `ints.positive`, not
        `ints.unsigned`: 0 would mean "delete everything, including the
        backup this run just wrote".
      '';
    };

    extraPaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/var/lib/acme/uploads" ];
      description = ''
        Directories to archive alongside the database, each as
        `files/<basename>_<stamp>.tar.zst.age`. A path that does not exist
        is skipped with a note, not an error -- a fresh node legitimately
        has no uploads directory yet.
      '';
    };

    recipientsFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/nixos/stack/age-recipients.txt";
      description = ''
        The age recipients every backup is encrypted to, as a path ON THE
        NODE -- deliberately a runtime path and not a store path, so the
        project's own infra/age-recipients.txt (pushed to /etc/nixos/stack
        by PUSH_CONFIG) is what governs who can restore. No private key
        that can decrypt a backup ever exists on the server.
      '';
    };

    onCalendar = lib.mkOption {
      type = lib.types.str;
      default = "03:00";
      description = ''
        24-hour UTC time of the nightly run, expanded into the timer's
        `OnCalendar` as `*-*-* <value>:00`. The timer is `Persistent`, so a
        node that was off at that time backs up shortly after it boots.
      '';
    };
  };

  config = lib.mkIf backups.enable {
    assertions = [
      {
        assertion = backups.bucket != "";
        message = "stackbase.backups.enable is on but stackbase.backups.bucket is empty -- set a bucket in stack.toml's [backups] table";
      }
    ];

    systemd.services.stackbase-backup = {
      description = "Off-box age-encrypted backup for ${cfg.project}";
      after = [ "postgresql.service" "network-online.target" ];
      wants = [ "network-online.target" ];
      requires = [ "postgresql.service" ];
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        # "-": the node is rebuilt before `up` has ever pushed credentials,
        # and a unit that refuses to even start would hide the script's own
        # much clearer message about what is missing.
        EnvironmentFile = "-${backupEnvFile}";
        ExecStart = "${backupScript}/bin/stackbase-backup";
      };
    };

    systemd.timers.stackbase-backup = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "*-*-* ${backups.onCalendar}:00";
        Persistent = true;
      };
    };

    environment.systemPackages = [ backupScript backupLsScript ];
  };
}
