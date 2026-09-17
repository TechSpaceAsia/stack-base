# Blue/green release engine for a stackbase node: a `deploy` system user
# (privileged only through narrow, exact-command sudo rules and, from
# Task 2 on, an SSH forced command), the app.sock ownership model, the
# `<project>@.service` template unit (one instance per color), the
# boot-time recovery unit, and the drain-stop timer pair.
#
# Reads `stackbase.project` from base.nix. Declares `stackbase.app.*` and
# `stackbase.deploy.*`. app-host.nix's nginx already proxies to
# `unix:/run/<project>/app.sock` -- this module is what turns that path
# into a symlink stack-deploy flips atomically between app-blue.sock and
# app-green.sock.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase;

  stackDeployPkg = pkgs.writeShellApplication {
    name = "stack-deploy";
    runtimeInputs = with pkgs; [
      coreutils
      util-linux
      curl
      systemd
      gnutar
      gzip
      findutils
      gnugrep
      gnused
    ];
    text = builtins.readFile ./deploy/stack-deploy.sh;
  };

  systemctlBin = "${pkgs.systemd}/bin/systemctl";

  # Exact-command NOPASSWD sudo rules for the `deploy` user's local
  # systemctl calls (distinct from the Task 2 SSH forced-command surface,
  # which only ever proxies to this same binary). Every entry names one
  # concrete unit -- no globs -- so `deploy` can never touch a unit other
  # than its own two app colors and its own two drain timers. start is
  # granted alongside restart/stop on the app units to match the
  # start|stop|restart surface Task 2's forced-command dispatcher exposes,
  # even though stack-deploy itself only ever calls restart (idempotent
  # whether the unit was already running or not).
  deploySudoCommands = lib.concatMap
    (color: [
      { command = "${systemctlBin} start ${cfg.project}@${color}.service"; options = [ "NOPASSWD" ]; }
      { command = "${systemctlBin} restart ${cfg.project}@${color}.service"; options = [ "NOPASSWD" ]; }
      { command = "${systemctlBin} stop ${cfg.project}@${color}.service"; options = [ "NOPASSWD" ]; }
      { command = "${systemctlBin} restart stackbase-drain@${color}.timer"; options = [ "NOPASSWD" ]; }
    ])
    [ "blue" "green" ];
in
{
  options.stackbase = {
    app.binary = lib.mkOption {
      type = lib.types.str;
      default = lib.replaceStrings [ "-" ] [ "_" ] cfg.project;
      defaultText = lib.literalExpression ''lib.replaceStrings [ "-" ] [ "_" ] config.stackbase.project'';
      description = ''
        Executable name inside a release directory
        (`/opt/<project>/<color>/current/<binary>`). Defaults to the
        project slug with `-` replaced by `_`, matching a typical Rust
        crate/binary name derived from a hyphenated project slug.
      '';
    };

    app.healthPath = lib.mkOption {
      type = lib.types.str;
      default = "/health";
      description = ''
        HTTP path stack-deploy GETs over the idle color's unix socket to
        decide whether a swap is safe. Only a 2xx response counts.
      '';
    };

    deploy.drainSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = ''
        Seconds to keep the outgoing color running (draining in-flight
        connections) after a successful swap before stopping it. Baked
        into the `stackbase-drain@.timer`'s `OnActiveSec` at eval time --
        changing it requires a rebuild, not just a restart.
      '';
    };

    deploy.keep = lib.mkOption {
      type = lib.types.ints.positive;
      default = 5;
      description = ''
        Default number of releases `stack-deploy prune` keeps, highest by
        SemVer, plus any release either color currently links to.
      '';
    };

    deploy.keys = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = ''
        Name -> SSH public key for accounts allowed to drive stack-deploy
        over the `deploy` user's forced-command SSH channel. Declared here
        so Task 1 (this module) and Task 2 (the forced-command dispatcher
        and sshd wiring) can be developed independently; unused by Task 1
        itself.
      '';
    };
  };

  config = {
    # Two distinct trust boundaries, two distinct groups -- do not merge
    # them. `<project>` is the app's own group; a later task drops
    # /var/lib/stackbase/app.env as `root:<project> 0640` (the app's own
    # secrets). `<project>-sock` exists purely so `deploy` and `nginx` can
    # reach /run/<project> and the app.sock socket file without also
    # getting read access to that secrets file -- `deploy` must never be
    # a member of `<project>` itself.
    users.groups.${cfg.project} = { };
    users.groups."${cfg.project}-sock" = { };
    users.users.${cfg.project} = {
      isSystemUser = true;
      group = cfg.project;
      extraGroups = [ "${cfg.project}-sock" ];
      home = "/var/empty";
      createHome = false;
      description = "stackbase app runtime user for ${cfg.project}";
    };

    users.groups.deploy = { };
    users.users.deploy = {
      isSystemUser = true;
      group = "deploy";
      # `<project>-sock`, not `<project>`: deploy only ever needs to
      # replace the app.sock symlink inside /run/<project>, never to read
      # the app's own secrets (app.env). Ownership of
      # /opt/<project>/{releases,blue,green} is deploy:deploy directly
      # (see C2 below), so no group membership is needed there either.
      extraGroups = [ "${cfg.project}-sock" ];
      home = "/var/lib/stackbase";
      createHome = false;
      description = "stackbase release engine (blue/green deploys)";
      # Minimal for Task 1: no authorized keys yet. Task 2 adds the
      # forced-command authorized_keys from stackbase.deploy.keys and adds
      # "deploy" to base.nix's sshd AllowUsers.
    };

    # nginx (app-host.nix) proxies to unix:/run/<project>/app.sock as the
    # `nginx` user. It never runs as <project>, so the only way it can
    # connect() to the app's socket is group membership: put it in
    # `<project>-sock` (not `<project>` -- see above), and rely on the app
    # process chmod'ing its socket file group-writable after bind
    # (connect() on an AF_UNIX socket needs write permission on the socket
    # special file, not just read). The fake app used by
    # tests/vm-deploy.nix does this; a real app must too.
    users.users.nginx.extraGroups = [ "${cfg.project}-sock" ];

    systemd.tmpfiles.rules = [
      "d /opt/${cfg.project} 0755 root root -"
      # Not group-writable by anyone but deploy: the app user (and nginx,
      # which shares its group for socket access) must never be able to
      # replace a release out from under itself. Modes inside a release
      # tree are normalised explicitly by stack-deploy on unpack (0755
      # dirs, 0644 files, 0755 for the declared binary), so no group
      # inheritance is needed here either -- world-readable bits already
      # give <project> everything it needs to read and run its release.
      "d /opt/${cfg.project}/releases 0755 deploy deploy -"
      "d /opt/${cfg.project}/blue 0755 deploy deploy -"
      "d /opt/${cfg.project}/green 0755 deploy deploy -"
      "d /var/lib/stackbase 0770 deploy deploy -"
      "d /var/lib/stackbase/incoming 0770 deploy deploy -"
      # /run is tmpfs, wiped every boot. Deliberately NOT RuntimeDirectory=
      # on the app template unit below: systemd's own RuntimeDirectory
      # bookkeeping removes the directory when a unit requesting it stops,
      # even while a *different* instance of the same template is still
      # using it (each blue/green instance would independently claim and
      # release the shared path) -- exactly the trap that would delete
      # /run/<project> out from under the still-running color during a
      # drain-stop. tmpfiles owns the directory unconditionally instead,
      # and stackbase-app-boot.service (below) recreates app.sock after
      # every boot since the symlink itself doesn't survive in tmpfs.
      # Owner <project>, group <project>-sock, setgid: a socket file the
      # app creates here inherits the *directory's* group
      # (<project>-sock) rather than the app's own primary group
      # (<project>), which is what lets nginx (a <project>-sock member)
      # reach it via the socket's own 0660/0666 mode.
      "d /run/${cfg.project} 2770 ${cfg.project} ${cfg.project}-sock -"
    ];

    systemd.services."${cfg.project}@" = {
      description = "stackbase app instance (%i)";
      after = [ "network.target" ];
      # Deliberately NOT wantedBy multi-user.target: stackbase-app-boot.service
      # decides which color (if any) to start at boot, and stack-deploy
      # starts/stops instances directly during a deploy.
      serviceConfig = {
        Type = "simple";
        User = cfg.project;
        Group = cfg.project;
        WorkingDirectory = "/opt/${cfg.project}/%i/current";
        ExecStart = "/opt/${cfg.project}/%i/current/${cfg.app.binary}";
        EnvironmentFile = "-/var/lib/stackbase/app.env";
        # A real Rust release binary needs neither PATH nor a shebang
        # lookup, but a script-based release (e.g. the fake app used by
        # tests/vm-deploy.nix, or any interpreter-based project) relies on
        # `/usr/bin/env` resolving its interpreter -- systemd units don't
        # inherit the interactive shell's PATH, only the manager's own
        # DefaultEnvironment, which doesn't reach into the Nix profile.
        Environment = [
          "SOCKET_PATH=/run/${cfg.project}/app-%i.sock"
          "PATH=/run/current-system/sw/bin:/usr/bin:/bin"
        ];
        Restart = "on-failure";
        RestartSec = 2;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        RestrictSUIDSGID = true;
        # The release tree under /opt is intentionally read-only to the
        # app (it only ever reads its own binary/static assets); the only
        # writable path it needs is its own socket directory.
        ReadWritePaths = [ "/run/${cfg.project}" ];
      };
    };

    systemd.services.stackbase-app-boot = {
      description = "Start the active-color app instance at boot and restore app.sock (/run is volatile)";
      after = [ "systemd-tmpfiles-setup.service" ];
      before = [ "nginx.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${stackDeployPkg}/bin/stack-deploy boot";
      };
    };

    # Drain-stop template: `deploy` (or stack-deploy running as root)
    # (re)arms `stackbase-drain@<color>.timer` after a successful swap;
    # drainSeconds later it fires the paired oneshot service below, which
    # re-validates against the current state file before stopping
    # anything -- see stack-deploy.sh's internal-drain-stop for the race
    # this guards against (a newer deploy reusing or re-activating the
    # same color before the old timer fires).
    systemd.services."stackbase-drain@" = {
      description = "Drain-stop the idle color %i, if it is still idle and this schedule hasn't been superseded";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${stackDeployPkg}/bin/stack-deploy internal-drain-stop %i";
      };
    };

    systemd.timers."stackbase-drain@" = {
      description = "Fires stackbase-drain@%i.service drainSeconds after being (re)armed";
      timerConfig = {
        OnActiveSec = cfg.deploy.drainSeconds;
        AccuracySec = "1s";
      };
    };

    security.sudo.extraRules = [
      {
        users = [ "deploy" ];
        commands = deploySudoCommands;
      }
    ];

    environment.etc."stackbase/deploy.env".text = ''
      STACK_PROJECT=${cfg.project}
      STACK_BINARY=${cfg.app.binary}
      STACK_HEALTH_PATH=${cfg.app.healthPath}
      STACK_DRAIN_SECONDS=${toString cfg.deploy.drainSeconds}
      STACK_KEEP=${toString cfg.deploy.keep}
    '';

    environment.systemPackages = [ stackDeployPkg ];
  };
}
