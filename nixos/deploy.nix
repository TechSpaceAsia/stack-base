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

  # The engine's OWN state directory. Deliberately NOT /var/lib/stackbase
  # itself: that path is app-host.nix's exclusive domain (root:nginx,
  # holds the TLS placeholder cert and, later, app.env) -- its
  # stackbase-origin-cert-placeholder.service reruns `install -d -m 0750
  # -o root -g nginx /var/lib/stackbase` on every nginx (re)start, which
  # would clobber any ownership this module tried to assert on that same
  # path. Giving the engine its own directory sidesteps the conflict
  # entirely rather than fighting over one shared path. Single source of
  # truth for this module; stack-deploy.sh has its own matching default
  # (STACK_STATE_DIR, wired through deploy.env below) and
  # tests/vm-deploy.nix has its own `stateDir` for the same reason -- one
  # binding per file, not a cross-file constant.
  stateDir = "/var/lib/stackbase-deploy";

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

  # The forced-command dispatcher installed as every stackbase.deploy.keys
  # entry's `command=`. Its argv never contains anything but the fixed
  # store path to stack-deploy plus already-validated words -- see
  # stack-deploy-ssh.sh's own header comment for the full protocol.
  stackDeploySshPkg = pkgs.writeShellApplication {
    name = "stack-deploy-ssh";
    runtimeInputs = with pkgs; [ coreutils ];
    text = builtins.replaceStrings
      [ "@stackDeployBin@" ]
      [ "${stackDeployPkg}/bin/stack-deploy" ]
      (builtins.readFile ./deploy/stack-deploy-ssh.sh);
  };

  systemctlBin = "${pkgs.systemd}/bin/systemctl";

  # A bare "type base64 [comment]" public key, no embedded options. Any
  # stackbase.deploy.keys entry that doesn't match this is either
  # malformed or -- more dangerously -- already carries its own
  # comma-separated options (e.g. a copy-pasted
  # "no-pty,command=...  ssh-ed25519 ..." line), which would silently
  # combine with the "restrict,command=..." prefix this module prepends
  # and could widen or break the forced-command confinement in ways that
  # are easy to miss in review. Reject it outright instead (see
  # assertions below).
  deployKeyTypeRegex =
    "(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\\.com|sk-ecdsa-sha2-nistp256@openssh\\.com)[ \t]+[A-Za-z0-9+/=]+([ \t]+.*)?";
  isValidDeployKey = key:
    !(lib.hasInfix "\n" key)
    && !(lib.hasInfix "\"" key)
    && (builtins.match deployKeyTypeRegex key != null);

  # "restrict" denies PTY allocation, port/agent/X11 forwarding, and
  # ~/.ssh/rc for this key outright; "command=" then forces every session
  # on it through the dispatcher above regardless of what the client asks
  # for -- see stack-deploy-ssh.sh for how it confines the command itself.
  deployAuthorizedKeyLine = key: ''restrict,command="${stackDeploySshPkg}/bin/stack-deploy-ssh" ${key}'';

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
        over the `deploy` user's forced-command SSH channel. Each value
        must be a bare `type base64 [comment]` public key with no
        embedded options, double quotes, or newlines -- see the
        assertions this module adds. Every key here gets
        `restrict,command="<store path>/bin/stack-deploy-ssh"` prepended
        automatically; `services.openssh.settings.AllowUsers` also gains
        `"deploy"`, but only once this attrset is non-empty.
      '';
    };

    deploy.maxUploadBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 500 * 1024 * 1024; # 500 MiB
      description = ''
        Hard cap on a single `upload` over the SSH forced-command channel,
        enforced while streaming stdin to disk (never buffered in
        memory). An oversized upload is refused and nothing is left under
        the engine's state directory's `incoming/`.
      '';
    };
  };

  config = {
    assertions = lib.mapAttrsToList
      (name: key: {
        assertion = isValidDeployKey key;
        message = ''
          stackbase.deploy.keys.${name}: must be a bare "type base64 [comment]" SSH public key (e.g. "ssh-ed25519 AAAA... name") with no embedded options, double quotes, or newlines -- got: ${key}
        '';
      })
      cfg.deploy.keys;

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
      home = "${stateDir}/deploy-home";
      createHome = false; # tmpfiles owns it, below, same as every other stackbase path
      description = "stackbase release engine (blue/green deploys)";
      # A real (functional) shell, not nologin: OpenSSH's `command=`
      # mechanism execs the user's login shell with `-c <forced command>`
      # -- there is no way to run a forced command without one. This is
      # NOT a login-friendly shell in practice: every key in
      # authorizedKeys.keys below carries `restrict,command=...`, so
      # whatever the client asks for (a bare interactive session, `bash`,
      # anything), sshd always runs stack-deploy-ssh instead.
      shell = pkgs.bash;
      openssh.authorizedKeys.keys = map deployAuthorizedKeyLine (lib.attrValues cfg.deploy.keys);
    };

    # nginx (app-host.nix) proxies to unix:/run/<project>/app.sock as the
    # `nginx` user. It never runs as <project>, so the only way it can
    # connect() to the app's socket is group membership: put it in
    # `<project>-sock` (not `<project>` -- see above). Reachability itself
    # (the socket actually being group-writable) comes entirely from the
    # app unit's UMask=0007, below -- the app itself does nothing special.
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
      # The engine's own state directory (active-color, generation,
      # pending-color, deploy.lock, drain-pending-*, incoming/,
      # deploy-home/) -- NOT /var/lib/stackbase itself; see the `stateDir`
      # comment above for why. Owned outright by deploy; setgid (leading
      # "2") so a file created here by ROOT (the boot/drain-stop units,
      # both root-run) still lands group "deploy" rather than "root" --
      # combined with stack-deploy.sh's atomic_write/acquire_lock
      # explicitly chmod'ing to 0660, this is what lets `deploy` read/write
      # state a root-run unit wrote (or vice versa) regardless of which
      # identity created it first. No "other" access at all -- only
      # deploy (owner) and, via the setgid group, anything else running as
      # the "deploy" group, which today is nothing but root (which
      # bypasses DAC anyway).
      "d ${stateDir} 2750 deploy deploy -"
      "d ${stateDir}/incoming 0770 deploy deploy -"
      # deploy's $HOME. Nothing stack-deploy-ssh writes here today (it
      # streams uploads straight into incoming/ above), but sshd/the login
      # shell it execs the forced command through both expect a real,
      # deploy-owned home directory to exist.
      "d ${stateDir}/deploy-home 0700 deploy deploy -"
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
      # (<project>), which combined with the app unit's UMask=0007
      # (below -- the socket comes out 0770) is what lets nginx (a
      # <project>-sock member) reach it, with no cooperation needed from
      # the app itself.
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
        # Socket reachability is a unit-level concern, not an app-level
        # one: a bare `UnixListener::bind()` (what a real Rust release
        # binary does -- no chmod call anywhere) gets the default 0022
        # umask, producing an 0755 socket that a group member can't
        # connect() to (AF_UNIX connect() needs *write*, not just
        # read/execute). UMask=0007 makes every file the app creates --
        # its socket included -- 0660/0770 instead: group
        # (<project>-sock, via /run/<project>'s setgid bit) gets rw, so
        # nginx and `deploy` can reach it with zero cooperation required
        # from the app. NOT platform-base production's 0117 (that strips
        # the execute bit off directories the app itself creates, which
        # this unit's own WorkingDirectory doesn't need since it never
        # creates directories, but 0007 is the correct general-purpose
        # choice and matches what this module's own socket directory
        # setgid trick assumes).
        UMask = "0007";
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

    # Appends to (never replaces) base.nix's own AllowUsers definition
    # (admins + root) -- NixOS merges multiple `listOf str` definitions by
    # concatenation. Only appended once there's at least one deploy key,
    # so a project that never sets stackbase.deploy.keys doesn't open an
    # sshd account with authorized_keys.keys == [] (which would just fail
    # every login anyway, but there's no reason to list it in AllowUsers
    # either).
    services.openssh.settings.AllowUsers = lib.mkIf (cfg.deploy.keys != { }) [ "deploy" ];

    environment.etc."stackbase/deploy.env".text = ''
      STACK_PROJECT=${cfg.project}
      STACK_BINARY=${cfg.app.binary}
      STACK_HEALTH_PATH=${cfg.app.healthPath}
      STACK_DRAIN_SECONDS=${toString cfg.deploy.drainSeconds}
      STACK_KEEP=${toString cfg.deploy.keep}
      STACK_MAX_UPLOAD_BYTES=${toString cfg.deploy.maxUploadBytes}
      STACK_STATE_DIR=${stateDir}
    '';

    environment.systemPackages = [ stackDeployPkg stackDeploySshPkg ];
  };
}
