# Hardening common to every stackbase node: admin accounts, key-only SSH,
# fail2ban, a journald cap, Nix flakes + weekly GC, and the base firewall
# (22 + 443 only -- app-host.nix relies on nothing more being open here).
#
# Declares `stackbase.project`, the one option every other stackbase module
# (app-host.nix, postgres.nix) reads. This module must import cleanly on its
# own; the others assume it is imported alongside them (lib.mkNode in
# flake.nix always does).
#
# Editing this file loosens or tightens every project built from
# stack-base -- change it deliberately, not as a one-off for a single node.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase;
in
{
  options.stackbase = {
    project = lib.mkOption {
      type = lib.types.str;
      description = ''
        Project slug (matches stack.toml's `project`). Used to name the
        Postgres database/role and the app's unix socket directory.
      '';
    };

    admins = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = ''
        Admin username -> SSH public key. Each admin gets a `wheel` account
        with passwordless sudo and key-only login. `root` also gets every
        admin key, because the provisioner's very first rebuild connects as
        root before any admin account exists on the node.
      '';
    };

    ssh.listenAddresses = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Addresses sshd binds to. Empty (the default) means all addresses.
      '';
    };
  };

  config = {
    assertions = [
      {
        assertion = cfg.admins != { };
        message = ''
          stackbase.admins must not be empty. With
          services.openssh.authorizedKeysInHomedir disabled below, root's
          only source of SSH keys is users.users.root.openssh.authorizedKeys.keys,
          which base.nix populates entirely from stackbase.admins -- an empty
          admin set would leave no key able to log in as anyone at all,
          including root, on the very first boot.
        '';
      }
    ];

    # A single computed value (rather than a separate `users.users.root.…`
    # binding) -- Nix's attrset-literal merging can't combine a plain
    # `mapAttrs` result at `users.users` with a further nested-path binding
    # at `users.users.root.…` in the same `config` literal.
    #
    # `lib.unique` on both lists: a live box was found with the same key
    # listed twice under one admin's own `/etc/ssh/authorized_keys.d/<name>`
    # (2 lines, 1 distinct value). Whatever upstream reason a key ends up
    # offered more than once for the same user -- two admins sharing one
    # key (which would otherwise double up in root's aggregate list below),
    # or the very same `keys.<admin>.keys` list being contributed by more
    # than one module -- deduplicating here is the one place that can never
    # under-count (`lib.unique` only ever drops an exact repeat of a value
    # already kept, never a distinct one) and never miss a case.
    users.users = lib.mapAttrs (_name: key: {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = lib.unique [ key ];
    }) cfg.admins // {
      # root needs key login too: the provisioner's very first rebuild
      # connects as root before any admin account exists on the node.
      # root legitimately gets every admin's key -- `lib.unique` only
      # collapses an exact repeat, so every distinct admin key still lands
      # here.
      root.openssh.authorizedKeys.keys = lib.unique (lib.attrValues cfg.admins);
    };

    security.sudo.wheelNeedsPassword = false;

    services.openssh = {
      enable = true;
      openFirewall = false; # networking.firewall below is the single source of truth
      listenAddresses = map (addr: { inherit addr; }) cfg.ssh.listenAddresses;
      # Declarative-only key sources. NixOS defaults this to true, which
      # makes AuthorizedKeysFile include "%h/.ssh/authorized_keys" ahead of
      # "/etc/ssh/authorized_keys.d/%u" -- a second, WRITABLE key source for
      # every account with a home directory it can write to. deploy.nix's
      # `deploy` user owns its own home (stateDir/deploy-home); anything
      # able to write there as `deploy` could plant an unrestricted key and
      # bypass every `restrict,command=` guarantee that module builds. With
      # this off, the ONLY trusted source for every account is
      # /etc/ssh/authorized_keys.d/%u, generated purely from
      # users.users.<name>.openssh.authorizedKeys.keys -- i.e. purely from
      # stackbase.admins/stackbase.deploy.keys. This also makes dropping an
      # admin from config a REAL revocation (a stray homedir key would
      # otherwise survive it) and stops a provider's cloud-init-delivered
      # root key (Hostinger's default cloud-init "ssh" module writes root's
      # first metadata key into ~root/.ssh/authorized_keys) from being a
      # second, out-of-band source -- root already gets every admin key
      # declaratively above, confirmed by `nix eval` against a real mkNode
      # config (see nixos/deploy.nix's Task 2 report, Fix round 1).
      authorizedKeysInHomedir = false;
      settings = {
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        PermitRootLogin = "prohibit-password";
        AllowUsers = (lib.attrNames cfg.admins) ++ [ "root" ];
        MaxAuthTries = 3;
      };
      # No typed option for PerSourcePenalties (OpenSSH 9.8+) -- extraConfig
      # is the documented escape hatch for settings the module doesn't wrap.
      extraConfig = ''
        PerSourcePenalties yes
      '';
    };

    # systemd-resolved -- enabled indirectly, not by this module: the
    # Hostinger provider module (nixos/providers/hostinger.nix) turns on
    # cloud-init's networking, which turns on systemd-networkd, which
    # defaults `services.resolved.enable` on -- otherwise listens for
    # LLMNR/mDNS on 0.0.0.0:5355 and [::]:5355. The firewall already blocks
    # both from outside, but there's no legitimate LAN-discovery use for a
    # public VPS, so turn them off at the source. `mkDefault` so a node that
    # genuinely needs one can still override it from extra.nix; harmless on
    # a system with resolved disabled entirely, since resolved's own module
    # only ever writes `settings.Resolve` into resolved.conf when
    # `services.resolved.enable` is true.
    services.resolved.settings.Resolve = {
      LLMNR = lib.mkDefault "no";
      MulticastDNS = lib.mkDefault "no";
    };

    services.fail2ban.enable = true; # ships a default sshd jail; defaults are fine here

    services.journald.extraConfig = ''
      SystemMaxUse=500M
    '';

    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    nix.gc = {
      automatic = true;
      dates = "weekly";
    };

    networking.firewall.allowedTCPPorts = [ 22 443 ];
  };
}
