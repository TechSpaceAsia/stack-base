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
    # A single computed value (rather than a separate `users.users.root.…`
    # binding) -- Nix's attrset-literal merging can't combine a plain
    # `mapAttrs` result at `users.users` with a further nested-path binding
    # at `users.users.root.…` in the same `config` literal.
    users.users = lib.mapAttrs (_name: key: {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = [ key ];
    }) cfg.admins // {
      # root needs key login too: the provisioner's very first rebuild
      # connects as root before any admin account exists on the node.
      root.openssh.authorizedKeys.keys = lib.attrValues cfg.admins;
    };

    security.sudo.wheelNeedsPassword = false;

    services.openssh = {
      enable = true;
      openFirewall = false; # networking.firewall below is the single source of truth
      listenAddresses = map (addr: { inherit addr; }) cfg.ssh.listenAddresses;
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
