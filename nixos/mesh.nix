# Cloudflare Mesh: the node joins as a headless `cloudflare-warp` connector,
# so an operator reaches it over Mesh instead of its public address (SSH over
# Mesh is the only use; nothing else is exposed through it).
#
# Shape follows platform-base's nixos/cloudflare-mesh.nix, minus the
# Tailscale CGNAT exception (stack-base nodes do not run Tailscale).
#
# Installing the daemon is all this module does. Enrolment is a one-time
# `warp-cli connector new <token>` that `./infra/up` runs over SSH
# (stackbase/mesh.py), with the token from the environment's secrets: a
# token is a credential, so it must not be in the Nix store or the
# repository. Give the node an include-only MASQUE device profile in the
# Cloudflare dashboard so that only Mesh destinations use the tunnel.
#
# The firewall is not opened: WARP dials out, and nothing needs to reach
# its UDP port from the Internet.
#
# The package comes from the `nixpkgs-warp` flake input, not the main
# nixpkgs: see flake.nix for why, and when to drop the pin. The 2026-10
# daemon build calls nft by the FHS path /usr/sbin/nft, which the 26.05
# service module does not provide, so nftables is bind-mounted there (as in
# platform-base).
{ nixpkgs-warp }:
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase.mesh;
  warpPkgs = import nixpkgs-warp {
    system = pkgs.stdenv.hostPlatform.system;
    config.allowUnfree = true; # this import only, to take the one package
  };
in
{
  options.stackbase.mesh.enable = lib.mkEnableOption "joining Cloudflare Mesh (headless cloudflare-warp connector)";

  config = lib.mkIf cfg.enable {
    services.cloudflare-warp = {
      enable = true;
      package = warpPkgs.cloudflare-warp.override { headless = true; };
      openFirewall = false;
    };

    systemd.services.cloudflare-warp.serviceConfig.BindReadOnlyPaths = [
      "${lib.getExe pkgs.nftables}:/usr/sbin/nft"
    ];

    # cloudflare-warp is unfree. Admit that one package, and nothing else.
    nixpkgs.config.allowUnfreePredicate = pkg: lib.getName pkg == "cloudflare-warp";
  };
}
