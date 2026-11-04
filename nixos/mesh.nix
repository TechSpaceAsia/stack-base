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
# platform-base also bind-mounts nftables at /usr/sbin/nft, because the
# 2026-10 daemon build calls nft by that FHS path. The nixpkgs this flake
# pins (nixos-26.05) packages cloudflare-warp 2026.3, which wraps warp-svc
# with nftables on its PATH instead and calls no FHS path, so the mount is
# not carried here. If a later pin ships the newer daemon, add
#   systemd.services.cloudflare-warp.serviceConfig.BindReadOnlyPaths =
#     [ "${lib.getExe pkgs.nftables}:/usr/sbin/nft" ];
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase.mesh;
in
{
  options.stackbase.mesh.enable = lib.mkEnableOption "joining Cloudflare Mesh (headless cloudflare-warp connector)";

  config = lib.mkIf cfg.enable {
    services.cloudflare-warp = {
      enable = true;
      package = pkgs.cloudflare-warp.override { headless = true; };
      openFirewall = false;
    };

    # cloudflare-warp is unfree. Admit that one package, and nothing else.
    nixpkgs.config.allowUnfreePredicate = pkg: lib.getName pkg == "cloudflare-warp";
  };
}
