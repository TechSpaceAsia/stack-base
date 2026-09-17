# PostgreSQL 16, socket-only, peer-auth-only, with a database and role
# named after the project. There is deliberately no way to reach this
# database over the network -- not even localhost TCP -- so there is no
# password to leak and nothing for the firewall to need to block.
#
# Reads `stackbase.project` from base.nix; declares no options of its own.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase;
in
{
  config = {
    services.postgresql = {
      enable = true;
      package = pkgs.postgresql_16;
      enableTCPIP = false;
      settings.listen_addresses = lib.mkForce "";

      # Replace the module's default rules (peer on the socket, md5 over
      # TCP) entirely: with enableTCPIP = false there is no TCP listener to
      # authenticate against anyway, so the only rule that can ever apply
      # is peer auth on the local unix socket.
      authentication = lib.mkForce ''
        local all all peer
      '';

      ensureDatabases = [ cfg.project ];
      ensureUsers = [
        {
          name = cfg.project;
          ensureDBOwnership = true;
        }
      ];
    };
  };
}
