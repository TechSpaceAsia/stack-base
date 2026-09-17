# The project's own NixOS configuration. You should not need to edit this
# file: it reads stack.toml and builds one machine per [nodes.*] entry, so
# adding a server means adding a few lines to stack.toml, not to Nix.
#
# Each node gets:
#   - the hardened stack-base modules (ssh, nginx, postgres, firewall)
#   - ./nodes/<name>/hardware-configuration.nix -- the server's own disk and
#     boot settings, copied off the machine on the first run
#   - ./nodes/<name>/extra.nix -- OPTIONAL. Create that file for anything
#     specific to one server (a network quirk, an extra package) and it is
#     picked up automatically.
#
# Only stack.toml is read here. stack.state.json records what stack-base has
# observed and done (IP addresses, record ids, fingerprints), but none of that
# is an input to a machine's configuration -- so the Nix side deliberately
# does not read it.
{
  description = "NixOS configuration for this project's servers";

  # Where the shared stack-base modules come from. NOTE: this repository is
  # not published yet -- confirm this URL before relying on it.
  inputs.stack-base.url = "github:matiboy/stack-base";

  outputs = { self, stack-base }:
    let
      stack = builtins.fromTOML (builtins.readFile ./stack.toml);

      # keys/<admin>.pub as Nix expects it: one line, no trailing newline.
      adminKey = admin:
        builtins.replaceStrings [ "\n" ] [ "" ]
          (builtins.readFile (./keys + "/${admin}.pub"));

      admins = builtins.listToAttrs
        (map (admin: { name = admin; value = adminKey admin; }) stack.admins);

      nodeConfig = name:
        let
          extra = ./nodes + "/${name}/extra.nix";
        in
        stack-base.lib.mkNode {
          modules = [
            (./nodes + "/${name}/hardware-configuration.nix")
            {
              networking.hostName = name;
              stackbase.project = stack.project;
              stackbase.domain = stack.domain;
              stackbase.admins = admins;
            }
          ] ++ (if builtins.pathExists extra then [ extra ] else [ ]);
        };
    in
    {
      nixosConfigurations = builtins.listToAttrs
        (map (name: { name = name; value = nodeConfig name; })
          (builtins.attrNames stack.nodes));
    };
}
