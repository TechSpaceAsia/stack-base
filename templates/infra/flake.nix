# The project's own NixOS configuration. You should not need to edit this
# file: it reads stack.toml and builds one machine per [nodes.*] entry, so
# adding a server means adding a few lines to stack.toml, not to Nix.
#
# Each node gets:
#   - the hardened stack-base modules (ssh, nginx, postgres, firewall) plus
#     the Hostinger provider module (boot.loader.*, cloud-init, networkd --
#     see stack-base's nixos/providers/hostinger.nix), via `mkNode`'s default
#     `provider = "hostinger"`
#   - ./nodes/<name>/hardware-configuration.nix -- the server's own disk
#     facts. Hostinger's image ships with an EMPTY /etc/nixos, so stack-base
#     generates this file itself (`nixos-generate-config
#     --show-hardware-config` run on the node) rather than copying it off an
#     existing one
#   - ./nodes/<name>/extra.nix -- OPTIONAL. Create that file for anything
#     specific to one server (a network quirk, an extra package) and it is
#     picked up automatically. It's also the escape hatch for a first-run
#     bootloader/network gap: it loads alongside the provider module's
#     defaults and can override any of them -- set the mismatched
#     boot.loader.*/networking.* option(s) there if the first rebuild fails
#     with a boot.loader or fileSystems error (see the README).
#   - ./conf.d/*.nix -- OPTIONAL, project-wide. Every .nix file in that
#     directory is imported on EVERY node. Use it for anything the whole
#     project needs (an extra package, a monitoring agent, a sysctl); use
#     ./nodes/<name>/extra.nix for anything specific to one server.
#
# Only stack.toml is read here. stack.state.json records what stack-base has
# observed and done (IP addresses, record ids, fingerprints), but none of that
# is an input to a machine's configuration -- so the Nix side deliberately
# does not read it.
{
  description = "NixOS configuration for this project's servers";

  # Where the shared stack-base modules come from. The third path segment
  # (v0.1.0) is the pinned release -- every project stays on it until you
  # deliberately move. To upgrade: change it here, then delete flake.lock
  # (or run `nix flake lock --update-input stack-base` if you have Nix
  # installed locally) and run ./infra/up -- it re-resolves the new ref and
  # writes a fresh lock.
  inputs.stack-base.url = "github:TechSpaceAsia/stack-base/v0.1.2";

  outputs = { self, stack-base }:
    let
      stack = builtins.fromTOML (builtins.readFile ./stack.toml);

      # keys/<admin>.pub as Nix expects it: one line, no trailing newline.
      adminKey = admin:
        builtins.replaceStrings [ "\n" ] [ "" ]
          (builtins.readFile (./keys + "/${admin}.pub"));

      admins = builtins.listToAttrs
        (map (admin: { name = admin; value = adminKey admin; }) stack.admins);

      # The project's ONE deploy key (`./infra/up deploy-key init`). Present
      # as soon as an operator has created it; the PRIVATE half lives only
      # in infra/deploy.age (and, for CI, in the repo's STACK_DEPLOY_KEY
      # secret). Layered on TOP of the admin keys below, never merged into
      # `admins` itself: every admin key also goes into
      # stackbase.deploy.keys (so an admin can deploy from their own laptop
      # with the same key they already log in with), but `deploy` must never
      # be able to reach root's or any admin's own authorized_keys -- only
      # nixos/deploy.nix's forced-command door reads stackbase.deploy.keys.
      deployPubPath = ./keys/deploy.pub;
      projectDeployKeys =
        if builtins.pathExists deployPubPath
        then {
          deploy = builtins.replaceStrings [ "\n" ] [ "" ]
            (builtins.readFile deployPubPath);
        }
        else { };

      deployKeys = admins // projectDeployKeys;

      # I6: the optional [app] table in stack.toml -- overrides for what
      # nixos/deploy.nix's stackbase.app.* options would otherwise default
      # (binary/healthPath) or a project could otherwise never set at all
      # from stack.toml (healthTries/healthSleep, I3's declarative knobs).
      # Every field is individually optional; only the ones actually
      # present in stack.toml are passed through, so an unset field keeps
      # stackbase.app.*'s own module-level default -- stackbase/config.py
      # already validated every field's shape/range before `up` ever gets
      # this far, so nothing here re-validates them.
      appConfig = stack.app or { };
      appOptions =
        (if appConfig ? binary then { binary = appConfig.binary; } else { })
        // (if appConfig ? health_path then { healthPath = appConfig.health_path; } else { })
        // (if appConfig ? health_tries then { healthTries = appConfig.health_tries; } else { })
        // (if appConfig ? health_sleep then { healthSleep = appConfig.health_sleep; } else { });

      # The optional [backups] table in stack.toml -> nixos/backups.nix's
      # stackbase.backups.* options. Naming a bucket is all it takes to
      # turn nightly backups on; every other field keeps the module's own
      # default when stack.toml does not set it.
      backupsConfig = stack.backups or { };
      backupsOptions =
        (if backupsConfig ? bucket then { bucket = backupsConfig.bucket; } else { })
        // (if backupsConfig ? retention_days then { retentionDays = backupsConfig.retention_days; } else { })
        // (if backupsConfig ? extra_paths then { extraPaths = backupsConfig.extra_paths; } else { })
        // (if backupsConfig ? on_calendar then { onCalendar = backupsConfig.on_calendar; } else { });

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
              stackbase.deploy.keys = deployKeys;
              stackbase.app = appOptions;
              stackbase.backups = backupsOptions;
            }
          ]
          # Project-wide modules: every infra/conf.d/*.nix lands on EVERY
          # node. Listed before the node's own extra.nix so list-valued
          # options concatenate project-wide-first; overriding a value set
          # here from extra.nix takes lib.mkForce, exactly as it would
          # between any two modules.
          ++ (stack-base.lib.confdModules ./conf.d)
          ++ (if builtins.pathExists extra then [ extra ] else [ ]);
        };
    in
    {
      nixosConfigurations = builtins.listToAttrs
        (map (name: { name = name; value = nodeConfig name; })
          (builtins.attrNames stack.nodes));
    };
}
