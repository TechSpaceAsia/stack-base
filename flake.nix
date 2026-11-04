# Entry point for every project built on stack-base. A consuming project's
# tiny `infra/flake.nix` pins this flake as `inputs.stack-base` and calls
# `lib.mkNode` per node -- it never imports nixos/*.nix directly. Change the
# module list here, or the modules themselves under nixos/, deliberately:
# it lands on every derived project's next rebuild.
{
  description = "stack-base: hardened NixOS modules for stackbase nodes";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  # Only nixos/mesh.nix's cloudflare-warp comes from here. nixos-26.05 ships
  # 2026.3.846.0; this commit has 2026.8.2115.0, the build carrying
  # Cloudflare's 2026-10-20 certificate-chain hotfix, without which Mesh
  # enrolment fails. Same commit platform-base pins. Drop this input (and use
  # pkgs.cloudflare-warp) once nixos-26.05 ships >= 2026.8.
  inputs.nixpkgs-warp.url = "github:NixOS/nixpkgs/d0fdd02155a254227dce86380a58a4bf94f1e56f";

  outputs = { self, nixpkgs, nixpkgs-warp }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = nixpkgs.lib;

      baseModules = [
        self.nixosModules.base
        self.nixosModules.appHost
        self.nixosModules.postgres
        self.nixosModules.deploy
        # Every server gets the module; `enable` defaults to false until a
        # bucket is named in stack.toml's [backups] table.
        self.nixosModules.backups
        # Same shape: off until stack.toml's [logs] table names a bucket.
        self.nixosModules.logs
        # Same shape: off until stack.toml's [mesh] table says enabled = true.
        self.nixosModules.mesh
        # Same shape: off until stack.toml's [alerts] table names recipients.
        self.nixosModules.alerts
      ];
    in
    {
      nixosModules.base = import ./nixos/base.nix;
      nixosModules.appHost = import ./nixos/app-host.nix;
      nixosModules.postgres = import ./nixos/postgres.nix;
      nixosModules.hostinger = import ./nixos/providers/hostinger.nix;
      nixosModules.deploy = import ./nixos/deploy.nix;
      nixosModules.backups = import ./nixos/backups.nix;
      nixosModules.logs = import ./nixos/logs.nix;
      nixosModules.mesh = import ./nixos/mesh.nix { inherit nixpkgs-warp; };
      nixosModules.alerts = import ./nixos/alerts.nix;
      nixosModules.default = { imports = baseModules; };

      # `provider` selects the module that reproduces one hosting provider's
      # image-level boot/networking assumptions (see nixos/providers/*.nix).
      # "hostinger" (the default -- every node this template builds targets
      # Hostinger) includes nixosModules.hostinger; `null` includes none (the
      # VM tests build nodes straight from baseModules and never pass
      # `provider` at all, so they are unaffected either way). Any other
      # value is almost certainly a typo, so it throws rather than silently
      # building a node with no provider module.
      lib.mkNode = { system ? "x86_64-linux", provider ? "hostinger", modules }:
        let
          providerModules =
            if provider == null then [ ]
            else if provider == "hostinger" then [ self.nixosModules.hostinger ]
            else throw "stack-base: unknown provider '${provider}' -- known providers: \"hostinger\", or null for none";
        in
        lib.nixosSystem {
          inherit system;
          modules = baseModules ++ providerModules ++ [
            { system.stateVersion = lib.mkDefault "26.05"; }
          ] ++ modules;
        };

      # Every `<dir>/*.nix` as a module list, sorted by file name; a missing
      # directory yields [ ]. A project's own infra/flake.nix calls this for
      # infra/conf.d/ -- modules that apply to EVERY node, as opposed to
      # infra/nodes/<name>/extra.nix, which applies to one. It lives here
      # rather than inline in the template so the VM test can exercise the
      # very same filter the template calls.
      #
      # `type == "regular"` on purpose: a subdirectory called "foo.nix"
      # would otherwise be imported as a module and fail confusingly, and a
      # dangling symlink would break evaluation for everyone.
      lib.confdModules = dir:
        if !builtins.pathExists dir then [ ]
        else
          let entries = builtins.readDir dir;
          in map (name: dir + "/${name}")
            (builtins.filter
              (name: entries.${name} == "regular" && lib.hasSuffix ".nix" name)
              (builtins.attrNames entries));

      checks.${system} = {
        vm = import ./tests/vm.nix { inherit self pkgs lib; };
        vm-deploy = import ./tests/vm-deploy.nix { inherit self pkgs lib; };
        vm-logs = import ./tests/vm-logs.nix { inherit self pkgs lib; };
        vm-alerts = import ./tests/vm-alerts.nix { inherit self pkgs lib; };
      };
    };
}
