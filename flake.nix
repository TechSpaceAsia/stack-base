# Entry point for every project built on stack-base. A consuming project's
# tiny `infra/flake.nix` pins this flake as `inputs.stack-base` and calls
# `lib.mkNode` per node -- it never imports nixos/*.nix directly. Change the
# module list here, or the modules themselves under nixos/, deliberately:
# it lands on every derived project's next rebuild.
{
  description = "stack-base: hardened NixOS modules for stackbase nodes";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = nixpkgs.lib;

      baseModules = [
        self.nixosModules.base
        self.nixosModules.appHost
        self.nixosModules.postgres
      ];
    in
    {
      nixosModules.base = import ./nixos/base.nix;
      nixosModules.appHost = import ./nixos/app-host.nix;
      nixosModules.postgres = import ./nixos/postgres.nix;
      nixosModules.default = { imports = baseModules; };

      lib.mkNode = { system ? "x86_64-linux", modules }:
        lib.nixosSystem {
          inherit system;
          modules = baseModules ++ [
            { system.stateVersion = lib.mkDefault "26.05"; }
          ] ++ modules;
        };

      checks.${system}.vm = import ./tests/vm.nix { inherit self pkgs lib; };
    };
}
