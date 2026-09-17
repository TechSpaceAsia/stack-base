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
        self.nixosModules.deploy
      ];
    in
    {
      nixosModules.base = import ./nixos/base.nix;
      nixosModules.appHost = import ./nixos/app-host.nix;
      nixosModules.postgres = import ./nixos/postgres.nix;
      nixosModules.hostinger = import ./nixos/providers/hostinger.nix;
      nixosModules.deploy = import ./nixos/deploy.nix;
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

      checks.${system} = {
        vm = import ./tests/vm.nix { inherit self pkgs lib; };
        vm-deploy = import ./tests/vm-deploy.nix { inherit self pkgs lib; };
      };
    };
}
