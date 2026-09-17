# Hostinger provider module: reproduces the boot + networking setup baked
# into Hostinger's NixOS 26.05 cloud image, because that image's /etc/nixos
# is EMPTY (a prebuilt cloud-init image, not a from-scratch `nixos-install`)
# -- see .superpowers/sdd/plan-01-stack-up/task-8a-brief.md for the live
# findings this module is designed against. `lib.mkNode` in ../../flake.nix
# includes this module only when a node's `provider` is "hostinger" (the
# default); the VM tests (`nixosModules.default`) never see it.
#
# What each option is for, and why it's here rather than left to the
# nixos-26.05 `services.cloud-init` module's own defaults (read in full at
# nixos/modules/services/system/cloud-init.nix in the pinned nixpkgs):
#
#   - `boot.loader.grub.enable`/`.device` (mkDefault): BIOS boot, GRUB on
#     /dev/sda on the real box. The generated hardware-configuration.nix
#     (steps.py::_capture_hardware, via `nixos-generate-config
#     --show-hardware-config`) never sets a bootloader -- this module is the
#     sole supplier, with mkDefault so a node whose disk genuinely differs
#     can still override it from infra/nodes/<node>/extra.nix.
#
#   - `services.cloud-init.enable = true`: turns on cloud-init generally.
#     On its own this already sets (all via mkDefault, so still overridable):
#     system_info.distro = "nixos", system_info.network.renderers =
#     ["networkd"], users = ["root"], disable_root = false, and the stock
#     cloud_init_modules/cloud_config_modules/cloud_final_modules lists --
#     which match the "stock NixOS services.cloud-init one" the live box
#     reported. It also writes /etc/cloud/cloud.cfg and the
#     cloud-init-local/cloud-init/cloud-config/cloud-final systemd units.
#     It does NOT set `preserve_hostname` to anything other than its own
#     mkDefault false -- see below.
#
#   - `services.cloud-init.network.enable = true`: the option that actually
#     matters for staying reachable after a reboot. It makes the cloud-init
#     module set `systemd.network.enable = true` (hard, not mkDefault),
#     which is what lets systemd-networkd consume the
#     `/etc/systemd/network/10-cloud-init-eth0.network` file cloud-init
#     renders at boot from the NoCloud network-config. `systemd.network.enable
#     = true` also makes nixos/modules/system/boot/networkd.nix set
#     `services.resolved.enable = mkDefault true` -- matching resolved being
#     active on the box, with no extra option needed from us for that part.
#
#   - `networking.useNetworkd = true`: NOT set by the cloud-init module --
#     added here. Without it, NixOS's scripted networking
#     (nixos/modules/tasks/network-interfaces-scripted.nix) still runs
#     dhcpcd for any interface it doesn't know about in Nix -- which is
#     every interface here, since the static IP is written by cloud-init at
#     runtime, never declared in Nix. nixpkgs itself emits a `warnings`
#     entry for exactly this combination (`systemd.network.enable = true`,
#     `networking.useDHCP = true` [the default], `networking.useNetworkd =
#     false`): "can cause both networkd and dhcpcd to manage the same
#     interfaces... loss of networking". This is the option that keeps eth0
#     static after a reboot; get it wrong and the node is unreachable.
#
#   - `services.cloud-init.settings.preserve_hostname = true`: overrides
#     cloud-init's own mkDefault false. Without this, cloud-init's
#     "update_hostname" module (in the default cloud_init_modules list)
#     would reset /etc/hostname from Hostinger's instance metadata on every
#     boot, fighting the per-node `networking.hostName` the project's flake
#     sets. There is no "update_etc_hosts" module in cloud-init's default
#     module lists, so /etc/hosts is never touched by cloud-init in the
#     first place -- nothing to override there.
#
#   - `boot.growPartition = true` + `fileSystems."/".autoResize` (mkDefault):
#     match `growpart.service` (the literal unit name
#     nixos/modules/system/boot/grow-partition.nix creates) and the
#     `x-systemd.growfs` mount option the live box has on `/`. This is
#     NixOS's own initrd-adjacent grow mechanism, not cloud-init's "growpart"
#     cloud-config module (which has no systemd unit of its own) -- the two
#     don't conflict; only NixOS's shows up as a named unit, which is what
#     was actually observed.
#
#   - `services.qemuGuest.enable = true`: the qemu-guest-agent service
#     (nixos/modules/virtualisation/qemu-guest-agent.nix), matching
#     "qemu-guest-agent active" on the box. This is unrelated to (and
#     doesn't conflict with) the `(modulesPath + "/profiles/qemu-guest.nix")`
#     import the generated hardware config already carries -- that profile
#     only adds virtio initrd kernel modules.
#
# Deliberately NOT touched here: `networking.firewall.*` and
# `services.openssh.settings.*` stay entirely base.nix's call -- this module
# opens no port and sets no ssh/password-auth option, so base.nix always
# wins (a `nix eval` in tests/test_template.py proves both). Cloud-init's
# "ssh" cloud-config module cannot change that in practice either: NixOS's
# /etc/ssh/sshd_config is generated into the Nix store and reapplied on
# every activation, so anything cloud-init writes there at boot is
# superseded the moment `nixos-rebuild switch` next runs.
{ lib, ... }:

{
  config = {
    boot.loader.grub.enable = lib.mkDefault true;
    boot.loader.grub.device = lib.mkDefault "/dev/sda";

    boot.growPartition = true;
    fileSystems."/".autoResize = lib.mkDefault true;

    services.cloud-init.enable = true;
    services.cloud-init.network.enable = true;
    services.cloud-init.settings.preserve_hostname = true;

    networking.useNetworkd = true;

    services.qemuGuest.enable = true;
  };
}
