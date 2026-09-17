# NixOS VM test wired as `checks.x86_64-linux.vm` in flake.nix. Boots a
# stackbase node plus two plain client machines -- `proxy` (inside the
# node's allowed-proxy-range) and `outsider` (outside it) -- and exercises
# the acceptance criteria from a real client's point of view: sshd
# hardening, the Postgres socket-only/peer-auth setup, and the
# geo/real_ip-gated nginx allow-list (Ruling R2/R7 in progress.md).
#
# Run with `nix flake check` (slow on first run -- it builds a NixOS VM).
{ self, pkgs, lib }:

let
  domain = "node.test";

  # A throwaway ed25519 public key -- there is no matching private key
  # anywhere, and no login is attempted with it in this test. It only needs
  # to be present so base.nix's admin-account config has something to work
  # with (`stackbase.admins` requires at least a plausible key string).
  adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBDGmdzpEogrHBnAP+a1MKjbV+D9E9nQOVx8m2wcmt3 vm-test-admin";

  # Must match app-host.nix's certDir/keyFile/certFile -- exercised below to
  # prove the ownership/mode fix (Finding 5) applies even when the real
  # cert pair already exists, not just when a placeholder is generated.
  certDir = "/var/lib/stackbase";
  keyFile = "${certDir}/origin.key";
  certFile = "${certDir}/origin.crt";
in
pkgs.testers.runNixOSTest {
  name = "stackbase-vm";

  nodes = {
    node =
      { nodes, ... }:
      {
        imports = [
          self.nixosModules.base
          self.nixosModules.appHost
          self.nixosModules.postgres
        ];

        stackbase.project = "teststack";
        stackbase.domain = domain;
        stackbase.admins.deploy = adminKey;

        # Real Cloudflare ranges are meaningless inside the test's private
        # vlan; swap in the `proxy` machine's own address so the
        # geo/real_ip allow-list mechanism can be exercised for real
        # against both an allowed and a non-allowed client (Ruling R2).
        stackbase.allowedProxyRanges = lib.mkForce [
          "${nodes.proxy.networking.primaryIPAddress}/32"
        ];

        environment.systemPackages = [ pkgs.iproute2 ];

        system.stateVersion = "26.05";
      };

    proxy =
      { ... }:
      {
        environment.systemPackages = [ pkgs.curl ];
        system.stateVersion = "26.05";
      };

    outsider =
      { ... }:
      {
        # curl for the nginx allow-list check; openssh for the ssh client
        # used in the publickey-only behavioural check.
        environment.systemPackages = [ pkgs.curl pkgs.openssh ];
        system.stateVersion = "26.05";
      };
  };

  testScript =
    { nodes, ... }:
    ''
      start_all()

      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("sshd.service")
      node.wait_for_unit("postgresql.service")
      node.wait_for_unit("nginx.service")
      node.wait_for_open_port(443)

      proxy.wait_for_unit("multi-user.target")
      outsider.wait_for_unit("multi-user.target")

      node_ip = "${nodes.node.networking.primaryIPAddress}"

      with subtest("sshd is hardened per Global Constraints + Task 6 brief"):
          # `sshd -T`'s dump preserves the directive's own case (e.g.
          # "PasswordAuthentication no", not "passwordauthentication no") --
          # confirmed by capturing the real dump during debugging, where the
          # settings below were all present and correct but this grep still
          # failed on case alone. Match case-insensitively.
          node.succeed("sshd -T | grep -qxi 'passwordauthentication no'")
          node.succeed("sshd -T | grep -qxi 'kbdinteractiveauthentication no'")
          node.succeed("sshd -T | grep -qxi 'maxauthtries 3'")

      with subtest("sshd only offers publickey auth (behavioural check, not just config parsing)"):
          # Config-parsing assertions above can't catch every way key-only
          # auth could fail to actually apply, so also prove it from a real
          # client: force password auth and pubkey auth off, and confirm the
          # server refuses with a "no more authentication methods" /
          # publickey-only denial rather than accepting or prompting.
          ssh_output = outsider.fail(
              "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no "
              "-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 "
              f"root@{node_ip} true 2>&1"
          )
          assert "Permission denied" in ssh_output and "publickey" in ssh_output, (
              f"expected a publickey-only denial, got: {ssh_output!r}"
          )

      with subtest("postgres is socket-only with peer auth"):
          node.fail("ss -ltn | grep -q ':5432'")
          node.succeed("sudo -u postgres psql -c 'select 1'")

      with subtest("nginx only serves an allowed proxy, refuses everyone else"):
          curl = (
              "curl -sk -o /dev/null -w '%{http_code}' "
              f"--resolve ${domain}:443:{node_ip} https://${domain}/__stack"
          )

          proxy_code = proxy.succeed(curl).strip()
          assert proxy_code == "200", f"expected 200 from the allowed proxy, got {proxy_code}"

          outsider_code = outsider.succeed(curl).strip()
          assert outsider_code == "403", f"expected 403 from a non-allowed source, got {outsider_code}"

      with subtest("origin cert ownership is fixed even when the real pair already exists (Finding 5)"):
          # The placeholder-cert oneshot already left ${keyFile}/${certFile}
          # owned root:nginx (proven implicitly by nginx being up above).
          # Simulate what a first PUSH_CONFIG leaves behind -- root:root
          # 0600, written entirely over ssh before this unit ever reruns --
          # and prove a rerun corrects it rather than only fixing ownership
          # the one time a placeholder is freshly generated.
          node.succeed("chown root:root ${keyFile} ${certFile}")
          node.succeed("chmod 0600 ${keyFile} ${certFile}")
          node.succeed("systemctl restart stackbase-origin-cert-placeholder.service")

          key_owner = node.succeed("stat -c '%U:%G %a' ${keyFile}").strip()
          cert_owner = node.succeed("stat -c '%U:%G %a' ${certFile}").strip()
          assert key_owner == "root:nginx 640", f"expected origin.key to be root:nginx 640, got {key_owner!r}"
          assert cert_owner == "root:nginx 644", f"expected origin.crt to be root:nginx 644, got {cert_owner!r}"

          node.succeed("systemctl is-active nginx")
    '';
}
