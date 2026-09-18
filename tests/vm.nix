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

  # A throwaway age identity, generated at BUILD time (a plain derivation --
  # `nix flake check` already realizes derivations referenced from module
  # config, so this needs no special IFD flag). Its PRIVATE half is in the
  # world-readable Nix store, which is exactly what makes it a test-only
  # identity: it proves a backup can be decrypted, and protects nothing.
  testAgeIdentity = pkgs.runCommand "stackbase-test-age-identity" { nativeBuildInputs = [ pkgs.age ]; } ''
    mkdir -p "$out"
    age-keygen -o "$out/key.txt" 2>/dev/null
    grep '^# public key: ' "$out/key.txt" | cut -d' ' -f4 > "$out/recipients.txt"
  '';

  backupBucket = "/var/backup-target";
  uploadsDir = "/var/lib/teststack-uploads";
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
          self.nixosModules.backups
        ]
        # The SAME filter a project's infra/flake.nix calls for
        # infra/conf.d/ -- tested here on a booted machine rather than only
        # at eval time (tests/test_template.py covers the eval side).
        ++ (self.lib.confdModules ./fixtures/confd);

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

        stackbase.backups.bucket = backupBucket;
        stackbase.backups.recipientsFile = "/etc/stackbase-test/recipients.txt";
        stackbase.backups.extraPaths = [ uploadsDir ];
        # The timer must exist and be scheduled, but must never actually
        # fire during the test -- every backup here is started explicitly.
        stackbase.backups.onCalendar = "23:59";

        environment.etc."stackbase-test/recipients.txt".source = "${testAgeIdentity}/recipients.txt";
        environment.etc."stackbase-test/identity.txt".source = "${testAgeIdentity}/key.txt";

        environment.systemPackages = [ pkgs.iproute2 pkgs.age pkgs.zstd pkgs.gnutar pkgs.rclone ];

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

      with subtest("authorized_keys is declarative-only: no ~/.ssh/authorized_keys homedir source (F1)"):
          # services.openssh.authorizedKeysInHomedir defaults to true, which
          # would put "%h/.ssh/authorized_keys" ahead of
          # "/etc/ssh/authorized_keys.d/%u" in AuthorizedKeysFile -- a
          # second, WRITABLE key source for any account that owns its own
          # home directory. base.nix turns this off for every account on
          # every stackbase node; confirm the exact resulting value rather
          # than just that it changed from the default.
          node.succeed(
              "sshd -T | grep -qxi 'authorizedkeysfile /etc/ssh/authorized_keys.d/%u'"
          )

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

      with subtest("infra/conf.d modules are imported on the node"):
          marker = node.succeed("cat /etc/stackbase-confd-marker").strip()
          assert marker == "hello from conf.d", f"unexpected conf.d marker: {marker!r}"
          # The fixture directory also holds a notes.txt -- proof the filter
          # takes *.nix only, since a non-module file would have failed the
          # build, not just this assertion.

      with subtest("the backup timer is scheduled"):
          # Deliberately no assertion that it has NOT fired: a `Persistent`
          # timer's behaviour on a machine with no timestamp file is not
          # something this test should pin down. It cannot have produced
          # anything either way -- there are no credentials on the node yet,
          # so a spontaneous run would have exited 1 with the "no
          # credentials" message.
          node.succeed("systemctl is-active stackbase-backup.timer")
          timers = node.succeed("systemctl list-timers --all --no-pager stackbase-backup.timer")
          assert "stackbase-backup.timer" in timers, timers

      with subtest("a backup run encrypts a real dump that decrypts to valid SQL"):
          # RCLONE_CONFIG_BACKUP_TYPE=local turns `backup:<bucket>` into a
          # plain directory path -- the whole pipeline (pg_dump | zstd | age
          # | rclone rcat) runs exactly as it does against R2.
          node.succeed("install -d -m 0755 ${uploadsDir}")
          node.succeed("echo hello-uploads > ${uploadsDir}/note.txt")
          node.succeed("install -m 0600 /dev/null /var/lib/stackbase/backup.env")
          node.succeed(
              "printf 'RCLONE_CONFIG_BACKUP_TYPE=local\\n' > /var/lib/stackbase/backup.env"
          )
          node.succeed(
              "sudo -u postgres psql -d teststack -c "
              "'create table backup_probe (id int primary key, note text)'"
          )
          node.succeed(
              "sudo -u postgres psql -d teststack -c "
              "\"insert into backup_probe values (1, 'probe-row')\""
          )

          node.succeed("systemctl start stackbase-backup.service")

          dump = node.succeed("ls ${backupBucket}/db/*.sql.zst.age").strip().splitlines()[0]
          assert dump.split("/")[-1].startswith("teststack_"), f"unexpected dump name: {dump!r}"

          plain = node.succeed(
              f"age -d -i /etc/stackbase-test/identity.txt {dump} | zstd -d"
          )
          assert "CREATE TABLE public.backup_probe" in plain, plain[:400]
          assert "probe-row" in plain, plain[:400]

      with subtest("an extra path is archived as its own encrypted tarball"):
          archive = node.succeed("ls ${backupBucket}/files/*.tar.zst.age").strip().splitlines()[0]
          assert archive.split("/")[-1].startswith("teststack-uploads_"), archive

          listing = node.succeed(
              f"age -d -i /etc/stackbase-test/identity.txt {archive} | zstd -d | tar -tf -"
          )
          assert "./note.txt" in listing, listing

      with subtest("a backup with no credentials fails loudly instead of silently doing nothing"):
          node.succeed("mv /var/lib/stackbase/backup.env /var/lib/stackbase/backup.env.away")
          node.fail("systemctl start stackbase-backup.service")
          # NOT named `log` -- the test script's own namespace already
          # binds `log: AbstractLogger` (the driver's structured logger),
          # and the VM check's Pyright-style type check on testScriptWithTypes
          # refuses to build if a local reassigns it to a plain str.
          unit_log = node.succeed("journalctl -u stackbase-backup -n 20 --no-pager")
          assert "no credentials" in unit_log, unit_log[-400:]
          node.succeed("mv /var/lib/stackbase/backup.env.away /var/lib/stackbase/backup.env")

      with subtest("a backup with no recipients file refuses rather than writing something undecryptable"):
          # /etc entries are symlinks into the store -- remove the link, and
          # put it back by hand afterwards (the store path is stable).
          node.succeed("rm -f /etc/stackbase-test/recipients.txt")
          node.fail("systemctl start stackbase-backup.service")
          unit_log = node.succeed("journalctl -u stackbase-backup -n 20 --no-pager")
          assert "nobody could decrypt" in unit_log, unit_log[-400:]

      with subtest("stackbase-backup-ls prints what landed in the bucket"):
          node.succeed("ln -sf ${testAgeIdentity}/recipients.txt /etc/stackbase-test/recipients.txt")
          listing = node.succeed("stackbase-backup-ls")
          assert "db/teststack_" in listing, listing
    '';
}
