# NixOS VM test wired as `checks.x86_64-linux.vm-deploy` in flake.nix.
# Exercises the blue/green release engine (nixos/deploy.nix +
# nixos/deploy/stack-deploy.sh) end to end against a real systemd + nginx
# node: first deploy, a swap with a live zero-downtime check, drain-stop, a
# broken release that must not clobber the rollback target, rollback,
# invalid-version rejection, the deploy lock, prune's SemVer retention,
# boot-time recovery (including the pending-color crash window), hardened
# tarball extraction, release-directory write protection, and the
# deploy/app trust-boundary split.
#
# Run with `nix flake check`, or in isolation with
# `nix build .#checks.x86_64-linux.vm-deploy -L`.
{ self, pkgs, lib }:

let
  domain = "node.test";
  project = "teststack";
  # Must match nixos/deploy.nix's own `stateDir` binding exactly -- see
  # its comment for why the engine's state lives here and not under
  # /var/lib/stackbase (app-host.nix's exclusive, root:nginx domain).
  stateDir = "/var/lib/stackbase-deploy";

  # Health tries/sleep are overridden per-invocation in the test (short,
  # per the brief) so this doesn't slow the suite down; the module's real
  # defaults (30 tries x 2s) are exercised implicitly by simply working.
  fastHealth = "STACK_DEPLOY_HEALTH_TRIES=10 STACK_DEPLOY_HEALTH_SLEEP=1";
  # Short and bounded: the broken release always fails, so this just
  # caps how long cmd_deploy takes to give up.
  brokenHealth = "STACK_DEPLOY_HEALTH_TRIES=3 STACK_DEPLOY_HEALTH_SLEEP=1";

  # One fake app, parameterised by __VERSION__ and __HEALTH_CODE__ (200 for
  # a working release, 500 for a broken one) rather than two near-identical
  # copies. Binds $SOCKET_PATH (removing a stale socket first) and answers
  # GET /health and GET /version -- deliberately does NOT touch the
  # socket's mode itself, matching platform-base's real
  # UnixListener::bind() (src/main.rs), which never chmods either. Socket
  # reachability for nginx comes entirely from the app unit's `UMask`
  # (nixos/deploy.nix), not from anything the app does -- this fake app
  # has to behave the same way, or the zero-downtime-through-nginx
  # assertions below would be proving the wrong mechanism.
  # Task 2: a test ed25519 keypair per role, generated at BUILD time (via
  # a plain derivation -- `nix build`/`nix flake check` already realize
  # derivations referenced from module config, so this needs no special
  # IFD flag). `client` holds the one key actually listed in
  # stackbase.deploy.keys; `stranger` is never listed anywhere (proves an
  # unknown key is denied); `admin` is listed under stackbase.admins, not
  # stackbase.deploy.keys (proves an admin key doesn't also work for the
  # `deploy` account).
  testKeypair = name: pkgs.runCommand "stackbase-test-key-${name}" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir -p "$out"
    ssh-keygen -q -t ed25519 -N "" -f "$out/id_ed25519" -C "${name}"
  '';
  clientKeypair = testKeypair "client";
  strangerKeypair = testKeypair "stranger";
  adminKeypair = testKeypair "admin";
  pubKeyOf = drv: lib.removeSuffix "\n" (builtins.readFile "${drv}/id_ed25519.pub");

  fakeApp = ''
    #!/usr/bin/env python3
    import http.server
    import os
    import socket

    VERSION = "__VERSION__"
    HEALTH_CODE = __HEALTH_CODE__
    SOCKET_PATH = os.environ["SOCKET_PATH"]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(HEALTH_CODE)
                self.end_headers()
                self.wfile.write(b"ok" if HEALTH_CODE < 300 else b"broken")
            elif self.path == "/version":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(VERSION.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            pass

    class UnixHTTPServer(http.server.HTTPServer):
        address_family = socket.AF_UNIX

    try:
        os.remove(SOCKET_PATH)
    except FileNotFoundError:
        pass

    httpd = UnixHTTPServer(SOCKET_PATH, Handler)
    httpd.serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "stackbase-vm-deploy";

  nodes = {
    node =
      { nodes, ... }:
      {
        imports = [
          self.nixosModules.base
          self.nixosModules.appHost
          self.nixosModules.deploy
        ];

        stackbase.project = project;
        stackbase.domain = domain;
        stackbase.deploy.drainSeconds = 2;
        # Small enough to be reliably exceeded by a deliberately oversized
        # test upload, comfortably larger than every real test tarball
        # (a few KB at most) so none of the legitimate upload subtests
        # trip it.
        stackbase.deploy.maxUploadBytes = 65536;

        # The one key actually allowed to drive stack-deploy over SSH.
        stackbase.deploy.keys.testclient = pubKeyOf clientKeypair;
        # An admin account (wheel + sudo, per base.nix) -- NOT a
        # stackbase.deploy.keys entry. Its key must not also work for the
        # `deploy` account.
        stackbase.admins.testadmin = pubKeyOf adminKeypair;

        stackbase.allowedProxyRanges = lib.mkForce [
          "${nodes.proxy.networking.primaryIPAddress}/32"
        ];

        environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.e2fsprogs ];

        environment.etc."stackbase-test/fake-app.py".text = fakeApp;

        system.stateVersion = "26.05";
      };

    proxy =
      { ... }:
      {
        environment.systemPackages = [ pkgs.curl ];
        system.stateVersion = "26.05";
      };

    # Holds the SSH client and every test keypair's private half, and
    # everything needed to build a release tarball locally (mirroring
    # make_tarball on `node`) so the upload protocol's stdin-streaming
    # path is exercised with a real client-to-node byte stream, not a
    # file already sitting on the node.
    client =
      { ... }:
      {
        environment.systemPackages = [ pkgs.openssh pkgs.gnutar pkgs.gzip pkgs.coreutils pkgs.curl ];
        environment.etc."stackbase-test/fake-app.py".text = fakeApp;
        environment.etc."deploy-test/client_id_ed25519" = {
          source = "${clientKeypair}/id_ed25519";
          mode = "0600";
        };
        environment.etc."deploy-test/stranger_id_ed25519" = {
          source = "${strangerKeypair}/id_ed25519";
          mode = "0600";
        };
        environment.etc."deploy-test/admin_id_ed25519" = {
          source = "${adminKeypair}/id_ed25519";
          mode = "0600";
        };
        system.stateVersion = "26.05";
      };
  };

  testScript =
    { nodes, ... }:
    ''
      start_all()

      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("nginx.service")
      proxy.wait_for_unit("multi-user.target")
      client.wait_for_unit("multi-user.target")

      node_ip = "${nodes.node.networking.primaryIPAddress}"
      STATE_DIR = "${stateDir}"
      curl_version = (
          "curl -sk -o /tmp/vbody -w '%{http_code}' "
          f"--resolve ${domain}:443:{node_ip} https://${domain}/version"
      )

      def make_release(version, health_code=200):
          "Write a release binary straight into releases/<version>/${project} (the 'already unpacked' deploy path)."
          node.succeed(
              f"sed -e 's/__VERSION__/{version}/' -e 's/__HEALTH_CODE__/{health_code}/' "
              f"/etc/stackbase-test/fake-app.py > /tmp/{version}-bin && "
              f"install -D -m0755 /tmp/{version}-bin /opt/${project}/releases/{version}/${project}"
          )

      def parse_colors(s):
          "Parse 'active=X idle=Y' into (active, idle)."
          parts = dict(kv.split("=", 1) for kv in s.strip().split())
          return parts["active"], parts["idle"]

      def make_tarball(version, health_code=200, setuid_binary=False, extra_world_writable_file=None):
          "Build a flat tarball (binary at the archive root) for the --tarball deploy path; returns its sha256."
          setup = ""
          members = "${project}"
          if setuid_binary:
              setup += "chmod 4755 /tmp/pkg/${project} && "
          if extra_world_writable_file:
              setup += (
                  f"echo hello > /tmp/pkg/{extra_world_writable_file} && "
                  f"chmod 0666 /tmp/pkg/{extra_world_writable_file} && "
              )
              members += f" {extra_world_writable_file}"
          node.succeed(
              "rm -rf /tmp/pkg && mkdir -p /tmp/pkg && "
              f"sed -e 's/__VERSION__/{version}/' -e 's/__HEALTH_CODE__/{health_code}/' "
              f"/etc/stackbase-test/fake-app.py > /tmp/pkg/${project} && "
              f"chmod +x /tmp/pkg/${project} && "
              f"{setup}"
              f"tar -czf /tmp/{version}.tar.gz -C /tmp/pkg {members}"
          )
          return node.succeed(f"sha256sum /tmp/{version}.tar.gz | cut -d' ' -f1").strip()

      with subtest("before any deploy: colors defaults to active=none idle=blue"):
          out = node.succeed("stack-deploy colors").strip()
          assert out == "active=none idle=blue", f"unexpected colors output: {out!r}"

      with subtest("first deploy (via --tarball) goes live on blue"):
          sha = make_tarball("v1.0.0")
          node.succeed(f"${fastHealth} stack-deploy deploy v1.0.0 --tarball /tmp/v1.0.0.tar.gz --sha256 {sha}")

          assert node.succeed("stack-deploy colors").strip() == "active=blue idle=green"
          assert node.succeed(f"cat {STATE_DIR}/active-color").strip() == "blue"
          assert node.succeed("readlink /run/${project}/app.sock").strip() == "app-blue.sock"

          # The fake app never touches its socket's mode -- this must come
          # entirely from the app unit's UMask (nixos/deploy.nix), the same
          # way a real (platform-base) app's bare UnixListener::bind() gets
          # a connectable socket.
          sock_stat = node.succeed("stat -c '%a %G' /run/${project}/app-blue.sock").strip()
          assert sock_stat == "770 ${project}-sock", f"expected socket mode 770, group ${project}-sock; got {sock_stat!r}"

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.0.0", f"expected 200/v1.0.0, got {code}/{body!r}"

      with subtest("second deploy goes live on green; zero downtime; blue stops after drain"):
          make_release("v1.1.0")

          # Fully detached: stdin/stdout/stderr must all be redirected away
          # from the inherited console pipe, or the test driver's
          # execute() blocks forever waiting for that pipe to close, since
          # the backgrounded loop still holds it open (bare `&` alone
          # isn't enough for a truly detached job).
          status, pid_out = proxy.execute(
              "rm -f /tmp/loop.log; "
              "( while true; do "
              f"code=$(curl -sk -o /tmp/vbody2 -w '%{{http_code}}' --resolve ${domain}:443:{node_ip} https://${domain}/version 2>/dev/null); "
              "echo \"$code $(cat /tmp/vbody2 2>/dev/null)\" >> /tmp/loop.log; "
              "sleep 0.05; done ) </dev/null >/dev/null 2>&1 & echo $!"
          )
          assert status == 0, f"failed to start the background curl loop: {pid_out}"
          loop_pid = pid_out.strip()

          node.succeed("${fastHealth} stack-deploy deploy v1.1.0")

          proxy.succeed("sleep 1")
          proxy.succeed(f"kill {loop_pid} 2>/dev/null || true")

          assert node.succeed("stack-deploy colors").strip() == "active=green idle=blue"

          loop_log = proxy.succeed("cat /tmp/loop.log")
          lines = [l for l in loop_log.splitlines() if l.strip()]
          assert lines, "the background curl loop recorded no requests at all"
          codes = {l.split()[0] for l in lines}
          bodies = {l.split()[1] for l in lines if len(l.split()) > 1}
          assert codes == {"200"}, f"saw a non-200 response during the swap: {codes}"
          assert {"v1.0.0", "v1.1.0"} <= bodies, f"never observed both versions during the swap: {bodies}"

          # Right after the swap, drainSeconds (2s) hasn't elapsed yet --
          # blue must still be running.
          node.succeed("systemctl is-active --quiet ${project}@blue.service")
          node.wait_until_succeeds("! systemctl is-active --quiet ${project}@blue.service", timeout=15)

      with subtest("a broken release cannot clobber the rollback target; rollback then succeeds to v1 (I2)"):
          # Idle is blue, still linked to v1.0.0 (untouched by the swap
          # above -- only green's link changed). Deploying a broken
          # release onto blue must not leave blue/current pointing at it.
          make_release("v1.2.0", health_code=500)

          # execute() runs the command under `set -e`, so a trailing
          # `; echo EXIT:$?` would never run once `stack-deploy` itself
          # exits non-zero -- use the (status, output) tuple execute()
          # already returns instead.
          status, out = node.execute("${brokenHealth} stack-deploy deploy v1.2.0")
          assert status == 1, f"expected exit 1 for a broken release, got status={status}, output={out!r}"

          blue_target = node.succeed("readlink /opt/${project}/blue/current").strip()
          assert blue_target == "../releases/v1.0.0", f"blue/current must be restored to v1.0.0, got {blue_target!r}"

          assert node.succeed("stack-deploy colors").strip() == "active=green idle=blue"
          assert node.succeed(f"cat {STATE_DIR}/active-color").strip() == "green"
          assert node.succeed("readlink /run/${project}/app.sock").strip() == "app-green.sock"
          node.fail("systemctl is-active --quiet ${project}@blue.service")

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.1.0", f"production should be unaffected by the broken deploy, got {code}/{body!r}"

          node.succeed("${fastHealth} stack-deploy rollback")
          assert node.succeed("stack-deploy colors").strip() == "active=blue idle=green"
          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.0.0", f"expected 200/v1.0.0 after rollback, got {code}/{body!r}"
          node.wait_until_succeeds("! systemctl is-active --quiet ${project}@green.service", timeout=15)

      with subtest("an invalid version string is rejected before touching disk"):
          status, out = node.execute("stack-deploy deploy v1.2")
          assert status == 2, f"expected exit 2 for an invalid version, got status={status}, output={out!r}"
          node.fail("test -e /opt/${project}/releases/v1.2")

      with subtest("a second concurrent deploy is refused with exit 3"):
          # Fully detached (see the zero-downtime loop above for why):
          # otherwise execute() would block here for the holder's whole
          # 5s, and the lock would already be free by the time the
          # concurrent deploy below runs.
          node.execute(f"flock {STATE_DIR}/deploy.lock sleep 5 </dev/null >/dev/null 2>&1 & sleep 1")
          status, out = node.execute("stack-deploy deploy v1.3.0")
          assert status == 3, f"expected exit 3 while the lock is held, got status={status}, output={out!r}"
          # let the holder release before continuing
          node.succeed("sleep 5")

      with subtest("prune keeps the 5 highest by SemVer, never a linked release, v1.10.0 outranks v1.9.0"):
          # Existing on disk: v1.0.0 (linked blue), v1.1.0 (linked green),
          # v1.2.0 (unlinked -- restored away from it above). Round out to
          # 8 releases, including one (v0.9.0) below both linked ones so
          # pruning still has something unprotected to remove even though
          # the two lowest-by-SemVer releases happen to both be linked.
          for v in ["v0.9.0", "v1.3.0", "v1.4.0", "v1.9.0", "v1.10.0"]:
              node.succeed(f"mkdir -p /opt/${project}/releases/{v}")

          before = set(node.succeed("ls /opt/${project}/releases").split())
          assert before == {
              "v0.9.0", "v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.9.0", "v1.10.0",
          }, f"unexpected release set going into prune: {before}"

          node.succeed("stack-deploy prune")
          after = set(node.succeed("ls /opt/${project}/releases").split())
          # keep=5 highest (v1.2.0 v1.3.0 v1.4.0 v1.9.0 v1.10.0) plus the
          # linked v1.0.0/v1.1.0, which rank below the keep-5 cutoff but
          # are protected; only the unlinked, unprotected v0.9.0 is
          # removed.
          assert after == {
              "v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.9.0", "v1.10.0",
          }, f"unexpected release set after prune: {after}"

          node.succeed("stack-deploy prune 1")
          after2 = set(node.succeed("ls /opt/${project}/releases").split())
          # keep=1 highest (v1.10.0) plus the two still-linked releases.
          assert after2 == {"v1.0.0", "v1.1.0", "v1.10.0"}, f"unexpected release set after prune 1: {after2}"

      with subtest("reboot: the active color comes back and /version is served again"):
          before_colors = node.succeed("stack-deploy colors").strip()
          assert before_colors == "active=blue idle=green", before_colors

          # .reboot() (ctrl-alt-delete) only reconnects when the machine
          # was started with allow_reboot=True; start_all() doesn't pass
          # that. shutdown() + start() is the standard nixos-test idiom
          # for simulating a reboot instead -- the backing disk image
          # persists across it, only /run (tmpfs) is wiped, which is
          # exactly the boot-recovery path being tested here.
          node.shutdown()
          node.start()

          node.wait_for_unit("multi-user.target")
          node.wait_for_unit("nginx.service")
          node.wait_for_unit("stackbase-app-boot.service")
          node.wait_until_succeeds("systemctl is-active --quiet ${project}@blue.service", timeout=30)

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.0.0", f"expected 200/v1.0.0 after reboot, got {code}/{body!r}"

      with subtest("boot resumes a swap interrupted between the app.sock flip and the state write (I3)"):
          # Simulate the crash window in activate_color: pending-color
          # says the swap was heading to green, but active-color was
          # never updated off blue (green is still linked+healthy from
          # earlier, so resuming it is legitimate).
          assert node.succeed("stack-deploy colors").strip() == "active=blue idle=green"
          node.succeed(f"echo green > {STATE_DIR}/pending-color")

          node.shutdown()
          node.start()

          node.wait_for_unit("multi-user.target")
          node.wait_for_unit("nginx.service")
          node.wait_for_unit("stackbase-app-boot.service")

          assert node.succeed("stack-deploy colors").strip() == "active=green idle=blue"
          node.fail(f"test -e {STATE_DIR}/pending-color")

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.1.0", (
              f"expected green/v1.1.0 to be serving after resuming the interrupted swap, got {code}/{body!r}"
          )

      with subtest("boot: pending-color with no linked release is discarded, falls back to active-color (I3)"):
          node.succeed("mv /opt/${project}/blue/current /tmp/blue-current-backup")
          node.succeed(f"echo blue > {STATE_DIR}/pending-color")

          # execute()'s (status, output) only captures stdout by default
          # (its internal wrapper pipes stdout alone into base64, no
          # `2>&1`) -- redirect stderr into stdout ourselves so the
          # diagnostic (written via `>&2`) shows up in `out`.
          status, out = node.execute("stack-deploy boot 2>&1")
          assert status == 0, f"expected boot to fall back cleanly, got status={status} output={out!r}"
          assert "has no linked release; discarding" in out, out

          assert node.succeed("stack-deploy colors").strip() == "active=green idle=blue"
          node.fail(f"test -e {STATE_DIR}/pending-color")

          node.succeed("mv /tmp/blue-current-backup /opt/${project}/blue/current")

      with subtest("boot: active color with no linked release fails with a clear message (I3)"):
          node.succeed("mv /opt/${project}/green/current /tmp/green-current-backup")

          status, out = node.execute("stack-deploy boot 2>&1")
          assert status == 1, f"expected boot to fail cleanly when active's link is missing, got status={status}"
          assert "has no linked release" in out and "redeploy to recover" in out, (
              f"expected a clear diagnostic, not an opaque unit failure, got: {out!r}"
          )

          node.succeed("mv /tmp/green-current-backup /opt/${project}/green/current")

      with subtest("a tarball containing a symlink member is rejected, leaves nothing in releases/ (C1)"):
          node.succeed(
              "rm -rf /tmp/evilpkg && mkdir -p /tmp/evilpkg && "
              "ln -s /etc /tmp/evilpkg/evil && "
              "tar -czf /tmp/v1.8.0.tar.gz -C /tmp/evilpkg evil"
          )
          sha = node.succeed("sha256sum /tmp/v1.8.0.tar.gz | cut -d' ' -f1").strip()
          status, out = node.execute(f"stack-deploy deploy v1.8.0 --tarball /tmp/v1.8.0.tar.gz --sha256 {sha}")
          assert status == 1, f"expected exit 1 for a tarball containing a symlink member, got status={status}, output={out!r}"
          node.fail("test -e /opt/${project}/releases/v1.8.0")

      with subtest("a setuid binary and a world-writable file are normalised to 0755/0644 on unpack (C1)"):
          sha = make_tarball("v2.0.0", setuid_binary=True, extra_world_writable_file="extra.txt")
          node.succeed(f"${fastHealth} stack-deploy deploy v2.0.0 --tarball /tmp/v2.0.0.tar.gz --sha256 {sha}")

          release_dir = "/opt/${project}/releases/v2.0.0"
          dir_mode = node.succeed(f"stat -c '%a' {release_dir}").strip()
          binary_mode = node.succeed(f"stat -c '%a' {release_dir}/${project}").strip()
          extra_mode = node.succeed(f"stat -c '%a' {release_dir}/extra.txt").strip()
          assert dir_mode == "755", f"expected the release dir to be normalised to 0755, got {dir_mode}"
          assert binary_mode == "755", f"expected the setuid binary to be normalised to 0755, got {binary_mode}"
          assert extra_mode == "644", f"expected the world-writable file to be normalised to 0644, got {extra_mode}"

      with subtest("releases/ and a release dir inside it are not writable by the app user (C2)"):
          node.fail("runuser -u ${project} -- touch /opt/${project}/releases/should-fail")
          node.fail("runuser -u ${project} -- mkdir /opt/${project}/releases/should-fail-dir")
          node.fail("runuser -u ${project} -- rm -rf /opt/${project}/releases/v1.0.0")
          node.fail("runuser -u ${project} -- touch /opt/${project}/releases/v1.1.0/should-fail")
          # -f: plain `rm` on a file the caller can't write (independent
          # of whether the parent directory would even allow the unlink)
          # prompts interactively instead of failing outright, which
          # hangs here since nothing is attached to answer it.
          node.fail("runuser -u ${project} -- rm -f /opt/${project}/releases/v1.1.0/${project}")

      with subtest("deploy is not in <project>'s group; app.env secrets stay out of its reach (I1)"):
          groups = node.succeed("id -Gn deploy").strip().split()
          assert "${project}" not in groups, f"deploy must not be a member of ${project}: {groups}"
          assert "${project}-sock" in groups, f"deploy should still be a member of ${project}-sock: {groups}"

          node.succeed("install -D -m0640 -o root -g ${project} /dev/null /var/lib/stackbase/app.env")
          node.succeed("echo 'SOME_SECRET=shh' > /var/lib/stackbase/app.env")
          node.fail("runuser -u deploy -- cat /var/lib/stackbase/app.env")
          # root -- and so stack-deploy running as root, e.g. via the
          # boot unit or an operator's own session -- is unaffected, and
          # the app.sock symlink flip keeps working under the new group
          # split (proven throughout this test, all as root; reconfirmed
          # explicitly here).
          node.succeed("cat /var/lib/stackbase/app.env")
          assert node.succeed("stack-deploy colors").strip().startswith("active=")

      with subtest("a tarball with an absolute-path member is rejected, nothing left in releases/ (N1a)"):
          # `tar -P` disables GNU tar's default leading-slash stripping,
          # so the member is stored (and listed) with its leading '/'
          # intact. Content is a few bytes -- small enough to trigger the
          # verbose listing's right-justified size-column padding that
          # broke the old name-recovery logic.
          node.succeed(
              "rm -rf /tmp/abspkg && mkdir -p /tmp/abspkg && "
              "echo hi > /tmp/abspkg/evil.txt && "
              "tar -P -czf /tmp/v1.20.0.tar.gz /tmp/abspkg/evil.txt"
          )
          sha = node.succeed("sha256sum /tmp/v1.20.0.tar.gz | cut -d' ' -f1").strip()
          status, out = node.execute(
              f"stack-deploy deploy v1.20.0 --tarball /tmp/v1.20.0.tar.gz --sha256 {sha} 2>&1"
          )
          assert status == 1, f"expected exit 1 for an absolute-path member, got status={status}, output={out!r}"
          node.fail("test -e /opt/${project}/releases/v1.20.0")

      with subtest("a tarball with a '..' path-component member is rejected, nothing left in releases/ (N1b)"):
          # --transform renames the stored member to include a '..'
          # component; GNU tar applies no safety check at creation time.
          # Content is again a few bytes, for the same padding reason.
          node.succeed(
              "rm -rf /tmp/dotpkg && mkdir -p /tmp/dotpkg && "
              "echo hi > /tmp/dotpkg/evil.txt && "
              "tar -czf /tmp/v1.21.0.tar.gz --transform 's,^evil.txt,../evil.txt,' -C /tmp/dotpkg evil.txt"
          )
          sha = node.succeed("sha256sum /tmp/v1.21.0.tar.gz | cut -d' ' -f1").strip()
          status, out = node.execute(
              f"stack-deploy deploy v1.21.0 --tarball /tmp/v1.21.0.tar.gz --sha256 {sha} 2>&1"
          )
          assert status == 1, f"expected exit 1 for a '..' member, got status={status}, output={out!r}"
          node.fail("test -e /opt/${project}/releases/v1.21.0")

      with subtest("a release with tiny files and a spaced file name deploys fine (N1c)"):
          # Regression guard for the fix itself: small files (well under
          # the ~1000-byte padding threshold) and a name containing
          # spaces must NOT be false-rejected by the new name recovery.
          node.succeed(
              "rm -rf /tmp/spacepkg && mkdir -p /tmp/spacepkg && "
              "sed -e 's/__VERSION__/v1.22.0/' -e 's/__HEALTH_CODE__/200/' "
              "/etc/stackbase-test/fake-app.py > '/tmp/spacepkg/${project}' && "
              "chmod +x '/tmp/spacepkg/${project}' && "
              "echo hi > '/tmp/spacepkg/read me.txt' && "
              "tar -czf /tmp/v1.22.0.tar.gz -C /tmp/spacepkg '${project}' 'read me.txt'"
          )
          sha = node.succeed("sha256sum /tmp/v1.22.0.tar.gz | cut -d' ' -f1").strip()
          node.succeed(f"${fastHealth} stack-deploy deploy v1.22.0 --tarball /tmp/v1.22.0.tar.gz --sha256 {sha}")
          node.succeed("test -e '/opt/${project}/releases/v1.22.0/read me.txt'")

      with subtest("pre-flip failure (idle unit cannot start, not the health check) leaves state untouched and restores the idle link (N2-A)"):
          active_color, idle_color = parse_colors(node.succeed("stack-deploy colors").strip())
          idle_link = "/opt/${project}/" + idle_color + "/current"
          prev_target = node.succeed(f"readlink {idle_link}").strip()
          active_before = node.succeed(f"cat {STATE_DIR}/active-color").strip()
          sock_before = node.succeed("readlink /run/${project}/app.sock").strip()

          # Release dir exists, but its binary is present-yet-not-executable
          # -- systemd's ExecStart fails outright (permission denied)
          # before the health check is ever reached.
          node.succeed(
              "rm -rf /opt/${project}/releases/v1.30.0 && "
              "install -D -m0644 /dev/null /opt/${project}/releases/v1.30.0/${project}"
          )

          status, out = node.execute("${brokenHealth} stack-deploy deploy v1.30.0 2>&1")
          assert status == 1, f"expected exit 1, got status={status}, output={out!r}"
          assert "bookkeeping is incomplete" not in out, (
              f"a pre-flip failure must not print the post-flip loud message: {out!r}"
          )

          assert node.succeed(f"readlink {idle_link}").strip() == prev_target, (
              "idle color's current link must be restored on a pre-flip failure"
          )
          active_color_after = node.succeed(f"cat {STATE_DIR}/active-color").strip()
          assert active_color_after == active_before, f"active-color must be untouched, expected {active_before!r} got {active_color_after!r}"
          sock_after = node.succeed("readlink /run/${project}/app.sock").strip()
          assert sock_after == sock_before, f"app.sock must be untouched, expected {sock_before!r} got {sock_after!r}"
          node.succeed(f"systemctl is-active --quiet ${project}@{active_color}.service")

      with subtest("post-flip failure (active-color unwritable) leaves traffic on the new color; a later boot converges (N2-B)"):
          active_color, idle_color = parse_colors(node.succeed("stack-deploy colors").strip())

          node.succeed(f"chattr +i {STATE_DIR}/active-color")
          try:
              status, out = node.execute("${fastHealth} stack-deploy rollback 2>&1")
              assert status == 1, f"expected exit 1, got status={status}, output={out!r}"
              assert "bookkeeping is incomplete" in out, f"expected the loud post-flip message, got: {out!r}"

              assert node.succeed("readlink /run/${project}/app.sock").strip() == f"app-{idle_color}.sock", (
                  "traffic must already be on the new color despite the failed active-color write"
              )
              node.succeed(f"systemctl is-active --quiet ${project}@{idle_color}.service")
              node.succeed(f"test -e {STATE_DIR}/pending-color")
              assert node.succeed(f"cat {STATE_DIR}/active-color").strip() == active_color, (
                  "active-color must still read the stale value -- the write never landed"
              )
          finally:
              node.succeed(f"chattr -i {STATE_DIR}/active-color")

          node.succeed("stack-deploy boot")
          active_color_converged = node.succeed(f"cat {STATE_DIR}/active-color").strip()
          assert active_color_converged == idle_color, f"expected active-color to converge to {idle_color!r}, got {active_color_converged!r}"
          node.fail(f"test -e {STATE_DIR}/pending-color")
          colors_converged = node.succeed("stack-deploy colors").strip()
          assert colors_converged == f"active={idle_color} idle={active_color}", (
              f"expected active={idle_color} idle={active_color}, got {colors_converged!r}"
          )

      with subtest("boot: pending-color whose release binary is missing falls back to active-color, which still comes up (N3)"):
          active_color, idle_color = parse_colors(node.succeed("stack-deploy colors").strip())
          idle_target = node.succeed("readlink -f /opt/${project}/" + idle_color + "/current").strip()
          # The idle color was left running by the previous (N2-B) subtest
          # -- a post-flip failure deliberately skips drain-scheduling, so
          # nothing ever stopped it. `systemctl start` on an
          # already-active unit is a no-op that would silently pass this
          # test for the wrong reason (the OLD process, still holding its
          # unlinked binary open, would keep answering health checks even
          # after we move the file). Stop it first so resolve_pending_color
          # has to genuinely fork+exec the missing binary.
          node.succeed(f"systemctl stop ${project}@{idle_color}.service")
          node.succeed(f"mv {idle_target}/${project} /tmp/n3-binary-backup")
          node.succeed(f"echo {idle_color} > {STATE_DIR}/pending-color")

          status, out = node.execute("${brokenHealth} stack-deploy boot 2>&1")
          assert status == 0, f"expected boot to still bring the active color up, got status={status}, output={out!r}"

          colors_after = node.succeed("stack-deploy colors").strip()
          assert colors_after == f"active={active_color} idle={idle_color}", (
              f"expected active={active_color} idle={idle_color}, got {colors_after!r}; boot output was {out!r}"
          )
          node.fail(f"test -e {STATE_DIR}/pending-color")
          node.succeed(f"systemctl is-active --quiet ${project}@{active_color}.service")

          node.succeed(f"mv /tmp/n3-binary-backup {idle_target}/${project}")

      # -----------------------------------------------------------------
      # Task 2: the restricted SSH door (deploy@node, forced command)
      # -----------------------------------------------------------------

      import shlex

      SSH_OPTS = (
          "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o BatchMode=yes -o ConnectTimeout=5 -o IdentitiesOnly=yes"
      )
      CLIENT_KEY = "/etc/deploy-test/client_id_ed25519"
      STRANGER_KEY = "/etc/deploy-test/stranger_id_ed25519"
      ADMIN_KEY = "/etc/deploy-test/admin_id_ed25519"

      def ssh(cmd, key=CLIENT_KEY, extra=""):
          "Runs `cmd` as the literal SSH_ORIGINAL_COMMAND against deploy@node. cmd=None omits the command argument entirely (a bare interactive-login attempt)."
          arg = "" if cmd is None else shlex.quote(cmd)
          # -n: redirect local stdin from /dev/null. None of these calls
          # ever need to relay real stdin (ssh_upload, below, builds its
          # own command with a `< file` redirect instead and deliberately
          # does NOT use -n, which would override that). Without it, a
          # command-less invocation (cmd=None, testing the bare
          # interactive-login-attempt case) tries to keep relaying this
          # non-tty test shell's own stdin to the remote session
          # indefinitely, hanging until the test driver's own call
          # timeout kills it (status 124) instead of the forced command's
          # prompt exit 2.
          # timeout 20: a blanket bound on every one of these calls, so a
          # future protocol surprise blocks this one subtest for at most
          # 20s instead of hanging the whole build until something else
          # kills it (see the -L/-R subtest below for exactly that
          # failure mode, hit for real during development).
          full = f"timeout 20 ssh {SSH_OPTS} -n {extra} -i {key} deploy@{node_ip} {arg}".strip()
          return client.execute(f"{full} 2>&1")

      def incoming_files():
          return set(node.succeed(f"ls {STATE_DIR}/incoming 2>/dev/null || true").split())

      def release_set():
          return set(node.succeed("ls /opt/${project}/releases").split())

      def client_make_tarball(version, health_code=200):
          "Build a flat tarball on the CLIENT (mirrors make_tarball on node) so `upload` streams real client->node bytes over ssh."
          client.succeed(
              "rm -rf /tmp/pkg && mkdir -p /tmp/pkg && "
              f"sed -e 's/__VERSION__/{version}/' -e 's/__HEALTH_CODE__/{health_code}/' "
              "/etc/stackbase-test/fake-app.py > /tmp/pkg/${project} && "
              "chmod +x /tmp/pkg/${project} && "
              f"tar -czf /tmp/{version}.tar.gz -C /tmp/pkg ${project}"
          )
          return client.succeed(f"sha256sum /tmp/{version}.tar.gz | cut -d' ' -f1").strip()

      def ssh_upload(version, sha, key=CLIENT_KEY):
          "Pipes /tmp/<version>.tar.gz on the CLIENT into `ssh ... 'upload <version> <sha>'`'s stdin."
          cmd = f"upload {version} {sha}"
          full = f"timeout 20 ssh {SSH_OPTS} -i {key} deploy@{node_ip} {shlex.quote(cmd)} < /tmp/{version}.tar.gz 2>&1"
          return client.execute(full)

      with subtest("ssh deploy@node status works over the forced command"):
          status, out = ssh("status")
          assert status == 0, f"expected exit 0, got {status}, output={out!r}"
          # This is the FIRST ssh connection in the whole test, so the
          # output also carries OpenSSH's one-time "Warning: Permanently
          # added ... to the list of known hosts." TOFU line ahead of the
          # actual command output -- check for the real payload rather
          # than assuming it's the first line.
          assert "active=" in out, f"unexpected status output: {out!r}"

      with subtest("VERSION_GREP (engine) and VERSION_RE (ssh dispatcher) come from one substituted source and stay identical (F3)"):
          # Both scripts get their version-grammar regex substituted at
          # build time from the SAME nixos/deploy.nix `versionRegex`
          # binding -- previously each script carried its own hand-copied
          # literal, kept in sync only by a comment. Read each BUILT
          # script's own constant back (not the Nix source) so a future
          # substitution or quoting mistake would actually be caught here.
          engine_re = node.succeed(
              "awk -F\"'\" '/^VERSION_GREP=/{print $2}' \"$(command -v stack-deploy)\""
          ).strip()
          ssh_re = node.succeed(
              "awk -F\"'\" '/^VERSION_RE=/{print $2}' \"$(command -v stack-deploy-ssh)\""
          ).strip()
          expected = r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
          assert engine_re == expected, f"stack-deploy's VERSION_GREP diverged from the expected grammar: {engine_re!r}"
          assert ssh_re == expected, f"stack-deploy-ssh's VERSION_RE diverged from the expected grammar: {ssh_re!r}"
          assert engine_re == ssh_re, f"VERSION_GREP and VERSION_RE diverged: {engine_re!r} vs {ssh_re!r}"

      with subtest("full upload -> deploy -> status -> rollback round trip over ssh, as deploy"):
          before_active, before_idle = parse_colors(node.succeed("stack-deploy colors").strip())

          sha = client_make_tarball("v3.0.0")
          status, out = ssh_upload("v3.0.0", sha)
          assert status == 0, f"upload over ssh failed: status={status} output={out!r}"
          node.succeed("test -d /opt/${project}/releases/v3.0.0")
          node.fail(f"test -e {STATE_DIR}/incoming/v3.0.0.tar.gz")
          node.fail(f"test -e {STATE_DIR}/incoming/v3.0.0.tar.gz.partial")

          status, out = ssh("deploy v3.0.0")
          assert status == 0, f"deploy over ssh failed: status={status} output={out!r}"

          active_after, _ = parse_colors(node.succeed("stack-deploy colors").strip())
          assert active_after == before_idle, f"expected the swap to land on {before_idle}, got {active_after}"

          status, out = ssh("status")
          assert status == 0, f"status over ssh failed: status={status} output={out!r}"
          assert "v3.0.0" in out, f"expected status to mention v3.0.0, got {out!r}"

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v3.0.0", f"expected v3.0.0 live after an ssh-driven deploy, got {code}/{body!r}"

          status, out = ssh("rollback")
          assert status == 0, f"rollback over ssh failed: status={status} output={out!r}"
          active_final, _ = parse_colors(node.succeed("stack-deploy colors").strip())
          assert active_final == before_active, f"expected rollback to land back on {before_active}, got {active_final}"

      with subtest("zero-downtime swap driven entirely over ssh"):
          before_active, before_idle = parse_colors(node.succeed("stack-deploy colors").strip())
          sha = client_make_tarball("v3.1.0")
          status, out = ssh_upload("v3.1.0", sha)
          assert status == 0, f"upload over ssh failed: {out!r}"

          status, pid_out = proxy.execute(
              "rm -f /tmp/loop2.log; "
              "( while true; do "
              f"code=$(curl -sk -o /tmp/vbody3 -w '%{{http_code}}' --resolve ${domain}:443:{node_ip} https://${domain}/version 2>/dev/null); "
              "echo \"$code $(cat /tmp/vbody3 2>/dev/null)\" >> /tmp/loop2.log; "
              "sleep 0.05; done ) </dev/null >/dev/null 2>&1 & echo $!"
          )
          assert status == 0, f"failed to start the background curl loop: {pid_out}"
          loop_pid = pid_out.strip()

          status, out = ssh("deploy v3.1.0")
          assert status == 0, f"deploy over ssh failed: status={status} output={out!r}"

          proxy.succeed("sleep 1")
          proxy.succeed(f"kill {loop_pid} 2>/dev/null || true")

          active_after, _ = parse_colors(node.succeed("stack-deploy colors").strip())
          assert active_after == before_idle

          loop_log = proxy.succeed("cat /tmp/loop2.log")
          lines = [l for l in loop_log.splitlines() if l.strip()]
          assert lines, "the background curl loop recorded no requests at all"
          codes = {l.split()[0] for l in lines}
          bodies = {l.split()[1] for l in lines if len(l.split()) > 1}
          assert codes == {"200"}, f"saw a non-200 response during an ssh-driven swap: {codes}"
          assert "v3.1.0" in bodies, f"never observed the new version during an ssh-driven swap: {bodies}"

      with subtest("a leftover pending-color is resolved when the next command arrives over ssh, as deploy (I3, over ssh)"):
          active_before, idle_before = parse_colors(node.succeed("stack-deploy colors").strip())
          # Simulate the crash window (see activate_color/I3): pending-color
          # says the swap to idle_before happened, but active-color was
          # never updated off active_before. idle_before already carries a
          # healthy linked release from earlier in the suite.
          node.succeed(f"echo {idle_before} > {STATE_DIR}/pending-color")

          sha = client_make_tarball("v3.2.0")
          status, out = ssh_upload("v3.2.0", sha)
          assert status == 0, f"upload over ssh failed: {out!r}"

          # The next command to arrive over ssh is `deploy` -- its first act
          # (resolve_pending_color, shared with rollback/boot) must finish
          # the interrupted swap to idle_before before this new deploy of
          # v3.2.0 proceeds onto what is then the (newly) idle color
          # (active_before).
          status, out = ssh("deploy v3.2.0")
          assert status == 0, f"deploy over ssh failed to resolve the pending swap: status={status} output={out!r}"
          node.fail(f"test -e {STATE_DIR}/pending-color")

          active_final, _ = parse_colors(node.succeed("stack-deploy colors").strip())
          assert active_final == active_before, (
              f"expected active to return to {active_before} after resolving the pending swap to {idle_before} "
              f"and deploying v3.2.0 on top of it, got {active_final}"
          )
          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v3.2.0", f"expected v3.2.0 live, got {code}/{body!r}"

      with subtest("the forced command refuses anything outside the protocol, with no side effects"):
          before_releases = release_set()
          before_incoming = incoming_files()

          bad_attempts = [
              ("no command at all (bare interactive login attempt)", None),
              ("bash", "bash"),
              ("status; id", "status; id"),
              ("status && id", "status && id"),
              ("command substitution as the command", "$(id)"),
              ("backticks as the command", "`id`"),
              ("a newline embedded in the command", "status\nid"),
              ("upload with an extra word", "upload v1.0.0 " + "0" * 64 + " extra"),
              ("a version with a shell metacharacter", "deploy v1.0.0;id"),
              ("a version with a path-traversal component", "deploy ../x"),
          ]

          for label, cmd in bad_attempts:
              status, out = ssh(cmd)
              assert status == 2, f"[{label}] expected exit 2, got status={status} output={out!r}"
              assert "uid=" not in out, f"[{label}] 'id' appears to have run: {out!r}"

          assert release_set() == before_releases, "a refused command left a new release behind"
          assert incoming_files() == before_incoming, "a refused command left something under incoming/"

      with subtest("ssh -t requests a PTY but none is granted (restrict)"):
          # Provoking and interpreting LIVE pty-req negotiation from this
          # non-interactive test shell proved unreliable across several
          # attempts: a plain -t never even reaches the server (OpenSSH's
          # client-side heuristic sees stdin isn't a terminal and silently
          # skips sending the request, printing its own unrelated local
          # notice instead); forcing it with -tt hangs this environment
          # instead (status 124) rather than producing a clean local
          # denial message either. The one thing all of that live
          # negotiation is meant to prove -- that `restrict` (which
          # unconditionally implies no-pty, among other things) is
          # actually the option guarding every deploy.keys entry -- is
          # verified far more robustly by reading the generated
          # authorized_keys file directly.
          keys_file = node.succeed("cat /etc/ssh/authorized_keys.d/deploy").strip()
          assert keys_file, "authorized_keys.d/deploy is empty"
          for line in keys_file.splitlines():
              assert line.startswith("restrict,command="), (
                  f"every deploy authorized_keys line must start with restrict,command=..., got: {line!r}"
              )

          # A plain `-t` (single) still proves the forced command runs
          # fine even when a pty WAS requested at the ssh(1) CLI level --
          # covering the "still works, doesn't hang or error out" half of
          # this property live, without depending on which side (client
          # heuristic vs. server restrict) is what ultimately prevented
          # allocation in this particular test environment.
          status, out = ssh("status", extra="-t")
          assert status == 0, f"expected the forced command to still run with -t requested, got status={status} output={out!r}"
          assert "active=" in out, f"expected the status command to still have run: {out!r}"

      with subtest("-R port forwarding is refused (restrict)"):
          # -R asks the server for a "tcpip-forward" global request up
          # front; restrict's no-port-forwarding makes the server refuse
          # it outright, and ExitOnForwardFailure=yes makes the CLIENT
          # exit immediately (non-zero) on that refusal -- this one is
          # bounded by ssh's own behaviour, but still wrapped in `timeout`
          # for the same blanket-safety reason as everywhere else here.
          status, out = client.execute(
              f"timeout 20 ssh {SSH_OPTS} -o ExitOnForwardFailure=yes "
              f"-R 127.0.0.1:9001:127.0.0.1:22 -i {CLIENT_KEY} deploy@{node_ip} status 2>&1"
          )
          assert status != 0, f"expected -R forwarding to be refused, got status=0 output={out!r}"

      with subtest("-L port forwarding is refused, proven at use time (restrict)"):
          # Unlike -R, a -L LISTENER always succeeds locally: ssh(1) just
          # binds a local port and waits, and only asks the server to
          # open a "direct-tcpip" channel once something actually
          # connects through it -- ExitOnForwardFailure does NOT fire at
          # connect time for -L the way it does for -R's up-front
          # tcpip-forward request. That means a bare `ssh -N -L ...`
          # connects fine and then sits there forever (the exact hang
          # this subtest went through during development, burning 10+
          # minutes per build before being caught): the server only
          # refuses the forwarded CHANNEL when something tries to use it,
          # and a refused request doesn't itself end the session.
          #
          # So: start it in the BACKGROUND, under `timeout 15` as a hard
          # backstop, with all three std fds redirected to files/devnull
          # (not left connected to execute()'s own pipe -- execute()
          # would otherwise block waiting for that pipe to close, same as
          # every other backgrounded job in this file); wait (bounded)
          # for the local listener to actually come up; prove a REAL
          # connection through it fails; then kill it explicitly rather
          # than waiting out the full 15s backstop.
          client.succeed(
              "rm -f /tmp/l-ssh.log /tmp/l-ssh.pid; "
              f"timeout 15 ssh {SSH_OPTS} -N -L 127.0.0.1:9000:127.0.0.1:443 "
              f"-i {CLIENT_KEY} deploy@{node_ip} "
              "</dev/null >/tmp/l-ssh.log 2>&1 & echo $! > /tmp/l-ssh.pid"
          )
          # bash's /dev/tcp pseudo-device: a bare TCP connect-and-close,
          # needs no extra package. Fails fast (connection refused) while
          # nothing is listening yet; succeeds once ssh's local listener
          # is up, regardless of what happens at the forwarding level.
          client.wait_until_succeeds(
              "timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9000 && exec 3<&-'",
              timeout=10,
          )
          status, out = client.execute(
              "curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://127.0.0.1:9000/ 2>&1"
          )
          assert status != 0, (
              f"expected the forwarded connection to be refused (curl should fail outright), "
              f"got status={status} output={out!r}"
          )
          client.execute("kill \"$(cat /tmp/l-ssh.pid)\" 2>/dev/null || true")
          ssh_log = client.succeed("cat /tmp/l-ssh.log 2>/dev/null || true")
          assert (
              "administratively prohibited" in ssh_log.lower()
              or "open failed" in ssh_log.lower()
          ), f"expected ssh's own log to mention the channel being refused, got: {ssh_log!r}"

      with subtest("scp and sftp are refused (the forced command applies to file-transfer subsystems too)"):
          status, out = client.execute(
              f"timeout 20 scp {SSH_OPTS} -O -i {CLIENT_KEY} /etc/hostname deploy@{node_ip}:/tmp/should-not-land 2>&1"
          )
          assert status != 0, f"expected scp to be refused, got status=0 output={out!r}"
          node.fail("test -e /tmp/should-not-land")

          status, out = client.execute(
              f"printf 'bye\\n' | timeout 20 sftp {SSH_OPTS} -i {CLIENT_KEY} deploy@{node_ip} 2>&1"
          )
          assert status != 0, f"expected sftp to be refused, got status=0 output={out!r}"

      with subtest("an oversized upload is refused, nothing left behind"):
          # stackbase.deploy.maxUploadBytes = 65536 for this node (see the
          # node's module config above) -- comfortably above every real
          # test tarball (a few KB) and comfortably below this 100 KB blob.
          client.succeed("dd if=/dev/urandom of=/tmp/big.bin bs=1024 count=100 status=none")
          before_incoming = incoming_files()
          sha = client.succeed("sha256sum /tmp/big.bin | cut -d' ' -f1").strip()
          cmd = f"upload v3.9.0 {sha}"
          status, out = client.execute(
              f"timeout 20 ssh {SSH_OPTS} -i {CLIENT_KEY} deploy@{node_ip} {shlex.quote(cmd)} < /tmp/big.bin 2>&1"
          )
          assert status != 0, f"expected the oversized upload to be refused, got status=0 output={out!r}"
          assert incoming_files() == before_incoming, f"an oversized upload left something under incoming/: {incoming_files()}"
          node.fail("test -d /opt/${project}/releases/v3.9.0")

      with subtest("upload with a wrong sha256 leaves nothing in releases/ or incoming/"):
          before_incoming = incoming_files()
          before_releases = release_set()
          sha_bad = "0" * 64
          real_sha = client_make_tarball("v3.10.0")
          assert sha_bad != real_sha
          status, out = ssh_upload("v3.10.0", sha_bad)
          assert status != 0, f"expected the upload to fail on a sha256 mismatch, got status=0 output={out!r}"
          assert incoming_files() == before_incoming
          assert release_set() == before_releases
          node.fail("test -d /opt/${project}/releases/v3.10.0")

      with subtest("re-uploading the SAME tarball under an existing version is idempotent -- exit 0 (P1)"):
          sha = client_make_tarball("v3.11.0")
          status, out = ssh_upload("v3.11.0", sha)
          assert status == 0, f"first upload failed: status={status} output={out!r}"

          sha_file = "/opt/${project}/releases/v3.11.0/.stackbase-sha256"
          recorded_sha = node.succeed(f"cat {sha_file}").strip()
          assert recorded_sha == sha, f"expected .stackbase-sha256 to hold the uploaded tarball's sha, got {recorded_sha!r} vs {sha!r}"
          mode = node.succeed(f"stat -c '%a' {sha_file}").strip()
          assert mode == "644", f"expected .stackbase-sha256 to be mode 0644, got {mode}"

          before_binary_sha = node.succeed(
              "sha256sum /opt/${project}/releases/v3.11.0/${project} | cut -d' ' -f1"
          ).strip()
          before_incoming = incoming_files()

          status, out = ssh_upload("v3.11.0", sha)
          assert status == 0, f"re-uploading the SAME content must exit 0, got status={status} output={out!r}"
          assert "already uploaded" in out and "same content" in out, (
              f"expected an 'already uploaded (same content)' info line, got: {out!r}"
          )
          assert incoming_files() == before_incoming, (
              f"a same-content re-upload left something under incoming/: {incoming_files()}"
          )

          after_binary_sha = node.succeed(
              "sha256sum /opt/${project}/releases/v3.11.0/${project} | cut -d' ' -f1"
          ).strip()
          assert after_binary_sha == before_binary_sha, "the release's own content must be untouched"
          after_recorded_sha = node.succeed(f"cat {sha_file}").strip()
          assert after_recorded_sha == sha

      with subtest("re-uploading DIFFERENT content under an EXISTING version is refused -- exit 4 (P1)"):
          sha_v1 = client_make_tarball("v3.12.0", health_code=200)
          status, out = ssh_upload("v3.12.0", sha_v1)
          assert status == 0, f"first upload failed: status={status} output={out!r}"

          sha_file = "/opt/${project}/releases/v3.12.0/.stackbase-sha256"
          before_recorded_sha = node.succeed(f"cat {sha_file}").strip()
          before_binary_sha = node.succeed(
              "sha256sum /opt/${project}/releases/v3.12.0/${project} | cut -d' ' -f1"
          ).strip()
          before_incoming = incoming_files()

          # A DIFFERENT tarball (different fake-app health code -> different
          # bytes -> different, correctly-computed sha256), re-tagged and
          # rebuilt under the SAME version string -- exactly the case P1
          # closes: silently keeping the old content is unsafe, so this must
          # be refused, distinctly (exit 4), not treated as a duplicate.
          sha_v2 = client_make_tarball("v3.12.0", health_code=201)
          assert sha_v2 != sha_v1, "the two tarballs must actually differ for this test to mean anything"
          status, out = ssh_upload("v3.12.0", sha_v2)
          assert status == 4, f"expected exit 4 for same-version/different-content, got status={status} output={out!r}"
          assert "already exists with different content" in out, f"expected the P1 refusal message, got: {out!r}"
          assert "bump the version" in out, f"expected the bump-the-version hint, got: {out!r}"

          assert incoming_files() == before_incoming, (
              f"a refused upload left something under incoming/: {incoming_files()}"
          )
          after_recorded_sha = node.succeed(f"cat {sha_file}").strip()
          assert after_recorded_sha == before_recorded_sha == sha_v1, (
              "the recorded sha must be unchanged after a refused upload"
          )
          after_binary_sha = node.succeed(
              "sha256sum /opt/${project}/releases/v3.12.0/${project} | cut -d' ' -f1"
          ).strip()
          assert after_binary_sha == before_binary_sha, "the release's own content must be unchanged after a refusal"

      with subtest("two concurrent uploads of the SAME new version: BOTH succeed, nothing left behind (F2, P1)"):
          # F2 (Fix round 1): the first implementation streamed into fixed
          # names (incoming/<version>.tar.gz.partial -> .tar.gz), so two
          # concurrent uploads of the same version raced on those SAME two
          # paths -- whichever session's EXIT trap fired first deleted the
          # OTHER session's file. Now each session gets its own mktemp'd
          # path, so the only place they can still collide is inside
          # `stack-deploy unpack` itself, which already holds the engine
          # lock -- serialising the two sessions there.
          #
          # P1 (Fix round 1) changed what "collide" means: both uploads
          # carry the exact SAME content (same tarball, same sha256). If the
          # loser's OWN `acquire_lock` call lands after the winner has
          # already released the lock, it now finds a release already there
          # with a MATCHING recorded sha256 -- "already uploaded (same
          # content)", exit 0, not the old "already exists -- pass --force"
          # refusal. But `acquire_lock` uses `flock -n` (non-blocking): if
          # the loser's call instead lands WHILE the winner still holds the
          # lock, it fails immediately with exit 3 ("another deploy is
          # already in progress") -- a real, expected outcome of a genuine
          # race, not a bug. So the loser's status is 0 OR 3, never the old
          # unconditional-refusal exit 1 (which, for genuinely IDENTICAL
          # content, can no longer happen at all).
          #
          # Both ssh sessions are launched fully DETACHED (all three std
          # fds redirected to files/devnull, not left connected to
          # execute()'s own pipe) -- the same pattern already used for the
          # -L port-forwarding subtest above, and for the same reason: a
          # backgrounded job whose fds are still attached to execute()'s
          # pipe makes execute() block waiting for that pipe to close.
          # Launching both, then polling (bounded) for their status files
          # to appear, sidesteps relying on a plain shell `wait` correctly
          # tracking two backgrounded subshells through however the test
          # driver's own exec wrapper runs the launching command.
          #
          # The test driver runs every command under `set -euo pipefail`
          # (nixos/lib/test-driver's own `execute()`), which IS inherited
          # into these backgrounded subshells: a bare `cmd; echo $? > file`
          # never reaches the `echo` at all when `cmd` fails, because
          # errexit aborts the subshell right at the failing command --
          # confirmed locally before writing this. `cmd || rc=$?` is
          # immune (the `||` alternative makes the whole simple-or-list
          # succeed regardless of `cmd`'s own exit status), so the exit
          # code is captured that way instead of a bare `echo $?`.
          sha = client_make_tarball("v4.0.0")
          before_incoming = incoming_files()
          node.fail("test -d /opt/${project}/releases/v4.0.0")

          upload_cmd = (
              f"timeout 20 ssh {SSH_OPTS} -i {CLIENT_KEY} deploy@{node_ip} "
              f"{shlex.quote('upload v4.0.0 ' + sha)} < /tmp/v4.0.0.tar.gz"
          )
          client.succeed(
              "rm -f /tmp/race-a.status /tmp/race-b.status /tmp/race-a.log /tmp/race-b.log; "
              f"( rc=0; {upload_cmd} > /tmp/race-a.log 2>&1 || rc=$?; echo $rc > /tmp/race-a.status ) "
              "</dev/null >/dev/null 2>&1 & "
              f"( rc=0; {upload_cmd} > /tmp/race-b.log 2>&1 || rc=$?; echo $rc > /tmp/race-b.status ) "
              "</dev/null >/dev/null 2>&1 &"
          )
          client.wait_until_succeeds(
              "test -f /tmp/race-a.status && test -f /tmp/race-b.status", timeout=25
          )

          status_a = client.succeed("cat /tmp/race-a.status").strip()
          status_b = client.succeed("cat /tmp/race-b.status").strip()
          log_a = client.succeed("cat /tmp/race-a.log")
          log_b = client.succeed("cat /tmp/race-b.log")

          statuses = {status_a, status_b}
          assert "0" in statuses, (
              f"expected at least one of the two concurrent uploads to succeed, got "
              f"status_a={status_a} status_b={status_b} (log_a={log_a!r} log_b={log_b!r})"
          )
          assert statuses <= {"0", "3"}, (
              f"a concurrent upload of IDENTICAL content must only ever succeed (0, possibly via the "
              f"P1 dedup fast path) or hit the non-blocking lock (3, the other upload still in flight) -- "
              f"never the old unconditional 'already exists' refusal; got status_a={status_a} "
              f"status_b={status_b} (log_a={log_a!r} log_b={log_b!r})"
          )
          # At most one of the two ever reaches the dedup fast path (it only
          # exists once a release is already there): 0 if the loser instead
          # hit the lock (3) before the winner had unpacked anything yet, 1
          # if it landed after.
          combined_logs = log_a + log_b
          assert combined_logs.count("already uploaded (same content)") <= 1, (
              f"expected at most one of the two racers to observe the dedup fast path, got: "
              f"log_a={log_a!r} log_b={log_b!r}"
          )

          node.succeed("test -d /opt/${project}/releases/v4.0.0")
          assert incoming_files() == before_incoming, (
              f"incoming/ must be back to its pre-race state once the race resolves, got {incoming_files()}"
          )

          # The winning release must be genuinely intact/deployable, not
          # just present on disk -- prove it with a real deploy.
          node.succeed("${fastHealth} stack-deploy deploy v4.0.0")
          assert "v4.0.0" in node.succeed("stack-deploy releases")

      with subtest("a key not listed in stackbase.deploy.keys is denied for the deploy account"):
          status, out = ssh("status", key=STRANGER_KEY)
          assert status != 0, f"expected auth failure for an unknown key, got status=0 output={out!r}"

      with subtest("an admin key is not accepted for the deploy account unless also in stackbase.deploy.keys"):
          status, out = ssh("status", key=ADMIN_KEY)
          assert status != 0, f"expected auth failure for an admin-only key against deploy@, got status=0 output={out!r}"

      # -------------------------------------------------------------
      # F1 (Fix round 1): base.nix now disables
      # services.openssh.authorizedKeysInHomedir, so the ONLY trusted key
      # source for every account is /etc/ssh/authorized_keys.d/%u
      # (declarative config). Prove that planting a key into either
      # deploy's or an admin's OWN homedir ~/.ssh/authorized_keys -- which
      # anything able to write there as that user could always do -- grants
      # NOTHING, and that the real declarative sources still work.
      # -------------------------------------------------------------

      STRANGER_PUB = "${pubKeyOf strangerKeypair}"

      with subtest("a key planted into deploy's own ~/.ssh/authorized_keys grants no access (F1a)"):
          node.succeed(
              f"install -d -m 0700 -o deploy -g deploy {STATE_DIR}/deploy-home/.ssh && "
              f"printf '%s\\n' {shlex.quote(STRANGER_PUB)} > /tmp/planted-deploy-authorized_keys && "
              f"install -m 0600 -o deploy -g deploy /tmp/planted-deploy-authorized_keys "
              f"{STATE_DIR}/deploy-home/.ssh/authorized_keys"
          )
          status, out = ssh("status", key=STRANGER_KEY)
          assert status != 0, (
              f"a key planted into deploy's own ~/.ssh/authorized_keys must NOT grant access "
              f"(authorizedKeysInHomedir must be off), got status=0 output={out!r}"
          )
          node.succeed(f"rm -rf {STATE_DIR}/deploy-home/.ssh")

      with subtest("a key planted into an admin's own ~/.ssh/authorized_keys grants no access (F1b)"):
          admin_group = node.succeed("id -gn testadmin").strip()
          node.succeed(
              f"install -d -m 0700 -o testadmin -g {admin_group} /home/testadmin/.ssh && "
              f"printf '%s\\n' {shlex.quote(STRANGER_PUB)} > /tmp/planted-admin-authorized_keys && "
              f"install -m 0600 -o testadmin -g {admin_group} /tmp/planted-admin-authorized_keys "
              f"/home/testadmin/.ssh/authorized_keys"
          )
          status, out = client.execute(
              f"timeout 20 ssh {SSH_OPTS} -n -i {STRANGER_KEY} testadmin@{node_ip} true 2>&1"
          )
          assert status != 0, (
              f"a key planted into an admin's own ~/.ssh/authorized_keys must NOT grant access, "
              f"got status=0 output={out!r}"
          )
          node.succeed("rm -rf /home/testadmin/.ssh")

      with subtest("positive controls: the listed deploy key and a declarative admin key still work (F1c)"):
          # The negative subtests above (this one, F1a, F1b, plus the
          # earlier "a key not listed"/"an admin key is not accepted"
          # subtests) are FOUR genuine SSH authentication failures from
          # this client's one source IP in quick succession.
          # PerSourcePenalties (base.nix, Task 6: `PerSourcePenalties
          # yes`) accrues an authfail penalty (default 5s) per failure and
          # starts enforcing once the accrued total crosses its default
          # 15s minimum -- four failures cross that, and the next
          # connection attempt can get refused outright at the
          # TCP/protocol level ("kex_exchange_identification: read:
          # Connection reset by peer") even though the key itself is
          # perfectly valid. That's a real, if noisy, side effect of a
          # real hardening feature working as designed, not a bug in
          # either -- poll (bounded) rather than assert once, the same way
          # a real client behind that same source IP would just retry.
          client.wait_until_succeeds(
              f"timeout 20 ssh {SSH_OPTS} -n -i {CLIENT_KEY} deploy@{node_ip} status 2>&1 | grep -q 'active='",
              timeout=60,
          )
          client.wait_until_succeeds(
              f"timeout 20 ssh {SSH_OPTS} -n -i {ADMIN_KEY} testadmin@{node_ip} true 2>&1",
              timeout=60,
          )

      with subtest("deploy has NO access to /var/lib/stackbase -- app-host.nix's root:nginx domain stays untouched"):
          # The engine's own state lives entirely under stateDir
          # (/var/lib/stackbase-deploy, deploy:deploy) -- nixos/deploy.nix
          # never asserts any ownership on /var/lib/stackbase itself, which
          # stays exactly as app-host.nix's cert-placeholder leaves it
          # (root:nginx 0750). `deploy` is a member of neither `root` nor
          # `nginx`, so it must have NO access whatsoever: can't list it,
          # can't read app.env or nginx's TLS private key (origin.key),
          # and can't create/rename/delete anything inside it (directory
          # write, which would let it swap in its own file even without
          # being able to read the original).
          node.fail("runuser -u deploy -- ls /var/lib/stackbase")
          node.fail("runuser -u deploy -- cat /var/lib/stackbase/app.env")
          node.fail("runuser -u deploy -- cat /var/lib/stackbase/origin.key")
          node.fail("runuser -u deploy -- touch /var/lib/stackbase/should-fail")
          node.fail("runuser -u deploy -- rm -f /var/lib/stackbase/app.env")
          node.fail(
              "runuser -u deploy -- mv /var/lib/stackbase/app.env /var/lib/stackbase/app.env.moved"
          )

      with subtest("deploy's sudo grant covers ONLY the exact systemctl invocations it needs"):
          node.fail("runuser -u deploy -- sudo -n systemctl restart nginx")
          node.fail("runuser -u deploy -- sudo -n systemctl start ${project}@blue.service --no-block")
          node.fail("runuser -u deploy -- sudo -n true")

          # `sudo -l` groups every command sharing the same runas/tag onto
          # ONE line, comma-separated -- not one line per grant as might
          # be assumed. "(ALL : ALL)" there is the runas specification
          # (which user/group sudo may run AS), not a granted COMMAND, so
          # its presence isn't itself a broader grant; what actually
          # matters is the comma-separated command list after "NOPASSWD:".
          status, listing = node.execute("runuser -u deploy -- sudo -n -l 2>&1")
          assert status == 0, f"expected sudo -n -l to succeed non-interactively, got status={status} output={listing!r}"
          grant_lines = [l for l in listing.splitlines() if "NOPASSWD" in l]
          assert len(grant_lines) == 1, f"expected exactly one NOPASSWD grant line, got: {listing!r}"
          commands = [c.strip() for c in grant_lines[0].split("NOPASSWD:", 1)[1].split(",")]
          assert len(commands) == 8, f"expected exactly 8 allowed commands, got {len(commands)}: {commands}"
          for verb in ["start", "restart", "stop"]:
              for color in ["blue", "green"]:
                  expected = f"systemctl {verb} ${project}@{color}.service"
                  assert any(c.endswith(expected) for c in commands), f"missing expected grant {expected!r} in {commands}"
          for color in ["blue", "green"]:
              expected = f"systemctl restart stackbase-drain@{color}.timer"
              assert any(c.endswith(expected) for c in commands), f"missing expected grant {expected!r} in {commands}"
    '';
}
