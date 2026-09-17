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

        stackbase.allowedProxyRanges = lib.mkForce [
          "${nodes.proxy.networking.primaryIPAddress}/32"
        ];

        environment.systemPackages = [ pkgs.python3 pkgs.util-linux ];

        environment.etc."stackbase-test/fake-app.py".text = fakeApp;

        system.stateVersion = "26.05";
      };

    proxy =
      { ... }:
      {
        environment.systemPackages = [ pkgs.curl ];
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

      node_ip = "${nodes.node.networking.primaryIPAddress}"
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
          assert node.succeed("cat /var/lib/stackbase/active-color").strip() == "blue"
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
          assert node.succeed("cat /var/lib/stackbase/active-color").strip() == "green"
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
          node.execute("flock /var/lib/stackbase/deploy.lock sleep 5 </dev/null >/dev/null 2>&1 & sleep 1")
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
          node.succeed("echo green > /var/lib/stackbase/pending-color")

          node.shutdown()
          node.start()

          node.wait_for_unit("multi-user.target")
          node.wait_for_unit("nginx.service")
          node.wait_for_unit("stackbase-app-boot.service")

          assert node.succeed("stack-deploy colors").strip() == "active=green idle=blue"
          node.fail("test -e /var/lib/stackbase/pending-color")

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.1.0", (
              f"expected green/v1.1.0 to be serving after resuming the interrupted swap, got {code}/{body!r}"
          )

      with subtest("boot: pending-color with no linked release is discarded, falls back to active-color (I3)"):
          node.succeed("mv /opt/${project}/blue/current /tmp/blue-current-backup")
          node.succeed("echo blue > /var/lib/stackbase/pending-color")

          # execute()'s (status, output) only captures stdout by default
          # (its internal wrapper pipes stdout alone into base64, no
          # `2>&1`) -- redirect stderr into stdout ourselves so the
          # diagnostic (written via `>&2`) shows up in `out`.
          status, out = node.execute("stack-deploy boot 2>&1")
          assert status == 0, f"expected boot to fall back cleanly, got status={status} output={out!r}"
          assert "has no linked release; discarding" in out, out

          assert node.succeed("stack-deploy colors").strip() == "active=green idle=blue"
          node.fail("test -e /var/lib/stackbase/pending-color")

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
    '';
}
