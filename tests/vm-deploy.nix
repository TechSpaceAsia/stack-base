# NixOS VM test wired as `checks.x86_64-linux.vm-deploy` in flake.nix.
# Exercises the blue/green release engine (nixos/deploy.nix +
# nixos/deploy/stack-deploy.sh) end to end against a real systemd + nginx
# node: first deploy, a swap with a live zero-downtime check, drain-stop,
# a failed health check, rollback, invalid-version rejection, the deploy
# lock, prune's SemVer retention, and boot-time recovery.
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

  # A minimal fake app: binds $SOCKET_PATH (removing a stale socket
  # first), chmods it so nginx -- a member of the project's group, see
  # deploy.nix -- can connect(), and answers GET /health and GET
  # /version. __VERSION__ is substituted per-release at test time.
  fakeAppGood = ''
    #!/usr/bin/env python3
    import http.server
    import os
    import socket

    VERSION = "__VERSION__"
    SOCKET_PATH = os.environ["SOCKET_PATH"]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
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
    os.chmod(SOCKET_PATH, 0o660)
    httpd.serve_forever()
  '';

  fakeAppBroken = ''
    #!/usr/bin/env python3
    import http.server
    import os
    import socket

    VERSION = "__VERSION__"
    SOCKET_PATH = os.environ["SOCKET_PATH"]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"broken")
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
    os.chmod(SOCKET_PATH, 0o660)
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

        environment.etc."stackbase-test/fake-app-good.py".text = fakeAppGood;
        environment.etc."stackbase-test/fake-app-broken.py".text = fakeAppBroken;

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

      def make_release(version, template="/etc/stackbase-test/fake-app-good.py"):
          "Write a release binary straight into releases/<version>/${project} (the 'already unpacked' deploy path)."
          node.succeed(
              f"sed 's/__VERSION__/{version}/' {template} > /tmp/{version}-bin && "
              f"install -D -m0755 /tmp/{version}-bin /opt/${project}/releases/{version}/${project}"
          )

      def make_tarball(version, template="/etc/stackbase-test/fake-app-good.py"):
          "Build a flat tarball (binary at the archive root) for the --tarball deploy path; returns its sha256."
          node.succeed(
              "rm -rf /tmp/pkg && mkdir -p /tmp/pkg && "
              f"sed 's/__VERSION__/{version}/' {template} > /tmp/pkg/${project} && "
              f"chmod +x /tmp/pkg/${project} && "
              f"tar -czf /tmp/{version}.tar.gz -C /tmp/pkg ${project}"
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

      with subtest("rollback returns to the previous version (blue/v1.0.0)"):
          node.succeed("${fastHealth} stack-deploy rollback")
          assert node.succeed("stack-deploy colors").strip() == "active=blue idle=green"
          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.0.0", f"expected 200/v1.0.0 after rollback, got {code}/{body!r}"
          node.wait_until_succeeds("! systemctl is-active --quiet ${project}@green.service", timeout=15)

      with subtest("a broken release fails health, leaves active/symlink/state untouched, stops the idle unit"):
          make_release("v1.2.0", template="/etc/stackbase-test/fake-app-broken.py")

          # execute() runs the command under `set -e`, so a trailing
          # `; echo EXIT:$?` would never run once `stack-deploy` itself
          # exits non-zero -- use the (status, output) tuple execute()
          # already returns instead.
          status, out = node.execute("${brokenHealth} stack-deploy deploy v1.2.0")
          assert status == 1, f"expected exit 1 for a broken release, got status={status}, output={out!r}"

          assert node.succeed("stack-deploy colors").strip() == "active=blue idle=green"
          assert node.succeed("cat /var/lib/stackbase/active-color").strip() == "blue"
          assert node.succeed("readlink /run/${project}/app.sock").strip() == "app-blue.sock"
          node.wait_until_succeeds("! systemctl is-active --quiet ${project}@green.service", timeout=15)

          code = proxy.succeed(curl_version).strip()
          body = proxy.succeed("cat /tmp/vbody").strip()
          assert code == "200" and body == "v1.0.0", f"production should be unaffected by the broken deploy, got {code}/{body!r}"

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
          # Existing on disk: v1.0.0 (linked blue), v1.1.0 (unlinked),
          # v1.2.0 (linked green, broken). Round out to 7 releases.
          for v in ["v1.3.0", "v1.4.0", "v1.9.0", "v1.10.0"]:
              node.succeed(f"mkdir -p /opt/${project}/releases/{v}")

          before = set(node.succeed("ls /opt/${project}/releases").split())
          assert before == {
              "v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.9.0", "v1.10.0",
          }, f"unexpected release set going into prune: {before}"

          node.succeed("stack-deploy prune")
          after = set(node.succeed("ls /opt/${project}/releases").split())
          # keep=5 highest (v1.2.0 v1.3.0 v1.4.0 v1.9.0 v1.10.0) plus the
          # linked-but-otherwise-pruned v1.0.0; v1.1.0 (unlinked, outside
          # the top 5) is the only one removed.
          assert after == {
              "v1.0.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.9.0", "v1.10.0",
          }, f"unexpected release set after prune: {after}"

          node.succeed("stack-deploy prune 1")
          after2 = set(node.succeed("ls /opt/${project}/releases").split())
          # keep=1 highest (v1.10.0) plus the two still-linked releases.
          assert after2 == {"v1.0.0", "v1.2.0", "v1.10.0"}, f"unexpected release set after prune 1: {after2}"

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
    '';
}
