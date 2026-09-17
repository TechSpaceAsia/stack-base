# nginx edge for a stackbase node: TLS termination, a Cloudflare-only
# allow-list enforced on the *real* TCP peer (not the rewritten client IP),
# a catch-all that refuses plain-IP / unknown-Host probes, and a proxy to
# the app's unix socket. Port 80 is never opened -- Cloudflare talks to the
# origin over 443 in Full (strict) mode.
#
# Reads `stackbase.project` from base.nix; declares `stackbase.domain` and
# `stackbase.allowedProxyRanges` here. Change the allow-list default only if
# Cloudflare's published ranges genuinely change (nixos/cloudflare-ips.nix).
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase;
  cloudflareIps = import ./cloudflare-ips.nix;

  certDir = "/var/lib/stackbase";
  certFile = "${certDir}/origin.crt";
  keyFile = "${certDir}/origin.key";

  geoAllowLines = lib.concatMapStringsSep "\n" (range: "    ${range} 1;") cfg.allowedProxyRanges;
  setRealIpFromLines = lib.concatMapStringsSep "\n" (range: "  set_real_ip_from ${range};") cfg.allowedProxyRanges;
in
{
  options.stackbase = {
    domain = lib.mkOption {
      type = lib.types.str;
      description = ''
        Public hostname this node serves (e.g. "acme.example.com"). Must
        match the Cloudflare DNS record and the origin cert's CN/SAN.
      '';
    };

    allowedProxyRanges = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = cloudflareIps.v4 ++ cloudflareIps.v6;
      description = ''
        CIDR ranges allowed to reach this host as an edge proxy, checked
        against the real TCP peer address (see the `geo` block this option
        drives). Defaults to Cloudflare's published ranges. A test overrides
        this to a single test-client address.
      '';
    };
  };

  config = {
    # origin.crt/origin.key are pushed onto the node by the provisioner at
    # deploy time (stackbase/reconcile.py PUSH_CONFIG) and are never in the
    # Nix store. On a brand new node those files don't exist yet, and nginx
    # refuses to start without a cert -- which would fail the very first
    # `nixos-rebuild switch`. This oneshot, ordered before nginx, generates
    # a throwaway self-signed pair only when the real files are absent, so
    # activation always succeeds. It never overwrites a real cert.
    #
    # The ownership/mode fix below runs on EVERY start, not just when a
    # placeholder was just generated: a first push writes the real pair as
    # root:root 0600 (steps.py's PUSH_CONFIG runs entirely over ssh as
    # root, before this unit -- or even nginx itself -- has ever run), and
    # if the fix only ran inside the "files are absent" branch, that real
    # pair would stay root:root forever and nginx (running as the nginx
    # user) would never be able to read the key.
    systemd.services.stackbase-origin-cert-placeholder = {
      description = "Generate a placeholder TLS cert for nginx until the real origin cert is pushed";
      before = [ "nginx.service" ];
      wantedBy = [ "nginx.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        set -eu
        install -d -m 0750 -o root -g nginx ${certDir}
        if [ ! -e ${keyFile} ] || [ ! -e ${certFile} ]; then
          ${pkgs.openssl}/bin/openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout ${keyFile} \
            -out ${certFile} \
            -days 3650 \
            -subj "/CN=stackbase-placeholder"
        fi
        chown root:nginx ${certFile} ${keyFile}
        chmod 0640 ${keyFile}
        chmod 0644 ${certFile}
      '';
    };

    services.nginx = {
      enable = true;
      recommendedTlsSettings = true;
      recommendedProxySettings = true;
      recommendedOptimisation = true;
      recommendedGzipSettings = true;

      # `real_ip` rewrites $remote_addr to the value of CF-Connecting-IP for
      # any connection whose TCP peer is in the allow-list, so by the time a
      # `server`/`location` block runs, $remote_addr is the *visitor's*
      # address -- an `allow <cf-range>; deny all;` there would reject every
      # real visitor. `$realip_remote_addr` still holds the original TCP
      # peer, so `geo` keys off that instead; the domain vhost below turns
      # it into a 403 with `if ($from_allowed_proxy = 0)`.
      appendHttpConfig = ''
        geo $realip_remote_addr $from_allowed_proxy {
          default 0;
        ${geoAllowLines}
        }

        ${setRealIpFromLines}
        real_ip_header CF-Connecting-IP;
      '';

      virtualHosts = {
        # Catch-all: plain-IP requests and any Host header other than our
        # domain land here and get refused outright.
        "_" = {
          default = true;
          onlySSL = true;
          sslCertificate = certFile;
          sslCertificateKey = keyFile;
          extraConfig = "return 444;";
        };

        ${cfg.domain} = {
          onlySSL = true;
          sslCertificate = certFile;
          sslCertificateKey = keyFile;
          extraConfig = ''
            if ($from_allowed_proxy = 0) {
              return 403;
            }
          '';

          # Static acceptance-check endpoint: works even before an app is
          # deployed, since the app socket won't exist yet.
          locations."/__stack" = {
            extraConfig = ''
              default_type text/plain;
              return 200 "stack is up\n";
            '';
          };

          # Until an app is deployed, `/run/<project>/app.sock` doesn't
          # exist and nginx answers 502 here -- expected, not a bug.
          locations."/" = {
            proxyPass = "http://unix:/run/${cfg.project}/app.sock";
          };
        };
      };
    };
  };
}
