# A local S3 target for VM tests: MinIO on the node itself, standing in for
# Cloudflare R2. Shared by every test that needs a bucket (tests/vm-logs.nix
# today), so the credentials, the endpoint and the client wrapper live in
# one place.
#
#   minio = import ./minio.nix { inherit pkgs; };
#   nodes.node.imports = [ minio.module ];
#   testScript = ''
#     ${minio.createBucket "node" "logs"}
#     node.succeed("s3 ls --recursive s3/logs/")
#   '';
#
# `s3` on the node is `mc` (minio-client) with an alias also called "s3"
# already pointing at this MinIO, so a test never has to configure it.
# The credentials below are test-only and live in the world-readable Nix
# store on purpose: they protect nothing.
{ pkgs }:

let
  accessKey = "stackbase-test";
  secretKey = "stackbase-test-secret";
  port = 9000;
  endpoint = "http://127.0.0.1:${toString port}";

  rootCredentials = pkgs.writeText "minio-root-credentials" ''
    MINIO_ROOT_USER=${accessKey}
    MINIO_ROOT_PASSWORD=${secretKey}
  '';

  # nixpkgs marks MinIO insecure (abandoned upstream, unfixed CVEs), and
  # refuses to evaluate it. Acceptable HERE only: it runs inside a throwaway
  # test VM, listens on loopback, and holds nothing but test data. Never
  # copy this override into a module a real server imports. If nixpkgs
  # drops the package, swap this fixture for Garage or SeaweedFS -- the
  # interface below (module, createBucket, logsEnv, `s3`) stays the same.
  package = pkgs.minio.overrideAttrs (old: {
    meta = old.meta // { knownVulnerabilities = [ ]; };
  });

  s3 = pkgs.writeShellScriptBin "s3" ''
    export MC_HOST_s3=http://${accessKey}:${secretKey}@127.0.0.1:${toString port}
    export MC_CONFIG_DIR=/tmp/.mc
    exec ${pkgs.minio-client}/bin/mc "$@"
  '';
in
{
  inherit accessKey secretKey port endpoint;

  # Same variable names as stackbase/logs.py writes to logs.env, so a node
  # under test reads exactly what a real one reads.
  logsEnv = ''
    AWS_ACCESS_KEY_ID=${accessKey}
    AWS_SECRET_ACCESS_KEY=${secretKey}
    LOGS_ENDPOINT=${endpoint}
  '';

  module = { ... }: {
    services.minio = {
      enable = true;
      inherit package;
      rootCredentialsFile = rootCredentials;
      listenAddress = "127.0.0.1:${toString port}";
      # R2's region name, so a client signing for "auto" (as Vector's R2
      # sink does) is accepted here exactly as it is there.
      region = "auto";
    };
    environment.systemPackages = [ s3 ];
  };

  # testScript snippet: wait for MinIO on `machine` and create `bucket`.
  createBucket = machine: bucket: ''
    ${machine}.wait_for_unit("minio.service")
    ${machine}.wait_for_open_port(${toString port})
    ${machine}.wait_until_succeeds("s3 mb --ignore-existing s3/${bucket}", timeout=60)
  '';
}
