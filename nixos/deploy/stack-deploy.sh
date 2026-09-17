# stack-deploy: blue/green release engine for a stackbase node.
#
# Subcommands: status, colors, deploy, rollback, prune, releases, boot,
# internal-drain-stop. Exit codes: 0 ok, 1 failure, 2 usage, 3 lock held.
#
# Project-specific values (project slug, binary name, health path, drain
# seconds, keep count) come from /etc/stackbase/deploy.env, written by
# nixos/deploy.nix from the stackbase.app.*/stackbase.deploy.* options.
# This script itself is generic -- it must not hardcode a project name.
#
# Packaged via pkgs.writeShellApplication, which already prepends
# `set -euo pipefail` and runs shellcheck at build time.

# shellcheck source=/dev/null
# (the real path only exists on a stackbase node; nothing to lint here)
if [ -f /etc/stackbase/deploy.env ]; then
  source /etc/stackbase/deploy.env
fi

: "${STACK_PROJECT:?STACK_PROJECT must be set (via /etc/stackbase/deploy.env or the environment)}"
: "${STACK_BINARY:?STACK_BINARY must be set}"
STACK_HEALTH_PATH="${STACK_HEALTH_PATH:-/health}"
STACK_DRAIN_SECONDS="${STACK_DRAIN_SECONDS:-60}"
STACK_KEEP="${STACK_KEEP:-5}"
STACK_DEPLOY_HEALTH_TRIES="${STACK_DEPLOY_HEALTH_TRIES:-30}"
STACK_DEPLOY_HEALTH_SLEEP="${STACK_DEPLOY_HEALTH_SLEEP:-2}"

PROJECT="$STACK_PROJECT"
GROUP="$STACK_PROJECT"
RELEASES_DIR="/opt/$PROJECT/releases"
BLUE_DIR="/opt/$PROJECT/blue"
GREEN_DIR="/opt/$PROJECT/green"
STATE_DIR="/var/lib/stackbase"
ACTIVE_COLOR_FILE="$STATE_DIR/active-color"
GENERATION_FILE="$STATE_DIR/generation"
LOCK_FILE="$STATE_DIR/deploy.lock"
RUN_DIR="/run/$PROJECT"
SOCK_LINK="$RUN_DIR/app.sock"

# Anchored on both ends: vMAJOR.MINOR.PATCH exactly, no leading zeros, no
# pre-release/build suffixes.
VERSION_GREP='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

die() {
  echo "✗ $*" >&2
  exit 1
}

usage_die() {
  echo "✗ $*" >&2
  exit 2
}

color_dir() {
  case "$1" in
    blue) echo "$BLUE_DIR" ;;
    green) echo "$GREEN_DIR" ;;
    *) die "invalid color: $1" ;;
  esac
}

other_color() {
  case "$1" in
    blue) echo green ;;
    green) echo blue ;;
    *) die "invalid color: $1" ;;
  esac
}

read_active() {
  if [ -f "$ACTIVE_COLOR_FILE" ]; then
    cat "$ACTIVE_COLOR_FILE"
  else
    echo none
  fi
}

idle_for() {
  local active="$1"
  if [ "$active" = none ]; then
    echo blue
  else
    other_color "$active"
  fi
}

linked_version() {
  local link
  link="$(color_dir "$1")/current"
  if [ -e "$link" ]; then
    basename "$(readlink -f "$link")"
  fi
}

release_version_of() {
  linked_version "$1"
}

current_version_or_dash() {
  local v
  v="$(linked_version "$1")"
  if [ -n "$v" ]; then
    echo "$v"
  else
    echo "-"
  fi
}

atomic_write() {
  local path="$1" content="$2" tmp
  tmp=$(mktemp "${path}.XXXXXX")
  printf '%s\n' "$content" > "$tmp"
  mv -T "$tmp" "$path"
}

atomic_symlink() {
  local target="$1" link="$2"
  local tmp="${link}.tmp"
  rm -f "$tmp"
  ln -s "$target" "$tmp"
  mv -T "$tmp" "$link"
}

# Runs the given systemctl verb+unit as root; when invoked as a non-root
# user (normally `deploy`) it goes through the narrow, exact-command
# NOPASSWD sudo rule set up by nixos/deploy.nix.
run_systemctl() {
  if [ "$(id -u)" -eq 0 ]; then
    systemctl "$1" "$2"
  else
    sudo -n systemctl "$1" "$2"
  fi
}

acquire_lock() {
  exec 9>"$LOCK_FILE" || die "cannot open lock file $LOCK_FILE"
  if ! flock -n 9; then
    echo "✗ another deploy is already in progress (lock held: $LOCK_FILE)" >&2
    exit 3
  fi
}

next_generation() {
  local cur next
  if [ -f "$GENERATION_FILE" ]; then
    cur=$(cat "$GENERATION_FILE")
  else
    cur=0
  fi
  next=$((cur + 1))
  atomic_write "$GENERATION_FILE" "$next"
  echo "$next"
}

validate_version() {
  if ! printf '%s\n' "$1" | grep -qE "$VERSION_GREP"; then
    usage_die "invalid version '$1' (expected vMAJOR.MINOR.PATCH, e.g. v1.2.3)"
  fi
}

wait_healthy() {
  local color="$1"
  local sock="$RUN_DIR/app-$color.sock" i code
  for ((i = 1; i <= STACK_DEPLOY_HEALTH_TRIES; i++)); do
    code=$(curl --unix-socket "$sock" -o /dev/null -s -w '%{http_code}' "http://localhost${STACK_HEALTH_PATH}" 2>/dev/null || echo 000)
    case "$code" in
      2??) return 0 ;;
    esac
    sleep "$STACK_DEPLOY_HEALTH_SLEEP"
  done
  return 1
}

# Shared tail end of both `deploy` and `rollback`: start the idle color on
# whatever release its `current` symlink already points at, health-check
# it, flip production traffic to it, persist state, and schedule the
# outgoing color's drain-stop. `prev_active` is the color that was active
# before this call (or "none" on the very first deploy, when there is
# nothing to drain).
activate_color() {
  local idle="$1" prev_active="$2" version

  version=$(release_version_of "$idle")

  echo "→ starting $idle on $version"
  run_systemctl restart "${PROJECT}@${idle}.service"

  if ! wait_healthy "$idle"; then
    echo "✗ $idle failed the health check ($STACK_HEALTH_PATH) after $STACK_DEPLOY_HEALTH_TRIES tries" >&2
    run_systemctl stop "${PROJECT}@${idle}.service" || true
    exit 1
  fi
  echo "✓ $idle is healthy"

  atomic_symlink "app-${idle}.sock" "$SOCK_LINK"
  echo "✓ traffic switched to $idle"

  # Constraint: the state file is written atomically AFTER the socket
  # symlink flip succeeds, never before.
  atomic_write "$ACTIVE_COLOR_FILE" "$idle"

  if [ "$prev_active" != none ] && [ "$prev_active" != "$idle" ]; then
    local gen
    gen=$(next_generation)
    atomic_write "$STATE_DIR/drain-pending-${prev_active}" "$gen"
    echo "→ $prev_active will stop in ${STACK_DRAIN_SECONDS}s"
    run_systemctl restart "stackbase-drain@${prev_active}.timer"
  fi

  echo "i migrations run at app start: keep them additive (expand -> migrate -> contract in a later release)"
}

deploy_unpack_tarball() {
  local version="$1" tarball="$2" sha256="$3" force="$4"
  local release_dir="$RELEASES_DIR/$version"

  [ -f "$tarball" ] || die "tarball not found: $tarball"

  if [ -e "$release_dir" ] && [ "$force" -ne 1 ]; then
    die "release $version already exists at $release_dir; pass --force to overwrite"
  fi

  local actual_sha
  actual_sha=$(sha256sum "$tarball" | awk '{print $1}')
  if [ "$actual_sha" != "$sha256" ]; then
    die "sha256 mismatch for $tarball: expected $sha256, got $actual_sha"
  fi

  local member
  while IFS= read -r member; do
    case "$member" in
      /*) die "tarball contains an absolute path member: $member" ;;
    esac
    if printf '%s\n' "$member" | tr '/' '\n' | grep -qx '\.\.'; then
      die "tarball contains a '..' path member: $member"
    fi
  done < <(tar -tzf "$tarball")

  local tmp_dir
  tmp_dir=$(mktemp -d "$RELEASES_DIR/.tmp-${version}-XXXXXX")
  tar -xzf "$tarball" -C "$tmp_dir"
  chgrp -R "$GROUP" "$tmp_dir"
  chmod -R g+rX "$tmp_dir"

  rm -rf "$release_dir"
  mv -T "$tmp_dir" "$release_dir"
  echo "✓ unpacked $version"
}

cmd_deploy() {
  local version="" tarball="" sha256="" force=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --tarball)
        [ $# -ge 2 ] || usage_die "--tarball requires a value"
        tarball="$2"
        shift 2
        ;;
      --sha256)
        [ $# -ge 2 ] || usage_die "--sha256 requires a value"
        sha256="$2"
        shift 2
        ;;
      --force)
        force=1
        shift
        ;;
      -*)
        usage_die "unknown option: $1"
        ;;
      *)
        [ -z "$version" ] || usage_die "unexpected argument: $1"
        version="$1"
        shift
        ;;
    esac
  done

  [ -n "$version" ] || usage_die "usage: stack-deploy deploy <version> [--tarball PATH --sha256 HEX] [--force]"
  validate_version "$version"

  if [ -n "$tarball" ] && [ -z "$sha256" ]; then
    usage_die "--tarball requires --sha256"
  fi
  if [ -z "$tarball" ] && [ -n "$sha256" ]; then
    usage_die "--sha256 requires --tarball"
  fi

  acquire_lock

  local release_dir="$RELEASES_DIR/$version"

  if [ -n "$tarball" ]; then
    deploy_unpack_tarball "$version" "$tarball" "$sha256" "$force"
  else
    [ -d "$release_dir" ] || die "release $version not found at $release_dir (unpack it first or pass --tarball)"
  fi

  local active idle
  active=$(read_active)
  idle=$(idle_for "$active")

  atomic_symlink "../releases/$version" "$(color_dir "$idle")/current"

  activate_color "$idle" "$active"
}

cmd_rollback() {
  acquire_lock

  local active idle link
  active=$(read_active)
  [ "$active" != none ] || die "nothing has been deployed yet; cannot rollback"
  idle=$(idle_for "$active")
  link="$(color_dir "$idle")/current"
  [ -e "$link" ] || die "idle color $idle has no linked release; nothing to roll back to"

  activate_color "$idle" "$active"
}

cmd_prune() {
  local keep="${1:-$STACK_KEEP}"
  [[ "$keep" =~ ^[1-9][0-9]*$ ]] || usage_die "keep count must be a positive integer, got: $keep"

  acquire_lock

  if [ ! -d "$RELEASES_DIR" ]; then
    echo "i no releases directory; nothing to prune"
    exit 0
  fi

  local blue_ver green_ver
  blue_ver=$(linked_version blue)
  green_ver=$(linked_version green)

  local all_versions=()
  while IFS= read -r v; do
    all_versions+=("$v")
  done < <(find "$RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | grep -E "$VERSION_GREP" | sort -V)

  local total=${#all_versions[@]}
  if [ "$total" -le "$keep" ]; then
    echo "i nothing to prune ($total release(s), keep=$keep)"
    exit 0
  fi

  local to_drop=$((total - keep)) i v pruned=0
  for ((i = 0; i < to_drop; i++)); do
    v="${all_versions[$i]}"
    if [ "$v" = "$blue_ver" ] || [ "$v" = "$green_ver" ]; then
      continue
    fi
    rm -rf "${RELEASES_DIR:?}/$v"
    echo "✓ pruned $v"
    pruned=$((pruned + 1))
  done
  echo "i pruned $pruned release(s), kept $((total - pruned))"
}

cmd_releases() {
  local active idle blue_ver green_ver v tag

  active=$(read_active)
  idle=$(idle_for "$active")
  blue_ver=$(linked_version blue)
  green_ver=$(linked_version green)

  [ -d "$RELEASES_DIR" ] || exit 0

  while IFS= read -r v; do
    tag=""
    if [ -n "$blue_ver" ] && [ "$v" = "$blue_ver" ]; then
      if [ "$active" = blue ]; then tag="$tag [blue/active]"; else tag="$tag [blue/idle]"; fi
    fi
    if [ -n "$green_ver" ] && [ "$v" = "$green_ver" ]; then
      if [ "$active" = green ]; then tag="$tag [green/active]"; else tag="$tag [green/idle]"; fi
    fi
    printf '%s%s\n' "$v" "$tag"
  done < <(find "$RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | grep -E "$VERSION_GREP" | sort -V)
}

cmd_colors() {
  local active idle
  active=$(read_active)
  idle=$(idle_for "$active")
  echo "active=$active idle=$idle"
}

cmd_status() {
  local active idle
  active=$(read_active)
  idle=$(idle_for "$active")
  echo "active=$active ($(current_version_or_dash "$active"))  idle=$idle ($(current_version_or_dash "$idle"))"
}

# Invoked only as root, as the ExecStart of stackbase-app-boot.service:
# starts whichever color active-color names and recreates app.sock, since
# /run is tmpfs and doesn't survive a reboot. Absent state file -> no-op.
cmd_boot() {
  local active
  active=$(read_active)
  if [ "$active" = none ]; then
    echo "i no active-color set; nothing to start at boot"
    exit 0
  fi
  systemctl start "${PROJECT}@${active}.service"
  atomic_symlink "app-${active}.sock" "$SOCK_LINK"
  echo "✓ $active started at boot; traffic restored"
}

# Invoked only as root, as the ExecStart of stackbase-drain@<color>.service
# when its paired timer fires. Re-validates against the current state
# before stopping anything, closing the race where a newer deploy has
# since reactivated or reused this same color:
#   - takes the same deploy.lock as `deploy`/`rollback` (non-blocking): a
#     live deploy might be mid-restart of this very unit, so back off
#     rather than risk stopping mid-restart.
#   - the color must still be idle (not the current active color).
#   - the generation recorded when this drain was scheduled must still
#     match the current generation counter; a newer deploy touching either
#     color bumps it, which invalidates every older pending drain.
cmd_internal_drain_stop() {
  local color="$1"

  exec 9>"$LOCK_FILE" || exit 0
  if ! flock -n 9; then
    echo "i drain-stop for $color skipped: a deploy is in progress"
    exit 0
  fi

  local active
  active=$(read_active)
  if [ "$active" = "$color" ]; then
    echo "i drain-stop for $color skipped: $color is active again"
    exit 0
  fi

  local pending_file="$STATE_DIR/drain-pending-${color}"
  if [ ! -f "$pending_file" ]; then
    echo "i drain-stop for $color skipped: no pending marker"
    exit 0
  fi

  local expected current
  expected=$(cat "$pending_file")
  if [ -f "$GENERATION_FILE" ]; then current=$(cat "$GENERATION_FILE"); else current=0; fi
  if [ "$expected" != "$current" ]; then
    echo "i drain-stop for $color skipped: superseded by a newer deploy"
    exit 0
  fi

  systemctl stop "${PROJECT}@${color}.service"
  rm -f "$pending_file"
  echo "✓ $color stopped after drain"
}

main() {
  [ $# -ge 1 ] || usage_die "usage: stack-deploy <status|colors|deploy|rollback|prune|releases> [...]"
  local cmd="$1"
  shift
  case "$cmd" in
    status) cmd_status "$@" ;;
    colors) cmd_colors "$@" ;;
    deploy) cmd_deploy "$@" ;;
    rollback) cmd_rollback "$@" ;;
    prune) cmd_prune "$@" ;;
    releases) cmd_releases "$@" ;;
    boot) cmd_boot "$@" ;;
    internal-drain-stop) cmd_internal_drain_stop "$@" ;;
    *) usage_die "unknown subcommand: $cmd" ;;
  esac
}

main "$@"
