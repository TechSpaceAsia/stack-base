# stack-deploy: blue/green release engine for a stackbase node.
#
# Subcommands: status, colors, deploy, rollback, prune, releases, unpack,
# boot, internal-drain-stop. Exit codes: 0 ok, 1 failure, 2 usage, 3 lock
# held, 4 version already exists with DIFFERENT content (unpack/deploy
# --tarball only -- see deploy_unpack_tarball's sha256 dedup check, Fix
# round 1 P1).
#
# Project-specific values (project slug, binary name, health path, drain
# seconds, keep count) come from /etc/stackbase/deploy.env, written by
# nixos/deploy.nix from the stackbase.app.*/stackbase.deploy.* options.
# This script itself is generic -- it must not hardcode a project name.
#
# Packaged via pkgs.writeShellApplication, which already prepends
# `set -euo pipefail` and runs shellcheck at build time.
#
# errexit gotcha: bash disables `set -e` for the ENTIRE body of a shell
# function for as long as that function call is itself the thing being
# tested by `if`/`!`/`&&`/`||` (e.g. `if ! some_func; then` or
# `some_func || exit 1`) -- not just for the top-level call, the whole
# dynamic extent of everything that function goes on to run. Any function
# invoked that way (activate_color is the main one) must explicitly check
# every state-mutating step itself (`if ! cmd; then ...; fi`) rather than
# relying on `set -e` to abort on failure, because it won't.

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
RELEASES_DIR="/opt/$PROJECT/releases"
BLUE_DIR="/opt/$PROJECT/blue"
GREEN_DIR="/opt/$PROJECT/green"
# The engine's own state directory -- deliberately NOT /var/lib/stackbase
# itself, which app-host.nix owns exclusively (root:nginx, holds the TLS
# placeholder cert and, later, app.env). deploy.nix creates this directory
# deploy:deploy and never touches /var/lib/stackbase's ownership.
STATE_DIR="${STACK_STATE_DIR:-/var/lib/stackbase-deploy}"
ACTIVE_COLOR_FILE="$STATE_DIR/active-color"
GENERATION_FILE="$STATE_DIR/generation"
LOCK_FILE="$STATE_DIR/deploy.lock"
RUN_DIR="/run/$PROJECT"
SOCK_LINK="$RUN_DIR/app.sock"

# Anchored on both ends: vMAJOR.MINOR.PATCH exactly, no leading zeros, no
# pre-release/build suffixes. Substituted by nixos/deploy.nix at build time
# from its own `versionRegex` binding -- the SAME substitution lands in
# stack-deploy-ssh.sh's VERSION_RE, so the two scripts can never disagree
# on what a valid version string looks like (Fix round 1, F3).
VERSION_GREP='@versionRegex@'

die() {
  echo "✗ $*" >&2
  exit 1
}

usage_die() {
  echo "✗ $*" >&2
  exit 2
}

# Exit code 4: a distinct, machine-readable signal that `unpack`/`deploy
# --tarball` refused to touch an EXISTING release because the newly
# uploaded content does not match what is already there -- never
# conflated with a plain `die` (exit 1, "something went wrong") or
# `usage_die` (exit 2, "you called this wrong"). See
# deploy_unpack_tarball's sha256 dedup check (Fix round 1, P1): the caller
# (stack-deploy-ssh.sh, and stackbase/release.py above it) needs to tell
# "already uploaded, identical -- safe, continue" apart from "already
# exists with DIFFERENT content -- unsafe, stop" without resorting to
# matching human-readable text.
die_exists_diff() {
  echo "✗ $*" >&2
  exit 4
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
  # 0660, not mktemp's default 0600: STATE_DIR is setgid (group "deploy"),
  # so a temp file created by root (the boot/drain-stop units, both
  # root-run) still lands group "deploy" -- but only 0660 actually lets
  # the OTHER identity read/write it back (root always bypasses DAC
  # regardless of mode, so this only matters for deploy reading a
  # root-written file, e.g. over the SSH door after a boot-time write).
  # Checked explicitly, unlike mktemp/printf above: their failure already
  # cascades into the final `mv` below also failing, correctly surfacing
  # to the caller -- but a failed chmod here would NOT stop `mv` from
  # still succeeding on an unmodified 0600 file, silently reintroducing
  # the exact bug this exists to fix.
  chmod 0660 "$tmp" || return 1
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
  # Unlike atomic_write's temp file (always FRESHLY created by mktemp, so
  # the calling process always owns it and chmod always succeeds),
  # deploy.lock is a single long-lived file reused across every
  # invocation for the rest of the node's life. `exec 9>` on a brand-new
  # file creates it at the process's umask-default mode (0644 under a
  # typical 022 umask) -- group-readable but not group-writable -- so
  # STATE_DIR's setgid bit (fixes the GROUP) is paired with this chmod
  # (fixes the MODE) to let the OTHER identity (root/deploy, whichever
  # didn't create the file) open it for writing later. But only the
  # file's actual OWNER (or root) may chmod it -- POSIX chmod(2) is not
  # governed by the target's write permission, only by caller-is-owner-or
  # -root -- so once some other identity already created (and, being the
  # owner at the time, successfully chmod'd) this file, a later
  # non-owning identity's own chmod attempt here fails with EPERM. That
  # is expected and harmless: the file is already at the mode its actual
  # creator set, which is exactly what this chmod would have set anyway.
  chmod 0660 "$LOCK_FILE" 2>/dev/null || true
  if ! flock -n 9; then
    echo "✗ another deploy is already in progress (lock held: $LOCK_FILE)" >&2
    exit 3
  fi
}

# A single global counter (not one per color): any deploy or rollback,
# regardless of which color it touches, invalidates every older pending
# drain-stop. That's intentionally coarser than it needs to be -- a
# scheme scoped per-color could still be correct with more bookkeeping --
# but the failure mode of "too coarse" is a color that stays running
# longer than its drainSeconds (a stale drain-stop skips itself and never
# retries), never a color getting killed that shouldn't be. Erring toward
# "leave it running" over "maybe kill the wrong one" is the right trade
# for a production traffic swap.
next_generation() {
  local cur next
  if [ -f "$GENERATION_FILE" ]; then
    cur=$(cat "$GENERATION_FILE") || cur=0
  else
    cur=0
  fi
  next=$((cur + 1))
  # Explicit check, not just "last statement's status": without this, a
  # failed atomic_write here would still let `echo "$next"` (always
  # successful) be the function's last command, so `$(next_generation)`
  # would report success even though the counter was never persisted.
  atomic_write "$GENERATION_FILE" "$next" || return 1
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
#
# Called as `if ! activate_color ...; then` / `activate_color ... ||
# exit 1` by both callers -- per the top-of-file errexit note, that means
# `set -e` does NOT apply anywhere in this function's body. Every
# state-mutating step below is therefore checked explicitly, and the
# function distinguishes two very different failure classes via its
# return code:
#
#   return 1 (pre-flip): failed before the app.sock flip (start, health
#   check, or the pending-color intent write). Nothing user-visible has
#   changed -- cmd_deploy restores the idle color's previous `current`
#   link; cmd_rollback has nothing to restore either way.
#
#   return 2 (post-flip): failed at or after the app.sock flip. Traffic
#   has ALREADY moved to $idle -- callers must NOT restore any link and
#   must NOT stop $idle. pending-color is left in place so the next
#   deploy/rollback/boot finishes the bookkeeping via
#   resolve_pending_color.
#
# A failure only to SCHEDULE the drain-stop (the last block) is a
# warning, not either failure class: the old color simply keeps running
# until the next deploy stops it explicitly.
activate_color() {
  local idle="$1" prev_active="$2" version

  version=$(linked_version "$idle")

  echo "→ starting $idle on $version"
  if ! run_systemctl restart "${PROJECT}@${idle}.service"; then
    echo "✗ failed to start $idle (${PROJECT}@${idle}.service)" >&2
    return 1
  fi

  if ! wait_healthy "$idle"; then
    echo "✗ $idle failed the health check ($STACK_HEALTH_PATH) after $STACK_DEPLOY_HEALTH_TRIES tries" >&2
    run_systemctl stop "${PROJECT}@${idle}.service" || echo "i also failed to stop $idle after its failed health check; it may still be running" >&2
    return 1
  fi
  echo "✓ $idle is healthy"

  # Intent file: written just before the traffic flip, removed just after
  # the state file is written. Closes the crash window between the two --
  # see resolve_pending_color, called from cmd_boot and from the top of
  # cmd_deploy/cmd_rollback (in case a previous run crashed mid-swap).
  # Still pre-flip: nothing user-visible has changed yet.
  if ! atomic_write "$STATE_DIR/pending-color" "$idle"; then
    echo "✗ failed to record the pending-color intent; aborting before the traffic flip" >&2
    run_systemctl stop "${PROJECT}@${idle}.service" || echo "i also failed to stop $idle while aborting" >&2
    return 1
  fi

  # ---- Point of no return -------------------------------------------
  # Everything from here on mutates live routing state or bookkeeping
  # about it. A failure past this line means traffic may already be on
  # $idle: never undo the flip, never stop $idle.
  if ! atomic_symlink "app-${idle}.sock" "$SOCK_LINK"; then
    echo "✗ FAILED to flip app.sock to $idle. $idle is healthy and running -- do NOT stop it. Traffic routing is now inconsistent with recorded state; re-run 'stack-deploy deploy'/'rollback', or reboot -- resolve_pending_color will finish the flip automatically." >&2
    return 2
  fi
  echo "✓ traffic switched to $idle"

  # Constraint: the state file is written atomically AFTER the socket
  # symlink flip succeeds, never before.
  if ! atomic_write "$ACTIVE_COLOR_FILE" "$idle"; then
    echo "✗ traffic is on $idle now, but active-color could not be updated -- bookkeeping is incomplete. Nothing to do by hand: pending-color is still recorded, and the next 'stack-deploy deploy'/'rollback'/boot will finish this automatically via resolve_pending_color." >&2
    return 2
  fi

  if ! rm -f "$STATE_DIR/pending-color"; then
    echo "✗ traffic is on $idle and active-color is correct, but the pending-color intent file could not be removed -- bookkeeping is incomplete. The next 'stack-deploy deploy'/'rollback'/boot will finish this automatically via resolve_pending_color." >&2
    return 2
  fi

  if [ "$prev_active" != none ] && [ "$prev_active" != "$idle" ]; then
    local gen
    if ! gen=$(next_generation); then
      echo "i failed to schedule $prev_active's drain-stop (generation counter write failed); $prev_active will keep running until the next deploy stops it explicitly" >&2
    elif ! atomic_write "$STATE_DIR/drain-pending-${prev_active}" "$gen"; then
      echo "i failed to schedule $prev_active's drain-stop (pending marker write failed); $prev_active will keep running until the next deploy stops it explicitly" >&2
    elif ! run_systemctl restart "stackbase-drain@${prev_active}.timer"; then
      echo "i failed to schedule $prev_active's drain-stop (timer arm failed); $prev_active will keep running until the next deploy stops it explicitly" >&2
    else
      echo "→ $prev_active will stop in ${STACK_DRAIN_SECONDS}s"
    fi
  fi

  echo "i migrations run at app start: keep them additive (expand -> migrate -> contract in a later release)"
  return 0
}

# Finishes or discards a swap interrupted between the app.sock flip and the
# active-color write (see activate_color). Called at the top of
# deploy/rollback/boot so a leftover intent from a crashed prior run is
# always resolved before anything else touches state.
#
# Called PLAINLY (never in a condition context) by all three callers, so
# ordinary `set -e` governs this function's own top-level statements --
# but the `if ...; then <mutations>; fi` body below is still worth
# guarding explicitly, for two reasons: (1) `run_systemctl`/`wait_healthy`
# failing is already caught by the `if`'s own condition, but the three
# mutations *inside* the `then` branch getting a bare `set -e` abort would
# give the operator no diagnostic beyond bash silently exiting; (2) it
# keeps this function consistent with activate_color's explicit
# pre/post-flip style, which is the same class of bookkeeping this
# function performs while resuming an interrupted swap.
resolve_pending_color() {
  [ -f "$STATE_DIR/pending-color" ] || return 0

  local pcolor link
  pcolor=$(cat "$STATE_DIR/pending-color")
  link="$(color_dir "$pcolor")/current"

  if [ -e "$link" ]; then
    echo "i resuming a swap to $pcolor that was interrupted before its state was persisted"
    # run_systemctl (not a bare `systemctl start`): this path runs
    # whenever a leftover pending-color is resolved from cmd_deploy or
    # cmd_rollback, both reachable by the unprivileged `deploy` user via
    # Task 2's SSH forced command -- a bare `systemctl start` would fail
    # outright as `deploy` (no permission), silently discarding a
    # resumable swap instead of finishing it.
    if run_systemctl start "${PROJECT}@${pcolor}.service" && wait_healthy "$pcolor"; then
      if ! atomic_symlink "app-${pcolor}.sock" "$SOCK_LINK"; then
        echo "✗ FAILED to flip app.sock to $pcolor while resuming an interrupted swap. $pcolor is healthy and running -- do NOT stop it. Re-run 'stack-deploy deploy'/'rollback', or reboot -- this will be retried automatically." >&2
        return 1
      fi
      if ! atomic_write "$ACTIVE_COLOR_FILE" "$pcolor"; then
        echo "✗ traffic is on $pcolor now, but active-color could not be updated while resuming an interrupted swap -- bookkeeping is incomplete. The next 'stack-deploy deploy'/'rollback'/boot will finish this automatically." >&2
        return 1
      fi
      if ! rm -f "$STATE_DIR/pending-color"; then
        echo "✗ traffic is on $pcolor and active-color is correct, but the pending-color intent file could not be removed while resuming an interrupted swap -- bookkeeping is incomplete. The next 'stack-deploy deploy'/'rollback'/boot will finish this automatically." >&2
        return 1
      fi
      echo "✓ interrupted swap to $pcolor completed"
      return 0
    fi
    echo "i $pcolor did not come up healthy while resuming the interrupted swap; falling back to active-color" >&2
    run_systemctl stop "${PROJECT}@${pcolor}.service" || true
  else
    echo "i pending-color ($pcolor) has no linked release; discarding" >&2
  fi

  if ! rm -f "$STATE_DIR/pending-color"; then
    echo "✗ failed to remove the stale pending-color intent file at $STATE_DIR/pending-color" >&2
    return 1
  fi
}

deploy_unpack_tarball() {
  local version="$1" tarball="$2" sha256="$3" force="$4"
  local release_dir="$RELEASES_DIR/$version"

  [ -f "$tarball" ] || die "tarball not found: $tarball"

  # P1 (Fix round 1): a release directory that already exists is no longer
  # an automatic refusal -- it's only refused when the content actually
  # differs. Re-uploading the EXACT SAME tarball (a retried `upload` after
  # a dropped connection, a re-run deploy) is safe and idempotent; silently
  # keeping stale content because a caller re-tagged and rebuilt the same
  # version WITHOUT bumping it is not, so that case is refused, distinctly
  # (exit 4, not the generic exit 1), rather than accepted. Compared
  # against the CALLER-SUPPLIED $sha256 here, before the tarball is even
  # opened: the "same content" branch below touches NOTHING on disk (no
  # extraction, no rename), so there is no integrity exposure in trusting
  # the caller's claim for this decision alone -- the real tarball bytes
  # are only ever trusted, and verified against $sha256, in the path that
  # actually writes something (further down). --force (only reachable from
  # `stack-deploy deploy --tarball ... --force`) skips this branch
  # entirely and always overwrites, same as before this change; because
  # the sha256 file below is written unconditionally, a --force overwrite
  # always ends up with a `.stackbase-sha256` matching the NEW content.
  if [ -e "$release_dir" ] && [ "$force" -ne 1 ]; then
    local recorded_sha=""
    if [ -r "$release_dir/.stackbase-sha256" ]; then
      recorded_sha=$(head -n1 "$release_dir/.stackbase-sha256" 2>/dev/null || true)
    fi
    if [ -n "$recorded_sha" ] && [ "$recorded_sha" = "$sha256" ]; then
      echo "release $version is already uploaded (same content)"
      return 0
    fi
    die_exists_diff "release $version already exists with different content -- a published version must never change; bump the version instead"
  fi

  # Open the tarball exactly once, on a dedicated fd, and run every
  # subsequent operation (hash, both listings, extraction) against
  # /proc/self/fd/$fd rather than $tarball itself. Each open() of that
  # magic symlink starts a fresh read at offset 0 of the SAME underlying
  # inode, so "the archive we hashed and validated" and "the archive we
  # extract" are provably identical even if something swapped the path
  # under us between steps (TOCTOU). Closed explicitly once extraction is
  # done; a die() anywhere below exits the whole process, which closes it
  # too.
  local fd
  exec {fd}<"$tarball" || die "cannot open tarball: $tarball"

  local actual_sha
  actual_sha=$(sha256sum "/proc/self/fd/$fd" | awk '{print $1}')
  if [ "$actual_sha" != "$sha256" ]; then
    die "sha256 mismatch for $tarball: expected $sha256, got $actual_sha"
  fi

  # Member NAMES come ONLY from the plain listing (`tar -tzf`), one per
  # line, never parsed out of the verbose listing. Verbose columns are
  # right-justified, so a small member's size field is padded with
  # leading spaces that survive naive stripping and land in the recovered
  # name (e.g. an absolute path arrives as "  /abs/path"), silently
  # defeating the checks below for any member under ~1000 bytes -- this
  # is exactly what let an absolute-path/`..` member slip past the old
  # check. The verbose listing (`tar -tvzf`) is used ONLY for the
  # member's type character in column 1, which doesn't suffer from that
  # problem.
  local names_count types_count
  names_count=$(tar -tzf "/proc/self/fd/$fd" | wc -l)
  types_count=$(tar -tvzf "/proc/self/fd/$fd" | wc -l)
  if [ "$names_count" -ne "$types_count" ]; then
    die "tarball's plain and verbose listings disagree on member count ($names_count vs $types_count); refusing"
  fi

  local line type_char
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    type_char="${line:0:1}"
    case "$type_char" in
      -|d) : ;;
      *) die "tarball contains a member that is not a regular file or directory (type '$type_char'): $line" ;;
    esac
  done < <(tar -tvzf "/proc/self/fd/$fd")

  local name
  while IFS= read -r name; do
    [ -n "$name" ] || die "tarball contains a member with an empty name"
    case "$name" in
      /*) die "tarball contains an absolute path member: $name" ;;
      *\\*) die "tarball contains a member name with a backslash escape (likely an escaped control byte such as a newline): $name" ;;
    esac
    if printf '%s\n' "$name" | tr '/' '\n' | grep -qx '\.\.'; then
      die "tarball contains a '..' path member: $name"
    fi
  done < <(tar -tzf "/proc/self/fd/$fd")

  local tmp_dir
  tmp_dir=$(mktemp -d "$RELEASES_DIR/.tmp-${version}-XXXXXX")
  # --no-same-owner/--no-same-permissions: don't trust the archive's
  # recorded uid/gid or mode bits (a crafted tarball could ship a setuid
  # root binary or a world-writable file) -- extract with the invoking
  # user's ownership and umask-based permissions as a first line of
  # defense. --no-overwrite-dir: never let extraction change the mode of
  # a directory that already exists at the destination (moot here since
  # tmp_dir is always fresh, but cheap insurance).
  tar -xzf "/proc/self/fd/$fd" -C "$tmp_dir" --no-same-owner --no-same-permissions --no-overwrite-dir

  exec {fd}<&-

  # Second, unconditional line of defense: normalise every mode
  # explicitly rather than trust the extraction flags above. A plain
  # 3-digit octal chmod always clears setuid/setgid/sticky (they'd need a
  # 4th digit), so this strips them regardless of what the archive or the
  # extracting umask produced.
  find "$tmp_dir" -type d -exec chmod 0755 {} +
  find "$tmp_dir" -type f -exec chmod 0644 {} +
  if [ -f "$tmp_dir/$STACK_BINARY" ]; then
    chmod 0755 "$tmp_dir/$STACK_BINARY"
  fi

  # P1 (Fix round 1): record the verified tarball sha256 beside the
  # unpacked release, INSIDE tmp_dir and BEFORE the rename below -- so a
  # release directory under releases/ never exists without this file (the
  # dedup check above treats a missing/unreadable one as "unknown
  # content", never as "same content"). Written after the mode-
  # normalisation find calls above and chmod'd explicitly here, so it is
  # never swept into the executable-bit branch (that only ever touches
  # $STACK_BINARY by name) -- this file must never become executable, and
  # must never be mistaken by the app for one of its own static assets.
  printf '%s\n' "$actual_sha" > "$tmp_dir/.stackbase-sha256"
  chmod 0644 "$tmp_dir/.stackbase-sha256"

  rm -rf "$release_dir"
  mv -T "$tmp_dir" "$release_dir"
  echo "✓ unpacked $version"
}

# Unpacks a verified tarball into releases/<version>/ without touching
# active-color/app.sock -- i.e. everything deploy_unpack_tarball does and
# nothing more. This is the ONE place tarball validation (sha256, member
# type/path safety, mode normalisation, refuse-overwrite) lives; Task 2's
# SSH `upload` dispatcher (stack-deploy-ssh.sh) calls this subcommand
# after streaming stdin to disk under a size cap, rather than
# re-implementing any of that validation itself.
cmd_unpack() {
  local version="" tarball="" sha256=""

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

  [ -n "$version" ] || usage_die "usage: stack-deploy unpack <version> --tarball PATH --sha256 HEX"
  validate_version "$version"
  [ -n "$tarball" ] || usage_die "--tarball is required"
  [ -n "$sha256" ] || usage_die "--sha256 is required"

  acquire_lock
  deploy_unpack_tarball "$version" "$tarball" "$sha256" 0
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
  resolve_pending_color

  local release_dir="$RELEASES_DIR/$version"

  if [ -n "$tarball" ]; then
    deploy_unpack_tarball "$version" "$tarball" "$sha256" "$force"
  else
    [ -d "$release_dir" ] || die "release $version not found at $release_dir (unpack it first or pass --tarball)"
  fi

  local active idle idle_link prev_target
  active=$(read_active)
  idle=$(idle_for "$active")
  idle_link="$(color_dir "$idle")/current"

  # Capture what the idle color's `current` pointed at before we repoint
  # it, so a failed health check below can put it back rather than leave
  # `rollback` targeting the broken candidate we're about to try.
  prev_target=""
  if [ -e "$idle_link" ]; then
    prev_target=$(readlink "$idle_link")
  fi

  atomic_symlink "../releases/$version" "$idle_link"

  # activate_color returns 1 (pre-flip: nothing changed) or 2 (post-flip:
  # traffic already moved) -- see its own comment. Capturing $? via `||`
  # rather than `if ! activate_color; then` for the same reason: either
  # form runs activate_color with errexit disabled, but its own internals
  # are now self-guarded either way, so this is just about getting the
  # exact return code out.
  local rc=0
  activate_color "$idle" "$active" || rc=$?
  if [ "$rc" -eq 2 ]; then
    # Post-flip: activate_color already printed the loud diagnostic.
    # Do NOT touch idle_link and do NOT stop $idle -- it's serving live
    # traffic.
    exit 1
  elif [ "$rc" -ne 0 ]; then
    # Pre-flip (rc == 1): nothing user-visible changed -- restore the
    # idle color's previous `current` target so a later `rollback` can't
    # target the broken candidate we just tried.
    if [ -n "$prev_target" ]; then
      atomic_symlink "$prev_target" "$idle_link"
      echo "i $idle/current restored to its previous release" >&2
    else
      rm -f "$idle_link"
      echo "i $idle/current removed (it had no previous release)" >&2
    fi
    exit 1
  fi
}

cmd_rollback() {
  acquire_lock
  resolve_pending_color

  local active idle link
  active=$(read_active)
  [ "$active" != none ] || die "nothing has been deployed yet; cannot rollback"
  idle=$(idle_for "$active")
  link="$(color_dir "$idle")/current"
  [ -e "$link" ] || die "idle color $idle has no linked release; nothing to roll back to"

  # Unlike cmd_deploy, rollback never repoints $link -- it targets
  # whatever the idle color's `current` already points at -- so there is
  # nothing to restore on either activate_color failure class (pre- or
  # post-flip); a bare exit 1 is correct for both. activate_color itself
  # already printed the right diagnostic for whichever class occurred.
  activate_color "$idle" "$active" || exit 1
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
# Takes the deploy lock first (always uncontended at boot -- flock is an
# in-kernel lock on an open fd, so it can never survive a reboot even if
# something crashed mid-deploy) so it can't race a deploy triggered in
# the same window, and so resolve_pending_color's own writes are safe.
cmd_boot() {
  acquire_lock
  resolve_pending_color

  local active
  active=$(read_active)
  if [ "$active" = none ]; then
    echo "i no active-color set; nothing to start at boot"
    exit 0
  fi

  local link
  link="$(color_dir "$active")/current"
  if [ ! -e "$link" ]; then
    die "active color $active has no linked release at $link -- state file and release directory are out of sync; redeploy to recover"
  fi

  # run_systemctl (not a bare `systemctl start`): cmd_boot itself is only
  # ever invoked as root via stackbase-app-boot.service, but it shares
  # resolve_pending_color/activate_color's code paths with cmd_deploy and
  # cmd_rollback (both reachable by `deploy` over Task 2's SSH forced
  # command) -- using the same sudo-aware wrapper everywhere those shared
  # helpers can run keeps this correct regardless of caller, at zero cost
  # when running as root (run_systemctl's root branch is a bare systemctl
  # call).
  if ! run_systemctl start "${PROJECT}@${active}.service"; then
    die "failed to start $active (${PROJECT}@${active}.service) at boot"
  fi
  if ! wait_healthy "$active"; then
    echo "✗ $active failed the health check ($STACK_HEALTH_PATH) at boot; leaving traffic unrouted" >&2
    exit 1
  fi

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
  [ $# -ge 1 ] || usage_die "usage: stack-deploy <status|colors|deploy|rollback|prune|releases|unpack> [...]"
  local cmd="$1"
  shift
  case "$cmd" in
    status) cmd_status "$@" ;;
    colors) cmd_colors "$@" ;;
    unpack) cmd_unpack "$@" ;;
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
