"""RAM-only scratch space: a directory that provably never touches a disk.

A couple of operations need somewhere to put bytes that must not survive
past the moment they're needed -- a freshly generated CI deploy private key
(`stackbase/ci.py`), or a secret being edited by hand
(`stackbase/secrets_cli.py`). Neither `/tmp` nor `tempfile.gettempdir()` is
good enough: both are usually disk-backed (or depend on `TMPDIR`, which
could point anywhere), so even an unlinked file can leave recoverable bytes
behind. `private_ram_dir()` is the one place in stack-base allowed to create
such a directory, and it refuses to run at all rather than silently falling
back to disk.

Where the RAM comes from depends on the operating system:

- Linux: `/dev/shm`, else a correctly-owned `$XDG_RUNTIME_DIR`.
- macOS: neither exists, so stack-base attaches a small RAM disk of its own
  (`hdiutil attach -nomount ram://N`, formatted and mounted by `diskutil`),
  uses it for the duration of the operation, and detaches it on the way out.
  That is the same thing an operator would otherwise have to do by hand
  before every `deploy-key init`, `ci-setup`, `secrets edit` or `deploy`.
"""

from __future__ import annotations

import contextlib
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator

from stackbase.errors import StackError

_DEV_SHM = Path("/dev/shm")
_PREFIX = "stackbase-"

_NO_RAM_HINT = (
    "run this command from a Linux machine (or CI) with /dev/shm, or from a Mac -- there "
    "stack-base attaches a RAM disk of its own for the duration of the command"
)

# 16 MiB of 512-byte sectors. HFS+ wants a few MiB of headroom for its own
# structures; everything stack-base ever puts here is a key or one secret's
# value, i.e. kilobytes.
_DARWIN_RAM_DISK_SECTORS = 32768

# Indirections so the tests can stand in for macOS and for its disk tools
# from a Linux box, where neither `hdiutil` nor `diskutil` exist.
_run = subprocess.run


def _is_darwin() -> bool:
    return sys.platform == "darwin"


def _dev_shm_candidate() -> Path | None:
    if not _DEV_SHM.is_dir():
        return None
    try:
        return Path(tempfile.mkdtemp(prefix=_PREFIX, dir=str(_DEV_SHM)))
    except OSError:
        return None


def _xdg_runtime_candidate() -> Path | None:
    """`$XDG_RUNTIME_DIR`, but only if it already looks like a real per-user
    runtime directory: it must exist, be owned by us, and be mode 0700 --
    this never creates or chmods it, only ever creates a subdirectory
    inside an already-trustworthy one.
    """
    raw = os.environ.get("XDG_RUNTIME_DIR")
    if not raw:
        return None
    base = Path(raw)
    try:
        info = base.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    if info.st_uid != os.getuid():
        return None
    if stat.S_IMODE(info.st_mode) != 0o700:
        return None
    try:
        return Path(tempfile.mkdtemp(prefix=_PREFIX, dir=str(base)))
    except OSError:
        return None


def _darwin_tool(argv: list[str], what: str) -> str:
    """Run one `hdiutil`/`diskutil` command and return its stdout, or raise."""
    try:
        result = _run(argv, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise StackError(f"{argv[0]} could not be run while {what}", str(exc)) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise StackError(
            f"{argv[0]} failed while {what}",
            detail[-1] if detail else f"run `{' '.join(argv)}` by hand to see why",
        )
    return result.stdout


def _darwin_mount_point(device: str) -> tuple[Path, bool]:
    """Where macOS mounted `device`, and whether it enforces ownership there.

    `diskutil eraseVolume` always mounts under /Volumes but picks the final
    name itself (it appends a number if the one asked for is taken), so ask
    rather than guess.
    """
    raw = _darwin_tool(["diskutil", "info", "-plist", device], "inspecting the RAM disk")
    try:
        info = plistlib.loads(raw.encode("utf-8"))
    except Exception as exc:  # plistlib raises several unrelated types
        raise StackError(
            "diskutil returned an unreadable description of the RAM disk", str(exc)
        ) from exc
    mount_point = info.get("MountPoint")
    if not isinstance(mount_point, str) or not mount_point:
        raise StackError(
            "the RAM disk was created but macOS did not mount it",
            f"run `diskutil info {device}` to see its state, then `hdiutil detach {device}`",
        )
    return Path(mount_point), bool(info.get("GlobalPermissionsEnabled", False))


@contextlib.contextmanager
def _darwin_ram_disk() -> Iterator[Path]:
    """Attach, format and mount a private RAM disk; detach it on the way out.

    No root needed: `hdiutil attach -nomount ram://` and `diskutil
    eraseVolume` both run as the ordinary logged-in user. The volume is
    chmod 0700 and, where macOS lets an ordinary user turn ownership on,
    ownership is enabled so that mode actually means something -- a
    freshly made volume otherwise has owners *ignored*, which is how macOS
    treats removable media (every local account would see the files as its
    own). When that cannot be enabled, the command still runs -- the
    guarantee that matters most, "never on a disk", holds regardless -- and
    says so once on stderr.
    """
    listing = _darwin_tool(
        ["hdiutil", "attach", "-nomount", f"ram://{_DARWIN_RAM_DISK_SECTORS}"],
        "creating a RAM disk",
    )
    device = listing.strip().split()[0] if listing.strip() else ""
    if not device.startswith("/dev/disk"):
        raise StackError(
            "hdiutil did not report a device for the new RAM disk",
            f"its output was: {listing.strip()!r}",
        )
    try:
        _darwin_tool(
            ["diskutil", "eraseVolume", "HFS+", f"{_PREFIX}{os.getpid()}", device],
            "formatting the RAM disk",
        )
        mount_point, owners_enforced = _darwin_mount_point(device)
        if not owners_enforced:
            # Not fatal when it fails: on most Macs this works for the
            # console user, and when it does not, the fallback below is
            # a warning, not a disk-backed directory.
            try:
                _darwin_tool(["diskutil", "enableOwnership", str(mount_point)], "enabling ownership")
            except StackError:
                pass
            _mount_point, owners_enforced = _darwin_mount_point(device)
        try:
            os.chmod(mount_point, 0o700)
        except OSError as exc:
            raise StackError(f"could not make the RAM disk at {mount_point} private", str(exc)) from exc
        if not owners_enforced:
            print(
                "warning: macOS does not enforce file ownership on the RAM disk stack-base just "
                "created, so another account logged in to this Mac right now could read its "
                "contents while this command runs -- the contents still never touch a disk",
                file=sys.stderr,
            )
        yield Path(tempfile.mkdtemp(prefix=_PREFIX, dir=str(mount_point)))
    finally:
        # `_wipe` has already run on the subdirectory by the time control
        # gets here (see private_ram_dir); detaching discards the memory
        # pages themselves. Plain detach first, forced if something (a
        # Finder window, Spotlight) still has the volume open.
        try:
            _darwin_tool(["hdiutil", "detach", device], "detaching the RAM disk")
        except StackError:
            try:
                _darwin_tool(["hdiutil", "detach", "-force", device], "detaching the RAM disk")
            except StackError:
                print(
                    f"warning: the RAM disk {device} could not be detached -- run "
                    f"`hdiutil detach -force {device}` to release it (it holds only zeroed files)",
                    file=sys.stderr,
                )


@contextlib.contextmanager
def private_ram_dir() -> Iterator[Path]:
    """Yield a fresh, 0700, RAM-backed scratch directory.

    Tries `/dev/shm` first (present on essentially every Linux box,
    including CI runners), then `$XDG_RUNTIME_DIR`. On macOS, where neither
    exists by default, it attaches a RAM disk of its own instead (see
    `_darwin_ram_disk`). Raises `StackError` if nothing is usable -- there
    is deliberately no disk-backed fallback.

    On the way out -- success, an exception, or `KeyboardInterrupt` -- every
    regular file directly or indirectly inside the directory is overwritten
    with zeros (best effort: a failure here never blocks cleanup), then the
    whole directory is removed. `tempfile.mkdtemp` itself always creates the
    directory (and this function's own subdirectory of it) at mode 0700, not
    subject to the umask.
    """
    directory = _dev_shm_candidate() or _xdg_runtime_candidate()
    if directory is not None:
        try:
            yield directory
        finally:
            _wipe(directory)
        return

    if _is_darwin():
        with _darwin_ram_disk() as directory:
            try:
                yield directory
            finally:
                _wipe(directory)
        return

    raise StackError(
        "no RAM-backed scratch space is available (/dev/shm and $XDG_RUNTIME_DIR are both "
        "missing or unusable)",
        _NO_RAM_HINT,
    )


def _wipe(directory: Path) -> None:
    """Best-effort zero-then-unlink of every regular file, then remove the tree."""
    for root, _dirs, files in os.walk(directory, topdown=False):
        for name in files:
            path = Path(root) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                size = path.stat().st_size
                with path.open("wb") as fh:
                    fh.write(b"\x00" * size)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass  # best effort -- the rmtree below still runs regardless
    shutil.rmtree(directory, ignore_errors=True)
