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
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Iterator

from stackbase.errors import StackError

_DEV_SHM = Path("/dev/shm")
_PREFIX = "stackbase-"

_NO_RAM_HINT = (
    "run this command from a Linux machine (or CI) with /dev/shm -- macOS has neither /dev/shm "
    "nor a usable $XDG_RUNTIME_DIR by default, so this command cannot run there safely"
)


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


@contextlib.contextmanager
def private_ram_dir() -> Iterator[Path]:
    """Yield a fresh, 0700, RAM-backed scratch directory.

    Tries `/dev/shm` first (present on essentially every Linux box,
    including CI runners), then `$XDG_RUNTIME_DIR`. Raises `StackError` if
    neither is usable -- there is deliberately no disk-backed fallback.

    On the way out -- success, an exception, or `KeyboardInterrupt` -- every
    regular file directly or indirectly inside the directory is overwritten
    with zeros (best effort: a failure here never blocks cleanup), then the
    whole directory is removed. `tempfile.mkdtemp` itself always creates the
    directory (and this function's own subdirectory of it) at mode 0700, not
    subject to the umask.
    """
    directory = _dev_shm_candidate() or _xdg_runtime_candidate()
    if directory is None:
        raise StackError(
            "no RAM-backed scratch space is available (/dev/shm and $XDG_RUNTIME_DIR are both "
            "missing or unusable)",
            _NO_RAM_HINT,
        )
    try:
        yield directory
    finally:
        _wipe(directory)


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
