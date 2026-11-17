#!/usr/bin/env python3
"""Ship this node's systemd journal to Cloudflare R2, one verified object at a time.

Run by a systemd timer (nixos/logs.nix). Each run:

1. Uploads any object spooled by an earlier run that did not verify.
2. Reads the journal after the saved cursor (`journalctl --output=json`),
   streaming line by line -- a 4 GB backlog is never held in memory.
3. Slims each entry to the fields a person searching logs needs, groups
   consecutive entries by the UTC hour they happened in, and writes each
   group gzipped to `pending/` (fsync'd), capped at `max_object_bytes` of
   NDJSON per object.
4. Uploads the group with `rclone rcat`, reads it back with `rclone cat` and
   compares sha256. Only then is the spool deleted and the cursor of the
   group's last entry saved (atomically). An upload R2 silently rejected can
   therefore never move the cursor -- the failure that retired Vector.
5. Stops when caught up or after `max_run_seconds`; the next run continues.

Object keys and fields match what Vector wrote before (key prefix
`journal/<host>/%Y/%m/%d/%H/`), so old archives and the README's search
commands keep working. Delivery is at-least-once: every line keeps the
journal `cursor`, so duplicates can be dropped downstream.

rclone is configured purely from the environment (remote `logs`,
`RCLONE_CONFIG_LOGS_*`); this script never reads or prints a credential.
Python stdlib only.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Iterator

MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_RUN_SECONDS = 240.0
REMOTE = "logs"

# journald field -> output field. Order is the order written per line.
_FIELDS = (
    ("_HOSTNAME", "host"),
    ("_SYSTEMD_UNIT", "unit"),
    ("SYSLOG_IDENTIFIER", "ident"),
    ("_PID", "pid"),
    ("PRIORITY", "priority"),
    ("MESSAGE", "message"),
    ("_BOOT_ID", "boot_id"),
    ("__CURSOR", "cursor"),
    ("CONTAINER_NAME", "CONTAINER_NAME"),
    ("CONTAINER_ID", "CONTAINER_ID"),
    ("IMAGE_NAME", "IMAGE_NAME"),
)


def _log(msg: str) -> None:
    print(f"log-shipper: {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Entry mapping


def _value(v: object) -> str | None:
    """journalctl's JSON value as a string.

    A string stays as is. A non-UTF-8 value arrives as a list of byte values
    and is decoded with replacement. A field repeated within one entry
    arrives as a list of values; the first is kept. `null` (a value
    journalctl declined to print) means absent.
    """
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        if all(isinstance(b, int) for b in v):
            try:
                return bytes(v).decode("utf-8", errors="replace")
            except ValueError:  # a value outside 0..255: not bytes after all
                return json.dumps(v)
        for item in v:
            s = _value(item)
            if s is not None:
                return s
        return None
    return str(v)


def _event_us(entry: dict) -> int | None:
    """When the event happened, in microseconds since the epoch."""
    for field in ("_SOURCE_REALTIME_TIMESTAMP", "__REALTIME_TIMESTAMP"):
        s = _value(entry.get(field))
        if s:
            try:
                return int(s)
            except ValueError:
                continue
    return None


def _iso(us: int) -> str:
    secs, frac = divmod(us, 1_000_000)
    return datetime.fromtimestamp(secs, UTC).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:06d}Z"


def slim(entry: dict) -> dict:
    """The fields shipped for one journal entry; absent ones are omitted."""
    out: dict[str, str] = {}
    us = _event_us(entry)
    if us is not None:
        out["timestamp"] = _iso(us)
    for src, dst in _FIELDS:
        v = _value(entry.get(src))
        if v is not None:
            out[dst] = v
    return out


def _slim_us(slimmed: dict) -> int:
    ts = slimmed.get("timestamp")
    if ts:
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            return int(dt.timestamp()) * 1_000_000 + dt.microsecond
        except ValueError:
            pass
    return int(time.time() * 1_000_000)


def object_key(host: str, first: dict, uid: str) -> str:
    """`journal/<host>/YYYY/MM/DD/HH/<first-event-unix-seconds>-<uid>.ndjson.gz`.

    `first` is the slimmed first entry of the object; its UTC event time
    picks the hour directory (an entry without one falls back to now).
    """
    secs = _slim_us(first) // 1_000_000
    hour = datetime.fromtimestamp(secs, UTC).strftime("%Y/%m/%d/%H")
    return f"journal/{host}/{hour}/{secs}-{uid}.ndjson.gz"


# --------------------------------------------------------------------------
# Config and state files


@dataclass
class Config:
    state: Path
    bucket: str
    host: str
    exclude_unit: str
    max_object_bytes: int = MAX_OBJECT_BYTES
    max_run_seconds: float = MAX_RUN_SECONDS

    @classmethod
    def from_env(cls) -> "Config":
        bucket = os.environ.get("LOGS_BUCKET", "").strip()
        if not bucket:
            raise RuntimeError("LOGS_BUCKET is not set")
        host = os.environ.get("LOGS_HOST", "").strip() or socket.gethostname().split(".")[0]
        return cls(
            state=Path(os.environ.get("LOGS_STATE", "").strip() or "/var/lib/stackbase-logs"),
            bucket=bucket,
            host=host,
            exclude_unit=os.environ.get("LOGS_EXCLUDE_UNIT", "").strip() or "stackbase-logs.service",
        )


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _read_cursor(cfg: Config) -> str | None:
    try:
        c = (cfg.state / "cursor").read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return c or None


def _save_cursor(cfg: Config, cursor: str) -> None:
    _write_atomic(cfg.state / "cursor", cursor + "\n")


def _pending_dir(cfg: Config) -> Path:
    return cfg.state / "pending"


def _spool_name(key: str) -> str:
    return urllib.parse.quote(key, safe="")


def _spool_key(name: str) -> str:
    return urllib.parse.unquote(name)


# --------------------------------------------------------------------------
# rclone


def _dest(cfg: Config, key: str) -> str:
    return f"{REMOTE}:{cfg.bucket}/{key}"


def _tail(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace").strip()
    return text[-500:] if text else "(no output)"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _upload_verified(cfg: Config, key: str, spool: Path) -> None:
    """Upload `spool` to `key` and prove it landed byte for byte; raise if not."""
    with open(spool, "rb") as f:
        put = subprocess.run(
            ["rclone", "rcat", _dest(cfg, key)], stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
    if put.returncode != 0:
        raise RuntimeError(f"upload of {key} failed (rclone rcat exit {put.returncode}): {_tail(put.stderr)}")

    h = hashlib.sha256()
    with tempfile.TemporaryFile() as err:
        with subprocess.Popen(["rclone", "cat", _dest(cfg, key)], stdout=subprocess.PIPE, stderr=err) as get:
            assert get.stdout is not None
            for chunk in iter(lambda: get.stdout.read(1 << 20), b""):
                h.update(chunk)
        rc = get.returncode
        err.seek(0)
        err_text = err.read()
    if rc != 0:
        raise RuntimeError(f"read-back of {key} failed (rclone cat exit {rc}): {_tail(err_text)}")
    want = _sha256_file(spool)
    if h.hexdigest() != want:
        raise RuntimeError(f"read-back of {key} does not match: sha256 {h.hexdigest()} != {want}")


def _last_cursor_in_spool(spool: Path) -> str | None:
    last = None
    with gzip.open(spool, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line).get("cursor", last)
    return last


def _ship_pending(cfg: Config) -> int:
    """Upload what an earlier run spooled but could not verify, oldest first."""
    pdir = _pending_dir(cfg)
    shipped = 0
    for p in sorted(pdir.iterdir()):
        if p.name.startswith("."):
            # A spool being written when the last run died; its entries are
            # after the saved cursor and will be read again.
            p.unlink()
            continue
        key = _spool_key(p.name)
        _log(f"retrying spooled object {key}")
        cursor = _last_cursor_in_spool(p)
        _upload_verified(cfg, key, p)
        p.unlink()
        _fsync_dir(pdir)
        if cursor:
            _save_cursor(cfg, cursor)
        shipped += 1
    return shipped


# --------------------------------------------------------------------------
# journalctl


class _CursorGone(Exception):
    pass


def _gap_warning(cursor: str, landed: str | None) -> None:
    _log(
        f"saved cursor no longer in the journal ({cursor}): the journal was rotated or the "
        "cursor is unreadable, so entries between it and where reading resumes may be lost; "
        f"resuming from {landed or 'the oldest entry'}"
    )


def _journal(cursor: str | None) -> Iterator[dict]:
    """Journal entries after `cursor` (or from the oldest), streamed.

    Reads with `--cursor`, not `--after-cursor`: for a well-formed cursor
    that has been rotated away, journalctl does not fail -- it seeks to the
    nearest entry and prints from there. Starting AT the cursor shows which
    happened: the first entry is the saved one (dropped, it was shipped) or
    it is not (the gap is logged and that entry is shipped too). A cursor
    journalctl cannot parse fails with "Failed to seek to cursor" and is
    handled by the caller.
    """
    argv = ["journalctl", "--output=json", "--no-pager", "--all"]
    if cursor:
        argv.append(f"--cursor={cursor}")
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err)
        assert proc.stdout is not None
        finished = False
        read = 0
        try:
            for raw in proc.stdout:
                if not raw.strip():
                    continue
                try:
                    entry = json.loads(raw)
                except ValueError:
                    _log("skipping a journal line that is not JSON")
                    continue
                if not isinstance(entry, dict):
                    continue
                read += 1
                if cursor and read == 1:
                    first = _value(entry.get("__CURSOR"))
                    if first == cursor:
                        continue
                    _gap_warning(cursor, first)
                yield entry
            finished = True
        finally:
            if not finished:
                proc.kill()
            proc.stdout.close()
            rc = proc.wait()
        err.seek(0)
        err_text = err.read()
    if rc != 0:
        if cursor and read == 0 and b"Failed to seek to cursor" in err_text:
            raise _CursorGone
        raise RuntimeError(f"journalctl exited {rc}: {_tail(err_text)}")


# --------------------------------------------------------------------------
# One run


class _Group:
    """One object being built: consecutive entries from one event-hour."""

    def __init__(self, cfg: Config, first: dict) -> None:
        self.key = object_key(cfg.host, first, str(uuid.uuid4()))
        self.hour = _slim_us(first) // 3_600_000_000
        self.final = _pending_dir(cfg) / _spool_name(self.key)
        self.part = self.final.with_name("." + self.final.name + ".part")
        self._file = open(self.part, "wb")
        self._gz = gzip.GzipFile(fileobj=self._file, mode="wb", mtime=0)
        self.size = 0
        self.lines = 0
        self.cursor: str | None = None

    def add(self, line: bytes) -> None:
        self._gz.write(line)
        self.size += len(line)
        self.lines += 1

    def seal(self) -> Path:
        self._gz.close()
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        os.replace(self.part, self.final)
        _fsync_dir(self.final.parent)
        return self.final

    def discard(self) -> None:
        if not self._file.closed:
            self._gz.close()
            self._file.close()
        self.part.unlink(missing_ok=True)


def _ship_group(cfg: Config, group: _Group) -> None:
    spool = group.seal()
    _upload_verified(cfg, group.key, spool)
    spool.unlink()
    _fsync_dir(spool.parent)
    if group.cursor:
        _save_cursor(cfg, group.cursor)


def _ship_journal(cfg: Config, cursor: str | None, out_of_time: Callable[[], bool]) -> int:
    shipped = 0
    group: _Group | None = None
    loose_cursor: str | None = None  # excluded entries read while no group was open
    try:
        for entry in _journal(cursor):
            entry_cursor = _value(entry.get("__CURSOR"))
            if _value(entry.get("_SYSTEMD_UNIT")) == cfg.exclude_unit:
                if group is not None:
                    group.cursor = entry_cursor or group.cursor
                else:
                    loose_cursor = entry_cursor or loose_cursor
                continue
            s = slim(entry)
            line = (json.dumps(s, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            hour = _slim_us(s) // 3_600_000_000
            if group is not None and (hour != group.hour or group.size + len(line) > cfg.max_object_bytes):
                current, group = group, None
                _ship_group(cfg, current)
                shipped += 1
                if out_of_time():
                    return shipped
            if group is None:
                group = _Group(cfg, s)
                loose_cursor = None
            group.add(line)
            group.cursor = entry_cursor or group.cursor
        if group is not None:
            current, group = group, None
            _ship_group(cfg, current)
            shipped += 1
        elif loose_cursor:
            _save_cursor(cfg, loose_cursor)
        return shipped
    finally:
        if group is not None:
            group.discard()


def run(cfg: Config, now: Callable[[], float] = time.monotonic) -> int:
    """Ship what is new; return how many objects were uploaded.

    Raises on any upload, read-back or journalctl failure, leaving the
    cursor where it was and the unverified object spooled in `pending/`.
    """
    start = now()

    def out_of_time() -> bool:
        return now() - start >= cfg.max_run_seconds

    pdir = _pending_dir(cfg)
    pdir.mkdir(parents=True, exist_ok=True)
    shipped = _ship_pending(cfg)

    if not out_of_time():
        cursor = _read_cursor(cfg)
        try:
            shipped += _ship_journal(cfg, cursor, out_of_time)
        except _CursorGone:
            _gap_warning(cursor or "", None)
            shipped += _ship_journal(cfg, None, out_of_time)

    _write_atomic(cfg.state / "last-success", f"{int(time.time())}\n")
    return shipped


def main() -> None:
    try:
        cfg = Config.from_env()
        n = run(cfg)
    except Exception as e:  # noqa: BLE001 - one line for the journal, then OnFailure
        _log(f"failed: {e}")
        sys.exit(1)
    if n:
        _log(f"shipped {n} object(s)")


if __name__ == "__main__":
    main()
