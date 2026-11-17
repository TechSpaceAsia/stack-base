"""Tests for nixos/log-shipper.py: the journal -> R2 shipper run on every node.

The script is not a package module (it is installed as a single file by the
NixOS module), so it is loaded from its path. `journalctl` and `rclone` are
replaced by small fakes put first on `PATH`:

- `journalctl` replays the JSON-lines file named by `FAKE_JOURNAL` and
  appends its argv to `journalctl.calls`. Like real journalctl (systemd 262),
  `--cursor=X` starts AT X when X exists and at the nearest (here: oldest)
  entry when X is well-formed but rotated away; only a malformed cursor fails
  with "Failed to seek to cursor". `--after-cursor` is refused.
- `rclone rcat logs:<bucket>/<key>` stores stdin under `r2/<key>`;
  `rclone cat` serves it back. `FAKE_RCAT_FAIL=1` makes `rcat` fail and
  `FAKE_CAT_CORRUPT=1` makes `cat` return different bytes. Every argv is
  appended to `rclone.calls`.
"""

from __future__ import annotations

import contextlib
import gzip
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import time
import unittest
import urllib.parse
from pathlib import Path
from tempfile import TemporaryDirectory

_SCRIPT = Path(__file__).resolve().parent.parent / "nixos" / "log-shipper.py"


def _load():
    loader = importlib.machinery.SourceFileLoader("log_shipper", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("log_shipper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["log_shipper"] = module  # @dataclass resolves annotations through it
    loader.exec_module(module)
    return module


_FAKE_JOURNALCTL = """\
#!{python}
import json, os, sys
calls = os.path.join(os.environ["FAKE_DIR"], "journalctl.calls")
with open(calls, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
entries = []
path = os.environ["FAKE_JOURNAL"]
if os.path.exists(path):
    with open(path) as f:
        entries = [json.loads(line) for line in f if line.strip()]
start = 0
for arg in sys.argv[1:]:
    if arg.startswith("--after-cursor"):
        sys.stderr.write("fake: use --cursor\\n")
        sys.exit(2)
    if arg.startswith("--cursor="):
        cursor = arg.split("=", 1)[1]
        if not cursor.startswith("s="):
            sys.stderr.write("Failed to seek to cursor: Invalid argument\\n")
            sys.exit(1)
        idx = [i for i, e in enumerate(entries) if e["__CURSOR"] == cursor]
        start = idx[0] if idx else 0
for e in entries[start:]:
    sys.stdout.write(json.dumps(e) + "\\n")
"""

_FAKE_RCLONE = """\
#!{python}
import json, os, sys
d = os.environ["FAKE_DIR"]
with open(os.path.join(d, "rclone.calls"), "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
op, dest = sys.argv[1], sys.argv[-1]
remote, rest = dest.split(":", 1)
assert remote == "logs", dest
bucket, key = rest.split("/", 1)
assert bucket == os.environ["FAKE_BUCKET"], bucket
path = os.path.join(d, "r2", key)
if op == "rcat":
    data = sys.stdin.buffer.read()
    if os.environ.get("FAKE_RCAT_FAIL") == "1":
        sys.stderr.write("ERROR : Failed to rcat: AccessDenied\\n")
        sys.exit(1)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
elif op == "cat":
    with open(path, "rb") as f:
        data = f.read()
    if os.environ.get("FAKE_CAT_CORRUPT") == "1":
        data = data + b"x"
    sys.stdout.buffer.write(data)
else:
    sys.exit(2)
"""

# 2026-11-17T04:00:02.760172Z
_T0 = 1794888002760172


def _entry(n: int, us: int, **extra: object) -> dict:
    e = {
        "__CURSOR": f"s=abc;i={n:x}",
        "__REALTIME_TIMESTAMP": str(us),
        "__MONOTONIC_TIMESTAMP": "12345",
        "_BOOT_ID": "b00b",
        "_HOSTNAME": "test-host",
        "_SYSTEMD_UNIT": "app.service",
        "SYSLOG_IDENTIFIER": "app",
        "_PID": "42",
        "PRIORITY": "6",
        "MESSAGE": f"message {n}",
        "_CMDLINE": "/bin/app --secret-flag",
        "_EXE": "/bin/app",
    }
    e.update(extra)
    return e


class ShipperTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load()
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for name, src in (("journalctl", _FAKE_JOURNALCTL), ("rclone", _FAKE_RCLONE)):
            p = self.bin / name
            p.write_text(src.replace("{python}", sys.executable), encoding="utf-8")
            p.chmod(0o755)
        self.journal = self.tmp / "journal.jsonl"
        self.state = self.tmp / "state"
        self.r2 = self.tmp / "r2"
        self._saved_env = dict(os.environ)
        os.environ["PATH"] = f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"
        os.environ["FAKE_DIR"] = str(self.tmp)
        os.environ["FAKE_JOURNAL"] = str(self.journal)
        os.environ["FAKE_BUCKET"] = "logs-bucket"
        for k in ("FAKE_RCAT_FAIL", "FAKE_CAT_CORRUPT"):
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved_env)
        self._tmp.cleanup()

    # helpers

    def cfg(self, **kw: object):
        base = dict(
            state=self.state,
            bucket="logs-bucket",
            host="test-host",
            exclude_unit="stackbase-logs.service",
            max_object_bytes=64 * 1024 * 1024,
            max_run_seconds=240.0,
        )
        base.update(kw)
        return self.mod.Config(**base)

    def write_journal(self, entries: list[dict], append: bool = False) -> None:
        with self.journal.open("a" if append else "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def run_quiet(self, cfg, **kw) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            n = self.mod.run(cfg, **kw)
        return n, err.getvalue()

    def objects(self) -> list[str]:
        if not self.r2.exists():
            return []
        return sorted(str(p.relative_to(self.r2)) for p in self.r2.rglob("*") if p.is_file())

    def object_lines(self, key: str) -> list[dict]:
        data = gzip.decompress((self.r2 / key).read_bytes()).decode("utf-8")
        return [json.loads(line) for line in data.splitlines()]

    def cursor(self) -> str | None:
        p = self.state / "cursor"
        return p.read_text(encoding="utf-8").strip() if p.exists() else None

    def pending(self) -> list[str]:
        p = self.state / "pending"
        return sorted(x.name for x in p.iterdir()) if p.exists() else []

    def calls(self, name: str) -> list[list[str]]:
        p = self.tmp / f"{name}.calls"
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]


class SlimTests(ShipperTestCase):
    def test_slim_maps_nine_fields_and_container_fields(self) -> None:
        e = _entry(1, _T0, CONTAINER_NAME="web", __SEQNUM="7")
        out = self.mod.slim(e)
        self.assertEqual(
            set(out),
            {"timestamp", "host", "unit", "ident", "pid", "priority", "message", "boot_id", "cursor", "CONTAINER_NAME"},
        )
        self.assertEqual(out["timestamp"], "2026-11-17T04:00:02.760172Z")
        self.assertEqual(out["host"], "test-host")
        self.assertEqual(out["unit"], "app.service")
        self.assertEqual(out["ident"], "app")
        self.assertEqual(out["pid"], "42")
        self.assertEqual(out["priority"], "6")
        self.assertEqual(out["message"], "message 1")
        self.assertEqual(out["boot_id"], "b00b")
        self.assertEqual(out["cursor"], "s=abc;i=1")
        self.assertEqual(out["CONTAINER_NAME"], "web")
        # _SOURCE_REALTIME_TIMESTAMP (when the event happened) wins.
        e2 = _entry(1, _T0, _SOURCE_REALTIME_TIMESTAMP=str(_T0 - 1_000_000))
        self.assertEqual(self.mod.slim(e2)["timestamp"], "2026-11-17T04:00:01.760172Z")

    def test_absent_fields_are_omitted(self) -> None:
        e = {"__CURSOR": "c", "__REALTIME_TIMESTAMP": str(_T0), "MESSAGE": None}
        self.assertEqual(self.mod.slim(e), {"timestamp": "2026-11-17T04:00:02.760172Z", "cursor": "c"})

    def test_binary_message_is_decoded_with_replacement(self) -> None:
        out = self.mod.slim(_entry(1, _T0, MESSAGE=[104, 105, 255]))
        self.assertEqual(out["message"], "hi�")

    def test_object_key_layout(self) -> None:
        key = self.mod.object_key("test-host", self.mod.slim(_entry(1, _T0)), "u-u-i-d")
        self.assertEqual(key, "journal/test-host/2026/11/17/04/1794888002-u-u-i-d.ndjson.gz")


class RunTests(ShipperTestCase):
    def test_ships_new_entries_and_saves_cursor(self) -> None:
        entries = [_entry(i, _T0 + i * 1000) for i in range(3)]
        self.write_journal(entries)
        before = time.time()
        n, _ = self.run_quiet(self.cfg())
        self.assertEqual(n, 1)
        objs = self.objects()
        self.assertEqual(len(objs), 1)
        self.assertRegex(
            objs[0],
            r"^journal/test-host/2026/11/17/04/1794888002-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\.ndjson\.gz$",
        )
        self.assertEqual(self.object_lines(objs[0]), [self.mod.slim(e) for e in entries])
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])
        self.assertEqual(self.pending(), [])
        ls = int((self.state / "last-success").read_text(encoding="utf-8").strip())
        self.assertGreaterEqual(ls, int(before))
        # The journal is read in full JSON, from the oldest entry, never --boot.
        argv = self.calls("journalctl")[0]
        self.assertIn("--output=json", argv)
        self.assertIn("--no-pager", argv)
        self.assertFalse(any(a.startswith(("--after-cursor", "--cursor")) for a in argv))
        self.assertFalse(any(a.startswith("--boot") or a == "-b" for a in argv))

    def test_entries_split_by_event_hour(self) -> None:
        h5 = 1794891600_000000  # 2026-11-17T05:00:00Z
        entries = [_entry(0, h5 - 2_000_000), _entry(1, h5 - 1_000_000), _entry(2, h5), _entry(3, h5 + 5)]
        self.write_journal(entries)
        n, _ = self.run_quiet(self.cfg())
        self.assertEqual(n, 2)
        objs = self.objects()
        self.assertEqual([o.split("/")[5] for o in objs], ["04", "05"])
        self.assertEqual(self.object_lines(objs[0]), [self.mod.slim(e) for e in entries[:2]])
        self.assertEqual(self.object_lines(objs[1]), [self.mod.slim(e) for e in entries[2:]])
        self.assertTrue(objs[1].split("/")[6].startswith("1794891600-"))
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])

    def test_second_run_sends_only_new_entries(self) -> None:
        first = [_entry(i, _T0 + i) for i in range(3)]
        self.write_journal(first)
        self.run_quiet(self.cfg())
        second = [_entry(i, _T0 + i) for i in range(3, 5)]
        self.write_journal(second, append=True)
        n, err = self.run_quiet(self.cfg())
        self.assertEqual(n, 1)
        self.assertNotIn("cursor no longer in the journal", err)
        # Read starts AT the saved entry (--cursor); that entry is not re-shipped.
        self.assertIn(f"--cursor={first[-1]['__CURSOR']}", self.calls("journalctl")[1])
        shipped = [line["cursor"] for o in self.objects() for line in self.object_lines(o)]
        self.assertEqual(sorted(shipped), sorted(e["__CURSOR"] for e in first + second))
        new = [o for o in self.objects() if self.object_lines(o)[0]["cursor"] == second[0]["__CURSOR"]]
        self.assertEqual(len(new), 1)
        self.assertEqual(self.object_lines(new[0]), [self.mod.slim(e) for e in second])
        self.assertEqual(self.cursor(), second[-1]["__CURSOR"])

    def test_failed_upload_keeps_cursor_and_spool(self) -> None:
        first = [_entry(0, _T0)]
        self.write_journal(first)
        self.run_quiet(self.cfg())
        entries = [_entry(i, _T0 + i) for i in range(1, 4)]
        self.write_journal(entries, append=True)
        os.environ["FAKE_RCAT_FAIL"] = "1"
        with self.assertRaises(Exception):
            self.run_quiet(self.cfg())
        self.assertEqual(self.cursor(), first[0]["__CURSOR"])
        pend = self.pending()
        self.assertEqual(len(pend), 1)
        key = urllib.parse.unquote(pend[0])
        self.assertTrue(key.startswith("journal/test-host/2026/11/17/04/1794888002-"), key)
        self.assertTrue(key.endswith(".ndjson.gz"))
        last_success = (self.state / "last-success").read_text(encoding="utf-8")

        # main() turns the same failure into exit status 1 and one stderr line.
        os.environ.update(LOGS_BUCKET="logs-bucket", LOGS_STATE=str(self.state), LOGS_HOST="test-host")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            self.mod.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("AccessDenied", err.getvalue())
        self.assertNotIn("secret", err.getvalue().lower())
        self.assertEqual(self.cursor(), first[0]["__CURSOR"])
        self.assertEqual(self.pending(), pend)
        self.assertEqual((self.state / "last-success").read_text(encoding="utf-8"), last_success)

        # Next run, with R2 accepting: the spooled object goes first, under the
        # same key, then the cursor moves and nothing is re-sent.
        del os.environ["FAKE_RCAT_FAIL"]
        before = len(self.calls("rclone"))
        n, _ = self.run_quiet(self.cfg())
        self.assertEqual(n, 1)
        rcats = [c for c in self.calls("rclone")[before:] if c[0] == "rcat"]
        self.assertEqual(rcats[0][-1], f"logs:logs-bucket/{key}")
        self.assertEqual(len(rcats), 1)
        self.assertEqual(self.object_lines(key), [self.mod.slim(e) for e in entries])
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])
        self.assertIn(f"--cursor={entries[-1]['__CURSOR']}", self.calls("journalctl")[-1])

    def test_readback_mismatch_keeps_cursor(self) -> None:
        self.write_journal([_entry(i, _T0 + i) for i in range(3)])
        os.environ["FAKE_CAT_CORRUPT"] = "1"
        with self.assertRaises(Exception) as cm:
            self.run_quiet(self.cfg())
        self.assertIn("sha256", str(cm.exception))
        self.assertIsNone(self.cursor())
        self.assertEqual(len(self.pending()), 1)
        self.assertFalse((self.state / "last-success").exists())

    def test_own_unit_is_excluded(self) -> None:
        entries = [
            _entry(0, _T0),
            _entry(1, _T0 + 1, _SYSTEMD_UNIT="stackbase-logs.service"),
            _entry(2, _T0 + 2),
            _entry(3, _T0 + 3, _SYSTEMD_UNIT="stackbase-logs.service"),
        ]
        self.write_journal(entries)
        self.run_quiet(self.cfg())
        objs = self.objects()
        self.assertEqual(len(objs), 1)
        self.assertEqual(self.object_lines(objs[0]), [self.mod.slim(entries[0]), self.mod.slim(entries[2])])
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])

    def test_only_excluded_entries_still_advance_cursor(self) -> None:
        entries = [_entry(0, _T0, _SYSTEMD_UNIT="stackbase-logs.service")]
        self.write_journal(entries)
        n, _ = self.run_quiet(self.cfg())
        self.assertEqual(n, 0)
        self.assertEqual(self.calls("rclone"), [])
        self.assertEqual(self.cursor(), entries[0]["__CURSOR"])

    def test_cursor_gone_restarts_from_oldest(self) -> None:
        entries = [_entry(i, _T0 + i) for i in range(3)]
        self.write_journal(entries)
        self.state.mkdir(parents=True)
        (self.state / "cursor").write_text("s=rotated;i=ffff\n", encoding="utf-8")
        n, err = self.run_quiet(self.cfg())
        # Real journalctl does not fail on a rotated-away cursor: it lands on
        # the nearest entry. The first entry is not the saved one, so the gap
        # is named and that entry is shipped too.
        self.assertEqual(self.calls("journalctl"), [["--output=json", "--no-pager", "--all", "--cursor=s=rotated;i=ffff"]])
        self.assertIn("cursor no longer in the journal", err)
        self.assertIn("s=rotated;i=ffff", err)
        self.assertEqual(n, 1)
        self.assertEqual(self.object_lines(self.objects()[0]), [self.mod.slim(e) for e in entries])
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])

    def test_malformed_cursor_restarts_from_oldest(self) -> None:
        entries = [_entry(i, _T0 + i) for i in range(3)]
        self.write_journal(entries)
        self.state.mkdir(parents=True)
        (self.state / "cursor").write_text("garbage\n", encoding="utf-8")
        n, err = self.run_quiet(self.cfg())
        argvs = self.calls("journalctl")
        self.assertEqual(len(argvs), 2)
        self.assertIn("--cursor=garbage", argvs[0])
        self.assertFalse(any(a.startswith("--cursor") for a in argvs[1]))
        self.assertIn("cursor no longer in the journal", err)
        self.assertEqual(n, 1)
        self.assertEqual(self.object_lines(self.objects()[0]), [self.mod.slim(e) for e in entries])
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])

    def test_other_journalctl_failure_raises(self) -> None:
        self.write_journal([_entry(0, _T0)])
        (self.bin / "journalctl").write_text(
            f"#!{sys.executable}\nimport sys\nsys.stderr.write('boom\\n')\nsys.exit(3)\n", encoding="utf-8"
        )
        with self.assertRaises(Exception) as cm:
            self.run_quiet(self.cfg())
        self.assertIn("boom", str(cm.exception))
        self.assertIsNone(self.cursor())

    def test_large_backlog_is_split_and_resumed(self) -> None:
        entries = [_entry(i, _T0 + i) for i in range(50)]
        self.write_journal(entries)

        def clock() -> float:
            # Time runs out as soon as the first object has landed.
            return 0.0 if not self.objects() else 10_000.0

        n, _ = self.run_quiet(self.cfg(max_object_bytes=1000), now=clock)
        self.assertEqual(n, 1)
        objs = self.objects()
        self.assertEqual(len(objs), 1)
        first_lines = self.object_lines(objs[0])
        self.assertLess(len(first_lines), 50)
        raw = sum(len(json.dumps(x, separators=(",", ":"))) + 1 for x in first_lines)
        self.assertLessEqual(raw, 1000)
        self.assertEqual(self.cursor(), first_lines[-1]["cursor"])
        self.assertEqual(self.pending(), [])

        n2, _ = self.run_quiet(self.cfg(max_object_bytes=1000))
        self.assertGreater(n2, 1)
        shipped = [line for o in self.objects() for line in self.object_lines(o)]
        self.assertEqual(sorted(x["cursor"] for x in shipped), sorted(e["__CURSOR"] for e in entries))
        self.assertEqual(self.cursor(), entries[-1]["__CURSOR"])

    def test_nothing_new_writes_last_success_only(self) -> None:
        self.write_journal([])
        before = time.time()
        n, _ = self.run_quiet(self.cfg())
        self.assertEqual(n, 0)
        self.assertEqual(self.calls("rclone"), [])
        self.assertIsNone(self.cursor())
        ls = int((self.state / "last-success").read_text(encoding="utf-8").strip())
        self.assertGreaterEqual(ls, int(before))


class ConfigTests(ShipperTestCase):
    def test_from_env_defaults(self) -> None:
        for k in ("LOGS_STATE", "LOGS_HOST", "LOGS_EXCLUDE_UNIT"):
            os.environ.pop(k, None)
        os.environ["LOGS_BUCKET"] = "b"
        cfg = self.mod.Config.from_env()
        self.assertEqual(cfg.bucket, "b")
        self.assertEqual(cfg.state, Path("/var/lib/stackbase-logs"))
        self.assertNotIn(".", cfg.host)
        self.assertTrue(cfg.host)
        self.assertEqual(cfg.exclude_unit, "stackbase-logs.service")
        self.assertEqual(cfg.max_object_bytes, 64 * 1024 * 1024)
        self.assertEqual(cfg.max_run_seconds, 240)

    def test_missing_bucket_fails_main(self) -> None:
        os.environ.pop("LOGS_BUCKET", None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            self.mod.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("LOGS_BUCKET", err.getvalue())


if __name__ == "__main__":
    unittest.main()
