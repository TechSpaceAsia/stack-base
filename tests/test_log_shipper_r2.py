"""Opt-in: nixos/log-shipper.py against a REAL Cloudflare R2 bucket.

Why this exists: Vector's uploads were silently rejected by real R2 while
every MinIO-based test passed. MinIO cannot prove R2 accepts what the
shipper sends; only R2 can. So this runs the real script with the real
`rclone`, configured exactly as nixos/logs.nix configures it (remote `logs`
from RCLONE_CONFIG_LOGS_* env, RCLONE_CONFIG=/dev/null, the key pair through
AWS env-auth), and only `journalctl` faked (a few fixed entries).

Skipped unless all four are set:

    STACKBASE_R2_TEST_ENDPOINT          https://<account>.r2.cloudflarestorage.com
    STACKBASE_R2_TEST_BUCKET            a bucket the key can write, read and delete in
    STACKBASE_R2_TEST_ACCESS_KEY_ID
    STACKBASE_R2_TEST_SECRET_ACCESS_KEY

Everything is written under `journal/_probe/` (LOGS_HOST=_probe) and deleted
again afterwards, even when the test fails. `rclone` must be on PATH:

    nix shell nixpkgs#rclone -c python3 -m unittest tests.test_log_shipper_r2 -v

Credentials are never printed: failures show the shipper's and rclone's
stderr only, never the environment.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory

_SCRIPT = Path(__file__).resolve().parent.parent / "nixos" / "log-shipper.py"
_VARS = (
    "STACKBASE_R2_TEST_ENDPOINT",
    "STACKBASE_R2_TEST_BUCKET",
    "STACKBASE_R2_TEST_ACCESS_KEY_ID",
    "STACKBASE_R2_TEST_SECRET_ACCESS_KEY",
)
_HOST = "_probe"
_PREFIX = f"journal/{_HOST}/"

# Replays FAKE_JOURNAL (JSON lines) whatever the arguments: the state dir is
# fresh, so the shipper reads from the oldest entry with no --cursor.
_FAKE_JOURNALCTL = """\
#!{python}
import os, sys
with open(os.environ["FAKE_JOURNAL"], "rb") as f:
    sys.stdout.buffer.write(f.read())
"""


@unittest.skipUnless(all(os.environ.get(v) for v in _VARS), "set STACKBASE_R2_TEST_* to run against real R2")
class RealR2Tests(unittest.TestCase):
    def setUp(self) -> None:
        rclone = shutil.which("rclone")
        if rclone is None:
            self.fail("rclone is not on PATH -- run under `nix shell nixpkgs#rclone`")
        self.bucket = os.environ["STACKBASE_R2_TEST_BUCKET"]

        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir()
        journalctl = fake_bin / "journalctl"
        journalctl.write_text(_FAKE_JOURNALCTL.replace("{python}", sys.executable))
        journalctl.chmod(0o755)
        (self.tmp / "home").mkdir()
        (self.tmp / "state").mkdir()

        # Only what the NixOS unit gives the script -- nothing inherited, so
        # a stray AWS_PROFILE or RCLONE_* on the operator's shell cannot
        # change what is tested.
        self.env = {
            "PATH": f"{fake_bin}{os.pathsep}{os.path.dirname(rclone)}{os.pathsep}/usr/bin:/bin",
            "HOME": str(self.tmp / "home"),
            "LOGS_BUCKET": self.bucket,
            "LOGS_STATE": str(self.tmp / "state"),
            "LOGS_HOST": _HOST,
            "LOGS_EXCLUDE_UNIT": "stackbase-logs.service",
            "FAKE_JOURNAL": str(self.tmp / "journal.jsonl"),
            "RCLONE_CONFIG": "/dev/null",
            "RCLONE_CONFIG_LOGS_TYPE": "s3",
            "RCLONE_CONFIG_LOGS_PROVIDER": "Cloudflare",
            "RCLONE_CONFIG_LOGS_ENV_AUTH": "true",
            "RCLONE_CONFIG_LOGS_REGION": "auto",
            "RCLONE_CONFIG_LOGS_NO_CHECK_BUCKET": "true",
            # What the unit's wrapper exports from logs.env's LOGS_ENDPOINT.
            "RCLONE_CONFIG_LOGS_ENDPOINT": os.environ["STACKBASE_R2_TEST_ENDPOINT"],
            "AWS_ACCESS_KEY_ID": os.environ["STACKBASE_R2_TEST_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["STACKBASE_R2_TEST_SECRET_ACCESS_KEY"],
        }
        # Registered before anything is uploaded: runs even if the test fails.
        self.addCleanup(self._purge)

    # -- rclone helpers (stderr only in failure messages, never the env) --

    def _rclone(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["rclone", *args], env=self.env, capture_output=True, timeout=120)

    def _remote(self, path: str = "") -> str:
        return f"logs:{self.bucket}/{_PREFIX}{path}"

    def _list(self) -> list[str]:
        r = self._rclone("lsf", "-R", "--files-only", self._remote())
        if r.returncode == 3:  # "directory not found": no object under the prefix
            return []
        self.assertEqual(r.returncode, 0, f"rclone lsf failed: {r.stderr.decode(errors='replace')[-500:]}")
        return [line for line in r.stdout.decode().splitlines() if line.strip()]

    def _purge(self) -> None:
        r = self._rclone("delete", self._remote())
        if r.returncode != 0:
            print(f"cleanup: rclone delete failed: {r.stderr.decode(errors='replace')[-500:]}", file=sys.stderr)

    # -- the tests --

    def test_ships_to_real_r2_and_reads_back(self) -> None:
        self._ship_and_check(3, lambda run_id, i: f"r2 probe {run_id} line {i}")

    def test_ships_object_above_rclone_streaming_cutoff(self) -> None:
        # rclone's --streaming-upload-cutoff is 100 KiB; a stdin upload above
        # it turns multipart. The shipper uploads a file of known size
        # (copyto: one PUT up to --s3-upload-cutoff). Random hex barely
        # compresses, so this object is several hundred KiB after gzip --
        # the size a backfill after an upgrade or an outage ships.
        size = self._ship_and_check(
            400, lambda run_id, i: f"r2 probe {run_id} line {i} " + os.urandom(1024).hex()
        )
        self.assertGreater(size, 100 * 1024, "object not above the 100 KiB streaming cutoff")

    def _ship_and_check(self, count: int, message) -> int:
        """Ship `count` fake entries through the real script; return the object's size."""
        run_id = str(uuid.uuid4())
        now_us = int(time.time() * 1_000_000) - 5_000_000
        # Keep every entry in one UTC hour so exactly one object is written.
        now_us = min(now_us, (now_us // 3_600_000_000 + 1) * 3_600_000_000 - count * 1000 - 1)
        entries = []
        expected = []
        for i in range(1, count + 1):
            us = now_us + i * 1000
            entry = {
                "__CURSOR": f"s=r2probe{run_id.replace('-', '')};i={i:x}",
                "__REALTIME_TIMESTAMP": str(us),
                "_BOOT_ID": "r2probeboot",
                "_HOSTNAME": _HOST,
                "_SYSTEMD_UNIT": "r2-probe.service",
                "SYSLOG_IDENTIFIER": "r2-probe",
                "_PID": str(1000 + i),
                "PRIORITY": "6",
                "MESSAGE": message(run_id, i),
                "_CMDLINE": "/bin/r2-probe --not-shipped",
            }
            entries.append(entry)
            secs, frac = divmod(us, 1_000_000)
            expected.append(
                {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs)) + f".{frac:06d}Z",
                    "host": _HOST,
                    "unit": "r2-probe.service",
                    "ident": "r2-probe",
                    "pid": str(1000 + i),
                    "priority": "6",
                    "message": entry["MESSAGE"],
                    "boot_id": "r2probeboot",
                    "cursor": entry["__CURSOR"],
                }
            )
        Path(self.env["FAKE_JOURNAL"]).write_text("".join(json.dumps(e) + "\n" for e in entries))

        run = subprocess.run(
            [sys.executable, str(_SCRIPT)], env=self.env, capture_output=True, timeout=300
        )
        self.assertEqual(
            run.returncode, 0, f"shipper exited {run.returncode}: {run.stderr.decode(errors='replace')[-1000:]}"
        )
        state = Path(self.env["LOGS_STATE"])
        self.assertEqual((state / "cursor").read_text().strip(), entries[-1]["__CURSOR"])
        self.assertEqual(list((state / "pending").iterdir()), [])
        self.assertTrue((state / "last-success").read_text().strip().isdigit())

        listed = self._list()
        self.assertEqual(len(listed), 1, listed)
        hour = time.strftime("%Y/%m/%d/%H", time.gmtime((now_us + 1000) // 1_000_000))
        self.assertTrue(listed[0].startswith(hour + "/"), listed)
        self.assertTrue(listed[0].endswith(".ndjson.gz"), listed)

        got = self._rclone("cat", self._remote(listed[0]))
        self.assertEqual(got.returncode, 0, f"rclone cat failed: {got.stderr.decode(errors='replace')[-500:]}")
        lines = [json.loads(line) for line in gzip.decompress(got.stdout).decode().splitlines() if line.strip()]
        self.assertEqual(lines, expected)

        self._purge()
        self.assertEqual(self._list(), [], f"{_PREFIX} is not empty after cleanup")
        return len(got.stdout)


if __name__ == "__main__":
    unittest.main()
