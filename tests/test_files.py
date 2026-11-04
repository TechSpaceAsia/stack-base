"""Tests for stackbase.files: the STORAGE_* block of the app's environment.

The bucket and its lock rule are Task 5's (`stackbase/r2.py`); this is the
other half -- handing the app the bucket's address and credentials, next to
`app_env` but never inside its digest.
"""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from stackbase.config import FilesConfig, load_config, NodeState, StackState, load_state, save_state
from stackbase.errors import StackError
from stackbase.files import storage_env_lines
from stackbase.r2 import R2Observation, files_lock_rule, r2_steps, r2_targets
from stackbase.reconcile import Action, Step, apply, local_facts, plan
from tests.fakes import FakeRunner
from tests.test_config import VALID_ED25519_KEY, VALID_TOML, TempInfraDir, write_key, write_toml
from tests.test_reconcile import (
    _IPV4,
    _VPS_ID,
    Infra,
    _config,
    _context,
    _converged_observed,
    _converged_state,
    _cp,
)

_SECRET = "s3cr3t-files-example-value"
_SECRETS = {
    "files_access_key_id": "FILESKEYEXAMPLE",
    "files_secret_access_key": _SECRET,
    "r2_endpoint": "https://abc123.r2.cloudflarestorage.com",
}


def _env(files: FilesConfig | None = None):
    return replace(_config().env(None), files=files if files is not None else FilesConfig())


_ON = FilesConfig(bucket="acme-files", lock_days=14)


class StorageEnvLinesTests(unittest.TestCase):
    def test_no_files_section_adds_nothing(self) -> None:
        self.assertEqual(storage_env_lines(_env(), {"app_env": "A=1\n", **_SECRETS}), [])

    def test_files_lines_rendered_with_lock_days(self) -> None:
        self.assertEqual(
            storage_env_lines(_env(_ON), _SECRETS),
            [
                "STORAGE_BUCKET=acme-files",
                "STORAGE_ENDPOINT=https://abc123.r2.cloudflarestorage.com",
                "STORAGE_REGION=auto",
                "STORAGE_ACCESS_KEY_ID=FILESKEYEXAMPLE",
                f"STORAGE_SECRET_ACCESS_KEY={_SECRET}",
                "STORAGE_LOCK_DAYS=14",
            ],
        )

    def test_lock_days_defaults_to_30(self) -> None:
        lines = storage_env_lines(_env(FilesConfig(bucket="b")), _SECRETS)
        self.assertIn("STORAGE_LOCK_DAYS=30", lines)

    def test_incomplete_files_credentials_named(self) -> None:
        with self.assertRaises(StackError) as caught:
            storage_env_lines(_env(_ON), {"files_access_key_id": "K"})
        text = f"{caught.exception} {caught.exception.hint}"
        self.assertIn("files_secret_access_key", text)
        self.assertIn("r2_endpoint", text)
        self.assertNotIn("files_access_key_id,", text)

    def test_odd_credential_value_refused_naming_the_key_only(self) -> None:
        bad = {**_SECRETS, "files_secret_access_key": "has space"}
        with self.assertRaises(StackError) as caught:
            storage_env_lines(_env(_ON), bad)
        self.assertIn("files_secret_access_key", str(caught.exception))
        self.assertNotIn("has space", f"{caught.exception} {caught.exception.hint}")

    def test_app_env_storage_collision_rejected(self) -> None:
        secrets = {**_SECRETS, "app_env": "FOO=1\n# c\n  STORAGE_BUCKET=mine\n"}
        with self.assertRaises(StackError) as caught:
            storage_env_lines(_env(_ON), secrets)
        self.assertIn("STORAGE_BUCKET", str(caught.exception))
        self.assertNotIn("mine", f"{caught.exception} {caught.exception.hint}")

    def test_collision_ignored_without_files(self) -> None:
        self.assertEqual(storage_env_lines(_env(), {"app_env": "STORAGE_BUCKET=x\n"}), [])


class LockDaysRangeTests(unittest.TestCase):
    def _load(self, days: int):
        with TempInfraDir() as infra_dir:
            write_toml(infra_dir, VALID_TOML + f'\n[files]\nbucket = "acme-files"\nlock_days = {days}\n')
            write_key(infra_dir, "matt", VALID_ED25519_KEY)
            return load_config(infra_dir)

    def test_range_enforced(self) -> None:
        for bad in (0, -1, 3651):
            with self.assertRaises(StackError, msg=bad) as caught:
                self._load(bad)
            self.assertIn("lock_days", str(caught.exception))
        for good in (1, 3650):
            self.assertEqual(self._load(good).env(None).files.lock_days, good)


class FilesBucketPlanTests(unittest.TestCase):
    def test_files_bucket_planned_with_lock_rule(self) -> None:
        env = _env(_ON)
        obs = R2Observation(target=r2_targets(env)[0], exists=False, rules=[])
        steps = r2_steps((obs,))
        self.assertEqual(
            [(s.action, s.bucket) for s in steps],
            [(Action.ENSURE_R2_BUCKET, "acme-files"), (Action.ENSURE_R2_LOCK, "acme-files")],
        )
        self.assertEqual(r2_targets(env)[0].rule, files_lock_rule(14))


class AppEnvPushTests(unittest.TestCase):
    def _observed(self, **local):
        base = _converged_observed()
        return replace(base, local=replace(base.local, **local))

    def test_no_files_section_changes_nothing(self) -> None:
        with Infra() as infra_dir:
            facts = local_facts(infra_dir, {"app_env": "A=1\n", **_SECRETS}, env=_env())
            self.assertIsNone(facts.files_env_sha)

    def test_files_change_alone_replans_the_app_env_push(self) -> None:
        env = _env(_ON)
        state = _converged_state()
        state.nodes["a"].app_env_sha = "same"
        state.nodes["a"].files_env_sha = "old"
        obs = self._observed(app_env_sha="same", files_env_sha="new")
        self.assertEqual([s.action for s in plan(_config(), state, obs, env=env)], [Action.ENSURE_APP_ENV])
        state.nodes["a"].files_env_sha = "new"
        self.assertEqual(plan(_config(), state, obs, env=env), [])

    def test_state_omits_unset_files_sha(self) -> None:
        with Infra() as infra_dir:
            env = _config().env(None)
            save_state(infra_dir, env, StackState(nodes={"a": NodeState(vps_id=1)}))
            node = json.loads((infra_dir / "stack.state.json").read_text(encoding="utf-8"))["nodes"]["a"]
            self.assertNotIn("files_env_sha", node)
            save_state(infra_dir, env, StackState(nodes={"a": NodeState(vps_id=1, files_env_sha="x")}))
            self.assertEqual(load_state(infra_dir, env).nodes["a"].files_env_sha, "x")

    def test_push_appends_storage_lines_and_records_both_digests(self) -> None:
        secrets = {"hostinger_token": "h", "cloudflare_token": "c", "app_env": "FOO=1\n", **_SECRETS}

        def handler(argv, kwargs):
            if "active-color" in argv[-1] and "cat --" in argv[-1]:
                return _cp(argv, returncode=0, stdout="blue\n")
            return _cp(argv, returncode=0)

        with Infra() as infra_dir:
            ctx, lines = _context(
                infra_dir,
                state=StackState(nodes={"a": NodeState(vps_id=_VPS_ID, ipv4=_IPV4, host_key_pinned=True)}),
                secrets=secrets,
                runner=FakeRunner(handler=handler),
                env=_env(_ON),
            )
            apply([Step(Action.ENSURE_APP_ENV, "a")], ctx, allow_purchase=False)
            pushed = next(
                c["kwargs"]["input"] for c in ctx.runner.calls if c["kwargs"].get("input") is not None
            )
            self.assertTrue(pushed.startswith("FOO=1\n"))
            self.assertIn("STORAGE_BUCKET=acme-files\n", pushed)
            for call in ctx.runner.calls:
                self.assertNotIn(_SECRET, " ".join(call["argv"]))
            for line in lines:
                self.assertNotIn(_SECRET, line)
            node = ctx.state.nodes["a"]
            self.assertIsNotNone(node.files_env_sha)
            from stackbase.reconcile import app_env_digest

            self.assertEqual(node.app_env_sha, app_env_digest("FOO=1\n"))


if __name__ == "__main__":
    unittest.main()
