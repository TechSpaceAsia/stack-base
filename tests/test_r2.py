"""Tests for stackbase.r2: the R2 account client, rule helpers and ENSURE planning.

Fixtures in tests/fixtures/r2_*.json follow Cloudflare's API reference
(developers.cloudflare.com/api/resources/r2/...), fetched 2026-11-04.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
from pathlib import Path

from stackbase.config import FilesConfig, LogsConfig, Node, StackConfig
from stackbase.errors import StackError
from stackbase.r2 import (
    R2Account,
    R2Observation,
    ensure_lifecycle_rule,
    ensure_lock_rule,
    files_lock_rule,
    logs_lifecycle_rule,
    merge_rule,
    observe_r2,
    r2_account_for,
    r2_steps,
    r2_targets,
)
from stackbase.reconcile import Action, Step
from tests.fakes import FakeServer

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_ACCT = "acct123"
_B = f"/accounts/{_ACCT}/r2/buckets"


def _fx(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _env(*, logs=None, files=None):
    cfg = StackConfig(
        project="acme",
        domain="acme.example.com",
        owner="matt",
        datacenter="kul",
        plan="KVM 1",
        price_item=None,
        auto_patch=True,
        admins=["matt"],
        nodes={"a": Node(name="a", role="primary", vps_id=1)},
        admin_keys={"matt": "ssh-ed25519 AAAA matt"},
    )
    env = cfg.env(None)
    return dataclasses.replace(env, logs=logs or LogsConfig(), files=files or FilesConfig())


class RuleHelperTests(unittest.TestCase):
    def test_logs_lifecycle_rule_shape(self) -> None:
        self.assertEqual(
            logs_lifecycle_rule(90),
            {
                "id": "stackbase-logs",
                "enabled": True,
                "conditions": {"prefix": "journal/"},
                "deleteObjectsTransition": {"condition": {"type": "Age", "maxAge": 90 * 86400}},
            },
        )

    def test_files_lock_rule_shape(self) -> None:
        self.assertEqual(
            files_lock_rule(30),
            {
                "id": "stackbase-files",
                "enabled": True,
                "prefix": "",
                "condition": {"type": "Age", "maxAgeSeconds": 30 * 86400},
            },
        )

    def test_merge_rule_replaces_own_id_only(self) -> None:
        rules = _fx("r2_lifecycle_get.json")["result"]["rules"]
        merged = merge_rule(rules, logs_lifecycle_rule(90))
        self.assertEqual([r["id"] for r in merged], ["someone-elses-rule", "stackbase-logs"])
        self.assertEqual(merged[0], rules[0])
        self.assertEqual(merged[1], logs_lifecycle_rule(90))
        self.assertEqual(rules[1]["deleteObjectsTransition"]["condition"]["maxAge"], 2592000)  # input untouched

    def test_merge_rule_appends_when_absent(self) -> None:
        merged = merge_rule([{"id": "x"}], logs_lifecycle_rule(7))
        self.assertEqual([r["id"] for r in merged], ["x", "stackbase-logs"])


class AccountClientTests(unittest.TestCase):
    def test_bucket_exists_true_and_false(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-logs", 200, _fx("r2_bucket_get.json"))
            server.script("GET", f"{_B}/nope-bucket", 404, _fx("r2_bucket_missing.json"))
            acct = R2Account("tok", _ACCT, base_url=server.url)
            self.assertTrue(acct.bucket_exists("acme-logs"))
            self.assertFalse(acct.bucket_exists("nope-bucket"))

    def test_create_bucket_posts_name(self) -> None:
        with FakeServer() as server:
            server.script("POST", _B, 200, _fx("r2_bucket_create.json"))
            R2Account("tok", _ACCT, base_url=server.url).create_bucket("acme-logs")
            self.assertEqual(server.requests[0]["body"], {"name": "acme-logs"})

    def test_get_and_put_lifecycle(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_lifecycle_get.json"))
            server.script("PUT", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_put_ok.json"))
            acct = R2Account("tok", _ACCT, base_url=server.url)
            rules = acct.get_lifecycle("acme-logs")
            self.assertEqual(len(rules), 2)
            acct.put_lifecycle("acme-logs", rules)
            self.assertEqual(server.requests[1]["body"], {"rules": rules})

    def test_get_and_put_lock(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-files/lock", 200, _fx("r2_lock_get.json"))
            server.script("PUT", f"{_B}/acme-files/lock", 200, _fx("r2_put_ok.json"))
            acct = R2Account("tok", _ACCT, base_url=server.url)
            rules = acct.get_lock("acme-files")
            self.assertEqual(rules[1]["condition"]["maxAgeSeconds"], 86400)
            acct.put_lock("acme-files", rules)
            self.assertEqual(server.requests[1]["body"], {"rules": rules})

    def test_put_refuses_an_empty_rule_list(self) -> None:
        acct = R2Account("tok", _ACCT, base_url="http://127.0.0.1:1")
        with self.assertRaises(StackError):
            acct.put_lock("acme-files", [])
        with self.assertRaises(StackError):
            acct.put_lifecycle("acme-logs", [])

    def test_bad_bucket_name_is_refused_before_any_request(self) -> None:
        acct = R2Account("tok", _ACCT, base_url="http://127.0.0.1:1")
        with self.assertRaises(StackError):
            acct.bucket_exists("../zones")

    def test_lock_update_preserves_foreign_rules(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-files/lock", 200, _fx("r2_lock_get.json"))
            server.script("PUT", f"{_B}/acme-files/lock", 200, _fx("r2_put_ok.json"))
            acct = R2Account("tok", _ACCT, base_url=server.url)
            ensure_lock_rule(acct, "acme-files", files_lock_rule(30))
            sent = server.requests[1]["body"]["rules"]
            self.assertEqual([r["id"] for r in sent], ["legal-hold", "stackbase-files"])
            self.assertEqual(sent[0], _fx("r2_lock_get.json")["result"]["rules"][0])
            self.assertEqual(sent[1]["condition"]["maxAgeSeconds"], 30 * 86400)

    def test_lifecycle_update_preserves_foreign_rules(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_lifecycle_get.json"))
            server.script("PUT", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_put_ok.json"))
            acct = R2Account("tok", _ACCT, base_url=server.url)
            ensure_lifecycle_rule(acct, "acme-logs", logs_lifecycle_rule(90))
            sent = server.requests[1]["body"]["rules"]
            self.assertEqual([r["id"] for r in sent], ["someone-elses-rule", "stackbase-logs"])


class UnreadableRulesTests(unittest.TestCase):
    """A GET we cannot read must never lead to a PUT (a PUT replaces every rule)."""

    _BAD = [
        ("result null", 200, {"success": True, "errors": [], "result": None}),
        ("result empty object", 200, {"success": True, "errors": [], "result": {}}),
        ("rules a string", 200, {"success": True, "errors": [], "result": {"rules": "oops"}}),
        ("non-dict entry", 200, {"success": True, "errors": [], "result": {"rules": [{"id": "a"}, "x"]}}),
        ("http 500", 500, {"success": False, "errors": [{"code": 1, "message": "boom"}]}),
    ]

    def test_no_put_after_unreadable_get(self) -> None:
        for kind, ensure, rule in (
            ("lifecycle", ensure_lifecycle_rule, logs_lifecycle_rule(90)),
            ("lock", ensure_lock_rule, files_lock_rule(30)),
        ):
            for label, status, body in self._BAD:
                with self.subTest(kind=kind, case=label), FakeServer() as server:
                    server.script("GET", f"{_B}/acme-b/{kind}", status, body)
                    server.script("PUT", f"{_B}/acme-b/{kind}", 200, _fx("r2_put_ok.json"))
                    acct = R2Account("tok", _ACCT, base_url=server.url)
                    with self.assertRaises(StackError):
                        ensure(acct, "acme-b", rule)
                    self.assertEqual([r["method"] for r in server.requests], ["GET"])

    def test_explicit_empty_rules_means_no_rules(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-b/lock", 200, _fx("r2_rules_empty.json"))
            server.script("PUT", f"{_B}/acme-b/lock", 200, _fx("r2_put_ok.json"))
            ensure_lock_rule(R2Account("tok", _ACCT, base_url=server.url), "acme-b", files_lock_rule(30))
            self.assertEqual([r["id"] for r in server.requests[1]["body"]["rules"]], ["stackbase-files"])

    def test_just_created_bucket_treats_empty_result_as_no_rules(self) -> None:
        with FakeServer() as server:
            server.script("POST", _B, 200, _fx("r2_bucket_create.json"))
            server.script("GET", f"{_B}/acme-b/lock", 200, {"success": True, "errors": [], "result": {}})
            server.script("PUT", f"{_B}/acme-b/lock", 200, _fx("r2_put_ok.json"))
            acct = R2Account("tok", _ACCT, base_url=server.url)
            acct.create_bucket("acme-b")
            ensure_lock_rule(acct, "acme-b", files_lock_rule(30))
            self.assertEqual([r["id"] for r in server.requests[2]["body"]["rules"]], ["stackbase-files"])

    def test_just_created_bucket_still_refuses_null_result(self) -> None:
        with FakeServer() as server:
            server.script("POST", _B, 200, _fx("r2_bucket_create.json"))
            server.script("GET", f"{_B}/acme-b/lock", 200, {"success": True, "errors": [], "result": None})
            acct = R2Account("tok", _ACCT, base_url=server.url)
            acct.create_bucket("acme-b")
            with self.assertRaises(StackError):
                ensure_lock_rule(acct, "acme-b", files_lock_rule(30))
            self.assertEqual([r["method"] for r in server.requests], ["POST", "GET"])

    def test_404_with_other_error_code_is_not_absent(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-b", 404, {"success": False, "errors": [{"code": 7003, "message": "no route"}]})
            with self.assertRaises(StackError) as ctx:
                R2Account("tok", _ACCT, base_url=server.url).bucket_exists("acme-b")
            self.assertIn("cloudflare_account_id", ctx.exception.hint)

    def test_bodyless_404_is_absent(self) -> None:
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-b", 404, None)
            self.assertFalse(R2Account("tok", _ACCT, base_url=server.url).bucket_exists("acme-b"))


class AccountIdTests(unittest.TestCase):
    def test_missing_account_id_names_secret(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs"))
        with self.assertRaises(StackError) as ctx:
            r2_account_for(env, {"cloudflare_token": "tok"})
        self.assertIn("cloudflare_account_id", ctx.exception.message + ctx.exception.hint)

    def test_the_account_id_hint_names_the_environment(self) -> None:
        env = dataclasses.replace(_env(logs=LogsConfig(bucket="acme-logs")), name="staging")
        with self.assertRaises(StackError) as ctx:
            r2_account_for(env, {"cloudflare_token": "tok"})
        self.assertIn('./infra/up --env "$ENV" secrets set cloudflare_account_id', ctx.exception.hint)
        self.assertIn("ENV=staging", ctx.exception.hint)

    def test_the_account_id_hint_has_no_env_flag_without_environments(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs"))
        with self.assertRaises(StackError) as ctx:
            r2_account_for(env, {"cloudflare_token": "tok"})
        self.assertNotIn("--env", ctx.exception.hint)

    def test_missing_token_names_secret(self) -> None:
        env = _env(files=FilesConfig(bucket="acme-files"))
        with self.assertRaises(StackError) as ctx:
            r2_account_for(env, {"cloudflare_account_id": _ACCT})
        self.assertIn("cloudflare_token", ctx.exception.message + ctx.exception.hint)

    def test_no_buckets_needs_nothing(self) -> None:
        self.assertIsNone(r2_account_for(_env(), {}))

    def test_disabled_logs_need_nothing(self) -> None:
        env = _env(logs=LogsConfig(enabled=False, bucket="acme-logs"))
        self.assertEqual(r2_targets(env), [])
        self.assertIsNone(r2_account_for(env, {}))


class TargetsTests(unittest.TestCase):
    def test_defaults(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs"), files=FilesConfig(bucket="acme-files"))
        targets = r2_targets(env)
        self.assertEqual([(t.kind, t.bucket) for t in targets], [("logs", "acme-logs"), ("files", "acme-files")])
        self.assertEqual(targets[0].rule, logs_lifecycle_rule(90))
        self.assertEqual(targets[1].rule, files_lock_rule(30))

    def test_configured_days(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs", retention_days=365), files=FilesConfig(bucket="f1", lock_days=7))
        targets = r2_targets(env)
        self.assertEqual(targets[0].rule, logs_lifecycle_rule(365))
        self.assertEqual(targets[1].rule, files_lock_rule(7))


class ObserveTests(unittest.TestCase):
    def test_observe_reads_bucket_and_rules(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs"), files=FilesConfig(bucket="acme-files"))
        with FakeServer() as server:
            server.script("GET", f"{_B}/acme-logs", 200, _fx("r2_bucket_get.json"))
            server.script("GET", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_lifecycle_get.json"))
            server.script("GET", f"{_B}/acme-files", 404, _fx("r2_bucket_missing.json"))
            seen = observe_r2(R2Account("tok", _ACCT, base_url=server.url), env)
            self.assertTrue(seen[0].exists)
            self.assertEqual(len(seen[0].rules), 2)
            self.assertFalse(seen[1].exists)
            self.assertEqual(seen[1].rules, [])
            # a missing bucket's rules are never requested
            self.assertEqual(len(server.requests), 3)
            self.assertTrue(all(r["method"] == "GET" for r in server.requests))


def _obs(env, *, exists=True, rules=None, which=0):
    target = r2_targets(env)[which]
    return R2Observation(target=target, exists=exists, rules=rules or [])


class PlanTests(unittest.TestCase):
    def test_missing_bucket_plans_create(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs"))
        steps = r2_steps((_obs(env, exists=False),))
        self.assertEqual(
            [(s.action, s.bucket) for s in steps],
            [(Action.ENSURE_R2_BUCKET, "acme-logs"), (Action.ENSURE_R2_LIFECYCLE, "acme-logs")],
        )

    def test_in_sync_bucket_plans_nothing(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs"), files=FilesConfig(bucket="acme-files"))
        logs = _obs(env, rules=[logs_lifecycle_rule(90)], which=0)
        files = _obs(env, rules=[{"id": "other"}, files_lock_rule(30)], which=1)
        self.assertEqual(r2_steps((logs, files)), [])

    def test_in_sync_tolerates_omitted_empty_prefix(self) -> None:
        env = _env(files=FilesConfig(bucket="acme-files"))
        stored = {"id": "stackbase-files", "enabled": True, "condition": {"type": "Age", "maxAgeSeconds": 30 * 86400}}
        self.assertEqual(r2_steps((_obs(env, rules=[stored]),)), [])

    def test_changed_days_plans_rule_change_and_shows_it(self) -> None:
        env = _env(logs=LogsConfig(bucket="acme-logs", retention_days=365))
        old = _fx("r2_lifecycle_get.json")["result"]["rules"]
        steps = r2_steps((_obs(env, rules=old),))
        self.assertEqual([s.action for s in steps], [Action.ENSURE_R2_LIFECYCLE])
        text = steps[0].description
        self.assertIn("acme-logs", text)
        self.assertIn("365 days", text)
        self.assertIn("30 days", text)  # what it replaces

    def test_missing_rule_on_existing_bucket(self) -> None:
        env = _env(files=FilesConfig(bucket="acme-files", lock_days=14))
        steps = r2_steps((_obs(env, rules=[{"id": "legal-hold"}]),))
        self.assertEqual([s.action for s in steps], [Action.ENSURE_R2_LOCK])
        self.assertIn("14 days", steps[0].description)

    def test_shared_bucket_is_created_once(self) -> None:
        env = _env(logs=LogsConfig(bucket="shared-bkt"), files=FilesConfig(bucket="shared-bkt"))
        obs = (_obs(env, exists=False, which=0), _obs(env, exists=False, which=1))
        creates = [s for s in r2_steps(obs) if s.action is Action.ENSURE_R2_BUCKET]
        self.assertEqual(len(creates), 1)

    def test_no_targets_no_steps(self) -> None:
        self.assertEqual(r2_steps(()), [])


class StepWiringTests(unittest.TestCase):
    def test_execute_lifecycle_step_writes_merged_rules(self) -> None:
        from tempfile import TemporaryDirectory

        from stackbase import steps
        from tests.test_reconcile import _context

        env = _env(logs=LogsConfig(bucket="acme-logs"))
        with FakeServer() as server, TemporaryDirectory() as tmp:
            server.script("GET", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_lifecycle_get.json"))
            server.script("PUT", f"{_B}/acme-logs/lifecycle", 200, _fx("r2_put_ok.json"))
            ctx, lines = _context(Path(tmp), env=env)
            ctx.r2 = R2Account("tok", _ACCT, base_url=server.url)
            step = Step(Action.ENSURE_R2_LIFECYCLE, bucket="acme-logs")
            message = steps.execute(ctx, step)
            sent = server.requests[1]["body"]["rules"]
            self.assertEqual(sent[1]["deleteObjectsTransition"]["condition"]["maxAge"], 90 * 86400)
            self.assertIn("acme-logs", message)

    def test_step_description_without_bucket_unchanged(self) -> None:
        self.assertEqual(Step(Action.REBUILD, "a").description, "node a: rebuilding NixOS (this can take a few minutes)")


if __name__ == "__main__":
    unittest.main()
