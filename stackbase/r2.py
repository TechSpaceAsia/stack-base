"""R2Account: the reconciler's interface to Cloudflare R2 bucket management.

Used for exactly three things, per environment: create the `[logs]` and
`[files]` buckets if missing, give the logs bucket its retention (lifecycle)
rule, and give the files bucket its bucket-lock rule. Endpoints (Cloudflare
API reference, fetched 2026-11-04):

    POST /accounts/{id}/r2/buckets                  {"name": ...}
    GET  /accounts/{id}/r2/buckets/{bucket}         404 / code 10006 when missing
    GET|PUT /accounts/{id}/r2/buckets/{bucket}/lifecycle   {"rules": [...]}
    GET|PUT /accounts/{id}/r2/buckets/{bucket}/lock        {"rules": [...]}

Both PUTs REPLACE the bucket's whole rule list, so every write is
read-merge-write: `merge_rule` swaps only the rule with our own id and leaves
every other rule exactly as it was. A PUT of an empty list would wipe rules,
so the client refuses to send one. This module has no method that deletes a
bucket, an object or a rule (`tests/test_no_delete.py` pins that).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from stackbase.errors import StackError
from stackbase.http import ApiError, request
from stackbase.secrets import redact

if TYPE_CHECKING:
    from stackbase.config import Environment
    from stackbase.reconcile import Step

_DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")

LOGS_RULE_ID = "stackbase-logs"
LOGS_PREFIX = "journal/"
FILES_RULE_ID = "stackbase-files"
DEFAULT_LOGS_RETENTION_DAYS = 90
DEFAULT_FILES_LOCK_DAYS = 30
_DAY = 86400


class R2Account:
    """Bearer-authenticated R2 client for one Cloudflare account."""

    def __init__(self, token: str, account_id: str, base_url: str = _DEFAULT_BASE_URL) -> None:
        if not _ACCOUNT_RE.match(account_id):
            raise StackError(
                "the 'cloudflare_account_id' secret does not look like a Cloudflare account id",
                "it is the 32-character id shown in the Cloudflare dashboard URL -- set it again with "
                "`printf '%s' \"$ACCOUNT_ID\" | ./infra/up secrets set cloudflare_account_id`",
            )
        self._token = token
        self._account_id = account_id
        self._base_url = base_url.rstrip("/")
        # Buckets this client created itself: they cannot hold foreign rules.
        self._created: set[str] = set()

    def _path(self, bucket: str, suffix: str = "") -> str:
        if not _BUCKET_RE.match(bucket):
            raise StackError(
                f"'{bucket}' is not a valid R2 bucket name",
                "bucket names are 3-63 characters: lowercase letters, digits and hyphens, "
                "starting and ending with a letter or digit -- fix it in stack.toml",
            )
        return f"/accounts/{self._account_id}/r2/buckets/{bucket}{suffix}"

    def _call(self, method: str, path: str, *, json_body: Any = None) -> dict[str, Any]:
        parsed = request(method, f"{self._base_url}{path}", token=self._token, json_body=json_body)
        if not isinstance(parsed, dict):
            raise ApiError(
                f"{method} {path} returned an unexpected response shape",
                "the Cloudflare API response was not a JSON object -- check the API status",
                status=200,
                body=redact(str(parsed)[:500], [self._token]),
            )
        if not parsed.get("success", False):
            errors = parsed.get("errors")
            text = "; ".join(
                f"{e.get('code')}: {e.get('message')}" for e in (errors if isinstance(errors, list) else []) if isinstance(e, dict)
            ) or "no error detail"
            text = redact(text, [self._token])
            raise ApiError(
                f"Cloudflare R2 request failed: {text}",
                "check that the Cloudflare token has 'Workers R2 Storage: Edit' and that "
                "cloudflare_account_id is the right account",
                status=200,
                body=text,
            )
        return parsed

    def bucket_exists(self, name: str) -> bool:
        path = self._path(name)
        try:
            self._call("GET", path)
        except ApiError as exc:
            # A missing bucket is HTTP 404 (error code 10006, "The specified
            # bucket does not exist"); anything else is a real failure.
            if exc.status == 404 and _is_missing_bucket(exc.body):
                return False
            if exc.status == 404:
                # A 404 that is not "bucket does not exist" is a wrong
                # account id or a token that cannot see this account.
                raise StackError(
                    f"R2 returned 404 for bucket '{name}' but not 'bucket does not exist'",
                    "check that cloudflare_account_id is the right account and that the token can see it",
                ) from exc
            raise
        return True

    def create_bucket(self, name: str) -> None:
        self._path(name)  # validates the name
        self._call("POST", f"/accounts/{self._account_id}/r2/buckets", json_body={"name": name})
        self._created.add(name)

    def get_lifecycle(self, name: str) -> list[dict]:
        return _rules(self._call("GET", self._path(name, "/lifecycle")), name, "lifecycle", fresh=name in self._created)

    def put_lifecycle(self, name: str, rules: list[dict]) -> None:
        self._put_rules(self._path(name, "/lifecycle"), rules)

    def get_lock(self, name: str) -> list[dict]:
        return _rules(self._call("GET", self._path(name, "/lock")), name, "lock", fresh=name in self._created)

    def put_lock(self, name: str, rules: list[dict]) -> None:
        self._put_rules(self._path(name, "/lock"), rules)

    def _put_rules(self, path: str, rules: list[dict]) -> None:
        if not rules:
            raise StackError(
                "refusing to write an empty R2 rule list",
                "a PUT replaces every rule on the bucket, so an empty list would remove them all -- "
                "this is a bug in stack-base, please report it",
            )
        self._call("PUT", path, json_body={"rules": rules})


def _is_missing_bucket(body: str) -> bool:
    """A body-less 404 is "absent"; a JSON one must carry error code 10006."""
    if not body.strip():
        return True
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return False
    errors = parsed.get("errors") if isinstance(parsed, dict) else None
    return isinstance(errors, list) and any(isinstance(e, dict) and e.get("code") == 10006 for e in errors)


def _rules(parsed: dict[str, Any], bucket: str, what: str, *, fresh: bool = False) -> list[dict]:
    """The rule list from a GET. Only an explicit `"rules": []` means "no rules".

    Both PUTs replace the whole list, so a GET we cannot read must never be
    mistaken for an empty bucket: merging into `[]` would erase every foreign
    rule (a legal-hold lock included). Anything unexpected refuses instead.
    (Cloudflare's reference marks `rules` optional but does not say an empty
    bucket omits it; the live API is believed to return `"rules": []`.)
    """
    result = parsed.get("result")
    if fresh and isinstance(result, dict) and "rules" not in result:
        # A bucket this run just created cannot hold foreign rules, so an
        # answer with no `rules` key (`result: {}`) means none yet.
        return []
    rules = result.get("rules") if isinstance(result, dict) else None
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        raise StackError(
            f"R2 returned an unreadable {what} rule list for bucket '{bucket}'",
            "nothing was written -- stack-base will not replace rules it cannot read; "
            "check the bucket in the Cloudflare dashboard and report this if it persists",
        )
    return rules


# -- Rules ---------------------------------------------------------------------


def merge_rule(rules: list[dict], rule: dict) -> list[dict]:
    """Replace the rule with `rule`'s id, or append it; every other rule is untouched."""
    merged: list[dict] = []
    replaced = False
    for existing in rules:
        if existing.get("id") == rule["id"]:
            if not replaced:
                merged.append(rule)
                replaced = True
            continue
        merged.append(existing)
    if not replaced:
        merged.append(rule)
    return merged


def logs_lifecycle_rule(days: int) -> dict:
    return {
        "id": LOGS_RULE_ID,
        "enabled": True,
        "conditions": {"prefix": LOGS_PREFIX},
        "deleteObjectsTransition": {"condition": {"type": "Age", "maxAge": days * _DAY}},
    }


def files_lock_rule(days: int) -> dict:
    return {
        "id": FILES_RULE_ID,
        "enabled": True,
        "prefix": "",
        "condition": {"type": "Age", "maxAgeSeconds": days * _DAY},
    }


def ensure_lifecycle_rule(account: R2Account, bucket: str, rule: dict) -> None:
    """Read the bucket's current rules fresh, swap in ours, write back."""
    account.put_lifecycle(bucket, merge_rule(account.get_lifecycle(bucket), rule))


def ensure_lock_rule(account: R2Account, bucket: str, rule: dict) -> None:
    account.put_lock(bucket, merge_rule(account.get_lock(bucket), rule))


def _subset(want: Any, have: Any) -> bool:
    if isinstance(want, dict):
        return isinstance(have, dict) and all(k in have and _subset(v, have[k]) for k, v in want.items())
    return want == have


def _normalised(kind: str, rule: dict) -> dict:
    """The API may omit an empty prefix; treat it as the empty string."""
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in rule.items()}
    if kind == "files":
        out.setdefault("prefix", "")
    else:
        out["conditions"] = {"prefix": "", **(out.get("conditions") or {})}
    return out


def _own_rule(kind: str, rules: list[dict], rule_id: str) -> dict | None:
    for existing in rules:
        if existing.get("id") == rule_id:
            return _normalised(kind, existing)
    return None


def rule_in_sync(kind: str, rules: list[dict], desired: dict) -> bool:
    """True when our own rule (by id) is present and says what we want.
    Foreign rules are ignored; extra fields the API adds to ours are tolerated."""
    own = _own_rule(kind, rules, desired["id"])
    return own is not None and _subset(_normalised(kind, desired), own)


def summarize_rule(kind: str, rule: dict) -> str:
    """Plain-English one-liner for `--plan`."""
    if kind == "files":
        seconds = rule.get("condition", {}).get("maxAgeSeconds")
        prefix = rule.get("prefix") or "everything"
        what = f"lock {prefix} against delete and overwrite for {_days(seconds)}"
    else:
        seconds = rule.get("deleteObjectsTransition", {}).get("condition", {}).get("maxAge")
        prefix = (rule.get("conditions") or {}).get("prefix") or "everything"
        what = f"delete {prefix} after {_days(seconds)}"
    return f"rule {rule.get('id')}: {what}"


def _days(seconds: Any) -> str:
    if isinstance(seconds, int) and seconds % _DAY == 0:
        n = seconds // _DAY
        return f"{n} day{'' if n == 1 else 's'}"
    return f"{seconds} seconds"


# -- Planning ------------------------------------------------------------------


@dataclass(frozen=True)
class R2Target:
    """One bucket an environment wants managed, and the rule it wants on it."""

    kind: str  # "logs" -> lifecycle rule, "files" -> bucket lock
    bucket: str
    rule: dict


@dataclass(frozen=True)
class R2Observation:
    """What R2 holds for one target. `rules` is empty when the bucket is missing."""

    target: R2Target
    exists: bool
    rules: list[dict]


def r2_targets(env: Environment) -> list[R2Target]:
    """The buckets `./infra/up` manages for `env`: `[logs].bucket` (unless logs
    are switched off) and `[files].bucket`. The backups bucket is not managed here."""
    targets: list[R2Target] = []
    if env.logs.bucket and env.logs.enabled is not False:
        days = env.logs.retention_days or DEFAULT_LOGS_RETENTION_DAYS
        targets.append(R2Target("logs", env.logs.bucket, logs_lifecycle_rule(days)))
    if env.files.bucket:
        days = env.files.lock_days or DEFAULT_FILES_LOCK_DAYS
        targets.append(R2Target("files", env.files.bucket, files_lock_rule(days)))
    return targets


def r2_account_for(env: Environment, secrets: dict[str, str], *, base_url: str = _DEFAULT_BASE_URL) -> R2Account | None:
    """The client for `env`, or None when it names no R2 bucket to manage
    (such a project needs no account id and makes no R2 call)."""
    if not r2_targets(env):
        return None
    account_id = secrets.get("cloudflare_account_id")
    if not account_id:
        raise StackError(
            "[logs] or [files] names an R2 bucket but the 'cloudflare_account_id' secret is not set",
            "set it: ACCOUNT_ID=<your Cloudflare account id>; "
            + ("" if env.implicit else f"ENV={env.name}; ")
            + "printf '%s' \"$ACCOUNT_ID\" | ./infra/up "
            + ("" if env.implicit else '--env "$ENV" ')
            + "secrets set cloudflare_account_id",
        )
    token = secrets.get("cloudflare_token")
    if not token:
        raise StackError(
            "[logs] or [files] names an R2 bucket but the 'cloudflare_token' secret is not set",
            "set a Cloudflare API token with 'Workers R2 Storage: Edit' as cloudflare_token "
            "(the DNS token may carry that scope too)",
        )
    return R2Account(token, account_id, base_url=base_url)


def observe_r2(account: R2Account, env: Environment) -> tuple[R2Observation, ...]:
    """Read-only: does each bucket exist, and what rules does it carry?"""
    seen: list[R2Observation] = []
    for target in r2_targets(env):
        if not account.bucket_exists(target.bucket):
            seen.append(R2Observation(target, False, []))
            continue
        rules = account.get_lifecycle(target.bucket) if target.kind == "logs" else account.get_lock(target.bucket)
        seen.append(R2Observation(target, True, rules))
    return tuple(seen)


def r2_steps(observations: tuple[R2Observation, ...]) -> list[Step]:
    """Pure: the ENSURE steps still needed. A bucket is created when missing
    (once, even if logs and files share it); its rule is written when absent or different."""
    from stackbase.reconcile import Action, Step  # deferred: reconcile imports this module

    steps: list[Step] = []
    creating: set[str] = set()
    for obs in observations:
        target = obs.target
        if not obs.exists and target.bucket not in creating:
            creating.add(target.bucket)
            steps.append(Step(Action.ENSURE_R2_BUCKET, bucket=target.bucket, detail="new bucket"))
        if obs.exists and rule_in_sync(target.kind, obs.rules, target.rule):
            continue
        current = _own_rule(target.kind, obs.rules, target.rule["id"])
        detail = summarize_rule(target.kind, target.rule)
        if current is not None:
            detail += f"; replaces {summarize_rule(target.kind, current)}"
        action = Action.ENSURE_R2_LIFECYCLE if target.kind == "logs" else Action.ENSURE_R2_LOCK
        steps.append(Step(action, bucket=target.bucket, detail=detail))
    return steps
