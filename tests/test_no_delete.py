"""Structural guard: stack-base must be incapable of cancelling a server.

Two independent checks, both static (no network, no imports of live code
paths that could themselves be wrong):

1. `stackbase/hostinger.py` is parsed with `ast` and scanned for any call
   where the string literal `"DELETE"` is one argument and another argument
   (including f-string constant segments) contains `"virtual-machines"` or
   `"billing"`. The scanner (`find_delete_violations`) is exercised directly
   against hand-written good/bad source snippets first, to prove the guard
   actually bites before trusting it against the real file.
2. `stackbase.reconcile.Action` (once Task 7 lands) must have no member
   whose name contains DELETE/DESTROY/CANCEL. `stackbase/reconcile.py`
   doesn't exist yet -- that check skips cleanly rather than failing.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

_HOSTINGER_PATH = Path(__file__).resolve().parent.parent / "stackbase" / "hostinger.py"
_BANNED_SUBSTRINGS = ("virtual-machines", "billing")
_FORBIDDEN_ACTION_WORDS = ("DELETE", "DESTROY", "CANCEL")


def _string_constants(node: ast.AST) -> list[str]:
    """Every string literal reachable from `node`: a bare `Constant`, or the
    constant segments of an f-string (`JoinedStr`)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return [
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        ]
    return []


def find_delete_violations(source: str) -> list[str]:
    """Return one description per call that sends `"DELETE"` at a VM/billing path.

    A "violation" is any `ast.Call` where `"DELETE"` appears as one of the
    call's string-literal arguments (positional or keyword) and a *different*
    string-literal argument of that same call contains "virtual-machines" or
    "billing" anywhere in its text (including an f-string's constant parts).
    """
    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        literals: list[str] = []
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            literals.extend(_string_constants(arg))
        if "DELETE" not in literals:
            continue
        for literal in literals:
            if any(banned in literal for banned in _BANNED_SUBSTRINGS):
                violations.append(f"line {node.lineno}: DELETE call touches '{literal}'")
    return violations


class DeleteGuardBitesTests(unittest.TestCase):
    """Prove the scanner itself works before trusting it against real code."""

    def test_rejects_delete_against_virtual_machines(self) -> None:
        bad_source = (
            "def evil(request):\n"
            "    vps_id = 1\n"
            '    request("DELETE", f"/api/vps/v1/virtual-machines/{vps_id}")\n'
        )
        violations = find_delete_violations(bad_source)
        self.assertTrue(violations, "expected the guard to reject a DELETE on virtual-machines")

    def test_rejects_delete_against_billing(self) -> None:
        bad_source = 'request("DELETE", "/api/billing/v1/subscriptions/1")\n'
        violations = find_delete_violations(bad_source)
        self.assertTrue(violations, "expected the guard to reject a DELETE on billing")

    def test_allows_delete_against_firewall_rules(self) -> None:
        good_source = (
            "def fine(request):\n"
            "    firewall_id = 1\n"
            "    rule_id = 2\n"
            '    request("DELETE", f"/api/vps/v1/firewall/{firewall_id}/rules/{rule_id}")\n'
        )
        violations = find_delete_violations(good_source)
        self.assertEqual(violations, [], "firewall rule deletes are explicitly permitted")

    def test_allows_delete_string_unrelated_to_any_call(self) -> None:
        # A bare "DELETE" string with no accompanying call shouldn't confuse the walker.
        harmless_source = 'METHODS = ["GET", "POST", "DELETE"]\n'
        self.assertEqual(find_delete_violations(harmless_source), [])


class HostingerSourceHasNoDeleteViolationsTests(unittest.TestCase):
    def test_real_hostinger_module_has_no_violations(self) -> None:
        source = _HOSTINGER_PATH.read_text(encoding="utf-8")
        violations = find_delete_violations(source)
        self.assertEqual(violations, [], f"hostinger.py must never DELETE a VM or touch billing: {violations}")


class ReconcileActionGuardTests(unittest.TestCase):
    def test_action_enum_has_no_forbidden_members(self) -> None:
        try:
            from stackbase import reconcile
        except ImportError:
            # `from package import missing_submodule` raises a plain ImportError
            # ("cannot import name ... from 'stackbase'"), not ModuleNotFoundError --
            # the fromlist import machinery can't tell "no such submodule" apart
            # from "no such attribute", so it collapses both into ImportError.
            self.skipTest("stackbase.reconcile does not exist yet (Task 7) -- guard will apply once it lands")
            return

        action_cls = getattr(reconcile, "Action", None)
        if action_cls is None:
            self.skipTest("stackbase.reconcile.Action does not exist yet")
            return

        forbidden = [
            member.name
            for member in action_cls
            if any(word in member.name for word in _FORBIDDEN_ACTION_WORDS)
        ]
        self.assertEqual(forbidden, [], f"reconcile.Action must never define a cancel/delete action: {forbidden}")


if __name__ == "__main__":
    unittest.main()
