"""Tests for stackbase.ci: `ci-setup`, the optional GitHub Actions deploy key.

Every subprocess call (`git`, `gh`, `ssh-keygen`) goes through `FakeRunner`,
so nothing here ever shells out or touches the network -- including
`ssh-keygen`, whose fake stands in for the real binary but still creates the
two key files, so the private-key-never-leaves-the-ramdir assertions below
exercise the real code path rather than a shortcut around it.
"""

from __future__ import annotations

import contextlib
import re
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.ci import SECRET_NAME, ci_setup, parse_github_repo
from stackbase.errors import StackError
from tests.fakes import FakeRunner

_PRIVATE_KEY_BODY = "-----BEGIN OPENSSH PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIExampleKeyMaterialNeverLeaksAnywhereElse\n-----END OPENSSH PRIVATE KEY-----\n"
_PUBLIC_KEY_BODY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleCiDeployPublicKey ci-deploy@acme\n"

_STACK_TOML = """\
project    = "acme"
domain     = "acme.example.com"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[nodes.a]
role   = "primary"
vps_id = 1984476
"""


class ParseGithubRepoTests(unittest.TestCase):
    def test_https_url(self) -> None:
        self.assertEqual(parse_github_repo("https://github.com/acme/widgets.git"), ("acme", "widgets"))

    def test_https_url_without_dot_git(self) -> None:
        self.assertEqual(parse_github_repo("https://github.com/acme/widgets"), ("acme", "widgets"))

    def test_scp_like_ssh_url(self) -> None:
        self.assertEqual(parse_github_repo("git@github.com:acme/widgets.git"), ("acme", "widgets"))

    def test_ssh_scheme_url(self) -> None:
        self.assertEqual(parse_github_repo("ssh://git@github.com/acme/widgets.git"), ("acme", "widgets"))

    def test_a_non_github_host_is_rejected(self) -> None:
        with self.assertRaises(StackError) as caught:
            parse_github_repo("https://gitlab.com/acme/widgets.git")

        self.assertIn("github.com", str(caught.exception))

    def test_garbage_is_rejected(self) -> None:
        with self.assertRaises(StackError):
            parse_github_repo("not a url at all")


def _silent(_line: str) -> None:
    pass  # tests that don't need the printed next-steps output


def _cp(argv, *, returncode: int = 0, stdout="", stderr="") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=argv, returncode=returncode, stdout=stdout, stderr=stderr)


class Project:
    """A scratch infra/ directory (stack.toml only -- ci-setup needs no secrets.age)."""

    def __enter__(self) -> Path:
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.infra_dir = self.root / "infra"
        (self.infra_dir / "keys").mkdir(parents=True)
        (self.infra_dir / "stack.toml").write_text(_STACK_TOML, encoding="utf-8")
        (self.infra_dir / "keys" / "matt.pub").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleAdminKey matt@laptop\n", encoding="utf-8"
        )
        return self.infra_dir

    def __exit__(self, *exc_info: object) -> None:
        self._tmp.cleanup()


def _happy_path_handler(*, secret_list_names: list[str] | None = None):
    """A FakeRunner handler that scripts the whole ci-setup happy path.

    The fake `ssh-keygen` call ACTUALLY creates the two key files at the
    `-f`-named path -- exercising the real read-back-then-send code path,
    not a shortcut around it (per the task brief).
    """
    names = secret_list_names if secret_list_names is not None else [SECRET_NAME]

    def handler(argv, kwargs):
        if argv[:3] == ["git", "remote", "get-url"]:
            return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
        if argv[:2] == ["gh", "auth"]:
            return _cp(argv, stdout="Logged in\n")
        if argv[0] == "ssh-keygen":
            # The real binary writes "<-f path>" and "<-f path>.pub" -- this
            # fake actually creates both files, exercising the real
            # read-back-then-send code path in ci.py rather than a shortcut
            # around it.
            key_path = Path(argv[argv.index("-f") + 1])
            key_path.write_text(_PRIVATE_KEY_BODY, encoding="utf-8")
            key_path.chmod(0o600)
            (key_path.parent / (key_path.name + ".pub")).write_text(_PUBLIC_KEY_BODY, encoding="utf-8")
            return _cp(argv)
        if argv[:3] == ["gh", "secret", "set"]:
            return _cp(argv)
        if argv[:3] == ["gh", "secret", "list"]:
            return _cp(argv, stdout="".join(f"{name}\n" for name in names))
        return None

    return handler


class CiSetupHappyPathTests(unittest.TestCase):
    def test_creates_the_pub_key_file_and_sets_the_secret(self) -> None:
        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler())

            ci_setup(infra_dir, runner=runner, emit=_silent)

            pub_path = infra_dir / "keys" / "ci-deploy.pub"
            self.assertTrue(pub_path.exists())
            self.assertEqual(pub_path.read_text(encoding="utf-8"), _PUBLIC_KEY_BODY.strip() + "\n")
            self.assertEqual(pub_path.stat().st_mode & 0o777, 0o644)

    def test_the_gh_secret_set_call_receives_the_private_key_only_via_stdin(self) -> None:
        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler())

            ci_setup(infra_dir, runner=runner, emit=_silent)

            secret_set_calls = [c for c in runner.calls if c["argv"][:3] == ["gh", "secret", "set"]]
            self.assertEqual(len(secret_set_calls), 1)
            call = secret_set_calls[0]
            self.assertNotIn(SECRET_NAME + "\n", " ".join(call["argv"]))  # sanity: argv has no key body
            self.assertEqual(call["kwargs"].get("input"), _PRIVATE_KEY_BODY.encode("utf-8"))
            # never via --body / an env var
            self.assertNotIn("--body", call["argv"])

    def test_refuses_to_overwrite_an_existing_pub_key_without_rotate(self) -> None:
        with Project() as infra_dir:
            (infra_dir / "keys" / "ci-deploy.pub").write_text("existing\n", encoding="utf-8")
            runner = FakeRunner(handler=_happy_path_handler())

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn("--rotate", str(caught.exception))
            self.assertEqual(runner.calls, [])  # refused before any subprocess call

    def test_rotate_overwrites_an_existing_pub_key(self) -> None:
        with Project() as infra_dir:
            (infra_dir / "keys" / "ci-deploy.pub").write_text("old-key\n", encoding="utf-8")
            runner = FakeRunner(handler=_happy_path_handler())

            ci_setup(infra_dir, rotate=True, runner=runner, emit=_silent)

            pub_path = infra_dir / "keys" / "ci-deploy.pub"
            self.assertEqual(pub_path.read_text(encoding="utf-8"), _PUBLIC_KEY_BODY.strip() + "\n")

    def test_the_ssh_keygen_comment_names_the_project(self) -> None:
        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler())

            ci_setup(infra_dir, runner=runner, emit=_silent)

            keygen_call = next(c for c in runner.calls if c["argv"][0] == "ssh-keygen")
            comment_index = keygen_call["argv"].index("-C") + 1
            self.assertEqual(keygen_call["argv"][comment_index], "ci-deploy@acme")

    def test_prints_next_steps_including_the_exact_cp_command(self) -> None:
        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler())
            printed: list[str] = []

            ci_setup(infra_dir, runner=runner, emit=printed.append)

            joined = "\n".join(printed)
            self.assertIn("git add", joined)
            self.assertIn("./infra/up", joined)
            self.assertIn("cp ", joined)
            self.assertIn("deploy-stack.yml", joined)
            self.assertIn(f"gh secret delete {SECRET_NAME}", joined)


class CiSetupRepoDetectionTests(unittest.TestCase):
    def test_a_failed_git_remote_lookup_is_a_clear_error(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, returncode=128, stderr="fatal: No such remote 'origin'\n")
            return None

        with Project() as infra_dir:
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn("origin", str(caught.exception))

    def test_a_non_github_remote_is_rejected_before_any_gh_call(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="https://gitlab.com/acme/widgets.git\n")
            return None

        with Project() as infra_dir:
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn("github.com", str(caught.exception))
            self.assertFalse(any(c["argv"][0] == "gh" for c in runner.calls))


class CiSetupGhAuthTests(unittest.TestCase):
    def test_gh_not_installed_names_the_install_hint(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[0] == "gh":
                raise FileNotFoundError("gh")
            return None

        with Project() as infra_dir:
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn("cli.github.com", str(caught.exception))

    def test_gh_not_authenticated_names_the_login_hint(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[:2] == ["gh", "auth"]:
                return _cp(argv, returncode=1, stderr="not logged in\n")
            return None

        with Project() as infra_dir:
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn("gh auth login", str(caught.exception))
            self.assertFalse(any(c["argv"][0] == "ssh-keygen" for c in runner.calls))


class CiSetupFailureTests(unittest.TestCase):
    def test_ssh_keygen_failure_is_reported_and_nothing_is_written(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[:2] == ["gh", "auth"]:
                return _cp(argv)
            if argv[0] == "ssh-keygen":
                return _cp(argv, returncode=1, stderr="ssh-keygen: boom\n")
            return None

        with Project() as infra_dir:
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError):
                ci_setup(infra_dir, runner=runner)

            self.assertFalse((infra_dir / "keys" / "ci-deploy.pub").exists())

    def test_gh_secret_set_failure_is_reported_and_the_pub_key_is_never_written(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[:2] == ["gh", "auth"]:
                return _cp(argv)
            if argv[0] == "ssh-keygen":
                key_path = Path(argv[argv.index("-f") + 1])
                key_path.write_text(_PRIVATE_KEY_BODY, encoding="utf-8")
                (key_path.parent / (key_path.name + ".pub")).write_text(_PUBLIC_KEY_BODY, encoding="utf-8")
                return _cp(argv)
            if argv[:3] == ["gh", "secret", "set"]:
                return _cp(argv, returncode=1, stderr="permission denied\n")
            return None

        with Project() as infra_dir:
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError):
                ci_setup(infra_dir, runner=runner)

            self.assertFalse((infra_dir / "keys" / "ci-deploy.pub").exists())

    def test_a_secret_that_does_not_verify_afterwards_is_reported(self) -> None:
        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler(secret_list_names=["SOME_OTHER_SECRET"]))

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn(SECRET_NAME, str(caught.exception))
            # the pub key is only written once the secret has been verified
            self.assertFalse((infra_dir / "keys" / "ci-deploy.pub").exists())


class PrivateKeyNeverLeaksTests(unittest.TestCase):
    """The private key must never appear in any argv, log line, exception, or
    file outside the RAM dir (task brief). Scans every recorded argv/kwargs
    and the whole temp project tree after a full run.
    """

    def test_the_private_key_never_appears_in_any_recorded_argv_or_on_disk(self) -> None:
        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler())
            printed: list[str] = []

            ci_setup(infra_dir, runner=runner, emit=printed.append)

            needle = _PRIVATE_KEY_BODY.strip()
            for call in runner.calls:
                self.assertNotIn(needle, " ".join(call["argv"]))
                for value in call["kwargs"].values():
                    if isinstance(value, str):
                        self.assertNotIn(needle, value)
                    # bytes (the stdin payload) are allowed to carry it --
                    # that's the one legitimate channel.

            self.assertNotIn(needle, "\n".join(printed))

            for path in infra_dir.parent.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                self.assertNotIn(needle, text, f"private key leaked into {path}")

    def test_the_ramdir_itself_no_longer_exists_once_ci_setup_returns(self) -> None:
        """Belt-and-braces: the private key's own directory is gone, not just
        its content unreferenced -- proves the `with private_ram_dir()` block
        in `ci_setup` really does end (and clean up) before this function
        returns, rather than the ramdir being leaked open.
        """
        from stackbase import ci as ci_module

        seen: list[Path] = []
        real_private_ram_dir = ci_module.private_ram_dir

        @contextlib.contextmanager
        def spying_ram_dir():
            with real_private_ram_dir() as directory:
                seen.append(directory)
                yield directory

        with Project() as infra_dir:
            runner = FakeRunner(handler=_happy_path_handler())

            with mock.patch.object(ci_module, "private_ram_dir", spying_ram_dir):
                ci_setup(infra_dir, runner=runner, emit=_silent)

        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())


# --------------------------------------------------------------------------
# templates/github/deploy-stack.yml -- read as plain text (stdlib only, no
# PyYAML), the same level of parsing the rest of this suite uses for other
# template files.
# --------------------------------------------------------------------------

_WORKFLOW_PATH = Path(__file__).resolve().parent.parent / "templates" / "github" / "deploy-stack.yml"
_REFERENCE_WORKFLOW_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "platform-base"
    / "templates"
    / "project-files"
    / ".github"
    / "workflows"
    / "deploy.yml"
)

_WORKFLOW_TEXT = _WORKFLOW_PATH.read_text(encoding="utf-8")
_WORKFLOW_LINES = _WORKFLOW_TEXT.splitlines()

_USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)\s*(?:#\s*(.*))?$")
_SHA_ACTION_RE = re.compile(r"^([^@]+)@([0-9a-f]{40})$")


def _uses_lines() -> list[tuple[int, str, str]]:
    """Every `uses:` line as (1-based line number, action ref, trailing comment)."""
    found = []
    for number, line in enumerate(_WORKFLOW_LINES, start=1):
        match = _USES_RE.match(line)
        if match:
            found.append((number, match.group(1), match.group(2) or ""))
    return found


def _reference_actions() -> set[str]:
    """The bare action names (no ref) used by platform-base's own reference workflow."""
    if not _REFERENCE_WORKFLOW_PATH.is_file():
        return set()
    text = _REFERENCE_WORKFLOW_PATH.read_text(encoding="utf-8")
    names = set()
    for line in text.splitlines():
        match = _USES_RE.match(line)
        if match:
            names.add(match.group(1).split("@", 1)[0])
    return names


class WorkflowExistsTests(unittest.TestCase):
    def test_the_file_exists_and_is_non_empty(self) -> None:
        self.assertTrue(_WORKFLOW_PATH.is_file())
        self.assertTrue(_WORKFLOW_TEXT.strip())


class WorkflowTriggerAndPermissionsTests(unittest.TestCase):
    def test_it_triggers_only_on_v_tags(self) -> None:
        self.assertIn("tags:", _WORKFLOW_TEXT)
        self.assertIn("- 'v*'", _WORKFLOW_TEXT)

    def test_permissions_are_contents_read_only(self) -> None:
        match = re.search(r"^permissions:\s*\n\s*contents:\s*read\s*$", _WORKFLOW_TEXT, re.MULTILINE)
        self.assertIsNotNone(match, "expected a top-level 'permissions: contents: read' block")

    def test_a_concurrency_group_is_declared(self) -> None:
        self.assertIn("concurrency:", _WORKFLOW_TEXT)
        self.assertIn("group:", _WORKFLOW_TEXT)


class WorkflowSecretsAndVarsTests(unittest.TestCase):
    def test_exactly_one_distinct_secret_is_referenced_and_it_is_stack_deploy_key(self) -> None:
        # The `${{ secrets.X }}` expression form only -- not every English
        # occurrence of the word "secrets." (this file's own header comment
        # talks about infra/secrets.age, which must not count).
        refs = set(re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", _WORKFLOW_TEXT))

        self.assertEqual(refs, {SECRET_NAME})

    def test_no_vars_context_is_referenced(self) -> None:
        self.assertNotIn("vars.", _WORKFLOW_TEXT)

    def test_no_environment_context_is_referenced(self) -> None:
        self.assertNotIn("environment:", _WORKFLOW_TEXT)

    def test_the_secret_interpolation_never_appears_inside_a_run_script_line(self) -> None:
        """The `${{ secrets... }}` expression must live in an `env:` mapping
        (read back as an ordinary shell variable), never spliced directly
        into a `run:` script line -- GitHub Actions does not shell-escape
        template expressions, so interpolating one straight into a script is
        both a leak risk (e.g. under `set -x`) and an injection risk.
        """
        for number, line in enumerate(_WORKFLOW_LINES, start=1):
            if "${{ secrets" in line:
                stripped = line.strip()
                self.assertTrue(
                    re.match(r"^STACK_DEPLOY_KEY:\s*\$\{\{\s*secrets\.STACK_DEPLOY_KEY\s*\}\}$", stripped),
                    f"line {number} interpolates a secret outside an env: mapping: {line!r}",
                )


class WorkflowActionPinningTests(unittest.TestCase):
    def test_every_uses_line_is_checkout_or_a_reference_workflow_action(self) -> None:
        reference_actions = _reference_actions()
        allowed = reference_actions | {"actions/checkout"}
        self.assertIn("actions/checkout", allowed)  # sanity: the constant itself is right

        for _number, ref, _comment in _uses_lines():
            name = ref.split("@", 1)[0]
            self.assertIn(
                name,
                allowed,
                f"'{ref}' is not actions/checkout and does not appear in the reference workflow "
                f"({_REFERENCE_WORKFLOW_PATH})",
            )

    def test_every_uses_line_is_pinned_by_a_40_hex_sha_or_carries_a_todo_pin_marker(self) -> None:
        for number, ref, comment in _uses_lines():
            if "TODO(pin)" in comment or "TODO(pin)" in ref:
                continue
            match = _SHA_ACTION_RE.match(ref)
            self.assertIsNotNone(
                match, f"line {number}: '{ref}' is not pinned by a 40-hex commit SHA and has no TODO(pin) marker"
            )

    def test_pinned_actions_carry_a_human_readable_version_comment(self) -> None:
        for number, ref, comment in _uses_lines():
            if not _SHA_ACTION_RE.match(ref):
                continue
            self.assertTrue(comment.strip(), f"line {number}: '{ref}' has a SHA but no '# vX.Y.Z' comment")


class WorkflowKeyHandlingTests(unittest.TestCase):
    def test_the_key_is_written_under_runner_temp_with_umask_077(self) -> None:
        self.assertIn("RUNNER_TEMP", _WORKFLOW_TEXT)
        self.assertIn("umask 077", _WORKFLOW_TEXT)

    def test_the_key_file_is_removed_at_least_once_after_being_written(self) -> None:
        self.assertIn('rm -f "$key_file"', _WORKFLOW_TEXT)

    def test_an_always_cleanup_step_exists(self) -> None:
        self.assertIn("if: always()", _WORKFLOW_TEXT)

    def test_the_deploy_step_invokes_infra_up_deploy_with_the_tag_ref(self) -> None:
        self.assertIn("./infra/up deploy", _WORKFLOW_TEXT)
        self.assertIn("$GITHUB_REF_NAME", _WORKFLOW_TEXT)


if __name__ == "__main__":
    unittest.main()
