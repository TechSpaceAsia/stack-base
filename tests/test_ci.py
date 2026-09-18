"""Tests for stackbase.ci: `ci-setup`, the optional GitHub Actions deploy key.

Every subprocess call (`git`, `gh`, `ssh-keygen`) goes through `FakeRunner`,
so nothing here ever shells out or touches the network -- including
`ssh-keygen`, whose fake stands in for the real binary but still creates the
two key files, so the private-key-never-leaves-the-ramdir assertions below
exercise the real code path rather than a shortcut around it.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stackbase.ci import SECRET_NAME, ci_setup, parse_github_repo
from stackbase.errors import StackError
from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, load_secrets
from stackbase.secrets_cli import deploy_key_init
from tests.fakes import FakeRunner
from tests.test_secrets import _generate_age_identity

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


_DEPLOY_TOOLS = shutil.which("age") is not None and shutil.which("age-keygen") is not None and shutil.which("ssh-keygen") is not None


@contextlib.contextmanager
def _deploy_project(*, with_key: bool):
    """A scratch infra/ with both recipients files, and optionally a real deploy key.

    The age identity and the deploy key are both REAL here (no fake
    subprocess): `ci_setup`'s whole job now is to read what
    `deploy_key_init` wrote, so faking either end would test nothing.
    """
    if not _DEPLOY_TOOLS:
        raise unittest.SkipTest("age / age-keygen / ssh-keygen not installed")
    with Project() as infra_dir:
        identity_path, public_key = _generate_age_identity(infra_dir.parent)
        (infra_dir / "age-recipients.txt").write_text(public_key + "\n", encoding="utf-8")
        (infra_dir / "deploy-recipients.txt").write_text(public_key + "\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(identity_path)}):
            runner = FakeRunner(handler=_happy_path_handler())
            if with_key:
                deploy_key_init(infra_dir, emit=_silent)
                yield infra_dir, runner, load_secrets(infra_dir, file=DEPLOY_FILE)[DEPLOY_KEY_NAME]
            else:
                yield infra_dir, runner


def _project_with_deploy_key():
    return _deploy_project(with_key=True)


def _project_without_deploy_key():
    return _deploy_project(with_key=False)


class CiSetupUsesTheProjectDeployKeyTests(unittest.TestCase):
    """`ci-setup` no longer mints its own key (Task 2): there is ONE project
    deploy key, created by `deploy_key_init`, and ci-setup's whole job is to
    read `deploy.age` and push it. Behaviour that used to belong to ci-setup
    itself (ssh-keygen invocation, refuse-without-rotate, private-key-never-
    leaks, registration-for-redaction) now belongs to `deploy_key_init` and
    is covered in `tests/test_secrets_cli.py`.
    """

    def test_it_never_runs_ssh_keygen_itself(self) -> None:
        with _project_with_deploy_key() as (infra_dir, runner, _private_key):
            ci_setup(infra_dir, emit=_silent, runner=runner)

            self.assertFalse(
                any(call["argv"][0] == "ssh-keygen" for call in runner.calls),
                "ci-setup must push the existing project deploy key, not mint its own",
            )

    def test_it_pushes_exactly_the_bytes_held_in_deploy_age(self) -> None:
        with _project_with_deploy_key() as (infra_dir, runner, private_key):
            ci_setup(infra_dir, emit=_silent, runner=runner)

            secret_calls = [c for c in runner.calls if c["argv"][:3] == ["gh", "secret", "set"]]
            self.assertEqual(len(secret_calls), 1)
            self.assertEqual(secret_calls[0]["kwargs"]["input"], private_key.encode("utf-8"))

    def test_an_absent_deploy_age_is_created_first(self) -> None:
        with _project_without_deploy_key() as (infra_dir, runner):
            ci_setup(infra_dir, emit=_silent, runner=runner)

            self.assertTrue((infra_dir / "deploy.age").exists())
            self.assertTrue((infra_dir / "keys" / "deploy.pub").is_file())

    def test_a_second_run_without_rotate_reuses_the_same_key(self) -> None:
        with _project_with_deploy_key() as (infra_dir, runner, private_key):
            ci_setup(infra_dir, emit=_silent, runner=runner)
            ci_setup(infra_dir, emit=_silent, runner=runner)

            pushed = [
                c["kwargs"]["input"] for c in runner.calls if c["argv"][:3] == ["gh", "secret", "set"]
            ]
            self.assertEqual(pushed, [private_key.encode("utf-8"), private_key.encode("utf-8")])


class CiSetupExistingKeyFailureAndRedactionTests(unittest.TestCase):
    """Fix round 1 (task 2 review): three behaviours that are `ci_setup`'s
    own -- not `deploy_key_init`'s -- and so are NOT covered by
    `tests/test_secrets_cli.py`: `deploy_key_init` never runs `gh` at all,
    and on an ordinary run against an EXISTING key (the common case)
    `deploy_key_init` is never even called. Each test here uses
    `_project_with_deploy_key()` for a real, already-existing `deploy.age`,
    then substitutes a custom `FakeRunner` to script the `gh` failure/
    verification path under test -- the fixture's own `_happy_path_handler`
    runner is discarded for that purpose.
    """

    def test_a_gh_secret_set_failure_is_reported_with_its_stderr(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[:2] == ["gh", "auth"]:
                return _cp(argv)
            if argv[:3] == ["gh", "secret", "set"]:
                return _cp(argv, returncode=1, stderr="permission denied\n")
            return None

        with _project_with_deploy_key() as (infra_dir, _fixture_runner, _private_key):
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            message = str(caught.exception)
            self.assertIn(SECRET_NAME, message)
            self.assertIn("permission denied", message)  # gh's own stderr surfaces, not a generic message

    def test_a_gh_secret_set_failure_with_no_stderr_falls_back_to_the_documented_hint(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[:2] == ["gh", "auth"]:
                return _cp(argv)
            if argv[:3] == ["gh", "secret", "set"]:
                return _cp(argv, returncode=1, stderr="")
            return None

        with _project_with_deploy_key() as (infra_dir, _fixture_runner, _private_key):
            runner = FakeRunner(handler=handler)

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            self.assertIn("gh auth status", str(caught.exception))

    def test_a_secret_that_does_not_verify_afterwards_is_reported(self) -> None:
        with _project_with_deploy_key() as (infra_dir, _fixture_runner, _private_key):
            runner = FakeRunner(handler=_happy_path_handler(secret_list_names=["SOME_OTHER_SECRET"]))

            with self.assertRaises(StackError) as caught:
                ci_setup(infra_dir, runner=runner)

            message = str(caught.exception)
            self.assertIn(SECRET_NAME, message)
            self.assertIn("acme/widgets", message)  # names the repo slug so the operator knows where to look

    def test_the_private_key_is_registered_before_gh_secret_set(self) -> None:
        # A tripwire runner: raises if `gh secret set` is ever reached before
        # `register_secret` has already seen the whole key -- proving the
        # registration happens strictly before that call, not just "at some
        # point during the run" (same technique the deleted
        # RegisterSecretForRedactionTests used against the old ssh-keygen
        # path -- this is the distinct call site right before `gh secret
        # set` in `ci_setup` itself, on the ordinary existing-key path).
        registered: list[str] = []
        state = {"registered_before_call": False}

        def handler(argv, kwargs):
            if argv[:3] == ["gh", "secret", "set"]:
                state["registered_before_call"] = bool(registered)
            return _happy_path_handler()(argv, kwargs)

        with _project_with_deploy_key() as (infra_dir, _fixture_runner, private_key):
            runner = FakeRunner(handler=handler)

            ci_setup(infra_dir, runner=runner, emit=_silent, register_secret=registered.append)

            self.assertTrue(
                state["registered_before_call"],
                "the private key was not registered before `gh secret set` ran",
            )
            self.assertIn(private_key, registered)

    def test_registration_happens_even_when_gh_secret_set_fails(self) -> None:
        def handler(argv, kwargs):
            if argv[:3] == ["git", "remote", "get-url"]:
                return _cp(argv, stdout="git@github.com:acme/widgets.git\n")
            if argv[:2] == ["gh", "auth"]:
                return _cp(argv)
            if argv[:3] == ["gh", "secret", "set"]:
                return _cp(argv, returncode=1, stderr="permission denied\n")
            return None

        with _project_with_deploy_key() as (infra_dir, _fixture_runner, private_key):
            runner = FakeRunner(handler=handler)
            registered: list[str] = []

            with self.assertRaises(StackError):
                ci_setup(infra_dir, runner=runner, emit=_silent, register_secret=registered.append)

            self.assertIn(private_key, registered)


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


class WorkflowRunnerTests(unittest.TestCase):
    def test_it_runs_on_the_self_hosted_x86_64_linux_runner(self) -> None:
        match = re.search(r"^\s*runs-on:\s*(.+)$", _WORKFLOW_TEXT, re.MULTILINE)

        self.assertIsNotNone(match, "expected a runs-on: line")
        self.assertEqual(match.group(1).strip(), "[self-hosted, x86_64-linux]")

    def test_there_is_exactly_one_job_and_one_runner(self) -> None:
        self.assertEqual(len(re.findall(r"^\s*runs-on:", _WORKFLOW_TEXT, re.MULTILINE)), 1)

    def test_nothing_installs_a_c_toolchain_at_job_time(self) -> None:
        # The runner is a NixOS machine that already carries the cross
        # compiler -- no package manager call belongs in this workflow at
        # all, not even in a comment that a reader might copy.
        self.assertNotIn("apt-get", _WORKFLOW_TEXT)
        self.assertNotIn("musl-tools", _WORKFLOW_TEXT)

    def test_it_still_adds_the_musl_rust_target(self) -> None:
        self.assertIn("rustup target add x86_64-unknown-linux-musl", _WORKFLOW_TEXT)

    def test_a_comment_says_where_the_runner_lives(self) -> None:
        self.assertIn("nixos-ollama", _WORKFLOW_TEXT)


class WorkflowKeyHandlingTests(unittest.TestCase):
    def test_the_key_is_written_under_runner_temp_with_umask_077(self) -> None:
        self.assertIn("RUNNER_TEMP", _WORKFLOW_TEXT)
        self.assertIn("umask 077", _WORKFLOW_TEXT)

    def test_the_key_file_path_is_exported_as_the_stackbase_ssh_identity(self) -> None:
        """Resolution path 1 of release.deploy_identity, not an ssh-agent.

        The runner holds no age identity, and both `ci-setup` and the README
        tell you to commit infra/deploy.age -- so deploy_identity would pick
        path 2 and hard-fail ("cannot decrypt it") before any agent was ever
        consulted. Exporting an explicit identity is what keeps path 1 in
        front of it, and is why this workflow decrypts nothing.
        """
        self.assertIn('echo "STACKBASE_SSH_IDENTITY=$key_file" >> "$GITHUB_ENV"', _WORKFLOW_TEXT)

    def test_no_ssh_agent_is_used(self) -> None:
        # An agent would only ever be consulted on resolution path 3, which
        # this workflow can never reach. Keeping one around reads like the
        # mechanism the deploy actually uses, and is not.
        self.assertNotIn("ssh-add", _WORKFLOW_TEXT)
        self.assertNotIn("ssh-agent", _WORKFLOW_TEXT)
        self.assertNotIn("SSH_AUTH_SOCK", _WORKFLOW_TEXT)

    def test_an_always_cleanup_step_removes_the_key_file(self) -> None:
        self.assertIn("if: always()", _WORKFLOW_TEXT)
        # The key now has to survive the whole job, so this step is the ONLY
        # thing that deletes it -- and it must still do so on a failed deploy.
        cleanup = _WORKFLOW_TEXT.split("if: always()", 1)[1]
        self.assertIn('rm -f "$RUNNER_TEMP/deploy_key"', cleanup)

    def test_the_deploy_step_invokes_infra_up_deploy_with_the_tag_ref(self) -> None:
        self.assertIn("./infra/up deploy", _WORKFLOW_TEXT)
        self.assertIn("$GITHUB_REF_NAME", _WORKFLOW_TEXT)


if __name__ == "__main__":
    unittest.main()
