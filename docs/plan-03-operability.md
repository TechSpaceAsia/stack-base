# stack-base — Plan 03: operability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a stack-base project the four things it still lacks to be operable by more than its author: a project deploy key that a build host can hold without holding everything else, project-wide NixOS modules, off-box encrypted backups, and a release build that works on NixOS.

**Architecture:** `infra/secrets.age` keeps every operator secret; a second, separately-addressed file `infra/deploy.age` holds exactly one value — the project's SSH deploy private key — encrypted to a *superset* recipient list, so a build host can be given a file identity that unlocks the deploy door and nothing else. The same generalised `load_secrets`/`save_secrets` machinery serves both. On the node side, one new base module (`nixos/backups.nix`) streams `pg_dump`/`tar` through `zstd` → `age` → `rclone` to an S3-compatible bucket with no plaintext and no credentials in the Nix store, and the template flake grows an `infra/conf.d/` directory whose `*.nix` files apply to every node.

**Tech Stack:** stdlib-only Python 3.11+ (`unittest`), NixOS modules + `pkgs.writeShellApplication` (shellcheck at build time), `pkgs.testers.runNixOSTest` VM checks, `age`, `rclone`, `zstd`, `ssh-keygen`, `gh`.

**Spec:** [`docs/plan-03-brief.md`](plan-03-brief.md) — binding. Plans 01/02 (`docs/plan-01-stack-up.md`, `docs/plan-02-deploy.md`) are shipped; this plan does not change their contracts except where the brief says so.

## Global Constraints

- stdlib-only Python 3.11+. The whole suite runs with `python3 -m unittest discover -s tests` from the repo root.
- NixOS modules must keep `nix flake check` and both VM checks (`tests/vm.nix`, `tests/vm-deploy.nix`) green; new behaviour that runs on a node gets a VM subtest.
- No plaintext secret is ever written outside `stackbase.ramdir.private_ram_dir()`. No secret value is ever printed, logged, or put in an argv or an environment variable of a subprocess (stdin only).
- Every expected failure is a `StackError(message, hint)`, printed as one line `error: <message> — <hint>`. Never raise a bare `Exception`, never `assert` for user-facing validation.
- User-facing snippets use shell variables for fill-ins (`TOKEN=<paste here>`), never inline placeholders.
- Every user-facing change is documented in `README.md` **in the same task** that makes it.
- Match the existing code style and comment density (see `stackbase/ci.py` and `stackbase/steps.py`): comments explain *why*, and every non-obvious refusal says what the operator should do instead.
- Nothing in this plan deletes a server, a DNS record, a firewall or a release. `tests/test_no_delete.py` must stay green.

## Decisions this plan makes (where the brief left a choice)

1. **`ciDeployKeys` is renamed.** In `templates/infra/flake.nix` the binding becomes `projectDeployKeys`, it reads `./keys/deploy.pub` (not `ci-deploy.pub`), and the attribute name inside `stackbase.deploy.keys` becomes `deploy` (was `ci-deploy`). There is one project key now, used by CI *and* by humans, so "ci" in the name would be a lie.
2. **No backwards compatibility for `keys/ci-deploy.pub`.** stack-base is unreleased (no tags yet); the template flake stops reading that path entirely. The README says to delete it and re-run `ci-setup`.
3. **`ci-setup` no longer refuses when a key exists.** Refusing-unless-`--rotate` moves to `deploy-key init`. `ci-setup` is now idempotent: it pushes whatever `deploy.age` holds (creating it first if absent), and `--rotate` forwards to `deploy-key init --rotate`.
4. **The superset check is skipped when `infra/deploy-recipients.txt` does not exist** (the project has no deploy key yet). Present → it must list every recipient of `age-recipients.txt`, or `up` refuses.
5. **`conf.d` modules are listed before `nodes/<name>/extra.nix`** in the module list, so list-valued options concatenate project-wide-first. Position alone does not decide precedence in the NixOS module system — two plain definitions of the same scalar option still conflict, and `extra.nix` overrides a `conf.d` value with `lib.mkForce` exactly as it would any other module's. The README says so.
6. **The `conf.d` filter lives in stack-base**, as `lib.confdModules` in the repo-root `flake.nix`, not as inline Nix in the template — that way the VM test exercises the same code the template calls.
7. **`build()` gains `project_slug`**, a keyword argument defaulting to `None`, rather than taking the whole `StackConfig`; `run_deploy` passes `cfg.project`. The persistent target dir is only used when it is given.
8. **The musl C compiler is only injected when BOTH env vars are unset** — an operator who set one deliberately keeps full control of both.
9. **`backup-now` lives in a new `stackbase/backups.py`**, not in `release.py`: it talks to the node as `root` (stack-base's own door), while everything in `release.py` talks to the restricted `deploy` door.

## File Structure

```
stackbase/secrets.py        (modify) SecretsFile + generalised load/save, recipients superset check,
                                     register_private_key/write_public_key moved here from ci.py
stackbase/secrets_cli.py    (modify) deploy_key_init / deploy_key_show_pub
stackbase/ci.py             (modify) ci-setup no longer generates a key; it pushes deploy.age's
stackbase/release.py        (modify) deploy_identity ctx manager; musl toolchain; persistent target
                                     dir; tailwindcss on PATH
stackbase/reconcile.py      (modify) ENSURE_BACKUP_ENV action, backup_env_sha fact, check_infra_clean
stackbase/steps.py          (modify) _ensure_backup_env executor
stackbase/backups.py        (create) backup.env content + digest, run_backup_now
stackbase/config.py         (modify) [backups] table -> BackupsConfig; NodeState.backup_env_sha
stackbase/__main__.py       (modify) deploy-key/backup-now subcommands, --allow-dirty, masked emit
nixos/backups.nix           (create) stackbase.backups.* + stackbase-backup.service/.timer
nixos/deploy/stack-deploy.sh (modify) "none" is a valid no-release-yet color in `status`
flake.nix                   (modify) nixosModules.backups, lib.confdModules
templates/infra/flake.nix   (modify) conf.d, keys/deploy.pub, [backups]
templates/infra/deploy-recipients.txt (create)
templates/infra/.gitignore  (modify) stray key material
templates/infra/stack.toml.example (modify) [backups]
templates/github/deploy-stack.yml  (modify) self-hosted runner
tests/fixtures/confd/hello.nix     (create)
tests/vm.nix                (modify) conf.d + backups subtests
tests/vm-deploy.nix         (modify) status-before-first-release subtest
tests/test_secrets.py tests/test_secrets_cli.py tests/test_ci.py tests/test_release.py
tests/test_reconcile.py tests/test_cli.py tests/test_template.py  (modify)
tests/test_backups.py       (create)
README.md                   (modify) per task
```

On-node layout this plan adds:

```
/var/lib/stackbase/backup.env        0600 root:root, rclone env-config credentials (never in the store)
backup:<bucket>/db/<project>_<UTC stamp>.sql.zst.age
backup:<bucket>/files/<basename>_<UTC stamp>.tar.zst.age
/etc/nixos/stack/age-recipients.txt  the recipients the node encrypts backups to (pushed by PUSH_CONFIG)
```

---

### Task 1: Two secrets files, one machinery

**Files:**
- Modify: `stackbase/secrets.py`
- Modify: `stackbase/ci.py` (import the two helpers from their new home)
- Modify: `stackbase/__main__.py` (call the superset check from `_up`)
- Create: `templates/infra/deploy-recipients.txt`
- Test: `tests/test_secrets.py`, `tests/test_template.py`

**Interfaces — Produces:**
- `secrets.SecretsFile(name: str, recipients_name: str, missing_hint: Callable[[Path, Path], str])`, and the two instances `secrets.SECRETS_FILE` (`secrets.age` / `age-recipients.txt`) and `secrets.DEPLOY_FILE` (`deploy.age` / `deploy-recipients.txt`).
- `secrets.DEPLOY_KEY_NAME = "deploy_ssh_key"` — the single key inside `deploy.age`.
- `load_secrets(infra_dir: Path, file: SecretsFile = SECRETS_FILE) -> dict[str, str]`
- `save_secrets(infra_dir: Path, data: dict[str, str], file: SecretsFile = SECRETS_FILE) -> None`
- `read_recipients(path: Path) -> list[str]`
- `check_recipients_superset(infra_dir: Path) -> None`
- `register_private_key(private_key_text: str, register_secret: Callable[[str], None]) -> None` (moved verbatim from `ci.py::_register_private_key`)
- `write_public_key(path: Path, content: str) -> None` (moved verbatim from `ci.py::_write_pub_key_atomically`)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_secrets.py` (it already has `TempInfraDir`, `_generate_age_identity` and `_AGE_AVAILABLE`):

```python
from stackbase.secrets import (
    DEPLOY_FILE,
    DEPLOY_KEY_NAME,
    SECRETS_FILE,
    check_recipients_superset,
    read_recipients,
    register_private_key,
    write_public_key,
)


class ReadRecipientsTests(unittest.TestCase):
    def test_skips_comments_and_blank_lines(self) -> None:
        with TempInfraDir() as infra_dir:
            path = infra_dir / "age-recipients.txt"
            path.write_text("# who\n\nage1aaa\n  age1bbb  \n", encoding="utf-8")

            self.assertEqual(read_recipients(path), ["age1aaa", "age1bbb"])

    def test_a_missing_file_is_a_stack_error(self) -> None:
        with TempInfraDir() as infra_dir:
            with self.assertRaises(StackError) as ctx:
                read_recipients(infra_dir / "age-recipients.txt")

            self.assertIn("age-recipients.txt", str(ctx.exception))


class RecipientsSupersetTests(unittest.TestCase):
    def test_no_deploy_recipients_file_means_nothing_to_check(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text("age1aaa\n", encoding="utf-8")

            check_recipients_superset(infra_dir)  # must not raise

    def test_a_superset_passes(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text("age1aaa\nage1bbb\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.txt").write_text(
                "age1aaa\nage1bbb\nage1buildhost\n", encoding="utf-8"
            )

            check_recipients_superset(infra_dir)  # must not raise

    def test_a_missing_recipient_is_refused_and_named(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text("age1aaa\nage1bbb\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.txt").write_text("age1aaa\n", encoding="utf-8")

            with self.assertRaises(StackError) as ctx:
                check_recipients_superset(infra_dir)

            message = str(ctx.exception)
            self.assertIn("deploy-recipients.txt", message)
            self.assertIn("age1bbb", message)
            self.assertIn("deploy-key init --rotate", message)


class PublicKeyWriteTests(unittest.TestCase):
    def test_write_public_key_creates_the_parent_and_a_0644_file(self) -> None:
        with TempInfraDir() as infra_dir:
            path = infra_dir / "keys" / "deploy.pub"

            write_public_key(path, "ssh-ed25519 AAAA deploy@acme\n")

            self.assertEqual(path.read_text(encoding="utf-8"), "ssh-ed25519 AAAA deploy@acme\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)


class RegisterPrivateKeyTests(unittest.TestCase):
    def test_the_whole_key_and_every_body_line_are_registered(self) -> None:
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
        registered: list[str] = []

        register_private_key(key, registered.append)

        self.assertIn(key, registered)
        self.assertIn("b3BlbnNzaC1rZXktdjEAAAAA", registered)
        self.assertFalse(any(value.startswith("-----") for value in registered if value != key))


@unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed -- skipping secrets round-trip tests")
class DeployFileRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._identity_tmp = tempfile.TemporaryDirectory()
        self.identity_path, self.public_key = _generate_age_identity(Path(self._identity_tmp.name))

    def tearDown(self) -> None:
        self._identity_tmp.cleanup()

    def test_deploy_age_round_trips_against_its_own_recipients_file(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "deploy-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            payload = {DEPLOY_KEY_NAME: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"}

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, payload, file=DEPLOY_FILE)

                self.assertTrue((infra_dir / "deploy.age").exists())
                self.assertFalse((infra_dir / "secrets.age").exists())

                self.assertEqual(load_secrets(infra_dir, file=DEPLOY_FILE), payload)

    def test_a_missing_deploy_age_names_the_init_command(self) -> None:
        with TempInfraDir() as infra_dir:
            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                with self.assertRaises(StackError) as ctx:
                    load_secrets(infra_dir, file=DEPLOY_FILE)

            self.assertIn("deploy.age", str(ctx.exception))
            self.assertIn("./infra/up deploy-key init", str(ctx.exception))

    def test_saving_deploy_age_without_its_recipients_file_is_refused(self) -> None:
        with TempInfraDir() as infra_dir:
            with self.assertRaises(StackError) as ctx:
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: "x"}, file=DEPLOY_FILE)

            self.assertIn("deploy-recipients.txt", str(ctx.exception))

    def test_the_two_files_stay_independent(self) -> None:
        with TempInfraDir() as infra_dir:
            (infra_dir / "age-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")
            (infra_dir / "deploy-recipients.txt").write_text(self.public_key + "\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)}):
                save_secrets(infra_dir, {"hostinger_token": "tok"}, file=SECRETS_FILE)
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: "key"}, file=DEPLOY_FILE)

                self.assertEqual(load_secrets(infra_dir), {"hostinger_token": "tok"})
                self.assertEqual(load_secrets(infra_dir, file=DEPLOY_FILE), {DEPLOY_KEY_NAME: "key"})
```

Add to `tests/test_template.py`, inside `TemplateFilesTests`:

```python
    def test_the_deploy_recipients_file_carries_instructions_and_no_real_keys(self) -> None:
        text = (_TEMPLATE_DIR / "deploy-recipients.txt").read_text(encoding="utf-8")

        self.assertIn("superset", text)
        self.assertIn("age-recipients.txt", text)
        real_keys = [
            line for line in text.splitlines() if line.strip().startswith("age1") and not line.startswith("#")
        ]
        self.assertEqual(real_keys, [], "the template must not ship a real recipient key")
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_secrets tests.test_template -v`
Expected: FAIL — `ImportError: cannot import name 'DEPLOY_FILE' from 'stackbase.secrets'`.

- [ ] **Step 3: Generalise `stackbase/secrets.py`**

Replace the module constants and the two functions. Keep the module docstring, `redact`, `_identity_path` and `_run_age` exactly as they are; add `dataclass`/`Callable` to the imports.

```python
_REDACTED = "***REDACTED***"

DEPLOY_KEY_NAME = "deploy_ssh_key"


def _secrets_missing_hint(secrets_path: Path, recipients_path: Path) -> str:
    # Only the two API tokens are yours to paste. The origin certificate
    # and its private key are generated by stack-base itself and added to
    # this same file (as "origin_cert"/"origin_key") the first time it
    # runs -- never type those in by hand.
    return (
        "create it with (CLOUDFLARE_TOKEN is optional -- leave it empty to skip DNS and the "
        "TLS origin certificate; the server is then reachable by IP/SSH only):\n"
        "HOSTINGER_TOKEN=<paste here>\n"
        "CLOUDFLARE_TOKEN=<paste here, or leave empty>\n"
        'printf \'{"hostinger_token": "%s", "cloudflare_token": "%s"}\' '
        '"$HOSTINGER_TOKEN" "$CLOUDFLARE_TOKEN" '
        f"| age -R {recipients_path} -o {secrets_path}"
    )


def _deploy_missing_hint(deploy_path: Path, _recipients_path: Path) -> str:
    return (
        "create it with `./infra/up deploy-key init` -- that generates the key in RAM and writes "
        f"{deploy_path} (encrypted) plus infra/keys/deploy.pub (committed)"
    )


@dataclass(frozen=True)
class SecretsFile:
    """One age-encrypted JSON file plus the recipients file it is encrypted to.

    Two exist. `SECRETS_FILE` holds everything an operator needs to run
    `up` (API tokens, the origin TLS key, app_env, the R2 credentials).
    `DEPLOY_FILE` holds exactly one value -- the project's SSH deploy
    private key -- against a DIFFERENT, wider recipient list, so a machine
    that only needs to push releases (a NixOS build host) can be given an
    identity that unlocks the deploy door and nothing else. Everything
    that reads or writes either file goes through the same code path;
    only this descriptor changes.
    """

    name: str
    recipients_name: str
    missing_hint: Callable[[Path, Path], str]


SECRETS_FILE = SecretsFile("secrets.age", "age-recipients.txt", _secrets_missing_hint)
DEPLOY_FILE = SecretsFile("deploy.age", "deploy-recipients.txt", _deploy_missing_hint)
```

`load_secrets` and `save_secrets` become:

```python
def load_secrets(infra_dir: Path, file: SecretsFile = SECRETS_FILE) -> dict[str, str]:
    """Decrypt `<infra_dir>/<file.name>` with the configured age identity.

    Returns the decrypted payload as a flat `{"key": "value"}` object. A
    missing file raises a `StackError` whose hint is the exact command to
    create that particular file.

    The identity is `$STACKBASE_AGE_IDENTITY` (or `~/.age/key.txt`) either
    way: on a laptop that is usually a YubiKey-backed plugin identity, on a
    build host it is a plain file identity listed ONLY in
    `deploy-recipients.txt`.
    """
    secrets_path = infra_dir / file.name
    recipients_path = infra_dir / file.recipients_name

    if not secrets_path.exists():
        raise StackError(f"{secrets_path} not found", file.missing_hint(secrets_path, recipients_path))

    identity_path = _identity_path()
    if not identity_path.exists():
        raise StackError(
            f"age identity {identity_path} not found",
            "set $STACKBASE_AGE_IDENTITY to your age identity file (any identity, including a "
            "YubiKey-backed plugin identity), or create ~/.age/key.txt",
        )

    result = _run_age(["-d", "-i", str(identity_path), str(secrets_path)])
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        detail = f" ({stderr})" if stderr else ""
        raise StackError(
            f"failed to decrypt {secrets_path}",
            f"check that {identity_path} is the right identity and is a recipient of {secrets_path}{detail}",
        )

    try:
        data = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StackError(
            f"{secrets_path} did not decrypt to valid JSON",
            f"re-create {file.name} from a flat JSON object -- it may have been corrupted or "
            "encrypted from something else",
        ) from exc

    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise StackError(
            f"{secrets_path} did not decrypt to a flat JSON object of strings",
            f're-create {file.name} from a JSON object like {{"key": "value"}} with no nesting',
        )

    return data


def save_secrets(infra_dir: Path, data: dict[str, str], file: SecretsFile = SECRETS_FILE) -> None:
    """Encrypt `data` as JSON to `<infra_dir>/<file.name>`; plaintext never touches disk.

    `age` writes to a same-directory temp file first
    (`<file.name>.<pid>.tmp`, created at mode 0600 with no window at a
    laxer mode -- `os.open` with `O_CREAT|O_EXCL` sets the mode atomically,
    and `age -o` writing into an already-existing file reuses that
    inode/mode rather than replacing it). Only once `age` has exited 0 and
    the temp file is non-empty is it `os.replace`d over the real file -- an
    atomic rename on the same filesystem. A crash or a failing `age`
    mid-write therefore can never truncate the only copy: the original file
    is untouched until the replace, and the temp file is removed on every
    failure path (M3, Fix round 1).
    """
    recipients_path = infra_dir / file.recipients_name
    secrets_path = infra_dir / file.name

    if not recipients_path.exists():
        raise StackError(
            f"{recipients_path} not found",
            f"create infra/{file.recipients_name} with one age public key per line "
            f"(one per person who should be able to decrypt {file.name})",
        )

    payload = json.dumps(data).encode("utf-8")
    tmp_path = secrets_path.parent / f"{file.name}.{os.getpid()}.tmp"

    # A stale temp file from a previous crash under the same pid (rare, but
    # possible across pid reuse) must not block this run from converging.
    tmp_path.unlink(missing_ok=True)
    fd = os.open(str(tmp_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)

    try:
        result = _run_age(["-R", str(recipients_path), "-o", str(tmp_path)], input_bytes=payload)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            raise StackError(
                f"failed to encrypt secrets to {secrets_path}",
                stderr or f"check that {recipients_path} contains valid age public keys",
            )
        if tmp_path.stat().st_size == 0:
            raise StackError(
                f"failed to encrypt secrets to {secrets_path}",
                "age exited successfully but produced no output -- nothing on disk was changed",
            )
        os.replace(tmp_path, secrets_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
```

Then append the recipients helpers and the two moved helpers:

```python
def read_recipients(path: Path) -> list[str]:
    """Every non-blank, non-comment line of an age recipients file, stripped."""
    if not path.exists():
        raise StackError(
            f"{path} not found",
            f"create {path} with one age public key per line (lines starting with # are ignored)",
        )
    return [
        stripped
        for line in path.read_text(encoding="utf-8").splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def check_recipients_superset(infra_dir: Path) -> None:
    """`deploy-recipients.txt` must list every recipient `age-recipients.txt` does.

    The split exists so a build host can decrypt the deploy key WITHOUT
    being able to decrypt anything else -- never the other way round.
    Anyone who already holds every secret in the project must not silently
    lose the ability to deploy, so the deploy list is a strict superset.

    No `deploy-recipients.txt` at all means this project has not set up a
    deploy key yet: nothing to check, no warning -- `deploy-key init` is
    what creates both files together.
    """
    deploy_recipients_path = infra_dir / DEPLOY_FILE.recipients_name
    if not deploy_recipients_path.exists():
        return

    secrets_recipients_path = infra_dir / SECRETS_FILE.recipients_name
    allowed = set(read_recipients(deploy_recipients_path))
    missing = [key for key in read_recipients(secrets_recipients_path) if key not in allowed]
    if not missing:
        return

    raise StackError(
        f"{deploy_recipients_path} is missing {len(missing)} recipient(s) that "
        f"{secrets_recipients_path} lists",
        "everyone who can decrypt secrets.age must also be able to decrypt deploy.age -- add "
        f"these line(s) to {deploy_recipients_path}, then run `./infra/up deploy-key init --rotate` "
        f"to re-encrypt it: {', '.join(missing)}",
    )


def register_private_key(private_key_text: str, register_secret: Callable[[str], None]) -> None:
    """Feed the private key's whole text, plus each base64 body line, into
    `register_secret` (F2, Fix round 1) -- before it is ever handed to
    anything that could echo it back.

    A PEM/OpenSSH private key is `-----BEGIN ...-----` / body lines /
    `-----END ...-----`; only the header/footer lines are non-secret. Each
    body line is registered individually (not just the joined whole) so that
    a partial echo of the key (e.g. one line of a remote command's stderr)
    is still masked, the same reasoning `reconcile.redaction_values` applies
    to `app_env`.
    """
    register_secret(private_key_text)
    for line in private_key_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-----"):
            continue
        if len(stripped) >= 8:
            register_secret(stripped)


def write_public_key(path: Path, content: str) -> None:
    """Write a PUBLIC key file atomically at 0644, creating its parent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp"
    tmp.write_text(content, encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(path)
```

- [ ] **Step 4: Point `ci.py` at the moved helpers**

In `stackbase/ci.py`, delete `_register_private_key` and `_write_pub_key_atomically` entirely, add `from stackbase.secrets import register_private_key, write_public_key` to the imports, and replace the two call sites:

```python
        _register_private_key(private_key_bytes.decode("utf-8", errors="replace"), register_secret)
```
becomes
```python
        register_private_key(private_key_bytes.decode("utf-8", errors="replace"), register_secret)
```
and
```python
    _write_pub_key_atomically(pub_path, public_key)
```
becomes
```python
    write_public_key(pub_path, public_key)
```

(Task 2 rewrites this function wholesale; this step only keeps the suite green in between.)

- [ ] **Step 5: Call the superset check from `up`**

In `stackbase/__main__.py`, add `check_recipients_superset` to the `from stackbase.secrets import ...` line, and call it in `_up` immediately after the config/state load, before any network call:

```python
def _up(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)
    # Before anything reaches the network: a deploy-recipients.txt that has
    # drifted behind age-recipients.txt means an admin who can read every
    # project secret can no longer decrypt the deploy key -- caught here,
    # once, rather than at their next failed deploy.
    check_recipients_superset(infra_dir)
    secrets.update(load_secrets(infra_dir))
```

- [ ] **Step 6: Ship the template recipients file**

Create `templates/infra/deploy-recipients.txt`:

```
# Who can decrypt infra/deploy.age -- the project's SSH deploy key.
#
# One age public key per line. Lines starting with # are ignored. Commit
# this file: public keys are not secret.
#
# This list MUST be a superset of infra/age-recipients.txt: everyone who
# can read the project's secrets must also be able to deploy. `./infra/up`
# refuses to run if a recipient is listed there but not here.
#
# It exists so the reverse is possible: a machine that only ships releases
# (a NixOS build host, for example) gets an age identity listed HERE ONLY.
# Compromising it yields "can push a release through the restricted door"
# and nothing else -- no API tokens, no TLS key, no app_env.
#
# To add a build host:
#
#   1. On the build host, once:
#
#        mkdir -p ~/.age && age-keygen -o ~/.age/key.txt && chmod 600 ~/.age/key.txt
#
#   2. Print its PUBLIC key and paste it below as a new line:
#
#        age-keygen -y ~/.age/key.txt
#
#   3. Re-encrypt deploy.age for the new list. That replaces the key, so
#      finish the sequence the command prints:
#
#        ./infra/up deploy-key init --rotate
```

- [ ] **Step 7: Run the tests — all green**

Run: `python3 -m unittest tests.test_secrets tests.test_template tests.test_ci -v`
Expected: OK (the `age`-dependent classes skip when `age`/`age-keygen` are not installed).

Run: `python3 -m unittest discover -s tests`
Expected: OK.

- [ ] **Step 8: Commit**

```bash
git add stackbase/secrets.py stackbase/ci.py stackbase/__main__.py \
        templates/infra/deploy-recipients.txt tests/test_secrets.py tests/test_template.py
git commit -m "secrets: generalise load/save over a file + recipients pair, add the deploy recipients superset check"
```

---

### Task 2: `deploy-key init|show-pub`, and `ci-setup` on top of it

**Files:**
- Modify: `stackbase/secrets_cli.py`, `stackbase/ci.py`, `stackbase/__main__.py`, `templates/infra/flake.nix`, `README.md`
- Test: `tests/test_secrets_cli.py`, `tests/test_ci.py`, `tests/test_template.py`, `tests/test_cli.py`

**Interfaces — Consumes:** `secrets.DEPLOY_FILE`, `secrets.DEPLOY_KEY_NAME`, `secrets.check_recipients_superset`, `secrets.register_private_key`, `secrets.write_public_key`, `secrets.load_secrets`, `secrets.save_secrets` (Task 1).

**Interfaces — Produces:**
- `secrets_cli.DEPLOY_PUB_FILENAME = "deploy.pub"` (under `infra/keys/`).
- `secrets_cli.deploy_key_init(infra_dir, *, rotate=False, runner=subprocess.run, emit=print, register_secret=_noop_register_value) -> None`
- `secrets_cli.deploy_key_show_pub(infra_dir, *, emit=print) -> None`
- `ci.ci_setup(...)` unchanged in signature, new behaviour: never runs `ssh-keygen` itself.
- CLI: `./infra/up deploy-key init [--rotate]`, `./infra/up deploy-key show-pub`.
- Template flake: `projectDeployKeys` reading `./keys/deploy.pub` into `stackbase.deploy.keys.deploy`.

- [ ] **Step 1: Write the failing tests for `deploy-key`**

Create `tests/test_secrets_cli.py` additions (append to the existing file; it already imports `unittest`, `Path`, `TemporaryDirectory` and `StackError`):

```python
import os
import subprocess
from unittest import mock

from stackbase.secrets import DEPLOY_KEY_NAME, load_secrets, DEPLOY_FILE
from stackbase.secrets_cli import DEPLOY_PUB_FILENAME, deploy_key_init, deploy_key_show_pub

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

_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None
_SSH_KEYGEN_AVAILABLE = shutil.which("ssh-keygen") is not None


def _deploy_project(infra_dir: Path, recipient: str) -> None:
    """A minimal infra/ with a valid stack.toml and both recipients files."""
    infra_dir.mkdir(parents=True, exist_ok=True)
    (infra_dir / "stack.toml").write_text(_STACK_TOML, encoding="utf-8")
    (infra_dir / "keys").mkdir(exist_ok=True)
    (infra_dir / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTemplateEval matt@laptop\n",
        encoding="utf-8",
    )
    (infra_dir / "age-recipients.txt").write_text(recipient + "\n", encoding="utf-8")
    (infra_dir / "deploy-recipients.txt").write_text(recipient + "\n", encoding="utf-8")


@unittest.skipUnless(
    _AGE_AVAILABLE and _SSH_KEYGEN_AVAILABLE, "age / ssh-keygen not installed"
)
class DeployKeyInitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.identity_path, self.public_key = _generate_age_identity(self.root)
        self.infra_dir = self.root / "infra"
        _deploy_project(self.infra_dir, self.public_key)
        self.env = mock.patch.dict(os.environ, {"STACKBASE_AGE_IDENTITY": str(self.identity_path)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_creates_deploy_age_and_the_public_half(self) -> None:
        emitted: list[str] = []

        deploy_key_init(self.infra_dir, emit=emitted.append)

        pub_path = self.infra_dir / "keys" / DEPLOY_PUB_FILENAME
        self.assertTrue((self.infra_dir / "deploy.age").exists())
        self.assertTrue(pub_path.read_text(encoding="utf-8").startswith("ssh-ed25519 "))
        self.assertIn("deploy@acme", pub_path.read_text(encoding="utf-8"))

        stored = load_secrets(self.infra_dir, file=DEPLOY_FILE)
        self.assertEqual(list(stored), [DEPLOY_KEY_NAME])
        self.assertIn("PRIVATE KEY", stored[DEPLOY_KEY_NAME])
        self.assertTrue(any("deploy-key" in line or "deploy key" in line for line in emitted))

    def test_the_private_key_never_lands_on_disk_outside_the_encrypted_file(self) -> None:
        deploy_key_init(self.infra_dir, emit=lambda _line: None)
        private_key = load_secrets(self.infra_dir, file=DEPLOY_FILE)[DEPLOY_KEY_NAME]
        body = [line for line in private_key.splitlines() if not line.startswith("-----")][0]

        for path in self.root.rglob("*"):
            if not path.is_file() or path.name == "deploy.age":
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            self.assertNotIn(body, text, f"private key material leaked into {path}")

    def test_refuses_to_replace_an_existing_key_without_rotate(self) -> None:
        deploy_key_init(self.infra_dir, emit=lambda _line: None)
        first = (self.infra_dir / "keys" / DEPLOY_PUB_FILENAME).read_text(encoding="utf-8")

        with self.assertRaises(StackError) as ctx:
            deploy_key_init(self.infra_dir, emit=lambda _line: None)

        self.assertIn("--rotate", str(ctx.exception))
        self.assertEqual((self.infra_dir / "keys" / DEPLOY_PUB_FILENAME).read_text(encoding="utf-8"), first)

    def test_rotate_replaces_both_halves_and_prints_the_follow_up_sequence(self) -> None:
        deploy_key_init(self.infra_dir, emit=lambda _line: None)
        first = (self.infra_dir / "keys" / DEPLOY_PUB_FILENAME).read_text(encoding="utf-8")
        emitted: list[str] = []

        deploy_key_init(self.infra_dir, rotate=True, emit=emitted.append)

        self.assertNotEqual((self.infra_dir / "keys" / DEPLOY_PUB_FILENAME).read_text(encoding="utf-8"), first)
        joined = "\n".join(emitted)
        self.assertIn("./infra/up", joined)
        self.assertIn("ci-setup", joined)

    def test_a_deploy_recipients_file_that_is_not_a_superset_is_refused_before_keygen(self) -> None:
        (self.infra_dir / "age-recipients.txt").write_text(
            self.public_key + "\nage1someoneelse\n", encoding="utf-8"
        )

        with self.assertRaises(StackError) as ctx:
            deploy_key_init(self.infra_dir, emit=lambda _line: None)

        self.assertIn("age1someoneelse", str(ctx.exception))
        self.assertFalse((self.infra_dir / "deploy.age").exists())

    def test_a_missing_deploy_recipients_file_names_the_file_to_create(self) -> None:
        (self.infra_dir / "deploy-recipients.txt").unlink()

        with self.assertRaises(StackError) as ctx:
            deploy_key_init(self.infra_dir, emit=lambda _line: None)

        self.assertIn("deploy-recipients.txt", str(ctx.exception))

    def test_the_private_key_is_registered_for_redaction(self) -> None:
        registered: list[str] = []

        deploy_key_init(self.infra_dir, emit=lambda _line: None, register_secret=registered.append)

        private_key = load_secrets(self.infra_dir, file=DEPLOY_FILE)[DEPLOY_KEY_NAME]
        self.assertIn(private_key, registered)


class DeployKeyShowPubTests(unittest.TestCase):
    def test_prints_the_committed_public_half(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            (infra_dir / "keys").mkdir()
            (infra_dir / "keys" / DEPLOY_PUB_FILENAME).write_text(
                "ssh-ed25519 AAAA deploy@acme\n", encoding="utf-8"
            )
            emitted: list[str] = []

            deploy_key_show_pub(infra_dir, emit=emitted.append)

            self.assertEqual(emitted, ["ssh-ed25519 AAAA deploy@acme"])

    def test_a_missing_public_half_names_the_init_command(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(StackError) as ctx:
                deploy_key_show_pub(Path(tmp), emit=lambda _line: None)

            self.assertIn("deploy-key init", str(ctx.exception))
```

If `tests/test_secrets_cli.py` does not already import `shutil` or define `_generate_age_identity`, add at the top of the file:

```python
import shutil

from tests.test_secrets import _generate_age_identity
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_secrets_cli -v`
Expected: FAIL — `ImportError: cannot import name 'deploy_key_init' from 'stackbase.secrets_cli'`.

- [ ] **Step 3: Implement the two commands**

In `stackbase/secrets_cli.py`, extend the imports and add the constants and functions at the end of the file:

```python
from stackbase.config import load_config
from stackbase.secrets import (
    DEPLOY_FILE,
    DEPLOY_KEY_NAME,
    check_recipients_superset,
    load_secrets,
    register_private_key,
    save_secrets,
    write_public_key,
)

# The PUBLIC half of the project's deploy key, committed like any other
# key under infra/keys/. The private half only ever exists inside
# infra/deploy.age (encrypted) and, for the seconds a command needs it, in
# a RAM-backed scratch directory.
DEPLOY_PUB_FILENAME = "deploy.pub"


def _noop_register_value(_value: str) -> None:
    pass


def deploy_key_init(
    infra_dir: Path,
    *,
    rotate: bool = False,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = _noop_register_value,
) -> None:
    """Generate the project's ONE SSH deploy key: `deploy.age` + `keys/deploy.pub`.

    The private half is generated inside `private_ram_dir()` (never a real
    disk), encrypted straight into `infra/deploy.age` against
    `infra/deploy-recipients.txt`, and then the RAM directory is wiped.
    The public half is written to `infra/keys/deploy.pub`, which the
    project's flake reads into `stackbase.deploy.keys` -- that is what
    installs it on every server.

    Refuses outright when `deploy.age` already exists unless `rotate` is
    set: replacing a live key is a sequence (commit, `up`, `ci-setup`), not
    a side effect of a mistyped command.

    `register_secret(value)` feeds the CLI's own redaction net (the same
    mechanism `ci_setup` uses) -- the private key is registered the moment
    it is read, before anything else can echo it.
    """
    cfg = load_config(infra_dir)
    deploy_path = infra_dir / DEPLOY_FILE.name
    pub_path = infra_dir / "keys" / DEPLOY_PUB_FILENAME

    if deploy_path.exists() and not rotate:
        raise StackError(
            f"{deploy_path} already exists",
            "pass --rotate to replace it -- the old key keeps working on the servers until you "
            "commit the new infra/keys/deploy.pub and run ./infra/up",
        )

    recipients_path = infra_dir / DEPLOY_FILE.recipients_name
    if not recipients_path.exists():
        raise StackError(
            f"{recipients_path} not found",
            "create infra/deploy-recipients.txt with one age public key per line -- it must list "
            "every recipient of infra/age-recipients.txt, plus any build host that deploys",
        )
    # Checked BEFORE ssh-keygen runs: a key encrypted to a list that has
    # already drifted would lock an admin out the moment it is committed.
    check_recipients_superset(infra_dir)

    with private_ram_dir() as ramdir:
        key_path = ramdir / "deploy_key"
        keygen = runner(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"deploy@{cfg.project}", "-f", str(key_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if keygen.returncode != 0:
            raise StackError(
                "ssh-keygen failed while generating the project deploy key",
                (keygen.stderr or "").strip() or "check that ssh-keygen is installed",
            )

        pub_key_path = ramdir / "deploy_key.pub"
        if not key_path.is_file() or not pub_key_path.is_file():
            raise StackError(
                "ssh-keygen did not produce both key files",
                "this is a bug in stack-base -- please report it",
            )

        private_key = key_path.read_text(encoding="utf-8")
        register_private_key(private_key, register_secret)
        public_key = pub_key_path.read_text(encoding="utf-8").strip() + "\n"

        save_secrets(infra_dir, {DEPLOY_KEY_NAME: private_key}, file=DEPLOY_FILE)

    # Past this point the RAM directory (and the private key it held) is
    # gone -- only the PUBLIC key is still in hand.
    write_public_key(pub_path, public_key)

    action = "rotated" if rotate else "created"
    emit(f"project deploy key {action}: {deploy_path} (encrypted) and {pub_path} (public).")
    emit("Next steps:")
    emit(f"  1. git add {deploy_path} {pub_path} && git commit -m 'deploy: {action} the project deploy key'")
    emit("  2. ./infra/up                 # installs the key on every server")
    emit("  3. ./infra/up ci-setup        # only if GitHub Actions deploys this project")
    if rotate:
        emit("  Deploys using the OLD key (CI, and any build host) FAIL until steps 1-3 are done.")


def deploy_key_show_pub(infra_dir: Path, *, emit: Callable[[str], None] = print) -> None:
    """Print the deploy key's PUBLIC half -- never touches deploy.age."""
    pub_path = infra_dir / "keys" / DEPLOY_PUB_FILENAME
    if not pub_path.is_file():
        raise StackError(
            f"{pub_path} not found",
            "run `./infra/up deploy-key init` first -- it writes the public half there",
        )
    emit(pub_path.read_text(encoding="utf-8").strip())
```

- [ ] **Step 4: Run the `deploy-key` tests — green**

Run: `python3 -m unittest tests.test_secrets_cli -v`
Expected: OK.

- [ ] **Step 5: Rewrite the `ci-setup` tests**

In `tests/test_ci.py`: replace every occurrence of the string `"ci-deploy.pub"` with `"deploy.pub"`, delete `test_refuses_to_overwrite_an_existing_pub_key_without_rotate`, `test_the_ssh_keygen_comment_names_the_project` and `test_ssh_keygen_failure_is_reported_and_nothing_is_written` (those behaviours now belong to `deploy_key_init`, and are covered in `tests/test_secrets_cli.py`), and add:

```python
class CiSetupUsesTheProjectDeployKeyTests(unittest.TestCase):
    def test_it_never_runs_ssh_keygen_itself(self) -> None:
        with _project_with_deploy_key() as (infra_dir, runner, _private_key):
            ci_setup(infra_dir, emit=lambda _line: None, runner=runner)

            self.assertFalse(
                any(call["argv"][0] == "ssh-keygen" for call in runner.calls),
                "ci-setup must push the existing project deploy key, not mint its own",
            )

    def test_it_pushes_exactly_the_bytes_held_in_deploy_age(self) -> None:
        with _project_with_deploy_key() as (infra_dir, runner, private_key):
            ci_setup(infra_dir, emit=lambda _line: None, runner=runner)

            secret_calls = [c for c in runner.calls if c["argv"][:3] == ["gh", "secret", "set"]]
            self.assertEqual(len(secret_calls), 1)
            self.assertEqual(secret_calls[0]["kwargs"]["input"], private_key.encode("utf-8"))

    def test_an_absent_deploy_age_is_created_first(self) -> None:
        with _project_without_deploy_key() as (infra_dir, runner):
            ci_setup(infra_dir, emit=lambda _line: None, runner=runner)

            self.assertTrue((infra_dir / "deploy.age").exists())
            self.assertTrue((infra_dir / "keys" / "deploy.pub").is_file())

    def test_a_second_run_without_rotate_reuses_the_same_key(self) -> None:
        with _project_with_deploy_key() as (infra_dir, runner, private_key):
            ci_setup(infra_dir, emit=lambda _line: None, runner=runner)
            ci_setup(infra_dir, emit=lambda _line: None, runner=runner)

            pushed = [
                c["kwargs"]["input"] for c in runner.calls if c["argv"][:3] == ["gh", "secret", "set"]
            ]
            self.assertEqual(pushed, [private_key.encode("utf-8"), private_key.encode("utf-8")])
```

The existing `_happy_path_handler` scripts an `ssh-keygen` branch that `ci_setup` must no longer reach; keep it (an unused branch is exactly what `test_it_never_runs_ssh_keygen_itself` proves) and add the two fixtures above `CiSetupUsesTheProjectDeployKeyTests`:

```python
import contextlib
import shutil

from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, load_secrets
from stackbase.secrets_cli import deploy_key_init
from tests.test_secrets import _generate_age_identity

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
```

with `import os` and `from unittest import mock` added to `tests/test_ci.py`'s imports if they are not already there. Note `_generate_age_identity` writes into `infra_dir.parent`, not `infra_dir` — an age identity inside the project directory is exactly what the "never on disk in the project" assertions elsewhere forbid.

- [ ] **Step 6: Rewrite `ci_setup`**

In `stackbase/ci.py`: delete the `PUB_KEY_FILENAME` constant and the whole `ssh-keygen` block, and replace `ci_setup` with:

```python
def ci_setup(
    infra_dir: Path,
    *,
    rotate: bool = False,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> None:
    """Push the project's deploy key into the repo-level GitHub Actions secret.

    There is ONE project deploy key (`infra/deploy.age`, public half
    `infra/keys/deploy.pub`), used by CI and by humans alike -- ci-setup no
    longer mints a separate one. Absent, it is created here by
    `deploy_key_init`; `--rotate` forwards to `deploy_key_init(rotate=True)`,
    which replaces both halves.

    Repo-level, not organization-level: the owner's GitHub plan has no
    org-level secrets/variables, so a repo secret is not a simplification
    here, it's the only option. A leaked key can only ever reach the same
    six door commands as any other `stackbase.deploy.keys` entry -- see the
    README.

    Everything that can fail cheaply (repo detection, `gh` auth) runs BEFORE
    a key is generated. The private key is registered for redaction before
    the one call that could conceivably echo it back.
    """
    deploy_path = infra_dir / DEPLOY_FILE.name

    repo_dir = infra_dir.parent
    owner, repo = parse_github_repo(_origin_url(repo_dir, runner=runner))
    repo_slug = f"{owner}/{repo}"

    _require_gh(runner=runner)

    if rotate or not deploy_path.exists():
        deploy_key_init(infra_dir, rotate=rotate, runner=runner, emit=emit, register_secret=register_secret)

    private_key = load_secrets(infra_dir, file=DEPLOY_FILE).get(DEPLOY_KEY_NAME)
    if not private_key:
        raise StackError(
            f"{deploy_path} has no '{DEPLOY_KEY_NAME}'",
            "re-create it with `./infra/up deploy-key init --rotate`",
        )
    register_private_key(private_key, register_secret)

    # The private key travels ONLY as this subprocess call's stdin
    # (`input=`) -- never as an argv element, never as an environment
    # variable, never written anywhere on this machine's disk.
    secret_set = runner(
        ["gh", "secret", "set", SECRET_NAME, "--repo", repo_slug],
        input=private_key.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if secret_set.returncode != 0:
        stderr = secret_set.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        raise StackError(
            f"gh secret set {SECRET_NAME} failed",
            (stderr or "").strip() or "check `gh auth status` and that you can push secrets to this repository",
        )

    verify = runner(
        ["gh", "secret", "list", "--repo", repo_slug, "--json", "name", "-q", ".[].name"],
        capture_output=True,
        text=True,
        check=False,
    )
    names = [line.strip() for line in (verify.stdout or "").splitlines() if line.strip()]
    if verify.returncode != 0 or SECRET_NAME not in names:
        raise StackError(
            f"could not confirm {SECRET_NAME} exists on {repo_slug} after setting it",
            f"run `gh secret list --repo {repo_slug}` yourself to check",
        )

    pub_path = infra_dir / "keys" / DEPLOY_PUB_FILENAME
    emit(f"{SECRET_NAME} on {repo_slug} now holds this project's deploy key.")
    emit("Next steps:")
    emit(f"  1. git add {deploy_path} {pub_path} && git commit -m 'ci: the project deploy key'")
    emit("  2. ./infra/up                 # installs the key on every server")
    emit(f"  3. mkdir -p .github/workflows && cp {_WORKFLOW_TEMPLATE} .github/workflows/deploy-stack.yml")
    emit("     git add .github/workflows/deploy-stack.yml && git commit -m 'ci: add the deploy workflow'")
    if rotate:
        # The GitHub secret was already replaced above, immediately -- not
        # step 2. Until step 1 is committed AND step 2 has installed the new
        # public half on every server, CI deploys fail outright (the runner
        # now offers the NEW private key; every server still only trusts the
        # OLD public one).
        emit("  CI deploys will FAIL (wrong key) until steps 1 and 2 above have both completed --")
        emit("  the GitHub secret was already replaced, just now.")
    emit("To turn CI deploys back off:")
    emit(f"  gh secret delete {SECRET_NAME} --repo {repo_slug}")
    emit("  (leave deploy.age and keys/deploy.pub in place -- they are also your own deploy key)")
```

Update `ci.py`'s imports to:

```python
from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, load_secrets, register_private_key
from stackbase.secrets_cli import DEPLOY_PUB_FILENAME, deploy_key_init
```

and delete the now-unused `load_config`, `private_ram_dir` and `write_public_key` imports if nothing else in the file uses them. Update the module docstring's first paragraph to say the key is the project's one deploy key, created by `deploy-key init`.

- [ ] **Step 7: Wire the CLI**

In `stackbase/__main__.py`, add the subparser next to `ci_setup_p`:

```python
    deploy_key_p = commands.add_parser(
        "deploy-key", help="the project's SSH deploy key -- used by you, by a build host, and by CI"
    )
    deploy_key_sub = deploy_key_p.add_subparsers(dest="deploy_key_command", required=True)

    deploy_key_init_p = deploy_key_sub.add_parser(
        "init", help="generate it in RAM: writes infra/deploy.age and infra/keys/deploy.pub"
    )
    deploy_key_init_p.add_argument("--rotate", action="store_true", help="replace an existing deploy key")
    deploy_key_init_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    deploy_key_show_p = deploy_key_sub.add_parser("show-pub", help="print the deploy key's public half")
    deploy_key_show_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")
```

the dispatch branch in `main()` (immediately after the `ci-setup` branch):

```python
        elif args.command == "deploy-key":
            _deploy_key(args, infra_dir, secrets)
```

and the handler next to `_ci_setup`:

```python
def _deploy_key(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    if args.deploy_key_command == "init":
        deploy_key_init(
            infra_dir,
            rotate=args.rotate,
            emit=_emit_plain,
            register_secret=_secret_register_counter(secrets),
        )
    elif args.deploy_key_command == "show-pub":
        deploy_key_show_pub(infra_dir, emit=_emit_plain)
    else:
        # deploy_key_sub is required=True, so this is unreachable in
        # practice -- an explicit branch beats a bare `else` doing nothing.
        raise StackError(
            f"unknown deploy-key command '{args.deploy_key_command}'",
            "this is a bug in stack-base -- please report it",
        )
```

with `deploy_key_init, deploy_key_show_pub` added to the `from stackbase.secrets_cli import ...` line.

Add to `tests/test_cli.py`, in the same style as the existing wiring tests:

```python
class DeployKeyCLIWiringTests(unittest.TestCase):
    def test_init_forwards_rotate(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.deploy_key_init") as init_mock:
                main(["--infra-dir", str(infra_dir), "deploy-key", "init", "--rotate"])

            self.assertEqual(init_mock.call_args.args[0], infra_dir)
            self.assertTrue(init_mock.call_args.kwargs["rotate"])

    def test_show_pub_is_wired(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with mock.patch("stackbase.__main__.deploy_key_show_pub") as show_mock:
                main(["--infra-dir", str(infra_dir), "deploy-key", "show-pub"])

            show_mock.assert_called_once()
```

- [ ] **Step 8: Point the template flake at `keys/deploy.pub`**

In `templates/infra/flake.nix`, replace the `ciDeployPubPath`/`ciDeployKeys` block with:

```nix
      # The project's ONE deploy key (`./infra/up deploy-key init`). Present
      # as soon as an operator has created it; the PRIVATE half lives only
      # in infra/deploy.age (and, for CI, in the repo's STACK_DEPLOY_KEY
      # secret). Layered on TOP of the admin keys below, never merged into
      # `admins` itself: every admin key also goes into
      # stackbase.deploy.keys (so an admin can deploy from their own laptop
      # with the same key they already log in with), but `deploy` must never
      # be able to reach root's or any admin's own authorized_keys -- only
      # nixos/deploy.nix's forced-command door reads stackbase.deploy.keys.
      deployPubPath = ./keys/deploy.pub;
      projectDeployKeys =
        if builtins.pathExists deployPubPath
        then {
          deploy = builtins.replaceStrings [ "\n" ] [ "" ]
            (builtins.readFile deployPubPath);
        }
        else { };

      deployKeys = admins // projectDeployKeys;
```

In `tests/test_template.py`, rename `CiDeployKeyTests` to `ProjectDeployKeyTests`, change `_CI_PUB` to

```python
    _DEPLOY_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAACIExampleDeployKey deploy@acme\n"
```

write it to `keys/deploy.pub`, and assert `self.assertIn("deploy", facts["deployKeys"])` plus that `ExampleDeployKey` appears in neither `rootKeys` nor `mattKeys`. Update the no-key test to write nothing and assert `self.assertNotIn("deploy", facts["deployKeys"])`.

- [ ] **Step 9: README**

In `README.md`, replace the "**What `./infra/up ci-setup` does:**" paragraph and the "**Turn it on**"/"**Rotate it**"/"**Turn it off**" blocks of `## Deploying from GitHub Actions (optional)` with copy describing the one project key, and add a new subsection immediately above `## Deploying from GitHub Actions (optional)`:

```markdown
## The project deploy key

Every project has exactly **one** SSH deploy key. You use it, a build host
uses it, and GitHub Actions uses it — all through the same restricted door
(`upload`, `deploy`, `rollback`, `status`, `colors`, `releases`, and
nothing else).

```bash
./infra/up deploy-key init         # generates it; writes infra/deploy.age + infra/keys/deploy.pub
./infra/up deploy-key show-pub     # prints the public half
git add infra/deploy.age infra/keys/deploy.pub && git commit -m "deploy: add the project deploy key"
./infra/up                         # installs it on every server
```

The private half is generated in RAM and goes straight into
`infra/deploy.age`, encrypted to `infra/deploy-recipients.txt` — a
**different** list from `infra/age-recipients.txt`, and one that must
contain every name on it. That asymmetry is the point: a build host gets an
age identity listed **only** in `deploy-recipients.txt`, so compromising it
yields "can push a release through the restricted door" and nothing else —
no API tokens, no TLS key, no `app_env`. `./infra/up` refuses to run if
`deploy-recipients.txt` has fallen behind `age-recipients.txt`.

`./infra/up deploy-key init --rotate` replaces both halves. It prints the
sequence that has to follow (commit → `./infra/up` → `ci-setup`); until it
is finished, anything still holding the old key cannot deploy.
```

Also, in `## What the files are`, add the three rows:

```markdown
| `deploy-recipients.txt` | Who can decrypt `deploy.age` — a superset of `age-recipients.txt`. Commit |
| `deploy.age` | The project's encrypted SSH deploy key. Commit (it's encrypted) |
| `keys/deploy.pub` | The deploy key's public half — this is what gets installed on the servers. Commit |
```

and in `## When it fails`:

```markdown
| `infra/deploy-recipients.txt is missing N recipient(s)` | Add the listed key(s) to `deploy-recipients.txt`, then `./infra/up deploy-key init --rotate` |
| `infra/deploy.age already exists` | Pass `--rotate` if you really mean to replace the project's deploy key |
```

Finally, add one line under "**Turn it off:**" saying that a project upgraded from an older stack-base should delete `infra/keys/ci-deploy.pub` and run `./infra/up deploy-key init` — the template flake no longer reads that path.

- [ ] **Step 10: Full suite, then commit**

Run: `python3 -m unittest discover -s tests`
Expected: OK.

```bash
git add stackbase/secrets_cli.py stackbase/ci.py stackbase/__main__.py \
        templates/infra/flake.nix README.md \
        tests/test_secrets_cli.py tests/test_ci.py tests/test_template.py tests/test_cli.py
git commit -m "deploy-key: one project key, created in RAM, pushed to CI by ci-setup"
```

---

### Task 3: Deploy identity resolution order

**Files:**
- Modify: `stackbase/release.py`, `stackbase/__main__.py`, `README.md`
- Test: `tests/test_release.py`

**Interfaces — Consumes:** `secrets.DEPLOY_FILE`, `secrets.DEPLOY_KEY_NAME`, `secrets.load_secrets`, `secrets.register_private_key`, `ramdir.private_ram_dir`.

**Interfaces — Produces:**
- `release.deploy_identity(infra_dir: Path, *, emit=print, register_secret=lambda _v: None) -> ContextManager[None]` — sets `$STACKBASE_SSH_IDENTITY` for the duration when it resolves a project key.
- `run_deploy` / `run_rollback` / `run_status` gain `register_secret: Callable[[str], None] = lambda _value: None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_release.py`:

```python
from stackbase.release import deploy_identity
from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, save_secrets

_TEST_PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


class DeployIdentityTests(unittest.TestCase):
    def test_an_explicit_env_identity_wins_and_nothing_is_decrypted(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp)
            (infra_dir / "deploy.age").write_bytes(b"would-not-decrypt")
            emitted: list[str] = []

            with mock.patch.dict(os.environ, {"STACKBASE_SSH_IDENTITY": "/home/me/.ssh/id_ed25519"}):
                with deploy_identity(infra_dir, emit=emitted.append):
                    self.assertEqual(os.environ["STACKBASE_SSH_IDENTITY"], "/home/me/.ssh/id_ed25519")

            self.assertEqual(emitted, [])

    def test_no_project_key_warns_once_and_leaves_the_agent_path_alone(self) -> None:
        with TemporaryDirectory() as tmp:
            emitted: list[str] = []
            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}

            with mock.patch.dict(os.environ, env, clear=True):
                with deploy_identity(Path(tmp), emit=emitted.append):
                    self.assertNotIn("STACKBASE_SSH_IDENTITY", os.environ)

            self.assertEqual(len(emitted), 1)
            self.assertIn("deploy-key init", emitted[0])

    @unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed")
    def test_deploy_age_is_decrypted_into_a_ram_dir_for_the_duration_only(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            identity_path, public_key = _generate_age_identity(Path(tmp))
            (infra_dir / "deploy-recipients.txt").write_text(public_key + "\n", encoding="utf-8")
            seen: dict[str, str] = {}

            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}
            env["STACKBASE_AGE_IDENTITY"] = str(identity_path)
            with mock.patch.dict(os.environ, env, clear=True):
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: _TEST_PRIVATE_KEY}, file=DEPLOY_FILE)

                with deploy_identity(infra_dir, emit=lambda _line: None):
                    key_path = Path(os.environ["STACKBASE_SSH_IDENTITY"])
                    seen["path"] = str(key_path)
                    self.assertTrue(key_path.is_absolute())
                    self.assertEqual(key_path.read_text(encoding="utf-8"), _TEST_PRIVATE_KEY)
                    self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                    self.assertFalse(
                        str(key_path).startswith(str(infra_dir)),
                        "the plaintext key must never be written inside the project",
                    )

                self.assertNotIn("STACKBASE_SSH_IDENTITY", os.environ)

            self.assertFalse(Path(seen["path"]).exists(), "the RAM scratch file must be wiped on exit")

    @unittest.skipUnless(_AGE_AVAILABLE, "age / age-keygen not installed")
    def test_the_private_key_is_registered_for_redaction(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            identity_path, public_key = _generate_age_identity(Path(tmp))
            (infra_dir / "deploy-recipients.txt").write_text(public_key + "\n", encoding="utf-8")
            registered: list[str] = []

            env = {key: value for key, value in os.environ.items() if key != "STACKBASE_SSH_IDENTITY"}
            env["STACKBASE_AGE_IDENTITY"] = str(identity_path)
            with mock.patch.dict(os.environ, env, clear=True):
                save_secrets(infra_dir, {DEPLOY_KEY_NAME: _TEST_PRIVATE_KEY}, file=DEPLOY_FILE)

                with deploy_identity(infra_dir, emit=lambda _line: None, register_secret=registered.append):
                    pass

            self.assertIn(_TEST_PRIVATE_KEY, registered)


class DeployIdentityIsUsedByTheCommandsTests(unittest.TestCase):
    def test_run_status_opens_the_identity_around_the_ssh_calls(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = RunDeploySkipBuildTests()._project(Path(tmp))
            order: list[str] = []

            @contextlib.contextmanager
            def fake_identity(*_args, **_kwargs):
                order.append("enter")
                yield
                order.append("exit")

            with (
                mock.patch("stackbase.release.deploy_identity", fake_identity),
                mock.patch("stackbase.release.status_nodes", side_effect=lambda *a, **k: order.append("status")),
            ):
                run_status(infra_dir, emit=lambda _line: None)

            self.assertEqual(order, ["enter", "status", "exit"])
```

`RunDeploySkipBuildTests._project(root)` is the infra-directory builder already in `tests/test_release.py` (line ~1038) — a `stack.toml` with one primary node `a` plus a `stack.state.json` giving it `10.0.0.1`; calling it as an unbound helper keeps this test to one source of truth for that fixture. Add `import contextlib`, `import shutil`, `from tests.test_secrets import _generate_age_identity`, `run_status` on the `from stackbase.release import (...)` list, and `_AGE_AVAILABLE = shutil.which("age") is not None and shutil.which("age-keygen") is not None` at the top of the file (none of them are there today). Place the two new classes AFTER `RunDeploySkipBuildTests` so the name is defined.

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_release -v`
Expected: FAIL — `ImportError: cannot import name 'deploy_identity' from 'stackbase.release'`.

- [ ] **Step 3: Implement `deploy_identity`**

In `stackbase/release.py`, add to the imports:

```python
from stackbase.ramdir import private_ram_dir
from stackbase.secrets import DEPLOY_FILE, DEPLOY_KEY_NAME, load_secrets, register_private_key
```

and add this section just above "Ship / rollback / status":

```python
# --------------------------------------------------------------------------
# The SSH identity a deploy uses
# --------------------------------------------------------------------------

# Read by stackbase/ssh.py's own `_identity_options` -- setting it here
# makes every Ssh() built inside the `with` block offer exactly one key
# (`-i <path> -o IdentitiesOnly=yes`), which is also what keeps a
# multi-key ssh-agent from burning through the node's MaxAuthTries (I4).
_SSH_IDENTITY_ENV = "STACKBASE_SSH_IDENTITY"

_NO_PROJECT_KEY_WARNING = (
    "! no project deploy key found (infra/deploy.age) -- using whatever your ssh-agent offers; "
    "run `./infra/up deploy-key init` to create one"
)


@contextlib.contextmanager
def deploy_identity(
    infra_dir: Path,
    *,
    emit: Callable[[str], None] = print,
    register_secret: Callable[[str], None] = lambda _value: None,
) -> Iterator[None]:
    """Resolve which SSH key this deploy offers, in a fixed order.

    1. `$STACKBASE_SSH_IDENTITY` -- an explicit operator choice always wins,
       and nothing is decrypted.
    2. `infra/deploy.age` -- decrypted with the age identity
       (`$STACKBASE_AGE_IDENTITY`; on a build host a file identity, on a
       laptop usually a YubiKey) into a RAM-backed scratch file for the
       duration of this block, and pointed at by `$STACKBASE_SSH_IDENTITY`.
       The plaintext key NEVER exists outside `private_ram_dir()`, which is
       zeroed and removed on the way out -- success, failure or Ctrl-C.
    3. Neither -- fall through to whatever the operator's ssh-agent offers,
       with one warning line so a silent "Permission denied" later is not a
       mystery.

    Unlike everything else in this module, path 2 needs an age identity.
    That is deliberate (it is what lets a build host deploy with a key that
    unlocks nothing else); a teammate who only holds an SSH key still
    deploys via path 1 or 3.
    """
    if os.environ.get(_SSH_IDENTITY_ENV):
        yield
        return

    deploy_path = infra_dir / DEPLOY_FILE.name
    if not deploy_path.exists():
        emit(_NO_PROJECT_KEY_WARNING)
        yield
        return

    private_key = load_secrets(infra_dir, file=DEPLOY_FILE).get(DEPLOY_KEY_NAME)
    if not private_key:
        raise StackError(
            f"{deploy_path} has no '{DEPLOY_KEY_NAME}'",
            "re-create it with `./infra/up deploy-key init --rotate`",
        )
    register_private_key(private_key, register_secret)

    with private_ram_dir() as ramdir:
        key_path = ramdir / "deploy_key"
        # Created at 0600 atomically (O_CREAT|O_EXCL), never chmod'ed
        # afterwards: ssh refuses a group/world-readable private key, and a
        # window at a laxer mode is exactly what this avoids.
        fd = os.open(str(key_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # ssh requires the trailing newline; ssh-keygen always writes
            # one, but a hand-edited deploy.age might not have it.
            handle.write(private_key if private_key.endswith("\n") else private_key + "\n")

        previous = os.environ.get(_SSH_IDENTITY_ENV)
        os.environ[_SSH_IDENTITY_ENV] = str(key_path)
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop(_SSH_IDENTITY_ENV, None)
            else:
                os.environ[_SSH_IDENTITY_ENV] = previous
```

Add `Iterator` to the `typing` import if it is not already there (it is — `release_worktree` uses it).

- [ ] **Step 4: Wrap the door-driving calls only**

In `run_deploy`, both `ship(...)` calls become:

```python
        with deploy_identity(infra_dir, emit=emit, register_secret=register_secret):
            ship(infra_dir, cfg, state, version, tarball, sha256, node=node, runner=runner, popen=popen, emit=emit)
```

(the build may take many minutes — the RAM key only exists for the upload/switch phase). `run_rollback` and `run_status` wrap their single `rollback_nodes(...)` / `status_nodes(...)` call the same way. All three gain the parameter:

```python
    register_secret: Callable[[str], None] = lambda _value: None,
```

Update the module docstring's "These commands need no secrets" paragraph to:

```
These commands need no API token and never decrypt `secrets.age`. They read
`stack.toml`, `stack.state.json` and `infra/known_hosts` -- plus, when the
project has one, `infra/deploy.age`, which needs the age identity. A
teammate whose only credential is an SSH key listed in
`stackbase.deploy.keys` still runs all three: they set
`$STACKBASE_SSH_IDENTITY`, or let their ssh-agent answer.
```

- [ ] **Step 5: Mask the deploy output**

In `stackbase/__main__.py`, replace `_emit_plain`'s use in the three deploy handlers with a masking emit bound to the shared `secrets` dict, so a stray echo of the key is masked:

```python
def _emit_masked(secrets: dict[str, str]) -> Callable[[str], None]:
    """A print that masks every value registered so far.

    `deploy`/`rollback`/`status` can now hold one secret -- the project's
    SSH deploy key, decrypted into RAM by `release.deploy_identity` -- so
    their output goes through the same masking path as the rest of the CLI
    rather than `_emit_plain`'s empty value list.
    """

    def emit(line: str) -> None:
        print(redact(line, redaction_values(secrets)))

    return emit
```

and change the three handlers to take and forward `secrets`:

```python
def _deploy(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_deploy(
        infra_dir,
        args.version,
        node=args.node,
        skip_build=args.skip_build,
        tarball_path=args.tarball,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )


def _rollback(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_rollback(
        infra_dir,
        node=args.node,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )


def _status(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_status(
        infra_dir,
        node=args.node,
        emit=_emit_masked(secrets),
        register_secret=_secret_register_counter(secrets),
    )
```

with the three `main()` branches passing `secrets`.

- [ ] **Step 6: Run the tests — green**

Run: `python3 -m unittest tests.test_release tests.test_cli -v`
Expected: OK.

- [ ] **Step 7: README**

In `README.md`'s `## Releasing a version`, add after the "**The flow:**" code block:

```markdown
**Which key a deploy offers**, in order:

1. `$STACKBASE_SSH_IDENTITY`, if you set it — an explicit choice always wins.
2. `infra/deploy.age`, decrypted to a RAM-only file for the duration of the
   command. This is the normal path, and the one a build host uses.
3. Your `ssh-agent`, with a warning that no project key was found.

The decrypted key never touches a real disk, and `./infra/up deploy` deletes
it the moment the command ends (including on Ctrl-C).
```

- [ ] **Step 8: Commit**

```bash
git add stackbase/release.py stackbase/__main__.py README.md tests/test_release.py tests/test_cli.py
git commit -m "deploy: resolve the SSH identity from the project deploy key, in RAM only"
```

---

### Task 4: `infra/conf.d/` and the dirty-working-tree guard

**Files:**
- Modify: `flake.nix`, `templates/infra/flake.nix`, `stackbase/reconcile.py`, `stackbase/__main__.py`, `README.md`
- Create: `tests/fixtures/confd/hello.nix`, `tests/fixtures/confd/notes.txt`
- Test: `tests/test_template.py`, `tests/test_reconcile.py`, `tests/test_cli.py`

**Interfaces — Produces:**
- `lib.confdModules :: path -> [ path ]` on the stack-base flake: every `<dir>/*.nix` regular file, sorted by name; a missing directory yields `[ ]`. Consumed by the template flake and by `tests/vm.nix` (Task 6).
- `reconcile.TOOL_WRITTEN_PATHS: tuple[str, ...]` — fnmatch patterns, relative to `infra/`, that stack-base writes itself.
- `reconcile.check_infra_clean(infra_dir: Path, *, runner=subprocess.run, emit=print) -> None`
- CLI: `./infra/up --allow-dirty`.

- [ ] **Step 1: Write the failing template tests**

Create `tests/fixtures/confd/hello.nix`:

```nix
# Fixture for the conf.d mechanism (tests/test_template.py and tests/vm.nix):
# a project-wide module that leaves one observable mark on every node.
{ ... }:
{
  environment.etc."stackbase-confd-marker".text = "hello from conf.d\n";
}
```

Create `tests/fixtures/confd/notes.txt`:

```
Not a .nix file. conf.d must ignore it.
```

Add to `tests/test_template.py`:

```python
_CONFD_HELLO = (_REPO_ROOT / "tests" / "fixtures" / "confd" / "hello.nix").read_text(encoding="utf-8")

_CONFD_SECOND = """\
{ ... }:
{
  environment.etc."stackbase-confd-second".text = "second\\n";
}
"""


@unittest.skipIf(_NIX is None, "nix is not installed")
class ConfdTests(unittest.TestCase):
    """infra/conf.d/*.nix applies to EVERY node; infra/nodes/<n>/extra.nix to one."""

    def _eval(self, directory: Path) -> dict:
        apply_fn = (
            "node: {"
            " marker = node.config.environment.etc ? \"stackbase-confd-marker\";"
            " second = node.config.environment.etc ? \"stackbase-confd-second\";"
            " }"
        )
        result = subprocess.run(
            [
                _NIX or "nix", "eval", "--json",
                f"path:{directory}#nixosConfigurations.a",
                "--apply", apply_fn,
                "--override-input", "stack-base", f"path:{_REPO_ROOT}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"nix eval failed:\n{result.stderr}")
        return json.loads(result.stdout)

    def test_no_confd_directory_still_evaluates(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)

            self.assertFalse(self._eval(directory)["marker"])

    def test_every_nix_file_in_confd_is_imported(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()
            (directory / "conf.d" / "hello.nix").write_text(_CONFD_HELLO, encoding="utf-8")
            (directory / "conf.d" / "second.nix").write_text(_CONFD_SECOND, encoding="utf-8")

            facts = self._eval(directory)

            self.assertTrue(facts["marker"])
            self.assertTrue(facts["second"])

    def test_a_non_nix_file_in_confd_is_ignored(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()
            (directory / "conf.d" / "notes.txt").write_text("not nix\n", encoding="utf-8")
            (directory / "conf.d" / "README.md").write_text("# not nix\n", encoding="utf-8")

            self.assertFalse(self._eval(directory)["marker"])

    def test_an_empty_confd_directory_is_fine(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            _instantiate_template(directory)
            (directory / "conf.d").mkdir()

            self.assertFalse(self._eval(directory)["marker"])
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_template.ConfdTests -v`
Expected: FAIL on `test_every_nix_file_in_confd_is_imported` — `marker` is `false`, because nothing imports `conf.d` yet.

- [ ] **Step 3: Add `lib.confdModules` to stack-base's flake**

In `flake.nix`, inside the `outputs` attrset, next to `lib.mkNode`:

```nix
      # Every `<dir>/*.nix` as a module list, sorted by file name; a missing
      # directory yields [ ]. A project's own infra/flake.nix calls this for
      # infra/conf.d/ -- modules that apply to EVERY node, as opposed to
      # infra/nodes/<name>/extra.nix, which applies to one. It lives here
      # rather than inline in the template so the VM test can exercise the
      # very same filter the template calls.
      #
      # `type == "regular"` on purpose: a subdirectory called "foo.nix"
      # would otherwise be imported as a module and fail confusingly, and a
      # dangling symlink would break evaluation for everyone.
      lib.confdModules = dir:
        if !builtins.pathExists dir then [ ]
        else
          let entries = builtins.readDir dir;
          in map (name: dir + "/${name}")
            (builtins.filter
              (name: entries.${name} == "regular" && lib.hasSuffix ".nix" name)
              (builtins.attrNames entries));
```

- [ ] **Step 4: Call it from the template flake**

In `templates/infra/flake.nix`, inside `nodeConfig`'s `let`, and in the module list:

```nix
      nodeConfig = name:
        let
          extra = ./nodes + "/${name}/extra.nix";
        in
        stack-base.lib.mkNode {
          modules = [
            (./nodes + "/${name}/hardware-configuration.nix")
            {
              networking.hostName = name;
              stackbase.project = stack.project;
              stackbase.domain = stack.domain;
              stackbase.admins = admins;
              stackbase.deploy.keys = deployKeys;
              stackbase.app = appOptions;
            }
          ]
          # Project-wide modules: every infra/conf.d/*.nix lands on EVERY
          # node. Listed before the node's own extra.nix so list-valued
          # options concatenate project-wide-first; overriding a value set
          # here from extra.nix takes lib.mkForce, exactly as it would
          # between any two modules.
          ++ (stack-base.lib.confdModules ./conf.d)
          ++ (if builtins.pathExists extra then [ extra ] else [ ]);
        };
```

Extend the file's header comment, in the bullet list of what each node gets:

```
#   - ./conf.d/*.nix -- OPTIONAL, project-wide. Every .nix file in that
#     directory is imported on EVERY node. Use it for anything the whole
#     project needs (an extra package, a monitoring agent, a sysctl); use
#     ./nodes/<name>/extra.nix for anything specific to one server.
```

- [ ] **Step 5: Run the template tests — green**

Run: `python3 -m unittest tests.test_template -v`
Expected: OK (slow: each `nix eval` builds the module set).

- [ ] **Step 6: Write the failing guard tests**

Add to `tests/test_reconcile.py`:

```python
from stackbase.reconcile import check_infra_clean


def _porcelain(*entries: str) -> str:
    """git status --porcelain -z output: NUL-terminated `XY path` records."""
    return "".join(entry + "\0" for entry in entries)


class CheckInfraCleanTests(unittest.TestCase):
    def _runner(self, stdout: str, returncode: int = 0) -> FakeRunner:
        return FakeRunner(
            default=subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")
        )

    def test_a_clean_tree_passes(self) -> None:
        check_infra_clean(Path("/repo/infra"), runner=self._runner(""), emit=lambda _line: None)

    def test_a_modified_stack_toml_is_refused(self) -> None:
        runner = self._runner(_porcelain(" M infra/stack.toml"))

        with self.assertRaises(StackError) as ctx:
            check_infra_clean(Path("/repo/infra"), runner=runner, emit=lambda _line: None)

        message = str(ctx.exception)
        self.assertIn("stack.toml", message)
        self.assertIn("--allow-dirty", message)

    def test_an_untracked_confd_module_is_refused_and_named(self) -> None:
        runner = self._runner(_porcelain("?? infra/conf.d/hello.nix"))

        with self.assertRaises(StackError) as ctx:
            check_infra_clean(Path("/repo/infra"), runner=runner, emit=lambda _line: None)

        self.assertIn("conf.d/hello.nix", str(ctx.exception))

    def test_the_files_stack_base_writes_itself_are_not_dirty(self) -> None:
        runner = self._runner(
            _porcelain(
                " M infra/nodes/a/hardware-configuration.nix",
                " M infra/flake.lock",
                " M infra/stack.state.json",
                " M infra/known_hosts",
                "?? infra/keys/deploy.pub",
                " M infra/secrets.age",
                "?? infra/deploy.age",
            )
        )

        check_infra_clean(Path("/repo/infra"), runner=runner, emit=lambda _line: None)

    def test_changes_outside_infra_are_irrelevant(self) -> None:
        runner = self._runner(_porcelain(" M src/main.rs", "?? Cargo.lock"))

        check_infra_clean(Path("/repo/infra"), runner=runner, emit=lambda _line: None)

    def test_a_rename_source_path_is_not_parsed_as_an_entry(self) -> None:
        # `-z` emits a rename as `R  <new>` followed by a separate field
        # holding the OLD path. Parsing that second field as a record would
        # read its first two characters as a status code.
        runner = self._runner(_porcelain("R  infra/conf.d/new.nix", "infra/conf.d/old.nix"))

        with self.assertRaises(StackError) as ctx:
            check_infra_clean(Path("/repo/infra"), runner=runner, emit=lambda _line: None)

        message = str(ctx.exception)
        self.assertIn("conf.d/new.nix", message)
        self.assertNotIn("old.nix", message)

    def test_not_a_git_repository_warns_once_and_proceeds(self) -> None:
        emitted: list[str] = []

        check_infra_clean(Path("/repo/infra"), runner=self._runner("", returncode=128), emit=emitted.append)

        self.assertEqual(len(emitted), 1)
        self.assertIn("git repository", emitted[0])

    def test_a_missing_git_binary_warns_once_and_proceeds(self) -> None:
        def raise_missing(_argv, **_kwargs):
            raise FileNotFoundError("git")

        emitted: list[str] = []

        check_infra_clean(Path("/repo/infra"), runner=raise_missing, emit=emitted.append)

        self.assertEqual(len(emitted), 1)
        self.assertIn("git", emitted[0])
```

and to `tests/test_cli.py`:

```python
class AllowDirtyTests(unittest.TestCase):
    def test_up_checks_the_working_tree_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.check_infra_clean") as check_mock,
                mock.patch("stackbase.__main__.load_config"),
                mock.patch("stackbase.__main__.load_state"),
                mock.patch("stackbase.__main__.check_recipients_superset"),
                mock.patch("stackbase.__main__.load_secrets", return_value={"hostinger_token": "t"}),
                mock.patch("stackbase.__main__.observe"),
                mock.patch("stackbase.__main__.plan", return_value=[]),
                mock.patch("stackbase.__main__.local_facts"),
                mock.patch("stackbase.__main__.HostingerClient"),
            ):
                main(["--infra-dir", str(infra_dir), "up"])

            check_mock.assert_called_once()

    def test_allow_dirty_skips_the_check(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.check_infra_clean") as check_mock,
                mock.patch("stackbase.__main__.load_config"),
                mock.patch("stackbase.__main__.load_state"),
                mock.patch("stackbase.__main__.check_recipients_superset"),
                mock.patch("stackbase.__main__.load_secrets", return_value={"hostinger_token": "t"}),
                mock.patch("stackbase.__main__.observe"),
                mock.patch("stackbase.__main__.plan", return_value=[]),
                mock.patch("stackbase.__main__.local_facts"),
                mock.patch("stackbase.__main__.HostingerClient"),
            ):
                main(["--infra-dir", str(infra_dir), "up", "--allow-dirty"])

            check_mock.assert_not_called()

    def test_plan_never_checks_the_working_tree(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = Path(tmp) / "infra"
            infra_dir.mkdir()
            with (
                mock.patch("stackbase.__main__.check_infra_clean") as check_mock,
                mock.patch("stackbase.__main__.load_config"),
                mock.patch("stackbase.__main__.load_state"),
                mock.patch("stackbase.__main__.check_recipients_superset"),
                mock.patch("stackbase.__main__.load_secrets", return_value={"hostinger_token": "t"}),
                mock.patch("stackbase.__main__.observe"),
                mock.patch("stackbase.__main__.plan", return_value=[]),
                mock.patch("stackbase.__main__.local_facts"),
                mock.patch("stackbase.__main__.HostingerClient"),
            ):
                main(["--infra-dir", str(infra_dir), "up", "--plan"])

            check_mock.assert_not_called()
```

- [ ] **Step 7: Run them and watch them fail**

Run: `python3 -m unittest tests.test_reconcile.CheckInfraCleanTests tests.test_cli.AllowDirtyTests -v`
Expected: FAIL — `ImportError: cannot import name 'check_infra_clean' from 'stackbase.reconcile'`.

- [ ] **Step 8: Implement the guard**

In `stackbase/reconcile.py`, add `from collections import deque` to the imports and this section immediately after `_captured_nodes`:

```python
# --------------------------------------------------------------------------
# The working-tree guard
# --------------------------------------------------------------------------

# Paths under infra/ that stack-base WRITES ITSELF during a run. A
# modification to any of these is expected mid-run (CAPTURE_HARDWARE,
# _fetch_lock_file, save_state, pin_host_key, deploy-key init), never an
# operator's half-finished edit -- matched with fnmatch, relative to the
# infra directory.
TOOL_WRITTEN_PATHS = (
    "nodes/*/hardware-configuration.nix",
    "flake.lock",
    "stack.state.json",
    "known_hosts",
    "keys/*.pub",
    "*.age",
)

_DIRTY_SUFFIX = ".nix"
_DIRTY_NAMES = ("stack.toml",)


def check_infra_clean(
    infra_dir: Path,
    *,
    runner: Any = subprocess.run,
    emit: Callable[[str], None] = print,
) -> None:
    """Refuse to push a working tree nobody has committed.

    What `up` puts on a server is the working tree, not HEAD: `_push_config`
    rsyncs `infra/` as it is on disk. That is convenient while iterating and
    dangerous afterwards -- an uncommitted `conf.d/*.nix` or a locally-edited
    `stack.toml` produces a server nobody else can reproduce, and the next
    teammate's `up` silently reverts it.

    Only files that change what a node BUILDS are considered: `*.nix`
    anywhere under infra/, and `stack.toml`. Everything stack-base writes
    itself (`TOOL_WRITTEN_PATHS`) is exempt, because a run legitimately
    modifies those while it is in flight.

    Not a git checkout at all (or no git installed) -- warn once and
    proceed: stack-base works fine without version control, it just cannot
    make this particular promise.
    """
    repo_dir = infra_dir.parent
    try:
        result = runner(
            ["git", "-C", str(repo_dir), "status", "--porcelain", "-z", "--", str(infra_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        emit("! git was not found -- skipping the check for uncommitted changes under infra/")
        return

    if result.returncode != 0:
        emit("! infra/ is not inside a git repository -- skipping the check for uncommitted changes")
        return

    offenders = sorted(_dirty_infra_paths(result.stdout or "", repo_dir=repo_dir, infra_dir=infra_dir))
    if not offenders:
        return

    raise StackError(
        f"infra/ has uncommitted changes that would be pushed to the servers: {', '.join(offenders)}",
        "what `up` pushes is your WORKING TREE, not the last commit -- commit them first so the "
        "next person's run reproduces this server, or re-run with --allow-dirty",
    )


def _dirty_infra_paths(porcelain_z: str, *, repo_dir: Path, infra_dir: Path) -> set[str]:
    """Paths from `git status --porcelain -z` that stack-base did not write itself.

    `-z` output is NUL-separated `XY <path>` records with NO quoting or
    escaping (unlike the default, where a path with a space or a non-ASCII
    byte comes back quoted). A rename or copy record (`R`/`C`) is followed
    by ONE extra field holding the source path -- consumed here, so its
    first two characters are never mistaken for a status code.
    """
    fields = deque(field for field in porcelain_z.split("\0") if field)
    dirty: set[str] = set()
    while fields:
        record = fields.popleft()
        status, path = record[:2], record[3:]
        if status[:1] in ("R", "C") and fields:
            fields.popleft()  # the rename/copy SOURCE path
        if not path:
            continue
        name = path.rsplit("/", 1)[-1]
        if not (name.endswith(_DIRTY_SUFFIX) or name in _DIRTY_NAMES):
            continue
        try:
            relative = (repo_dir / path).relative_to(infra_dir).as_posix()
        except ValueError:
            continue  # not under infra/ after all
        if not any(fnmatch.fnmatch(relative, pattern) for pattern in TOOL_WRITTEN_PATHS):
            dirty.add(relative)
    return dirty
```

- [ ] **Step 9: Wire `--allow-dirty`**

In `stackbase/__main__.py`: add the flag,

```python
    up.add_argument(
        "--allow-dirty",
        action="store_true",
        help="push infra/ even with uncommitted *.nix or stack.toml changes",
    )
```

add `check_infra_clean` to the `from stackbase.reconcile import (...)` list, and call it in `_up` right after `check_recipients_superset`:

```python
    # `--plan` changes nothing, so it never has to be clean. Otherwise:
    # what gets pushed is the working tree, so refuse to push one nobody
    # has committed unless the operator says so explicitly.
    if not args.plan and not args.allow_dirty:
        check_infra_clean(infra_dir)
```

- [ ] **Step 10: Run the tests — green**

Run: `python3 -m unittest tests.test_reconcile tests.test_cli -v`
Expected: OK.

Run: `python3 -m unittest discover -s tests`
Expected: OK.

- [ ] **Step 11: README**

Add a subsection to `## Everyday things`, after "**Open a shell on a server.**":

```markdown
**Project-wide NixOS settings.** Anything every server should have goes in
`infra/conf.d/<whatever>.nix` — one file or many, all of them imported on
every node:

```nix
# infra/conf.d/monitoring.nix
{ pkgs, ... }:
{
  environment.systemPackages = [ pkgs.htop ];
}
```

`infra/nodes/<name>/extra.nix` stays what it always was: settings for **one**
server. A `conf.d` file and an `extra.nix` that both set the same option
conflict, the same way any two NixOS modules would — use `lib.mkForce` in
`extra.nix` to win.

**`up` pushes your working tree, not your last commit.** If `infra/` has an
uncommitted or untracked `*.nix` file or a modified `stack.toml`, `./infra/up`
stops and names them: a server built from something nobody else has would be
silently reverted by the next teammate's run. Commit, or pass `--allow-dirty`
when you are deliberately trying something out. The files stack-base writes
itself (`stack.state.json`, `known_hosts`, `flake.lock`, `nodes/*/hardware-configuration.nix`,
`keys/*.pub`, `*.age`) never trigger it.
```

In `## When it fails`, add:

```markdown
| `infra/ has uncommitted changes that would be pushed` | Commit them, or re-run with `--allow-dirty` if you are deliberately testing |
```

In `## What the files are`, add:

```markdown
| `conf.d/*.nix` | Optional, yours: NixOS settings applied to every server |
```

- [ ] **Step 12: Commit**

```bash
git add flake.nix templates/infra/flake.nix stackbase/reconcile.py stackbase/__main__.py \
        README.md tests/fixtures/confd tests/test_template.py tests/test_reconcile.py tests/test_cli.py
git commit -m "conf.d: project-wide NixOS modules, and refuse to push an uncommitted infra/"
```

---

### Task 5: Backups — module, credentials, `backup-now`

**Files:**
- Create: `nixos/backups.nix`, `stackbase/backups.py`, `tests/test_backups.py`
- Modify: `flake.nix`, `templates/infra/flake.nix`, `templates/infra/stack.toml.example`, `stackbase/config.py`, `stackbase/reconcile.py`, `stackbase/steps.py`, `stackbase/__main__.py`, `README.md`
- Test: `tests/test_backups.py`, `tests/test_config.py`, `tests/test_reconcile.py`, `tests/test_template.py`, `tests/test_cli.py`

**Interfaces — Consumes:** `reconcile.REMOTE_CERT_DIR` (`/var/lib/stackbase`), `reconcile.SSH_USER` (`root`), `Ssh.run`/`Ssh.run_stream`.

**Interfaces — Produces:**
- NixOS options `stackbase.backups.{enable,bucket,retentionDays,extraPaths,recipientsFile,onCalendar}`, unit `stackbase-backup.service` + `.timer`, and the `stackbase-backup` / `stackbase-backup-ls` commands on the node.
- `config.BackupsConfig(bucket: str | None, retention_days: int | None, extra_paths: list[str] | None, on_calendar: str | None)` on `StackConfig.backups`.
- `config.NodeState.backup_env_sha: str | None`.
- `backups.BACKUP_ENV_PATH = "/var/lib/stackbase/backup.env"`
- `backups.backup_env_content(secrets: dict[str, str]) -> str | None`
- `backups.backup_env_digest(content: str) -> str`
- `backups.run_backup_now(infra_dir, *, node=None, runner=subprocess.run, popen=subprocess.Popen, emit=print) -> None`
- `reconcile.Action.ENSURE_BACKUP_ENV`, `Local.backup_env_sha`, `steps._ensure_backup_env`.
- CLI: `./infra/up backup-now [--node NAME]`.

- [ ] **Step 1: Write the failing Python tests**

Create `tests/test_backups.py`:

```python
"""Tests for stackbase.backups: the rclone credentials file and `backup-now`."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from stackbase.backups import (
    BACKUP_ENV_PATH,
    backup_env_content,
    backup_env_digest,
    run_backup_now,
)
from stackbase.errors import StackError
from tests.fakes import FakePopen, FakeRunner

_STACK_TOML = """\
project    = "acme"
domain     = "acme.example.com"
owner      = "matt"
datacenter = "kul"
plan       = "KVM 1"
admins     = ["matt"]

[backups]
bucket = "acme-backups"

[nodes.a]
role   = "primary"
vps_id = 1

[nodes.b]
role = "replica"
vps_id = 2
"""

_FULL_SECRETS = {
    "r2_access_key_id": "AKIAEXAMPLE",
    "r2_secret_access_key": "s3cr3t-example",
    "r2_endpoint": "https://abc123.r2.cloudflarestorage.com",
}


def _infra(tmp: Path) -> Path:
    infra_dir = tmp / "infra"
    (infra_dir / "keys").mkdir(parents=True)
    (infra_dir / "stack.toml").write_text(_STACK_TOML, encoding="utf-8")
    (infra_dir / "keys" / "matt.pub").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTemplateEval matt@laptop\n", encoding="utf-8"
    )
    (infra_dir / "stack.state.json").write_text(
        json.dumps({"version": 1, "nodes": {"a": {"ipv4": "1.2.3.4"}, "b": {"ipv4": "5.6.7.8"}}}),
        encoding="utf-8",
    )
    (infra_dir / "known_hosts").write_text("", encoding="utf-8")
    return infra_dir


class BackupEnvContentTests(unittest.TestCase):
    def test_all_three_values_produce_the_rclone_env_config(self) -> None:
        self.assertEqual(
            backup_env_content(_FULL_SECRETS),
            "RCLONE_CONFIG_BACKUP_TYPE=s3\n"
            "RCLONE_CONFIG_BACKUP_PROVIDER=Cloudflare\n"
            "RCLONE_CONFIG_BACKUP_ACCESS_KEY_ID=AKIAEXAMPLE\n"
            "RCLONE_CONFIG_BACKUP_SECRET_ACCESS_KEY=s3cr3t-example\n"
            "RCLONE_CONFIG_BACKUP_ENDPOINT=https://abc123.r2.cloudflarestorage.com\n",
        )

    def test_a_missing_value_means_no_file_at_all(self) -> None:
        for key in _FULL_SECRETS:
            partial = {k: v for k, v in _FULL_SECRETS.items() if k != key}
            self.assertIsNone(backup_env_content(partial), key)

    def test_an_empty_value_means_no_file_at_all(self) -> None:
        self.assertIsNone(backup_env_content({**_FULL_SECRETS, "r2_endpoint": ""}))

    def test_no_r2_keys_at_all_means_no_file(self) -> None:
        self.assertIsNone(backup_env_content({"hostinger_token": "tok"}))

    def test_a_newline_in_a_value_is_refused_by_name_never_by_value(self) -> None:
        with self.assertRaises(StackError) as ctx:
            backup_env_content({**_FULL_SECRETS, "r2_access_key_id": "AKIA\nEVIL=1"})

        message = str(ctx.exception)
        self.assertIn("r2_access_key_id", message)
        self.assertNotIn("EVIL", message)

    def test_the_digest_is_stable_and_content_addressed(self) -> None:
        content = backup_env_content(_FULL_SECRETS)
        self.assertEqual(backup_env_digest(content), backup_env_digest(content))
        self.assertNotEqual(
            backup_env_digest(content),
            backup_env_digest(backup_env_content({**_FULL_SECRETS, "r2_endpoint": "https://other/"})),
        )


class RunBackupNowTests(unittest.TestCase):
    def test_it_starts_the_unit_then_lists_the_bucket_on_every_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            for _ in range(4):
                popen.script(returncode=0, output="ok\n")

            run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            commands = [call["argv"][-1] for call in popen.calls]
            self.assertEqual(
                commands,
                [
                    "systemctl start stackbase-backup.service",
                    "stackbase-backup-ls",
                    "systemctl start stackbase-backup.service",
                    "stackbase-backup-ls",
                ],
            )
            self.assertTrue(all("root@" in " ".join(call["argv"]) for call in popen.calls))

    def test_a_failed_unit_names_the_journal_command(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=1, output="Job for stackbase-backup.service failed\n")

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("journalctl -u stackbase-backup", str(ctx.exception))

    def test_node_restricts_the_run_to_one_node(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            popen.script(returncode=0, output="ok\n")

            run_backup_now(infra_dir, node="b", runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertEqual(len(popen.calls), 2)
            self.assertTrue(all("5.6.7.8" in " ".join(call["argv"]) for call in popen.calls))

    def test_an_unknown_node_lists_the_known_ones(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, node="zz", runner=FakeRunner(), popen=FakePopen(), emit=lambda _l: None)

            self.assertIn("a, b", str(ctx.exception))

    def test_a_project_with_no_bucket_says_so_before_any_ssh(self) -> None:
        with TemporaryDirectory() as tmp:
            infra_dir = _infra(Path(tmp))
            (infra_dir / "stack.toml").write_text(
                _STACK_TOML.replace('[backups]\nbucket = "acme-backups"\n', ""), encoding="utf-8"
            )
            popen = FakePopen()

            with self.assertRaises(StackError) as ctx:
                run_backup_now(infra_dir, runner=FakeRunner(), popen=popen, emit=lambda _line: None)

            self.assertIn("[backups]", str(ctx.exception))
            self.assertEqual(popen.calls, [])
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_backups -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'stackbase.backups'`.

- [ ] **Step 3: Write `stackbase/backups.py`**

```python
"""Off-box backups: the node's rclone credentials, and `backup-now`.

The backup itself runs entirely on the node (`nixos/backups.nix`:
`pg_dump`/`tar` -> `zstd` -> `age` -> `rclone`, on a timer). This module is
the laptop side of it: it renders the one credentials file the node needs
(`/var/lib/stackbase/backup.env`, pushed by the ENSURE_BACKUP_ENV step) and
drives an on-demand run over SSH.

The credentials come from `secrets.age`'s `r2_access_key_id`,
`r2_secret_access_key` and `r2_endpoint`, and are rendered in rclone's
env-config form -- `RCLONE_CONFIG_<REMOTE>_<SETTING>` -- so the remote
named "backup" exists without any rclone.conf, and nothing sensitive is
ever in the Nix store or in a unit file.

Unlike `release.py`, this talks to the node as `root` through stack-base's
own SSH path, not through the restricted `deploy` door: starting a systemd
unit is not one of that door's six words, and never should be.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Callable

from stackbase.config import load_config, load_state
from stackbase.errors import StackError
from stackbase.reconcile import SSH_USER
from stackbase.ssh import Ssh

BACKUP_ENV_PATH = "/var/lib/stackbase/backup.env"

BACKUP_UNIT = "stackbase-backup.service"

# secrets.age keys -> rclone env-config variables, in the order they are
# written. The remote is literally called "backup", which is what
# nixos/backups.nix's own `backup:<bucket>/...` paths refer to.
_R2_KEYS: tuple[tuple[str, str], ...] = (
    ("r2_access_key_id", "RCLONE_CONFIG_BACKUP_ACCESS_KEY_ID"),
    ("r2_secret_access_key", "RCLONE_CONFIG_BACKUP_SECRET_ACCESS_KEY"),
    ("r2_endpoint", "RCLONE_CONFIG_BACKUP_ENDPOINT"),
)


def backup_env_content(secrets: dict[str, str]) -> str | None:
    """Render `/var/lib/stackbase/backup.env`, or `None` if R2 isn't configured.

    All three values or none: a half-filled credentials file would let the
    unit start and fail every night. Absent, no step is planned and nothing
    on the node is removed -- same contract as `app_env`.

    A newline in any value would smuggle an extra `KEY=value` line into a
    root-owned EnvironmentFile, so it is refused -- naming the KEY, never
    any part of the value (the global "secrets are never echoed" rule).
    """
    values = []
    for key, _variable in _R2_KEYS:
        value = secrets.get(key)
        if not value:
            return None
        if "\n" in value or "\r" in value:
            raise StackError(
                f"infra/secrets.age's '{key}' contains a newline",
                f"R2 credentials must be single-line values -- fix it with "
                f"`./infra/up secrets set {key}` and run `up` again",
            )
        values.append(value)

    lines = ["RCLONE_CONFIG_BACKUP_TYPE=s3", "RCLONE_CONFIG_BACKUP_PROVIDER=Cloudflare"]
    lines.extend(f"{variable}={value}" for (_key, variable), value in zip(_R2_KEYS, values))
    return "\n".join(lines) + "\n"


def backup_env_digest(content: str) -> str:
    """sha256 hex digest of an already-rendered backup.env."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def run_backup_now(
    infra_dir: Path,
    *,
    node: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> None:
    """Run the backup unit on every selected node now, then list the bucket.

    Streams both commands so a multi-minute dump does not look like a hang.
    Stops at the first node whose unit fails -- an unnoticed failing backup
    is the whole thing this command exists to prevent.
    """
    cfg = load_config(infra_dir)
    state = load_state(infra_dir)

    if not cfg.backups.bucket:
        raise StackError(
            "this project has no backup bucket",
            'add a [backups] section to stack.toml with bucket = "<name>" and run `./infra/up` first',
        )

    if node is None:
        names = list(cfg.nodes)
    elif node in cfg.nodes:
        names = [node]
    else:
        known = ", ".join(cfg.nodes) or "none"
        raise StackError(f"there is no node called '{node}' in stack.toml", f"known nodes: {known}")

    for name in names:
        node_state = state.nodes.get(name)
        ipv4 = node_state.ipv4 if node_state else None
        if not ipv4:
            raise StackError(
                f"stack-base does not know an address for node '{name}' yet",
                "run `up` first -- the address is recorded once the server is running",
            )
        ssh = Ssh(infra_dir, ipv4, user=SSH_USER, runner=runner, popen=popen)

        emit(f"→ node {name}: running {BACKUP_UNIT}")
        returncode, tail = ssh.run_stream(f"systemctl start {BACKUP_UNIT}", emit=emit, check=False)
        if returncode != 0:
            raise StackError(
                f"the backup unit failed on node {name} (exit {returncode})",
                "\n".join(tail).strip()
                or f"read the node's own log: ./infra/up ssh {name} -- journalctl -u stackbase-backup -n 50",
            )

        emit(f"→ node {name}: contents of backup:{cfg.backups.bucket}")
        returncode, tail = ssh.run_stream("stackbase-backup-ls", emit=emit, check=False)
        if returncode != 0:
            raise StackError(
                f"could not list the backup bucket from node {name} (exit {returncode})",
                "\n".join(tail).strip() or "check the node's /var/lib/stackbase/backup.env and rclone access",
            )
```

- [ ] **Step 4: `[backups]` in stack.toml**

In `stackbase/config.py`, add the regexes next to `_APP_BINARY_RE`:

```python
# The [backups] table. `bucket` is an R2/S3 bucket name (or, in the VM
# test, a local directory) -- conservative on purpose: it is interpolated
# into an rclone remote path on the node. `on_calendar` is a 24h HH:MM,
# expanded to "*-*-* HH:MM:00" by the module.
_BUCKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,127}$")
_ON_CALENDAR_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
```

the dataclass next to `AppConfig`:

```python
@dataclass(frozen=True)
class BackupsConfig:
    """The optional `[backups]` table -- overrides for nixos/backups.nix's
    own `stackbase.backups.*` defaults. Every field is `None` when the
    project never set it, so an unset field keeps the module's default.
    No bucket at all means backups are off (the module's `enable` defaults
    to "a bucket is set").
    """

    bucket: str | None = None
    retention_days: int | None = None
    extra_paths: list[str] | None = None
    on_calendar: str | None = None
```

the `StackConfig` field:

```python
    backups: BackupsConfig = field(default_factory=BackupsConfig)
```

(and `backups=_parse_backups(data, toml_path)` in `load_config`'s return), plus the parser next to `_parse_app`:

```python
def _parse_backups(data: dict[str, Any], toml_path: Path) -> BackupsConfig:
    raw = data.get("backups")
    if raw is None:
        return BackupsConfig()
    if not isinstance(raw, dict):
        raise StackError(
            f"{toml_path} has an invalid '[backups]' table",
            '[backups] must be a table, e.g. [backups]\\nbucket = "acme-backups"',
        )
    _reject_unknown_keys(raw, BackupsConfig, f"{toml_path} [backups]")

    bucket = raw.get("bucket")
    if bucket is not None and (not isinstance(bucket, str) or not _BUCKET_RE.match(bucket)):
        raise StackError(
            f"{toml_path} has an invalid [backups].bucket {bucket!r}",
            "bucket must match ^[A-Za-z0-9][A-Za-z0-9._/-]{1,127}$ -- the R2 bucket's name",
        )

    retention_days = _optional_ranged_int(raw, "retention_days", 1, 3650, toml_path)

    extra_paths = raw.get("extra_paths")
    if extra_paths is not None:
        if not isinstance(extra_paths, list) or not all(isinstance(item, str) for item in extra_paths):
            raise StackError(
                f"{toml_path} has an invalid [backups].extra_paths",
                'extra_paths must be a list of absolute paths, e.g. ["/var/lib/acme/uploads"]',
            )
        for item in extra_paths:
            # Interpolated into a root shell command on the node. The
            # module quotes it too; this is the first of those two layers.
            if not item.startswith("/") or any(ch.isspace() for ch in item) or '"' in item or "'" in item:
                raise StackError(
                    f"{toml_path} has an invalid [backups].extra_paths entry {item!r}",
                    "each entry must be an absolute path with no whitespace or quotes",
                )
        extra_paths = list(extra_paths)

    on_calendar = raw.get("on_calendar")
    if on_calendar is not None and (not isinstance(on_calendar, str) or not _ON_CALENDAR_RE.match(on_calendar)):
        raise StackError(
            f"{toml_path} has an invalid [backups].on_calendar {on_calendar!r}",
            'on_calendar must be a 24-hour UTC time like "03:00"',
        )

    return BackupsConfig(
        bucket=bucket, retention_days=retention_days, extra_paths=extra_paths, on_calendar=on_calendar
    )
```

and the state field on `NodeState`:

```python
    # sha256 of the backup.env content (from secrets.age's r2_* keys) most
    # recently pushed to this node. None until the first push.
    backup_env_sha: str | None = None
```

Add to `tests/test_config.py`, in the same shape as the existing `[app]` tests: a valid `[backups]` round-trip (`bucket`/`retention_days`/`extra_paths`/`on_calendar` all land on `cfg.backups`), an absent table yielding all-`None`, an unknown key inside `[backups]` rejected, `retention_days = 0` rejected, `extra_paths = ["relative/path"]` rejected, `extra_paths = ["/a b"]` rejected, and `on_calendar = "25:00"` rejected.

- [ ] **Step 5: The ENSURE_BACKUP_ENV step**

In `stackbase/reconcile.py`:

```python
    ENSURE_APP_ENV = "ensure_app_env"
    ENSURE_BACKUP_ENV = "ensure_backup_env"
```

```python
    Action.ENSURE_BACKUP_ENV: "updating the backup credentials on the server",
```

on `Local`:

```python
    # sha256 of the rendered backup.env (from secrets.age's r2_* keys), or
    # None when the project has no R2 credentials. Compared against each
    # node's recorded `NodeState.backup_env_sha` -- see `_needs_backup_env`.
    backup_env_sha: str | None = None
```

in `local_facts`:

```python
    backup_env = backup_env_content(secrets)
    return Local(
        ...,
        backup_env_sha=backup_env_digest(backup_env) if backup_env else None,
    )
```

in `plan()`, immediately after the `_needs_app_env` block inside the per-node loop:

```python
        # Same placement and contract as ENSURE_APP_ENV: after REBUILD (the
        # /var/lib/stackbase directory and the backup unit only exist once
        # the node has rebuilt), and absent r2_* secrets plan nothing and
        # remove nothing.
        if _needs_backup_env(state, observed, name):
            steps.append(Step(Action.ENSURE_BACKUP_ENV, name))
```

and:

```python
def _needs_backup_env(state: StackState, observed: Observed, name: str) -> bool:
    desired = observed.local.backup_env_sha
    if desired is None:
        return False
    node_state = state.nodes.get(name) or NodeState()
    return node_state.backup_env_sha != desired
```

with `from stackbase.backups import backup_env_content, backup_env_digest` — **imported inside `local_facts`**, not at module scope, because `stackbase/backups.py` imports `SSH_USER` from this module (the same deferred-import trick `apply()` already uses for `stackbase.steps`).

In `stackbase/steps.py`, add the executor after `_ensure_app_env`:

```python
def _ensure_backup_env(ctx: Context, step: Step) -> str:
    """Push the rclone credentials to /var/lib/stackbase/backup.env, 0600 root:root.

    Same model as `_ensure_app_env`: the content travels over an ssh stdin
    pipe only -- never a local file, never an argv -- into a temp name
    created with its final owner/mode BEFORE any content is written, then
    `mv -f`d into place. Root-only, unlike app.env: the app has no business
    reading the bucket's credentials, and neither has `deploy`.

    Nothing is restarted: the backup unit reads this file when the timer
    next fires (or when `./infra/up backup-now` runs it).
    """
    node = _node(step)
    content = backup_env_content(ctx.secrets)
    if not content:
        raise StackError(
            "infra/secrets.age has no complete set of R2 credentials to push",
            "this is a bug in stack-base -- please report it",
        )

    ssh = ctx.ssh(node)
    tmp_path = _cert_path("backup.env.new")
    final_path = _cert_path("backup.env")
    ssh.run(f"set -eu; install -d -m 0750 {shlex.quote(REMOTE_CERT_DIR)}")
    ssh.run(f"set -eu; install -m 0600 -o root -g root /dev/null {tmp_path}")
    ssh.run(f"set -eu; cat > {tmp_path}", input=content)
    ssh.run(f"set -eu; mv -f {tmp_path} {final_path}")

    ctx.node_state(node).backup_env_sha = backup_env_digest(content)
    return f"node {node}: backup credentials updated"
```

with `from stackbase.backups import backup_env_content, backup_env_digest` at the top of `steps.py` (no cycle: `steps` already imports `reconcile`), `Action.ENSURE_BACKUP_ENV: _ensure_backup_env` added to `_EXECUTORS`, and `Action.ENSURE_BACKUP_ENV` added to the `from stackbase.reconcile import (...)` list.

Add to `tests/test_reconcile.py` two new classes, modelled line for line on the ones already there:

- `BackupEnvPlanTests`, alongside `AppEnvPlanTests` (line ~342): absent r2 secrets plan no step; all three present with no recorded sha plans `Step(Action.ENSURE_BACKUP_ENV, name)` for every node, positioned after that node's `REBUILD`; a matching recorded sha plans nothing; a changed `r2_endpoint` plans it again.
- `EnsureBackupEnvTests`, alongside `EnsureAppEnvTests` (line ~1791): the pushed content appears only in an `input=` kwarg and in no argv; `install -m 0600 -o root -g root /dev/null` runs before any `cat >`; `backup_env_sha` is recorded only after the final `mv -f`, so a failing `mv` leaves state unchanged and the step retries on the next `up`.

- [ ] **Step 6: `nixos/backups.nix`**

```nix
# Off-box, age-encrypted backups for a stackbase node: the project's
# Postgres database plus any extra directories, streamed straight to an
# S3-compatible bucket (Cloudflare R2 by default).
#
# Modelled on hanskraft's own pg-backup/backup-uploads units
# (nixos/service.nix there), made generic and made to stream: nothing is
# ever written to a temp file, so a dump's plaintext never touches the
# node's disk at all.
#
#   pg_dump | zstd | age -R <recipients> | rclone rcat backup:<bucket>/db/...
#   tar     | zstd | age -R <recipients> | rclone rcat backup:<bucket>/files/...
#
# Reads `stackbase.project` from base.nix. Credentials come from
# /var/lib/stackbase/backup.env (0600 root:root), written by `./infra/up`
# from secrets.age's r2_* keys -- never from the Nix store, which is
# world-readable. Recipients come from the project's own
# infra/age-recipients.txt as pushed to /etc/nixos/stack/, so restoring a
# backup needs an age identity that never existed on the server.
{ config, lib, pkgs, ... }:

let
  cfg = config.stackbase;
  backups = cfg.backups;

  backupEnvFile = "/var/lib/stackbase/backup.env";

  backupScript = pkgs.writeShellApplication {
    name = "stackbase-backup";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnutar
      pkgs.zstd
      pkgs.age
      # Two of the three recipients on a typical project are YubiKey
      # identities (age1yubikey1...); plain age shells out to this plugin
      # for those lines, so it has to be on PATH even to ENCRYPT.
      pkgs.age-plugin-yubikey
      pkgs.rclone
      pkgs.util-linux
      config.services.postgresql.package
    ];
    text = ''
      if [ -z "''${RCLONE_CONFIG_BACKUP_TYPE:-}" ]; then
        echo "stackbase-backup: no credentials in ${backupEnvFile} -- add r2_access_key_id, r2_secret_access_key and r2_endpoint to infra/secrets.age and run ./infra/up" >&2
        exit 1
      fi

      BUCKET=${lib.escapeShellArg backups.bucket}
      RECIPIENTS=${lib.escapeShellArg backups.recipientsFile}
      STAMP=$(date -u +%Y%m%dT%H%M%SZ)

      if [ ! -r "$RECIPIENTS" ]; then
        echo "stackbase-backup: no age recipients file at $RECIPIENTS -- refusing to write a backup nobody could decrypt" >&2
        exit 1
      fi

      prune_prefix() {
        local prefix="$1"
        # `rclone delete` on a prefix that does not exist yet is an error,
        # and a first-ever run legitimately has no files/ prefix.
        if rclone lsf "backup:$BUCKET/$prefix/" >/dev/null 2>&1; then
          rclone delete --min-age ${toString backups.retentionDays}d "backup:$BUCKET/$prefix/"
        fi
      }

      echo "→ ${cfg.project} database → backup:$BUCKET/db/${cfg.project}_$STAMP.sql.zst.age"
      runuser -u postgres -- pg_dump ${lib.escapeShellArg cfg.project} \
        | zstd -3 -q \
        | age -R "$RECIPIENTS" \
        | rclone rcat "backup:$BUCKET/db/${cfg.project}_$STAMP.sql.zst.age"

      for path in ${lib.escapeShellArgs backups.extraPaths}; do
        if [ ! -d "$path" ]; then
          echo "i no directory at $path -- skipping"
          continue
        fi
        base=$(basename "$path")
        echo "→ $path → backup:$BUCKET/files/''${base}_$STAMP.tar.zst.age"
        tar -C "$path" -cf - . \
          | zstd -3 -q \
          | age -R "$RECIPIENTS" \
          | rclone rcat "backup:$BUCKET/files/''${base}_$STAMP.tar.zst.age"
      done

      echo "→ pruning anything older than ${toString backups.retentionDays} days"
      prune_prefix db
      prune_prefix files
      echo "✓ backup complete"
    '';
  };

  # Listing the bucket needs the same credentials the unit gets from its
  # EnvironmentFile -- `./infra/up backup-now` runs this as root right
  # after the unit, so an operator sees what actually landed.
  backupLsScript = pkgs.writeShellApplication {
    name = "stackbase-backup-ls";
    runtimeInputs = [ pkgs.coreutils pkgs.rclone ];
    text = ''
      if [ ! -r ${backupEnvFile} ]; then
        echo "stackbase-backup-ls: no credentials in ${backupEnvFile}" >&2
        exit 1
      fi
      set -a
      # shellcheck source=/dev/null
      source ${backupEnvFile}
      set +a
      rclone lsl ${lib.escapeShellArg "backup:${backups.bucket}"}
    '';
  };
in
{
  options.stackbase.backups = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = backups.bucket != "";
      defaultText = lib.literalExpression ''config.stackbase.backups.bucket != ""'';
      description = ''
        Whether to run nightly off-box backups. Defaults to "a bucket is
        configured", so a project turns backups on by naming a bucket in
        stack.toml's [backups] table and nothing else.
      '';
    };

    bucket = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = ''
        The destination bucket, used as `backup:<bucket>/...` against an
        rclone remote called "backup" that is configured entirely from
        environment variables in ${backupEnvFile}. With
        `RCLONE_CONFIG_BACKUP_TYPE=local` this is a directory path instead,
        which is how the VM test exercises the whole pipeline.
      '';
    };

    retentionDays = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = ''
        Objects older than this are deleted from both the `db/` and
        `files/` prefixes at the end of every run.
      '';
    };

    extraPaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/var/lib/acme/uploads" ];
      description = ''
        Directories to archive alongside the database, each as
        `files/<basename>_<stamp>.tar.zst.age`. A path that does not exist
        is skipped with a note, not an error -- a fresh node legitimately
        has no uploads directory yet.
      '';
    };

    recipientsFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/nixos/stack/age-recipients.txt";
      description = ''
        The age recipients every backup is encrypted to, as a path ON THE
        NODE -- deliberately a runtime path and not a store path, so the
        project's own infra/age-recipients.txt (pushed to /etc/nixos/stack
        by PUSH_CONFIG) is what governs who can restore. No private key
        that can decrypt a backup ever exists on the server.
      '';
    };

    onCalendar = lib.mkOption {
      type = lib.types.str;
      default = "03:00";
      description = ''
        24-hour UTC time of the nightly run, expanded into the timer's
        `OnCalendar` as `*-*-* <value>:00`. The timer is `Persistent`, so a
        node that was off at that time backs up shortly after it boots.
      '';
    };
  };

  config = lib.mkIf backups.enable {
    assertions = [
      {
        assertion = backups.bucket != "";
        message = "stackbase.backups.enable is on but stackbase.backups.bucket is empty -- set a bucket in stack.toml's [backups] table";
      }
    ];

    systemd.services.stackbase-backup = {
      description = "Off-box age-encrypted backup for ${cfg.project}";
      after = [ "postgresql.service" "network-online.target" ];
      wants = [ "network-online.target" ];
      requires = [ "postgresql.service" ];
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        # "-": the node is rebuilt before `up` has ever pushed credentials,
        # and a unit that refuses to even start would hide the script's own
        # much clearer message about what is missing.
        EnvironmentFile = "-${backupEnvFile}";
        ExecStart = "${backupScript}/bin/stackbase-backup";
      };
    };

    systemd.timers.stackbase-backup = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "*-*-* ${backups.onCalendar}:00";
        Persistent = true;
      };
    };

    environment.systemPackages = [ backupScript backupLsScript ];
  };
}
```

In `flake.nix`: `nixosModules.backups = import ./nixos/backups.nix;` and `self.nixosModules.backups` appended to `baseModules` (every server gets the module; `enable` defaults to false until a bucket is named).

- [ ] **Step 7: Template flake + example**

In `templates/infra/flake.nix`, next to `appOptions`:

```nix
      # The optional [backups] table in stack.toml -> nixos/backups.nix's
      # stackbase.backups.* options. Naming a bucket is all it takes to
      # turn nightly backups on; every other field keeps the module's own
      # default when stack.toml does not set it.
      backupsConfig = stack.backups or { };
      backupsOptions =
        (if backupsConfig ? bucket then { bucket = backupsConfig.bucket; } else { })
        // (if backupsConfig ? retention_days then { retentionDays = backupsConfig.retention_days; } else { })
        // (if backupsConfig ? extra_paths then { extraPaths = backupsConfig.extra_paths; } else { })
        // (if backupsConfig ? on_calendar then { onCalendar = backupsConfig.on_calendar; } else { });
```

and `stackbase.backups = backupsOptions;` in the inline module, right after `stackbase.app = appOptions;`.

In `templates/infra/stack.toml.example`, append:

```toml
# Optional. Nightly off-box backups: the project's database, plus any
# directories listed here, encrypted to infra/age-recipients.txt and
# uploaded to Cloudflare R2. Naming a bucket is what turns them on; the
# credentials live in secrets.age as r2_access_key_id,
# r2_secret_access_key and r2_endpoint. retention_days defaults to 30 and
# on_calendar to "03:00" (UTC).
# [backups]
# bucket = "acme-backups"
# retention_days = 30
# extra_paths = ["/var/lib/acme/uploads"]
# on_calendar = "03:00"
```

Add to `tests/test_template.py`: a `nix eval` test that a `[backups]` table in stack.toml lands on `stackbase.backups.{bucket,retentionDays,extraPaths,onCalendar}` and switches `stackbase.backups.enable` to `true`, and one that no `[backups]` table leaves `enable` at `false`. Extend `test_the_example_stack_toml_parses_and_covers_the_schema` so the commented-out `[backups]` block is asserted to be *absent* from the parsed TOML (it is a comment) while the text itself mentions `bucket`.

- [ ] **Step 8: Wire `backup-now`**

In `stackbase/__main__.py`:

```python
    backup_now_p = commands.add_parser("backup-now", help="run the backup on every node now and list the bucket")
    backup_now_p.add_argument("--node", help="restrict to one node")
    backup_now_p.add_argument("--debug", action="store_true", help="print the full traceback on failure")
```

```python
        elif args.command == "backup-now":
            _backup_now(args, infra_dir, secrets)
```

```python
def _backup_now(args: argparse.Namespace, infra_dir: Path, secrets: dict[str, str]) -> None:
    run_backup_now(infra_dir, node=args.node, emit=_emit_masked(secrets))
```

with `from stackbase.backups import run_backup_now` added to the imports. Add a wiring test to `tests/test_cli.py` in the same shape as `DeployKeyCLIWiringTests`.

- [ ] **Step 9: Run the Python suite**

Run: `python3 -m unittest tests.test_backups tests.test_config tests.test_reconcile tests.test_cli -v`
Expected: OK.

Run: `nix flake check --no-build 2>&1 | tail -20`
Expected: no evaluation error (the VM checks are still built in Task 6; `--no-build` keeps this step to evaluation).

- [ ] **Step 10: README**

Add a `## Backups` section immediately after `## The app's environment (app_env)`:

```markdown
## Backups

Every server backs itself up nightly, off-box and encrypted, as soon as you
name a bucket:

```toml
# infra/stack.toml
[backups]
bucket = "acme-backups"
retention_days = 30
extra_paths = ["/var/lib/acme/uploads"]
```

```bash
R2_ACCESS_KEY_ID=<paste here>
R2_SECRET_ACCESS_KEY=<paste here>
R2_ENDPOINT=<paste here, e.g. https://<account>.r2.cloudflarestorage.com>
printf '%s' "$R2_ACCESS_KEY_ID"     | ./infra/up secrets set r2_access_key_id
printf '%s' "$R2_SECRET_ACCESS_KEY" | ./infra/up secrets set r2_secret_access_key
printf '%s' "$R2_ENDPOINT"          | ./infra/up secrets set r2_endpoint
./infra/up
```

What happens at 03:00 UTC on each node:

| | |
|---|---|
| database | `pg_dump` → `zstd` → `age` → `backup:<bucket>/db/<project>_<stamp>.sql.zst.age` |
| each `extra_paths` entry | `tar` → `zstd` → `age` → `backup:<bucket>/files/<basename>_<stamp>.tar.zst.age` |
| then | anything older than `retention_days` is deleted from both prefixes |

Nothing is ever written to the node's disk in the clear, and **no key that
can decrypt a backup exists on the server**: the recipients are your own
`infra/age-recipients.txt`, so restoring needs an age identity that only
your team holds. The R2 credentials live in `secrets.age` and are pushed to
`/var/lib/stackbase/backup.env` (root-only, 0600) — never into the Nix
store, which is world-readable.

```bash
./infra/up backup-now            # run it now on every node, then list the bucket
./infra/up backup-now --node a
```

Each node backs up **its own** database (see "What a replica is TODAY"), so
a two-node project produces two independent sets of objects.
```

In `## When it fails`, add:

```markdown
| `the backup unit failed on node a` | `./infra/up ssh a -- journalctl -u stackbase-backup -n 50` — the usual causes are wrong R2 credentials or a bucket that does not exist |
| `this project has no backup bucket` | Add `[backups] bucket = "..."` to `stack.toml` and run `./infra/up` |
```

- [ ] **Step 11: Commit**

```bash
git add nixos/backups.nix stackbase/backups.py stackbase/config.py stackbase/reconcile.py \
        stackbase/steps.py stackbase/__main__.py flake.nix templates/infra/flake.nix \
        templates/infra/stack.toml.example README.md \
        tests/test_backups.py tests/test_config.py tests/test_reconcile.py \
        tests/test_cli.py tests/test_template.py
git commit -m "backups: nightly age-encrypted pg_dump/tar to R2, with backup-now"
```

---

### Task 6: VM subtests for conf.d and backups

**Files:**
- Modify: `tests/vm.nix`
- Test: the VM check itself (`nix build .#checks.x86_64-linux.vm -L`)

**Interfaces — Consumes:** `lib.confdModules` (Task 4), `nixosModules.backups` and the `stackbase-backup.service`/`stackbase-backup-ls` contract (Task 5).

**Interfaces — Produces:** nothing new — this task proves the two previous ones on a booted machine.

- [ ] **Step 1: Extend the VM node**

In `tests/vm.nix`'s `let` block, after `certFile`:

```nix
  # A throwaway age identity, generated at BUILD time (a plain derivation --
  # `nix flake check` already realizes derivations referenced from module
  # config, so this needs no special IFD flag). Its PRIVATE half is in the
  # world-readable Nix store, which is exactly what makes it a test-only
  # identity: it proves a backup can be decrypted, and protects nothing.
  testAgeIdentity = pkgs.runCommand "stackbase-test-age-identity" { nativeBuildInputs = [ pkgs.age ]; } ''
    mkdir -p "$out"
    age-keygen -o "$out/key.txt" 2>/dev/null
    grep '^# public key: ' "$out/key.txt" | cut -d' ' -f4 > "$out/recipients.txt"
  '';

  backupBucket = "/var/backup-target";
  uploadsDir = "/var/lib/teststack-uploads";
```

and in the `node` module:

```nix
        imports = [
          self.nixosModules.base
          self.nixosModules.appHost
          self.nixosModules.postgres
          self.nixosModules.backups
        ]
        # The SAME filter a project's infra/flake.nix calls for
        # infra/conf.d/ -- tested here on a booted machine rather than only
        # at eval time (tests/test_template.py covers the eval side).
        ++ (self.lib.confdModules ./fixtures/confd);

        stackbase.backups.bucket = backupBucket;
        stackbase.backups.recipientsFile = "/etc/stackbase-test/recipients.txt";
        stackbase.backups.extraPaths = [ uploadsDir ];
        # The timer must exist and be scheduled, but must never actually
        # fire during the test -- every backup here is started explicitly.
        stackbase.backups.onCalendar = "23:59";

        environment.etc."stackbase-test/recipients.txt".source = "${testAgeIdentity}/recipients.txt";
        environment.etc."stackbase-test/identity.txt".source = "${testAgeIdentity}/key.txt";

        environment.systemPackages = [ pkgs.iproute2 pkgs.age pkgs.zstd pkgs.gnutar pkgs.rclone ];
```

(replacing the existing `environment.systemPackages = [ pkgs.iproute2 ];` line).

- [ ] **Step 2: Add the two subtests**

At the end of `tests/vm.nix`'s `testScript`, after the origin-cert subtest:

```python
      with subtest("infra/conf.d modules are imported on the node"):
          marker = node.succeed("cat /etc/stackbase-confd-marker").strip()
          assert marker == "hello from conf.d", f"unexpected conf.d marker: {marker!r}"
          # The fixture directory also holds a notes.txt -- proof the filter
          # takes *.nix only, since a non-module file would have failed the
          # build, not just this assertion.

      with subtest("the backup timer is scheduled"):
          # Deliberately no assertion that it has NOT fired: a `Persistent`
          # timer's behaviour on a machine with no timestamp file is not
          # something this test should pin down. It cannot have produced
          # anything either way -- there are no credentials on the node yet,
          # so a spontaneous run would have exited 1 with the "no
          # credentials" message.
          node.succeed("systemctl is-active stackbase-backup.timer")
          timers = node.succeed("systemctl list-timers --all --no-pager stackbase-backup.timer")
          assert "stackbase-backup.timer" in timers, timers

      with subtest("a backup run encrypts a real dump that decrypts to valid SQL"):
          # RCLONE_CONFIG_BACKUP_TYPE=local turns `backup:<bucket>` into a
          # plain directory path -- the whole pipeline (pg_dump | zstd | age
          # | rclone rcat) runs exactly as it does against R2.
          node.succeed("install -d -m 0755 ${uploadsDir}")
          node.succeed("echo hello-uploads > ${uploadsDir}/note.txt")
          node.succeed("install -m 0600 /dev/null /var/lib/stackbase/backup.env")
          node.succeed(
              "printf 'RCLONE_CONFIG_BACKUP_TYPE=local\\n' > /var/lib/stackbase/backup.env"
          )
          node.succeed(
              "sudo -u postgres psql -d teststack -c "
              "'create table backup_probe (id int primary key, note text)'"
          )
          node.succeed(
              "sudo -u postgres psql -d teststack -c "
              "\"insert into backup_probe values (1, 'probe-row')\""
          )

          node.succeed("systemctl start stackbase-backup.service")

          dump = node.succeed("ls ${backupBucket}/db/*.sql.zst.age").strip().splitlines()[0]
          assert dump.split("/")[-1].startswith("teststack_"), f"unexpected dump name: {dump!r}"

          plain = node.succeed(
              f"age -d -i /etc/stackbase-test/identity.txt {dump} | zstd -d"
          )
          assert "CREATE TABLE public.backup_probe" in plain, plain[:400]
          assert "probe-row" in plain, plain[:400]

      with subtest("an extra path is archived as its own encrypted tarball"):
          archive = node.succeed("ls ${backupBucket}/files/*.tar.zst.age").strip().splitlines()[0]
          assert archive.split("/")[-1].startswith("teststack-uploads_"), archive

          listing = node.succeed(
              f"age -d -i /etc/stackbase-test/identity.txt {archive} | zstd -d | tar -tf -"
          )
          assert "./note.txt" in listing, listing

      with subtest("a backup with no credentials fails loudly instead of silently doing nothing"):
          node.succeed("mv /var/lib/stackbase/backup.env /var/lib/stackbase/backup.env.away")
          node.fail("systemctl start stackbase-backup.service")
          log = node.succeed("journalctl -u stackbase-backup -n 20 --no-pager")
          assert "no credentials" in log, log[-400:]
          node.succeed("mv /var/lib/stackbase/backup.env.away /var/lib/stackbase/backup.env")

      with subtest("a backup with no recipients file refuses rather than writing something undecryptable"):
          # /etc entries are symlinks into the store -- remove the link, and
          # put it back by hand afterwards (the store path is stable).
          node.succeed("rm -f /etc/stackbase-test/recipients.txt")
          node.fail("systemctl start stackbase-backup.service")
          log = node.succeed("journalctl -u stackbase-backup -n 20 --no-pager")
          assert "nobody could decrypt" in log, log[-400:]

      with subtest("stackbase-backup-ls prints what landed in the bucket"):
          node.succeed("ln -sf ${testAgeIdentity}/recipients.txt /etc/stackbase-test/recipients.txt")
          listing = node.succeed("stackbase-backup-ls")
          assert "db/teststack_" in listing, listing
```

- [ ] **Step 3: Build the VM check**

Run: `nix build .#checks.x86_64-linux.vm -L`
Expected: the driver prints each `subtest:` line and the build succeeds. (Slow — tens of minutes on a cold store. Do **not** run this on a machine without Nix; the Python suite does not cover it.)

- [ ] **Step 4: Keep `nix flake check` green**

Run: `nix flake check -L`
Expected: both VM checks pass.

- [ ] **Step 5: Commit**

```bash
git add tests/vm.nix
git commit -m "test(vm): prove conf.d modules load and a backup decrypts on a booted node"
```

---

### Task 7: Building a release on NixOS

**Files:**
- Modify: `stackbase/release.py`, `README.md`
- Test: `tests/test_release.py`

**Interfaces — Produces:**
- `release.MUSL_CC_ENV = "CC_x86_64_unknown_linux_musl"`, `release.MUSL_LINKER_ENV = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"`, `release.MUSL_GCC = "x86_64-unknown-linux-musl-gcc"`.
- `release.cargo_target_dir(project_slug: str) -> Path | None` — the persistent per-project target directory, or `None` when the operator has set `$CARGO_TARGET_DIR`.
- `build(worktree, project, *, work_dir, project_slug: str | None = None, runner=…, popen=…, emit=…) -> Path` — unchanged behaviour when `project_slug` is `None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_release.py` (the `BuildTests` neighbourhood; `_worktree` already exists). `tests/test_release.py` imports neither `shutil` nor `run_status`/`run_rollback` today — add `import shutil` at the top if Task 3 has not already:

```python
from stackbase.release import MUSL_CC_ENV, MUSL_GCC, MUSL_LINKER_ENV, cargo_target_dir


def _fake_musl_gcc(tmp: Path) -> Path:
    """A directory containing an executable x86_64-unknown-linux-musl-gcc."""
    bin_dir = tmp / "toolchain"
    bin_dir.mkdir()
    gcc = bin_dir / MUSL_GCC
    gcc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gcc.chmod(0o755)
    return bin_dir


class MuslToolchainTests(unittest.TestCase):
    def test_a_cross_gcc_on_path_is_wired_into_both_variables(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            bin_dir = _fake_musl_gcc(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env_without = {
                key: value
                for key, value in os.environ.items()
                if key not in (MUSL_CC_ENV, MUSL_LINKER_ENV)
            }
            env_without["PATH"] = str(bin_dir)
            with mock.patch.dict(os.environ, env_without, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            env = popen.calls[0]["kwargs"]["env"]
            self.assertEqual(env[MUSL_CC_ENV], str(bin_dir / MUSL_GCC))
            self.assertEqual(env[MUSL_LINKER_ENV], str(bin_dir / MUSL_GCC))

    def test_no_cross_gcc_on_path_changes_nothing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env_without = {
                key: value
                for key, value in os.environ.items()
                if key not in (MUSL_CC_ENV, MUSL_LINKER_ENV)
            }
            env_without["PATH"] = str(root / "empty")
            with mock.patch.dict(os.environ, env_without, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            env = popen.calls[0]["kwargs"]["env"]
            self.assertNotIn(MUSL_CC_ENV, env)
            self.assertNotIn(MUSL_LINKER_ENV, env)

    def test_an_operator_set_variable_is_never_overwritten(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            bin_dir = _fake_musl_gcc(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env = {**os.environ, "PATH": str(bin_dir), MUSL_CC_ENV: "/usr/bin/my-own-cc"}
            env.pop(MUSL_LINKER_ENV, None)
            with mock.patch.dict(os.environ, env, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            call_env = popen.calls[0]["kwargs"]["env"]
            self.assertEqual(call_env[MUSL_CC_ENV], "/usr/bin/my-own-cc")
            self.assertNotIn(MUSL_LINKER_ENV, call_env)


class CargoTargetDirTests(unittest.TestCase):
    def test_it_is_under_xdg_cache_home_and_named_for_the_project(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/cache"}, clear=False):
            os.environ.pop("CARGO_TARGET_DIR", None)

            self.assertEqual(cargo_target_dir("acme"), Path("/cache/stack-base/target/acme"))

    def test_an_operator_set_cargo_target_dir_wins(self) -> None:
        with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": "/somewhere"}, clear=False):
            self.assertIsNone(cargo_target_dir("acme"))

    def test_build_uses_the_persistent_dir_and_finds_the_binary_there(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            # The binary must be found under the TARGET dir, not under the
            # throwaway worktree -- a stale copy there would mask the bug.
            shutil.rmtree(worktree / "target")
            target_root = root / "cache" / "stack-base" / "target" / "acme"
            release_dir = target_root / "x86_64-unknown-linux-musl" / "release"
            release_dir.mkdir(parents=True)
            (release_dir / "stack_demo").write_bytes(b"pretend-elf-binary")
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env = {**os.environ, "XDG_CACHE_HOME": str(root / "cache")}
            env.pop("CARGO_TARGET_DIR", None)
            with mock.patch.dict(os.environ, env, clear=True):
                bundle_dir = build(
                    worktree, project, work_dir=root, project_slug="acme", popen=popen, emit=lambda _l: None
                )

            self.assertEqual(popen.calls[0]["kwargs"]["env"]["CARGO_TARGET_DIR"], str(target_root))
            self.assertTrue((bundle_dir / "stack_demo").is_file())

    def test_without_a_project_slug_the_worktree_target_is_used(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            popen = FakePopen()
            popen.script(returncode=0, output="ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            env = {key: value for key, value in os.environ.items() if key != "CARGO_TARGET_DIR"}
            with mock.patch.dict(os.environ, env, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            self.assertNotIn("CARGO_TARGET_DIR", popen.calls[0]["kwargs"]["env"])


class TailwindOnPathTests(unittest.TestCase):
    def _fake_tailwind(self, tmp: Path) -> Path:
        bin_dir = tmp / "tw"
        bin_dir.mkdir()
        binary = bin_dir / "tailwindcss"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        return bin_dir

    def test_tailwindcss_on_path_is_preferred_over_the_downloaded_binary(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root, with_tailwind=True)
            bin_dir = self._fake_tailwind(root)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=0, output="tailwind ok\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(bin_dir)}, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            tailwind_call = popen.calls[1]
            self.assertEqual(tailwind_call["argv"][0], str(bin_dir / "tailwindcss"))
            self.assertEqual(
                tailwind_call["argv"][1:],
                ["-i", "src/templates/input.css", "-o", "static/css/output.css", "--minify"],
            )

    def test_a_failing_css_build_names_both_ways_to_get_tailwind(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root, with_tailwind=True)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            popen.script(returncode=1, output="tailwind blew up\n")
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(root / "empty")}, clear=True):
                with self.assertRaises(StackError) as ctx:
                    build(worktree, project, work_dir=root, popen=popen, emit=lambda _line: None)

            hint = str(ctx.exception)
            self.assertIn("tailwindcss on PATH", hint)
            self.assertIn("tools/install-tailwindcss.sh", hint)

    def test_the_skip_message_names_all_three_ways(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = _worktree(root)
            popen = FakePopen()
            popen.script(returncode=0, output="cargo ok\n")
            emitted: list[str] = []
            project = Project(version="1.0.0", binary="stack_demo")

            with mock.patch.dict(os.environ, {**os.environ, "PATH": str(root / "empty")}, clear=True):
                build(worktree, project, work_dir=root, popen=popen, emit=emitted.append)

            skip = next(line for line in emitted if "no CSS build step" in line)
            self.assertIn("build:css", skip)
            self.assertIn("tailwindcss on PATH", skip)
            self.assertIn("tools/tailwindcss", skip)
```

Note the existing `test_runs_tools_tailwindcss_when_no_package_json_script` keeps passing only if `tailwindcss` is not on the test machine's PATH. Make it deterministic by wrapping its body in `with mock.patch.dict(os.environ, {**os.environ, "PATH": str(Path(tmp) / "empty")}, clear=True):`.

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_release -v`
Expected: FAIL — `ImportError: cannot import name 'MUSL_CC_ENV' from 'stackbase.release'`.

- [ ] **Step 3: Implement the three changes**

In `stackbase/release.py`, add `import shutil` (already imported) and these constants next to `_TAR_EXTENSIONS`:

```python
# NixOS ships the musl cross toolchain as `x86_64-unknown-linux-musl-gcc`,
# not as the `musl-gcc` wrapper cargo looks for by default on Debian-family
# distros -- so a `cargo build --target x86_64-unknown-linux-musl` there
# fails at link time with "linker `cc` not found" unless these two are
# set. This is exactly what obi's workflow does by hand.
MUSL_GCC = "x86_64-unknown-linux-musl-gcc"
MUSL_CC_ENV = "CC_x86_64_unknown_linux_musl"
MUSL_LINKER_ENV = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
```

and:

```python
def cargo_target_dir(project_slug: str) -> Path | None:
    """The persistent cargo target directory for this project, or `None`.

    Every `deploy` builds in a FRESH `git worktree` (that is what makes a
    release reproducible), which means cargo starts from nothing every
    single time -- minutes of rebuilding dependencies that did not change.
    Pointing `CARGO_TARGET_DIR` at one stable per-project directory keeps
    the incremental cache across releases while the source tree stays
    clean and detached.

    `None` when the operator has already set `$CARGO_TARGET_DIR`: their
    choice wins, and `build` then leaves the variable exactly as it found
    it.
    """
    if os.environ.get("CARGO_TARGET_DIR"):
        return None
    cache_home = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(cache_home) / "stack-base" / "target" / project_slug
```

`build`'s signature and environment block become:

```python
def build(
    worktree: Path,
    project: Project,
    *,
    work_dir: Path,
    project_slug: str | None = None,
    runner: Any = subprocess.run,
    popen: Any = subprocess.Popen,
    emit: Callable[[str], None] = print,
) -> Path:
```

```python
    existing_rustflags = os.environ.get("RUSTFLAGS", "").strip()
    crt_static = "-C target-feature=+crt-static"
    rustflags = f"{existing_rustflags} {crt_static}" if existing_rustflags else crt_static
    env = {**os.environ, "RUSTFLAGS": rustflags}

    # Only when BOTH are unset: an operator who set one deliberately keeps
    # full control of the pair, rather than getting a half-overridden
    # toolchain that is harder to reason about than either choice alone.
    musl_gcc = shutil.which(MUSL_GCC)
    if musl_gcc and not env.get(MUSL_CC_ENV) and not env.get(MUSL_LINKER_ENV):
        env[MUSL_CC_ENV] = musl_gcc
        env[MUSL_LINKER_ENV] = musl_gcc
        emit(f"→ using {musl_gcc} as the musl C compiler and linker")

    # A persistent, per-project target directory (see `cargo_target_dir`).
    # Note the binary then lives THERE, not under the throwaway worktree --
    # which is also the bug this fixes for anyone who already had
    # $CARGO_TARGET_DIR set.
    if project_slug:
        target_dir = cargo_target_dir(project_slug)
        if target_dir is not None:
            target_dir.mkdir(parents=True, exist_ok=True)
            env["CARGO_TARGET_DIR"] = str(target_dir)
            emit(f"→ reusing the build cache at {target_dir}")

    emit("→ building the release binary (cargo build --release --target x86_64-unknown-linux-musl)")
    returncode, tail = _stream_local(
        ["cargo", "build", "--release", "--target", "x86_64-unknown-linux-musl"],
        cwd=worktree,
        env=env,
        popen=popen,
        emit=emit,
    )
    if returncode != 0:
        raise StackError(f"cargo build failed (exit {returncode})", _cargo_failure_hint(tail))

    _build_css(worktree, popen=popen, emit=emit)

    target_root = Path(env["CARGO_TARGET_DIR"]) if env.get("CARGO_TARGET_DIR") else worktree / "target"
    binary_path = target_root / "x86_64-unknown-linux-musl" / "release" / project.binary
```

(the rest of `build` is unchanged), and `_cargo_failure_hint` gains one branch before the `musl-gcc` one:

```python
    if "linker `cc` not found" in combined or "cannot find crt1.o" in combined:
        return (
            "no musl C compiler was found -- on NixOS put one on PATH "
            "(nix-shell -p pkgsCross.musl64.stdenv.cc), elsewhere install musl-tools "
            "(e.g. `apt install musl-tools`)"
        )
```

`_build_css`'s tailwind half becomes:

```python
    # `tailwindcss` on PATH beats `tools/tailwindcss`: the downloaded
    # standalone binary is a patchelf-less glibc build that simply cannot
    # execute on NixOS, so a project that has both must use the one from
    # the environment.
    tailwind_on_path = shutil.which("tailwindcss")
    local_tailwind = worktree / "tools" / "tailwindcss"
    if tailwind_on_path:
        tailwind = tailwind_on_path
        label = "tailwindcss on PATH"
    elif local_tailwind.is_file():
        tailwind = str(local_tailwind)
        label = "tools/tailwindcss"
    else:
        emit(
            "! no CSS build step found (no package.json build:css script, no tailwindcss on PATH, "
            "no tools/tailwindcss) -- skipping"
        )
        return

    emit(f"→ building CSS ({label})")
    returncode, tail = _stream_local(
        [tailwind, "-i", "src/templates/input.css", "-o", "static/css/output.css", "--minify"],
        cwd=worktree,
        popen=popen,
        emit=emit,
    )
    if returncode != 0:
        raise StackError(
            f"the CSS build failed (exit {returncode})",
            _tail_hint(
                tail,
                f"stack-base used {tailwind} -- on NixOS, put tailwindcss on PATH "
                "(nix-shell -p tailwindcss); elsewhere ./tools/install-tailwindcss.sh downloads "
                "tools/tailwindcss",
            ),
        )
```

Finally, `run_deploy` passes the slug:

```python
            bundle_dir = build(
                worktree,
                project,
                work_dir=work_dir,
                project_slug=cfg.project,
                runner=runner,
                popen=popen,
                emit=emit,
            )
```

- [ ] **Step 4: Run the tests — green**

Run: `python3 -m unittest tests.test_release -v`
Expected: OK.

- [ ] **Step 5: README**

In `## Releasing a version`, after the "**Which key a deploy offers**" list added in Task 3:

```markdown
**Where the build happens.** `deploy` builds in a throwaway `git worktree`
of the tag, but keeps cargo's incremental cache in
`~/.cache/stack-base/target/<project>` so a second release is not a cold
build. Set `$CARGO_TARGET_DIR` yourself to override it.

**Building on NixOS.** Two things differ from a Debian-family machine, and
`deploy` handles both: the musl cross compiler is called
`x86_64-unknown-linux-musl-gcc` (it is wired into `$CC_x86_64_unknown_linux_musl`
and `$CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER` automatically when it is
on PATH and you have not set either yourself), and the standalone
`tools/tailwindcss` binary cannot run at all — put `tailwindcss` on PATH and
it is used in preference. A build shell that has everything:

```bash
nix-shell -p pkgsCross.musl64.stdenv.cc tailwindcss cargo rustc
```
```

- [ ] **Step 6: Commit**

```bash
git add stackbase/release.py README.md tests/test_release.py
git commit -m "release: build on NixOS -- cross-gcc detection, a persistent target dir, tailwindcss from PATH"
```

---

### Task 8: Self-hosted CI runner, and `status` before the first release

**Files:**
- Modify: `templates/github/deploy-stack.yml`, `nixos/deploy/stack-deploy.sh`, `tests/vm-deploy.nix`, `README.md`
- Test: `tests/test_ci.py`, `tests/vm-deploy.nix`

**Interfaces — Produces:** no new API. `stack-deploy status` on a node with no release exits 0 with clean stderr; the workflow template targets `[self-hosted, x86_64-linux]`.

- [ ] **Step 1: Write the failing workflow tests**

Add to `tests/test_ci.py`, in the workflow section (`_WORKFLOW_TEXT` / the parsed document those tests already use):

```python
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
```

`tests/test_ci.py` already has `re` imported and `_WORKFLOW_TEXT` defined at module level (there is no YAML parser in the stdlib, so every workflow assertion in that file is a regex or a substring check — follow that).

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_ci -v`
Expected: FAIL — `runs-on` is `"ubuntu-latest"`.

- [ ] **Step 3: Edit the workflow template**

In `templates/github/deploy-stack.yml`:

```yaml
jobs:
  deploy:
    # A self-hosted runner, not ubuntu-latest: minutes on it are free (it
    # is our own machine), and it is a NixOS box that already carries the
    # musl cross compiler and tailwindcss -- so no C toolchain is
    # installed at job time at all. `./infra/up deploy` wires
    # $CC_x86_64_unknown_linux_musl / the cargo linker variable to
    # x86_64-unknown-linux-musl-gcc by itself when it finds it on PATH
    # (stackbase/release.py).
    #
    # The runner lives on nixos-ollama; its registration and toolchain are
    # host-level config in platform-base, not in this repository. Both
    # labels must match what that runner registers with.
    runs-on: [self-hosted, x86_64-linux]
```

and replace the toolchain step with:

```yaml
      - name: Install the musl Rust target
        # The cross COMPILER is part of the runner's own NixOS config; only
        # the Rust target itself is per-job (and a no-op once cached).
        run: rustup target add x86_64-unknown-linux-musl
```

- [ ] **Step 4: Write the failing VM subtest for `status`**

In `tests/vm-deploy.nix`, immediately after the existing `"before any deploy: colors defaults to active=none idle=blue"` subtest:

```python
      with subtest("before any deploy: status is clean output, with nothing on stderr (F)"):
          # `read_active` returns the sentinel "none", which used to be fed
          # straight to color_dir() inside a command substitution -- that
          # died with "✗ invalid color: none" on stderr while the outer
          # echo still printed the right line. A no-release-yet node is a
          # normal state, not an error.
          out = node.succeed("stack-deploy status 2>/tmp/status.err").strip()
          err = node.succeed("cat /tmp/status.err")
          assert out == "active=none (-)  idle=blue (-)", f"unexpected status output: {out!r}"
          assert err == "", f"status wrote to stderr before any deploy: {err!r}"
```

- [ ] **Step 5: Fix `current_version_or_dash`**

In `nixos/deploy/stack-deploy.sh`:

```sh
current_version_or_dash() {
  # "none" is a legitimate color here -- read_active returns it when no
  # release has ever been deployed -- and it has no directory, so it must
  # never reach color_dir(), whose die() would print "invalid color: none"
  # to stderr from inside this command substitution while the caller
  # happily printed the rest of its line (F).
  if [ "$1" = none ]; then
    echo "-"
    return 0
  fi

  local v
  v="$(linked_version "$1")"
  if [ -n "$v" ]; then
    echo "$v"
  else
    echo "-"
  fi
}
```

- [ ] **Step 6: Run everything**

Run: `python3 -m unittest tests.test_ci -v`
Expected: OK.

Run: `nix build .#checks.x86_64-linux.vm-deploy -L`
Expected: the new subtest passes along with the rest.

- [ ] **Step 7: README**

In `## Deploying from GitHub Actions (optional)`, replace the paragraph that describes the workflow's runner with:

```markdown
The workflow runs on a **self-hosted** runner (`runs-on: [self-hosted,
x86_64-linux]`), which is a NixOS machine we own: minutes are free, and it
already carries the musl cross compiler and `tailwindcss`, so the workflow
installs nothing but the Rust target. If you do not have that runner, change
`runs-on` to `ubuntu-latest` and add `sudo apt-get install -y musl-tools`
back to the toolchain step.
```

- [ ] **Step 8: Commit**

```bash
git add templates/github/deploy-stack.yml nixos/deploy/stack-deploy.sh tests/vm-deploy.nix \
        tests/test_ci.py README.md
git commit -m "ci: deploy from the self-hosted NixOS runner; status is clean before the first release"
```

---

### Task 9: Guards, the two README sections, and the v0.1.0 tag

**Files:**
- Modify: `templates/infra/.gitignore`, `README.md`
- Test: `tests/test_template.py`

**Interfaces — Produces:** no API. This task closes the plan: the stray-key-material guard, the two cross-cutting README sections the brief asks for, the release tag.

- [ ] **Step 1: Write the failing tests**

Replace `test_the_gitignore_only_hides_build_output` in `tests/test_template.py` with:

```python
    def test_the_gitignore_hides_build_output_and_stray_key_material(self) -> None:
        entries = [
            line.strip()
            for line in (_TEMPLATE_DIR / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        self.assertEqual(
            entries,
            [
                "result",
                "*.age.*.tmp",
                "secrets/",
                "*.key",
                "id_ed25519*",
                "id_rsa*",
                "*.pem",
                "*.age.tmp",
            ],
        )

    def test_the_gitignore_never_hides_a_file_that_must_be_committed(self) -> None:
        """secrets.age, deploy.age and keys/*.pub are the whole point of the repo."""
        import fnmatch

        patterns = [
            line.strip()
            for line in (_TEMPLATE_DIR / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        must_commit = [
            "secrets.age",
            "deploy.age",
            "keys/matt.pub",
            "keys/deploy.pub",
            "age-recipients.txt",
            "deploy-recipients.txt",
            "stack.toml",
            "stack.state.json",
            "known_hosts",
            "flake.lock",
            "conf.d/hello.nix",
        ]

        for path in must_commit:
            for pattern in patterns:
                self.assertFalse(
                    fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern),
                    f"{path} must be committable, but .gitignore's '{pattern}' hides it",
                )
```

and add, in the same class:

```python
    def test_the_version_is_the_one_being_released(self) -> None:
        import stackbase

        self.assertEqual(stackbase.__version__, "0.1.0")

    def test_a_github_pinned_lock_resolves_to_the_public_repository(self) -> None:
        """The `up` wrapper must turn a github-type flake.lock node into the
        real clone URL. Network is never touched -- this only exercises the
        pure resolution step (Brief G).
        """
        import importlib.machinery
        import importlib.util

        # `templates/infra/up` has no .py extension, so
        # spec_from_file_location cannot pick a loader for it -- name the
        # source loader explicitly. Importing it only defines functions
        # (everything else is behind `if __name__ == "__main__"`).
        loader = importlib.machinery.SourceFileLoader("template_up", str(_TEMPLATE_DIR / "up"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)

        with TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "flake.lock"
            lock_path.write_text(
                json.dumps(
                    {
                        "nodes": {
                            "root": {"inputs": {"stack-base": "stack-base"}},
                            "stack-base": {
                                "locked": {
                                    "type": "github",
                                    "owner": "TechSpaceAsia",
                                    "repo": "stack-base",
                                    "rev": "a" * 40,
                                }
                            },
                        },
                        "root": "root",
                        "version": 7,
                    }
                ),
                encoding="utf-8",
            )

            url, rev = module.locked_stack_base(lock_path)

        self.assertEqual(url, "https://github.com/TechSpaceAsia/stack-base.git")
        self.assertEqual(rev, "a" * 40)
```

- [ ] **Step 2: Run them and watch them fail**

Run: `python3 -m unittest tests.test_template.TemplateFilesTests -v`
Expected: FAIL on the `.gitignore` entries assertion (the file still has two entries).

- [ ] **Step 3: Extend the template `.gitignore`**

`templates/infra/.gitignore` becomes:

```gitignore
# Nix leaves a `result` symlink behind after a local build. Nothing else in
# this directory is generated, and nothing in it is secret: secrets.age and
# deploy.age are encrypted (commit them), and stack.state.json, known_hosts,
# flake.lock, keys/ and nodes/ are all records the whole team needs --
# commit those too.
result

# secrets.py's save_secrets() writes through a same-directory temp file
# before its atomic rename -- a crash mid-save can leave one of these
# behind, for either secrets.age or deploy.age. Encrypted, like the real
# files, but still a stray write-ahead artefact that must never be
# committed.
*.age.*.tmp

# Belt and braces for key material that has no business in this directory
# in the first place. stack-base itself never writes any of these: a file
# matching one of them is something a person put there by hand (a
# decrypted bundle, a private key copied off a server, a certificate's
# key), and the one thing worse than having it on disk is committing it.
#
# None of these can match a file that must be committed: the encrypted
# bundles are `*.age` (not `*.age.tmp`), and public keys are `keys/*.pub`.
secrets/
*.key
id_ed25519*
id_rsa*
*.pem
*.age.tmp
```

- [ ] **Step 4: Run the tests — green**

Run: `python3 -m unittest tests.test_template.TemplateFilesTests -v`
Expected: OK.

- [ ] **Step 5: Write the two README sections**

Add `## Things to watch` immediately before `## When it fails`:

```markdown
## Things to watch

Three ways to hurt yourself that no amount of code can prevent.

**1. Never decrypt a secret to disk by hand.** stack-base never writes a
plaintext secret anywhere except RAM (`/dev/shm`, wiped on the way out) —
not to `/tmp`, not to the repository, not for a second. The moment you run
something like `age -d -i ~/.age/key.txt infra/secrets.age > secrets.json`,
every token, the TLS private key and the whole of `app_env` are sitting in
the project directory, an editor swapfile away from a commit and a `rm`
away from being recoverable off the disk anyway. Use the commands instead:

```bash
./infra/up secrets keys          # what's in there
./infra/up secrets edit app_env  # change one value, in RAM
./infra/up deploy-key show-pub   # the public half, which is not a secret
```

**2. `conf.d` files have the full power of NixOS.** Anything in
`infra/conf.d/*.nix` (or `infra/nodes/<name>/extra.nix`) is a NixOS module
with the same authority as stack-base's own: it can `lib.mkForce` its way
past the sshd hardening, re-open the firewall, disable fail2ban or add a
user. That is deliberate — an escape hatch that needed permission would not
be an escape hatch — but it means these files deserve a real code review,
the same as any change to stack-base itself. A repo-wide quality checker is
the intended second line of defence; today, review is the only one.

**3. What you push is your working tree.** `./infra/up` rsyncs `infra/` as
it exists on your disk, not as it exists in the last commit. `up` refuses
when an uncommitted `*.nix` or `stack.toml` would go out (`--allow-dirty`
overrides it), but that check only covers files that change what a node
builds — and it cannot help at all in a checkout that is not a git
repository. If a server is behaving unlike anything in `git log`, check
`git status` before you check anything else.
```

Add `## Restore` immediately after the `## Backups` section from Task 5:

```markdown
### Restore

A backup is an `age`-encrypted, `zstd`-compressed stream. Restoring needs
your age identity — the one thing that never existed on the server.

```bash
# 1. Fetch the object. From the node (it already has the credentials):
./infra/up ssh a -- stackbase-backup-ls          # find the name you want
./infra/up ssh a -- rclone copyto \
  "backup:<bucket>/db/<project>_20260918T030000Z.sql.zst.age" /tmp/restore.sql.zst.age
# ...then copy it to your machine, or run rclone yourself with the same
# RCLONE_CONFIG_BACKUP_* variables.

# 2. Decrypt, decompress, and load. The database, into a FRESH database
#    first -- never straight over a live one:
age -d -i ~/.age/key.txt restore.sql.zst.age | zstd -d > restore.sql
sudo -u postgres createdb <project>_restored
sudo -u postgres psql <project>_restored < restore.sql

# 3. The files variant:
age -d -i ~/.age/key.txt uploads_20260918T030000Z.tar.zst.age \
  | zstd -d \
  | tar -C /var/lib/<project>/uploads -xf -
```

If your identity is a YubiKey, `age-plugin-yubikey` must be on your PATH for
step 2 — the same requirement the node has for writing the backup.

**Test this before you need it.** A backup nobody has ever restored is a
hypothesis, not a backup.
```

- [ ] **Step 6: Confirm the version, run the whole suite**

Run: `python3 -c "import stackbase; print(stackbase.__version__)"`
Expected: `0.1.0` (the brief says to bump to 0.1.0; the file already carries it, so there is nothing to change — see "Brief conflicts" at the foot of this plan).

Run: `python3 -m unittest discover -s tests`
Expected: OK (≈520 tests).

Run: `nix flake check -L`
Expected: both VM checks pass.

- [ ] **Step 7: Commit and tag**

```bash
git add templates/infra/.gitignore README.md tests/test_template.py
git commit -m "docs: things to watch, restore, and the stray-key-material guard"
git tag v0.1.0
```

Do **not** push the tag. `git tag` only; whoever owns the repository decides when it goes out. (platform-base's own rule that a tag must match `Cargo.toml` does not apply here — stack-base is a Python tool, and `stackbase.__version__` is its single source of truth.)

- [ ] **Step 8: Verify the tag**

Run: `git tag -l --format='%(refname:short) %(objectname:short) %(contents:subject)'`
Expected: one line, `v0.1.0 <sha> docs: things to watch, restore, and the stray-key-material guard`.

---

## Brief conflicts resolved

| Brief says | Reality | Resolution |
|---|---|---|
| G: "Bump `stackbase.__version__` to 0.1.0" | `stackbase/__init__.py` already reads `__version__ = "0.1.0"` | Task 9 asserts it rather than bumping it, and still creates the `v0.1.0` tag. |
| A: gitignore gains `*.age.tmp` | The file already has `secrets.age.*.tmp`, which does not cover `deploy.age`'s temp file (`deploy.age.<pid>.tmp`) | Task 9 keeps the brief's `*.age.tmp` **and** generalises the existing entry to `*.age.*.tmp`, so both encrypted files' write-ahead artefacts are covered. |
| B: "VM test: a `conf.d/hello.nix` that adds a marker file" | `conf.d` is a *template-flake* feature, and the VM tests build nodes from `self.nixosModules.*`, never from the template | Task 4 moves the filter into stack-base as `lib.confdModules`, so Task 6's VM test exercises the same code the template calls, and `tests/test_template.py` additionally proves the template wiring at eval time. |
| A: "`up` checks and refuses otherwise" (superset) | Says nothing about a project that has no deploy key yet | Decision 4: an absent `deploy-recipients.txt` skips the check silently. |
| C: `recipientsFile` default "`infra/age-recipients.txt` as shipped to the node" | Needs a concrete on-node path | `/etc/nixos/stack/age-recipients.txt` (`reconcile.REMOTE_CONFIG_DIR`), typed `str` and NOT a store path, so the pushed file governs. |
| C: hanskraft's model writes plaintext dumps to `/tmp` first | Global constraint: nothing sensitive on disk | The generic module streams (`pg_dump | zstd | age | rclone rcat`) — no temp file at all, which is strictly better than the model it copies. |
| A: "keep the attr name or rename — plan decides" | — | Decision 1: `ciDeployKeys` → `projectDeployKeys`, file `keys/ci-deploy.pub` → `keys/deploy.pub`, attr `ci-deploy` → `deploy`. |
