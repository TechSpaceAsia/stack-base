# stack-base

stack-base turns one text file into running servers. You describe what your
project should have — a domain, who gets access, one or two servers — in
`infra/stack.toml`, and `./infra/up` makes reality match it: buying or
installing the server, locking it down, getting a TLS certificate and
pointing the domain at it through Cloudflare. It is safe to run again at any
time: it checks what is already true and only does what is missing.

You do **not** need to know NixOS, Nix, or infrastructure to use it.

## What you need first

On your own machine: `python3`, `git`, `ssh`, `rsync`, `age`, `openssl`.
That's it — no Nix.

```bash
# Debian/Ubuntu
sudo apt install python3 git openssh-client rsync age openssl
# macOS (python3, git, ssh and openssl ship with Xcode Command Line Tools on
# most Macs already, but installing them here is harmless if they don't)
brew install python3 git openssh rsync age openssl
```

You also need:

- **A Hostinger API token** (hPanel → account → API). It buys and manages the
  servers.
- **A Cloudflare API token** (optional) with these permissions, scoped to your
  zone: **Zone → DNS → Edit** and **Zone → SSL and Certificates → Edit**.
  Leave it out and stack-base still stands up the server — it just skips DNS
  and the TLS origin certificate, so the server is only reachable by its bare
  IP over SSH. Add the token later and run `./infra/up` again to fill both
  in.
- **Your Cloudflare zone set to Full (strict) SSL mode** (only if you're using
  Cloudflare). stack-base installs a Cloudflare origin certificate on the
  server; Full (strict) is the setting that makes Cloudflare actually check
  it. "Flexible" would leave the traffic between Cloudflare and your server
  unencrypted.
- **An SSH key** (`~/.ssh/id_ed25519.pub`, or run `ssh-keygen -t ed25519`).
  It must be one that `ssh` will actually offer without being asked: loaded
  in an `ssh-agent` (`ssh-add ~/.ssh/id_ed25519`) or configured via
  `IdentityFile` in `~/.ssh/config` for the server's address. stack-base
  runs `ssh` in batch mode and never prompts, so a key that only works when
  something asks you for it (or for its passphrase) will just fail.

## First run, step by step

**1. Fill in `infra/stack.toml`.** Copy `stack.toml.example` to `stack.toml`
and edit it — every line has a comment explaining it.

**2. Add your SSH public key.** For each name in `admins`:

```bash
cp ~/.ssh/id_ed25519.pub infra/keys/your-name.pub
```

**3. Make an age key** (this is what encrypts the project's secrets so they
can live safely in git):

```bash
mkdir -p ~/.age && age-keygen -o ~/.age/key.txt   # keep this file private
age-keygen -y ~/.age/key.txt                      # prints your PUBLIC key
```

Paste that public key into `infra/age-recipients.txt`, one per line.

**4. Create the secrets file, then set your tokens.** First bootstrap an
empty, encrypted secrets file (a one-time pipe straight into `age` — nothing
plaintext ever touches disk, even here):

```bash
printf '{}' | age -R infra/age-recipients.txt -o infra/secrets.age
```

Then set each token with `secrets set` — see [Managing secrets](#managing-secrets)
below for the full command reference. `cloudflare_token` is optional — skip
it for now to stand the server up reachable by IP/SSH only; add it later and
run `./infra/up` again to fill in DNS and the TLS origin certificate:

```bash
HOSTINGER_TOKEN=<paste here>
printf '%s' "$HOSTINGER_TOKEN" | ./infra/up secrets set hostinger_token

CLOUDFLARE_TOKEN=<paste here, or skip this line entirely>
printf '%s' "$CLOUDFLARE_TOKEN" | ./infra/up secrets set cloudflare_token
```

`infra/secrets.age` is encrypted — commit it. The tokens themselves never
touch your disk unencrypted and never appear in any output.

**5. Look before you leap.**

```bash
./infra/up --plan
```

This only reads. It prints a numbered list of what it *would* do, and
`nothing to do` when everything already matches.

**6. Do it.**

```bash
./infra/up
```

Then commit what it wrote back: `infra/stack.state.json`,
`infra/known_hosts`, `infra/nodes/` and `infra/flake.lock`.

## What each step means

| Step | What it does |
|---|---|
| registering the team's SSH keys | Tells Hostinger about everyone's public key |
| buying / installing | Buys a server (only if you said so) and installs NixOS on it |
| waiting for the server | Waits for it to boot and get an IP address |
| applying the firewall | Closes everything except SSH (22) and HTTPS (443) |
| remembering the fingerprint | Records the server's SSH identity so a swap can't go unnoticed |
| copying disk and boot settings | Copies the server's own hardware config into `infra/nodes/` |
| creating the origin certificate | Gets a TLS certificate from Cloudflare for your domain |
| uploading | Copies `infra/` and the certificate onto the server |
| rebuilding NixOS | Applies the configuration (this is the slow one — minutes) |
| updating the application's environment file | Pushes `app_env` from `secrets.age` to the server and restarts the running release (see [The app's environment](#the-apps-environment-app_env) below) |
| pointing the domain | Points your domain at the server in Cloudflare |

## Everyday things

**Add a second server.** Add a section to `stack.toml`, then run `./infra/up`:

```toml
[nodes.b]
role = "replica"
```

Leave out `vps_id` and stack-base offers to buy it; include `vps_id` if you
already own the machine.

**Add a teammate.** Put their public key in `infra/keys/<name>.pub`, add
their name to `admins` in `stack.toml`, and run `./infra/up`. They also need
to add their age public key to `infra/age-recipients.txt` — then someone who
can already decrypt `secrets.age` re-encrypts it for the new list.

**Remove a teammate.** Delete them from `admins` and delete their
`keys/<name>.pub`, then run `./infra/up`. Their account and access disappear
on the next rebuild. Remove their line from `age-recipients.txt`, then
re-run any `./infra/up secrets set <key>` (or `secrets edit <key>`) for each
token — that re-encrypts `secrets.age` against the new recipient list as a
side effect of saving. Rotate the tokens too, since they have seen them.

**Open a shell on a server.**

```bash
./infra/up ssh a               # a shell on node "a"
./infra/up ssh a -- systemctl status nginx
```

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

**Buying a server.** stack-base will never spend money by accident. It needs
all of: `price_item` filled in, the `--allow-purchase` flag, a real terminal,
and you typing the exact phrase it asks for:

```bash
./infra/up --allow-purchase
# About to buy 1 x KVM 1 from Hostinger for node(s) a.
# Type exactly 'buy KVM 1 x1' to go ahead:
```

Anything else and nothing is bought. **stack-base can never cancel or delete
a server** — it has no code that can. Cancel it yourself in hPanel.

## Managing secrets

`infra/secrets.age` holds every token, key, and the app's own `app_env` as
one flat, encrypted JSON object. The safe way to touch it is one key at a
time, never the whole bundle — these four subcommands are built so the safe
way is also the easy way; none of them ever writes more than one key's
value to disk, and only ever to RAM (never a real disk, and wiped
immediately after):

| Command | What it does |
|---|---|
| `./infra/up secrets keys` | Lists every key's NAME, sorted — never a value |
| `./infra/up secrets set <key>` | Sets `<key>`'s value, read whole from stdin |
| `./infra/up secrets unset <key>` | Removes `<key>` (refuses `hostinger_token` — `up` can't run without it) |
| `./infra/up secrets edit <key>` | Opens `<key>`'s value in `$VISUAL`/`$EDITOR`/`vi` |

`secrets set` reads its value from stdin — pipe it in, or redirect it from a
file; it refuses to prompt at an interactive terminal (typing a secret
straight into a terminal is too easy to leave sitting in shell history):

```bash
HOSTINGER_TOKEN=<paste here>
printf '%s' "$HOSTINGER_TOKEN" | ./infra/up secrets set hostinger_token
# or, from a file:
./infra/up secrets set hostinger_token < token.txt
```

`secrets edit <key>` writes ONLY that key's value to a private, RAM-backed
scratch file (mode 0600), opens it in your editor, reads it back, and wipes
the file the moment the editor exits — even if you never save. If the
content comes back unchanged, nothing is re-encrypted. Your editor's own
swap/backup files are its own business, not stack-base's — for vim,
consider `:set noswapfile nobackup noundofile` if that matters to you.

Both `set` and `edit` validate `app_env` (every non-blank, non-comment line
must look like `NAME=value`) before saving it — the same check `up` itself
performs, so a mistake is caught here, not on the next `up`.

Key names must match `^[a-z][a-z0-9_]{0,40}$` — lowercase letters, digits,
and underscores, starting with a letter.

## Releasing a version

Once a server is up (`./infra/up` has completed at least once), you ship
application code with `./infra/up deploy`, `./infra/up rollback`, and
`./infra/up status`. These are a separate concern from `./infra/up` itself:
`up` makes the SERVER match `stack.toml`; `deploy` puts a RELEASE of your
app on it, blue/green, with zero downtime.

**Before your first deploy:**

- `./infra/up` must have completed at least once (the server, its `deploy`
  user, and the systemd units a release runs under all come from that).
- Set `app_env` and push it — `./infra/up secrets edit app_env` then
  `./infra/up` — **before** your first `deploy`. Without it the app starts
  with no `DATABASE_URL` (or whatever else it needs) and fails its own
  health check, so the deploy is refused. See
  [The app's environment](#the-apps-environment-app_env) above.
- `/` answers 502 until the first release goes live — that's expected, not
  a bug: nothing is listening on the app socket yet.

**The flow:**

```bash
git tag v1.2.3       # on a commit whose Cargo.toml says version = "1.2.3"
git push origin v1.2.3
./infra/up deploy v1.2.3
```

**Which key a deploy offers**, in order:

1. `$STACKBASE_SSH_IDENTITY`, if you set it — an explicit choice always wins.
2. `infra/deploy.age`, decrypted to a RAM-only file for the duration of the
   command. This is the normal path, and the one a build host uses.
3. Your `ssh-agent`, with a warning that no project key was found.

The decrypted key never touches a real disk, and `./infra/up deploy` deletes
it the moment the command ends (including on Ctrl-C). Step 3 is only for a
project that has no deploy key at all: once `infra/deploy.age` exists, a
machine that cannot decrypt it is refused rather than quietly falling back to
your agent. If you hold no age identity, step 1 is your way in:

```bash
STACKBASE_SSH_IDENTITY=<path to your SSH private key>
./infra/up deploy v1.2.3
```

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

`deploy` builds a clean, deterministic release from that tag (a fresh `git
worktree`, never your working tree — the same build a GitHub Actions
deploy runs, see [below](#deploying-from-github-actions-optional)), uploads
it, starts it on the currently-idle color, health-checks it, and only THEN
atomically switches traffic — nginx never serves a half-started release.
The old color keeps running for
`drainSeconds` (60s by default) so in-flight requests finish, then stops.
Releases are pruned to the newest 5 by SemVer after every successful
deploy (a release either color is currently linked to is never pruned,
even if it ranks below the cutoff).

```bash
./infra/up status      # what's live on every node, right now
./infra/up rollback     # swap back to the previously-active release
```

**What `rollback` does NOT do: it does not roll back the database.**
Migrations run at app startup and are never undone by a rollback — this is
why every migration must be additive-only (expand the schema → migrate the
data → drop/rename the old column in a LATER release, once nothing depends
on it anymore). A migration that isn't additive can break the
currently-live color mid-swap, since both the new and old release's code
run against the same database during the swap window.

**Exit codes**, from the restricted `deploy@` SSH door (`upload`/`deploy`/
`rollback` all use these):

| Exit | Meaning | What to do |
|---|---|---|
| 0 | ok | nothing |
| 1 | failure (bad health check, build error, ...) | the output above names it — fix and re-run; nothing was switched |
| 2 | usage error (bad version string, wrong argument count) | fix the command and re-run |
| 3 | another deploy is already in progress on that node | wait for it to finish, then re-run |
| 4 | this version already exists on that node with DIFFERENT content | a published version must never change — bump the version, tag, and deploy that instead; there is deliberately no `--force` over ssh |

`--node <name>` restricts a `deploy`/`rollback`/`status` call to one node
instead of every node in `stack.toml`.

**What a replica is TODAY.** Every node — primary or replica — runs its
own LOCAL, initially-empty Postgres; DNS only ever points at the primary.
Deploying to replicas first (the default order: replicas, then primary) is
a smoke test against a DIFFERENT database, not a test of real replicated
traffic — actual database replication is a later piece of work, not
something `deploy` does today. Don't rely on a replica's deploy succeeding
as proof the primary's data will behave the same way.

**Writable paths for the app.** The release tree under `/opt/<project>` is
read-only to the app. `/var/lib/<project>` (systemd's `StateDirectory=`,
owned by the app user, mode 0750) is the one place for uploads or other
local files the app needs to persist — see
[What the files are](#what-the-files-are)-style caveats: it's per NODE, not
shared between blue/green or between nodes, and it is not backed up yet.

**Long-lived requests and the old color.** SSE streams and other
long-running requests on the OLD color are cut when it stops, `drainSeconds`
after the swap (and, failing a graceful stop within `TimeoutStopSec`,
force-killed). A client reconnecting picks up the new color; there's no
in-place migration of an open connection.

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

## Deploying from GitHub Actions (optional)

Deploys (`./infra/up deploy vX.Y.Z`) normally run from a laptop, over the
same restricted SSH door every `stackbase.deploy.keys` entry uses. That
door can optionally also be driven by GitHub Actions on every tag push,
so a release ships as soon as you `git push --tags`, with no laptop
involved.

The workflow runs on a **self-hosted** runner (`runs-on: [self-hosted,
x86_64-linux]`), which is a NixOS machine we own: minutes are free, and it
already carries the musl cross compiler and `tailwindcss`, so the workflow
installs nothing but the Rust target. If you do not have that runner, change
`runs-on` to `ubuntu-latest` and add `sudo apt-get install -y musl-tools`
back to the toolchain step. If you push a tag without doing either, the
deploy job just queues forever with no error — GitHub does not fail a job
for want of a matching runner, it simply never schedules it — so a tag that
never deploys and never fails is a sign to check `runs-on`, not to wait
longer.

**What `./infra/up ci-setup` does:** pushes the project's own deploy key
(above) straight into a **repository-level** GitHub Actions secret
(`STACK_DEPLOY_KEY`) — repo-level, not organization-level, because this
GitHub plan has no org-level secrets/variables to use instead. If this
project has no deploy key yet, `ci-setup` creates one first (same as running
`deploy-key init` yourself). `ci-setup` needs the
[`gh` CLI](https://cli.github.com), authenticated (`gh auth login`).

**Turn it on** (three commands):

```bash
./infra/up ci-setup
git add infra/deploy.age infra/keys/deploy.pub && git commit -m "ci: the project deploy key"
./infra/up                 # installs the key on every server
```

then copy the workflow itself into place. `ci-setup` prints the exact `cp`
command for you (the source path depends on which stack-base revision your
project is pinned to), in the shape of:

```bash
mkdir -p .github/workflows
cp <stack-base checkout>/templates/github/deploy-stack.yml .github/workflows/deploy-stack.yml
git add .github/workflows/deploy-stack.yml && git commit -m "ci: add the deploy workflow"
```

**Rotate it** with `./infra/up ci-setup --rotate` — this forwards to
`./infra/up deploy-key init --rotate` and immediately replaces the GitHub
Actions secret (`STACK_DEPLOY_KEY`) with the new key. There IS a window
where CI deploys are broken: GitHub Actions is now offering the NEW private
key, but every server still only trusts the OLD public one, until you
commit the new `infra/deploy.age`/`infra/keys/deploy.pub` and run
`./infra/up` (which is what installs the new key on every server):

```bash
git add infra/deploy.age infra/keys/deploy.pub && git commit -m "deploy: rotate the project deploy key"
./infra/up                 # installs the new key on every server -- CI deploys work again after this
```

Because it's the SAME key everywhere, rotating it also replaces what you
and any build host deploy with — there is no "laptop deploys are
unaffected" any more (Task 2 removed the separate `ci-deploy` key).

**Turn it off** (CI only — this does not remove the deploy key itself,
since it's also your own):

```bash
gh secret delete STACK_DEPLOY_KEY --repo <owner>/<repo>
```

A project upgraded from an older stack-base that still has
`infra/keys/ci-deploy.pub` should delete that file and run
`./infra/up deploy-key init` — the template flake no longer reads that
path.

**What a leaked CI key can and cannot do.** It's just another
`stackbase.deploy.keys` entry, confined the same way every one of them is
(`restrict,command=...`): it can only ever run the door's six words --
`upload`, `deploy`, `rollback`, `status`, `colors`, `releases`. It **cannot**
get an interactive shell, **cannot** read `infra/secrets.age` or anything
else on the server, and **cannot** touch nginx or TLS. It **can** deploy any
version it can upload, and roll back — so protect your `v*` tags (branch
protection rules, required reviews on who can push a tag) the same way
you'd protect a production deploy button.

**Migrations must be additive.** The app runs its own migrations at
startup, and a CI-triggered deploy has no manual "review before it touches
the database" step — so every migration must be additive-only (expand,
migrate the data, THEN contract in a later release). A migration that
drops or renames a column a still-running old release depends on can break
the currently-live color mid-swap.

## The app's environment (`app_env`)

The platform-base app reads its configuration — database URL, session
secrets, OAuth credentials, anything else in `.env.example` — from a single
`EnvironmentFile` systemd loads before the app starts, as root, before the
process drops to its own unprivileged user. stack-base owns getting that file
onto the server: it lives in `secrets.age` as one more key, `app_env`, and
`./infra/up` pushes it to `/var/lib/stackbase/app.env` whenever its content
changes.

**Set it** with [`secrets edit`](#managing-secrets) — it's one string of
`KEY=value` lines, so an editor is the natural way to write it:

```bash
./infra/up secrets edit app_env
```

your editor opens with `app_env`'s current value (empty the first time);
save something like this and exit:

```
DATABASE_URL=postgres:///acme
SESSION_SECRET=...
CSRF_SECRET=...
OAUTH_CLIENT_ID=...
OAUTH_CLIENT_SECRET=...
OAUTH_REDIRECT_URL=https://acme.example.com/auth/callback
```

then run `./infra/up` to push it. (`secrets set app_env` works too, if you'd
rather pipe the whole value in from a script or a file — see
[Managing secrets](#managing-secrets).)

At minimum a platform-base app needs: `DATABASE_URL` (`postgres:///<project>`
— peer auth over the Unix socket, no password), a session secret and a CSRF
secret, and the OAuth client id/secret/redirect URL. Check the project's own
`.env.example` for anything else it expects. `SOCKET_PATH` is reserved — the
systemd unit sets it itself, per color, and `secrets set`/`secrets edit`/`up`
all refuse an `app_env` that tries to set it.

**What `./infra/up` does with it:** the whole value, and every individual
`KEY=value` line inside it, are redacted from every line stack-base prints —
same as every other secret. The file lands on the server as `root:<project>
0640`, written to a temp name with that owner and mode already set, then
moved into place — so it's never briefly world-readable or half-written.
stack-base never writes it to a local file; it only ever exists in memory on
your machine and in `secrets.age`.

**Restart semantics.** Pushing a new `app_env` restarts whichever color is
currently live (`systemctl try-restart <project>@blue` or `@green`) so the
new values take effect — this is a brief blip, not a blue/green swap; env
changes aren't part of the zero-downtime release mechanism. If you want to
roll an env change out with zero downtime, push it with `./infra/up` and then
`deploy` (or re-deploy) a release — the new release process picks up the new
`app_env` when it starts, and the swap itself stays zero-downtime as usual.
If no release has been deployed to a node yet, `./infra/up` pushes the file
and skips the restart (there's nothing running to restart) — the new
environment simply applies from the first deploy.

Removing `app_env` from `secrets.age` does **not** delete the file already on
the server — that's a deliberate manual act (`./infra/up ssh a -- rm
/var/lib/stackbase/app.env`), not something a config diff should do for you.

`stack.state.json` records a sha256 digest of `app_env` (so `up` can tell
whether it needs to push again) — that digest is only as unguessable as the
secrets inside `app_env` itself, so keep at least one long, random value in
there (the session secret already is one) rather than only short,
guessable values.

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

All three credentials or none: with an incomplete set, `./infra/up` pushes
nothing and the nightly job stays off, rather than failing quietly at 03:00
every night.

What happens at 03:00 UTC on each node:

| | |
|---|---|
| database | `pg_dump` → `zstd` → `age` → `backup:<bucket>/db/<project>_<stamp>.sql.zst.age` |
| each `extra_paths` entry | `tar` → `zstd` → `age` → `backup:<bucket>/files/<basename>_<stamp>.tar.zst.age` |
| then | anything older than `retention_days` is deleted from those two prefixes |

`retention_days` defaults to 30 and `on_calendar` to `"03:00"` (UTC). The
deletion only ever runs against `<bucket>/db/` and `<bucket>/files/` — never
the bucket root, and never with a retention of 0.

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

**A bucket listing is not a success report.** Each object is streamed
straight to the bucket as it is produced, so a run that dies part-way
through — the database goes away mid-dump, the node runs out of network —
leaves a **short, still-encrypted object** behind that looks exactly like a
good one in a listing. Two things follow:

- **The unit is the source of truth, not the bucket.** A broken pipe fails
  the whole run loudly (`systemctl status stackbase-backup`, or `./infra/up
  ssh a -- journalctl -u stackbase-backup -n 50`), and the pruning step
  never runs on a failed run — so a bad night can never delete good
  backups. If you monitor one thing, monitor that unit.
- **A truncated object fails to restore; it does not restore badly.** The
  `age`/`zstd` pipeline above stops with a decompression error on a short
  object rather than handing `psql` half a database — so a restore that
  starts is a restore you can trust. Restore the previous timestamp if one
  fails.

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

## When it fails

Every failure is one line: what went wrong, then what to check.

| The error says | What to do |
|---|---|
| `secrets.age not found` | Do step 4 above — the message includes the exact command |
| `failed to decrypt …/secrets.age` | Your age key isn't a recipient yet. Ask a teammate to re-encrypt it for you |
| `infra/deploy-recipients.txt is missing N recipient(s)` | Add the listed key(s) to `deploy-recipients.txt`, then `./infra/up deploy-key init --rotate` |
| `infra/deploy.age already exists` | Pass `--rotate` if you really mean to replace the project's deploy key |
| `the API token is wrong or expired` | Re-issue the token and re-create `secrets.age` |
| `the API token doesn't have permission` | Cloudflare: add **Zone → SSL and Certificates → Edit**. Hostinger: use a full-access token |
| `no Cloudflare zone found for domain …` | The token can't see that zone — check it's scoped to the right account |
| `multiple A records found for …` | Two records fight over the name. Delete the wrong one in the Cloudflare dashboard; stack-base won't guess |
| `no Hostinger data center named …` | The message lists the valid names — put one in `stack.toml` |
| `node(s) a have no vps_id…` | Either set `vps_id`, or re-run with `--allow-purchase` |
| `buying a server needs a price_item` | Copy the plan's catalog id from Hostinger into `price_item` |
| `the new configuration failed to build` | The build output is above the error. Fix `infra/`, run again — nothing was made permanent |
| `You must set the option boot.loader…` or a `fileSystems` error | The provider module's defaults don't match this node's disk/network — see "First run on a new provider image" below |
| `node a stopped answering SSH…` | See below |
| `the SSH host key … does not match` | Either the server was reinstalled (delete its line from `infra/known_hosts`) or something is wrong. If you didn't reinstall it, stop and investigate |
| `infra/flake.lock is missing` | First run against an unpublished stack-base: set `STACKBASE_SRC` (below) |
| `app_env has a line that is not KEY=value` | Fix the offending line in `app_env` and re-encrypt `secrets.age` — see [The app's environment](#the-apps-environment-app_env) |
| `node a has no '<project>' group yet` | Run `./infra/up` again once REBUILD has completed for that node at least once — the group is created by the first rebuild |
| `infra/secrets.age's 'app_env' sets 'SOCKET_PATH', which is reserved` | Remove that line from `app_env` — the systemd unit sets it itself, per color |
| Too many authentication failures / connection refused right after a deploy attempt | Your `ssh-agent` is probably offering more keys than the node's `MaxAuthTries` allows before the right one is tried, and fail2ban has banned you. Set `STACKBASE_SSH_IDENTITY=~/.ssh/id_ed25519` (or add an `IdentitiesOnly yes` `Host` block to `~/.ssh/config`) so only your real key is offered. To recover from an existing ban: wait 10 minutes, or unban yourself from hPanel's browser console with `fail2ban-client set sshd unbanip <your-ip>` |
| `this server's default binary name` (during `deploy`) | Your crate's binary name doesn't match `<project>` with `-` → `_`. Add `[app] binary = "..."` to `stack.toml` (the message gives the exact value) and run `./infra/up` before deploying again |
| Cargo.toml declares several `[[bin]]` entries and stack.toml has no `[app].binary` | Ambiguous — add `[app] binary = "..."` to `stack.toml`, choosing one of the listed candidates |
| `infra/ has uncommitted changes that would be pushed` | Commit them, or re-run with `--allow-dirty` if you are deliberately testing |
| `the backup unit failed on node a` | `./infra/up ssh a -- journalctl -u stackbase-backup -n 50` — the usual causes are wrong R2 credentials or a bucket that does not exist |
| `this project has no backup bucket` | Add `[backups] bucket = "..."` to `stack.toml` and run `./infra/up` |

A failed run changes nothing further and can always simply be run again: it
picks up exactly where it stopped.

## First run on a new provider image

Hostinger's NixOS image ships with an **empty `/etc/nixos`** — it's a
prebuilt cloud-init image, not a machine that was ever `nixos-install`ed with
its own configuration. So there is no `configuration.nix` on the server to
copy settings out of. Instead:

- stack-base generates the disk facts itself, by running
  `nixos-generate-config --show-hardware-config` on the node and saving the
  result as `infra/nodes/<name>/hardware-configuration.nix`.
- The boot loader (GRUB on `/dev/sda`) and the networking stack that keeps
  the node reachable after a reboot (cloud-init's static IP hand-off to
  systemd-networkd) are supplied declaratively by stack-base's own
  Hostinger provider module — you never need to write these by hand.

The very first rebuild on a brand new server can still fail with an error
like `You must set the option boot.loader.grub.devices…` or a `fileSystems`
assertion, if a particular node's disk or network genuinely differs from
what the provider module assumes (a non-default disk layout, a different
provider image entirely). When that happens, the fix is the same escape
hatch every node has: create `infra/nodes/<name>/extra.nix` and set the
option(s) that need to differ there — it's loaded alongside the provider
module's defaults and can override any of them — then run `./infra/up`
again. This fails at the *test* stage, before anything is activated, so
nothing on the server changes until it builds cleanly.

## What Hostinger's NixOS image actually ships (verified live, Sept 2026)

A real Hostinger VPS was taken all the way through `./infra/up` — first
rebuild (test → probe → switch), a second run reporting `nothing to do`, and
a deliberate reboot that came back in ~31s with the same host key, the
static IPv4/IPv6 re-rendered by cloud-init, all services active, 0 failed
units, and password auth still refused. What the image itself ships,
confirmed on that box:

- `/etc/nixos` is **empty** — a prebuilt cloud-init image, not a
  `nixos-install`ed machine.
- cloud-init's datasource is **NoCloud**, delivered on a `cidata` ISO
  mounted at `/dev/sr0` (meta-data, network-config, user-data, vendor-data).
- Networking is **static, not DHCP**: cloud-init renders the IPv4/IPv6
  addresses into `/etc/systemd/network/`, and systemd-networkd +
  systemd-resolved own the interface from there — no dhcpcd, no
  NetworkManager.
- **BIOS boot, GRUB on `/dev/sda`.**
- A single ext4 root partition, `LABEL=nixos`, that grows to fill the disk
  on boot (`x-systemd.growfs` + a `growpart.service`).
- **qemu-guest-agent** is active.
- Root's first SSH key is delivered by cloud-init, not by stack-base.
- `nix 2.34.8`, channel `nixos-26.05` — `experimental-features` is **not**
  set in `nix.conf`. `nixos-rebuild --flake` still works regardless:
  `nixos-rebuild` itself enables `nix-command`/`flakes` for the duration of
  the run whenever `--flake` is passed, it doesn't depend on the box's own
  `nix.conf` at all.
- **1 vCPU / ~3.9 GB RAM** — the very first rebuild (building the whole
  system closure) took a few minutes; expect that specifically on the first
  run, not on later ones once the store has more in it already.

Three Hostinger API quirks learned the same way, all already handled in
code (`stackbase/http.py`, `stackbase/hostinger.py`, `stackbase/reconcile.py`):

- Every request needs a **non-default `User-Agent`** — Hostinger (behind
  Cloudflare) rejects urllib's default `Python-urllib/3.x` with an HTTP
  `1010`. stack-base sends an explicit, identifying one.
- The setup/purchase password is validated against **both** `root_password`
  (a wider symbol set) **and** `panel_password` (a narrower one) — the only
  symbols that satisfy both are `#+?@`, and stack-base's generated password
  is built from exactly that intersection.
- The node's hostname sent to Hostinger **must be an FQDN** — a short
  `<project>-<node>` name is rejected with "Wrong hostname FQDN format",
  even though Hostinger's own API docs don't call this out.

## If you get locked out

stack-base applies a new configuration in two stages on purpose. First it
*tests* it — active now, but not the boot default — then it opens a fresh SSH
connection to prove you can still get in, and only then makes it permanent.
So a configuration that locks you out fails at the probe and is never saved.

If you cannot reach a server:

1. **Reboot it from hPanel.** It comes back on the last configuration that
   was made permanent — the tested one is discarded.
2. If it still won't come up, use the **browser console in hPanel**, which
   reaches the machine even with no network and no sshd, and log in as `root`.
3. Fix the cause in `infra/`, then run `./infra/up` again.

## Running against an unpublished stack-base

While stack-base has no published repository, point `STACKBASE_SRC` at a
local clone:

```bash
STACKBASE_SRC=~/code/stack-base ./infra/up --plan
```

In this mode the local checkout is uploaded to the server alongside your
config and used directly, so edits to stack-base take effect on the next run.

> `templates/infra/flake.nix` pins `inputs.stack-base.url` to
> `github:TechSpaceAsia/stack-base`.

## What the files are

| File | |
|---|---|
| `stack.toml` | What you want. The only file you normally edit |
| `keys/*.pub` | Everyone's SSH public key. Commit |
| `age-recipients.txt` | Everyone's age public key — who can read the secrets. Commit |
| `secrets.age` | The encrypted API tokens, TLS key and the app's own `app_env`. Commit (it's encrypted) |
| `deploy-recipients.txt` | Who can decrypt `deploy.age` — a superset of `age-recipients.txt`. Commit |
| `deploy.age` | The project's encrypted SSH deploy key. Commit (it's encrypted) |
| `keys/deploy.pub` | The deploy key's public half — this is what gets installed on the servers. Commit |
| `stack.state.json` | What stack-base has done so far — addresses, record ids, fingerprints. Written for you: commit it, don't edit it. The servers' configuration is built from `stack.toml` alone, so nothing in here changes what gets installed |
| `known_hosts` | The servers' SSH fingerprints. Commit |
| `nodes/<name>/` | Each server's own disk and boot settings, copied off the machine. Commit |
| `nodes/<name>/extra.nix` | Optional, yours: anything specific to one server |
| `conf.d/*.nix` | Optional, yours: NixOS settings applied to every server |
| `flake.nix`, `flake.lock` | Which version of stack-base this project uses. Commit |

`stack.state.json` contains the servers' real IPs — if this repository is
public, so is the origin address (nginx still refuses any connection that
doesn't arrive via Cloudflare, but SSH is reachable at that address).
