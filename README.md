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

## Deploying from GitHub Actions (optional)

Deploys (`./infra/up deploy vX.Y.Z`) normally run from a laptop, over the
same restricted SSH door every `stackbase.deploy.keys` entry uses. That
door can optionally also be driven by GitHub Actions on every tag push,
so a release ships as soon as you `git push --tags`, with no laptop
involved.

**What `./infra/up ci-setup` does:** generates a fresh ed25519 key pair,
held only in RAM on your machine (never written to your disk), and pushes
the PRIVATE half straight into a **repository-level** GitHub Actions secret
(`STACK_DEPLOY_KEY`) — repo-level, not organization-level, because this
GitHub plan has no org-level secrets/variables to use instead. The PUBLIC
half is written to `infra/keys/ci-deploy.pub`, which you commit like any
other key. `ci-setup` needs the [`gh` CLI](https://cli.github.com),
authenticated (`gh auth login`).

**Turn it on** (three commands):

```bash
./infra/up ci-setup
git add infra/keys/ci-deploy.pub && git commit -m "ci: add the CI deploy key"
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

**Rotate it** with `./infra/up ci-setup --rotate`, then commit the new
`infra/keys/ci-deploy.pub` and run `./infra/up` — the OLD key keeps working
on every server until that `./infra/up` has actually completed (it's what
removes the old key from `stackbase.deploy.keys`), so there's no window
where deploys are broken mid-rotation.

**Turn it off:**

```bash
rm infra/keys/ci-deploy.pub
./infra/up                                        # removes the key from every server
gh secret delete STACK_DEPLOY_KEY --repo <owner>/<repo>
```

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
`.env.example` for anything else it expects. Do **not** put `SOCKET_PATH` in
`app_env` — the systemd unit sets that itself, per color.

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

## When it fails

Every failure is one line: what went wrong, then what to check.

| The error says | What to do |
|---|---|
| `secrets.age not found` | Do step 4 above — the message includes the exact command |
| `failed to decrypt …/secrets.age` | Your age key isn't a recipient yet. Ask a teammate to re-encrypt it for you |
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

> **To be confirmed when the repository is published:**
> `templates/infra/flake.nix` pins `inputs.stack-base.url` to
> `github:matiboy/stack-base`. That URL is a placeholder — update it (and
> re-lock) once the real location is known. It appears in exactly one place.

## What the files are

| File | |
|---|---|
| `stack.toml` | What you want. The only file you normally edit |
| `keys/*.pub` | Everyone's SSH public key. Commit |
| `age-recipients.txt` | Everyone's age public key — who can read the secrets. Commit |
| `secrets.age` | The encrypted API tokens, TLS key and the app's own `app_env`. Commit (it's encrypted) |
| `stack.state.json` | What stack-base has done so far — addresses, record ids, fingerprints. Written for you: commit it, don't edit it. The servers' configuration is built from `stack.toml` alone, so nothing in here changes what gets installed |
| `known_hosts` | The servers' SSH fingerprints. Commit |
| `nodes/<name>/` | Each server's own disk and boot settings, copied off the machine. Commit |
| `nodes/<name>/extra.nix` | Optional, yours: anything specific to one server |
| `flake.nix`, `flake.lock` | Which version of stack-base this project uses. Commit |

`stack.state.json` contains the servers' real IPs — if this repository is
public, so is the origin address (nginx still refuses any connection that
doesn't arrive via Cloudflare, but SSH is reachable at that address).
