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

**4. Create the secrets file.** Set the two variables, then run the command
as-is. `CLOUDFLARE_TOKEN` is optional — leave it empty (`CLOUDFLARE_TOKEN=`)
to skip DNS and the TLS origin certificate for now; the server is still
provisioned, just reachable by IP/SSH only until you add the token and run
`./infra/up` again:

```bash
HOSTINGER_TOKEN=<paste here>
CLOUDFLARE_TOKEN=<paste here, or leave empty>
printf '{"hostinger_token": "%s", "cloudflare_token": "%s"}' \
  "$HOSTINGER_TOKEN" "$CLOUDFLARE_TOKEN" \
  | age -R infra/age-recipients.txt -o infra/secrets.age
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
on the next rebuild. Remove their line from `age-recipients.txt` and
re-encrypt `secrets.age` too — and rotate the tokens, since they have seen
them.

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
| `secrets.age` | The encrypted API tokens and TLS key. Commit (it's encrypted) |
| `stack.state.json` | What stack-base has done so far — addresses, record ids, fingerprints. Written for you: commit it, don't edit it. The servers' configuration is built from `stack.toml` alone, so nothing in here changes what gets installed |
| `known_hosts` | The servers' SSH fingerprints. Commit |
| `nodes/<name>/` | Each server's own disk and boot settings, copied off the machine. Commit |
| `nodes/<name>/extra.nix` | Optional, yours: anything specific to one server |
| `flake.nix`, `flake.lock` | Which version of stack-base this project uses. Commit |

`stack.state.json` contains the servers' real IPs — if this repository is
public, so is the origin address (nginx still refuses any connection that
doesn't arrive via Cloudflare, but SSH is reachable at that address).
