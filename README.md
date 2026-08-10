# file-guard

Per-process access control for credential files. *Little Snitch, but for file reads.*

Any process running as you can read `~/.aws/credentials`, `~/.config/gcloud/...`,
`~/.claude/.credentials.json`, your SSH keys - and exfiltrate them. File
permissions don't help: the malicious code **runs as you**. This is the
supply-chain secret-theft problem: one poisoned dependency reads every secret on
disk.

A password manager (1Password, `pass`, …) solves this for tools that accept
injected env vars (`op run`, `.envrc` + `op read`). But many tools **write
plaintext credentials to disk and read them back themselves** - `gcloud`, `aws`,
`docker login`, `kubectl`, `gh`, the Claude Code CLI. You can't keep those only
in a vault. file-guard sits in front of those on-disk files and only lets
processes **you've authorized** read *and write* them; everything else is denied
(or prompted).

> [!WARNING]
> **Status: early / Linux-only.** The protection only holds in the
> **privileged (root) deployment** described below. Read
> [Security model & limitations](#security-model--limitations) before relying on
> it.

## How it works

For each watched file, file-guard commits a complete snapshot to a private
SQLite database before replacing the path with a FUSE endpoint. On every `open()` it
resolves the **calling process** and consults your policy, in the **direction**
of the access (read vs write):

| Policy state            | Action                                   |
|-------------------------|------------------------------------------|
| Allowed (rule)          | serve / accept the real contents         |
| Denied (rule)           | return `EACCES`                          |
| Allowed (this session)  | serve / accept the real contents         |
| Unknown                 | prompt you (or fall back to `default_action`) |

A read-write FUSE file is mounted at the original path; the caller PID comes from
the FUSE request and is resolved via `/proc/<pid>/exe`. Reads serve the stored
contents; authorized writes are buffered and persisted back to the store on
close. Consuming tools need no reconfiguration: the path they read/write is
unchanged.

### Identity: pinned by content hash

A transient grant ("allow once / this session") is bound to the **exact process
instance** (pid + start time), so a recycled PID can't inherit it. A permanent
"allow always" rule **pins the binary's sha256**; for an interpreter it also
pins the **entry script's path and content hash**, so "python running gcloud"
doesn't bless other scripts and an
in-place edit of the script re-prompts. If a pinned binary or script later
changes - a package upgrade, or malware swapped in its place - the pin no longer
matches and file-guard **re-prompts** rather than silently honoring the old
grant. (A mismatch re-prompts; it is not a hard deny, so a legitimate rebuild
just re-authorizes.)

### Prompts: the session agent

The root daemon has no terminal or display, so it doesn't draw prompts itself -
it asks a small **session agent** (`file-guard agent`) running as you, over a
unix socket. The agent renders the prompt (GUI via `zenity`/`kdialog`, a terminal
fallback) and returns your choice. It can also send a desktop notification
alongside any prompt. If the agent is
unreachable, the daemon applies `default_action` (deny by default) - it never
blocks. See [the agent socket note](#security-model--limitations) for why the
socket is root-anchored.

## Install

### Debian / Ubuntu

Grab the `.deb` from a [release](https://github.com/gantrydev/file-guard/releases):

```sh
sudo apt install ./file-guard_*_amd64.deb
```

It installs the binary, a root `file-guard.service`, and a socket-activated
`file-guard-agent@.service` whose listening socket is created by root (the
hardened topology), and pulls in `fuse3`. Nothing is enabled until you configure
it - see [2b](#2b-privileged-daemon-the-secure-deployment) and
[`packaging/README.md`](packaging/README.md).

### Nix

```sh
# Try it without installing
nix run github:gantrydev/file-guard -- --help

# Dev shell (cargo, rustc, clippy, rustfmt, fuse3 wired for pkg-config)
nix develop
cargo build

# Build the binary
nix build github:gantrydev/file-guard
./result/bin/file-guard --help
```

### From source

Any Linux with `pkg-config` and `libfuse3` (Debian/Ubuntu: `fuse3`,
`libfuse3-dev`) plus a Rust toolchain, then `cargo build --release`.

## Quick start

### 1. Write a config

Start from [`config.example.toml`](config.example.toml), or compose per-tool
blocks from [`configs/`](configs/):

```sh
{ cat configs/_settings.toml configs/aws.toml configs/gcloud.toml configs/claude.toml; } \
  | sudo tee /etc/file-guard/config.toml
```

### 2a. Development

```sh
sudo install -d -m 0700 /var/lib/file-guard-dev
sudo env \
  FILE_GUARD_CONFIG="$HOME/.config/file-guard/config.toml" \
  FILE_GUARD_STORE_DIR=/var/lib/file-guard-dev/store \
  target/debug/file-guard start
```

Storage v2 deliberately refuses to run the credential store as the guarded
user. Development runs in the foreground as root with a separate root-owned
store; unknown accesses can still prompt in the terminal. Use 2b for a managed
deployment.

### 2b. Privileged daemon (the secure deployment)

Run the daemon as **root** so the backing store at `/var/lib/file-guard` is
root-owned and unreadable by the user the malware runs as. **Both the Debian
package and the NixOS module do this** - that root-owned store is the protection
that matters, and **both root-anchor the prompt agent's socket by default**
(created by root via systemd socket activation, so a same-uid attacker can't
hijack it; see [the agent-socket note](#security-model--limitations)).

**Debian / Ubuntu.** After installing the `.deb` (replace `alice`):

```sh
echo 'FILE_GUARD_USER=alice' | sudo tee -a /etc/default/file-guard   # whose ~ is guarded
sudoedit /etc/file-guard/config.toml                                 # add [[watch]] blocks
sudo systemctl enable --now file-guard-agent@alice.socket            # root-anchored socket
sudo systemctl edit file-guard-agent@alice.service                   # add DISPLAY/XAUTHORITY/DBUS env
sudo systemctl enable --now file-guard.service
```

**NixOS.** Add the flake and enable the module:

```nix
# flake.nix
{
  inputs.file-guard.url = "github:gantrydev/file-guard";
  # …
}

# configuration.nix
{
  imports = [ inputs.file-guard.nixosModules.default ];
  services.file-guard = {
    enable = true;
    user = "alice";                              # whose ~ is guarded
    configFile = "/etc/file-guard/config.toml";  # paths use ~ → alice's home
  };
}
```

The module sets `programs.fuse.userAllowOther = true` so your tools can reach the
root-owned mounts, and wires a **socket-activated prompt agent** that runs as
`user`. For GUI prompts, point the agent at that user's session and switch the
method:

```nix
services.file-guard = {
  enable = true;
  user = "alice";
  configFile = "/etc/file-guard/config.toml";
  promptMethod = "gui";                       # default: "gui"
  notify = true;                               # optional desktop heads-up
  agentEnvironment = {                        # so dialogs reach alice's display
    DISPLAY = ":0";
    XAUTHORITY = "/home/alice/.Xauthority";
    DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/1000/bus";
  };
};
```

The agent's socket is created by **root** (systemd socket activation) in a
root-owned directory, so a same-uid attacker can neither hijack the socket name
nor connect to it. With `promptMethod = "log-only"`, prompts are non-interactive
and unknown accesses use `default_action` on timeout. Set `notify = true` for an
informational desktop notification in that mode. The old `"notification"`
value remains a compatibility alias for this combination.

To try the GUI prompt path by hand, run the agent in your graphical session and
point the root development daemon at the same socket and private store:

```sh
file-guard agent --method gui &
sudo install -d -m 0700 /var/lib/file-guard-dev
sudo env \
  FILE_GUARD_CONFIG="$HOME/.config/file-guard/config.toml" \
  FILE_GUARD_STORE_DIR=/var/lib/file-guard-dev/store \
  FILE_GUARD_AGENT_SOCKET="$XDG_RUNTIME_DIR/file-guard-agent.sock" \
  target/debug/file-guard start
```

## Configuration

A single TOML file (no `include` mechanism yet). See
[`config.example.toml`](config.example.toml) for the full annotated reference and
[`configs/`](configs/) for drop-in per-tool blocks (aws, gcloud, claude, ssh,
docker, kubernetes, github, npm).

Rules created via "Allow always" / "Deny always" prompts are appended to the
config automatically.

## CLI

```
file-guard start [-d]                  # run the daemon (foreground; -d is a no-op)
file-guard agent [--method M] [--socket P]   # run the session prompt agent
file-guard stop                        # SIGTERM the running daemon (unmounts cleanly)
file-guard status                      # daemon state, mount status, recent access
file-guard log [-n N] [-f]             # print/follow the audit log (needs a file
                                       #   log_destination; else use journalctl)
file-guard rules                       # list rules (with indices)
file-guard rules add --file F --binary B --action allow|deny [--access read|write|any] [--no-pin]
file-guard rules remove <index>        # remove the rule at INDEX (preserves comments)
file-guard store <f>                   # snapshot and remove a file for offline storage
file-guard restore <f>                 # restore a file from its snapshot
```

The audit log is NDJSON (one object per access) when `log_destination` is a file
path, so it's both human-readable via `file-guard log` and machine-queryable
(e.g. `jq` over the file).

## Security model & limitations

The crash/recovery states and exact durability ordering are documented in
[`docs/storage-v2.md`](docs/storage-v2.md).

**Threat model:** non-root malware running as *you* (a poisoned dependency),
trying to read or write credential files. **Not** in scope: a root attacker (root
bypasses FUSE and can read anything), a process with `ptrace` over your session
(it can drive the agent or any of your processes), or network exfiltration.

Known limitations - read before relying on this:

- **Run it privileged, or it does nothing on Linux.** The backing store must be
  owned by a *different* uid than the guarded user; otherwise the same malware
  just reads the store directly. Both the Debian package and the NixOS module run
  the daemon as root for this reason. Storage v2 refuses to open the production
  credential store as a non-root user.
- **The prompt agent must be root-anchored to be trustworthy** - and both
  packaged deployments make it so by default. If same-uid malware could occupy
  the agent's socket, it would auto-approve its own prompts; the NixOS module and
  the Debian package both prevent this by having **root** create the socket
  (systemd socket activation) at `/run/file-guard/agent.sock` in a root-owned
  directory (mode `0755`); the socket itself is mode `0600`. The only unhardened path is the dev-only
  `file-guard agent` self-bind in `$XDG_RUNTIME_DIR`, which warns loudly and is
  for testing, not protection.
- **Linux only.** FUSE and `/proc` are required.
- **Identity = binary hash (+ script path & content hash for interpreters); a
  trusted tool's own deps are still inside the boundary.** A rule pins the
  caller's binary sha256, and for interpreters (python/node/…) also the **script
  path** from argv and the **script's content hash** - so "python running gcloud"
  doesn't authorize "python running something else", and an in-place edit of the
  script re-prompts. Two caveats remain: the script *path* comes from argv, which
  a *deliberate* impersonator can forge (it's defense-in-depth, strongest against
  opportunistic disk-scanning malware, not a hard boundary); and nothing can stop
  a compromised dependency *inside* the legitimate tool from reading the secret
  that tool is authorized to use. Strongest for compiled tools, where the binary
  *is* the identity.
- **Nix/home-manager:** the resolved path is a `/nix/store/<hash>` path that
  changes on every package update. Hash-pinned rules **re-prompt** after an
  upgrade (by design) - just re-confirm. Credential files that are **symlinks**
  (e.g. `~/.npmrc` into the read-only Nix store) are now **refused** rather than
  clobbered; point the watch at the real file.
- **GUI needs a session.** Under systemd, GUI prompts only appear if the agent is
  given the user's display env (`agentEnvironment`); otherwise it falls back to
  the terminal and unknown accesses deny on timeout. Optional notifications also
  require a working desktop session bus.
- **Writes are last-writer-wins.** Concurrent write handles to the same file
  don't merge; the last one to close persists its buffer. Fine for the
  single-writer credential-file case.

## How it compares

file-guard occupies a specific niche: **per-access consent for credential files
that their own tools insist on reading from disk**, with the *tool left working
unchanged*. That's different from the usual suspects:

| Tool | Model | Where file-guard differs |
|---|---|---|
| **Landlock / AppArmor / SELinux** | static kernel MAC: a profile denies a process access up front | file-guard is *interactive consent* + per-binary **hash/script identity** that re-prompts on change; the guarded tool keeps working at its normal path instead of being statically denied. Landlock is also opt-in *by the process itself* - malware won't sandbox itself. |
| **bubblewrap / firejail / containers** | sandbox the *untrusted* program away from secrets | great when you can enumerate and wrap untrusted things - but the tools that **need** the creds (`aws`, `gcloud`) can't be sandboxed away from them. file-guard guards the *file* regardless of who opens it. |
| **1Password / `op run` / env injection** | inject secrets as env vars into tools that accept them | file-guard's niche is exactly the tools that **don't** - they write plaintext creds to disk and re-read them. It sits in front of any backend rather than replacing the vault. |
| **Short-lived creds / OIDC / hardware keys** | remove the long-lived on-disk secret entirely | the right fix where the provider supports it; file-guard guards the antipattern for the many tools that still keep a long-lived secret on disk. |

**What it deliberately does *not* do:** stop a compromised dependency running
*inside* a tool you've already authorized (it gets that tool's secret), defend
against root or a `ptrace`-capable same-uid process, or control network
exfiltration. For those, combine it with sandboxing and short-lived credentials -
file-guard shrinks the blast radius from *every secret on disk* to *the specific
file the specific authorized binary is allowed to touch*, it isn't a total
boundary.

## Development

```sh
nix develop
cargo build
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
```

CI runs the above on Linux for every push/PR.

## License

MIT - see [LICENSE](LICENSE).
