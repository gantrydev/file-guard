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
> **Status: early / Linux-only.** The macOS Endpoint Security backend is not
> built (see [macOS](#macos)), and the Linux protection only holds in the
> **privileged (root) deployment** described below. Read
> [Security model & limitations](#security-model--limitations) before relying on
> it.

## How it works

For each watched file, file-guard moves the real contents into a backing store
and serves the original path through an interception layer. On every `open()` it
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

(A macOS Endpoint Security backend exists in-tree but is not built - see
[macOS](#macos).)

### Identity: pinned by content hash

A transient grant ("allow once / this session") is bound to the **exact process
instance** (pid + start time), so a recycled PID can't inherit it. A permanent
"allow always" rule **pins the binary's sha256** (and, on macOS, its code
signature). If that binary later changes - a package upgrade, or malware swapped
in its place - the pin no longer matches and file-guard **re-prompts** rather
than silently honoring the old grant. (A mismatch re-prompts; it is not a hard
deny, so a legitimate rebuild just re-authorizes.)

### Prompts: the session agent

The root daemon has no terminal or display, so it doesn't draw prompts itself -
it asks a small **session agent** (`file-guard agent`) running as you, over a
unix socket. The agent renders the prompt (GUI via `zenity`/`kdialog`, a terminal
fallback, or a desktop notification) and returns your choice. If the agent is
unreachable, the daemon applies `default_action` (deny by default) - it never
blocks. See [the agent socket note](#security-model--limitations) for why the
socket is root-anchored.

## Install

Requires Nix with flakes.

```sh
# Try it without installing
nix run github:gantryops/file-guard -- --help

# Dev shell (cargo, rustc, clippy, rustfmt, fuse3 wired for pkg-config)
nix develop
cargo build

# Build the binary
nix build github:gantryops/file-guard
./result/bin/file-guard --help
```

Non-Nix Linux builds need `pkg-config` and `libfuse3` (Debian/Ubuntu: `fuse3`,
`libfuse3-dev`) plus a Rust toolchain, then `cargo build --release`.

## Quick start

### 1. Write a config

Start from [`config.example.toml`](config.example.toml), or compose per-tool
blocks from [`configs/`](configs/):

```sh
{ cat configs/_settings.toml configs/aws.toml configs/gcloud.toml configs/claude.toml; } \
  | sudo tee /etc/file-guard/config.toml
```

### 2a. Development (your own user - NOT secure, see limitations)

```sh
FILE_GUARD_CONFIG=~/.config/file-guard/config.toml file-guard start
```

Runs in the foreground; unknown accesses prompt you in the terminal. Useful to
see what touches your secrets, but the backing store is readable by your own user
(so same-uid malware can bypass it). For real protection use 2b.

### 2b. Privileged daemon (NixOS module - the supported secure deployment)

Add the flake and enable the module. The daemon runs as **root**, so the backing
store at `/var/lib/file-guard` is root-owned and unreadable by the user the
malware is running as:

```nix
# flake.nix
{
  inputs.file-guard.url = "github:gantryops/file-guard";
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
  promptMethod = "gui";                       # default: "notification"
  agentEnvironment = {                        # so dialogs reach alice's display
    DISPLAY = ":0";
    XAUTHORITY = "/home/alice/.Xauthority";
    DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/1000/bus";
  };
};
```

The agent's socket is created by **root** (systemd socket activation) in a
root-owned directory, so a same-uid attacker can neither hijack the socket name
nor connect to it. With `promptMethod = "notification"` (the default) prompts are
informational only and unknown accesses deny on timeout - define explicit
`[[rule]]`s for that mode.

To try the GUI prompt path by hand (dev), run the agent in your graphical session
and the daemon alongside it (both as the same user resolve the same socket):

```sh
file-guard agent --method gui &                 # renders prompts in your session
FILE_GUARD_CONFIG=~/.config/file-guard/config.toml file-guard start
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
file-guard start [-d]          # start the daemon (foreground; -d is a no-op for now)
file-guard agent [--method M] [--socket P]   # run the session prompt agent
file-guard rules               # list rules
file-guard store <f>           # move a file into the backing store
file-guard restore <f>         # restore a file from the backing store
file-guard stop|status|log|rules add|rules remove   # not implemented yet (exit non-zero)
```

## Security model & limitations

**Threat model:** non-root malware running as *you* (a poisoned dependency),
trying to read or write credential files. **Not** in scope: a root attacker (root
bypasses FUSE and can read anything), a process with `ptrace` over your session
(it can drive the agent or any of your processes), or network exfiltration.

Known limitations - read before relying on this:

- **Run it privileged, or it does nothing on Linux.** The backing store must be
  owned by a *different* uid than the guarded user; otherwise the same malware
  just reads the store directly. The NixOS module runs the daemon as root for
  this reason. Running as your own user is development-only.
- **The prompt agent must be root-anchored to be trustworthy.** If same-uid
  malware can occupy the agent's socket, it can auto-approve its own prompts. The
  NixOS module prevents this by having **root** create the socket (systemd socket
  activation) in a root-owned directory. The manual/dev path
  (`file-guard agent` self-binding in `$XDG_RUNTIME_DIR`) is **not** hardened
  against same-uid impersonation - use it for testing, not protection.
- **Linux only.** The macOS Endpoint Security path is not built - see
  [macOS](#macos).
- **Identity = binary hash (+ script path for interpreters); a trusted tool's
  own deps are still inside the boundary.** A rule pins the caller's binary
  sha256, and for interpreters (python/node/…) also the **script path** from
  argv - so "python running gcloud" doesn't authorize "python running something
  else". Two caveats remain: the script comes from argv, which a *deliberate*
  impersonator can forge (it's defense-in-depth, strongest against opportunistic
  disk-scanning malware, not a hard boundary); and nothing can stop a compromised
  dependency *inside* the legitimate tool from reading the secret that tool is
  authorized to use. Strongest for compiled tools, where the binary *is* the
  identity.
- **Nix/home-manager:** the resolved path is a `/nix/store/<hash>` path that
  changes on every package update. Hash-pinned rules **re-prompt** after an
  upgrade (by design) - just re-confirm. Credential files that are **symlinks**
  (e.g. `~/.npmrc` into the read-only Nix store) are now **refused** rather than
  clobbered; point the watch at the real file.
- **GUI needs a session.** Under systemd, GUI prompts only appear if the agent is
  given the user's display env (`agentEnvironment`); otherwise it falls back to
  notification/terminal and unknown accesses deny on timeout.
- **Writes are last-writer-wins.** Concurrent write handles to the same file
  don't merge; the last one to close persists its buffer. Fine for the
  single-writer credential-file case.

## Implementation status

| Area                                   | State                         |
|----------------------------------------|-------------------------------|
| Linux FUSE interception (read + write)  | works                         |
| macOS Endpoint Security                 | not built (backend in-tree)   |
| Direction-aware policy (read vs write)  | works                         |
| Process-instance grants (pid+start time)| works                         |
| Binary hash / signature pinning         | works (Linux hash; macOS sig pending ES) |
| Session prompt agent + IPC              | works                         |
| Prompt: GUI (zenity/kdialog)            | works                         |
| Prompt: terminal / notification         | works                         |
| Backing store: moved originals          | works                         |
| Backing store: age-encrypted / `op`     | not implemented               |
| `stop` / `status` / `log` / `rules add` | not implemented               |
| Structured audit log to file/syslog     | not implemented (tracing only)|
| Tests                                   | unit-level                    |

## Development

```sh
nix develop
cargo build
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
```

CI runs the above on Linux for every push/PR.

## macOS

A macOS Endpoint Security backend exists in the tree (`src/es.rs`,
`src/process/macos.rs`) but is not built: it is excluded from the flake/CI and is
not wired to the current policy/agent. Finishing it needs the `es_message_t`
layout fix and the `start_time` offset fix, and - to run at all - an Endpoint
Security entitlement from Apple plus a signed, notarized binary running as root.
The policy, rules, identity pinning, and prompt agent are already
cross-platform, so the macOS work is wiring up enforcement, not a rewrite.

## License

MIT - see [LICENSE](LICENSE).
