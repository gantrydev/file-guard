# file-guard

A FUSE-based credential access control daemon that protects sensitive files
by requiring per-process authorization before granting read access.

Think "Little Snitch for file reads."

## Problem

Any process running as your user can read credential files
(`~/.aws/credentials`, `~/.ssh/id_ed25519`, etc.). A compromised dependency
(e.g. a malicious `.pth` file in a supply-chain attack) can silently
exfiltrate all your secrets.

File permissions do not help — the malicious code runs as you.

## Goal

Only processes you explicitly trust can read your credentials. Unknown
processes trigger a user prompt. Denied processes get an error — no data.

## Behaviour

### Mounting

`file-guard` replaces watched credential files with FUSE mounts. The
original file is moved to a secure backing store before mounting. The FUSE
mount sits at the original path so consuming tools (terraform, aws, ssh)
require no reconfiguration.

```
~/.aws/credentials          ← FUSE-mounted (served by file-guard)
~/.ssh/id_ed25519           ← FUSE-mounted
~/.config/gcloud/adc.json   ← FUSE-mounted
```

When file-guard starts, for each watched file:
1. Move the original file to the backing store (if not already stored).
2. Mount a FUSE file at the original path.
3. Begin serving requests.

When file-guard stops:
1. Unmount all FUSE files.
2. Optionally restore the originals (configurable).

### Access control

On every `open()` of a watched file:

1. Retrieve the calling process PID from the FUSE request.
2. Resolve the PID to its binary path:
   - macOS: `proc_pidpath()`
   - Linux: `readlink /proc/<PID>/exe`
3. Determine the **direction** from the open flags (read vs write).
4. Look up the policy for `(file, binary, direction)`, verifying the binary's
   pinned identity (sha256 / macOS signature) where the rule has one.
5. Decision:

| Policy state       | Action                                      |
|---------------------|---------------------------------------------|
| Allowed (always)    | Serve (read) / accept (write) immediately.  |
| Denied (always)     | Return `EACCES`.                            |
| Allowed (this session) | Serve / accept.                          |
| Unknown             | Prompt the user, then act on their choice.  |

A rule is direction-scoped: a `read` rule does not authorize writes. A
persistent rule pins the binary's content hash; if the binary later changes, the
pin no longer matches and the access re-prompts (it is not treated as a deny).
Transient ("once" / "this session") grants are bound to the exact process
instance (pid + start time).

### Writes

The mount is read-write. A write `open()` is gated exactly like a read, in the
`write` direction. Authorized writes are buffered per file handle and persisted
to the backing store on `flush`/`fsync`/`release`; `truncate` is gated as a
write. An unauthorized write handle (or `truncate`) gets `EACCES`.

### Prompting

When an unknown process tries to read a watched file, the user sees a
prompt with:

- **Process name** and full binary path (e.g. `/usr/bin/python3.12`)
- **Parent process** chain (e.g. `python ← bash ← Terminal.app`)
- **File** being accessed (e.g. `~/.aws/credentials`)
- **Code signature** (macOS only, if signed)

The user chooses one of:

- **Allow once** — permit this single read, ask again next time.
- **Allow always** — add the binary path to the permanent allowlist for this file.
- **Allow this session** — allow until file-guard restarts.
- **Deny once** — block this read, ask again next time.
- **Deny always** — add to the permanent denylist for this file.

The prompt has a **configurable timeout** (default: 30 seconds). If the
user does not respond, the default action is **deny**.

### Prompt delivery

The enforcing daemon runs privileged and may have no terminal or display, so it
does not render prompts itself. A separate **session agent** (`file-guard agent`)
runs as the guarded user and renders prompts; the daemon asks it for a decision
over a unix socket (one JSON request/response per connection). The agent
serializes rendering so only one dialog is ever live.

Methods (selected by `prompt_method`, rendered by the agent):

1. **GUI dialog** — `zenity` / `kdialog` on Linux (argv only, never shell/AppleScript
   interpolation); falls back to the terminal, then to the daemon's
   `default_action`.
2. **Terminal** — an stdin prompt on the agent's tty.
3. **Notification** — `notify-send` (Linux) / `osascript` (macOS); informational
   only, so unknown accesses resolve to `default_action` on timeout.

**Socket trust:** so that same-uid malware cannot impersonate the agent and
self-approve, the listening socket must be created by a different uid — in the
supported deployment, **root** via systemd socket activation, in a root-owned
directory. Both ends verify peer credentials. The dev path (the agent
self-binding in `$XDG_RUNTIME_DIR`) is not hardened against same-uid
impersonation.

## Configuration

A single config file: `~/.config/file-guard/config.toml`

```toml
# Global settings
[settings]
default_action = "deny"       # "allow" | "deny" — when prompt times out
prompt_timeout = 30           # seconds
prompt_method = "terminal"    # "terminal" | "gui" | "notification"
restore_on_stop = false       # restore original files when daemon stops

# Files to protect
[[watch]]
path = "~/.aws/credentials"

[[watch]]
path = "~/.aws/config"

[[watch]]
path = "~/.ssh/id_ed25519"

[[watch]]
path = "~/.ssh/id_rsa"

[[watch]]
path = "~/.ssh/config"

[[watch]]
path = "~/.config/gcloud/application_default_credentials.json"

[[watch]]
path = "~/.docker/config.json"

[[watch]]
path = "~/.netrc"

[[watch]]
path = "~/.npmrc"

[[watch]]
path = "~/.pypirc"

# Per-file policy overrides
[[watch]]
path = "~/.gitconfig"
default_action = "allow"      # low-sensitivity, allow by default

# Pre-defined rules (can also be built up via prompts)
[[rule]]
file = "~/.aws/credentials"
binary = "/opt/homebrew/bin/terraform"
action = "allow"

[[rule]]
file = "~/.aws/credentials"
binary = "/opt/homebrew/bin/aws"
action = "allow"

[[rule]]
file = "~/.config/gcloud/application_default_credentials.json"
binary = "/opt/homebrew/bin/terraform"
action = "allow"

[[rule]]
file = "~/.config/gcloud/application_default_credentials.json"
binary = "/opt/homebrew/bin/gcloud"
action = "allow"

[[rule]]
file = "~/.ssh/id_ed25519"
binary = "/usr/bin/ssh"
action = "allow"

[[rule]]
file = "~/.ssh/id_ed25519"
binary = "/usr/bin/git"
action = "allow"
```

Rules created via "allow always" / "deny always" prompts are appended to
this file automatically.

## Backing store

The real credential contents must be stored somewhere the daemon can read
but regular filesystem access cannot reach. Options (in order of preference):

1. **Backend integration** — fetch from 1Password (`op`), macOS Keychain,
   `pass`, `age`-encrypted files, etc. The file never sits in plaintext
   outside the FUSE response.
2. **Encrypted local store** — an `age`-encrypted directory managed by
   file-guard. Decrypted only into memory at daemon startup (passphrase or
   hardware key).
3. **Moved originals** — the original files moved to a root-owned directory
   with `700` permissions (weakest option, but simplest).

The backing store is pluggable. The daemon only needs a trait:

```
read(file_id) -> bytes
store(file_id, bytes)
delete(file_id)
list() -> [file_id]
```

## Logging

All access attempts are logged:

```
2026-03-24T10:15:03Z ALLOW ~/.aws/credentials ← /opt/homebrew/bin/terraform (pid 42381)
2026-03-24T10:15:07Z PROMPT ~/.ssh/id_ed25519 ← /usr/bin/python3.12 (pid 42399)
2026-03-24T10:15:12Z DENY ~/.ssh/id_ed25519 ← /usr/bin/python3.12 (pid 42399) [user denied]
2026-03-24T10:15:12Z DENY ~/.ssh/id_ed25519 ← /usr/bin/python3.12 (pid 42399) [timeout]
```

Log destination is configurable: file, stdout, or syslog.

## CLI

```
file-guard start              # start the daemon (foreground)
file-guard start -d           # start the daemon (background, via launchd/systemd)
file-guard agent              # run the session prompt agent (renders prompts)
file-guard stop               # unmount all, stop daemon
file-guard status             # show watched files, mount state, recent access
file-guard log                # tail the access log
file-guard rules              # list all current rules
file-guard rules add          # interactively add a rule
file-guard rules remove       # remove a rule
file-guard store <file>       # move a credential file into the backing store
file-guard restore <file>     # restore a file from the backing store to disk
```

## Edge cases

### Daemon crash
The FUSE mount becomes stale (EIO / ENOTCONN). The original file is NOT
exposed because it was moved to the backing store. A process supervisor
(launchd / systemd) should auto-restart the daemon and re-mount.
Consuming tools will fail during the brief restart window — this is
acceptable and safer than exposing credentials.

### Symlinked files (e.g. Nix / Home Manager)
file-guard **refuses** to guard a symlinked watched path (it would otherwise
follow/clobber an unintended target, e.g. a read-only Nix store file). Point the
watch at the real file. Following the symlink target safely is deferred.

### PID recycling
A PID can be reused after a process exits. Transient ("allow once" / "allow this
session") grants are keyed on PID **plus process start time** (procfs / sysctl),
so a recycled PID does not inherit a previous process's grant.

### Binary changed since the rule was pinned
A persistent rule pins the binary's sha256 (and macOS signature). If the binary
at that path changes — an upgrade, or a swapped-in attacker binary — the pin no
longer matches: the rule is skipped and the access **re-prompts**. It is not a
hard deny, so a legitimate rebuild simply re-authorizes.

### Child processes
A rule allowing `/usr/bin/terraform` does NOT automatically allow a child
process terraform spawns (e.g. a provider plugin). Each binary path is
evaluated independently. Users can add additional rules as prompted.

### Multiple reads
Once a process is allowed for a file (via "allow once"), subsequent
`read()` calls within the same `open()`—`close()` cycle are served
without re-prompting. The authorization is per file-descriptor, not per
`read()` syscall.

### Concurrent access
Multiple processes can read different (or the same) watched files
simultaneously. FUSE handles this natively via its multi-threaded request
dispatch.

## Non-goals

- Protecting against root-level attackers (root bypasses FUSE).
- Protecting against an attacker who can `ptrace` your session (it can drive the
  prompt agent or any of your processes).
- Network monitoring (use Little Snitch / LuLu for that).
- Replacing secret managers — file-guard is an access control layer that
  works *in front of* any backend.

## Platforms

- **Linux** (via kernel FUSE) — the supported platform.
- **macOS** (via Endpoint Security) — backend exists in-tree but not built;
  pending the ES layout fix and an Apple entitlement. See the README "macOS".
