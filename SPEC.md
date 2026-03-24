# cred-guard

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

`cred-guard` replaces watched credential files with FUSE mounts. The
original file is moved to a secure backing store before mounting. The FUSE
mount sits at the original path so consuming tools (terraform, aws, ssh)
require no reconfiguration.

```
~/.aws/credentials          ← FUSE-mounted (served by cred-guard)
~/.ssh/id_ed25519           ← FUSE-mounted
~/.config/gcloud/adc.json   ← FUSE-mounted
```

When cred-guard starts, for each watched file:
1. Move the original file to the backing store (if not already stored).
2. Mount a FUSE file at the original path.
3. Begin serving requests.

When cred-guard stops:
1. Unmount all FUSE files.
2. Optionally restore the originals (configurable).

### Access control

On every `open()` / `read()` of a watched file:

1. Retrieve the calling process PID from the FUSE request.
2. Resolve the PID to its binary path:
   - macOS: `proc_pidpath()`
   - Linux: `readlink /proc/<PID>/exe`
3. Look up the binary path in the policy for that file.
4. Decision:

| Policy state       | Action                                      |
|---------------------|---------------------------------------------|
| Allowed (always)    | Return file contents immediately.           |
| Denied (always)     | Return `EACCES`.                            |
| Allowed (this session) | Return file contents.                    |
| Unknown             | Prompt the user, then act on their choice.  |

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
- **Allow this session** — allow until cred-guard restarts.
- **Deny once** — block this read, ask again next time.
- **Deny always** — add to the permanent denylist for this file.

The prompt has a **configurable timeout** (default: 30 seconds). If the
user does not respond, the default action is **deny**.

### Prompt delivery

The prompt must be visible regardless of where the user is working. Multiple
delivery methods, used concurrently:

1. **Native OS notification** — macOS: `osascript` / UserNotifications.
   Linux: `notify-send` / D-Bus.
2. **Terminal popup** — a TUI rendered in the cred-guard foreground process
   or a dedicated pane. This is the primary interaction method for terminal
   users.
3. **GUI dialog** (optional) — a small window with the process info and
   buttons for the five choices.

At least one prompt method must support receiving the user's response (not
just display). The terminal and GUI methods support this natively; the
notification method is informational only (shows what happened after the
decision is made via another method, or after timeout/deny).

## Configuration

A single config file: `~/.config/cred-guard/config.toml`

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
   cred-guard. Decrypted only into memory at daemon startup (passphrase or
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
cred-guard start              # start the daemon (foreground)
cred-guard start -d           # start the daemon (background, via launchd/systemd)
cred-guard stop               # unmount all, stop daemon
cred-guard status             # show watched files, mount state, recent access
cred-guard log                # tail the access log
cred-guard rules              # list all current rules
cred-guard rules add          # interactively add a rule
cred-guard rules remove       # remove a rule
cred-guard store <file>       # move a credential file into the backing store
cred-guard restore <file>     # restore a file from the backing store to disk
```

## Edge cases

### Daemon crash
The FUSE mount becomes stale (EIO / ENOTCONN). The original file is NOT
exposed because it was moved to the backing store. A process supervisor
(launchd / systemd) should auto-restart the daemon and re-mount.
Consuming tools will fail during the brief restart window — this is
acceptable and safer than exposing credentials.

### Symlinked files (e.g. Nix / Home Manager)
If a watched path is a symlink, cred-guard follows the symlink and mounts
over the **target** file. The symlink continues to point to the now
FUSE-mounted target. This requires special handling if the target is in a
read-only Nix store — in that case, the symlink itself should be replaced
with a FUSE mount (remove symlink, mount at that path).

### PID recycling
A PID can be reused after a process exits. To prevent a new process from
inheriting a previous process's "allow once" / "allow this session" grant,
the daemon must track PID + process start time (available from procfs /
sysctl) as the unique process identity.

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
- Write protection (credential files are served read-only).
- Network monitoring (use Little Snitch / LuLu for that).
- Replacing secret managers — cred-guard is an access control layer that
  works *in front of* any backend.

## Platforms

- macOS (via macFUSE)
- Linux (via kernel FUSE)
