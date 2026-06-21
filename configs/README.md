# Sample configs

Drop-in `[[watch]]` / `[[rule]]` blocks for common credential-bearing tools.
file-guard reads a **single** config file (it has no `include` mechanism yet), so
compose the tools you want by concatenating the blocks you need:

```sh
# build /etc/file-guard/config.toml from the pieces you want
{ cat configs/_settings.toml
  cat configs/aws.toml
  cat configs/gcloud.toml
  cat configs/claude.toml
} | sudo tee /etc/file-guard/config.toml
```

Or just start from the curated [`../config.example.toml`](../config.example.toml).

## Rules and binary paths

A rule matches on the caller's **resolved** executable path (`readlink
/proc/<pid>/exe`), the access **direction** (`access = "read"` by default, or
`"write"`/`"any"`), and — when present — the binary's pinned `sha256`. The
example rules use conventional paths like `/usr/bin/aws` and are read-only.
Adjust them to your system — or delete them and let the daemon prompt you, then
pick **Allow always**, which records the real path, direction, and current hash
automatically.

> **Nix / home-manager:** the resolved path is a `/nix/store/<hash>-pkg/bin/<tool>`
> path that changes on every package update. A hash-pinned rule **re-prompts**
> after an upgrade (by design) — just re-confirm. Capture rules via the prompt so
> they're pinned. Note also that home-manager-managed cred files are often
> **symlinks into the read-only Nix store** (e.g. `~/.npmrc`); file-guard now
> **refuses** to guard a symlinked path — point the watch at the real file.

## What these files guard

| File              | Protects                                                            |
|-------------------|---------------------------------------------------------------------|
| `aws.toml`        | `~/.aws/credentials`                                                 |
| `gcloud.toml`     | gcloud ADC + `credentials.db` + `access_tokens.db`                  |
| `claude.toml`     | `~/.claude/.credentials.json` (Claude Code OAuth token)            |
| `ssh.toml`        | `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`                               |
| `docker.toml`     | `~/.docker/config.json` (registry auth)                            |
| `kubernetes.toml` | `~/.kube/config`                                                    |
| `github.toml`     | `~/.config/gh/hosts.yml` (gh token)                               |
| `npm.toml`        | `~/.npmrc` (registry tokens)                                       |
