# Packaging (Debian/Ubuntu `.deb`)

A `.deb` is built with [`cargo-deb`](https://github.com/kornelski/cargo-deb)
from the `[package.metadata.deb]` block in `Cargo.toml` plus the files in this
directory. CI builds and attaches it to each `v*` release; to build locally:

```sh
sudo apt-get install -y pkg-config libfuse3-dev      # build deps
cargo install cargo-deb
cargo deb                                            # -> target/debian/file-guard_*.deb
```

## What it installs

| Path | Purpose |
|---|---|
| `/usr/bin/file-guard` | the binary |
| `/lib/systemd/system/file-guard.service` | root daemon (system service) |
| `/lib/systemd/user/file-guard-agent.service` | per-user prompt agent |
| `/etc/file-guard/config.toml` | config (conffile; guards nothing by default) |
| `/etc/default/file-guard` | daemon environment (set `FILE_GUARD_USER`) |

Runtime deps: `fuse3` (provides the `fusermount3` helper + `libfuse3`).
Recommends: `zenity` and `libnotify-bin` for GUI prompts / notifications.

Nothing is enabled or started on install — guarding real credentials is an
explicit opt-in.

## Setup

1. Tell the daemon which user it guards:
   ```sh
   echo 'FILE_GUARD_USER=alice' | sudo tee -a /etc/default/file-guard
   ```
2. Add the files to guard in `/etc/file-guard/config.toml` (`[[watch]]` blocks).
3. Start the per-user agent **as that user** (renders prompts in the desktop):
   ```sh
   systemctl --user enable --now file-guard-agent.service
   ```
4. Start the daemon:
   ```sh
   sudo systemctl enable --now file-guard.service
   ```

## Security tiers (read this)

This package wires the **convenient desktop** topology: the agent is a per-user
service and its socket lives in the user's runtime dir. GUI prompts work out of
the box, but a determined **same-uid** attacker could occupy that socket and
self-approve prompts — so it is *defense-in-depth against opportunistic malware*,
not a hard boundary against a targeted same-uid attacker.

The **hardened** topology (root-created socket via systemd socket activation, so
the socket name can't be hijacked) is what the NixOS module ships. To replicate
it here, run the agent as a `User=` system service fed by a root-owned
`file-guard-agent.socket` — see the NixOS module in `flake.nix` for the exact
unit shapes.

The daemon's own protection (root-owned store, unreadable by the guarded user)
requires it to run as **root**, which the system service does.
