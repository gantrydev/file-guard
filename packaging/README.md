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
| `/lib/systemd/system/file-guard-agent@.socket` | root-anchored agent socket (per user) |
| `/lib/systemd/system/file-guard-agent@.service` | prompt agent, runs as the guarded user |
| `/usr/lib/tmpfiles.d/file-guard.conf` | creates root-owned `/run/file-guard` |
| `/etc/file-guard/config.toml` | config (conffile; guards nothing by default) |
| `/etc/default/file-guard` | daemon environment (set `FILE_GUARD_USER`) |

Runtime deps: `fuse3` (provides the `fusermount3` helper + `libfuse3`).
Recommends: `zenity` and `libnotify-bin` for GUI prompts / notifications.

Nothing is enabled or started on install - guarding real credentials is an
explicit opt-in.

## Release package integration test

Run the published `.deb` in a clean Ubuntu container:

```sh
scripts/test-deb-release.sh
```

The runner resolves the latest GitHub release, verifies its published SHA-256
digest, installs the amd64 package with `apt`, and checks its metadata, runtime
dependencies, files, modes, systemd units, tmpfiles rule, CLI behavior, and a
real SQLite/FUSE write, crash-restart, and restore lifecycle. Set
`FILE_GUARD_RELEASE_TAG=v0.1.17` to test a specific release. The FUSE test passes
`/dev/fuse` and `CAP_SYS_ADMIN` into the disposable container; set
`FILE_GUARD_REQUIRE_FUSE=0` to run only the package checks on a host without
FUSE. Before publishing, set `FILE_GUARD_DEB_PATH` and
`FILE_GUARD_RELEASE_TAG` to run the same checks against a local package.
Starting the units under systemd still requires a systemd PID 1 and is reported
as an explicit skip.

## Setup

Replace `alice` with the user whose credentials are guarded.

1. Tell the daemon which user it guards:
   ```sh
   echo 'FILE_GUARD_USER=alice' | sudo tee -a /etc/default/file-guard
   ```
2. Add the files to guard in `/etc/file-guard/config.toml` (`[[watch]]` blocks).
3. Enable the root-anchored agent socket for that user, and (for GUI prompts)
   give the agent the user's display:
   ```sh
   sudo systemctl enable --now file-guard-agent@alice.socket
   sudo systemctl edit file-guard-agent@alice.service   # add the [Service] env below
   ```
   ```ini
   [Service]
   Environment=DISPLAY=:0
   Environment=XAUTHORITY=/home/alice/.Xauthority
   Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
   ```
4. Start the daemon:
   ```sh
   sudo systemctl enable --now file-guard.service
   ```

## Security topology

This package ships the **hardened** topology by default - the same one the NixOS
module uses. The agent's listening socket (`/run/file-guard/agent.sock`) is
created and held by **root** (PID 1) via systemd socket activation, inside the
root-owned `/run/file-guard` (mode `0755`); the socket is mode `0600`. A same-uid attacker can therefore
neither hijack the socket name nor connect to it to self-approve prompts; the
agent process runs as the guarded user only so GUI dialogs reach their session,
and receives the listening fd rather than creating it.

The daemon's own protection (root-owned `0700` store + audit log under
`/var/lib/file-guard`, unreadable by the guarded user) requires it to run as
**root**, which the system service does.

> Without the socket-activated agent enabled, the daemon has no one to prompt:
> unknown accesses fall back to each file's `default_action` (deny by default).
> The dev-only `file-guard agent` self-bind path (in `$XDG_RUNTIME_DIR`) is *not*
> hardened against same-uid impersonation - use it for testing, not protection.
