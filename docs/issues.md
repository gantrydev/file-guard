# Known issues & improvement areas

This document tracks technical debt, sharp edges, and missing polish in the
current Linux codebase.

---

## 1. ~~Confirm the Rust edition/toolchain requirement~~ ✅ RESOLVED

Kept `edition = "2024"`: it is stable, and the codebase uses edition-2024 let
chains. The Nix development shell and CI provide a compatible stable toolchain.

---

## 2. ~~`fs2` is an unmaintained dependency~~ ✅ RESOLVED

Replaced with `rustix::fs::flock` in `config.rs`, `logging.rs`, and
`store/sqlite.rs`. The `fs2` dependency has been removed from `Cargo.toml`.

---

## 3. ~~`pidfd_open` + `pidfd_send_signal` requires Linux ≥ 5.1~~ ✅ RESOLVED

Added a `kill()` fallback in `control.rs::signal_linux_daemon()`. When
`pidfd_open` fails with `ENOSYS` or `EINVAL`, the daemon verifies the
start-time identity and signals via `libc::kill()`. The `stop()` polling loop
falls back to sleep-based identity checks when no pidfd is available.

---

## 4. ~~`sysinfo::System::new_all()` scans the entire process table on every prompt~~ ✅ RESOLVED

Replaced with direct `/proc/<pid>/stat` parsing via the `procfs` crate. The
`parent_chain()` function now reads one `/proc/<ppid>/stat` per hop (max 16),
avoiding the whole-table scan. The `sysinfo` dependency has been removed from
`Cargo.toml`.

---

## 5. ~~SHA-256 hash cache has no eviction~~ ✅ RESOLVED

Added a `MAX_CACHE_ENTRIES` cap (1000 entries). When the cache reaches this
limit, it is cleared entirely before inserting the next entry — simple,
effective, and triggers only on long-running daemons under heavy churn.

---

## 6. ~~`setattr` truncate does synchronous `block_on` on the FUSE session thread~~ ✅ RESOLVED

The `setattr()` handler now follows the same off-thread spawn pattern used in
`open()`. When a handle-less truncate arrives, authorization and truncation
run inside a spawned tokio task, so a slow prompt cannot stall the entire
mount. The synchronous `authorize()` method (which did `block_on`) has been
removed as dead code — both `open()` and `setattr()` now use the free-standing
`decide_open()`.

---

## 7. ~~Limited rule management~~ ✅ RESOLVED

Added the following rule management subcommands:

- **`rules edit <index>`** — change action (`--action`), access direction
  (`--access`), or re-pin the binary hash (`--repin` / `--no-pin`). Uses
  `toml_edit` for in-place editing that preserves comments and formatting.
- **`rules find`** — filter by `--file`, `--binary`, or `--action` (substring
  match on path fields, exact match on action).
- **`rules export`** — dump all rules as TOML to stdout.
- **`rules import`** — merge rules from TOML on stdin, skipping exact
  duplicates.
- **Duplicate detection** — `append_rule` compares the complete rule, including
  binary/script identity pins, while holding the config lock. Re-authorizing an
  upgraded binary therefore persists its new hash.

---

## 8. ~~Large files with minimal internal documentation~~ ✅ RESOLVED

Added module-level doc comments to all four large files:

| File | Doc summary |
|---|---|
| `src/transaction.rs` | State-machine overview with ASCII-art phase diagram, crash-recovery semantics |
| `src/store/sqlite.rs` | Storage layout, crash-safety invariants, finalization protocol |
| `src/secure_file.rs` | Race-free file ops via `openat`/`O_NOFOLLOW`, key types and their roles |
| `src/fuse_fs/credential_fs.rs` | FUSE handler architecture, shared-content buffer, off-thread authorization pattern |

---

## 9. ~~`SessionState::clear()` is dead code~~ ✅ RESOLVED

Removed the unused method. A future session-reset command should add the state
operation together with a real daemon control path instead of carrying an
unused binary-internal API.

---

## 10. ~~`config.rs` index-based rule access uses bare `.unwrap()`~~ ✅ RESOLVED

Replaced `.unwrap()` with `.expect("rule must exist after bounds check")` in
`remove_rule_at()`.

---

## 11. ~~No `systemd` notification on startup completion~~ ✅ RESOLVED

Added `notify_systemd_ready()` and `notify_systemd_stopping()` to
`daemon.rs`. The daemon sends `READY=1` to the `NOTIFY_SOCKET` after all
mounts are up, and `STOPPING=1` during shutdown. Uses `UnixDatagram` directly
(no link-time dependency on libsystemd), supporting both absolute pathname and
Linux abstract sockets. The Debian and NixOS service definitions use
`Type=notify`.

---

## 12. ~~`notification` prompt method is a no-op from the user's perspective~~ ✅ RESOLVED

Renamed `PromptMethod::Notification` → `PromptMethod::LogOnly`. Settings
deserialization migrates the legacy `notification` value to `log_only` with
notifications enabled, so existing configs keep their visible behavior. Added
a separate `notify: bool` setting (default `false`) that fires a
`notify-send` desktop notification alongside any prompt method. This decouples
"how to prompt" from "whether to notify": `log_only` is now an explicit choice
to skip interactive prompts, and `notify = true` adds a visible heads-up on
top of whatever prompt method is active.

---

## 13. ~~Test-only `MemoryStore` lives in the main `store/mod.rs`~~ ✅ RESOLVED

Moved the `testing` module (with `MemoryStore` and `mount_intent_record`) to a
dedicated `src/testing.rs`. The `store/mod.rs` module is now shorter, and test
utilities live in a single, obvious location. Imports in `credential_fs.rs`
and `fuse_fs/mod.rs` updated to `crate::testing::*`.
