# Remaining issues after the ownership-model pass

This list contains work that is still genuinely open. The architectural changes
that closed findings from the earlier review are summarized at the end so the
same issues are not rediscovered under different symptoms.

## Recovery tooling for blocked snapshots (Medium)

Storage v2 correctly persists `blocked_reason` and stops automatic destructive
work after an identity mismatch. There is still no supported command to inspect
that record, export its verified credential bytes to a separately chosen path,
or clear the block after an operator has reconciled the filesystem.

This is an availability and operability gap, not a data-loss gap: the snapshot
remains durable, but recovery currently requires database-level expertise.

The proper fix is a read-only recovery API first:

1. list blocked records with lifecycle, bound path, parent identity, revision,
   and reason;
2. export one verified snapshot with `O_EXCL`, no symlink following, explicit
   destination ownership/mode, file fsync, and parent-directory fsync; and
3. only then design an explicit operator-approved reconciliation command. It
   must never turn "clear block" into an automatic retry against an unverified
   pathname.

## Resource budgets for hostile access rates (Low)

Credential contents and protocol frames have hard size limits, prompt rendering
is rate-limited, and each credential now has a single mutation owner. The FUSE
open path and audit sink still have no per-process operation or disk-space
budget. A same-uid process can generate repeated denied opens and grow a file
audit log until an external log-rotation or filesystem quota intervenes.

A fix needs explicit semantics rather than silent event loss: per-process
request budgets may return `EAGAIN`, while audit saturation must emit a durable
health signal and preserve deny events according to a documented retention
policy. Packaged deployments should also ship log rotation or journal limits.

## Self-bound prompt socket is development-only (Medium if misdeployed)

The packaged systemd topology is root-anchored: PID 1 owns the listening socket
name in `/run/file-guard`, and the daemon verifies peer credentials. The
standalone `file-guard agent` fallback binds inside the guarded user's runtime
directory, where another process with that same uid can replace or impersonate
the agent. The command logs a warning and is not a security boundary.

An HMAC file readable by the user agent would not solve same-uid impersonation;
the attacker could read it too. Production hardening therefore requires a
privileged socket owner or equivalent service-manager capability, not another
shared bearer token. The remaining work is to make unsupported deployment
topologies harder to enable accidentally and document platform equivalents to
systemd socket activation.

## Stale PID file before the next control command (Low)

`SIGKILL` and process crashes cannot run daemon cleanup. PID reuse is already
handled safely by the stored process start time, and `status`/`stop` remove a
stale record after verification. The pathname can nevertheless remain until the
next control invocation. A systemd `ExecStopPost` cleanup is useful operator
polish but does not change signaling safety.

## Remaining test work

- Fuzz `Config`, rule-import, prompt, and control-protocol parsing with bounded
  inputs and a no-panic/no-unbounded-allocation property.
- Add a packaged integration test that exercises control-socket ownership and
  read-vs-mutation authorization with distinct root and guarded-user processes.
- Continue running the ignored FUSE suite on a real `/dev/fuse`; unit tests cover
  transition invariants but cannot validate kernel mount behavior.
- Run the live parent-rename script on the supported distribution matrix. The
  deterministic transaction test remains the byte-preservation oracle.

## Findings closed by the architecture pass

- Runtime prompts and rule CLI commands no longer rewrite operator TOML.
  Learned rules have a SQLite owner, stable IDs, and a versioned daemon control
  path; a sidecar lease closes daemon-start/offline-command races; seed
  reconciliation migrates rules from the legacy live-TOML representation to
  SQLite before replacing the complete declarative config. Edits are owner-side
  field patches, so concurrent changes to different fields cannot overwrite one
  another through a stale CLI snapshot.
- Config updates use a stable sidecar lock plus identity-checked atomic rename.
  The concurrent-writer test proves that successful updates are not lost, and
  existing ownership/mode are preserved.
- Credential writes and truncates are serialized across snapshot commit and
  in-memory publication. A blocked-store concurrency test proves two mutations
  cannot prepare from the same revision.
- Permanent identities distinguish pinned from explicitly unpinned state.
  Malformed hashes, orphaned script hashes, relative identity paths, and hash
  failures cannot silently create path-only grants.
- Executable identity is captured from `/proc/<pid>/exe` with start-time checks,
  so a later pathname replacement cannot change which executable was approved.
  Session grants also include executable and script identity, so `exec` cannot
  inherit a grant merely because PID and start time remain unchanged.
- Matching denies win independently of rule order.
- Prompt and control frames are bounded and timed; protocol-version and
  oversize cases are tested. Prompt rate limiting occurs after successful
  parsing and returns an explicit `NoResponse` instead of dropping a client.
- Audit following holds an open-file cursor, advances only past complete NDJSON
  records, drains bounded chunks, and detects truncation or replacement without
  inode-reuse ambiguity. The privileged writer rejects unsafe ancestors,
  symlinks, hard links, special files, and writable-by-others targets.
- The live parent-rename test now reads the mount at its actual displaced path,
  signals only the daemon it created, leaves attacker content untouched, and
  verifies the durable manual-recovery block.
