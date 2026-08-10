# Parent-directory rename tests

## Security property

A pathname is not an object identity. If the watched parent is renamed and a
new directory appears at the old pathname, file-guard must never redirect a
credential operation into that replacement directory.

The transaction record stores the captured parent device and inode.
`TransactionManager::resolve_bound_path` requires the current pathname to name
that same parent before continuing. `ResolvedPath` then performs mutations
relative to an open parent-directory descriptor and verifies that the pathname
still resolves to the held directory before and after the operation.

This has two consequences:

1. Replacing the pathname before resolution is rejected by the durable parent
   identity check.
2. Renaming it after resolution does not retarget an operation: descriptor-
   relative filesystem calls still address the captured directory. The later
   binding check detects the namespace change and retains the snapshot.

Trusted-ancestor validation separately rejects untrusted staging and database
directories. It is not a substitute for the parent identity checks.

## Deterministic transaction test

`parent_replacement_during_restore_keeps_the_snapshot` injects a directory
replacement at the restore transition boundary. It asserts that:

- restore fails;
- the replacement pathname is not written;
- the original snapshot bytes remain in the store; and
- the record receives a durable `blocked_reason`.

Run it with:

```bash
./scripts/test-parent-binding.sh
```

## Live FUSE test

Linux moves a mount with the directory entry that contains it. After renaming
the watched parent, the active file-guard mount is therefore found below the
displaced directory; a file created at the old pathname is a separate,
attacker-controlled object.

`test-parent-rename-attack.sh` checks the real topology rather than reading the
replacement pathname as if the mount had stayed there. It:

1. starts an isolated daemon and verifies a baseline mounted read;
2. renames the mounted parent and creates an attacker file at the old path;
3. verifies reads and writes through the displaced mount while the attacker
   file remains unchanged;
4. stops the daemon with `restore_on_stop = true` and requires the parent
   mismatch to fail closed;
5. verifies the daemon exits, the moved mount disappears, and the attacker file
   remains untouched; and
6. restores the original parent identity and confirms that offline restore
   reports the persisted manual-recovery block.

The script signals only the daemon PID it started and attempts cleanup only for
its two exact mount paths.

Run it as root on a host with FUSE:

```bash
cargo build --release
sudo ./scripts/test-parent-rename-attack.sh
```

The live test proves namespace isolation and durable blocking. Byte-for-byte
snapshot preservation is asserted by the deterministic transaction test; the
project does not yet expose blocked snapshot contents through a recovery CLI.

## Recovery boundary

A `blocked_reason` intentionally stops all automatic destructive work. Clearing
one requires an operator to decide which observed filesystem object is valid.
The recovery CLI needed to inspect and export a blocked snapshot is tracked in
`docs/storage-v2.md`; automatic unblocking would weaken the identity guarantee.
