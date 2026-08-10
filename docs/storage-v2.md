# Storage v2 transaction model

Storage v2 maintains one invariant: after every coordinator operation and at
every replay point, at least one complete, recoverable copy of the logical
credential exists. A complete snapshot includes contents, original existence,
restore metadata, path and parent bindings, staging identities, phase, and
revision.

## Two durability domains

SQLite owns snapshot transactions. One snapshot row contains the serialized
header and credential bytes. Updates use an immediate transaction and a
generation/revision compare-and-swap. The database uses a rollback journal,
`synchronous=FULL`, `secure_delete=ON`, a format application ID, and an exact
strict schema. Contents and restoration metadata never commit independently.
Initial creation fsyncs the store root, database file, and containing
directories before the database can become authoritative.

The filesystem cannot participate in the SQLite transaction. A small
coordinator therefore commits an intent, performs one idempotent filesystem
transition with `rustix`, verifies its result through directory descriptors,
fsyncs the affected namespaces, and commits the outcome. Startup replays any
intent by accepting only its exact pre-operation or post-operation inode
layout.

## Durable phases

| Phase | Filesystem meaning | Recoverable copy |
| --- | --- | --- |
| `captured` | The complete SQLite row is committed. The watched path is unchanged; staging need not exist yet. | Original path and database snapshot. |
| `installing` | The protected staging directory and exact placeholder identity are committed. | Database snapshot plus original path before exchange, or database snapshot plus detached original afterward. |
| `installed` | The verified placeholder is at the watched path. A present original remains in protected staging. | Database snapshot and detached original. |
| `mounting` | The installed layout is unchanged. The tokenized FUSE mount may be absent or present and must be reconciled with mountinfo. | Last committed database snapshot and detached original. |
| `unmounting` | New mounted writes are fenced and the intended outcome is durably `restore` or `leave_installed`. | Last committed database snapshot and detached original. |
| `storing` | Offline removal is authorized. Replay accepts only the original path or its exact staged inode. | Database snapshot plus the original path or staged inode. |
| `stored` | The watched path is absent and the original inode is protected in staging. | Database snapshot and staged inode. |
| `restoring` | A deterministic staging name is committed. Its optional prepared inode identity is committed before rename. | Database snapshot throughout; restored path after rename. |
| `restored` | Target contents, security-relevant metadata, and post-rename identity were verified and both namespaces were synced. | Restored path and database snapshot. |
| `deleting` | Snapshot cleanup is explicitly authorized. A fresh final inode is fsynced; the restored target is retired; recognized older inodes are removed while the complete snapshot row still exists. | Database snapshot and private final inode. |
| `finalizing` | One SQLite transaction replaced the snapshot row with an explicit marker bound to the private final inode. Replay accepts only that inode in staging or the same inode at the target. | Private final inode before the atomic rename; that exact inode at the target afterward. |

A detected mismatch sets `blocked_reason` without changing the current phase or
snapshot contents. Automatic destructive work then stops. Keeping the phase
avoids a second, duplicated recovery state machine.

TODO: add a read-only CLI that lists blocked records and exports a verified
snapshot to a separately chosen destination. Clearing a block automatically is
intentionally omitted because it would turn an identity mismatch into a
destructive recovery decision.

`logical_present` is distinct from original existence. An untouched originally
absent path is removed on restore. The first durably accepted FUSE write or
truncate makes it present, including an empty newly created credential.

## Ordering and replay

Capture reads a singly linked regular file through a no-follow descriptor and
commits the complete database row before creating staging or changing the
watched namespace. Placeholder preparation is deterministic and replayable
from `captured`. Installation commits `installing`, uses `renameat2`, verifies
the detached snapshot and resulting identities, fsyncs both directories, and
then commits `installed`. The detached inode is not unlinked during capture or
installation.

Mounted writes replace the whole SQLite row with CAS before FUSE reports
success. Unmount first changes the revision to `unmounting`, fencing late
writes. Restore starts only after the owned mount is absent. It prepares and
fsyncs the restoration inode under a reserved construction name, atomically
promotes it to its committed staging name, commits its identity, renames,
verifies the restored bytes and metadata, syncs both namespaces, and commits
`restored`. Construction names and invalid files whose identity has not yet
been committed are disposable replay debris; the complete SQLite snapshot is
used to rebuild them.

Cleanup verifies the target and commits `deleting`. While the complete snapshot
row remains, it creates and fsyncs a fresh final inode, moves the restored target
aside without replacement, verifies and removes only recorded older staging
objects, and syncs both namespaces. One SQLite transaction then replaces the
snapshot row with a finalization marker containing the path, parent, staging
location, inode identity, metadata, length, and digest. The coordinator moves
that private inode to the absent target with `RENAME_NOREPLACE`, verifies and
syncs it, and deletes only the marker. No credential-bearing object is deleted
after the last private copy is transferred to the target. An uncertain SQLite
commit or marker deletion is resolved by reloading the row.

## Refusal rules and guarantee boundary

Path components are resolved without following symlinks. The coordinator binds
the parent directory by device and inode and reopens the pathname to detect a
renamed or replaced parent. It rejects symlinks, hardlinks, special files,
replaced placeholders, changed detached inodes, unexpected staging entries,
illegal transitions, malformed rows, and content or metadata mismatches.

The database root and staging roots are mode `0700`; production database
ancestors must be root-owned real directories, with only root-owned sticky
ancestors allowed to be group/world-writable. Staging must be on the watched
path's filesystem. Restore preserves uid, gid, mode, mtime, atime at initial
installation, and extended attributes. Replay tolerates later atime changes
caused by ordinary reads but rechecks bytes, uid, gid, mode, mtime, xattrs, and
inode identity.

The mounted FUSE presentation keeps the captured ownership and mode but exposes
synthetic timestamps. Timestamp, ownership, mode, and flag mutations through
the mount are unsupported and return an error; content writes and truncation
are committed synchronously to the snapshot.

The crash guarantee assumes Linux `renameat2`, a local filesystem with durable
file and directory fsync, a functioning SQLite durability contract, root-owned
private storage, and no root attacker. Linux cannot atomically condition a
rename or unlink on an expected inode in a hostile parent. The finalization
marker avoids coupling database-content deletion to a mutable pathname: the
last private inode is transferred with one atomic no-replace rename, and later
cleanup deletes metadata only. The coordinator checks both sides immediately
around each operation and retains the snapshot or final inode on every detected
race. Once that inode has been exposed at the restored user-owned path, an actor
allowed to mutate the watched parent can still rename the parent or alter/delete
the restored file; protecting a file after it has intentionally been returned
to that actor is outside the lifecycle boundary.

Legacy raw-store import is intentionally separate. The old files have contents
but no existence bit, restoration metadata, phase, or inode bindings. Migration
must be explicit and quiesced, preserve a backup, and require operator input for
ambiguous entries.
