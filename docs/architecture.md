# Architecture and invariants

file-guard crosses three mutable systems: the Linux filesystem namespace, the
kernel mount table, and durable SQLite state. Correctness depends on assigning
one authority to each resource and defining where every mutation takes effect.

## Ownership

| Resource | Authority | Stable identity | Serialization |
|---|---|---|---|
| Operator configuration | Administrator | Read-only config path | No runtime writes |
| Learned rules | Daemon or one offline command | Database rule ID | Owner lease plus SQLite transaction |
| Live credential contents | Per-credential state owner | Snapshot generation and revision | One mutation at a time |
| Filesystem target | `ResolvedPath` | Parent fd plus device/inode | Binding verification |
| Mount presence | Kernel | Mount ID plus file-guard token | Observed reconciliation |
| Persistent authorization | Policy engine | Complete pinned identity | No implicit downgrade |

Declarative `[[rule]]` entries are administrator-owned inputs. Rules learned
from an interactive prompt are runtime state and must not rewrite the operator's
configuration.

Seed reconciliation also handles the legacy representation. Rules present only
in an older live TOML are durably inserted into the learned repository while the
owner lease and config lock are held, before the complete declarative seed
replaces that file. Repeating the migration is idempotent; a crash between the
database commit and config rename can create only a temporary duplicate, not a
lost authorization.

## Invariants

1. Every successful learned-rule mutation is durable exactly once.
2. Every successful credential mutation commits one successor revision.
3. Credential writes and truncates are serialized per watched file.
4. A verification or persistence failure never weakens authorization.
5. Only an explicit operator choice may create an unpinned rule.
6. Path-based mutation requires the captured parent binding to remain valid.
7. A mount-absence transition requires current kernel evidence.
8. Recovery never deletes the final recoverable copy of a credential.
9. Rule conflicts are order-independent: any matching deny wins.
10. Protocol readers bound message size and advance only across complete frames.

## Rule ownership and control

Operator `[[rule]]` entries are loaded from the declarative config and exposed
as read-only rules. Prompt decisions and `file-guard rules add/import/edit`
write `rules.sqlite`; they never rewrite the config. While the daemon is live,
a versioned Unix-socket API is the only mutation path and updates the database
and active policy under the same policy lock. A stable sidecar lease is the
actual ownership primitive: the daemon acquires it before publishing the socket
or loading rules. Each open repository retains the lease, so it is not released
until every credential mount and in-flight authorization task has dropped its
policy state. An offline command must acquire the same lease before opening the
repository. This closes the check/use race between observing an absent socket
and daemon startup.

Edits and removals resolve a displayed index to a stable learned-rule ID before
mutation. Edits send field patches, not stale whole-rule snapshots, and the
owner applies each patch under the policy lock. Declarative entries have no
learned ID and cannot be edited through the runtime API.

The control socket is anchored in a trusted directory. Kernel peer credentials
authorize reads for the daemon and guarded user, while mutations require the
daemon uid. Frames have a fixed maximum size and timeout, and connection tasks
are children of the control server so shutdown cannot leave detached owners.

## Credential mutation model

The in-memory content and its snapshot record form one committed state. A
write or truncate constructs a candidate from that state, durably commits the
candidate using the current revision, and only then publishes it in memory.
The durable commit is the linearization point. A failed commit leaves the
previous state published.

Reads may observe the last committed state while a mutation is being prepared,
but no two mutations may prepare from the same in-memory revision.

## Filesystem identity model

A pathname is a lookup input, not an object identity. After resolution,
file-guard operates through an open parent directory and a single entry name.
Device and inode identities bind durable records to that parent. Renames,
replacement directories, and mount movement must be observed rather than
inferred from the original pathname.

The same rule applies to privileged metadata. Operator config and audit-log
files are opened with no symlink following and accepted only beneath trusted
directories. Privileged config must be a root-controlled, non-writable regular
file. The audit sink additionally rejects hard links and files writable by
group or others.

## Authorization model

Pinned and intentionally unpinned identities are distinct states. Failure to
hash a binary or script cannot be represented as an unpinned identity. Failure
to capture the running executable denies identification before policy
evaluation. If a user requests a permanent decision but an associated script
cannot be captured, the current access uses that decision once and no permanent
rule is created.

The binary hash is captured from `/proc/<pid>/exe`, with the process start time
checked before and after hashing. It therefore describes the executable object
that issued the access, even if its pathname is later replaced. Rule-file hash
strings are validated and normalized before policy construction; an orphaned
script hash or relative identity path is rejected before persistence.

Session grants bind PID and start time together with the captured executable
path, hash, and script path. Because Linux preserves process start time across
`exec`, using PID and start time alone would let a replacement image inherit the
previous image's grant.

All matching rules are evaluated without insertion-order precedence. A matching
deny wins over any matching allow; otherwise at least one matching allow is
required. This prevents a learned allow from shadowing an administrator deny
and makes duplicate source ordering irrelevant.
