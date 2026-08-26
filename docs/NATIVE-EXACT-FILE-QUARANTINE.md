# Native exact-file quarantine

Public Core v1.1.8 supplies a customer-neutral Linux x86_64 backend for the
`QUARANTINE_EXACT_FILE` primitive. The backend is capability, not authority.
It can run only from a private, independently reviewed emergency package bound
to a signed registry and an explicit human live-GO.

The helper accepts at most 64 regular files. The canonical manifest is sorted
by relative-path UTF-8 bytes and binds each path, SHA-256, size, mode, owner,
group, parent device/inode and file device/inode. It rejects duplicate paths, duplicate physical
objects, symlinked path chains, hard links, root drift, destination collisions
and cross-filesystem targets before the first file move.

All targets are pre-opened through `openat2` with beneath/no-symlink/no-magic
resolution. Quarantine uses `renameat2(RENAME_NOREPLACE)` into an
operation-derived owner-only directory outside the WordPress root. Quarantined
objects are mode `0400`. A durable journal records each committed target.
Failure triggers reverse-order exact compensation. If compensation cannot be
proved, the result is `PARTIAL_OR_DIVERGED`; isolation must remain active and a
separate reconciliation decision is required. The bounded
`reconcile-rollback` mode can restore a mixed exact-original/exact-quarantine
set and rejects every third state. The apply receipt exposes the quarantine
root device/inode, which all later observation and rollback calls must bind.

Rollback is no-replace and restores only the exact bound object, path and
metadata. A collision or changed quarantine object fails closed. Neither
quarantine nor rollback permanently deletes bytes.

On hosts without a trusted physical loader the released ephemeral transport
stages a pinned static launcher, verifies its bytes and metadata, and executes
the helper from a sealed memfd. This transport has the explicit residual risk
`SAME_PRINCIPAL_TOCTOU_RISK_REQUIRES_EXPLICIT_LIVE_GO`; read-only capture
acceptance does not authorize mutation. The private live approval must bind
that risk separately.
