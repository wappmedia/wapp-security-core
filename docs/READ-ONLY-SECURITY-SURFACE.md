# Read-only security surface

`READ_ONLY_SECURITY_SURFACE_V1` binds one complete, stable native inventory to
the released static security ruleset and an exact signed provenance set. It
does not traverse the target again and is not a second scanner.

Every regular file is emitted once with exact path, content hash and filesystem
identity. Executable, WordPress runtime, drop-in and security-configuration
classes remain visible, but suffixes and known paths do not limit coverage.
This prevents extensionless or disguised executable content from disappearing
from the security surface.
Known exact malicious content and executables below an `uploads` component are
terminal `ACTION_REQUIRED`. Exact signed official/runtime provenance can yield
`PASS`. Every other regular object remains `UNRESOLVED` and prevents
semantic coverage from becoming complete.

Public Core does not mint a capture from loose inventory rows. It consumes a
signed canonical collection envelope that binds the released Product Seal,
native-helper policy and SHA, runtime identity, exact inventory commitment and
an honest trusted-memfd or degraded-ephemeral collection lifecycle. The signed
provenance scope commits to the complete current regular-file set. Every
provenance record references a separately signed, capture-bound source artifact;
omitted, replaced or substituted source evidence therefore remains unresolved.

The artifact is read-only and non-authorizing. It never grants CLEAN, closure,
preparation, remediation, apply or mutation authority. Private integration is
responsible for validating the provenance producer and combining the surface
with current database, identity, cron and customer evidence.

Raw customer source bytes are never emitted. Unsupported objects, incomplete
native coverage, stale evidence, mismatched provenance and release/ruleset
substitution all fail closed.

The surface records that its local classification step creates no server temp
file and modifies no target file. Collection-lifecycle claims (including a
degraded ephemeral launcher) remain in the separately validated Private
capture lineage and are not overwritten or generalized by this contract.
