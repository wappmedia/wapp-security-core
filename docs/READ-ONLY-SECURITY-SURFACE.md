# Read-only security surface

`READ_ONLY_SECURITY_SURFACE_V1` binds one complete, stable native inventory to
the released static security ruleset and an exact signed provenance set. It
does not traverse the target again and is not a second scanner.

Every executable, WordPress runtime file, drop-in and security configuration
file is emitted once with exact path, content hash and filesystem identity.
Known exact malicious content and executables below an `uploads` component are
terminal `ACTION_REQUIRED`. Exact signed official/runtime provenance can yield
`PASS`. Every other security-relevant object remains `UNRESOLVED` and prevents
semantic coverage from becoming complete.

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
