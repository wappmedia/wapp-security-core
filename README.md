# Wapp Security Core

Public, customer-neutral runtime contracts for Wapp Security.

Emergency Operator Mode v1 validates a locked, independently reviewed package
and presents a human-operated one-shot execution boundary. It does not collect
customer evidence, create customer plans, provide unrestricted shell access, or
grant canonical production authority.

Independent package reviews require an asymmetric reviewer signature whose
public key is pinned in the clean Product Seal runtime. The public distribution
ships with no trusted production reviewer. A private consumer may supply one
explicit reviewer through a separate root-owned, symlink-free, non-writable
trust-anchor file. The private integration must provide its normalized absolute
path, exact SHA-256, reviewer identity and versioned key identity through the
four `WAPP_EMERGENCY_REVIEWER_*` configuration variables. All parent
directories and the open file descriptor are verified before bytes are used.

## Commands

```text
wapp emergency-clean example.test
wapp emergency-clean example.test --execute
wapp emergency-clean example.test --reopen
wapp closure-check example.test
wapp plugin-policy plugin-record.json
```

The generic runtime supports exact package contracts for file quarantine,
verified file replacement, sparse `active_plugins` member removal, exact option
removal, credential-neutral identity quarantine, atomic reopen, recurrence
failure and closure evaluation.

Version 1.1.9 adds a bounded native Linux backend for deterministic exact-file
quarantine and exact rollback on hosts without Python. It remains
non-authorizing and is usable only through the reviewed private emergency
package/registry/human-GO chain. See
[Native exact-file quarantine](docs/NATIVE-EXACT-FILE-QUARANTINE.md).

## Trust boundary

This repository contains only engine code, schemas expressed by the validator,
synthetic fixtures and public regression tests. Customer evidence, case plans,
review artifacts, launchers, reports, credentials and production configuration
belong in a separate private consumer. A consumer must pin an exact released
Core commit and keep every customer artifact outside this repository.

Emergency remediation never automatically means `VERIFIED CLEAN`. Reopen is a
separate human operation and closure is evaluated independently.

The plugin policy command includes a narrow, non-authorizing rule for the
`file-manager-for-work` slug. It always flags that slug, requires an exact
verified inventory fingerprint for `REMOVE_REQUIRED`, and otherwise returns
`PROVENANCE_REVIEW_REQUIRED`. It never classifies malware without separate
incident evidence.

See [Emergency Operator Mode v1](docs/EMERGENCY-OPERATOR-MODE-V1.md).
