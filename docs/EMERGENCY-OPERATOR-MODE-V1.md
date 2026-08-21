# Emergency Operator Mode v1

Emergency Operator Mode packages the production-proven human-operated fallback
without changing canonical READY, provider or closure authority.

## Operator flow

```bash
wapp emergency-clean example.test
wapp emergency-clean example.test --execute
wapp emergency-clean example.test --reopen
wapp closure-check example.test
```

The default remediation command verifies a private HMAC-signed registry,
package, exact dependency set and independent package review. It displays the
exact site/root, isolation, actions, rollback state, operation and package hash,
then stops. Product commit and current runtime bytes are rederived from the
bound Product Seal. Independent review additionally requires an ECDSA P-256
signature from a reviewer key pinned in that Product Seal; the package HMAC
cannot manufacture review authority. `--execute` reads the reviewed launcher once, verifies its
pinned bytes and feeds those same bytes directly to fixed `/bin/bash`; its
pathname is never reopened after verification. The launcher must request the
package-bound human phrase and enforce its own
preflight, isolation, stability, mutation, recurrence and postcheck contracts.
The generic CLI also requires that exact package-bound phrase from a fresh
interactive terminal; approval cannot be supplied through argv or environment.

Reopen is a separate registry entry and one-shot package. It is bound to the
exact reviewed remediation package, its verified execution/postcheck record and
the still-active isolation identity. It may only reverse that exact isolation
operation and must re-isolate on a failed post-open check.

## Supported package primitives

- `QUARANTINE_EXACT_FILE`
- `REPLACE_EXACT_FILE`
- `REMOVE_EXACT_ACTIVE_PLUGIN`
- `REMOVE_EXACT_OPTION`
- `QUARANTINE_IDENTITY_ACCESS`

Executable targets precede config, database and identity stages. Every action
binds exact before/after state and a signed rollback artifact. Session tokens,
passwords and credential values are never accepted in the identity contract.

## Isolation and failure behavior

Self-managed same-filesystem atomic document-root isolation is preferred. A
previously reviewed public+origin HTTP block may be represented explicitly but
does not become provider authority. Denial is status-semantic (`401`, `403`,
`404`, `410` or `503`); short bodies are valid. Stability is package-bound and
at least 60 seconds. Recurrence becomes `RED_EXTERNAL_REQUIRED`; partial execution becomes
reconciliation with no blind retry.

## Closure

`wapp closure-check` evaluates a signed closure record separately. It can return:

- `WORDPRESS_INCIDENT_VERIFIED_CLEAN`
- `CLEAN_WITH_HARDENING_REMAINING`
- `CLEAN_WITH_DOCUMENTED_ASSURANCE_LIMITATIONS`
- `STILL_INCOMPLETE`

Critical/High findings, recurrence, material filesystem/database gaps, unknown
executable persistence or unresolved malicious privileged access always block
incident-clean status. CLEAN also requires fresh, same-site/root/operation and
Product-bound closure evidence plus the exact reviewed remediation and reopen
lineage, a typed post-open receipt and typed closure observations from which all
closure checks are derived. Stale or cross-site evidence remains
`STILL_INCOMPLETE`.

## Deliberate v1 boundary

This release is the generic operator-package layer (fallback B). It does not
invent a new mutation engine, collect arbitrary evidence, create provider
authority, promote degraded evidence to CLEAN, or automatically generate a
customer package. Exact case plans and launchers remain separately generated,
reviewed and signed, while the generic CLI validates and presents them through
one consistent operator surface.
