# Wapp Security Core

Public, customer-neutral runtime contracts for Wapp Security.

Emergency Operator Mode v1 validates a locked, independently reviewed package
and presents a human-operated one-shot execution boundary. It does not collect
customer evidence, create customer plans, provide unrestricted shell access, or
grant canonical production authority.

## Commands

```text
wapp emergency-clean example.test
wapp emergency-clean example.test --execute
wapp emergency-clean example.test --reopen
wapp closure-check example.test
```

The generic runtime supports exact package contracts for file quarantine,
verified file replacement, sparse `active_plugins` member removal, exact option
removal, credential-neutral identity quarantine, atomic reopen, recurrence
failure and closure evaluation.

## Trust boundary

This repository contains only engine code, schemas expressed by the validator,
synthetic fixtures and public regression tests. Customer evidence, case plans,
review artifacts, launchers, reports, credentials and production configuration
belong in a separate private consumer. A consumer must pin an exact released
Core commit and keep every customer artifact outside this repository.

Emergency remediation never automatically means `VERIFIED CLEAN`. Reopen is a
separate human operation and closure is evaluated independently.

See [Emergency Operator Mode v1](docs/EMERGENCY-OPERATOR-MODE-V1.md).
