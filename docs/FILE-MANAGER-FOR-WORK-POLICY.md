# File Manager for Work policy

This public, customer-neutral rule evaluates a strict plugin inventory record.
The slug `file-manager-for-work` is always flagged, whether active or inactive.

The verified variant is version `4.2.5`, author metadata `Your Name`, provenance
`UNKNOWN`, with canonical sorted-inventory SHA-256
`08f697068f2b2b3758e8a9e8088d88c3e60e6f1c643dd6d9bab84dfbd0166e6c`.
Only an exact match returns `REMOVE_REQUIRED`. The same slug with any other
fingerprint or metadata returns `PROVENANCE_REVIEW_REQUIRED`.

The result is read-only and non-authorizing. It does not classify the plugin as
malware. `REMOVE_REQUIRED` carries only a required remediation contract:
byte-exact snapshot/prestate, exact deactivation if active, site-health check,
exact directory quarantine/removal, postcheck, and forensic/hardening journal.
Separate evidence, approval and execution gates remain mandatory.
