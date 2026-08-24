# Native filesystem evidence helper

Version 1.1.0 adds a bounded, bootstrap-free Linux x86_64 helper for descriptor-confined filesystem inventory and selected-target rollback-byte capture.

The public contract is provider-neutral. A caller supplies one absolute root; the helper rejects the filesystem root, relative paths, empty/dot components, symlink traversal, identity drift, unsupported no-atime semantics, and cap overflow. It executes only the fixed `inventory` and `rollback` modes. The helper never executes WordPress, PHP, plugins, themes, or customer code, and it has no mutation or remediation authority.

The Linux artifact is built reproducibly with exact Zig 0.15.2, stored as canonical base64 text, and bound by both encoded and decoded SHA-256 identities. The loader verifies fixed root-owned system tools, decodes into a sealed anonymous memory file, and uses `execveat`; it does not create a target-side executable. macOS is an explicit unsupported runtime for the Linux evidence operation and is used only to verify source portability and fail-closed platform behavior.

Private integrations remain responsible for site selection, transport, credentials, evidence signatures, Product/Scan lineage, customer records, and authorization. None of those are part of Public Core.
