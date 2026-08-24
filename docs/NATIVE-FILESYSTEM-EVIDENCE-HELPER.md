# Native filesystem evidence helper

Version 1.1.3 adds a bounded, bootstrap-free Linux x86_64 helper for descriptor-confined filesystem inventory, selected-target rollback-byte capture, and signed explanation of a two-pass inventory mismatch.

The public contract is provider-neutral. A caller supplies one absolute root; the helper rejects the filesystem root, relative paths, empty/dot components, symlink traversal, identity drift, unsupported no-atime semantics, and cap overflow. It executes only the fixed `inventory`, `rollback`, and `diagnostic` modes. The helper never executes WordPress, PHP, plugins, themes, or customer code, and it has no mutation or remediation authority.

`inventory` remains fail-closed on any mismatch. `diagnostic` runs the same two full descriptor-bound snapshots and is valid only when they differ. It emits a deterministic, bounded delta of normalized path identities and permitted metadata; it never suppresses the mismatch or classifies a path as benign or malicious. The local `wapp signed-drift-diagnostic` wrapper binds the raw delta to the exact operation, root, helper, Core version, snapshot hashes, runtime identity, and caller-supplied UTC observation time, then signs the canonical JSON with the existing recovery-integrity key. Every authority flag is false and `decision_eligible` is false. The artifact cannot serve as CLEAN, closure, preparation, apply, or remediation authority.

The Linux artifact is built reproducibly with exact Zig 0.15.2, stored as canonical base64 text, and bound by both encoded and decoded SHA-256 identities. The loader verifies fixed root-owned system tools, decodes into a sealed anonymous memory file, and uses `execveat`; it does not create a target-side executable. macOS is an explicit unsupported runtime for the Linux evidence operation and is used only to verify source portability and fail-closed platform behavior.

Private integrations remain responsible for site selection, transport, credentials, evidence signatures, Product/Scan lineage, customer records, and authorization. None of those are part of Public Core.
