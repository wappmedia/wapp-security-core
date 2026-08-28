#!/usr/bin/env python3
"""Derive a bounded, non-authorizing volatile runtime disposition."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")
SINT = re.compile(r"^-?(0|[1-9][0-9]*)$")
MODE = re.compile(r"^[0-7]{3,4}$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
VERS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")
COMPONENT_TYPES = {"WORDPRESS_CORE_RUNTIME", "WORDPRESS_PLUGIN_RUNTIME", "WORDPRESS_THEME_RUNTIME", "MU_PLUGIN_RUNTIME", "DROP_IN_RUNTIME"}
RUNTIME_ROLES = {"APPEND_ONLY_LOG", "GENERATED_RUNTIME_STATE"}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"volatile-runtime-disposition: {message}")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def read_regular(path: pathlib.Path, cap: int = 125_829_120) -> bytes:
    if not path.is_absolute():
        fail("dependency path must be absolute")
    try:
        before_path = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        fail("dependency unavailable")
    try:
        before = os.fstat(fd)
        if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            fail("dependency identity invalid")
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before_path) != identity(before):
            fail("dependency path/descriptor mismatch")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(1_048_576, cap + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                fail("dependency byte cap")
            chunks.append(chunk)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat()):
            fail("dependency drift")
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_json(path: pathlib.Path) -> tuple[dict[str, object], bytes]:
    raw = read_regular(path)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("dependency JSON invalid")
    if not isinstance(value, dict) or canonical(value) != raw:
        fail("dependency serialization noncanonical")
    return value, raw


def decode_rel(value: str) -> bytes:
    if len(value) == 0 or len(value) > 8192 or len(value) % 2 or not re.fullmatch(r"[0-9a-f]+", value):
        fail("path encoding invalid")
    raw = bytes.fromhex(value)
    if raw.startswith(b"/") or b"\0" in raw or any(part in (b"", b".", b"..") for part in raw.split(b"/")):
        fail("path normalization invalid")
    return raw


def decode_abs(value: str) -> bytes:
    if len(value) < 2 or len(value) > 8192 or len(value) % 2 or not re.fullmatch(r"[0-9a-f]+", value):
        fail("absolute path encoding invalid")
    raw = bytes.fromhex(value)
    if not raw.startswith(b"/") or raw.endswith(b"/") or b"\0" in raw or any(part in (b"", b".", b"..") for part in raw[1:].split(b"/")):
        fail("absolute path normalization invalid")
    return raw


def exact_uint(value: str, label: str) -> int:
    if not UINT.fullmatch(value):
        fail(f"{label} invalid")
    result = int(value)
    if result > 2**64 - 1:
        fail(f"{label} out of range")
    return result


def exact_sint(value: str, label: str) -> int:
    if not SINT.fullmatch(value):
        fail(f"{label} invalid")
    result = int(value)
    if result < -(2**63) or result > 2**63 - 1:
        fail(f"{label} out of range")
    return result


def parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        fail(f"{label} invalid")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        fail(f"{label} invalid")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        fail(f"{label} noncanonical")
    return parsed


def diagnostic(path: pathlib.Path) -> tuple[dict[str, object], bytes]:
    value, raw = load_json(path)
    if value.get("tool") != "wapp-security-signed-drift-diagnostic" or value.get("schema") != 1 or value.get("diagnostic_mode") != "SIGNED_DRIFT_DIAGNOSTIC_MODE_V1":
        fail("diagnostic type invalid")
    if value.get("decision_eligible") is not False or value.get("descriptor_bound") is not True or value.get("authority") != {"apply": False, "clean": False, "closure": False, "mutation": False, "prepare": False, "ready": False}:
        fail("diagnostic authority invalid")
    if value.get("issue_deltas") != []:
        fail("diagnostic unresolved issue delta")
    return value, raw


def runtime_continuity(first: dict[str, object], second: dict[str, object]) -> dict[str, object]:
    left, right = first.get("runtime_identity"), second.get("runtime_identity")
    if not isinstance(left, dict) or not isinstance(right, dict):
        fail("repeated observation runtime identity missing")
    left_contract, right_contract = left.get("contract"), right.get("contract")
    if left_contract != right_contract:
        fail("repeated observation runtime contract mismatch")
    if left_contract == "TRUSTED_PERL_SEALED_MEMFD_EXECVEAT_V1":
        if left != right or first.get("runtime_identity_sha256") != second.get("runtime_identity_sha256"):
            fail("repeated observation runtime identity mismatch")
        if first.get("ephemeral_bootstrap_audit") is not None or second.get("ephemeral_bootstrap_audit") is not None or first.get("ephemeral_bootstrap_audit_sha256") is not None or second.get("ephemeral_bootstrap_audit_sha256") is not None:
            fail("persistent runtime has unexpected lifecycle audit")
        return left
    if left_contract != "DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1":
        fail("repeated observation runtime contract unsupported")
    required = {"contract", "helper_sha256", "identity_hex", "identity_scope", "identity_sha256", "launcher_metadata", "launcher_sha256", "transport"}
    if set(left) != required or set(right) != required or left.get("identity_scope") != "OPERATION_SCOPED" or right.get("identity_scope") != "OPERATION_SCOPED":
        fail("ephemeral runtime identity contract invalid")
    left_meta, right_meta = left.get("launcher_metadata"), right.get("launcher_metadata")
    meta_keys = {"bytes", "device", "gid", "inode", "mode", "uid"}
    if not isinstance(left_meta, dict) or not isinstance(right_meta, dict) or set(left_meta) != meta_keys or set(right_meta) != meta_keys:
        fail("ephemeral launcher metadata missing")
    if first.get("inventory_operation_id") == second.get("inventory_operation_id"):
        fail("ephemeral lifecycle operation replay")
    audit_hashes = (first.get("ephemeral_bootstrap_audit_sha256"), second.get("ephemeral_bootstrap_audit_sha256"))
    audits = (first.get("ephemeral_bootstrap_audit"), second.get("ephemeral_bootstrap_audit"))
    audit_keys = {"cleanup_state", "contract", "launcher_bytes", "launcher_identity_sha256", "launcher_metadata", "launcher_sha256", "operation_id", "runtime_identity_sha256", "stage_identity_sha256"}
    if any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in audit_hashes) or audit_hashes[0] == audit_hashes[1]:
        fail("ephemeral lifecycle audit invalid or replayed")
    if any(not isinstance(audit, dict) or set(audit) != audit_keys for audit in audits):
        fail("ephemeral lifecycle audit contract invalid")
    assert isinstance(audits[0], dict) and isinstance(audits[1], dict)
    for artifact, audit in ((first, audits[0]), (second, audits[1])):
        artifact_runtime = artifact.get("runtime_identity")
        if not isinstance(artifact_runtime, dict) or audit.get("contract") != "EPHEMERAL_BOOTSTRAP_AUDIT_V2" or audit.get("operation_id") != artifact.get("inventory_operation_id") or audit.get("cleanup_state") != "CLEANUP_VERIFIED" or audit.get("launcher_sha256") != artifact_runtime.get("launcher_sha256") or audit.get("launcher_bytes") != artifact_runtime.get("launcher_metadata", {}).get("bytes") or audit.get("launcher_metadata") != artifact_runtime.get("launcher_metadata") or audit.get("runtime_identity_sha256") != artifact.get("runtime_identity_sha256") or any(not isinstance(audit.get(key), str) or not HEX64.fullmatch(audit[key]) for key in ("launcher_identity_sha256", "stage_identity_sha256")):
            fail("ephemeral lifecycle audit binding invalid")
    if audits[0]["stage_identity_sha256"] == audits[1]["stage_identity_sha256"]:
        fail("ephemeral staging lifecycle replay")
    exact = ("launcher_sha256", "helper_sha256", "transport")
    if any(left.get(key) != right.get(key) for key in exact):
        fail("ephemeral release identity mismatch")
    # The inode is intentionally operation-scoped. All other ownership,
    # permission, filesystem and release-byte properties remain exact.
    stable_meta = {key: left_meta[key] for key in sorted(meta_keys - {"inode"})}
    if stable_meta != {key: right_meta[key] for key in sorted(meta_keys - {"inode"})}:
        fail("ephemeral launcher metadata drift")
    return {
        "contract": left_contract,
        "identity_scope": "OPERATION_SCOPED",
        "launcher_sha256": left["launcher_sha256"],
        "helper_sha256": left["helper_sha256"],
        "transport": left["transport"],
        "stable_launcher_metadata": stable_meta,
        "verified_lifecycles": [
            {"operation_id": first["inventory_operation_id"], "runtime_identity_sha256": first["runtime_identity_sha256"], "audit_sha256": audit_hashes[0], "launcher_identity_sha256": audits[0]["launcher_identity_sha256"], "stage_identity_sha256": audits[0]["stage_identity_sha256"]},
            {"operation_id": second["inventory_operation_id"], "runtime_identity_sha256": second["runtime_identity_sha256"], "audit_sha256": audit_hashes[1], "launcher_identity_sha256": audits[1]["launcher_identity_sha256"], "stage_identity_sha256": audits[1]["stage_identity_sha256"]},
        ],
    }


def state_without_ctime(state: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in state.items() if key != "ctime_ns"}


def behavior(delta: dict[str, object]) -> str:
    if delta.get("change_type") != "MODIFIED" or delta.get("pass1_exists") is not True or delta.get("pass2_exists") is not True:
        fail("create/delete/replace cannot be disposed")
    before, after = delta.get("pass1"), delta.get("pass2")
    if not isinstance(before, dict) or not isinstance(after, dict) or before.get("type") != "REGULAR" or after.get("type") != "REGULAR":
        fail("volatile target must remain a regular file")
    try:
        if int(str(before.get("mode")), 8) & 0o111 or int(str(after.get("mode")), 8) & 0o111:
            fail("executable volatile target rejected")
    except ValueError:
        fail("volatile file mode invalid")
    if state_without_ctime(before) == state_without_ctime(after) and before.get("ctime_ns") != after.get("ctime_ns"):
        return "CTIME_ONLY"
    stable = ("type", "device", "inode", "mode", "uid", "gid", "nlink", "symlink_target_hex", "uploads")
    if any(before.get(key) != after.get(key) for key in stable):
        fail("volatile file identity changed")
    try:
        mode = int(str(after.get("mode")), 8)
        first_size, second_size = int(before["size"]), int(after["size"])
        first_mtime, second_mtime = int(before["mtime_ns"]), int(after["mtime_ns"])
        first_ctime, second_ctime = int(before["ctime_ns"]), int(after["ctime_ns"])
    except (KeyError, TypeError, ValueError):
        fail("volatile file metadata invalid")
    if mode & 0o111 or second_size <= first_size or second_mtime < first_mtime or second_ctime < first_ctime:
        fail("runtime log behavior invalid")
    # Upload-area logs need an additional descriptor-bound prefix proof at
    # capture time.  The disposition alone never admits their content drift.
    return "APPEND_PREFIX_REQUIRED_UPLOAD_LOG_GROWTH" if after.get("uploads") is True else "APPEND_PREFIX_REQUIRED_LOG_GROWTH"


def provenance(path: pathlib.Path) -> tuple[dict[str, dict[str, object]], dict[str, object], bytes]:
    value, raw = load_json(path)
    if set(value) != {"generated_at", "paths", "root_path_hex", "schema", "target_product_identity_sha256", "tool"} or value.get("tool") != "wapp-security-runtime-provenance-evidence" or value.get("schema") != 1:
        fail("runtime provenance type invalid")
    parse_time(value.get("generated_at"), "provenance timestamp")
    root_hex = value.get("root_path_hex")
    if not isinstance(root_hex, str) or not root_hex.startswith("2f"):
        fail("runtime provenance root invalid")
    target_product = value.get("target_product_identity_sha256")
    if not isinstance(target_product, str) or not HEX64.fullmatch(target_product):
        fail("target Product identity invalid")
    rows = value.get("paths")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        fail("runtime provenance path cardinality invalid")
    indexed: dict[str, dict[str, object]] = {}
    for row in rows:
        required = {"component", "incident_persistence", "ioc_correlation", "normalized_path_hex", "runtime_role"}
        if not isinstance(row, dict) or set(row) != required:
            fail("runtime provenance row invalid")
        path_hex = row.get("normalized_path_hex")
        if not isinstance(path_hex, str):
            fail("runtime path invalid")
        raw_path = decode_rel(path_hex)
        if path_hex in indexed:
            fail("duplicate runtime provenance path")
        component = row.get("component")
        if not isinstance(component, dict) or set(component) != {"component_evidence_sha256", "component_identity_sha256", "component_root_path_hex", "component_type", "component_version", "slug"}:
            fail("component provenance invalid")
        component_root = component.get("component_root_path_hex")
        if not isinstance(component_root, str):
            fail("component root invalid")
        root_raw = decode_rel(component_root)
        if raw_path != root_raw and not raw_path.startswith(root_raw + b"/"):
            fail("runtime path outside proven component surface")
        if component.get("component_type") not in COMPONENT_TYPES or not isinstance(component.get("slug"), str) or not SAFE_NAME.fullmatch(component["slug"]) or not isinstance(component.get("component_version"), str) or not VERS.fullmatch(component["component_version"]):
            fail("component identity invalid")
        if any(not isinstance(component.get(key), str) or not HEX64.fullmatch(component[key]) for key in ("component_evidence_sha256", "component_identity_sha256")):
            fail("component evidence binding invalid")
        ioc, persistence = row.get("ioc_correlation"), row.get("incident_persistence")
        if not isinstance(ioc, dict) or set(ioc) != {"evidence_sha256", "matches"} or ioc.get("matches") != 0 or not isinstance(ioc.get("evidence_sha256"), str) or not HEX64.fullmatch(ioc["evidence_sha256"]):
            fail("IOC correlation is not closed")
        if not isinstance(persistence, dict) or set(persistence) != {"evidence_sha256", "related"} or persistence.get("related") is not False or not isinstance(persistence.get("evidence_sha256"), str) or not HEX64.fullmatch(persistence["evidence_sha256"]):
            fail("incident persistence relation is not closed")
        if row.get("runtime_role") not in RUNTIME_ROLES:
            fail("runtime role invalid")
        indexed[path_hex] = row
    if list(indexed) != sorted(indexed):
        fail("runtime provenance ordering invalid")
    return indexed, value, raw


def reference(path: pathlib.Path, raw: bytes) -> dict[str, object]:
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def parse_candidate(path: pathlib.Path, disposition: dict[str, object]) -> tuple[dict[str, object], bytes]:
    raw = read_regular(path)
    if not raw.endswith(b"\n") or b"\0" in raw or len(raw) > 125_829_120:
        fail("volatile inventory candidate framing invalid")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("volatile inventory candidate encoding invalid")
    if not lines or len(lines) > 200_010:
        fail("volatile inventory candidate cardinality invalid")
    nonce: str | None = None
    root: list[str] | None = None
    runtime: list[str] | None = None
    summary: list[str] | None = None
    header: list[str] | None = None
    entries: dict[str, list[str]] = {}
    candidate_paths: dict[str, tuple[str, str]] = {}
    snapshot_lines: list[str] = []
    candidate_started = False
    audit: list[str] | None = None
    for index, line in enumerate(lines):
        fields = line.split("\t")
        kind = fields[0]
        if kind == "CAPTURE_NONCE":
            if index != 0 or nonce is not None or len(fields) != 2 or not HEX64.fullmatch(fields[1]):
                fail("volatile inventory candidate nonce invalid")
            nonce = fields[1]
        elif kind == "ROOT":
            if candidate_started or root is not None or len(fields) != 11:
                fail("volatile inventory candidate root invalid")
            root = fields
            snapshot_lines.append(line)
        elif kind == "RUNTIME":
            if candidate_started or runtime is not None or len(fields) != 5:
                fail("volatile inventory candidate runtime invalid")
            runtime = fields
            snapshot_lines.append(line)
        elif kind == "ENTRY":
            if candidate_started or len(fields) != 16 or fields[1] in entries:
                fail("volatile inventory candidate entry invalid")
            relative = b"" if fields[1] == "" else decode_rel(fields[1])
            absolute = decode_abs(fields[2])
            root_raw = decode_abs(str(disposition.get("root_path_hex", "")))
            if absolute != root_raw + (b"/" + relative if relative else b""):
                fail("volatile inventory candidate absolute path mismatch")
            if fields[3] not in {"REGULAR", "DIRECTORY"} or not MODE.fullmatch(fields[5]):
                fail("volatile inventory candidate entry metadata invalid")
            size = exact_uint(fields[4], "entry size")
            exact_uint(fields[6], "entry uid"); exact_uint(fields[7], "entry gid")
            exact_sint(fields[8], "entry mtime"); exact_sint(fields[9], "entry ctime")
            exact_uint(fields[10], "entry device"); exact_uint(fields[11], "entry inode"); nlink = exact_uint(fields[12], "entry nlink")
            expected_uploads = any(part == b"uploads" for part in relative.split(b"/"))
            if fields[15] != ("1" if expected_uploads else "0") or fields[13] != "-":
                fail("volatile inventory candidate entry location/target invalid")
            if fields[3] == "REGULAR":
                if size > 1_073_741_824 or nlink != 1 or not HEX64.fullmatch(fields[14]):
                    fail("volatile inventory candidate regular identity invalid")
            elif fields[14] != "-":
                fail("volatile inventory candidate directory hash invalid")
            if size > 2**63 - 1:
                fail("volatile inventory candidate entry size out of range")
            entries[fields[1]] = fields
            snapshot_lines.append(line)
        elif kind == "SUMMARY":
            if candidate_started or summary is not None or len(fields) != 20:
                fail("volatile inventory candidate summary invalid")
            summary = fields
            snapshot_lines.append(line)
        elif kind == "VOLATILE_RUNTIME_CANDIDATE":
            if header is not None or len(fields) != 6:
                fail("volatile inventory candidate header invalid")
            candidate_started = True
            header = fields
        elif kind == "VOLATILE_RUNTIME_CANDIDATE_PATH":
            if not candidate_started or audit is not None or len(fields) != 4 or fields[1] in candidate_paths:
                fail("volatile inventory candidate path invalid")
            decode_rel(fields[1])
            if fields[2] not in {"CTIME_ONLY", "APPEND_PREFIX_VERIFIED_LOG_GROWTH", "APPEND_PREFIX_VERIFIED_UPLOAD_LOG_GROWTH"} or fields[3] not in {"OBSERVED_DRIFT", "OBSERVED_STABLE"}:
                fail("volatile inventory candidate behavior invalid")
            candidate_paths[fields[1]] = (fields[2], fields[3])
        elif kind == "EPHEMERAL_BOOTSTRAP_AUDIT_V2":
            if not candidate_started or audit is not None or index != len(lines) - 1 or len(fields) != 9:
                fail("volatile inventory bootstrap audit invalid")
            audit = fields
        elif kind == "UNRESOLVED":
            fail("volatile inventory candidate has unresolved coverage")
        else:
            fail("volatile inventory candidate row type invalid")
    if None in (nonce, root, runtime, summary, header):
        fail("volatile inventory candidate binding missing")
    assert nonce is not None and root is not None and runtime is not None and summary is not None and header is not None
    if snapshot_lines != sorted(snapshot_lines) or len(snapshot_lines) != len(set(snapshot_lines)):
        fail("volatile inventory candidate snapshot ordering invalid")
    if list(candidate_paths) != sorted(candidate_paths):
        fail("volatile inventory candidate disposition ordering invalid")
    root_identity = disposition.get("root_identity")
    if not isinstance(root_identity, dict) or set(root_identity) != {"device", "inode"}:
        fail("volatile inventory disposition root identity invalid")
    if root[1] != disposition.get("root_path_hex") or root[2] != root[1] or exact_uint(root[3], "root device") != root_identity["device"] or exact_uint(root[4], "root inode") != root_identity["inode"]:
        fail("volatile inventory candidate root mismatch")
    if not MODE.fullmatch(root[5]):
        fail("volatile inventory candidate root mode invalid")
    for offset, label in ((6, "root uid"), (7, "root gid"), (8, "root nlink")):
        exact_uint(root[offset], label)
    exact_sint(root[9], "root mtime"); exact_sint(root[10], "root ctime")
    runtime_identity = disposition.get("runtime_identity")
    expected_runtime_path = b"memfd:wapp-native-displaced-inventory-linux-x86_64-v1".hex()
    if not isinstance(runtime_identity, dict) or runtime[1] != "PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1" or runtime[2] != expected_runtime_path or runtime[3] != disposition.get("helper_sha256") or not HEX64.fullmatch(runtime[3]) or not HEX64.fullmatch(runtime[4]):
        fail("volatile inventory candidate helper mismatch")
    expected_caps = ["200000", "50000", "150000", "1073741824", "34359738368", "64", "900", "4096", "125829120"]
    if summary[11:] != expected_caps or summary[8] != "0" or summary[9] != "true" or not HEX64.fullmatch(summary[10]):
        fail("volatile inventory candidate coverage incomplete")
    counts = [exact_uint(value, "inventory summary") for value in summary[1:8]]
    entry_lines = ["\t".join(entries[key]) for key in sorted(entries)]
    inventory_hash = hashlib.sha256("".join(line + "\n" for line in entry_lines).encode("ascii")).hexdigest()
    regular = [row for row in entries.values() if row[3] == "REGULAR"]
    directories = [row for row in entries.values() if row[3] == "DIRECTORY"]
    uploads = [row for row in entries.values() if row[15] == "1"]
    expected_counts = [len(entries), len(directories), len(regular), len(regular), sum(int(row[4]) for row in regular), len(uploads), 0]
    if counts != expected_counts or counts[0] > 200_000 or counts[1] > 50_000 or counts[2] > 150_000 or counts[4] > 34_359_738_368 or summary[10] != inventory_hash:
        fail("volatile inventory candidate summary derivation mismatch")
    root_entry = entries.get("")
    expected_root_entry_metadata = [root[5], root[6], root[7], root[9], root[10], root[3], root[4], root[8]]
    if root_entry is None or root_entry[3] != "DIRECTORY" or (int(root_entry[10]), int(root_entry[11])) != (root_identity["device"], root_identity["inode"]) or root_entry[5:13] != expected_root_entry_metadata:
        fail("volatile inventory candidate root row mismatch")
    runtime_contract = runtime_identity.get("contract")
    if runtime_contract == "DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1":
        policy_path = pathlib.Path(__file__).resolve().parent.parent / "config/native-ephemeral-bootstrap.json"
        policy, _ = load_json(policy_path)
        stable_meta = runtime_identity.get("stable_launcher_metadata")
        if runtime_identity.get("identity_scope") != "OPERATION_SCOPED" or runtime_identity.get("launcher_sha256") != policy.get("launcher_binary_sha256") or runtime_identity.get("helper_sha256") != runtime[3] or runtime_identity.get("transport") != "sealed_memfd_execveat_v1" or not isinstance(stable_meta, dict) or stable_meta.get("bytes") != policy.get("launcher_binary_bytes") or stable_meta.get("mode") != "700":
            fail("volatile inventory degraded runtime identity mismatch")
        if audit is None or audit[1] != nonce or audit[2] != policy.get("launcher_binary_sha256") or audit[3] != str(policy.get("launcher_binary_bytes")) or audit[8] != "CLEANUP_VERIFIED" or any(not HEX64.fullmatch(audit[index]) for index in (5, 6, 7)):
            fail("volatile inventory degraded bootstrap audit mismatch")
        metadata_parts = audit[4].split(":")
        if len(metadata_parts) != 6 or not all(UINT.fullmatch(value) for value in metadata_parts[:2] + metadata_parts[3:]) or not MODE.fullmatch(metadata_parts[2]):
            fail("volatile inventory degraded launcher metadata invalid")
        candidate_meta = {"uid": int(metadata_parts[0]), "gid": int(metadata_parts[1]), "mode": metadata_parts[2], "device": int(metadata_parts[3]), "inode": int(metadata_parts[4]), "bytes": int(metadata_parts[5])}
        if {key: candidate_meta[key] for key in sorted(candidate_meta.keys() - {"inode"})} != stable_meta or candidate_meta["bytes"] != policy.get("launcher_binary_bytes") or candidate_meta["mode"] != "700":
            fail("volatile inventory degraded launcher metadata drift")
        candidate_runtime = f"loader=DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1|launcher_sha={audit[2]}|launcher_meta={audit[4]}|helper_sha={runtime[3]}|transport=sealed_memfd_execveat_v1"
        expected_runtime_sha = hashlib.sha256(candidate_runtime.encode("ascii")).hexdigest()
        expected_launcher_identity = hashlib.sha256((audit[4] + "\0" + audit[2]).encode("ascii")).hexdigest()
        if audit[5] != expected_runtime_sha or runtime[4] != expected_runtime_sha or audit[6] != expected_launcher_identity:
            fail("volatile inventory degraded runtime/audit identity mismatch")
        lifecycles = runtime_identity.get("verified_lifecycles")
        lifecycle_keys = {"audit_sha256", "launcher_identity_sha256", "operation_id", "runtime_identity_sha256", "stage_identity_sha256"}
        if not isinstance(lifecycles, list) or len(lifecycles) != 2 or any(not isinstance(item, dict) or set(item) != lifecycle_keys for item in lifecycles):
            fail("volatile inventory degraded lifecycle history invalid")
        # Ephemeral staging is operation-scoped. A filesystem may legitimately
        # recycle the same inode after an exact verified unlink, so identical
        # release bytes and metadata can reproduce the runtime identity hash.
        # Replay is bound by the independently fresh operation and staging
        # identities; bytes/helper/metadata/cleanup remain exact above.
        if nonce in {str(item["operation_id"]) for item in lifecycles} or audit[7] in {str(item["stage_identity_sha256"]) for item in lifecycles}:
            fail("volatile inventory degraded lifecycle replay")
    elif runtime_contract == "TRUSTED_PERL_SEALED_MEMFD_EXECVEAT_V1":
        if runtime[4] != runtime_identity.get("identity_sha256") or audit is not None:
            fail("volatile inventory unexpected bootstrap audit")
    else:
        fail("volatile inventory runtime contract invalid")
    token = disposition.get("helper_policy_token")
    token_sha = disposition.get("helper_policy_token_sha256")
    if not isinstance(token, str) or not isinstance(token_sha, str) or hashlib.sha256(token.encode("ascii")).hexdigest() != token_sha:
        fail("volatile inventory disposition token invalid")
    if header != ["VOLATILE_RUNTIME_CANDIDATE", "BOUNDED_VOLATILE_RUNTIME_CANDIDATE_V1", token_sha, str(len(disposition.get("paths", []))), "VISIBLE", "UNVERIFIED_NON_AUTHORIZING"]:
        fail("volatile inventory candidate disposition binding invalid")
    expected_paths: dict[str, str] = {}
    behavior_map = {
        "CTIME_ONLY": "CTIME_ONLY",
        "APPEND_PREFIX_REQUIRED_LOG_GROWTH": "APPEND_PREFIX_VERIFIED_LOG_GROWTH",
        "APPEND_PREFIX_REQUIRED_UPLOAD_LOG_GROWTH": "APPEND_PREFIX_VERIFIED_UPLOAD_LOG_GROWTH",
    }
    disposition_paths = disposition.get("paths")
    if not isinstance(disposition_paths, list):
        fail("volatile inventory disposition paths invalid")
    for row in disposition_paths:
        if not isinstance(row, dict) or not isinstance(row.get("normalized_path_hex"), str) or row.get("behavior") not in behavior_map:
            fail("volatile inventory disposition row invalid")
        expected_paths[row["normalized_path_hex"]] = behavior_map[row["behavior"]]
    if set(candidate_paths) != set(expected_paths):
        fail("volatile inventory candidate path scope mismatch")
    bound_paths: list[dict[str, object]] = []
    for path_hex in sorted(expected_paths):
        behavior_value, observed = candidate_paths[path_hex]
        if behavior_value != expected_paths[path_hex]:
            fail("volatile inventory candidate behavior mismatch")
        entry = entries.get(path_hex)
        if entry is None or entry[3] != "REGULAR" or entry[14] == "-" or not HEX64.fullmatch(entry[14]):
            fail("volatile inventory candidate path not visibly hashed")
        try:
            if int(entry[5], 8) & 0o111:
                fail("volatile inventory candidate executable rejected")
        except ValueError:
            fail("volatile inventory candidate mode invalid")
        bound_paths.append({
            "normalized_path_hex": path_hex,
            "behavior": behavior_value,
            "observation": observed,
            "visible_entry_sha256": hashlib.sha256(("\t".join(entry) + "\n").encode("ascii")).hexdigest(),
        })
    return {
        "capture_nonce": nonce,
        "root_path_hex": root[1],
        "root_device": root[3],
        "root_inode": root[4],
        "runtime_mode": runtime[1],
        "runtime_path_hex": runtime[2],
        "runtime_identity_sha256": runtime[4],
        "inventory_summary_sha256": summary[10],
        "ephemeral_bootstrap_audit_sha256": hashlib.sha256(("\t".join(audit) + "\n").encode("ascii")).hexdigest() if audit else None,
        "entry_count": int(summary[1]),
        "file_count": int(summary[3]),
        "paths": bound_paths,
    }, raw


def inventory_derive(candidate_path: pathlib.Path, disposition_path: pathlib.Path) -> dict[str, object]:
    disposition_value, disposition_raw = load_json(disposition_path)
    verified = verify(disposition_value)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if now < parse_time(verified["issued_at"], "issued timestamp") or now > parse_time(verified["expires_at"], "expiry"):
        fail("disposition not current for inventory binding")
    candidate, candidate_raw = parse_candidate(candidate_path, verified)
    return {
        "tool": "wapp-security-bounded-volatile-runtime-inventory",
        "schema": 1,
        "contract": "BOUNDED_VOLATILE_RUNTIME_INVENTORY_V1",
        "authority": {"apply": False, "clean": False, "closure": False, "mutation": False, "prepare": False, "ready": False, "remediation": False},
        "decision_eligible": False,
        "filesystem_coverage_weakened": False,
        "paths_remain_visible": True,
        "raw_candidate": reference(candidate_path, candidate_raw),
        "signed_disposition": reference(disposition_path, disposition_raw),
        "public_core_version": verified["public_core_version"],
        "helper_sha256": verified["helper_sha256"],
        "target_product_identity_sha256": verified["target_product_identity_sha256"],
        **candidate,
    }


def inventory_verify(value: dict[str, object]) -> dict[str, object]:
    if value.get("tool") != "wapp-security-bounded-volatile-runtime-inventory" or value.get("schema") != 1:
        fail("volatile inventory artifact type invalid")
    refs = (value.get("raw_candidate"), value.get("signed_disposition"))
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"bytes", "path", "sha256"} or not isinstance(ref["path"], str) or not ref["path"].startswith("/") or not isinstance(ref["sha256"], str) or not HEX64.fullmatch(ref["sha256"]) or not isinstance(ref["bytes"], int):
            fail("volatile inventory artifact reference invalid")
        raw = read_regular(pathlib.Path(ref["path"]))
        if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            fail("volatile inventory artifact source substitution")
    expected = inventory_derive(pathlib.Path(refs[0]["path"]), pathlib.Path(refs[1]["path"]))
    if canonical(value) != canonical(expected):
        fail("volatile inventory artifact derivation mismatch")
    return expected


def derive(first_path: pathlib.Path, second_path: pathlib.Path, provenance_path: pathlib.Path, issued_at: str) -> dict[str, object]:
    first, first_raw = diagnostic(first_path)
    second, second_raw = diagnostic(second_path)
    if first_path == second_path or hashlib.sha256(first_raw).digest() == hashlib.sha256(second_raw).digest():
        fail("two distinct signed observations required")
    first_time, second_time = parse_time(first.get("observed_at"), "first observation"), parse_time(second.get("observed_at"), "second observation")
    if second_time <= first_time or second_time - first_time > dt.timedelta(hours=24):
        fail("repeated observation chronology invalid")
    issued = parse_time(issued_at, "issued timestamp")
    if issued < second_time or issued - second_time > dt.timedelta(minutes=10):
        fail("disposition issue currentness invalid")
    exact = ("root_path_hex", "helper_sha256", "public_core_version")
    if any(first.get(key) != second.get(key) for key in exact):
        fail("repeated observation identity mismatch")
    root_identities = [first.get("pass1_root"), first.get("pass2_root"), second.get("pass1_root"), second.get("pass2_root")]
    if not all(isinstance(identity, dict) and set(identity) == {"device", "inode"} for identity in root_identities) or any(identity != root_identities[0] for identity in root_identities[1:]):
        fail("repeated observation root identity mismatch")
    runtime_identity = runtime_continuity(first, second)
    first_product, second_product = first.get("product_seal"), second.get("product_seal")
    product_keys = ("commit", "version", "runtime_components")
    if not isinstance(first_product, dict) or not isinstance(second_product, dict) or any(first_product.get(key) != second_product.get(key) for key in product_keys):
        fail("repeated observation Product identity mismatch")
    first_deltas, second_deltas = first.get("deltas"), second.get("deltas")
    if not isinstance(first_deltas, list) or not isinstance(second_deltas, list) or not first_deltas or len(first_deltas) != len(second_deltas):
        fail("repeated observation delta cardinality mismatch")
    def index(rows: list[object]) -> dict[str, tuple[str, dict[str, object]]]:
        out: dict[str, tuple[str, dict[str, object]]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("normalized_path_hex"), str):
                fail("diagnostic delta row invalid")
            path_hex = row["normalized_path_hex"]
            decode_rel(path_hex)
            if path_hex in out:
                fail("duplicate diagnostic path")
            out[path_hex] = (behavior(row), row)
        return out
    left, right = index(first_deltas), index(second_deltas)
    if set(left) != set(right) or any(left[path][0] != right[path][0] for path in left):
        fail("repeated observations do not match")
    for path_hex in left:
        first_post, second_pre = left[path_hex][1].get("pass2"), right[path_hex][1].get("pass1")
        if not isinstance(first_post, dict) or not isinstance(second_pre, dict):
            fail("observation continuity state missing")
        if left[path_hex][0] == "CTIME_ONLY":
            if state_without_ctime(first_post) != state_without_ctime(second_pre) or int(second_pre["ctime_ns"]) < int(first_post["ctime_ns"]):
                fail("ctime observation continuity invalid")
        elif first_post != second_pre:
            fail("log observation boundary is not byte-exact")
    proven, provenance_value, provenance_raw = provenance(provenance_path)
    if set(proven) != set(left) or provenance_value["root_path_hex"] != first["root_path_hex"]:
        fail("provenance scope mismatch")
    provenance_time = parse_time(provenance_value["generated_at"], "provenance timestamp")
    if provenance_time < first_time or provenance_time > issued:
        fail("runtime provenance currentness invalid")
    paths: list[dict[str, object]] = []
    token_parts: list[str] = []
    for path_hex in sorted(left):
        derived_behavior = left[path_hex][0]
        expected_role = "APPEND_ONLY_LOG" if derived_behavior in ("APPEND_PREFIX_REQUIRED_LOG_GROWTH", "APPEND_PREFIX_REQUIRED_UPLOAD_LOG_GROWTH") else "GENERATED_RUNTIME_STATE"
        if proven[path_hex]["runtime_role"] != expected_role:
            fail("runtime role/behavior mismatch")
        if derived_behavior in ("APPEND_PREFIX_REQUIRED_LOG_GROWTH", "APPEND_PREFIX_REQUIRED_UPLOAD_LOG_GROWTH") and not decode_rel(path_hex).lower().endswith(b".log"):
            fail("monotonic runtime log lacks exact log suffix")
        token_parts.append(({"APPEND_PREFIX_REQUIRED_LOG_GROWTH": "L", "APPEND_PREFIX_REQUIRED_UPLOAD_LOG_GROWTH": "A"}.get(derived_behavior, "C")) + ":" + path_hex)
        paths.append({
            "normalized_path_hex": path_hex,
            "disposition": "VOLATILE_RUNTIME_VERIFIED",
            "behavior": derived_behavior,
            "component": proven[path_hex]["component"],
            "runtime_role": proven[path_hex]["runtime_role"],
            "ioc_correlation": proven[path_hex]["ioc_correlation"],
            "incident_persistence": proven[path_hex]["incident_persistence"],
        })
    token = ",".join(token_parts)
    if len(token) > 32768:
        fail("helper policy token cap")
    expires = issued + dt.timedelta(hours=2)
    return {
        "tool": "wapp-security-bounded-volatile-runtime-disposition",
        "schema": 1,
        "contract": "BOUNDED_VOLATILE_RUNTIME_DISPOSITION_V1",
        "disposition": "VOLATILE_RUNTIME_VERIFIED",
        "authority": {"apply": False, "clean": False, "closure": False, "mutation": False, "prepare": False, "ready": False, "remediation": False},
        "decision_eligible": False,
        "filesystem_coverage_weakened": False,
        "paths_remain_visible": True,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root_path_hex": first["root_path_hex"],
        "root_identity": root_identities[0],
        "helper_sha256": first["helper_sha256"],
        "runtime_identity": runtime_identity,
        "public_core_version": first["public_core_version"],
        "target_product_identity_sha256": provenance_value["target_product_identity_sha256"],
        "diagnostics": [reference(first_path, first_raw), reference(second_path, second_raw)],
        "runtime_provenance": reference(provenance_path, provenance_raw),
        "helper_policy_token": token,
        "helper_policy_token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "paths": paths,
    }


def verify(value: dict[str, object]) -> dict[str, object]:
    if value.get("tool") != "wapp-security-bounded-volatile-runtime-disposition" or value.get("schema") != 1:
        fail("artifact type invalid")
    diagnostics = value.get("diagnostics")
    provenance_ref = value.get("runtime_provenance")
    if not isinstance(diagnostics, list) or len(diagnostics) != 2 or not isinstance(provenance_ref, dict):
        fail("artifact dependency binding invalid")
    refs = diagnostics + [provenance_ref]
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"bytes", "path", "sha256"} or not isinstance(ref["path"], str) or not ref["path"].startswith("/") or not isinstance(ref["sha256"], str) or not HEX64.fullmatch(ref["sha256"]) or not isinstance(ref["bytes"], int):
            fail("artifact dependency reference invalid")
        raw = read_regular(pathlib.Path(ref["path"]))
        if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            fail("artifact dependency substitution")
    expected = derive(pathlib.Path(diagnostics[0]["path"]), pathlib.Path(diagnostics[1]["path"]), pathlib.Path(provenance_ref["path"]), str(value.get("issued_at", "")))
    if canonical(value) != canonical(expected):
        fail("artifact derivation mismatch")
    return expected


def write_exclusive(path: pathlib.Path, payload: bytes) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        fail("output collision or non-absolute path")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        fail("output exclusive create failed")
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                fail("output write failed")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> None:
    if len(sys.argv) == 7 and sys.argv[1] == "create":
        first, second, provenance_path, issued, output = map(pathlib.Path, (sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]))
        write_exclusive(output, canonical(derive(first, second, provenance_path, str(issued))))
        return
    if len(sys.argv) == 3 and sys.argv[1] in ("verify", "dependencies", "policy-token"):
        artifact = pathlib.Path(sys.argv[2])
        value, _ = load_json(artifact)
        verified = verify(value)
        if sys.argv[1] == "dependencies":
            for ref in verified["diagnostics"] + [verified["runtime_provenance"]]:
                print(ref["path"])
        elif sys.argv[1] == "policy-token":
            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            if now < parse_time(verified["issued_at"], "issued timestamp") or now > parse_time(verified["expires_at"], "expiry"):
                fail("disposition expired")
            print(verified["helper_policy_token"])
        else:
            print("BOUNDED_VOLATILE_RUNTIME_DISPOSITION: VERIFIED_NON_AUTHORIZING")
        return
    if len(sys.argv) == 5 and sys.argv[1] == "inventory-create":
        candidate, disposition_path, output = map(pathlib.Path, sys.argv[2:5])
        write_exclusive(output, canonical(inventory_derive(candidate, disposition_path)))
        return
    if len(sys.argv) == 3 and sys.argv[1] in ("inventory-verify", "inventory-dependencies"):
        artifact = pathlib.Path(sys.argv[2])
        value, _ = load_json(artifact)
        verified = inventory_verify(value)
        if sys.argv[1] == "inventory-dependencies":
            print(verified["raw_candidate"]["path"])
            print(verified["signed_disposition"]["path"])
        else:
            print("BOUNDED_VOLATILE_RUNTIME_INVENTORY: VERIFIED_NON_AUTHORIZING")
        return
    fail("usage")


if __name__ == "__main__":
    main()
