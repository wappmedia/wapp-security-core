#!/usr/bin/env python3
"""Deterministic, read-only semantic binder for native filesystem evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any


HEX = re.compile(r"^(?:[a-f0-9]{2})*$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
UINT = re.compile(r"^(?:0|[1-9][0-9]*)$")
MODE = re.compile(r"^[0-7]{3,4}$")
STAMP = "%Y-%m-%dT%H:%M:%SZ"
MAX_ARTIFACT = 128 * 1024 * 1024
MAX_OBJECTS = 200_000
FALSE_AUTHORITY = {
    "apply": False,
    "clean": False,
    "closure": False,
    "mutation": False,
    "prepare": False,
    "ready": False,
    "remediation": False,
}
PROVENANCE = {
    ("OFFICIAL_UPSTREAM_EXACT", "WORDPRESS_ORG_CHECKSUMS_V1"),
    ("OFFICIAL_UPSTREAM_EXACT", "WORDPRESS_ORG_RELEASE_ARCHIVE_V1"),
    ("OFFICIAL_UPSTREAM_EXACT", "SIGNED_VENDOR_RELEASE_MANIFEST_V1"),
    ("RELEASED_RUNTIME_VERIFIED", "BOUNDED_VOLATILE_RUNTIME_DISPOSITION_V1"),
}


class Invalid(ValueError):
    pass


def fail(message: str) -> None:
    raise Invalid(message)


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular(path: pathlib.Path, maximum: int = MAX_ARTIFACT) -> bytes:
    if not path.is_absolute():
        fail("absolute artifact path required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"secure artifact open failed: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            fail("bounded regular single-link artifact required")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum:
                fail("artifact byte cap exceeded")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after):
            fail("artifact changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, Invalid) as error:
        fail(f"strict JSON required: {error}")
    if not isinstance(value, dict):
        fail("top-level JSON object required")
    return value, raw


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        fail(f"invalid {label}")
    try:
        return dt.datetime.strptime(value, STAMP).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        fail(f"invalid {label}")


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} key set mismatch")
    return value


def reference(path: pathlib.Path, raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "path": str(path), "sha256": sha(raw)}


def validate_reference(value: Any, label: str) -> tuple[pathlib.Path, bytes]:
    ref = exact_keys(value, {"bytes", "path", "sha256"}, label)
    if not isinstance(ref["path"], str) or not ref["path"].startswith("/") or not isinstance(ref["bytes"], int) or ref["bytes"] < 1 or not isinstance(ref["sha256"], str) or not HEX64.fullmatch(ref["sha256"]):
        fail(f"invalid {label} reference")
    path = pathlib.Path(ref["path"])
    raw = read_regular(path)
    if len(raw) != ref["bytes"] or sha(raw) != ref["sha256"]:
        fail(f"{label} reference substitution")
    return path, raw


def decode_relative(value: str) -> bytes:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        fail("invalid normalized path hex")
    raw = bytes.fromhex(value)
    parts = raw.split(b"/") if raw else []
    if b"\0" in raw or any(part in (b"", b".", b"..") for part in parts):
        fail("unsafe normalized path")
    return raw


def parse_inventory(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_ARTIFACT or not raw.endswith(b"\n"):
        fail("inventory framing or cap")
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeError:
        fail("inventory must be ASCII")
    if not lines or lines != sorted(set(lines)):
        fail("inventory ordering or duplication")
    entries: dict[str, dict[str, Any]] = {}
    unresolved: list[list[str]] = []
    roots: list[list[str]] = []
    runtimes: list[list[str]] = []
    summaries: list[list[str]] = []
    for line in lines:
        fields = line.split("\t")
        if fields[0] == "ENTRY":
            if len(fields) != 16 or not HEX.fullmatch(fields[1]) or not HEX.fullmatch(fields[2]) or fields[3] not in {"REGULAR", "DIRECTORY", "SYMLINK", "BLOCK_DEVICE", "CHAR_DEVICE", "FIFO", "SOCKET", "OTHER"} or any(not UINT.fullmatch(item) for item in fields[4:5] + fields[6:13]) or not MODE.fullmatch(fields[5]) or (fields[13] != "-" and not HEX.fullmatch(fields[13])) or (fields[14] != "-" and not HEX64.fullmatch(fields[14])) or fields[15] not in {"0", "1"}:
                fail("invalid inventory entry")
            relative = decode_relative(fields[1])
            if fields[1] in entries:
                fail("duplicate inventory path")
            entries[fields[1]] = {
                "absolute_path_hex": fields[2], "type": fields[3], "size": int(fields[4]),
                "mode": fields[5], "uid": int(fields[6]), "gid": int(fields[7]),
                "mtime_ns": int(fields[8]), "ctime_ns": int(fields[9]), "device": int(fields[10]),
                "inode": int(fields[11]), "nlink": int(fields[12]), "symlink_target_hex": fields[13],
                "sha256": fields[14], "uploads": fields[15] == "1", "relative": relative,
                "line": line,
            }
        elif fields[0] == "UNRESOLVED":
            if len(fields) != 4 or not re.fullmatch(r"[A-Z0-9_]+", fields[1]) or not HEX.fullmatch(fields[2]) or not HEX64.fullmatch(fields[3]):
                fail("invalid unresolved inventory row")
            unresolved.append(fields)
        elif fields[0] == "ROOT":
            if len(fields) != 11 or not HEX.fullmatch(fields[1]) or not HEX.fullmatch(fields[2]) or any(not UINT.fullmatch(item) for item in fields[3:5] + fields[6:11]) or not MODE.fullmatch(fields[5]):
                fail("invalid root row")
            roots.append(fields)
        elif fields[0] == "RUNTIME":
            if len(fields) != 5 or not HEX.fullmatch(fields[2]) or not HEX64.fullmatch(fields[3]) or not HEX64.fullmatch(fields[4]):
                fail("invalid runtime row")
            runtimes.append(fields)
        elif fields[0] == "SUMMARY":
            if len(fields) != 20 or any(not UINT.fullmatch(item) for item in fields[1:9] + fields[11:20]) or fields[9] not in {"true", "false"} or not HEX64.fullmatch(fields[10]):
                fail("invalid summary row")
            summaries.append(fields)
        else:
            fail("unknown inventory row")
    if len(entries) > MAX_OBJECTS or len(roots) != 1 or len(runtimes) != 1 or len(summaries) != 1:
        fail("inventory singleton or object cap")
    root, runtime, summary = roots[0], runtimes[0], summaries[0]
    if bytes.fromhex(root[1]) != bytes.fromhex(root[2]) or not bytes.fromhex(root[1]).startswith(b"/"):
        fail("production root alias or framing invalid")
    if runtime[1] != "PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1" or bytes.fromhex(runtime[2]) != b"memfd:wapp-native-displaced-inventory-linux-x86_64-v1":
        fail("native runtime contract mismatch")
    entry_lines = [entry["line"] for entry in entries.values()]
    inventory_commitment = sha(("\n".join(sorted(entry_lines)) + "\n").encode("ascii"))
    if inventory_commitment != summary[10]:
        fail("inventory commitment mismatch")
    regular = [entry for entry in entries.values() if entry["type"] == "REGULAR"]
    directories = [entry for entry in entries.values() if entry["type"] == "DIRECTORY"]
    hashed = [entry for entry in regular if entry["sha256"] != "-"]
    other = [entry for entry in entries.values() if entry["type"] not in {"REGULAR", "DIRECTORY"}]
    counts = [len(entries), len(directories), len(regular), len(hashed), sum(entry["size"] for entry in hashed), sum(1 for entry in entries.values() if entry["uploads"]), len(other), len(unresolved)]
    if counts != [int(item) for item in summary[1:9]] or (summary[9] == "true") != (len(unresolved) == 0):
        fail("inventory summary derivation mismatch")
    if summary[11:] != ["200000", "150000", "150000", "1073741824", "34359738368", "64", "900", "4096", "125829120"]:
        fail("inventory cap contract mismatch")
    physical = bytes.fromhex(root[2])
    issue_paths = {row[2] for row in unresolved}
    for entry in entries.values():
        expected = physical if not entry["relative"] else physical + b"/" + entry["relative"]
        if bytes.fromhex(entry["absolute_path_hex"]) != expected:
            fail("inventory absolute path mismatch")
        if entry["uploads"] != (b"uploads" in entry["relative"].split(b"/")):
            fail("uploads classification mismatch")
        path_hex = entry["relative"].hex()
        if entry["type"] == "REGULAR":
            if entry["sha256"] == "-" and path_hex not in issue_paths:
                fail("unhashed regular object not unresolved")
            if entry["nlink"] != 1 and not any(row[1] == "HARDLINK_UNRESOLVED" and row[2] == path_hex for row in unresolved):
                fail("hardlink accepted as covered")
        elif entry["type"] != "DIRECTORY" and path_hex not in issue_paths:
            fail("unsupported object accepted as covered")
    root_entry = entries.get("")
    if root_entry is None or root_entry["type"] != "DIRECTORY" or root_entry["absolute_path_hex"] != root[2]:
        fail("root inventory entry missing")
    if [root_entry[key] for key in ("device", "inode", "mode", "uid", "gid", "nlink", "mtime_ns", "ctime_ns")] != [int(root[3]), int(root[4]), root[5], int(root[6]), int(root[7]), int(root[8]), int(root[9]), int(root[10])]:
        fail("root inventory identity mismatch")
    return {
        "entries": entries, "root_path_hex": root[1], "physical_root_hex": root[2],
        "root_identity": {"device": int(root[3]), "inode": int(root[4]), "mode": root[5], "uid": int(root[6]), "gid": int(root[7]), "nlink": int(root[8]), "mtime_ns": int(root[9]), "ctime_ns": int(root[10])},
        "runtime_mode": runtime[1], "runtime_path_hex": runtime[2], "helper_sha256": runtime[3],
        "runtime_identity_sha256": runtime[4], "inventory_commitment_sha256": inventory_commitment,
        "coverage_complete": summary[9] == "true", "unresolved_count": len(unresolved),
        "uncovered_path_count": len({row[2] for row in unresolved}), "counts": counts,
    }


def validate_release(commit: str, version: str) -> None:
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        fail("invalid Public Core commit")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        fail("invalid Public Core version")


def product_seal(value: dict[str, Any], raw: bytes, commit: str, version: str, project_root: pathlib.Path) -> None:
    exact_keys(value, {"tool", "schema", "generated_at", "version", "git", "discovery_policy", "component_count", "components", "local_only", "site_credentials_used"}, "Product Seal")
    git = exact_keys(value.get("git"), {"branch", "commit", "clean"}, "Product Seal git")
    if value["tool"] != "wapp-security-product-seal" or value["schema"] != 2 or value["version"] != version or git.get("commit") != commit or git.get("clean") is not True or value["local_only"] is not True or value["site_credentials_used"] is not False:
        fail("Product Seal identity mismatch")
    components = value.get("components")
    if not isinstance(components, list) or value.get("component_count") != len(components):
        fail("Product Seal component count mismatch")
    indexed: dict[str, dict[str, Any]] = {}
    for component in components:
        exact_keys(component, {"path", "sha256", "bytes"}, "Product Seal component")
        path = component["path"]
        if not isinstance(path, str) or path.startswith("/") or pathlib.PurePosixPath(path).as_posix() != path or path in indexed or not HEX64.fullmatch(component["sha256"]) or not isinstance(component["bytes"], int) or component["bytes"] < 1:
            fail("Product Seal component invalid")
        indexed[path] = component
    if list(indexed) != sorted(indexed):
        fail("Product Seal component ordering invalid")
    manifest_path = project_root / "config/canonical-components.txt"
    manifest_raw = read_regular(manifest_path, 1024 * 1024)
    try:
        manifest_lines = manifest_raw.decode("utf-8", "strict").splitlines()
    except UnicodeError:
        fail("canonical component manifest encoding invalid")
    canonical_paths = [line for line in manifest_lines if line and not line.startswith("#")]
    if len(canonical_paths) != len(set(canonical_paths)) or any(path.startswith("/") or pathlib.PurePosixPath(path).as_posix() != path for path in canonical_paths):
        fail("canonical component manifest invalid")
    required = set(canonical_paths) | {"VERSION", "bin/wapp-package-audit", "bin/wapp-public-data-boundary", "bin/wapp-release-check", "bin/wapp-test", "config/canonical-components.txt"}
    if set(indexed) != required:
        fail("Product Seal canonical component set mismatch")
    expected_policy = "tracked runtime toolchain: root launchers + install/update + bin/wapp dispatcher + bin/wapp-* + lib runtime + native helper source/build/encoded artifact/policy + release-sealed trust policy + VERSION + canonical surface manifest; sites.csv excluded"
    if value["discovery_policy"] != expected_policy:
        fail("Product Seal discovery policy mismatch")
    for relative in required:
        candidate = project_root / relative
        current = read_regular(candidate, 2 * 1024 * 1024)
        if indexed[relative] != {"path": relative, "sha256": sha(current), "bytes": len(current)}:
            fail("Product Seal current component substitution")


def capture_verify(value: dict[str, Any], current_commit: str, current_version: str, native_policy_path: pathlib.Path, ruleset_path: pathlib.Path, *, require_current: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_keys = {"tool", "schema", "contract", "classification_scope", "observed_at", "expires_at", "capture_nonce", "public_core", "public_product_seal", "source_collection_evidence", "native_policy", "collection_lifecycle", "root_path_hex", "physical_root_hex", "root_identity", "runtime_mode", "runtime_path_hex", "helper_sha256", "runtime_identity_sha256", "inventory_rows", "inventory_commitment_sha256", "entry_count", "unresolved_count", "uncovered_path_count", "coverage_complete", "authority"}
    exact_keys(value, expected_keys, "capture")
    if value["tool"] != "wapp-security-native-inventory-capture-binding" or value["schema"] != 1 or value["contract"] != "COMPLETE_BOUNDED_DESCRIPTOR_NOFOLLOW_TWO_PASS_V1" or value["classification_scope"] != "INVENTORY_ONLY_NO_DISPOSITION_V1":
        fail("capture type mismatch")
    if value["authority"] != FALSE_AUTHORITY:
        fail("capture authority invalid")
    validate_release(current_commit, current_version)
    rows_path, rows_raw = validate_reference(value["inventory_rows"], "capture inventory")
    source_path, source_raw = validate_reference(value["source_collection_evidence"], "source collection evidence")
    public = exact_keys(value["public_core"], {"commit", "version"}, "capture public_core")
    if public != {"commit": current_commit, "version": current_version}:
        fail("cross-release capture substitution")
    product_path, product_raw = validate_reference(value["public_product_seal"], "public Product Seal")
    product_value, loaded_product_raw = load(product_path)
    if product_raw != loaded_product_raw:
        fail("Product Seal read substitution")
    project_root = ruleset_path.parent.parent
    product_seal(product_value, product_raw, current_commit, current_version, project_root)
    policy_path, policy_raw = validate_reference(value["native_policy"], "native policy")
    if policy_path != native_policy_path or value["native_policy"] != reference(native_policy_path, read_regular(native_policy_path)):
        fail("native policy path or release substitution")
    policy, loaded_policy_raw = load(policy_path)
    if policy_raw != loaded_policy_raw or policy.get("tool") != "wapp-security-native-filesystem-helper-policy" or policy.get("schema") != 3 or policy.get("binary_sha256") != value["helper_sha256"]:
        fail("released native helper identity mismatch")
    inventory = parse_inventory(rows_raw)
    derived = {
        "root_path_hex": inventory["root_path_hex"], "physical_root_hex": inventory["physical_root_hex"],
        "root_identity": inventory["root_identity"], "runtime_mode": inventory["runtime_mode"],
        "runtime_path_hex": inventory["runtime_path_hex"], "helper_sha256": inventory["helper_sha256"],
        "runtime_identity_sha256": inventory["runtime_identity_sha256"],
        "inventory_commitment_sha256": inventory["inventory_commitment_sha256"], "entry_count": inventory["counts"][0],
        "unresolved_count": inventory["unresolved_count"], "uncovered_path_count": inventory["uncovered_path_count"],
        "coverage_complete": inventory["coverage_complete"],
    }
    for key, expected in derived.items():
        if value[key] != expected:
            fail(f"capture {key} derivation mismatch")
    if not HEX64.fullmatch(value["capture_nonce"]):
        fail("capture nonce invalid")
    observed, expires = timestamp(value["observed_at"], "capture observation"), timestamp(value["expires_at"], "capture expiry")
    if expires <= observed or expires - observed > dt.timedelta(minutes=30):
        fail("capture lifetime invalid")
    lifecycle = exact_keys(value["collection_lifecycle"], {"bootstrap_assurance", "server_temp_files_created", "target_host_ephemeral_bootstrap_modified", "target_filesystem_modified", "wordpress_filesystem_modified", "database_modified", "customer_configuration_modified", "ephemeral_cleanup_verified", "wordpress_executed", "php_executed"}, "collection lifecycle")
    common_false = ("wordpress_filesystem_modified", "database_modified", "customer_configuration_modified", "wordpress_executed", "php_executed")
    if any(lifecycle[key] is not False for key in common_false) or lifecycle["ephemeral_cleanup_verified"] is not True:
        fail("collection lifecycle mutation/execution mismatch")
    if lifecycle["bootstrap_assurance"] == "TRUSTED_MEMFD_LAUNCHER":
        expected_flags = (False, False, False)
    elif lifecycle["bootstrap_assurance"] == "DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP":
        expected_flags = (True, True, True)
    else:
        fail("collection bootstrap assurance invalid")
    if tuple(lifecycle[key] for key in ("server_temp_files_created", "target_host_ephemeral_bootstrap_modified", "target_filesystem_modified")) != expected_flags:
        fail("collection lifecycle assurance semantics mismatch")
    source, loaded_source_raw = load(source_path)
    exact_keys(source, {"tool", "schema", "contract", "observed_at", "expires_at", "capture_nonce", "inventory_rows", "root_path_hex", "physical_root_hex", "root_identity", "runtime_mode", "runtime_path_hex", "helper_sha256", "runtime_identity_sha256", "inventory_commitment_sha256", "collection_lifecycle", "authority"}, "source collection evidence")
    if loaded_source_raw != source_raw or source["tool"] != "wapp-security-native-inventory-collection-evidence" or source["schema"] != 1 or source["contract"] != "COMPLETE_BOUNDED_DESCRIPTOR_NOFOLLOW_TWO_PASS_V1" or source["authority"] != FALSE_AUTHORITY:
        fail("source collection evidence type or authority invalid")
    source_expected = {
        "observed_at": value["observed_at"], "expires_at": value["expires_at"], "capture_nonce": value["capture_nonce"],
        "inventory_rows": value["inventory_rows"], "root_path_hex": value["root_path_hex"], "physical_root_hex": value["physical_root_hex"],
        "root_identity": value["root_identity"], "runtime_mode": value["runtime_mode"], "runtime_path_hex": value["runtime_path_hex"],
        "helper_sha256": value["helper_sha256"], "runtime_identity_sha256": value["runtime_identity_sha256"],
        "inventory_commitment_sha256": value["inventory_commitment_sha256"], "collection_lifecycle": value["collection_lifecycle"],
    }
    if any(source[key] != expected for key, expected in source_expected.items()):
        fail("source collection evidence substitution")
    if require_current:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        observed, expires = timestamp(value["observed_at"], "capture observation"), timestamp(value["expires_at"], "capture expiry")
        if now < observed - dt.timedelta(seconds=60) or now > expires:
            fail("capture is not current")
    return value, inventory


def ruleset(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    value, raw = load(path)
    exact_keys(value, {"tool", "schema", "contract", "classification_version", "config_basenames", "executable_suffixes", "known_malicious", "uploads_executable_rule", "wordpress_runtime_roots", "wordpress_dropins"}, "ruleset")
    if value["tool"] != "wapp-security-read-only-surface-ruleset" or value["schema"] != 1 or value["contract"] != "READ_ONLY_SECURITY_SURFACE_V1" or value["classification_version"] != "READ_ONLY_SECURITY_SURFACE_V1":
        fail("ruleset identity mismatch")
    for key in ("config_basenames", "executable_suffixes", "wordpress_runtime_roots", "wordpress_dropins"):
        rows = value[key]
        if not isinstance(rows, list) or rows != sorted(set(rows)) or not all(isinstance(item, str) and item and item == item.lower() and "\0" not in item for item in rows):
            fail(f"ruleset {key} invalid")
    malicious: dict[str, str] = {}
    if not isinstance(value["known_malicious"], list):
        fail("ruleset malicious records invalid")
    for row in value["known_malicious"]:
        exact_keys(row, {"rule_id", "sha256"}, "malicious rule")
        if not isinstance(row["rule_id"], str) or not re.fullmatch(r"[A-Z0-9_]+", row["rule_id"]) or not HEX64.fullmatch(row["sha256"]) or row["sha256"] in malicious:
            fail("malicious rule invalid")
        malicious[row["sha256"]] = row["rule_id"]
    value["malicious_index"] = malicious
    return value, raw


def regular_set_commitment(inventory: dict[str, Any]) -> str:
    rows = [path_hex + "\t" + entry["sha256"] for path_hex, entry in inventory["entries"].items() if entry["type"] == "REGULAR"]
    return sha(("\n".join(sorted(rows)) + "\n").encode("ascii"))


def provenance(value: dict[str, Any], capture_path: pathlib.Path, capture_raw: bytes, capture: dict[str, Any], inventory: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[pathlib.Path]]:
    exact_keys(value, {"tool", "schema", "contract", "scope_mode", "regular_file_set_sha256", "record_set_sha256", "generated_at", "expires_at", "capture", "authority", "records"}, "provenance")
    if value["tool"] != "wapp-security-read-only-surface-provenance" or value["schema"] != 1 or value["contract"] != "READ_ONLY_SECURITY_SURFACE_PROVENANCE_V1" or value["scope_mode"] != "COMPLETE_CURRENT_REGULAR_FILE_SET_V1" or value["authority"] != FALSE_AUTHORITY:
        fail("provenance type or authority invalid")
    generated, expires = timestamp(value["generated_at"], "provenance timestamp"), timestamp(value["expires_at"], "provenance expiry")
    capture_observed, capture_expires = timestamp(capture["observed_at"], "capture observation"), timestamp(capture["expires_at"], "capture expiry")
    if generated < capture_observed or generated > capture_expires or expires <= generated or expires > capture_expires:
        fail("provenance currentness invalid")
    ref = exact_keys(value["capture"], {"bytes", "path", "sha256"}, "provenance capture")
    if ref != reference(capture_path, capture_raw):
        fail("provenance capture substitution")
    if value["regular_file_set_sha256"] != regular_set_commitment(inventory):
        fail("provenance regular-file scope substitution")
    records = value["records"]
    if not isinstance(records, list) or len(records) > MAX_OBJECTS:
        fail("provenance record cap")
    indexed: dict[str, dict[str, Any]] = {}; dependencies: list[pathlib.Path] = []
    for record in records:
        exact_keys(record, {"path_hex", "sha256", "disposition", "source_kind", "source_identity_sha256", "source_artifact"}, "provenance record")
        path_hex = record["path_hex"]
        decode_relative(path_hex)
        source_path, source_raw = validate_reference(record["source_artifact"], "provenance source")
        source_value, loaded_source_raw = load(source_path)
        exact_keys(source_value, {"tool", "schema", "contract", "observed_at", "expires_at", "capture", "path_hex", "sha256", "disposition", "source_kind", "authority"}, "provenance source artifact")
        source_observed = timestamp(source_value["observed_at"], "provenance source observation")
        source_expires = timestamp(source_value["expires_at"], "provenance source expiry")
        if source_value["tool"] != "wapp-security-read-only-surface-source-evidence" or source_value["schema"] != 1 or source_value["contract"] != "READ_ONLY_SECURITY_SURFACE_SOURCE_EVIDENCE_V1" or source_value["authority"] != FALSE_AUTHORITY:
            fail("provenance source type or authority invalid")
        if source_value["capture"] != reference(capture_path, capture_raw) or source_observed < timestamp(capture["observed_at"], "capture observation") or source_expires <= source_observed or source_expires > timestamp(capture["expires_at"], "capture expiry"):
            fail("provenance source currentness or capture substitution")
        expected_source = {key: record[key] for key in ("path_hex", "sha256", "disposition", "source_kind")}
        if {key: source_value[key] for key in expected_source} != expected_source:
            fail("provenance source record substitution")
        if loaded_source_raw != source_raw or record["source_identity_sha256"] != sha(source_raw) or path_hex in indexed or not HEX64.fullmatch(record["sha256"]) or (record["disposition"], record["source_kind"]) not in PROVENANCE:
            fail("provenance record invalid")
        indexed[path_hex] = record;dependencies.append(source_path)
    if records != [indexed[key] for key in sorted(indexed)]:
        fail("provenance ordering invalid")
    if value["record_set_sha256"] != sha(canonical(records)):
        fail("provenance record-set commitment mismatch")
    return indexed, dependencies


def classify(entry: dict[str, Any], path_hex: str, rule: dict[str, Any], record: dict[str, Any] | None) -> dict[str, Any]:
    relative = entry["relative"]
    lower = relative.lower()
    text = lower.decode("utf-8", "surrogateescape")
    basename = text.rsplit("/", 1)[-1]
    suffix = pathlib.PurePosixPath(text).suffix
    executable = suffix in set(rule["executable_suffixes"]) or bool(int(entry["mode"], 8) & 0o111)
    config = basename in set(rule["config_basenames"])
    runtime_root = next((root for root in rule["wordpress_runtime_roots"] if text == root or text.startswith(root + "/")), None)
    dropin = text in set(rule["wordpress_dropins"])
    malicious_rule = rule["malicious_index"].get(entry["sha256"])
    object_class = "CONFIG" if config else "DROPIN" if dropin else "RUNTIME" if runtime_root else "EXECUTABLE" if executable else "REGULAR_CONTENT"
    location = "UPLOADS" if entry["uploads"] else "ROOT" if b"/" not in relative else "WORDPRESS_RUNTIME" if runtime_root or dropin else "OTHER"
    rules: list[str] = []
    result = "UNRESOLVED"
    disposition = "UNKNOWN_SECURITY_RELEVANT_CONTENT"
    provenance_value: dict[str, str] | None = None
    if malicious_rule is not None:
        rules.append(malicious_rule)
        result, disposition = "ACTION_REQUIRED", "KNOWN_MALICIOUS_EXACT"
    if executable and entry["uploads"]:
        rules.append(rule["uploads_executable_rule"])
        result, disposition = "ACTION_REQUIRED", "EXECUTABLE_UPLOAD"
    if record is not None:
        provenance_value = {key: record[key] for key in ("disposition", "source_kind", "source_identity_sha256")}
        if record["sha256"] != entry["sha256"]:
            rules.append("PROVENANCE_CONTENT_IDENTITY_MISMATCH")
            if result != "ACTION_REQUIRED":
                result, disposition = "UNRESOLVED", "CONTRADICTORY_PROVENANCE"
        elif result == "ACTION_REQUIRED":
            rules.append("PROVENANCE_CANNOT_DOWNGRADE_ACTION_REQUIRED")
        else:
            rules.append("EXACT_SIGNED_PROVENANCE_MATCH")
            result, disposition = "PASS", record["disposition"]
    if not rules:
        rules.append("SECURITY_RELEVANT_PROVENANCE_REQUIRED")
    return {
        "path_hex": path_hex, "absolute_path_hex": entry["absolute_path_hex"], "object_class": object_class,
        "location_class": location, "type": entry["type"], "sha256": entry["sha256"], "bytes": entry["size"],
        "mode": entry["mode"], "uid": entry["uid"], "gid": entry["gid"], "device": entry["device"],
        "inode": entry["inode"], "nlink": entry["nlink"], "result": result, "disposition": disposition,
        "rule_ids": sorted(set(rules)), "provenance": provenance_value,
    }


def surface_derive(capture_path: pathlib.Path, provenance_path: pathlib.Path, ruleset_path: pathlib.Path, native_policy_path: pathlib.Path, generated_at: str, current_commit: str, current_version: str) -> dict[str, Any]:
    validate_release(current_commit, current_version)
    capture_value, capture_raw = load(capture_path)
    capture, inventory = capture_verify(capture_value, current_commit, current_version, native_policy_path, ruleset_path, require_current=True)
    if capture["public_core"] != {"commit": current_commit, "version": current_version}:
        fail("cross-release capture substitution")
    generated = timestamp(generated_at, "surface timestamp")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if generated < now - dt.timedelta(minutes=10) or generated > now + dt.timedelta(seconds=60):
        fail("surface issue timestamp is not current")
    observed, capture_expiry = timestamp(capture["observed_at"], "capture observation"), timestamp(capture["expires_at"], "capture expiry")
    if generated < observed or generated > capture_expiry:
        fail("surface currentness invalid")
    provenance_value, provenance_raw = load(provenance_path)
    records, _ = provenance(provenance_value, capture_path, capture_raw, capture, inventory)
    provenance_expiry = timestamp(provenance_value["expires_at"], "provenance expiry")
    if generated > provenance_expiry:
        fail("provenance stale")
    rule, rule_raw = ruleset(ruleset_path)
    objects: list[dict[str, Any]] = []
    entries = inventory["entries"]
    for path_hex in sorted(entries):
        entry = entries[path_hex]
        if entry["type"] == "REGULAR" and entry["sha256"] != "-":
            objects.append(classify(entry, path_hex, rule, records.get(path_hex)))
    missing = sorted(set(records) - set(entries))
    for path_hex in missing:
        record = records[path_hex]
        objects.append({
            "path_hex": path_hex, "absolute_path_hex": None, "object_class": "EXPECTED_PROVENANCE_OBJECT",
            "location_class": "UNKNOWN", "type": "ABSENT", "sha256": None, "bytes": 0, "mode": None,
            "uid": None, "gid": None, "device": None, "inode": None, "nlink": None,
            "result": "UNRESOLVED", "disposition": "PROVENANCE_OBJECT_ABSENT",
            "rule_ids": ["PROVENANCE_OBJECT_ABSENT"],
            "provenance": {key: record[key] for key in ("disposition", "source_kind", "source_identity_sha256")},
        })
    objects.sort(key=lambda row: row["path_hex"])
    evaluated = len(objects)
    action = sum(row["result"] == "ACTION_REQUIRED" for row in objects)
    unresolved = sum(row["result"] == "UNRESOLVED" for row in objects)
    passed = sum(row["result"] == "PASS" for row in objects)
    semantic_complete = inventory["coverage_complete"] and unresolved == 0 and evaluated == passed + action
    terminal_clean = semantic_complete and action == 0
    expires_at = min(capture_expiry, provenance_expiry).strftime(STAMP)
    surface_commitment = sha(canonical(objects))
    return {
        "tool": "wapp-security-read-only-security-surface", "schema": 1,
        "contract": "READ_ONLY_SECURITY_SURFACE_V1", "classification_version": rule["classification_version"],
        "generated_at": generated_at, "expires_at": expires_at,
        "public_core": {"commit": current_commit, "version": current_version},
        "ruleset": reference(ruleset_path, rule_raw), "capture": reference(capture_path, capture_raw),
        "provenance": reference(provenance_path, provenance_raw), "capture_nonce": capture["capture_nonce"],
        "root_path_hex": capture["root_path_hex"], "physical_root_hex": capture["physical_root_hex"],
        "root_identity": capture["root_identity"], "helper_sha256": capture["helper_sha256"],
        "runtime_identity_sha256": capture["runtime_identity_sha256"],
        "inventory_commitment_sha256": capture["inventory_commitment_sha256"],
        "surface_commitment_sha256": surface_commitment,
        "counts": {"inventory_entries": capture["entry_count"], "applicable": evaluated, "evaluated": evaluated, "pass": passed, "action_required": action, "unresolved": unresolved, "inventory_unresolved": capture["unresolved_count"], "inventory_uncovered": capture["uncovered_path_count"]},
        "coverage_complete": semantic_complete, "terminal_clean_candidate": terminal_clean,
        "state": "COMPLETE_NO_ACTION" if terminal_clean else "COMPLETE_ACTION_REQUIRED" if semantic_complete else "UNRESOLVED_NON_CLEAN",
        "objects": objects, "classification_target_filesystem_modified": False,
        "classification_server_temp_files_created": False, "wordpress_executed": False,
        "php_executed": False, "database_queried": False,
        "raw_customer_source_exported": False, "read_only": True, "non_authorizing": True,
        "authority": FALSE_AUTHORITY,
    }


def surface_verify(value: dict[str, Any], current_commit: str, current_version: str, native_policy_path: pathlib.Path) -> dict[str, Any]:
    if value.get("tool") != "wapp-security-read-only-security-surface" or value.get("schema") != 1:
        fail("surface type invalid")
    public = exact_keys(value.get("public_core"), {"commit", "version"}, "surface public_core")
    validate_release(current_commit, current_version)
    if public != {"commit": current_commit, "version": current_version}:
        fail("cross-release surface substitution")
    capture_path, _ = validate_reference(value.get("capture"), "surface capture")
    provenance_path, _ = validate_reference(value.get("provenance"), "surface provenance")
    ruleset_path, _ = validate_reference(value.get("ruleset"), "surface ruleset")
    expected = surface_derive(capture_path, provenance_path, ruleset_path, native_policy_path, str(value.get("generated_at", "")), public["commit"], public["version"])
    if canonical(value) != canonical(expected):
        fail("surface derivation mismatch")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if now > timestamp(value["expires_at"], "surface expiry"):
        fail("surface is stale")
    return expected


def write_exclusive(path: pathlib.Path, payload: bytes) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        fail("output collision or non-absolute path")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        fail("output exclusive create failed")
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                fail("output write failed")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    try:
        if len(sys.argv) == 7 and sys.argv[1] in {"capture-verify", "capture-dependencies"}:
            artifact, commit, version, policy_path, ruleset_path = sys.argv[2:]
            value, _ = load(pathlib.Path(artifact))
            capture_verify(value, commit, version, pathlib.Path(policy_path), pathlib.Path(ruleset_path), require_current=True)
            if sys.argv[1] == "capture-dependencies":
                for key in ("inventory_rows", "public_product_seal", "source_collection_evidence"):
                    print(value[key]["path"])
            else:
                print("READ_ONLY_NATIVE_CAPTURE_BINDING: VERIFIED_NON_AUTHORIZING")
            return 0
        if len(sys.argv) == 8 and sys.argv[1] == "provenance-dependencies":
            capture_path, provenance_path, commit, version, policy_path, ruleset_path = sys.argv[2:]
            capture_value, capture_raw = load(pathlib.Path(capture_path))
            capture, inventory = capture_verify(capture_value, commit, version, pathlib.Path(policy_path), pathlib.Path(ruleset_path), require_current=True)
            provenance_value, _ = load(pathlib.Path(provenance_path))
            _, dependencies = provenance(provenance_value, pathlib.Path(capture_path), capture_raw, capture, inventory)
            for path in sorted(set(dependencies)):
                print(path)
            return 0
        if len(sys.argv) == 10 and sys.argv[1] == "create":
            capture, provenance_path, ruleset_path, policy_path, generated, commit, version, output = sys.argv[2:]
            write_exclusive(pathlib.Path(output), canonical(surface_derive(pathlib.Path(capture), pathlib.Path(provenance_path), pathlib.Path(ruleset_path), pathlib.Path(policy_path), generated, commit, version)))
            return 0
        if len(sys.argv) == 6 and sys.argv[1] in {"verify", "surface-dependencies"}:
            value, _ = load(pathlib.Path(sys.argv[2]))
            verified = surface_verify(value, sys.argv[3], sys.argv[4], pathlib.Path(sys.argv[5]))
            if sys.argv[1] == "surface-dependencies":
                print(value["capture"]["path"]); print(value["provenance"]["path"])
            else:
                print(f"READ_ONLY_SECURITY_SURFACE_V1: {verified['state']}")
            return 0
        fail("usage")
    except Invalid as error:
        print(f"read-only-security-surface: {error}", file=sys.stderr)
        return 20
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
