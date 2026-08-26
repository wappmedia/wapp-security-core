#!/usr/bin/env python3
"""Fail-closed package validation for HUMAN_OPERATOR_EMERGENCY v1.

This module does not collect evidence and cannot mutate a target.  It binds a
reviewed, case-specific one-shot launcher to a generic operator contract.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
ALLOWED_CLASSES = {
    "YELLOW_SELF_REMEDIATION",
    "RED_EXTERNAL_REQUIRED",
    "NEEDS_MORE_INVESTIGATION",
    "NOT_APPLICABLE",
}
ALLOWED_PRIMITIVES = {
    "QUARANTINE_EXACT_FILE",
    "REPLACE_EXACT_FILE",
    "REMOVE_EXACT_ACTIVE_PLUGIN",
    "REMOVE_EXACT_OPTION",
    "QUARANTINE_IDENTITY_ACCESS",
    "REOPEN_ATOMIC_DOCROOT",
}
ALLOWED_ISOLATION = {
    "SELF_MANAGED_ATOMIC_DOCROOT_ISOLATION",
    "HUMAN_OPERATOR_VERIFIED_HTTP_ORIGIN_BLOCK",
}
DENIAL_STATUSES = {401, 403, 404, 410, 503}
REQUIRED_PRODUCT_COMPONENTS = {
    "bin/wapp",
    "bin/wapp-emergency-clean",
    "bin/wapp-closure-check",
    "lib/emergency-operator-v1.py",
    "lib/recovery-integrity.sh",
    "config/reviewer-trust-anchors.json",
    "config/native-filesystem-helper.json",
    "lib/native-displaced-inventory-loader.sh",
    "libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt",
    "native/build-displaced-inventory-helper.sh",
    "native/displaced-inventory-helper.c",
    "config/native-ephemeral-bootstrap.json",
    "lib/native-displaced-inventory-ephemeral-loader.sh",
    "libexec/wapp-native-ephemeral-memfd-launcher-linux-x86_64.b64.txt",
    "native/build-ephemeral-memfd-launcher.sh",
    "native/ephemeral-memfd-launcher.c",
}
PRODUCT_PATHSPECS = (
    "VERSION", "wapp", "wapp-scan", "install.command", "update.command",
    "uninstall.command", "bin/wapp", "bin/wapp-*", "lib/*.sh", "lib/*.py",
    "lib/*.php", "lib/*.m", "config/canonical-components.txt",
    "config/provider-authenticators.json", "config/aws-custody-core.json",
    "config/aws-custody-production-policy.json.example",
    "config/reviewer-trust-anchors.json", "config/native-filesystem-helper.json",
    "config/native-ephemeral-bootstrap.json",
    "native/*.c", "native/*.sh", "libexec/*.txt",
)


class ContractError(Exception):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def load(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            fail("artifact must be a regular non-symlink file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"invalid JSON artifact: {error}")
    if not isinstance(value, dict):
        fail("artifact root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} key set mismatch")


def string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        fail(f"{label} must be a string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        fail(f"{label} contains control characters")
    return value


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        fail(f"{label} must be boolean")
    return value


def digest(value: Any, label: str) -> str:
    result = string(value, label)
    if not HEX64.fullmatch(result):
        fail(f"{label} must be lowercase SHA-256")
    return result


def absolute(value: Any, label: str) -> str:
    result = string(value, label)
    if not result.startswith("/") or result == "/" or os.path.normpath(result) != result:
        fail(f"{label} must be a normalized absolute path")
    return result


def sha(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                return hasher.hexdigest()
            hasher.update(block)


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def external_reviewer_trust() -> dict[str, Any] | None:
    names = {
        "path": "WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_FILE",
        "sha": "WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_SHA256",
        "reviewer": "WAPP_EMERGENCY_REVIEWER_ID",
        "key": "WAPP_EMERGENCY_REVIEWER_KEY_ID",
    }
    present = {key: name in os.environ for key, name in names.items()}
    configured = {key: os.environ.get(name, "") for key, name in names.items()}
    if not any(present.values()):
        return None
    if not all(present.values()) or not all(configured.values()):
        fail("external reviewer trust configuration incomplete")
    if not HEX64.fullmatch(configured["sha"]):
        fail("external reviewer trust anchor hash invalid")
    reviewer_id = string(configured["reviewer"], "external reviewer identity")
    key_id = string(configured["key"], "external reviewer key identity")
    path_text = absolute(configured["path"], "external reviewer trust anchor path")
    if path_text.startswith("//"):
        fail("external reviewer trust anchor path must be normalized absolute")

    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        fail("external reviewer trust anchor descriptor protections unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        current = os.open("/", directory_flags)
        descriptors.append(current)
        root_info = os.fstat(current)
        if root_info.st_uid != 0 or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail("external reviewer trust anchor root is untrusted")
        parts = Path(path_text).parts[1:]
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(child)
            current = child
            info = os.fstat(current)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                fail("external reviewer trust anchor parent is untrusted")
        descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            fail("external reviewer trust anchor file is untrusted")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            total += len(block)
            if total > 65536:
                fail("external reviewer trust anchor exceeds bounded size")
            chunks.append(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            fail("external reviewer trust anchor descriptor drift")
        raw = b"".join(chunks)
    except OSError as error:
        fail(f"external reviewer trust anchor unavailable: {error}")
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    if hashlib.sha256(raw).hexdigest() != configured["sha"]:
        fail("external reviewer trust anchor hash drift")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> Any:
        raise ValueError(f"invalid constant: {constant}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"external reviewer trust anchor invalid JSON: {error}")
    if not isinstance(value, dict):
        fail("external reviewer trust anchor root must be an object")
    reviewers = value.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 1:
        fail("external reviewer trust anchor must pin exactly one reviewer")
    reviewer = reviewers[0]
    if not isinstance(reviewer, dict) or reviewer.get("reviewer_id") != reviewer_id or reviewer.get("key_id") != key_id:
        fail("external reviewer identity/key mismatch")
    return value


def reviewer_trust_anchors() -> dict[tuple[str, str], dict[str, Any]]:
    project_root = Path(__file__).resolve().parent.parent
    value = external_reviewer_trust()
    if value is None:
        value = load(project_root / "config/reviewer-trust-anchors.json")
    exact_keys(value, {"tool", "schema", "reviewers"}, "reviewer_trust")
    if value["tool"] != "wapp-security-reviewer-trust-anchors" or type(value["schema"]) is not int or value["schema"] != 1:
        fail("reviewer trust protocol mismatch")
    reviewers = value["reviewers"]
    if not isinstance(reviewers, list):
        fail("reviewer trust reviewers must be a list")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for index, reviewer in enumerate(reviewers):
        label = f"reviewer_trust.reviewers[{index}]"
        if not isinstance(reviewer, dict):
            fail(f"{label} must be an object")
        exact_keys(reviewer, {"reviewer_id", "key_id", "algorithm", "public_key_pem"}, label)
        reviewer_id = string(reviewer["reviewer_id"], f"{label}.reviewer_id")
        key_id = string(reviewer["key_id"], f"{label}.key_id")
        if reviewer["algorithm"] != "ECDSA_P256_SHA256":
            fail(f"{label}.algorithm unsupported")
        public_key = reviewer["public_key_pem"]
        if not isinstance(public_key, str) or not public_key.startswith("-----BEGIN PUBLIC KEY-----\n") or not public_key.endswith("-----END PUBLIC KEY-----\n"):
            fail(f"{label}.public_key_pem invalid")
        identity = (reviewer_id, key_id)
        if identity in result:
            fail("duplicate reviewer trust identity")
        result[identity] = reviewer
    return result


def review_payload(value: dict[str, Any]) -> bytes:
    signed = {
        key: value[key]
        for key in ("tool", "schema", "result", "package_sha256", "reviewer_id", "key_id", "signature_algorithm")
    }
    return json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_review_signature(value: dict[str, Any]) -> None:
    reviewer_id = string(value["reviewer_id"], "review.reviewer_id")
    key_id = string(value["key_id"], "review.key_id")
    if value["signature_algorithm"] != "ECDSA_P256_SHA256":
        fail("review signature algorithm mismatch")
    reviewer = reviewer_trust_anchors().get((reviewer_id, key_id))
    if reviewer is None:
        fail("reviewer identity/key is not release-pinned")
    try:
        signature = base64.b64decode(string(value["signature_b64"], "review.signature_b64"), validate=True)
    except (ValueError, binascii.Error):
        fail("review signature encoding invalid")
    if not signature or len(signature) > 256:
        fail("review signature size invalid")
    openssl = Path("/usr/bin/openssl")
    if openssl.is_symlink() or not openssl.is_file() or openssl.stat().st_uid != 0 or openssl.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail("trusted OpenSSL verifier unavailable")
    try:
        with tempfile.TemporaryDirectory() as directory:
            public_key = Path(directory) / "reviewer-public-key"
            signature_file = Path(directory) / "review-signature"
            public_key.write_text(reviewer["public_key_pem"], encoding="utf-8")
            signature_file.write_bytes(signature)
            os.chmod(public_key, 0o600)
            os.chmod(signature_file, 0o600)
            key_details = subprocess.run(
                [str(openssl), "pkey", "-pubin", "-in", str(public_key), "-text", "-noout"],
                capture_output=True, text=True,
            )
            if key_details.returncode != 0:
                fail("reviewer public key is invalid")
            details = key_details.stdout + key_details.stderr
            if not re.search(r"(?:ASN1 OID|NIST CURVE):\s*(?:prime256v1|P-256)\b", details):
                fail("reviewer public key is not ECDSA P-256")
            if not re.search(r"Public-Key:\s*\(256 bit\)", details):
                fail("reviewer public key size mismatch")
            verified = subprocess.run(
                [str(openssl), "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature_file)],
                input=review_payload(value), capture_output=True,
            )
    except OSError as error:
        fail(f"review signature verification unavailable: {error}")
    if verified.returncode != 0:
        fail("independent review signature invalid")


def bound_file(value: Any, label: str, *, executable: bool = False) -> Path:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    exact_keys(value, {"path", "sha256"}, label)
    path = Path(absolute(value["path"], f"{label}.path"))
    expected = digest(value["sha256"], f"{label}.sha256")
    if path.is_symlink() or not path.is_file() or sha(path) != expected:
        fail(f"{label} identity/hash mismatch")
    mode = path.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail(f"{label} is group/world writable")
    if executable and not os.access(path, os.X_OK):
        fail(f"{label} is not executable")
    return path


def verify_product_seal(path: Path, declared_commit: str, *, current_runtime: bool = True) -> None:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "generated_at", "version", "git",
            "discovery_policy", "component_count", "components",
            "local_only", "site_credentials_used",
        },
        "product.seal",
    )
    if value["tool"] != "wapp-security-product-seal" or value["schema"] != 2:
        fail("Product Seal tool/schema mismatch")
    git = value["git"]
    if not isinstance(git, dict):
        fail("Product Seal git identity missing")
    exact_keys(git, {"branch", "commit", "clean"}, "product.seal.git")
    string(git["branch"], "product.seal.git.branch", nonempty=False)
    commit = string(git["commit"], "product.seal.git.commit")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or commit != declared_commit or git["clean"] is not True:
        fail("Product Seal commit/clean binding mismatch")
    if value["local_only"] is not True or value["site_credentials_used"] is not False:
        fail("Product Seal safety flags mismatch")
    string(value["generated_at"], "product.seal.generated_at")
    string(value["version"], "product.seal.version", nonempty=False)
    string(value["discovery_policy"], "product.seal.discovery_policy")
    components = value["components"]
    count = integer(value["component_count"], "product.seal.component_count", minimum=1)
    if not isinstance(components, list) or len(components) != count:
        fail("Product Seal component coverage mismatch")
    project_root = Path(__file__).resolve().parent.parent
    seen: set[str] = set()
    ordered: list[str] = []
    for index, component in enumerate(components):
        label = f"product.seal.components[{index}]"
        if not isinstance(component, dict):
            fail(f"{label} must be an object")
        exact_keys(component, {"path", "sha256", "bytes"}, label)
        relative = string(component["path"], f"{label}.path")
        if relative.startswith("/") or os.path.normpath(relative) != relative or relative.startswith("../"):
            fail(f"{label}.path invalid")
        if relative in seen:
            fail("Product Seal duplicate component")
        seen.add(relative)
        ordered.append(relative)
        component_sha = digest(component["sha256"], f"{label}.sha256")
        component_bytes = integer(component["bytes"], f"{label}.bytes")
        if current_runtime:
            candidate = project_root / relative
            if candidate.is_symlink() or not candidate.is_file():
                fail(f"Product Seal current component unavailable: {relative}")
            if sha(candidate) != component_sha:
                fail(f"Product Seal current component hash drift: {relative}")
            if candidate.stat().st_size != component_bytes:
                fail(f"Product Seal current component byte drift: {relative}")
    if ordered != sorted(ordered) or not REQUIRED_PRODUCT_COMPONENTS.issubset(seen):
        fail("Product Seal current runtime coverage incomplete")
    if not current_runtime:
        return
    git_path = "/usr/bin/git"
    if not Path(git_path).is_file() or Path(git_path).is_symlink():
        fail("canonical Git runtime unavailable")
    try:
        current_commit = subprocess.run(
            [git_path, "-C", str(project_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        dirty = subprocess.run(
            [git_path, "-C", str(project_root), "status", "--porcelain", "--untracked-files=no", "--", "."],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        canonical = subprocess.run(
            [git_path, "-C", str(project_root), "ls-files", "--", *PRODUCT_PATHSPECS],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        fail("cannot derive canonical current Product runtime")
    if current_commit != commit or dirty or set(canonical) != seen:
        fail("Product Seal does not match current clean canonical runtime")


def verify_file_state(value: Any, label: str, *, after: bool = False) -> None:
    required = {"sha256", "bytes"}
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    exact_keys(value, required, label)
    digest(value["sha256"], f"{label}.sha256")
    integer(value["bytes"], f"{label}.bytes")


def verify_rollback(value: Any, label: str) -> tuple[str, bool]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    exact_keys(value, {"artifact", "restores", "automatic"}, label)
    bound_file(value["artifact"], f"{label}.artifact")
    if value["restores"] not in {"EXACT_ORIGINAL", "ROLE_LEVEL_ONLY", "NONE_IRREVERSIBLE_SECURITY_STATE"}:
        fail(f"{label}.restores unsupported")
    automatic = boolean(value["automatic"], f"{label}.automatic")
    return value["restores"], automatic


def verify_action(action: Any, index: int) -> tuple[int, str]:
    label = f"actions[{index}]"
    if not isinstance(action, dict):
        fail(f"{label} must be an object")
    exact_keys(action, {"order", "primitive", "target", "before", "after", "rollback", "stage"}, label)
    order = integer(action["order"], f"{label}.order", minimum=1)
    primitive = string(action["primitive"], f"{label}.primitive")
    if primitive not in ALLOWED_PRIMITIVES:
        fail(f"{label}.primitive unsupported")
    stage = string(action["stage"], f"{label}.stage")
    if stage not in {"EXECUTABLE", "CONFIG", "DATABASE", "IDENTITY", "REOPEN"}:
        fail(f"{label}.stage unsupported")
    target = action["target"]
    if not isinstance(target, dict):
        fail(f"{label}.target must be an object")
    verify_file_state(action["before"], f"{label}.before")
    verify_file_state(action["after"], f"{label}.after")
    restores, automatic = verify_rollback(action["rollback"], f"{label}.rollback")

    if primitive in {"QUARANTINE_EXACT_FILE", "REPLACE_EXACT_FILE"}:
        exact_keys(target, {"path", "parent_device", "parent_inode", "device", "inode", "mode"}, f"{label}.target")
        absolute(target["path"], f"{label}.target.path")
        for key in ("parent_device", "parent_inode", "device", "inode"):
            string(target[key], f"{label}.target.{key}")
        if not re.fullmatch(r"0[0-7]{3}", string(target["mode"], f"{label}.target.mode")):
            fail(f"{label}.target.mode invalid")
        expected_stage = "EXECUTABLE" if primitive == "QUARANTINE_EXACT_FILE" else "CONFIG"
        if stage != expected_stage:
            fail(f"{label} stage/primitive mismatch")
        if restores != "EXACT_ORIGINAL" or automatic is not True:
            fail(f"{label} file rollback contract mismatch")
    elif primitive == "REOPEN_ATOMIC_DOCROOT":
        exact_keys(target, {"canonical_root", "isolated_root", "device", "inode"}, f"{label}.target")
        absolute(target["canonical_root"], f"{label}.target.canonical_root")
        absolute(target["isolated_root"], f"{label}.target.isolated_root")
        string(target["device"], f"{label}.target.device")
        string(target["inode"], f"{label}.target.inode")
        if stage != "REOPEN":
            fail(f"{label} reopen stage mismatch")
        if restores != "EXACT_ORIGINAL" or automatic is not True:
            fail(f"{label} reopen rollback contract mismatch")
    elif primitive == "REMOVE_EXACT_ACTIVE_PLUGIN":
        exact_keys(target, {"table", "option_id", "option_name", "member", "integer_key"}, f"{label}.target")
        if target["table"] != "options" or target["option_name"] != "active_plugins":
            fail(f"{label} active_plugins identity mismatch")
        integer(target["option_id"], f"{label}.target.option_id", minimum=1)
        integer(target["integer_key"], f"{label}.target.integer_key")
        string(target["member"], f"{label}.target.member")
        if stage != "DATABASE":
            fail(f"{label} active_plugins stage mismatch")
        if restores != "EXACT_ORIGINAL" or automatic is not True:
            fail(f"{label} active_plugins rollback contract mismatch")
    elif primitive == "REMOVE_EXACT_OPTION":
        exact_keys(target, {"table", "option_id", "option_name", "autoload"}, f"{label}.target")
        if target["table"] != "options":
            fail(f"{label} option table mismatch")
        integer(target["option_id"], f"{label}.target.option_id", minimum=1)
        string(target["option_name"], f"{label}.target.option_name")
        string(target["autoload"], f"{label}.target.autoload", nonempty=False)
        if stage != "DATABASE":
            fail(f"{label} option stage mismatch")
        if restores != "EXACT_ORIGINAL" or automatic is not True:
            fail(f"{label} option rollback contract mismatch")
    else:
        exact_keys(target, {"table", "user_id", "meta_rows", "session_policy", "incident_marker_policy"}, f"{label}.target")
        if target["table"] != "usermeta":
            fail(f"{label} identity table mismatch")
        integer(target["user_id"], f"{label}.target.user_id", minimum=1)
        rows = target["meta_rows"]
        if not isinstance(rows, list) or not rows:
            fail(f"{label}.target.meta_rows must be non-empty")
        seen: set[int] = set()
        for row_index, row in enumerate(rows):
            if not isinstance(row, dict):
                fail(f"{label}.target.meta_rows[{row_index}] invalid")
            exact_keys(row, {"umeta_id", "key_sha256", "value_sha256", "bytes", "disposition"}, f"{label}.target.meta_rows[{row_index}]")
            row_id = integer(row["umeta_id"], f"{label}.target.meta_rows[{row_index}].umeta_id", minimum=1)
            if row_id in seen:
                fail(f"{label}.target duplicate umeta_id")
            seen.add(row_id)
            digest(row["key_sha256"], f"{label}.target.meta_rows[{row_index}].key_sha256")
            digest(row["value_sha256"], f"{label}.target.meta_rows[{row_index}].value_sha256")
            integer(row["bytes"], f"{label}.target.meta_rows[{row_index}].bytes")
            if row["disposition"] not in {"REMOVE_ROLE", "REMOVE_LEVEL", "INVALIDATE_SESSION", "REMOVE_INCIDENT_MARKER"}:
                fail(f"{label}.target.meta_rows[{row_index}].disposition invalid")
        if target["session_policy"] != "NEVER_EXPORT_OR_RESTORE" or target["incident_marker_policy"] != "NEVER_RESTORE":
            fail(f"{label} identity secret/rollback policy mismatch")
        if stage != "IDENTITY":
            fail(f"{label} identity stage mismatch")
        if restores != "ROLE_LEVEL_ONLY" or automatic is not False:
            fail(f"{label} identity rollback contract mismatch")
    return order, stage


def verify_consumption_marker(marker: Path, package_sha256: str) -> Path:
    if marker.is_symlink() or not marker.is_dir():
        fail("historical package consumption marker unavailable")
    marker_state = marker.stat()
    if marker_state.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail("historical package consumption marker is group/world writable")
    identity = marker / "package-sha256"
    if identity.is_symlink() or not identity.is_file():
        fail("historical package consumption identity unavailable")
    identity_state = identity.stat()
    if identity_state.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail("historical package consumption identity is group/world writable")
    try:
        raw = identity.read_bytes()
    except OSError as error:
        fail(f"historical package consumption identity unreadable: {error}")
    if raw != (package_sha256 + "\n").encode("ascii"):
        fail("historical package consumption identity mismatch")
    return identity


def reopen_authority_digest(package: dict[str, Any]) -> str:
    """Cycle-safe commitment to every reopen authority input except its reservation ref."""
    committed = json.loads(json.dumps(package))
    continuation = committed.get("continuation")
    if not isinstance(continuation, dict) or "reopen_reservation" not in continuation:
        fail("reopen authority commitment input incomplete")
    del continuation["reopen_reservation"]
    return canonical_digest(committed)


def verify_reopen_source_lineage(
    continuation: dict[str, Any], domain: str, site: dict[str, Any], reopen_package: dict[str, Any],
    reopen_action: dict[str, Any],
    reopen_operation: str, reopen_generated: int, reopen_expires: int,
) -> tuple[dict[str, Any], list[str]]:
    """Admit a consumed remediation only as immutable reopen provenance."""
    exact_keys(continuation, {
        "remediation_package", "remediation_review", "remediation_registry",
        "remediation_consumption_identity", "coherent_plan", "execution_audit",
        "execution_postcheck", "current_isolation", "reopen_reservation",
        "isolation_identity_sha256",
    }, "continuation")
    remediation_path = bound_file(continuation["remediation_package"], "continuation.remediation_package")
    remediation_review_path = bound_file(continuation["remediation_review"], "continuation.remediation_review")
    remediation = verify_package(remediation_path, domain, historical_execution=True)
    verify_review(remediation_review_path, remediation_path)
    remediation_value = load(remediation_path)
    if (remediation["phase"] != "REMEDIATION" or remediation["classification"] != "YELLOW_SELF_REMEDIATION"
        or remediation["operation_id"] == reopen_operation or remediation_value["continuation"] is not None
        or site != remediation_value["site"]):
        fail("reopen consumed remediation identity mismatch")
    consumption = bound_file(continuation["remediation_consumption_identity"], "continuation.remediation_consumption_identity")
    if str(consumption) != remediation["consumption_identity"]:
        fail("reopen remediation consumption identity mismatch")

    registry_path = bound_file(continuation["remediation_registry"], "continuation.remediation_registry")
    registry = load(registry_path)
    exact_keys(registry, {"tool", "schema", "domain", "remediation", "reopen", "closure"}, "continuation remediation registry")
    if (registry["tool"] != "wapp-security-emergency-operator-registry" or registry["schema"] != 1
        or registry["domain"] != domain or registry["reopen"] is not None or registry["closure"] is not None
        or not isinstance(registry["remediation"], dict)):
        fail("reopen remediation authorization registry mismatch")
    exact_keys(registry["remediation"], {"package", "review"}, "continuation remediation registry entry")
    if (registry["remediation"]["package"] != continuation["remediation_package"]
        or registry["remediation"]["review"] != continuation["remediation_review"]):
        fail("reopen remediation registry package/review mismatch")

    plan_path = bound_file(continuation["coherent_plan"], "continuation.coherent_plan")
    plan = load(plan_path)
    exact_keys(plan, {
        "tool", "schema", "state", "domain", "operation_id", "root", "site_identity", "package",
        "private_product_commit", "public_core_commit", "coordinator", "sites_config_sha256",
        "action_contract_sha256", "action_count", "dispatch_count", "dispatch", "apply_order",
        "rollback_order", "stages", "human_operator_required", "bounded_consumers_own_exact_mutations",
        "filesystem_database_acid_claimed", "scope_expansion_allowed", "arbitrary_sql_allowed",
        "canonical_ready_claimed", "mutation_authority",
    }, "continuation coherent plan")
    if (plan["tool"] != "wapp-security-human-operator-emergency-coordinator-plan" or plan["schema"] != 1
        or plan["state"] != "PREPARED_NO_MUTATION" or plan["domain"] != domain
        or plan["operation_id"] != remediation["operation_id"] or plan["root"] != remediation["root"]
        or plan["package"] != continuation["remediation_package"] or plan["public_core_commit"] != remediation["product_commit"]
        or not HEX64.fullmatch(string(plan["sites_config_sha256"], "continuation.coherent_plan.sites_config_sha256"))
        or not HEX64.fullmatch(string(plan["action_contract_sha256"], "continuation.coherent_plan.action_contract_sha256"))
        or plan["stages"] != ["PREPARED", "FILES_APPLIED", "DB_APPLIED", "IDENTITY_APPLIED", "POSTCHECK_VERIFIED"]
        or plan["human_operator_required"] is not True or plan["bounded_consumers_own_exact_mutations"] is not True
        or plan["filesystem_database_acid_claimed"] is not False or plan["scope_expansion_allowed"] is not False
        or plan["arbitrary_sql_allowed"] is not False or plan["canonical_ready_claimed"] is not False
        or plan["mutation_authority"] is not False):
        fail("reopen coherent plan lineage/authority mismatch")
    if (not isinstance(plan["site_identity"], dict) or plan["site_identity"].get("domain") != domain
        or plan["site_identity"].get("wordpress_root") != remediation["root"]
        or not re.fullmatch(r"[0-9a-f]{40}", string(plan["private_product_commit"], "continuation.coherent_plan.private_product_commit"))
        or plan["coordinator"] != remediation_value["launcher"]):
        fail("reopen coherent plan site/coordinator identity mismatch")
    coordinator_path = bound_file(plan["coordinator"], "continuation.coherent_plan.coordinator", executable=True)
    actions = remediation["actions"]
    action_count = integer(plan["action_count"], "continuation.coherent_plan.action_count", minimum=1)
    dispatch_count = integer(plan["dispatch_count"], "continuation.coherent_plan.dispatch_count", minimum=1)
    dispatches = plan["dispatch"]
    if not isinstance(dispatches, list) or action_count != len(actions) or dispatch_count != len(dispatches):
        fail("reopen coherent plan dispatch cardinality mismatch")
    consumer_for = {
        "QUARANTINE_EXACT_FILE": "BOUNDED_QUARANTINE_EXACT_FILE",
        "REPLACE_EXACT_FILE": "BOUNDED_REPLACE_EXACT_FILE",
        "REMOVE_EXACT_ACTIVE_PLUGIN": "BOUNDED_REMOVE_EXACT_ACTIVE_PLUGIN",
        "REMOVE_EXACT_OPTION": "BOUNDED_REMOVE_EXACT_OPTION",
        "QUARANTINE_IDENTITY_ACCESS": "BOUNDED_IDENTITY_QUARANTINE",
    }
    observed_orders: list[int] = []; observed_consumers: list[str] = []; plan_dependencies: list[str] = []
    for index, dispatch in enumerate(dispatches):
        if not isinstance(dispatch, dict): fail("reopen coherent plan dispatch malformed")
        exact_keys(dispatch, {"order", "stage", "consumer", "action_count", "action_orders", "binding"}, f"continuation.coherent_plan.dispatch[{index}]")
        if integer(dispatch["order"], f"continuation.coherent_plan.dispatch[{index}].order", minimum=1) != index + 1:
            fail("reopen coherent plan dispatch order mismatch")
        orders = dispatch["action_orders"]
        if not isinstance(orders, list) or integer(dispatch["action_count"], f"continuation.coherent_plan.dispatch[{index}].action_count", minimum=1) != len(orders):
            fail("reopen coherent plan action grouping mismatch")
        consumer = string(dispatch["consumer"], f"continuation.coherent_plan.dispatch[{index}].consumer")
        dispatch_stage = string(dispatch["stage"], f"continuation.coherent_plan.dispatch[{index}].stage")
        for order in orders:
            order = integer(order, f"continuation.coherent_plan.dispatch[{index}].action_order", minimum=1)
            if (order > len(actions) or consumer_for.get(actions[order - 1]["primitive"]) != consumer
                or actions[order - 1]["stage"] != dispatch_stage):
                fail("reopen coherent plan action/consumer mismatch")
            observed_orders.append(order)
        observed_consumers.append(consumer)
        plan_dependencies.append(str(bound_file(dispatch["binding"], f"continuation.coherent_plan.dispatch[{index}].binding")))
    if (observed_orders != list(range(1, len(actions) + 1)) or plan["apply_order"] != observed_consumers
        or plan["rollback_order"] != list(reversed(observed_consumers))):
        fail("reopen coherent plan complete ordering mismatch")

    audit_path = bound_file(continuation["execution_audit"], "continuation.execution_audit")
    _, audit_lines = bounded_text_lines(audit_path, "continuation execution audit", maximum_bytes=1024 * 1024)
    ts = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
    patterns = [
        re.compile(rf"{ts}\tPREPARED package={re.escape(remediation['package_sha256'])} operation={re.escape(remediation['operation_id'])} plan={re.escape(sha(plan_path))} one_shot_claimed=true incident_mutation_started=false"),
        re.compile(rf"{ts}\tISOLATION_VERIFIED rebind_sha256=[0-9a-f]{{64}} canonical_root_absent=true public_origin_denied=true incident_mutation_started=false"),
        *[re.compile(rf"{ts}\tDISPATCH_VERIFIED order={i+1} consumer={re.escape(c)} result_sha256=[0-9a-f]{{64}}") for i,c in enumerate(observed_consumers)],
        re.compile(rf"{ts}\tPOSTCHECK_VERIFIED completed={dispatch_count} isolation_remains=true separate_reopen_authority_required=true"),
    ]
    if len(audit_lines) != len(patterns) or any(pattern.fullmatch(line) is None for pattern,line in zip(patterns,audit_lines)):
        fail("reopen execution audit exact completed lineage mismatch")
    audit_epochs = [reconciliation_timestamp(line.split("\t", 1)[0], "continuation.execution_audit") for line in audit_lines]
    if (audit_epochs != sorted(audit_epochs) or audit_epochs[0] < remediation["generated_at_epoch"]
        or audit_epochs[-1] >= remediation["expires_at_epoch"] or audit_epochs[-1] > reopen_generated):
        fail("reopen execution audit time ordering mismatch")

    isolation_identity = canonical_digest({"site": remediation_value["site"], "isolation": remediation_value["isolation"]})
    postcheck_path = bound_file(continuation["execution_postcheck"], "continuation.execution_postcheck")
    postcheck = load(postcheck_path)
    exact_keys(postcheck, {
        "tool", "schema", "state", "domain", "root", "remediation_operation_id",
        "remediation_package_sha256", "isolation_identity_sha256", "isolated_root",
        "isolation_active", "recurrence", "incident_targets_absent", "coherent_plan_sha256",
        "execution_audit_sha256", "expected_dispatch_count", "dispatch_results",
        "exact_mutation_state", "generated_at_epoch", "authority",
    }, "execution_postcheck")
    postcheck_generated = integer(
        postcheck["generated_at_epoch"], "execution_postcheck.generated_at_epoch", minimum=audit_epochs[-1],
    )
    expected_result_hashes: list[str] = []
    for line in audit_lines[2:-1]:
        match = re.fullmatch(
            rf"{ts}\tDISPATCH_VERIFIED order=(\d+) consumer=([A-Z0-9_]+) result_sha256=([0-9a-f]{{64}})",
            line,
        )
        if match is None:
            fail("reopen execution dispatch result binding malformed")
        expected_result_hashes.append(match.group(3))
    results = postcheck["dispatch_results"]
    if not isinstance(results, list) or len(results) != dispatch_count:
        fail("execution postcheck dispatch result cardinality mismatch")
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            fail("execution postcheck dispatch result malformed")
        exact_keys(result, {
            "order", "consumer", "result_sha256", "primitive_orders", "mutation_state",
            "poststate_verified", "target_cardinality_verified",
        }, f"execution_postcheck.dispatch_results[{index}]")
        primitive_orders = result["primitive_orders"]
        if (integer(result["order"], f"execution_postcheck.dispatch_results[{index}].order", minimum=1) != index + 1
            or result["consumer"] != observed_consumers[index]
            or digest(result["result_sha256"], f"execution_postcheck.dispatch_results[{index}].result_sha256") != expected_result_hashes[index]
            or not isinstance(primitive_orders, list) or primitive_orders != dispatches[index]["action_orders"]
            or result["mutation_state"] != "COMPLETED_AS_DECLARED"
            or result["poststate_verified"] is not True or result["target_cardinality_verified"] is not True):
            fail("execution postcheck exact dispatch/poststate mismatch")
    if (postcheck["tool"] != "wapp-security-emergency-execution-postcheck" or postcheck["schema"] != 2
        or postcheck["state"] != "APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW" or postcheck["domain"] != domain
        or postcheck["root"] != site["root"] or postcheck["remediation_operation_id"] != remediation["operation_id"]
        or postcheck["remediation_package_sha256"] != remediation["package_sha256"]
        or postcheck["isolation_identity_sha256"] != isolation_identity
        or postcheck["isolated_root"] != reopen_action["target"]["isolated_root"]
        or postcheck["isolation_active"] is not True or postcheck["recurrence"] is not False
        or postcheck["incident_targets_absent"] is not True or postcheck["coherent_plan_sha256"] != sha(plan_path)
        or postcheck["execution_audit_sha256"] != sha(audit_path)
        or integer(postcheck["expected_dispatch_count"], "execution_postcheck.expected_dispatch_count", minimum=1) != dispatch_count
        or postcheck["exact_mutation_state"] != "COMPLETED_AS_DECLARED" or postcheck_generated > reopen_generated
        or postcheck["authority"] is not False):
        fail("execution postcheck/reopen lineage mismatch")

    observation_path = bound_file(continuation["current_isolation"], "continuation.current_isolation")
    observation = load(observation_path)
    exact_keys(observation, {"tool", "schema", "state", "domain", "operation_id", "canonical_root",
        "isolated_root", "canonical_root_present", "isolated_root_present", "path_chain_no_symlinks",
        "root", "wp_config", "private_parents", "capture_nonce", "captured_at_epoch"}, "continuation current isolation")
    if not isinstance(observation["root"], dict) or not isinstance(observation["wp_config"], dict):
        fail("reopen current isolated metadata malformed")
    exact_keys(observation["root"], {"device", "inode", "type", "nlink", "uid", "gid", "mode", "size", "mtime_ns", "ctime_ns"}, "continuation.current_isolation.root")
    exact_keys(observation["wp_config"], {"relative_path", "device", "inode", "type", "nlink", "uid", "gid", "mode", "size", "mtime_ns", "ctime_ns", "sha256", "symlink"}, "continuation.current_isolation.wp_config")
    parents = observation["private_parents"]
    if not isinstance(parents, list) or not parents:
        fail("reopen current isolation private parent lineage missing")
    for index, parent in enumerate(parents):
        if not isinstance(parent, dict):
            fail("reopen current isolation private parent malformed")
        exact_keys(parent, {"path", "device", "inode", "type", "uid", "gid", "mode", "mtime_ns", "ctime_ns", "symlink"}, f"continuation.current_isolation.private_parents[{index}]")
        if parent["type"] != "directory" or parent["symlink"] is not False:
            fail("reopen current isolation private parent trust mismatch")
    captured = integer(observation["captured_at_epoch"], "continuation.current_isolation.captured_at_epoch", minimum=1)
    parent_paths: set[str] = set()
    for parent in parents:
        parent_path = absolute(parent["path"], "continuation.current_isolation.private_parent.path")
        if parent_path in parent_paths or parent["device"] != site["root_device"] or not re.fullmatch(r"[0-7]{4}", parent["mode"]):
            fail("reopen current isolation private parent identity mismatch")
        parent_paths.add(parent_path)
        if int(parent["mode"], 8) & 0o022:
            fail("reopen current isolation private parent is group/world writable")
    if (observation["tool"] != "wapp-security-isolated-root-observation" or observation["schema"] != 2
        or observation["state"] != "ISOLATED_EXACT" or observation["domain"] != domain
        or observation["operation_id"] != remediation["operation_id"] or observation["canonical_root"] != site["root"]
        or observation["isolated_root"] != reopen_action["target"]["isolated_root"] or observation["canonical_root_present"] is not False
        or observation["isolated_root_present"] is not True or observation["path_chain_no_symlinks"] is not True
        or observation["root"].get("device") != site["root_device"] or observation["root"].get("inode") != site["root_inode"]
        or observation["root"]["type"] != "directory" or observation["root"]["nlink"] == "0"
        or observation["wp_config"].get("relative_path") != "wp-config.php" or observation["wp_config"].get("type") != "file"
        or observation["wp_config"].get("device") != site["root_device"] or observation["wp_config"].get("symlink") is not False
        or observation["wp_config"].get("nlink") != "1"
        or not HEX64.fullmatch(observation["wp_config"].get("sha256", "")) or not HEX64.fullmatch(observation["capture_nonce"])
        or captured < postcheck_generated or captured > reopen_generated or reopen_generated - captured > 300):
        fail("reopen current isolated state mismatch/stale")

    reservation_path = bound_file(continuation["reopen_reservation"], "continuation.reopen_reservation")
    source_marker = Path(remediation_value["one_shot"]["consumption_marker"])
    if reservation_path != source_marker / "reopen-reservation.json": fail("reopen reservation path mismatch")
    completed_reopen = source_marker / "reopen-completed"
    if completed_reopen.exists() or completed_reopen.is_symlink():
        fail("source remediation lineage already has a completed reopen")
    reservation = load(reservation_path)
    exact_keys(reservation, {"tool", "schema", "state", "domain", "root", "source_operation_id",
        "source_package_sha256", "reopen_operation_id", "created_at_epoch", "expires_at_epoch",
        "reopen_authority_sha256", "source_replay_allowed", "authority"}, "reopen reservation")
    if (reservation["tool"] != "wapp-security-emergency-reopen-reservation" or reservation["schema"] != 1
        or reservation["state"] != "RESERVED_FOR_DISTINCT_REOPEN" or reservation["domain"] != domain
        or reservation["root"] != site["root"] or reservation["source_operation_id"] != remediation["operation_id"]
        or reservation["source_package_sha256"] != remediation["package_sha256"]
        or reservation["reopen_operation_id"] != reopen_operation or reservation["created_at_epoch"] != reopen_generated
        or reservation["expires_at_epoch"] != reopen_expires
        or reservation["reopen_authority_sha256"] != reopen_authority_digest(reopen_package)
        or reservation["source_replay_allowed"] is not False
        or reservation["authority"] is not False):
        fail("reopen reservation lineage mismatch")
    if digest(continuation["isolation_identity_sha256"], "continuation.isolation_identity_sha256") != isolation_identity:
        fail("reopen isolation identity mismatch")
    return remediation, [str(remediation_path), str(remediation_review_path), str(consumption), str(registry_path),
        str(plan_path), str(coordinator_path), *plan_dependencies, str(audit_path), str(postcheck_path),
        str(observation_path), str(reservation_path)]


def verify_package(
    path: Path,
    domain: str,
    *,
    now: int | None = None,
    historical_execution: bool = False,
    current_dispatch: bool = False,
    legacy_consumption_identity: Path | None = None,
) -> dict[str, Any]:
    if historical_execution and current_dispatch:
        fail("package cannot be both current dispatch and historical execution")
    if legacy_consumption_identity is not None and not historical_execution:
        fail("legacy consumption identity requires explicit historical execution mode")
    value = load(path)
    expected = {
        "tool", "schema", "state", "phase", "contract", "classification", "domain", "operation_id",
        "generated_at_epoch", "expires_at_epoch", "site", "product", "evidence", "isolation",
        "actions", "continuation", "human_gate", "one_shot", "forensic_record", "independent_review",
        "launcher", "portability", "failure_policy", "authority",
    }
    exact_keys(value, expected, "package")
    if value["tool"] != "wapp-security-emergency-operator-package" or value["schema"] != 1:
        fail("package protocol mismatch")
    if value["state"] != "LOCKED_REVIEWED_STOP_BEFORE_HUMAN_DECISION":
        fail("package state is not locked/reviewed")
    phase = string(value["phase"], "phase")
    if phase not in {"REMEDIATION", "REOPEN"}:
        fail("package phase mismatch")
    if historical_execution and phase != "REMEDIATION":
        fail("historical execution package must be remediation")
    if value["contract"] not in {"HUMAN_OPERATOR_EMERGENCY", "HUMAN_OPERATOR_EMERGENCY_SELF_ISOLATED"}:
        fail("package contract mismatch")
    classification = string(value["classification"], "classification")
    if classification not in ALLOWED_CLASSES:
        fail("unsupported classification")
    actual_domain = string(value["domain"], "domain").lower()
    if actual_domain != domain or not DOMAIN.fullmatch(actual_domain):
        fail("domain binding mismatch")
    operation = string(value["operation_id"], "operation_id")
    if not HEX32.fullmatch(operation):
        fail("operation_id invalid")
    generated = integer(value["generated_at_epoch"], "generated_at_epoch", minimum=1)
    expires = integer(value["expires_at_epoch"], "expires_at_epoch", minimum=generated + 1)
    current_time = int(time.time()) if now is None else now
    if not historical_execution and generated > current_time:
        fail("package is future dated")
    if not historical_execution and current_time >= expires:
        fail("package expired")

    site = value["site"]
    if not isinstance(site, dict):
        fail("site must be an object")
    exact_keys(site, {"site_id", "root", "root_device", "root_inode", "ssh_endpoint", "origin_ip"}, "site")
    string(site["site_id"], "site.site_id")
    absolute(site["root"], "site.root")
    string(site["root_device"], "site.root_device")
    string(site["root_inode"], "site.root_inode")
    string(site["ssh_endpoint"], "site.ssh_endpoint")
    string(site["origin_ip"], "site.origin_ip")

    for name in ("product", "evidence"):
        if not isinstance(value[name], dict):
            fail(f"{name} must be an object")
    exact_keys(value["product"], {"commit", "seal"}, "product")
    if not re.fullmatch(r"[0-9a-f]{40}", string(value["product"]["commit"], "product.commit")):
        fail("product commit invalid")
    product_seal_path = bound_file(value["product"]["seal"], "product.seal")
    verify_product_seal(
        product_seal_path,
        value["product"]["commit"],
        current_runtime=not historical_execution,
    )
    exact_keys(value["evidence"], {"incident", "prestate", "rollback_index"}, "evidence")
    for key in ("incident", "prestate", "rollback_index"):
        evidence_path = bound_file(value["evidence"][key], f"evidence.{key}")
        evidence_value = load(evidence_path)
        if evidence_value.get("domain") != domain or evidence_value.get("root") != site["root"]:
            fail(f"evidence.{key} site/root binding mismatch")

    isolation = value["isolation"]
    if not isinstance(isolation, dict):
        fail("isolation must be an object")
    exact_keys(isolation, {"method", "public_origin_required", "accepted_https_statuses", "stability_seconds", "exact_reverse_reopen"}, "isolation")
    if isolation["method"] not in ALLOWED_ISOLATION:
        fail("isolation method unsupported")
    if boolean(isolation["public_origin_required"], "isolation.public_origin_required") is not True:
        fail("public+origin isolation is mandatory")
    statuses = isolation["accepted_https_statuses"]
    if not isinstance(statuses, list) or not statuses or any(status not in DENIAL_STATUSES for status in statuses):
        fail("isolation denial status contract invalid")
    integer(isolation["stability_seconds"], "isolation.stability_seconds", minimum=60)
    if boolean(isolation["exact_reverse_reopen"], "isolation.exact_reverse_reopen") is not True:
        fail("exact reverse reopen is mandatory")

    actions = value["actions"]
    if classification == "YELLOW_SELF_REMEDIATION" and (not isinstance(actions, list) or not actions):
        fail("YELLOW package requires actions")
    if not isinstance(actions, list):
        fail("actions must be a list")
    order_and_stage = [verify_action(action, index) for index, action in enumerate(actions)]
    if [item[0] for item in order_and_stage] != list(range(1, len(actions) + 1)):
        fail("action ordering must be contiguous and deterministic")
    rank = {"EXECUTABLE": 1, "CONFIG": 2, "DATABASE": 3, "IDENTITY": 4, "REOPEN": 5}
    if [rank[item[1]] for item in order_and_stage] != sorted(rank[item[1]] for item in order_and_stage):
        fail("unsafe dependency ordering")
    for index, action in enumerate(actions):
        if action["primitive"] in {"QUARANTINE_EXACT_FILE", "REPLACE_EXACT_FILE"} and not action["target"]["path"].startswith(site["root"] + "/"):
            fail(f"actions[{index}] target outside serving root")
    if phase == "REOPEN":
        if value["contract"] != "HUMAN_OPERATOR_EMERGENCY_SELF_ISOLATED" or len(actions) != 1 or actions[0]["primitive"] != "REOPEN_ATOMIC_DOCROOT" or actions[0]["target"]["canonical_root"] != site["root"]:
            fail("reopen package must contain exactly one bound atomic docroot reopen")
    elif any(action["primitive"] == "REOPEN_ATOMIC_DOCROOT" for action in actions):
        fail("remediation package cannot contain reopen action")

    continuation = value["continuation"]
    continuation_dependencies: list[str] = []
    source_remediation_marker: str | None = None
    reopen_source_lineage_state = ""
    if phase == "REMEDIATION":
        if continuation is not None:
            fail("remediation package cannot carry reopen continuation")
    else:
        if not isinstance(continuation, dict):
            fail("reopen continuation is required")
        remediation, continuation_dependencies = verify_reopen_source_lineage(
            continuation, domain, site, value, actions[0], operation, generated, expires,
        )
        source_remediation_marker = remediation["consumption_marker"]
        reopen_source_lineage_state = "CONSUMED_EXECUTED_REMEDIATION_LINEAGE_VERIFIED_FOR_REOPEN"
        if (actions[0]["target"]["device"] != site["root_device"]
            or actions[0]["target"]["inode"] != site["root_inode"]):
            fail("reopen action root identity mismatch")

    gate = value["human_gate"]
    if not isinstance(gate, dict):
        fail("human_gate must be an object")
    exact_keys(gate, {"required", "phrase_format"}, "human_gate")
    if boolean(gate["required"], "human_gate.required") is not True:
        fail("human confirmation is mandatory")
    phrase_verb = "RENSA" if phase == "REMEDIATION" else "ÅTERÖPPNA"
    expected_phrase = f"{phrase_verb} {domain} {sha(path)[:12]}"
    if gate["phrase_format"] != f"{phrase_verb} <DOMAIN> <PACKAGE_SHA256_12>":
        fail("human confirmation phrase format mismatch")

    one_shot = value["one_shot"]
    if not isinstance(one_shot, dict):
        fail("one_shot must be an object")
    exact_keys(one_shot, {"required", "consumption_marker"}, "one_shot")
    if boolean(one_shot["required"], "one_shot.required") is not True:
        fail("one-shot contract required")
    marker = Path(absolute(one_shot["consumption_marker"], "one_shot.consumption_marker"))
    if source_remediation_marker is not None and str(marker) == source_remediation_marker:
        fail("reopen cannot reuse remediation consumption marker")
    package_sha256 = sha(path)
    consumption_identity: Path | None = None
    if historical_execution:
        if legacy_consumption_identity is None:
            consumption_identity = verify_consumption_marker(marker, package_sha256)
        else:
            if legacy_consumption_identity.is_symlink() or not legacy_consumption_identity.is_file():
                fail("legacy package consumption identity unavailable")
            identity_state = legacy_consumption_identity.stat()
            if identity_state.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                fail("legacy package consumption identity is group/world writable")
            try:
                identity_raw = legacy_consumption_identity.read_bytes()
            except OSError as error:
                fail(f"legacy package consumption identity unreadable: {error}")
            if identity_raw != (package_sha256 + "\n").encode("ascii"):
                fail("legacy package consumption identity mismatch")
            consumption_identity = legacy_consumption_identity
    elif current_dispatch:
        consumption_identity = verify_consumption_marker(marker, package_sha256)
    elif marker.exists() or marker.is_symlink():
        fail("package already consumed or marker collision")

    forensic_path = bound_file(value["forensic_record"], "forensic_record")
    forensic_value = load(forensic_path)
    if forensic_value.get("domain") != domain or forensic_value.get("root") != site["root"]:
        fail("forensic record site/root binding mismatch")
    review = value["independent_review"]
    if not isinstance(review, dict):
        fail("independent_review must be an object")
    exact_keys(review, {"required_result"}, "independent_review")
    if review["required_result"] != "PASS_NO_P0_P1_P2":
        fail("independent review requirement mismatch")
    launcher = bound_file(value["launcher"], "launcher", executable=True)

    portability = value["portability"]
    if not isinstance(portability, dict):
        fail("portability must be an object")
    exact_keys(portability, {"bash_3_2", "db_integrity", "blocked_http"}, "portability")
    if portability != {"bash_3_2": True, "db_integrity": "NATIVE_READ_ONLY_FALLBACK", "blocked_http": "STATUS_SEMANTICS_NO_MIN_BODY"}:
        fail("portability contract mismatch")
    failure = value["failure_policy"]
    if not isinstance(failure, dict):
        fail("failure_policy must be an object")
    exact_keys(failure, {"recurrence", "partial_execution", "blind_retry", "scope_expansion"}, "failure_policy")
    if failure != {"recurrence": "ABORT_RED_EXTERNAL_REQUIRED", "partial_execution": "RECONCILE_NO_RETRY", "blind_retry": False, "scope_expansion": False}:
        fail("failure policy mismatch")
    authority = value["authority"]
    if not isinstance(authority, dict):
        fail("authority must be an object")
    exact_keys(authority, {"canonical_ready", "provider_authorized", "autonomous_mutation", "closure"}, "authority")
    if any(boolean(authority[key], f"authority.{key}") for key in authority):
        fail("emergency package must be non-canonical/non-autonomous")

    return {
        "domain": domain,
        "phase": phase,
        "classification": classification,
        "contract": value["contract"],
        "operation_id": operation,
        "generated_at_epoch": generated,
        "package_sha256": package_sha256,
        "expires_at_epoch": expires,
        "root": site["root"],
        "isolation": isolation["method"],
        "stability_seconds": isolation["stability_seconds"],
        "actions": actions,
        "launcher": str(launcher),
        "launcher_sha256": value["launcher"]["sha256"],
        "human_phrase": expected_phrase,
        "dependencies": [
            value["product"]["seal"]["path"],
            value["evidence"]["incident"]["path"],
            value["evidence"]["prestate"]["path"],
            value["evidence"]["rollback_index"]["path"],
            *[action["rollback"]["artifact"]["path"] for action in actions],
            value["forensic_record"]["path"],
            value["launcher"]["path"],
            *continuation_dependencies,
        ],
        "consumption_marker": str(marker),
        "consumption_identity": str(consumption_identity) if consumption_identity else "",
        "product_commit": value["product"]["commit"],
        "reopen_source_lineage_state": reopen_source_lineage_state,
    }


def verify_registry(path: Path, domain: str, phase: str) -> dict[str, str]:
    value = load(path)
    exact_keys(value, {"tool", "schema", "domain", "remediation", "reopen", "closure"}, "registry")
    if value["tool"] != "wapp-security-emergency-operator-registry" or value["schema"] != 1 or value["domain"] != domain:
        fail("registry protocol/domain mismatch")
    selected = value[phase]
    if selected is None:
        fail(f"registry has no {phase} package")
    if not isinstance(selected, dict):
        fail(f"registry.{phase} must be an object")
    if phase == "closure":
        exact_keys(selected, {"record"}, f"registry.{phase}")
        return {"artifact": str(bound_file(selected["record"], f"registry.{phase}.record"))}
    exact_keys(selected, {"package", "review"}, f"registry.{phase}")
    return {
        "artifact": str(bound_file(selected["package"], f"registry.{phase}.package")),
        "review": str(bound_file(selected["review"], f"registry.{phase}.review")),
    }


def verify_review(path: Path, package: Path) -> dict[str, Any]:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "result", "package_sha256", "reviewer_id",
            "key_id", "signature_algorithm", "signature_b64",
        },
        "review",
    )
    if value["tool"] != "wapp-security-emergency-package-review" or value["schema"] != 1:
        fail("review protocol mismatch")
    if value["result"] != "PASS_NO_P0_P1_P2" or digest(value["package_sha256"], "review.package_sha256") != sha(package):
        fail("independent review/package binding mismatch")
    verify_review_signature(value)
    return value


def verify_reopen_postcheck(
    path: Path,
    domain: str,
    root: str,
    remediation: dict[str, Any],
    reopen: dict[str, Any],
    closure_generated: int,
) -> dict[str, Any]:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "state", "domain", "root", "reopen_operation_id",
            "reopen_package_sha256", "remediation_operation_id", "remediation_package_sha256",
            "generated_at_epoch", "isolation_reversed", "post_open_verified", "recurrence",
            "incident_targets_absent",
        },
        "reopen_postcheck",
    )
    if value["tool"] != "wapp-security-emergency-reopen-postcheck" or value["schema"] != 1:
        fail("reopen postcheck protocol mismatch")
    generated = integer(value["generated_at_epoch"], "reopen_postcheck.generated_at_epoch", minimum=reopen["generated_at_epoch"])
    for key in ("isolation_reversed", "post_open_verified", "recurrence", "incident_targets_absent"):
        boolean(value[key], f"reopen_postcheck.{key}")
    if (
        value["state"] != "POSTOPEN_VERIFIED_YELLOW"
        or value["domain"] != domain
        or value["root"] != root
        or value["reopen_operation_id"] != reopen["operation_id"]
        or value["reopen_package_sha256"] != reopen["package_sha256"]
        or value["remediation_operation_id"] != remediation["operation_id"]
        or value["remediation_package_sha256"] != remediation["package_sha256"]
        or generated > closure_generated
    ):
        fail("reopen postcheck lineage mismatch")
    return value


def derive_closure_checks(path: Path, domain: str, root: str, operation: str, product_commit: str, minimum_epoch: int, maximum_epoch: int) -> dict[str, Any]:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "domain", "root", "operation_id", "product_commit",
            "generated_at_epoch", "scan", "coverage", "recurrence", "identity",
        },
        "closure_evidence",
    )
    if value["tool"] != "wapp-security-emergency-closure-evidence" or value["schema"] != 1:
        fail("closure evidence protocol mismatch")
    generated = integer(value["generated_at_epoch"], "closure_evidence.generated_at_epoch", minimum=minimum_epoch)
    if (
        value["domain"] != domain
        or value["root"] != root
        or value["operation_id"] != operation
        or value["product_commit"] != product_commit
        or generated > maximum_epoch
    ):
        fail("closure evidence current lineage mismatch")
    scan = value["scan"]
    coverage = value["coverage"]
    recurrence = value["recurrence"]
    identity = value["identity"]
    for candidate, keys, label in (
        (scan, {"critical", "high"}, "closure_evidence.scan"),
        (coverage, {"filesystem_complete", "database_complete", "runtime_ok"}, "closure_evidence.coverage"),
        (recurrence, {"detected", "unknown_executable_persistence", "incident_targets_absent"}, "closure_evidence.recurrence"),
        (identity, {"unresolved_malicious_privileged_access"}, "closure_evidence.identity"),
    ):
        if not isinstance(candidate, dict):
            fail(f"{label} must be an object")
        exact_keys(candidate, keys, label)
    checks = {
        "critical": integer(scan["critical"], "closure_evidence.scan.critical"),
        "high": integer(scan["high"], "closure_evidence.scan.high"),
        "filesystem_complete": boolean(coverage["filesystem_complete"], "closure_evidence.coverage.filesystem_complete"),
        "database_complete": boolean(coverage["database_complete"], "closure_evidence.coverage.database_complete"),
        "runtime_ok": boolean(coverage["runtime_ok"], "closure_evidence.coverage.runtime_ok"),
        "recurrence": boolean(recurrence["detected"], "closure_evidence.recurrence.detected"),
        "unknown_executable_persistence": boolean(recurrence["unknown_executable_persistence"], "closure_evidence.recurrence.unknown_executable_persistence"),
        "unresolved_malicious_privileged_access": boolean(identity["unresolved_malicious_privileged_access"], "closure_evidence.identity.unresolved_malicious_privileged_access"),
        "incident_targets_absent": boolean(recurrence["incident_targets_absent"], "closure_evidence.recurrence.incident_targets_absent"),
    }
    return checks


def verify_historical_execution_audit(
    path: Path,
    phase: str,
    domain: str,
    root: str,
    operation: str,
    package_sha256: str,
    minimum_epoch: int,
    maximum_epoch: int,
    *,
    remediation_operation: str = "",
    remediation_package_sha256: str = "",
) -> tuple[int, list[str]]:
    value = load(path)
    expected = {
        "tool", "schema", "phase", "domain", "root", "operation_id",
        "package_sha256", "started_at_epoch", "completed_at_epoch", "source_audit",
        "human_operator_confirmed", "actions_completed", "read_only_validation",
        "authority",
    }
    if phase == "REOPEN":
        expected |= {"remediation_operation_id", "remediation_package_sha256"}
    exact_keys(value, expected, "historical_execution_audit")
    started = integer(value["started_at_epoch"], "historical_execution_audit.started_at_epoch", minimum=minimum_epoch)
    completed = integer(value["completed_at_epoch"], "historical_execution_audit.completed_at_epoch", minimum=started)
    if (
        value["tool"] != "wapp-security-emergency-historical-execution-audit"
        or value["schema"] != 1
        or value["phase"] != phase
        or value["domain"] != domain
        or value["root"] != root
        or value["operation_id"] != operation
        or value["package_sha256"] != package_sha256
        or completed > maximum_epoch
        or boolean(value["human_operator_confirmed"], "historical_execution_audit.human_operator_confirmed") is not True
        or boolean(value["actions_completed"], "historical_execution_audit.actions_completed") is not True
        or boolean(value["read_only_validation"], "historical_execution_audit.read_only_validation") is not True
        or value["authority"] is not False
    ):
        fail("historical execution audit binding/result mismatch")
    if phase == "REOPEN" and (
        value["remediation_operation_id"] != remediation_operation
        or value["remediation_package_sha256"] != remediation_package_sha256
    ):
        fail("historical reopen audit remediation binding mismatch")
    source = bound_file(value["source_audit"], "historical_execution_audit.source_audit")
    return completed, [str(path), str(source)]


def verify_historical_remediation_poststate(
    path: Path,
    domain: str,
    root: str,
    operation: str,
    package_sha256: str,
    isolation_identity: str,
    root_device: str,
    root_inode: str,
    minimum_epoch: int,
    maximum_epoch: int,
) -> tuple[int, list[str]]:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "state", "domain", "root", "root_device", "root_inode",
            "operation_id", "package_sha256", "isolation_identity_sha256",
            "generated_at_epoch", "isolation_active", "recurrence",
            "incident_targets_absent", "source_poststate", "read_only_validation",
            "authority",
        },
        "historical_remediation_poststate",
    )
    generated = integer(value["generated_at_epoch"], "historical_remediation_poststate.generated_at_epoch", minimum=minimum_epoch)
    if (
        value["tool"] != "wapp-security-emergency-historical-remediation-poststate"
        or value["schema"] != 1
        or value["state"] != "APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW"
        or value["domain"] != domain
        or value["root"] != root
        or value["root_device"] != root_device
        or value["root_inode"] != root_inode
        or value["operation_id"] != operation
        or value["package_sha256"] != package_sha256
        or value["isolation_identity_sha256"] != isolation_identity
        or generated > maximum_epoch
        or boolean(value["isolation_active"], "historical_remediation_poststate.isolation_active") is not True
        or boolean(value["recurrence"], "historical_remediation_poststate.recurrence") is not False
        or boolean(value["incident_targets_absent"], "historical_remediation_poststate.incident_targets_absent") is not True
        or boolean(value["read_only_validation"], "historical_remediation_poststate.read_only_validation") is not True
        or value["authority"] is not False
    ):
        fail("historical remediation poststate binding/result mismatch")
    source = bound_file(value["source_poststate"], "historical_remediation_poststate.source_poststate")
    return generated, [str(path), str(source)]


def verify_historical_post_open(
    path: Path,
    domain: str,
    root: str,
    root_device: str,
    root_inode: str,
    remediation_operation: str,
    remediation_package_sha256: str,
    reopen_operation: str,
    reopen_package_sha256: str,
    minimum_epoch: int,
    maximum_epoch: int,
) -> tuple[int, list[str], bool, bool]:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "state", "domain", "root", "root_device", "root_inode",
            "remediation_operation_id", "remediation_package_sha256",
            "reopen_operation_id", "reopen_package_sha256", "generated_at_epoch",
            "isolation_reversed", "post_open_verified", "recurrence",
            "incident_targets_absent", "source_post_open", "read_only_validation",
            "authority",
        },
        "historical_post_open",
    )
    generated = integer(value["generated_at_epoch"], "historical_post_open.generated_at_epoch", minimum=minimum_epoch)
    for key in ("isolation_reversed", "post_open_verified", "recurrence", "incident_targets_absent", "read_only_validation"):
        boolean(value[key], f"historical_post_open.{key}")
    if (
        value["tool"] != "wapp-security-emergency-historical-post-open-verification"
        or value["schema"] != 1
        or value["state"] != "APPLIED_EXACT_AND_POSTOPEN_VERIFIED_YELLOW"
        or value["domain"] != domain
        or value["root"] != root
        or value["root_device"] != root_device
        or value["root_inode"] != root_inode
        or value["remediation_operation_id"] != remediation_operation
        or value["remediation_package_sha256"] != remediation_package_sha256
        or value["reopen_operation_id"] != reopen_operation
        or value["reopen_package_sha256"] != reopen_package_sha256
        or generated > maximum_epoch
        or value["isolation_reversed"] is not True
        or value["post_open_verified"] is not True
        or value["recurrence"] is not False
        or value["incident_targets_absent"] is not True
        or value["read_only_validation"] is not True
        or value["authority"] is not False
    ):
        fail("historical post-open binding/result mismatch")
    source = bound_file(value["source_post_open"], "historical_post_open.source_post_open")
    return generated, [str(path), str(source)], value["recurrence"], value["incident_targets_absent"]


def verify_historical_execution_lineage(
    path: Path,
    review_path: Path,
    domain: str,
    closure_generated: int,
) -> dict[str, Any]:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "state", "domain", "root", "generated_at_epoch",
            "isolation_identity_sha256", "remediation", "reopen", "authority",
        },
        "historical_lineage",
    )
    normal_lineage = value["state"] == "EXECUTED_AND_POSTOPEN_VERIFIED_HISTORICAL"
    legacy_lineage = value["state"] == "LEGACY_RECONCILED_EXECUTION_AND_POSTOPEN_VERIFIED_HISTORICAL"
    if (
        value["tool"] != "wapp-security-emergency-historical-execution-lineage"
        or value["schema"] != 1
        or not (normal_lineage or legacy_lineage)
        or value["domain"] != domain
    ):
        fail("historical execution lineage protocol/domain mismatch")
    root = absolute(value["root"], "historical_lineage.root")
    generated = integer(value["generated_at_epoch"], "historical_lineage.generated_at_epoch", minimum=1)
    if generated > closure_generated:
        fail("historical execution lineage is future dated")
    isolation_identity = digest(value["isolation_identity_sha256"], "historical_lineage.isolation_identity_sha256")
    if value["authority"] is not False:
        fail("historical execution lineage cannot authorize mutation or closure")

    remediation_entry = value["remediation"]
    if not isinstance(remediation_entry, dict):
        fail("historical_lineage.remediation must be an object")
    normal_remediation_keys = {
        "package", "review", "operation_id", "consumption_identity",
        "execution_audit", "execution_poststate",
    }
    legacy_remediation_keys = {
        "package", "review", "operation_id", "consumption_identity",
        "provenance_class", "legacy_reconciliation", "legacy_reconciliation_review",
        "original_execution_audit_sha256",
    }
    exact_keys(
        remediation_entry,
        normal_remediation_keys if normal_lineage else legacy_remediation_keys,
        "historical_lineage.remediation",
    )
    remediation_package = bound_file(remediation_entry["package"], "historical_lineage.remediation.package")
    remediation_review = bound_file(remediation_entry["review"], "historical_lineage.remediation.review")
    legacy_consumption_identity = None
    if legacy_lineage:
        legacy_consumption_identity = bound_file(
            remediation_entry["consumption_identity"],
            "historical_lineage.remediation.consumption_identity",
        )
    remediation = verify_package(
        remediation_package,
        domain,
        now=closure_generated,
        historical_execution=True,
        legacy_consumption_identity=legacy_consumption_identity,
    )
    verify_review(remediation_review, remediation_package)
    remediation_operation = string(remediation_entry["operation_id"], "historical_lineage.remediation.operation_id")
    if remediation_operation != remediation["operation_id"] or remediation["root"] != root:
        fail("historical remediation operation/site binding mismatch")
    expected_isolation = canonical_digest({
        "site": load(remediation_package)["site"],
        "isolation": load(remediation_package)["isolation"],
    })
    if isolation_identity != expected_isolation:
        fail("historical remediation isolation identity mismatch")
    remediation_value = load(remediation_package)
    root_device = string(remediation_value["site"]["root_device"], "historical remediation root_device")
    root_inode = string(remediation_value["site"]["root_inode"], "historical remediation root_inode")
    consumption_identity = legacy_consumption_identity
    if normal_lineage:
        consumption_identity = bound_file(
            remediation_entry["consumption_identity"],
            "historical_lineage.remediation.consumption_identity",
        )
    if consumption_identity is None:
        fail("historical remediation consumption binding unavailable")
    if (
        str(consumption_identity) != remediation["consumption_identity"]
        or consumption_identity.read_bytes() != (remediation["package_sha256"] + "\n").encode("ascii")
    ):
        fail("historical remediation consumption binding mismatch")
    if normal_lineage:
        remediation_audit = bound_file(remediation_entry["execution_audit"], "historical_lineage.remediation.execution_audit")
        remediation_poststate = bound_file(remediation_entry["execution_poststate"], "historical_lineage.remediation.execution_poststate")
        remediation_completed, remediation_audit_dependencies = verify_historical_execution_audit(
            remediation_audit,
            "REMEDIATION",
            domain,
            root,
            remediation_operation,
            remediation["package_sha256"],
            remediation["generated_at_epoch"],
            generated,
        )
        remediation_poststate_generated, remediation_poststate_dependencies = verify_historical_remediation_poststate(
            remediation_poststate,
            domain,
            root,
            remediation_operation,
            remediation["package_sha256"],
            isolation_identity,
            root_device,
            root_inode,
            remediation_completed,
            generated,
        )
    else:
        if remediation_entry["provenance_class"] != "LEGACY_RECONCILED_EXECUTION":
            fail("legacy historical remediation provenance class mismatch")
        original_audit_sha256 = digest(
            remediation_entry["original_execution_audit_sha256"],
            "historical_lineage.remediation.original_execution_audit_sha256",
        )
        reconciliation_path = bound_file(
            remediation_entry["legacy_reconciliation"],
            "historical_lineage.remediation.legacy_reconciliation",
        )
        reconciliation_review = bound_file(
            remediation_entry["legacy_reconciliation_review"],
            "historical_lineage.remediation.legacy_reconciliation_review",
        )
        reconciled = verify_legacy_reconciled_execution(
            reconciliation_path,
            reconciliation_review,
            domain,
            now=generated,
        )
        if (
            reconciled["state"] != "LEGACY_RECONCILED_EXECUTION"
            or reconciled["root"] != root
            or reconciled["root_device"] != root_device
            or reconciled["root_inode"] != root_inode
            or reconciled["operation_id"] != remediation_operation
            or reconciled["package_sha256"] != remediation["package_sha256"]
            or reconciled["isolation_identity_sha256"] != isolation_identity
            or reconciled["original_audit_sha256"] != original_audit_sha256
            or reconciled["original_audit_signed_at_execution"] is not False
            or reconciled["isolation_active"] is not True
            or reconciled["recurrence"] is not False
            or reconciled["authority"] is not False
        ):
            fail("legacy reconciliation/historical remediation binding mismatch")
        remediation_completed = reconciled["generated_at_epoch"]
        remediation_poststate_generated = remediation_completed
        remediation_audit_dependencies = reconciled["dependencies"]
        remediation_poststate_dependencies = []

    reopen_entry = value["reopen"]
    if not isinstance(reopen_entry, dict):
        fail("historical_lineage.reopen must be an object")
    exact_keys(
        reopen_entry,
        {
            "package", "review", "operation_id", "remediation_operation_id",
            "remediation_package_sha256", "consumption_identity", "execution_audit",
            "post_open_verification",
        },
        "historical_lineage.reopen",
    )
    reopen_package = bound_file(reopen_entry["package"], "historical_lineage.reopen.package")
    reopen_review = bound_file(reopen_entry["review"], "historical_lineage.reopen.review")
    verify_review(reopen_review, reopen_package)
    reopen_value = load(reopen_package)
    reopen_operation = string(reopen_entry["operation_id"], "historical_lineage.reopen.operation_id")
    if not HEX32.fullmatch(reopen_operation):
        fail("historical reopen operation identity invalid")
    remediation_reference = string(
        reopen_entry["remediation_operation_id"],
        "historical_lineage.reopen.remediation_operation_id",
    )
    remediation_sha_reference = digest(
        reopen_entry["remediation_package_sha256"],
        "historical_lineage.reopen.remediation_package_sha256",
    )
    if (
        reopen_value.get("domain") != domain
        or reopen_value.get("reopen_operation_id") != reopen_operation
        or reopen_value.get("remediation_operation_id") != remediation_operation
        or remediation_reference != remediation_operation
        or remediation_sha_reference != remediation["package_sha256"]
        or not isinstance(reopen_value.get("evidence"), dict)
        or reopen_value["evidence"].get("remediation_package_sha256") != remediation["package_sha256"]
        or not isinstance(reopen_value.get("exact_mutation"), dict)
        or reopen_value["exact_mutation"].get("destination") != root
        or reopen_value["exact_mutation"].get("expected_root_device") != root_device
        or reopen_value["exact_mutation"].get("expected_root_inode") != root_inode
        or not isinstance(reopen_value.get("authority"), dict)
        or set(reopen_value["authority"]) != {"canonical_ready", "closure", "provider_authorized", "verified_clean"}
        or any(item is not False for item in reopen_value["authority"].values())
    ):
        fail("historical reopen package lineage mismatch")
    reopen_one_shot = reopen_value.get("one_shot")
    if not isinstance(reopen_one_shot, dict) or reopen_one_shot.get("required") is not True:
        fail("historical reopen one-shot contract missing")
    reopen_marker = Path(absolute(reopen_one_shot.get("consumption_marker"), "historical reopen consumption marker"))
    reopen_package_sha = sha(reopen_package)
    reopen_identity_actual = verify_consumption_marker(reopen_marker, reopen_package_sha)
    reopen_identity = bound_file(
        reopen_entry["consumption_identity"],
        "historical_lineage.reopen.consumption_identity",
    )
    if str(reopen_identity) != str(reopen_identity_actual):
        fail("historical reopen consumption binding mismatch")
    reopen_audit = bound_file(reopen_entry["execution_audit"], "historical_lineage.reopen.execution_audit")
    reopen_postopen = bound_file(
        reopen_entry["post_open_verification"],
        "historical_lineage.reopen.post_open_verification",
    )
    reopen_audit_completed, reopen_audit_dependencies = verify_historical_execution_audit(
        reopen_audit,
        "REOPEN",
        domain,
        root,
        reopen_operation,
        reopen_package_sha,
        remediation_poststate_generated,
        generated,
        remediation_operation=remediation_operation,
        remediation_package_sha256=remediation["package_sha256"],
    )
    reopen_completed, reopen_postopen_dependencies, recurrence, incident_targets_absent = verify_historical_post_open(
        reopen_postopen,
        domain,
        root,
        root_device,
        root_inode,
        remediation_operation,
        remediation["package_sha256"],
        reopen_operation,
        reopen_package_sha,
        reopen_audit_completed,
        generated,
    )
    verify_review(review_path, path)
    return {
        "domain": domain,
        "root": root,
        "operation_id": remediation_operation,
        "remediation_package_sha256": remediation["package_sha256"],
        "reopen_operation_id": reopen_operation,
        "reopen_package_sha256": reopen_package_sha,
        "product_commit": remediation["product_commit"],
        "root_device": root_device,
        "root_inode": root_inode,
        "post_open_generated_at_epoch": reopen_completed,
        "recurrence": recurrence,
        "incident_targets_absent": incident_targets_absent,
        "remediation_provenance_class": (
            "SIGNED_EXECUTION_AUDIT" if normal_lineage else "LEGACY_RECONCILED_EXECUTION"
        ),
        "dependencies": [
            str(path), str(review_path), str(remediation_package), str(remediation_review),
            *remediation["dependencies"], *remediation_audit_dependencies,
            *remediation_poststate_dependencies, str(reopen_package), str(reopen_review),
            *reopen_audit_dependencies, *reopen_postopen_dependencies,
        ],
    }


def bounded_text_lines(path: Path, label: str, *, maximum_bytes: int) -> tuple[bytes, list[str]]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"{label} is not strict UTF-8: {error}")
    if not raw or len(raw) > maximum_bytes or not raw.endswith(b"\n") or b"\x00" in raw:
        fail(f"{label} framing invalid")
    lines = text.splitlines()
    if not lines or any(not line for line in lines):
        fail(f"{label} contains empty or no records")
    return raw, lines


def reconciliation_timestamp(value: str, label: str) -> int:
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        fail(f"{label} timestamp invalid")
    return int(parsed.timestamp())


def expected_legacy_action_contract(actions: list[dict[str, Any]]) -> dict[str, Any]:
    quarantine = sum(action["primitive"] == "QUARANTINE_EXACT_FILE" for action in actions)
    replace = sum(action["primitive"] == "REPLACE_EXACT_FILE" for action in actions)
    active_actions = [action for action in actions if action["primitive"] == "REMOVE_EXACT_ACTIVE_PLUGIN"]
    option_rows = sum(action["primitive"] == "REMOVE_EXACT_OPTION" for action in actions)
    identity_actions = [action for action in actions if action["primitive"] == "QUARANTINE_IDENTITY_ACCESS"]
    supported = {
        "QUARANTINE_EXACT_FILE", "REPLACE_EXACT_FILE", "REMOVE_EXACT_ACTIVE_PLUGIN",
        "REMOVE_EXACT_OPTION", "QUARANTINE_IDENTITY_ACCESS",
    }
    if any(action["primitive"] not in supported for action in actions):
        fail("legacy reconciliation package action is unsupported")
    active_rows = {
        (
            action["target"]["table"],
            action["target"]["option_id"],
            action["target"]["option_name"],
        )
        for action in active_actions
    }
    identity_meta_rows = sum(len(action["target"]["meta_rows"]) for action in identity_actions)
    return {
        "actions_sha256": canonical_digest(actions),
        "quarantine_file_targets": quarantine,
        "replace_file_targets": replace,
        "active_plugin_members": len(active_actions),
        "active_plugin_rows": len(active_rows),
        "option_rows": option_rows,
        "identity_targets": len(identity_actions),
        "identity_meta_rows": identity_meta_rows,
    }


def verify_legacy_reconciled_execution(
    path: Path,
    review_path: Path,
    domain: str,
    *,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify an explicit, reviewed after-the-fact legacy execution attestation.

    This is deliberately not a fallback from the normal signed historical path.
    It verifies the original unsigned bytes and a fresh, independently reviewed
    read-only poststate, and it never grants remediation, reopen, or closure
    authority.
    """
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "state", "domain", "root", "root_device", "root_inode",
            "operation_id", "package_sha256", "generated_at_epoch",
            "isolation_identity_sha256", "sources", "source_reviewer",
            "original_execution_audit", "action_contract", "verified_poststate",
            "statement", "authority",
        },
        "legacy_reconciliation",
    )
    if (
        value["tool"] != "wapp-security-emergency-legacy-execution-reconciliation-attestation"
        or value["schema"] != 1
        or value["state"] != "LEGACY_RECONCILED_EXECUTION"
        or value["domain"] != domain
    ):
        fail("legacy reconciliation protocol/domain mismatch")
    root = absolute(value["root"], "legacy_reconciliation.root")
    root_device = string(value["root_device"], "legacy_reconciliation.root_device")
    root_inode = string(value["root_inode"], "legacy_reconciliation.root_inode")
    operation = string(value["operation_id"], "legacy_reconciliation.operation_id")
    if not HEX32.fullmatch(operation):
        fail("legacy reconciliation operation identity invalid")
    package_sha256 = digest(value["package_sha256"], "legacy_reconciliation.package_sha256")
    generated = integer(value["generated_at_epoch"], "legacy_reconciliation.generated_at_epoch", minimum=1)
    current_time = int(time.time()) if now is None else now
    if generated > current_time:
        fail("legacy reconciliation is future dated")
    isolation_identity = digest(
        value["isolation_identity_sha256"],
        "legacy_reconciliation.isolation_identity_sha256",
    )
    if value["statement"] != "AFTER_THE_FACT_VERIFICATION_ORIGINAL_EXECUTION_AUDIT_UNSIGNED":
        fail("legacy reconciliation statement mismatch")
    if value["authority"] is not False:
        fail("legacy reconciliation cannot authorize mutation, reopen, or closure")

    sources = value["sources"]
    if not isinstance(sources, dict):
        fail("legacy_reconciliation.sources must be an object")
    exact_keys(
        sources,
        {
            "package", "package_review", "signed_registry", "consumption_identity",
            "original_execution_audit", "preserved_execution_audit", "current_poststate",
            "current_poststate_hmac", "collector", "collector_hmac",
        },
        "legacy_reconciliation.sources",
    )
    source_paths = {
        key: bound_file(reference, f"legacy_reconciliation.sources.{key}")
        for key, reference in sources.items()
    }
    package_path = source_paths["package"]
    package_review_path = source_paths["package_review"]
    consumption_identity = source_paths["consumption_identity"]
    package = verify_package(
        package_path,
        domain,
        now=generated,
        historical_execution=True,
        legacy_consumption_identity=consumption_identity,
    )
    package_review = verify_review(package_review_path, package_path)
    if (
        package["package_sha256"] != package_sha256
        or package["operation_id"] != operation
        or package["root"] != root
    ):
        fail("legacy reconciliation remediation package binding mismatch")
    package_value = load(package_path)
    if (
        package_value["site"]["root_device"] != root_device
        or package_value["site"]["root_inode"] != root_inode
    ):
        fail("legacy reconciliation site identity mismatch")
    expected_isolation = canonical_digest({
        "site": package_value["site"],
        "isolation": package_value["isolation"],
    })
    if isolation_identity != expected_isolation:
        fail("legacy reconciliation isolation identity mismatch")
    action_contract = value["action_contract"]
    if not isinstance(action_contract, dict):
        fail("legacy_reconciliation.action_contract must be an object")
    expected_actions = expected_legacy_action_contract(package["actions"])
    exact_keys(action_contract, set(expected_actions), "legacy_reconciliation.action_contract")
    for key, expected in expected_actions.items():
        if key == "actions_sha256":
            observed: Any = digest(action_contract[key], f"legacy action contract {key}")
        else:
            observed = integer(action_contract[key], f"legacy action contract {key}")
        if observed != expected:
            fail("legacy reconciliation action contract mismatch")

    registry = load(source_paths["signed_registry"])
    exact_keys(registry, {"tool", "schema", "domain", "remediation", "reopen", "closure"}, "legacy signed registry")
    if (
        registry["tool"] != "wapp-security-emergency-operator-registry"
        or registry["schema"] != 1
        or registry["domain"] != domain
        or registry["remediation"] != {
            "package": sources["package"],
            "review": sources["package_review"],
        }
    ):
        fail("legacy signed registry/remediation binding mismatch")

    source_reviewer = value["source_reviewer"]
    if not isinstance(source_reviewer, dict):
        fail("legacy_reconciliation.source_reviewer must be an object")
    exact_keys(
        source_reviewer,
        {"reviewer_id", "key_id", "signature_algorithm", "package_review_sha256"},
        "legacy_reconciliation.source_reviewer",
    )
    if (
        source_reviewer["reviewer_id"] != package_review["reviewer_id"]
        or source_reviewer["key_id"] != package_review["key_id"]
        or source_reviewer["signature_algorithm"] != package_review["signature_algorithm"]
        or digest(source_reviewer["package_review_sha256"], "legacy source review sha256") != sha(package_review_path)
    ):
        fail("legacy reconciliation source reviewer binding mismatch")

    original = value["original_execution_audit"]
    if not isinstance(original, dict):
        fail("legacy_reconciliation.original_execution_audit must be an object")
    exact_keys(
        original,
        {
            "sha256", "bytes", "device", "inode", "uid", "gid", "mode", "mtime_epoch",
            "signed_at_execution", "hmac_present_at_execution",
        },
        "legacy_reconciliation.original_execution_audit",
    )
    original_path = source_paths["original_execution_audit"]
    preserved_path = source_paths["preserved_execution_audit"]
    original_sha = digest(original["sha256"], "legacy original audit sha256")
    if (
        original_sha != sources["original_execution_audit"]["sha256"]
        or original_sha != sources["preserved_execution_audit"]["sha256"]
    ):
        fail("legacy original/preserved audit byte identity mismatch")
    original_raw, audit_lines = bounded_text_lines(original_path, "legacy original execution audit", maximum_bytes=4 * 1024 * 1024)
    preserved_raw, _ = bounded_text_lines(preserved_path, "legacy preserved execution audit", maximum_bytes=4 * 1024 * 1024)
    original_state = original_path.stat()
    if (
        original_raw != preserved_raw
        or integer(original["bytes"], "legacy original audit bytes", minimum=1) != len(original_raw)
        or string(original["device"], "legacy original audit device") != str(original_state.st_dev)
        or string(original["inode"], "legacy original audit inode") != str(original_state.st_ino)
        or integer(original["uid"], "legacy original audit uid") != original_state.st_uid
        or integer(original["gid"], "legacy original audit gid") != original_state.st_gid
        or string(original["mode"], "legacy original audit mode") != format(stat.S_IMODE(original_state.st_mode), "04o")
        or integer(original["mtime_epoch"], "legacy original audit mtime") != int(original_state.st_mtime)
        or boolean(original["signed_at_execution"], "legacy original audit signed_at_execution") is not False
        or boolean(original["hmac_present_at_execution"], "legacy original audit hmac_present_at_execution") is not False
    ):
        fail("legacy original execution audit metadata/status mismatch")
    for candidate in (original_path, preserved_path):
        hmac_path = Path(str(candidate) + ".hmac")
        if hmac_path.exists() or hmac_path.is_symlink():
            fail("legacy unsigned execution audit unexpectedly has HMAC")
    begin = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tBEGIN contract=[A-Z0-9_]+"
        + r" site=" + re.escape(domain)
        + r" operation=" + re.escape(operation)
        + r" package=" + re.escape(package_sha256)
        + r" operator=[A-Za-z0-9._-]+$"
    )
    terminal = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t"
        r"[A-Z0-9_]+_REMEDIATION_COMPLETE_ISOLATION_REMAINS_ACTIVE$"
    )
    begin_records = [(index, line) for index, line in enumerate(audit_lines) if begin.fullmatch(line)]
    terminal_records = [(index, line) for index, line in enumerate(audit_lines) if terminal.fullmatch(line)]
    audit_apply = (
        f"WAPP_[A-Z0-9_]+_DB_APPLY_V1\\|{re.escape(operation)}\\|COMMITTED"
        f"\\|active={expected_actions['active_plugin_rows']}"
        f"\\|options={expected_actions['option_rows']}"
        f"\\|identity={expected_actions['identity_meta_rows']}"
        f"\\|credential_neutral={1 if expected_actions['identity_targets'] else 0}"
        r"\|sessions_restored=0"
    )
    audit_after = (
        f"WAPP_[A-Z0-9_]+_DB_AFTER_V1\\|{re.escape(operation)}\\|EXACT"
        f"\\|active={expected_actions['active_plugin_rows']}"
        r"\|options=0\|identity=0"
        f"\\|user_preserved={1 if expected_actions['identity_targets'] else 0}"
        r"\|sessions=0"
    )
    audit_apply_records = [
        (index, line) for index, line in enumerate(audit_lines)
        if re.fullmatch(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t" + audit_apply + r"$", line)
    ]
    audit_database_records = [
        (index, line) for index, line in enumerate(audit_lines)
        if re.fullmatch(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t" + audit_after + r"$", line)
    ]
    quarantine_records = [
        (index, line) for index, line in enumerate(audit_lines)
        if re.fullmatch(
            r"WAPP_[A-Z0-9_]+_FILES_QUARANTINED_V1\|" + re.escape(operation)
            + r"\|" + str(expected_actions["quarantine_file_targets"]),
            line,
        )
    ]
    replace_records = [
        (index, line) for index, line in enumerate(audit_lines)
        if re.fullmatch(
            r"WAPP_[A-Z0-9_]+_FILES_TRANSFORMED_V1\|" + re.escape(operation)
            + r"\|" + str(expected_actions["replace_file_targets"]),
            line,
        )
    ]
    file_markers_ok = (
        (expected_actions["quarantine_file_targets"] == 0 and not quarantine_records)
        or (expected_actions["quarantine_file_targets"] > 0 and len(quarantine_records) == 1)
    ) and (
        (expected_actions["replace_file_targets"] == 0 and not replace_records)
        or (expected_actions["replace_file_targets"] > 0 and len(replace_records) == 1)
    )
    database_expected = any(
        expected_actions[key] > 0
        for key in ("active_plugin_members", "option_rows", "identity_targets")
    )
    database_markers_ok = (
        (not database_expected and not audit_apply_records and not audit_database_records)
        or (database_expected and len(audit_apply_records) == 1 and len(audit_database_records) == 1)
    )
    generic_quarantine = [line for line in audit_lines if re.fullmatch(r"WAPP_[A-Z0-9_]+_FILES_QUARANTINED_V1\|" + re.escape(operation) + r"\|[0-9]+", line)]
    generic_replace = [line for line in audit_lines if re.fullmatch(r"WAPP_[A-Z0-9_]+_FILES_TRANSFORMED_V1\|" + re.escape(operation) + r"\|[0-9]+", line)]
    generic_apply = [line for line in audit_lines if re.fullmatch(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tWAPP_[A-Z0-9_]+_DB_APPLY_V1\|" + re.escape(operation) + r"\|.+$", line)]
    generic_after = [line for line in audit_lines if re.fullmatch(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tWAPP_[A-Z0-9_]+_DB_AFTER_V1\|" + re.escape(operation) + r"\|.+$", line)]
    if (
        len(begin_records) != 1
        or len(terminal_records) != 1
        or not file_markers_ok
        or not database_markers_ok
        or len(generic_quarantine) != len(quarantine_records)
        or len(generic_replace) != len(replace_records)
        or len(generic_apply) != len(audit_apply_records)
        or len(generic_after) != len(audit_database_records)
    ):
        fail("legacy original execution audit success/site binding unavailable")
    begin_index, begin_line = begin_records[0]
    terminal_index, terminal_line = terminal_records[0]
    file_indices = [index for index, _ in (*quarantine_records, *replace_records)]
    if database_expected:
        apply_index, apply_line = audit_apply_records[0]
        after_index, after_line = audit_database_records[0]
        if not (
            begin_index < min(file_indices, default=apply_index)
            and max(file_indices, default=begin_index) < apply_index < after_index < terminal_index
        ):
            fail("legacy original execution audit marker order invalid")
    elif not (begin_index < min(file_indices, default=terminal_index) and max(file_indices, default=begin_index) < terminal_index):
        fail("legacy original execution audit marker order invalid")
    audit_started = reconciliation_timestamp(begin_line.split("\t", 1)[0], "legacy audit start")
    audit_completed = reconciliation_timestamp(terminal_line.split("\t", 1)[0], "legacy audit completion")
    if database_expected:
        apply_at = reconciliation_timestamp(apply_line.split("\t", 1)[0], "legacy database apply")
        after_at = reconciliation_timestamp(after_line.split("\t", 1)[0], "legacy database after")
        if not audit_started <= apply_at <= after_at <= audit_completed:
            fail("legacy original execution audit database chronology invalid")
    if not (
        package["generated_at_epoch"] <= audit_started <= audit_completed
        < package["expires_at_epoch"] <= generated <= current_time
    ):
        fail("legacy original execution audit chronology invalid")
    identity_user_ids = sorted({
        action["target"]["user_id"]
        for action in package["actions"]
        if action["primitive"] == "QUARANTINE_IDENTITY_ACCESS"
    })
    if len(identity_user_ids) > 1:
        fail("legacy reconciliation multiple identity targets unsupported")
    audit_pre = (
        f"WAPP_[A-Z0-9_]+_DB_PRE_V1\\|{re.escape(operation)}\\|EXACT"
        f"\\|active={expected_actions['active_plugin_rows']}"
        f"\\|options={expected_actions['option_rows']}"
        f"\\|identity={expected_actions['identity_meta_rows']}"
        r"\|session=0"
        f"\\|user={identity_user_ids[0] if identity_user_ids else 0}"
    )
    allowed_timestamped = [
        begin,
        terminal,
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tOPEN endpoint=(?:public|origin) route=\S+ frame=[0-9]{3}\|\|[0-9]+$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tPUBLIC_CORE_HUMAN_GATE_ALREADY_VERIFIED$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tSELF_MANAGED_ATOMIC_DOCROOT_ISOLATION_ACTIVE$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tISOLATION endpoint=(?:public|origin) scheme=(?:http|https) route=\S+ denied=1$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tISOLATION_PREWRITE observation=[0-9]+$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tRECURRENCE_AFTER_EXECUTABLE observation=[0-9]+$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tEXECUTABLES_QUARANTINED files=" + str(expected_actions["quarantine_file_targets"]) + r"$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t" + audit_pre + r"$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t" + audit_apply + r"$"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\t" + audit_after + r"$"),
    ]
    file_total = expected_actions["quarantine_file_targets"] + expected_actions["replace_file_targets"]
    allowed_untimestamped = [
        re.compile(r"^WAPP_[A-Z0-9_]+_ISOLATION_OBSERVED_OPEN_V1\|" + re.escape(operation) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_ISOLATION_PREPARED_V1\|" + re.escape(operation) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_ISOLATION_ACTIVE_V1\|" + re.escape(operation) + r"\|root_inode=" + re.escape(root_inode) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_FILES_OBSERVED_ISOLATED_V1\|" + re.escape(operation) + r"\|" + str(file_total) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_FILES_PREPARED_V1\|" + re.escape(operation) + r"\|" + str(file_total) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_FILES_OBSERVED_PREWRITE_V1\|" + re.escape(operation) + r"\|" + str(file_total) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_FILES_VERIFIED_V1\|" + re.escape(operation) + r"\|" + str(file_total) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_FILES_QUARANTINED_V1\|" + re.escape(operation) + r"\|" + str(expected_actions["quarantine_file_targets"]) + r"$"),
        re.compile(r"^WAPP_[A-Z0-9_]+_FILES_TRANSFORMED_V1\|" + re.escape(operation) + r"\|" + str(expected_actions["replace_file_targets"]) + r"$"),
    ]
    timestamp_prefix = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\t")
    for index, line in enumerate(audit_lines):
        timestamp_match = timestamp_prefix.match(line)
        if timestamp_match:
            if not any(pattern.fullmatch(line) for pattern in allowed_timestamped):
                fail("legacy original execution audit contains unknown timestamped record")
            line_epoch = reconciliation_timestamp(timestamp_match.group(1), "legacy audit record")
            if index < begin_index or index > terminal_index or not package["generated_at_epoch"] <= line_epoch <= audit_completed:
                fail("legacy original execution audit record chronology invalid")
        elif not any(pattern.fullmatch(line) for pattern in allowed_untimestamped):
            fail("legacy original execution audit contains unknown untimestamped record")

    _, poststate_lines = bounded_text_lines(
        source_paths["current_poststate"],
        "legacy reconciliation current poststate",
        maximum_bytes=1024 * 1024,
    )
    if not re.fullmatch(r"WAPP_[A-Z0-9_]+_LEGACY_RECONCILIATION_CURRENT_POSTSTATE_V1", poststate_lines[0]):
        fail("legacy reconciliation poststate protocol mismatch")
    expected_fields = {
        "domain": domain,
        "root": root,
        "root_device": root_device,
        "root_inode": root_inode,
        "operation_id": operation,
        "package_sha256": package_sha256,
        "original_audit_sha256": original_sha,
        "original_audit_signed_at_execution": "false",
        "read_only": "true",
        "authority": "false",
    }
    observed_fields: dict[str, str] = {}
    for line in poststate_lines[1:11]:
        if line.count("=") != 1:
            fail("legacy reconciliation poststate binding malformed")
        key, item = line.split("=", 1)
        if key in observed_fields:
            fail("legacy reconciliation poststate binding duplicated")
        observed_fields[key] = item
    if observed_fields != expected_fields:
        fail("legacy reconciliation poststate binding mismatch")
    cursor = 11
    begin_times: list[int] = []
    end_times: list[int] = []
    expected_file_total = expected_actions["quarantine_file_targets"] + expected_actions["replace_file_targets"]
    poststate_after = re.compile(audit_after)
    for observation_index in (0, 1):
        if cursor >= len(poststate_lines):
            fail("legacy reconciliation observation missing")
        begin_match = re.fullmatch(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\tOBSERVATION_BEGIN index="
            + str(observation_index),
            poststate_lines[cursor],
        )
        if begin_match is None:
            fail("legacy reconciliation observation order mismatch")
        begin_times.append(reconciliation_timestamp(begin_match.group(1), "legacy observation"))
        cursor += 1
        evidence = poststate_lines[cursor:]
        end_offset = next(
            (
                offset for offset, line in enumerate(evidence)
                if re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tOBSERVATION_END index="
                    + str(observation_index),
                    line,
                )
            ),
            None,
        )
        if end_offset is None:
            fail("legacy reconciliation observation end missing")
        block = evidence[:end_offset]
        end_line = evidence[end_offset]
        end_at = reconciliation_timestamp(end_line.split("\t", 1)[0], "legacy observation end")
        if end_at < begin_times[-1]:
            fail("legacy reconciliation observation chronology invalid")
        if any("OBSERVATION_" in line for line in block):
            fail("legacy reconciliation observation nesting invalid")
        isolation_count = sum(bool(re.fullmatch(r"WAPP_[A-Z0-9_]+_ISOLATION_VERIFIED_V1\|" + re.escape(operation), line)) for line in block)
        file_count = sum(bool(re.fullmatch(r"WAPP_[A-Z0-9_]+_FILES_VERIFIED_V1\|" + re.escape(operation) + r"\|" + str(expected_file_total), line)) for line in block)
        database_count = sum(bool(poststate_after.fullmatch(line)) for line in block)
        public_records = [line for line in block if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tHTTP_ISOLATION endpoint=public route=\S+ denied=1", line)]
        origin_records = [line for line in block if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\tHTTP_ISOLATION endpoint=origin route=\S+ denied=1", line)]
        public_denied = len(public_records)
        origin_denied = len(origin_records)
        for denial in (*public_records, *origin_records):
            denial_at = reconciliation_timestamp(denial.split("\t", 1)[0], "legacy isolation evidence")
            if not begin_times[-1] <= denial_at <= end_at:
                fail("legacy reconciliation isolation evidence chronology invalid")
        recognized = isolation_count + file_count + database_count + public_denied + origin_denied
        if (
            isolation_count != 1
            or file_count != 1
            or database_count != (1 if database_expected else 0)
            or public_denied < 1
            or origin_denied < 1
            or recognized != len(block)
        ):
            fail("legacy reconciliation observation proof incomplete")
        end_times.append(end_at)
        cursor += end_offset + 1
    terminal_poststate = "RECONCILIATION_POSTSTATE_VERIFIED recurrence=false isolation_active=true"
    if cursor != len(poststate_lines) - 1 or not poststate_lines[cursor].endswith("\t" + terminal_poststate):
        fail("legacy reconciliation exact poststate proof incomplete")
    if (
        begin_times[0] < package["expires_at_epoch"]
        or end_times[0] >= begin_times[1]
        or begin_times[1] - begin_times[0] < 60
    ):
        fail("legacy reconciliation bounded stability window incomplete")
    poststate_completed = reconciliation_timestamp(
        poststate_lines[cursor].split("\t", 1)[0],
        "legacy reconciliation completion",
    )
    if poststate_completed < end_times[1] or poststate_completed > generated:
        fail("legacy reconciliation poststate chronology invalid")

    verified = value["verified_poststate"]
    if not isinstance(verified, dict):
        fail("legacy_reconciliation.verified_poststate must be an object")
    exact_keys(
        verified,
        {
            "quarantine_exact", "active_plugins_exact", "incident_options_absent",
            "incident_identity_access_quarantined", "recurrence", "isolation_active",
            "site_identity_verified", "read_only",
        },
        "legacy_reconciliation.verified_poststate",
    )
    expected_verified = {
        "quarantine_exact": True,
        "active_plugins_exact": True,
        "incident_options_absent": True,
        "incident_identity_access_quarantined": True,
        "recurrence": False,
        "isolation_active": True,
        "site_identity_verified": True,
        "read_only": True,
    }
    for key in expected_verified:
        boolean(verified[key], f"legacy_reconciliation.verified_poststate.{key}")
    if verified != expected_verified:
        fail("legacy reconciliation verified poststate is incomplete")

    reconciliation_review = verify_review(review_path, path)
    return {
        "state": "LEGACY_RECONCILED_EXECUTION",
        "domain": domain,
        "root": root,
        "root_device": root_device,
        "root_inode": root_inode,
        "operation_id": operation,
        "package_sha256": package_sha256,
        "isolation_identity_sha256": isolation_identity,
        "generated_at_epoch": generated,
        "original_audit_sha256": original_sha,
        "original_audit_signed_at_execution": False,
        "reconciliation_reviewer_id": reconciliation_review["reviewer_id"],
        "reconciliation_reviewer_key_id": reconciliation_review["key_id"],
        "isolation_active": True,
        "recurrence": False,
        "authority": False,
        "dependencies": [str(path), str(review_path), *[str(item) for item in source_paths.values()]],
    }


def verify_current_site_identity(
    path: Path,
    domain: str,
    root: str,
    operation: str,
    product_commit: str,
    root_device: str,
    root_inode: str,
    minimum_epoch: int,
    maximum_epoch: int,
) -> int:
    value = load(path)
    exact_keys(
        value,
        {
            "tool", "schema", "domain", "root", "operation_id", "product_commit",
            "generated_at_epoch", "root_device", "root_inode", "serving_root_verified",
            "read_only", "authority",
        },
        "current_site_identity",
    )
    generated = integer(value["generated_at_epoch"], "current_site_identity.generated_at_epoch", minimum=minimum_epoch)
    if (
        value["tool"] != "wapp-security-emergency-current-site-identity"
        or value["schema"] != 1
        or value["domain"] != domain
        or value["root"] != root
        or value["operation_id"] != operation
        or value["product_commit"] != product_commit
        or value["root_device"] != root_device
        or value["root_inode"] != root_inode
        or generated > maximum_epoch
        or boolean(value["serving_root_verified"], "current_site_identity.serving_root_verified") is not True
        or boolean(value["read_only"], "current_site_identity.read_only") is not True
        or value["authority"] is not False
    ):
        fail("current site/root identity binding mismatch")
    string(value["root_device"], "current_site_identity.root_device")
    string(value["root_inode"], "current_site_identity.root_inode")
    return generated


def verify_closure(path: Path, domain: str, *, now: int | None = None) -> dict[str, Any]:
    value = load(path)
    schema = value.get("schema")
    common = {
        "tool", "schema", "domain", "root", "operation_id", "generated_at_epoch",
        "fresh_until_epoch", "product", "evidence", "checks", "assurance_limitations",
        "hardening_findings", "authority",
    }
    expected = common | (
        {"remediation", "reopen"}
        if schema == 1
        else {"historical_execution", "current_site_identity"}
    )
    exact_keys(value, expected, "closure")
    if value["tool"] != "wapp-security-emergency-closure-record" or schema not in {1, 2} or value["domain"] != domain:
        fail("closure protocol/domain mismatch")
    root = absolute(value["root"], "closure.root")
    operation = string(value["operation_id"], "closure.operation_id")
    if not HEX32.fullmatch(operation):
        fail("closure operation identity invalid")
    generated = integer(value["generated_at_epoch"], "closure.generated_at_epoch", minimum=1)
    fresh_until = integer(value["fresh_until_epoch"], "closure.fresh_until_epoch", minimum=generated + 1)
    current_time = int(time.time()) if now is None else now
    if generated > current_time:
        fail("closure record is future dated")
    product = value["product"]
    if not isinstance(product, dict):
        fail("closure product must be an object")
    exact_keys(product, {"commit", "seal"}, "closure.product")
    product_commit = string(product["commit"], "closure.product.commit")
    if not re.fullmatch(r"[0-9a-f]{40}", product_commit):
        fail("closure product commit invalid")
    product_path = bound_file(product["seal"], "closure.product.seal")
    verify_product_seal(product_path, product_commit)

    package_dependencies: list[str] = [str(product_path)]
    if schema == 1:
        package_summaries: dict[str, dict[str, Any]] = {}
        package_paths: dict[str, Path] = {}
        for phase in ("remediation", "reopen"):
            entry = value[phase]
            if not isinstance(entry, dict):
                fail(f"closure.{phase} must be an object")
            expected_entry = {"package", "review"}
            if phase == "reopen":
                expected_entry.add("execution_postcheck")
            exact_keys(entry, expected_entry, f"closure.{phase}")
            package_path = bound_file(entry["package"], f"closure.{phase}.package")
            review_path = bound_file(entry["review"], f"closure.{phase}.review")
            summary = verify_package(
                package_path,
                domain,
                now=generated,
                historical_execution=(phase == "remediation"),
            )
            verify_review(review_path, package_path)
            if summary["phase"] != phase.upper() or summary["root"] != root:
                fail(f"closure.{phase} package lineage mismatch")
            package_summaries[phase] = summary
            package_paths[phase] = package_path
            package_dependencies.extend([str(package_path), str(review_path)])
        remediation = package_summaries["remediation"]
        reopen = package_summaries["reopen"]
        reopen_value = load(package_paths["reopen"])
        if (
            operation != remediation["operation_id"]
            or value["product"] != load(package_paths["remediation"])["product"]
            or reopen_value["continuation"]["remediation_package"]["sha256"] != remediation["package_sha256"]
        ):
            fail("closure remediation/reopen/Product binding mismatch")
        reopen_postcheck_path = bound_file(value["reopen"]["execution_postcheck"], "closure.reopen.execution_postcheck")
        reopen_postcheck = verify_reopen_postcheck(
            reopen_postcheck_path, domain, root, remediation, reopen, generated,
        )
        package_dependencies.append(str(reopen_postcheck_path))
        evidence_minimum_epoch = reopen_postcheck["generated_at_epoch"]
        lineage_recurrence = reopen_postcheck["recurrence"]
        lineage_targets_absent = reopen_postcheck["incident_targets_absent"]
        lineage_post_open_verified = reopen_postcheck["post_open_verified"]
        lineage_isolation_reversed = reopen_postcheck["isolation_reversed"]
    else:
        historical = value["historical_execution"]
        if not isinstance(historical, dict):
            fail("closure.historical_execution must be an object")
        exact_keys(historical, {"lineage", "review"}, "closure.historical_execution")
        lineage_path = bound_file(historical["lineage"], "closure.historical_execution.lineage")
        lineage_review = bound_file(historical["review"], "closure.historical_execution.review")
        lineage = verify_historical_execution_lineage(lineage_path, lineage_review, domain, generated)
        if lineage["root"] != root or lineage["operation_id"] != operation:
            fail("closure historical execution site/operation mismatch")
        package_dependencies.extend(lineage["dependencies"])
        current_site_path = bound_file(value["current_site_identity"], "closure.current_site_identity")
        current_site_generated = verify_current_site_identity(
            current_site_path,
            domain,
            root,
            operation,
            product_commit,
            lineage["root_device"],
            lineage["root_inode"],
            lineage["post_open_generated_at_epoch"],
            generated,
        )
        package_dependencies.append(str(current_site_path))
        evidence_minimum_epoch = current_site_generated
        lineage_recurrence = lineage["recurrence"]
        lineage_targets_absent = lineage["incident_targets_absent"]
        lineage_post_open_verified = True
        lineage_isolation_reversed = True
    if not isinstance(value["evidence"], list) or len(value["evidence"]) != 1:
        fail("closure requires exactly one canonical evidence artifact")
    evidence_path = bound_file(value["evidence"][0], "closure.evidence[0]")
    derived_checks = derive_closure_checks(
        evidence_path, domain, root, operation, product_commit,
        evidence_minimum_epoch, generated,
    )
    evidence_dependencies = [str(evidence_path)]
    checks = value["checks"]
    if not isinstance(checks, dict):
        fail("closure checks must be an object")
    exact_keys(checks, {"critical", "high", "filesystem_complete", "database_complete", "runtime_ok", "recurrence", "unknown_executable_persistence", "unresolved_malicious_privileged_access", "incident_targets_absent"}, "closure.checks")
    critical = integer(checks["critical"], "closure.checks.critical")
    high = integer(checks["high"], "closure.checks.high")
    for key in ("filesystem_complete", "database_complete", "runtime_ok", "recurrence", "unknown_executable_persistence", "unresolved_malicious_privileged_access", "incident_targets_absent"):
        boolean(checks[key], f"closure.checks.{key}")
    if checks != derived_checks:
        fail("closure checks are not derived from canonical evidence")
    if (
        checks["recurrence"] != lineage_recurrence
        or checks["incident_targets_absent"] != lineage_targets_absent
    ):
        fail("closure evidence/reopen postcheck mismatch")
    limitations = value["assurance_limitations"]
    hardening = value["hardening_findings"]
    if not isinstance(limitations, list) or any(not isinstance(item, str) or not item for item in limitations):
        fail("closure assurance limitations invalid")
    for index, item in enumerate(limitations):
        string(item, f"closure.assurance_limitations[{index}]")
    if not isinstance(hardening, list) or any(not isinstance(item, str) or not item for item in hardening):
        fail("closure hardening findings invalid")
    for index, item in enumerate(hardening):
        string(item, f"closure.hardening_findings[{index}]")
    if value["authority"] is not False:
        fail("closure record cannot self-authorize")
    blocked = (
        current_time >= fresh_until or not lineage_isolation_reversed or not lineage_post_open_verified
        or critical > 0 or high > 0 or not checks["filesystem_complete"] or not checks["database_complete"]
        or not checks["runtime_ok"] or checks["recurrence"] or checks["unknown_executable_persistence"]
        or checks["unresolved_malicious_privileged_access"] or not checks["incident_targets_absent"]
    )
    if blocked:
        status = "STILL_INCOMPLETE"
    elif hardening:
        status = "CLEAN_WITH_HARDENING_REMAINING"
    elif limitations:
        status = "CLEAN_WITH_DOCUMENTED_ASSURANCE_LIMITATIONS"
    else:
        status = "WORDPRESS_INCIDENT_VERIFIED_CLEAN"
    return {
        "domain": domain, "status": status, "hardening": hardening,
        "assurance_limitations": limitations, "record_sha256": sha(path),
        "dependencies": [*package_dependencies, *evidence_dependencies],
    }


def execute_pinned_launcher(path: Path, expected_sha: str, package_sha: str) -> int:
    digest(expected_sha, "launcher.sha256")
    digest(package_sha, "package.sha256")
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(str(path), flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                fail("launcher descriptor is not a trusted regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot pin launcher descriptor: {error}")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        fail("launcher descriptor drifted while pinned")
    raw = b"".join(chunks)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        fail("launcher pinned-byte hash mismatch")
    try:
        with tempfile.TemporaryFile(mode="w+b") as pinned:
            pinned.write(raw)
            pinned.flush()
            os.fsync(pinned.fileno())
            pinned.seek(0)
            if hashlib.sha256(pinned.read()).hexdigest() != expected_sha:
                fail("anonymous launcher readback mismatch")
            pinned.seek(0)
            pinned_state = os.fstat(pinned.fileno())
            if not stat.S_ISREG(pinned_state.st_mode) or pinned_state.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                fail("anonymous launcher pin permissions invalid")
            os.dup2(pinned.fileno(), 9)
            os.set_inheritable(9, True)
            if not Path("/dev/fd/9").exists():
                fail("trusted anonymous launcher descriptor alias unavailable")
            environment = {
                "HOME": os.environ.get("HOME", ""),
                "USER": os.environ.get("USER", ""),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LC_ALL": "C",
            }
            os.execve("/bin/bash", ["/bin/bash", "/dev/fd/9", "--execute", package_sha], environment)
    except OSError as error:
        fail(f"cannot execute anonymous pinned launcher: {error}")
    return 20


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    package_parser = sub.add_parser("verify-package")
    package_parser.add_argument("--package", required=True)
    package_parser.add_argument("--domain", required=True)
    package_parser.add_argument("--now-epoch", type=int)
    dispatch_parser = sub.add_parser("verify-current-dispatch")
    dispatch_parser.add_argument("--package", required=True)
    dispatch_parser.add_argument("--review", required=True)
    dispatch_parser.add_argument("--domain", required=True)
    dispatch_parser.add_argument("--package-sha256", required=True)
    registry_parser = sub.add_parser("registry-package")
    registry_parser.add_argument("--registry", required=True)
    registry_parser.add_argument("--domain", required=True)
    registry_parser.add_argument("--phase", choices=("remediation", "reopen", "closure"), required=True)
    closure_parser = sub.add_parser("verify-closure")
    closure_parser.add_argument("--record", required=True)
    closure_parser.add_argument("--domain", required=True)
    closure_parser.add_argument("--now-epoch", type=int)
    review_parser = sub.add_parser("verify-review")
    review_parser.add_argument("--review", required=True)
    review_parser.add_argument("--package", required=True)
    review_parser.add_argument("--domain", required=True)
    legacy_parser = sub.add_parser("verify-legacy-reconciliation")
    legacy_parser.add_argument("--attestation", required=True)
    legacy_parser.add_argument("--review", required=True)
    legacy_parser.add_argument("--domain", required=True)
    legacy_parser.add_argument("--now-epoch", type=int)
    exec_parser = sub.add_parser("exec-launcher")
    exec_parser.add_argument("--launcher", required=True)
    exec_parser.add_argument("--sha256", required=True)
    exec_parser.add_argument("--package-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "exec-launcher":
            return execute_pinned_launcher(Path(args.launcher), args.sha256, args.package_sha256)
        domain = args.domain.lower()
        if not DOMAIN.fullmatch(domain):
            fail("invalid domain")
        if args.command == "verify-package":
            result = verify_package(Path(args.package), domain, now=args.now_epoch)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        elif args.command == "verify-current-dispatch":
            package_path = Path(args.package)
            if not HEX64.fullmatch(args.package_sha256) or sha(package_path) != args.package_sha256:
                fail("current dispatch package hash mismatch")
            result = verify_package(
                package_path,
                domain,
                current_dispatch=True,
            )
            verify_review(Path(args.review), package_path)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        elif args.command == "registry-package":
            print(json.dumps(verify_registry(Path(args.registry), domain, args.phase), sort_keys=True, separators=(",", ":")))
        elif args.command == "verify-review":
            verify_package(Path(args.package), domain)
            verify_review(Path(args.review), Path(args.package))
            print("PASS_NO_P0_P1_P2")
        elif args.command == "verify-legacy-reconciliation":
            print(json.dumps(
                verify_legacy_reconciled_execution(
                    Path(args.attestation),
                    Path(args.review),
                    domain,
                    now=args.now_epoch,
                ),
                sort_keys=True,
                separators=(",", ":"),
            ))
        else:
            print(json.dumps(verify_closure(Path(args.record), domain, now=args.now_epoch), sort_keys=True, separators=(",", ":")))
    except ContractError as error:
        print(f"emergency-operator-v1: {error}", file=sys.stderr)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
