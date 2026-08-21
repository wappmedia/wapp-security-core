#!/usr/bin/env python3
"""Fail-closed package validation for HUMAN_OPERATOR_EMERGENCY v1.

This module does not collect evidence and cannot mutate a target.  It binds a
reviewed, case-specific one-shot launcher to a generic operator contract.
"""
from __future__ import annotations

import argparse
import base64
import binascii
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
}
PRODUCT_PATHSPECS = (
    "VERSION", "wapp", "wapp-scan", "install.command", "update.command",
    "uninstall.command", "bin/wapp", "bin/wapp-*", "lib/*.sh", "lib/*.py",
    "lib/*.php", "lib/*.m", "config/canonical-components.txt",
    "config/provider-authenticators.json", "config/aws-custody-core.json",
    "config/aws-custody-production-policy.json.example",
    "config/reviewer-trust-anchors.json",
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


def reviewer_trust_anchors() -> dict[tuple[str, str], dict[str, Any]]:
    project_root = Path(__file__).resolve().parent.parent
    path = project_root / "config/reviewer-trust-anchors.json"
    value = load(path)
    exact_keys(value, {"tool", "schema", "reviewers"}, "reviewer_trust")
    if value["tool"] != "wapp-security-reviewer-trust-anchors" or value["schema"] != 1:
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


def verify_product_seal(path: Path, declared_commit: str) -> None:
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
        candidate = project_root / relative
        if candidate.is_symlink() or not candidate.is_file():
            fail(f"Product Seal current component unavailable: {relative}")
        if sha(candidate) != digest(component["sha256"], f"{label}.sha256"):
            fail(f"Product Seal current component hash drift: {relative}")
        if candidate.stat().st_size != integer(component["bytes"], f"{label}.bytes"):
            fail(f"Product Seal current component byte drift: {relative}")
    if ordered != sorted(ordered) or not REQUIRED_PRODUCT_COMPONENTS.issubset(seen):
        fail("Product Seal current runtime coverage incomplete")
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


def verify_package(path: Path, domain: str, *, now: int | None = None) -> dict[str, Any]:
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
    if current_time >= expires:
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
    verify_product_seal(product_seal_path, value["product"]["commit"])
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
    if phase == "REMEDIATION":
        if continuation is not None:
            fail("remediation package cannot carry reopen continuation")
    else:
        if not isinstance(continuation, dict):
            fail("reopen continuation is required")
        exact_keys(
            continuation,
            {"remediation_package", "remediation_review", "execution_postcheck", "isolation_identity_sha256"},
            "continuation",
        )
        remediation_path = bound_file(continuation["remediation_package"], "continuation.remediation_package")
        remediation_review_path = bound_file(continuation["remediation_review"], "continuation.remediation_review")
        remediation = verify_package(remediation_path, domain, now=current_time)
        verify_review(remediation_review_path, remediation_path)
        if remediation["phase"] != "REMEDIATION" or remediation["classification"] != "YELLOW_SELF_REMEDIATION":
            fail("reopen continuation remediation identity mismatch")
        remediation_value = load(remediation_path)
        isolation_identity = canonical_digest({"site": remediation_value["site"], "isolation": remediation_value["isolation"]})
        if digest(continuation["isolation_identity_sha256"], "continuation.isolation_identity_sha256") != isolation_identity:
            fail("reopen isolation identity mismatch")
        if site != remediation_value["site"] or value["product"] != remediation_value["product"]:
            fail("reopen site/Product lineage mismatch")
        postcheck_path = bound_file(continuation["execution_postcheck"], "continuation.execution_postcheck")
        postcheck = load(postcheck_path)
        exact_keys(
            postcheck,
            {
                "tool", "schema", "state", "domain", "root", "remediation_operation_id",
                "remediation_package_sha256", "isolation_identity_sha256", "isolated_root",
                "isolation_active", "recurrence", "incident_targets_absent", "generated_at_epoch",
            },
            "execution_postcheck",
        )
        if postcheck["tool"] != "wapp-security-emergency-execution-postcheck" or postcheck["schema"] != 1:
            fail("execution postcheck protocol mismatch")
        postcheck_generated = integer(postcheck["generated_at_epoch"], "execution_postcheck.generated_at_epoch", minimum=remediation["generated_at_epoch"])
        if postcheck_generated > current_time:
            fail("execution postcheck is future dated")
        if (
            postcheck["state"] != "APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW"
            or postcheck["domain"] != domain
            or postcheck["root"] != site["root"]
            or postcheck["remediation_operation_id"] != remediation["operation_id"]
            or postcheck["remediation_package_sha256"] != remediation["package_sha256"]
            or postcheck["isolation_identity_sha256"] != isolation_identity
            or postcheck["isolated_root"] != actions[0]["target"]["isolated_root"]
            or postcheck["isolation_active"] is not True
            or postcheck["recurrence"] is not False
            or postcheck["incident_targets_absent"] is not True
        ):
            fail("execution postcheck/reopen continuation mismatch")
        continuation_dependencies.extend([str(remediation_path), str(remediation_review_path), str(postcheck_path)])

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
    if marker.exists() or marker.is_symlink():
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
        "package_sha256": sha(path),
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


def verify_closure(path: Path, domain: str, *, now: int | None = None) -> dict[str, Any]:
    value = load(path)
    expected = {
        "tool", "schema", "domain", "root", "operation_id", "generated_at_epoch",
        "fresh_until_epoch", "product", "remediation", "reopen", "evidence", "checks",
        "assurance_limitations", "hardening_findings", "authority",
    }
    exact_keys(value, expected, "closure")
    if value["tool"] != "wapp-security-emergency-closure-record" or value["schema"] != 1 or value["domain"] != domain:
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
        summary = verify_package(package_path, domain, now=generated)
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
    if not isinstance(value["evidence"], list) or len(value["evidence"]) != 1:
        fail("closure requires exactly one canonical evidence artifact")
    evidence_path = bound_file(value["evidence"][0], "closure.evidence[0]")
    derived_checks = derive_closure_checks(
        evidence_path, domain, root, operation, product_commit,
        reopen_postcheck["generated_at_epoch"], generated,
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
        checks["recurrence"] != reopen_postcheck["recurrence"]
        or checks["incident_targets_absent"] != reopen_postcheck["incident_targets_absent"]
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
        current_time >= fresh_until or not reopen_postcheck["isolation_reversed"] or not reopen_postcheck["post_open_verified"]
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
        elif args.command == "registry-package":
            print(json.dumps(verify_registry(Path(args.registry), domain, args.phase), sort_keys=True, separators=(",", ":")))
        elif args.command == "verify-review":
            verify_package(Path(args.package), domain)
            verify_review(Path(args.review), Path(args.package))
            print("PASS_NO_P0_P1_P2")
        else:
            print(json.dumps(verify_closure(Path(args.record), domain, now=args.now_epoch), sort_keys=True, separators=(",", ":")))
    except ContractError as error:
        print(f"emergency-operator-v1: {error}", file=sys.stderr)
        return 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
