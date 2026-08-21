#!/usr/bin/env python3
"""Customer-neutral, non-authorizing plugin disposition policy."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

EXACT_KEYS = {
    "tool", "schema", "slug", "version", "author", "provenance",
    "activation_status", "inventory_sha256",
}
TARGET_SLUG = "file-manager-for-work"
VERIFIED_VERSION = "4.2.5"
VERIFIED_AUTHOR = "Your Name"
VERIFIED_PROVENANCE = "UNKNOWN"
VERIFIED_INVENTORY_SHA256 = "08f697068f2b2b3758e8a9e8088d88c3e60e6f1c643dd6d9bab84dfbd0166e6c"
SHA256 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> None:
    raise ValueError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{label} must be a non-empty string")
    return value


def read_record(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    if not path.is_absolute():
        fail("record path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            fail("record must be a regular non-symlink file")
        raw = os.read(descriptor, 16385)
    finally:
        os.close(descriptor)
    if len(raw) > 16384:
        fail("record exceeds bounded size")
    value = json.loads(
        raw,
        object_pairs_hook=strict_object,
        parse_constant=lambda token: fail(f"non-finite JSON value: {token}"),
    )
    if not isinstance(value, dict) or set(value) != EXACT_KEYS:
        fail("record key set mismatch")
    if (
        value["tool"] != "wapp-plugin-inventory-record"
        or type(value["schema"]) is not int
        or value["schema"] != 1
    ):
        fail("record protocol mismatch")
    return value


def evaluate(value: dict[str, Any]) -> dict[str, Any]:
    slug = text(value["slug"], "slug")
    version = text(value["version"], "version")
    author = text(value["author"], "author")
    provenance = text(value["provenance"], "provenance")
    activation = text(value["activation_status"], "activation_status")
    fingerprint = text(value["inventory_sha256"], "inventory_sha256")
    if activation not in {"ACTIVE", "INACTIVE"}:
        fail("activation_status must be ACTIVE or INACTIVE")
    if SHA256.fullmatch(fingerprint) is None:
        fail("inventory_sha256 must be canonical lowercase SHA-256")
    record_sha = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    flagged = slug == TARGET_SLUG
    exact = flagged and (
        version == VERIFIED_VERSION
        and author == VERIFIED_AUTHOR
        and provenance == VERIFIED_PROVENANCE
        and fingerprint == VERIFIED_INVENTORY_SHA256
    )
    disposition = (
        "REMOVE_REQUIRED" if exact else
        "PROVENANCE_REVIEW_REQUIRED" if flagged else
        "NOT_APPLICABLE"
    )
    return {
        "activation_status": activation,
        "apply_authority": False,
        "closure_authority": False,
        "disposition": disposition,
        "flagged": flagged,
        "inventory_record_sha256": record_sha,
        "malware_classification": "NOT_ESTABLISHED",
        "mutation_authority": False,
        "prepare_authority": False,
        "remediation_contract": [
            "SNAPSHOT_EXACT_PLUGIN_DIRECTORY",
            "DEACTIVATE_EXACT_MEMBER_IF_ACTIVE",
            "SITE_HEALTH_CHECK",
            "QUARANTINE_OR_REMOVE_EXACT_DIRECTORY",
            "POSTCHECK_ABSENT_AND_HEALTH",
            "FORENSIC_HARDENING_JOURNAL",
        ] if disposition == "REMOVE_REQUIRED" else [],
        "rule": "file-manager-for-work-policy-v1",
        "schema": 1,
        "slug": slug,
        "tool": "wapp-plugin-policy-result",
    }


def main() -> int:
    try:
        if len(sys.argv) != 2:
            fail("usage: plugin-policy.py RECORD.json")
        print(json.dumps(evaluate(read_record(sys.argv[1])), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"plugin-policy: {error}", file=sys.stderr)
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
