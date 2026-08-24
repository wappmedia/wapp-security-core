#!/usr/bin/env python3
"""Deterministic public-source boundary for Wapp Security Core."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
TOKEN = re.compile(rb"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})")
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
DOMAIN_LITERAL = re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)+(?:com|net|org|se|io|dev|cloud|app|co|nu)(?![A-Za-z0-9.-])", re.IGNORECASE)
SECRET_ASSIGNMENT = re.compile(r"(?i)(?:password|passwd|secret|token|private[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]")
DISALLOWED_PATH = re.compile(r"/(?:Users|private/var|var/folders)/[A-Za-z0-9._-]+/")
ALLOWED_DOCUMENTATION_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")
ALLOWED_INFRASTRUCTURE_DOMAINS = {"ziglang.org"}
TEXT_SUFFIXES = {"", ".bash", ".c", ".json", ".md", ".py", ".sh", ".txt", ".yml", ".yaml"}


def tracked_files(root: Path) -> list[Path]:
    ignored = {".git", "__pycache__"}
    return sorted(
        path for path in root.rglob("*")
        if path.is_file() and not path.is_symlink() and not any(part in ignored for part in path.relative_to(root).parts)
    )


def valid_ipv4(value: str) -> bool:
    try:
        parts = [int(part) for part in value.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and all(0 <= part <= 255 for part in parts)


def scan_blob(relative: str, raw: bytes, *, display: str | None = None) -> list[str]:
    findings: list[str] = []
    label = relative if display is None else display
    if relative.startswith(("reports/", "quarantine/", "forensics/")):
        return [f"{label}: prohibited artifact directory"]
    if Path(relative).suffix.lower() not in TEXT_SUFFIXES:
        return [f"{label}: unapproved public file type"]
    if b"\x00" in raw:
        return [f"{label}: binary content prohibited"]
    if PRIVATE_KEY.search(raw):
        findings.append(f"{label}: private key material")
    if TOKEN.search(raw):
        findings.append(f"{label}: credential/token pattern")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{label}: non-UTF-8 content"]
    if DISALLOWED_PATH.search(text):
        findings.append(f"{label}: local/private absolute path")
    if SECRET_ASSIGNMENT.search(text):
        findings.append(f"{label}: embedded secret assignment")
    for match in EMAIL.finditer(text):
        findings.append(f"{label}: email-like identifier: {match.group(0)}")
    for match in IPV4.finditer(text):
        value = match.group(0)
        if valid_ipv4(value) and not value.startswith(ALLOWED_DOCUMENTATION_NETS):
            findings.append(f"{label}: non-documentation IPv4 literal: {value}")
    for match in DOMAIN_LITERAL.finditer(text):
        if match.group(0).lower() not in ALLOWED_INFRASTRUCTURE_DOMAINS:
            findings.append(f"{label}: non-synthetic domain literal: {match.group(0)}")
    return findings


def scan_worktree(root: Path) -> list[str]:
    findings: list[str] = []
    for path in tracked_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            raw = path.read_bytes()
        except OSError as error:
            findings.append(f"{relative}: unreadable: {error}")
            continue
        findings.extend(scan_blob(relative, raw))
    return findings


def git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "-c", "core.quotePath=false", *args],
            check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"git history unavailable: {error}") from error


def scan_history(root: Path) -> list[str]:
    findings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for raw_commit in git(root, "rev-list", "--all").decode("ascii").splitlines():
        if not re.fullmatch(r"[0-9a-f]{40,64}", raw_commit):
            findings.append("history: malformed commit identity")
            continue
        metadata = git(root, "cat-file", "commit", raw_commit)
        findings.extend(
            scan_blob(
                "commit-metadata.txt",
                metadata,
                display=f"history:{raw_commit[:12]}:commit-metadata",
            )
        )
    for raw_tag in git(root, "for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags").decode("ascii").splitlines():
        object_id, _, object_type = raw_tag.partition(" ")
        if object_type != "tag":
            continue
        metadata = git(root, "cat-file", "tag", object_id)
        findings.extend(
            scan_blob(
                "tag-metadata.txt",
                metadata,
                display=f"history:{object_id[:12]}:tag-metadata",
            )
        )
    for raw_line in git(root, "rev-list", "--objects", "--all").decode("utf-8").splitlines():
        object_id, _, object_path = raw_line.partition(" ")
        if git(root, "cat-file", "-t", object_id).strip() != b"blob":
            continue
        relative = object_path or f"object-{object_id}"
        identity = (object_id, relative)
        if identity in seen:
            continue
        seen.add(identity)
        raw = git(root, "cat-file", "blob", object_id)
        if relative.startswith(("reports/", "quarantine/", "forensics/")):
            findings.append(f"history:{object_id[:12]}:{relative}: prohibited artifact directory")
            continue
        findings.extend(scan_blob(relative, raw, display=f"history:{object_id[:12]}:{relative}"))
    return findings


def scan(root: Path, *, worktree_only: bool) -> list[str]:
    findings = scan_worktree(root)
    if not worktree_only:
        try:
            findings.extend(scan_history(root))
        except RuntimeError as error:
            findings.append(str(error))
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--worktree-only", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not root.is_dir():
        print("PUBLIC_DATA_BOUNDARY: invalid root", file=sys.stderr)
        return 20
    findings = scan(root, worktree_only=args.worktree_only)
    if findings:
        print("PUBLIC_DATA_BOUNDARY: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 20
    print("PUBLIC_DATA_BOUNDARY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
