#!/usr/bin/env python3
"""Canonical non-authorizing wrapper for native two-pass drift diagnostics."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile

HEX64 = re.compile(r"^[0-9a-f]{64}$")
INTEGER = re.compile(r"^(0|[1-9][0-9]*)$")
MODE = re.compile(r"^[0-7]{3,4}$")
TYPES = {"REGULAR", "DIRECTORY", "SYMLINK", "BLOCK_DEVICE", "CHAR_DEVICE", "FIFO", "SOCKET", "OTHER"}
CHANGES = {"CREATED", "DELETED", "MODIFIED", "REPLACED"}
RAW_BYTE_CAP = 125_829_120
ARTIFACT_BYTE_CAP = 251_658_240
# Mirrors the helper's maximum diagnostic record including its newline.
LINE_BYTE_CAP = 40_960
IO_CHUNK = 1_048_576


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"signed-drift-diagnostic: {message}")


def regular_nonsymlink(path: pathlib.Path) -> bytes:
    try:
        before_path = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        fail("raw capture unavailable")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before_path.st_mode) or before.st_size > RAW_BYTE_CAP:
            fail("raw capture identity invalid")
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            before_path.st_dev, before_path.st_ino, before_path.st_mode, before_path.st_size, before_path.st_mtime_ns, before_path.st_ctime_ns
        ):
            fail("raw capture path/descriptor mismatch")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(IO_CHUNK, RAW_BYTE_CAP + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > RAW_BYTE_CAP:
                fail("raw capture byte cap")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(after_path) or total != before.st_size:
            fail("raw capture drift during verification")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class BoundInput:
    """Descriptor-bound, repeatable, bounded input without whole-file retention."""

    def __init__(self, path: pathlib.Path, byte_cap: int, label: str):
        self.path = path
        self.byte_cap = byte_cap
        self.label = label
        try:
            path_before = path.lstat()
            self.descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            fail(f"{label} unavailable")
        self.before = os.fstat(self.descriptor)
        if (
            not path.is_absolute()
            or not stat.S_ISREG(self.before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or self.before.st_nlink != 1
            or self.before.st_size < 1
            or self.before.st_size > byte_cap
            or identity(path_before) != identity(self.before)
        ):
            os.close(self.descriptor)
            fail(f"{label} identity invalid")
        self.handle = os.fdopen(self.descriptor, "rb", buffering=IO_CHUNK, closefd=False)
        self.digest = hashlib.sha256()
        self.total = 0

    def rewind(self) -> None:
        self.handle.seek(0)
        self.digest = hashlib.sha256()
        self.total = 0

    def lines(self):
        while True:
            line = self.handle.readline(LINE_BYTE_CAP + 1)
            if not line:
                break
            self.total += len(line)
            if self.total > self.byte_cap or len(line) > LINE_BYTE_CAP or not line.endswith(b"\n") or b"\0" in line:
                fail(f"{self.label} framing invalid")
            self.digest.update(line)
            try:
                yield line[:-1].decode("ascii", "strict")
            except UnicodeDecodeError:
                fail(f"{self.label} is not canonical ASCII")
        if self.total != self.before.st_size:
            fail(f"{self.label} byte count drift")

    def verify_stable(self) -> None:
        self.handle.flush()
        after = os.fstat(self.descriptor)
        try:
            path_after = self.path.lstat()
        except OSError:
            fail(f"{self.label} path unavailable after read")
        if identity(self.before) != identity(after) or identity(after) != identity(path_after):
            fail(f"{self.label} drift during verification")

    def close(self) -> None:
        self.handle.close()
        os.close(self.descriptor)


class BoundedWriter:
    def __init__(self, descriptor: int, byte_cap: int):
        self.descriptor = descriptor
        self.byte_cap = byte_cap
        self.total = 0

    def write(self, payload: bytes) -> None:
        if self.total + len(payload) > self.byte_cap:
            fail("diagnostic artifact byte cap")
        offset = 0
        while offset < len(payload):
            written = os.write(self.descriptor, payload[offset:])
            if written <= 0:
                fail("output write failed")
            offset += written
        self.total += len(payload)


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def write_exclusive(path: pathlib.Path, payload: bytes) -> None:
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


def decode_hex(value: str, *, absolute: bool) -> bytes:
    if len(value) % 2 or not re.fullmatch(r"[0-9a-f]*", value):
        fail("path encoding invalid")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        fail("path encoding invalid")
    if b"\0" in raw or (absolute and not raw.startswith(b"/")) or (not absolute and raw.startswith(b"/")):
        fail("path normalization mismatch")
    parts = raw.split(b"/")
    if absolute:
        parts = parts[1:]
    if not absolute and raw == b"":
        return raw
    if not parts or any(part in (b"", b".", b"..") for part in parts):
        fail("path normalization mismatch")
    return raw


def exact_timestamp(value: str) -> str:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        fail("timestamp invalid")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        fail("timestamp invalid")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        fail("timestamp noncanonical")
    return value


def numeric(value: str, label: str) -> int:
    if not INTEGER.fullmatch(value):
        fail(f"{label} invalid")
    result = int(value)
    if result > 2**64 - 1:
        fail(f"{label} out of range")
    return result


def signed_numeric(value: str, label: str) -> int:
    if not re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
        fail(f"{label} invalid")
    result = int(value)
    if result < -(2**63) or result > 2**63 - 1:
        fail(f"{label} out of range")
    return result


def pass_state(values: list[str], exists: bool) -> dict[str, object] | None:
    if not exists:
        if values != ["-"] * 13:
            fail("absent pass contains invented metadata")
        return None
    kind, device, inode, size, mode, uid, gid, nlink, mtime_ns, ctime_ns, sha256, target_hex, uploads = values
    if kind not in TYPES or not MODE.fullmatch(mode):
        fail("entry metadata invalid")
    if sha256 != "-" and not HEX64.fullmatch(sha256):
        fail("entry hash invalid")
    if target_hex != "-" and (len(target_hex) > 8192 or len(target_hex) % 2 or not re.fullmatch(r"[0-9a-f]*", target_hex)):
        fail("symlink target encoding invalid")
    if kind != "SYMLINK" and target_hex != "-":
        fail("unexpected symlink target")
    if uploads not in ("0", "1"):
        fail("uploads marker invalid")
    return {
        "type": kind,
        "device": numeric(device, "device"),
        "inode": numeric(inode, "inode"),
        "size": numeric(size, "size"),
        "mode": mode,
        "uid": numeric(uid, "uid"),
        "gid": numeric(gid, "gid"),
        "nlink": numeric(nlink, "nlink"),
        "mtime_ns": signed_numeric(mtime_ns, "mtime"),
        "ctime_ns": signed_numeric(ctime_ns, "ctime"),
        "sha256": None if sha256 == "-" else sha256,
        "symlink_target_hex": None if target_hex == "-" else target_hex,
        "uploads": uploads == "1",
    }


def load_policy(policy_path: pathlib.Path) -> dict[str, object]:
    value = json.loads(policy_path.read_text(encoding="utf-8"))
    helper = value.get("binary_sha256")
    if not isinstance(helper, str) or not HEX64.fullmatch(helper):
        fail("release helper policy invalid")
    return value


def file_identity(path: pathlib.Path) -> dict[str, object]:
    raw = regular_nonsymlink(path)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def load_product_seal(seal_path: pathlib.Path, root: pathlib.Path) -> dict[str, object]:
    if not seal_path.is_absolute():
        fail("Product Seal path must be absolute")
    raw = regular_nonsymlink(seal_path)
    try:
        seal = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Product Seal JSON invalid")
    version = (root / "VERSION").read_text(encoding="ascii").strip()
    git = seal.get("git") if isinstance(seal, dict) else None
    if seal.get("tool") != "wapp-security-product-seal" or seal.get("schema") != 2 or seal.get("version") != version or not isinstance(git, dict) or git.get("clean") is not True or not re.fullmatch(r"[0-9a-f]{40}", str(git.get("commit", ""))):
        fail("Product Seal release identity invalid")
    try:
        current_commit = subprocess.run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["/usr/bin/git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"], check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        fail("exact Public Core checkout unavailable")
    if current_commit != git["commit"] or dirty:
        fail("Public Core commit or worktree drift")
    components = seal.get("components")
    if not isinstance(components, list) or seal.get("component_count") != len(components):
        fail("Product Seal component cardinality invalid")
    indexed: dict[str, dict[str, object]] = {}
    for component in components:
        if not isinstance(component, dict) or set(component) != {"path", "sha256", "bytes"}:
            fail("Product Seal component invalid")
        relative = component["path"]
        if not isinstance(relative, str) or relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts or relative in indexed or not HEX64.fullmatch(str(component["sha256"])) or not isinstance(component["bytes"], int):
            fail("Product Seal component identity invalid")
        current = file_identity(root / relative)
        if current != {"sha256": component["sha256"], "bytes": component["bytes"]}:
            fail("Product Seal component drift")
        indexed[relative] = component
    required = {
        "VERSION",
        "bin/wapp-signed-drift-diagnostic",
        "config/native-ephemeral-bootstrap.json",
        "config/native-filesystem-helper.json",
        "lib/native-displaced-inventory-ephemeral-loader.sh",
        "lib/native-displaced-inventory-loader.sh",
        "lib/native-drift-diagnostic.py",
        "libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt",
        "native/displaced-inventory-helper.c",
    }
    if not required.issubset(indexed):
        fail("Product Seal diagnostic runtime surface incomplete")
    return {
        "path": str(seal_path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "commit": git["commit"],
        "version": version,
        "component_count": len(components),
        "runtime_components": {name: indexed[name]["sha256"] for name in sorted(required)},
    }


def validate_runtime_identity(runtime_hex: str, runtime_sha: str, helper_sha: str, ephemeral_policy: dict[str, object]) -> dict[str, object]:
    if len(runtime_hex) % 2 or len(runtime_hex) > 2048 or not re.fullmatch(r"[0-9a-f]+", runtime_hex):
        fail("runtime identity encoding invalid")
    try:
        runtime = bytes.fromhex(runtime_hex).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        fail("runtime identity invalid")
    if hashlib.sha256(runtime.encode("ascii")).hexdigest() != runtime_sha:
        fail("runtime identity digest mismatch")
    maximum = re.fullmatch(r"loader=/usr/bin/perl\|loader_sha=([0-9a-f]{64})\|loader_meta=([0-9]+:[0-9]+:[0-7]{3,4}:[0-9]+:[0-9]+:[0-9]+)\|helper_sha=([0-9a-f]{64})\|transport=sealed_memfd_execveat_v1", runtime)
    degraded = re.fullmatch(r"loader=DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1\|launcher_sha=([0-9a-f]{64})\|launcher_meta=([0-9]+:[0-9]+:[0-7]{3,4}:[0-9]+:[0-9]+:[0-9]+)\|helper_sha=([0-9a-f]{64})\|transport=sealed_memfd_execveat_v1", runtime)
    if maximum and maximum.group(3) == helper_sha:
        return {"contract": "TRUSTED_PERL_SEALED_MEMFD_EXECVEAT_V1", "identity_hex": runtime_hex, "identity_sha256": runtime_sha}
    if degraded and degraded.group(1) == ephemeral_policy.get("launcher_binary_sha256") and degraded.group(3) == helper_sha:
        metadata = degraded.group(2).split(":")
        if len(metadata) != 6 or not all(INTEGER.fullmatch(item) for item in metadata) or metadata[2] != "700" or int(metadata[5]) != ephemeral_policy.get("launcher_binary_bytes"):
            fail("ephemeral launcher metadata invalid")
        return {
            "contract": "DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1",
            "identity_scope": "OPERATION_SCOPED",
            "identity_hex": runtime_hex,
            "identity_sha256": runtime_sha,
            "launcher_sha256": degraded.group(1),
            "launcher_metadata": {
                "uid": int(metadata[0]),
                "gid": int(metadata[1]),
                "mode": metadata[2],
                "device": int(metadata[3]),
                "inode": int(metadata[4]),
                "bytes": int(metadata[5]),
            },
            "helper_sha256": degraded.group(3),
            "transport": "sealed_memfd_execveat_v1",
        }
    fail("runtime identity contract mismatch")


def parse_delta(line: str, previous: bytes | None) -> tuple[dict[str, object], bytes]:
    fields = line.split("\t")
    if len(fields) != 31 or fields[0] != "DRIFT" or fields[2] not in CHANGES:
        fail("diagnostic delta invalid")
    path = decode_hex(fields[1], absolute=False)
    if previous is not None and path <= previous:
        fail("diagnostic path order invalid")
    exists1, exists2 = fields[3] == "true", fields[4] == "true"
    if fields[3] not in ("true", "false") or fields[4] not in ("true", "false") or not (exists1 or exists2):
        fail("diagnostic existence invalid")
    pass1 = pass_state(fields[5:18], exists1)
    pass2 = pass_state(fields[18:31], exists2)
    expected_change = "CREATED" if not exists1 else "DELETED" if not exists2 else "REPLACED" if (
        pass1["type"], pass1["device"], pass1["inode"]
    ) != (pass2["type"], pass2["device"], pass2["inode"]) else "MODIFIED"
    if fields[2] != expected_change or (exists1 and exists2 and pass1 == pass2):
        fail("diagnostic change classification invalid")
    return ({
        "normalized_path_hex": fields[1],
        "change_type": fields[2],
        "pass1_exists": exists1,
        "pass2_exists": exists2,
        "pass1": pass1,
        "pass2": pass2,
    }, path)


def parse_issue(line: str, previous: tuple[str, str, str, bool, bool] | None) -> tuple[dict[str, object], tuple[str, str, str, bool, bool]]:
    fields = line.split("\t")
    if len(fields) != 6 or fields[0] != "DRIFT_ISSUE" or not re.fullmatch(r"[A-Z0-9_]{1,64}", fields[2]) or not HEX64.fullmatch(fields[3]) or fields[4] not in ("true", "false") or fields[5] not in ("true", "false") or fields[4] == fields[5]:
        fail("diagnostic issue delta invalid")
    decode_hex(fields[1], absolute=False)
    current = (fields[1], fields[2], fields[3], fields[4] == "true", fields[5] == "true")
    if previous is not None and current <= previous:
        fail("diagnostic issue order invalid")
    return ({"normalized_path_hex": fields[1], "reason": fields[2], "detail_sha256": fields[3], "pass1_exists": fields[4] == "true", "pass2_exists": fields[5] == "true"}, current)


def parse_raw_pass(
    source: BoundInput,
    expected_root: str,
    expected_operation: str,
    policy: dict[str, object],
    ephemeral_policy: dict[str, object],
    emit_delta=None,
    after_deltas=None,
    emit_issue=None,
) -> dict[str, object]:
    source.rewind()
    iterator = iter(source.lines())
    try:
        nonce = next(iterator)
        header = next(iterator).split("\t")
    except StopIteration:
        fail("diagnostic header missing")
    if nonce != f"CAPTURE_NONCE\t{expected_operation}":
        fail("inventory operation binding mismatch")
    if len(header) != 16 or header[0:2] != ["DRIFT_DIAGNOSTIC", "SIGNED_DRIFT_DIAGNOSTIC_MODE_V1"]:
        fail("diagnostic header invalid")
    if header[14:] != ["READ_ONLY", "NON_AUTHORIZING"]:
        fail("diagnostic authority invalid")
    expected_root_hex = os.fsencode(expected_root).hex()
    if header[2] != expected_root_hex or decode_hex(header[2], absolute=True) != os.fsencode(expected_root):
        fail("diagnostic root mismatch")
    for value in header[7:11]:
        if not HEX64.fullmatch(value):
            fail("diagnostic cryptographic binding invalid")
    if header[9] != policy["binary_sha256"]:
        fail("diagnostic helper SHA mismatch")
    runtime = validate_runtime_identity(header[11], header[10], header[9], ephemeral_policy)
    count = numeric(header[12], "delta count")
    issue_count = numeric(header[13], "issue delta count")
    if count > 200_000 or issue_count > 200_000 or count + issue_count == 0:
        fail("diagnostic delta cap")
    previous: bytes | None = None
    for index in range(count):
        try:
            delta, previous = parse_delta(next(iterator), previous)
        except StopIteration:
            fail("diagnostic cardinality mismatch")
        if emit_delta is not None:
            emit_delta(delta, index)
    if after_deltas is not None:
        after_deltas()
    previous_issue = None
    for index in range(issue_count):
        try:
            issue, previous_issue = parse_issue(next(iterator), previous_issue)
        except StopIteration:
            fail("diagnostic cardinality mismatch")
        if emit_issue is not None:
            emit_issue(issue, index)
    bootstrap_audit = None
    audit = None
    try:
        trailing = next(iterator)
    except StopIteration:
        trailing = None
    if trailing is not None:
        if not trailing.startswith("EPHEMERAL_BOOTSTRAP_AUDIT_V2\t"):
            fail("diagnostic trailing record invalid")
        bootstrap_audit = trailing
        audit = bootstrap_audit.split("\t")
        if len(audit) != 9 or audit[1] != expected_operation or audit[-1] != "CLEANUP_VERIFIED" or any(not HEX64.fullmatch(audit[index]) for index in (5, 6, 7)):
            fail("ephemeral bootstrap audit invalid")
        try:
            next(iterator)
            fail("diagnostic trailing data")
        except StopIteration:
            pass
    if bootstrap_audit:
        metadata = runtime.get("launcher_metadata")
        if not isinstance(metadata, dict):
            fail("ephemeral runtime metadata missing")
        metadata_text = ":".join(str(metadata[key]) for key in ("uid", "gid", "mode", "device", "inode", "bytes"))
        expected_launcher_identity = hashlib.sha256((metadata_text + "\0" + str(runtime.get("launcher_sha256"))).encode("ascii")).hexdigest()
        if runtime["contract"] != "DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1" or audit[2] != ephemeral_policy.get("launcher_binary_sha256") or audit[3] != str(ephemeral_policy.get("launcher_binary_bytes")) or audit[4] != metadata_text or audit[5] != runtime.get("identity_sha256") or audit[6] != expected_launcher_identity:
            fail("ephemeral runtime/audit mismatch")
    elif runtime["contract"] == "DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1":
        fail("ephemeral bootstrap audit missing")
    lifecycle = None if bootstrap_audit is None else {
        "contract": "EPHEMERAL_BOOTSTRAP_AUDIT_V2",
        "operation_id": audit[1],
        "launcher_sha256": audit[2],
        "launcher_bytes": int(audit[3]),
        "launcher_metadata": runtime["launcher_metadata"],
        "runtime_identity_sha256": audit[5],
        "launcher_identity_sha256": audit[6],
        "stage_identity_sha256": audit[7],
        "cleanup_state": audit[8],
    }
    return {
        "root_path_hex": header[2],
        "pass1_root": {"device": numeric(header[3], "pass1 root device"), "inode": numeric(header[4], "pass1 root inode")},
        "pass2_root": {"device": numeric(header[5], "pass2 root device"), "inode": numeric(header[6], "pass2 root inode")},
        "pass1_snapshot_sha256": header[7],
        "pass2_snapshot_sha256": header[8],
        "helper_sha256": header[9],
        "runtime_identity_sha256": header[10],
        "runtime_identity": runtime,
        "delta_count": count,
        "issue_delta_count": issue_count,
        "ephemeral_bootstrap_audit": lifecycle,
        "ephemeral_bootstrap_audit_sha256": hashlib.sha256((bootstrap_audit + "\n").encode("ascii")).hexdigest() if bootstrap_audit else None,
    }


def build_metadata(source: BoundInput, expected_root: str, operation: str, observed_at: str, product_seal_path: pathlib.Path, root: pathlib.Path) -> dict[str, object]:
    if not source.path.is_absolute() or not expected_root.startswith("/") or not HEX64.fullmatch(operation):
        fail("bounded invocation invalid")
    policy = load_policy(root / "config/native-filesystem-helper.json")
    ephemeral_policy = json.loads((root / "config/native-ephemeral-bootstrap.json").read_text(encoding="utf-8"))
    product_seal = load_product_seal(product_seal_path, root)
    parsed = parse_raw_pass(source, expected_root, operation, policy, ephemeral_policy)
    raw_sha256 = source.digest.hexdigest()
    source.verify_stable()
    version = (root / "VERSION").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        fail("Public Core version invalid")
    return {
        "tool": "wapp-security-signed-drift-diagnostic",
        "schema": 1,
        "diagnostic_mode": "SIGNED_DRIFT_DIAGNOSTIC_MODE_V1",
        "authority": {"apply": False, "clean": False, "closure": False, "mutation": False, "prepare": False, "ready": False},
        "decision_eligible": False,
        "descriptor_bound": True,
        "observed_at": exact_timestamp(observed_at),
        "inventory_operation_id": operation,
        "public_core_version": version,
        "product_seal": product_seal,
        "raw_capture": {"path": str(source.path), "sha256": raw_sha256, "bytes": source.total},
        **parsed,
    }


def write_artifact(output: pathlib.Path, source: BoundInput, metadata: dict[str, object], expected_root: str, operation: str, policy: dict[str, object], ephemeral_policy: dict[str, object]) -> None:
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        fail("output exclusive create failed")
    created = os.fstat(descriptor)
    writer = BoundedWriter(descriptor, ARTIFACT_BYTE_CAP)

    def pair(key: str, value: object, first: bool = False) -> None:
        writer.write((b"" if first else b",") + json_bytes(key) + b":" + json_bytes(value))

    try:
        writer.write(b"{")
        pair("authority", metadata["authority"], True)
        pair("decision_eligible", metadata["decision_eligible"])
        writer.write(b',"deltas":[')

        def emit_delta(value: dict[str, object], index: int) -> None:
            writer.write((b"" if index == 0 else b",") + json_bytes(value))

        def after_deltas() -> None:
            writer.write(b']')
            pair("descriptor_bound", metadata["descriptor_bound"])
            pair("diagnostic_mode", metadata["diagnostic_mode"])
            pair("ephemeral_bootstrap_audit", metadata["ephemeral_bootstrap_audit"])
            pair("ephemeral_bootstrap_audit_sha256", metadata["ephemeral_bootstrap_audit_sha256"])
            pair("helper_sha256", metadata["helper_sha256"])
            pair("inventory_operation_id", metadata["inventory_operation_id"])
            writer.write(b',"issue_deltas":[')

        def emit_issue(value: dict[str, object], index: int) -> None:
            writer.write((b"" if index == 0 else b",") + json_bytes(value))

        second = parse_raw_pass(source, expected_root, operation, policy, ephemeral_policy, emit_delta, after_deltas, emit_issue)
        source.verify_stable()
        for key in ("root_path_hex", "pass1_root", "pass2_root", "pass1_snapshot_sha256", "pass2_snapshot_sha256", "helper_sha256", "runtime_identity_sha256", "runtime_identity", "delta_count", "issue_delta_count", "ephemeral_bootstrap_audit", "ephemeral_bootstrap_audit_sha256"):
            if second[key] != metadata[key]:
                fail("raw capture changed between bounded passes")
        if source.digest.hexdigest() != metadata["raw_capture"]["sha256"] or source.total != metadata["raw_capture"]["bytes"]:
            fail("raw capture bytes changed between bounded passes")
        writer.write(b']')
        pair("observed_at", metadata["observed_at"])
        pair("pass1_root", metadata["pass1_root"])
        pair("pass1_snapshot_sha256", metadata["pass1_snapshot_sha256"])
        pair("pass2_root", metadata["pass2_root"])
        pair("pass2_snapshot_sha256", metadata["pass2_snapshot_sha256"])
        pair("product_seal", metadata["product_seal"])
        pair("public_core_version", metadata["public_core_version"])
        pair("raw_capture", metadata["raw_capture"])
        pair("root_path_hex", metadata["root_path_hex"])
        pair("runtime_identity", metadata["runtime_identity"])
        pair("runtime_identity_sha256", metadata["runtime_identity_sha256"])
        pair("schema", metadata["schema"])
        pair("tool", metadata["tool"])
        writer.write(b"}\n")
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            current = output.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                output.unlink()
        except OSError:
            pass
        raise
    os.close(descriptor)


class JsonStream:
    """Small strict JSON reader used only to recover immutable derivation inputs."""

    def __init__(self, source: BoundInput):
        self.source = source
        self.source.rewind()
        self.handle = source.handle
        self.buffer = b""
        self.offset = 0

    def _fill(self) -> bool:
        if self.offset < len(self.buffer):
            return True
        chunk = self.handle.read(IO_CHUNK)
        if not chunk:
            self.buffer = b""
            self.offset = 0
            return False
        self.source.total += len(chunk)
        if self.source.total > self.source.byte_cap:
            fail("artifact byte cap")
        self.source.digest.update(chunk)
        self.buffer = chunk
        self.offset = 0
        return True

    def peek(self) -> int | None:
        return self.buffer[self.offset] if self._fill() else None

    def take(self) -> int:
        value = self.peek()
        if value is None:
            fail("artifact JSON truncated")
        self.offset += 1
        return value

    def whitespace(self) -> None:
        while self.peek() in (9, 10, 13, 32):
            self.take()

    def expect(self, value: int) -> None:
        self.whitespace()
        if self.take() != value:
            fail("artifact JSON invalid")

    def string(self) -> str:
        self.whitespace()
        if self.take() != 34:
            fail("artifact JSON string required")
        raw = bytearray(b'"')
        escaped = False
        while True:
            item = self.take()
            raw.append(item)
            if len(raw) > LINE_BYTE_CAP:
                fail("artifact JSON string cap")
            if item < 32:
                fail("artifact JSON control character")
            if escaped:
                escaped = False
            elif item == 92:
                escaped = True
            elif item == 34:
                break
        try:
            value = json.loads(bytes(raw))
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("artifact JSON string invalid")
        if not isinstance(value, str):
            fail("artifact JSON string invalid")
        return value

    def literal(self) -> None:
        self.whitespace()
        token = bytearray()
        while self.peek() is not None and self.peek() not in (9, 10, 13, 32, 44, 93, 125):
            token.append(self.take())
            if len(token) > 128:
                fail("artifact JSON scalar cap")
        try:
            json.loads(bytes(token))
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("artifact JSON scalar invalid")

    def skip(self, depth: int = 0) -> None:
        if depth > 32:
            fail("artifact JSON depth cap")
        self.whitespace()
        current = self.peek()
        if current == 34:
            self.string()
        elif current == 123:
            self.take();self.whitespace()
            if self.peek() == 125:
                self.take();return
            while True:
                self.string();self.expect(58);self.skip(depth + 1);self.whitespace();separator = self.take()
                if separator == 125:return
                if separator != 44:fail("artifact JSON object invalid")
        elif current == 91:
            self.take();self.whitespace()
            if self.peek() == 93:
                self.take();return
            while True:
                self.skip(depth + 1);self.whitespace();separator = self.take()
                if separator == 93:return
                if separator != 44:fail("artifact JSON array invalid")
        else:
            self.literal()

    def selected_object(self, wanted: set[str]) -> dict[str, str]:
        result = {}
        seen = set()
        self.expect(123);self.whitespace()
        if self.peek() == 125:
            self.take();return result
        while True:
            key = self.string()
            if key in seen:fail("artifact duplicate JSON key")
            seen.add(key);self.expect(58)
            if key in wanted:
                result[key] = self.string()
            else:
                self.skip(1)
            self.whitespace();separator = self.take()
            if separator == 125:return result
            if separator != 44:fail("artifact JSON object invalid")


def extract_bindings(artifact: pathlib.Path) -> dict[str, str]:
    source = BoundInput(artifact, ARTIFACT_BYTE_CAP, "diagnostic artifact")
    reader = JsonStream(source)
    wanted_strings = {"inventory_operation_id", "observed_at", "root_path_hex", "tool"}
    result = {}
    seen = set()
    reader.expect(123);reader.whitespace()
    while reader.peek() != 125:
        key = reader.string()
        if key in seen:fail("artifact duplicate top-level key")
        seen.add(key);reader.expect(58)
        if key in wanted_strings:
            result[key] = reader.string()
        elif key == "product_seal":
            selected = reader.selected_object({"path"})
            result["product_seal_path"] = selected.get("path", "")
        elif key == "raw_capture":
            selected = reader.selected_object({"path"})
            result["raw_capture_path"] = selected.get("path", "")
        else:
            reader.skip(1)
        reader.whitespace();separator = reader.take()
        if separator == 125:break
        if separator != 44:fail("artifact JSON object invalid")
    reader.whitespace()
    if reader.peek() is not None:fail("artifact JSON trailing data")
    source.verify_stable();source.close()
    required = wanted_strings | {"product_seal_path", "raw_capture_path"}
    if set(result) != required or result["tool"] != "wapp-security-signed-drift-diagnostic" or not result["product_seal_path"].startswith("/") or not result["raw_capture_path"].startswith("/"):
        fail("artifact derivation bindings missing")
    return result


def compare_bound_files(left: pathlib.Path, right: pathlib.Path) -> bool:
    first = BoundInput(left, ARTIFACT_BYTE_CAP, "diagnostic artifact")
    second = BoundInput(right, ARTIFACT_BYTE_CAP, "rederived artifact")
    same = first.before.st_size == second.before.st_size
    if same:
        while True:
            a = first.handle.read(IO_CHUNK);b = second.handle.read(IO_CHUNK)
            if a != b:
                same = False;break
            if not a:break
    first.verify_stable();second.verify_stable();first.close();second.close()
    return same


def create_artifact(raw_path: pathlib.Path, expected_root: str, operation: str, observed_at: str, product_seal: pathlib.Path, output: pathlib.Path, root: pathlib.Path) -> None:
    source = BoundInput(raw_path, RAW_BYTE_CAP, "raw capture")
    try:
        metadata = build_metadata(source, expected_root, operation, observed_at, product_seal, root)
        policy = load_policy(root / "config/native-filesystem-helper.json")
        ephemeral_policy = json.loads((root / "config/native-ephemeral-bootstrap.json").read_text(encoding="utf-8"))
        write_artifact(output, source, metadata, expected_root, operation, policy, ephemeral_policy)
    finally:
        source.close()


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    if len(sys.argv) == 8 and sys.argv[1] == "create":
        raw_path, expected_root, operation, observed_at, product_seal, output = pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], pathlib.Path(sys.argv[6]), pathlib.Path(sys.argv[7])
        if not output.is_absolute() or output.exists() or output.is_symlink():
            fail("output collision or non-absolute path")
        create_artifact(raw_path, expected_root, operation, observed_at, product_seal, output, root)
        return
    if len(sys.argv) == 3 and sys.argv[1] == "product-seal-path":
        print(extract_bindings(pathlib.Path(sys.argv[2]))["product_seal_path"])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        artifact = pathlib.Path(sys.argv[2])
        bindings = extract_bindings(artifact)
        try:
            expected_root = os.fsdecode(decode_hex(bindings["root_path_hex"], absolute=True))
        except (ValueError, UnicodeDecodeError):
            fail("artifact root binding invalid")
        temporary_directory = pathlib.Path(tempfile.mkdtemp(prefix="wapp-drift-rederive-"))
        os.chmod(temporary_directory, 0o700)
        temporary = temporary_directory / "artifact.json"
        try:
            create_artifact(pathlib.Path(bindings["raw_capture_path"]), expected_root, bindings["inventory_operation_id"], bindings["observed_at"], pathlib.Path(bindings["product_seal_path"]), temporary, root)
            if not compare_bound_files(artifact, temporary):
                fail("artifact derivation mismatch")
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            try:
                temporary_directory.rmdir()
            except OSError:
                pass
        print("SIGNED_DRIFT_DIAGNOSTIC: VERIFIED_NON_AUTHORIZING")
        return
    fail("usage")


if __name__ == "__main__":
    main()
