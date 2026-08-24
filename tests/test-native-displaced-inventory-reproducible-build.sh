#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
POLICY="$ROOT/config/native-filesystem-helper.json"
ARTIFACT="$ROOT/libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt"
if [[ -z "${WAPP_ZIG_BIN:-}" ]];then
  printf 'PASS: native helper reproducible rebuild reserved for canonical pinned-toolchain validation\n';exit 0
fi
[[ "$WAPP_ZIG_BIN" == /*&&-f "$WAPP_ZIG_BIN"&&! -L "$WAPP_ZIG_BIN"&&-x "$WAPP_ZIG_BIN"&&"$($WAPP_ZIG_BIN version)" == 0.15.2 ]]||{ printf 'FAIL: exact regular Zig 0.15.2 executable required\n' >&2;exit 1; }
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-native-reproducible)";trap 'rm -rf "$TMP"' EXIT
env ZIG_GLOBAL_CACHE_DIR="$TMP/global" ZIG_LOCAL_CACHE_DIR="$TMP/local" WAPP_ZIG_BIN="$WAPP_ZIG_BIN" WAPP_NATIVE_HELPER_OUTPUT="$TMP/helper.b64.txt" /bin/bash "$ROOT/native/build-displaced-inventory-helper.sh" >/dev/null
cmp -s "$ARTIFACT" "$TMP/helper.b64.txt"||{ printf 'FAIL: encoded native artifact is not byte-reproducible\n' >&2;exit 1; }
/usr/bin/python3 - "$POLICY" "$TMP/helper.b64.txt" <<'PY'
import base64,hashlib,json,pathlib,sys
policy=json.loads(pathlib.Path(sys.argv[1]).read_text());encoded=pathlib.Path(sys.argv[2]).read_bytes();raw=base64.b64decode(encoded.strip(),validate=True)
assert hashlib.sha256(encoded).hexdigest()==policy['encoded_sha256'] and len(encoded)==policy['encoded_bytes']
assert hashlib.sha256(raw).hexdigest()==policy['binary_sha256'] and len(raw)==policy['binary_bytes']
PY
printf 'PASS: native helper source rebuild is byte-identical with exact Zig 0.15.2\n'
