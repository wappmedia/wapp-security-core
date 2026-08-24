#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
ZIG_BIN="${WAPP_ZIG_BIN:-zig}"
SOURCE="$ROOT/native/displaced-inventory-helper.c"
OUTPUT="${WAPP_NATIVE_HELPER_OUTPUT:-$ROOT/libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt}"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-native-helper-build)"
trap 'rm -rf "$TMP"' EXIT

[[ "$($ZIG_BIN version)" == 0.15.2 ]]||{
  printf 'native-helper-build: exact Zig 0.15.2 required\n' >&2
  exit 20
}

mkdir -p "$(dirname "$OUTPUT")"
"$ZIG_BIN" cc \
  -target x86_64-linux-musl \
  -static -O2 -s -std=gnu11 \
  -Wall -Wextra -Werror \
  -o "$TMP/helper" "$SOURCE"

[[ "$(LC_ALL=C file "$TMP/helper")" == *'ELF 64-bit LSB executable, x86-64'*&&
   "$(LC_ALL=C file "$TMP/helper")" == *'statically linked'* ]]||{
  printf 'native-helper-build: unexpected output identity\n' >&2
  exit 20
}
[[ "$(wc -c < "$TMP/helper"|tr -d ' ')" -le 1048576 ]]||{
  printf 'native-helper-build: output byte cap exceeded\n' >&2
  exit 20
}

chmod 755 "$TMP/helper"
/usr/bin/python3 - "$TMP/helper" "$TMP/helper.b64" <<'PY'
import base64, pathlib, sys
source, output = map(pathlib.Path, sys.argv[1:])
output.write_bytes(base64.b64encode(source.read_bytes()) + b"\n")
PY
chmod 644 "$TMP/helper.b64"
mv "$TMP/helper.b64" "$OUTPUT"
printf 'NATIVE_HELPER_BUILT: %s\n' "$OUTPUT"
printf 'ENCODED_SHA256: %s\n' "$(shasum -a 256 "$OUTPUT"|awk '{print $1}')"
printf 'BINARY_SHA256: %s\n' "$(shasum -a 256 "$TMP/helper"|awk '{print $1}')"
