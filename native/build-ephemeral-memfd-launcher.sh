#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
ZIG_BIN="${WAPP_ZIG_BIN:-}"
SOURCE="$ROOT/native/ephemeral-memfd-launcher.c"
OUTPUT="${WAPP_EPHEMERAL_LAUNCHER_OUTPUT:-$ROOT/libexec/wapp-native-ephemeral-memfd-launcher-linux-x86_64.b64.txt}"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-ephemeral-launcher-build)"
trap 'rm -rf "$TMP"' EXIT
[[ "$ZIG_BIN" == /*&&-f "$ZIG_BIN"&&! -L "$ZIG_BIN"&&-x "$ZIG_BIN"&&"$($ZIG_BIN version)" == 0.15.2 ]]||{ printf 'ephemeral-launcher-build: explicit exact regular Zig 0.15.2 required\n' >&2;exit 20;}
"$ZIG_BIN" cc -target x86_64-linux-musl -static -O2 -s -std=gnu11 -Wall -Wextra -Werror -o "$TMP/launcher" "$SOURCE"
[[ "$(LC_ALL=C file "$TMP/launcher")" == *'ELF 64-bit LSB executable, x86-64'*&&"$(LC_ALL=C file "$TMP/launcher")" == *'statically linked'* ]]||{ printf 'ephemeral-launcher-build: unexpected output identity\n' >&2;exit 20;}
[[ "$(wc -c < "$TMP/launcher"|tr -d ' ')" -le 262144 ]]||{ printf 'ephemeral-launcher-build: output byte cap exceeded\n' >&2;exit 20;}
/usr/bin/python3 - "$TMP/launcher" "$OUTPUT.tmp" <<'PY'
import base64,pathlib,sys
source,output=map(pathlib.Path,sys.argv[1:]);output.write_bytes(base64.b64encode(source.read_bytes())+b'\n')
PY
chmod 644 "$OUTPUT.tmp";mv "$OUTPUT.tmp" "$OUTPUT"
printf 'EPHEMERAL_LAUNCHER_BUILT: %s\n' "$OUTPUT"
printf 'ENCODED_SHA256: %s\n' "$(shasum -a 256 "$OUTPUT"|awk '{print $1}')"
printf 'BINARY_SHA256: %s\n' "$(shasum -a 256 "$TMP/launcher"|awk '{print $1}')"
printf 'BINARY_BYTES: %s\n' "$(wc -c < "$TMP/launcher"|tr -d ' ')"
