#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
SOURCE="$ROOT/native/exact-file-quarantine-ephemeral-memfd-launcher.c"
OUTPUT="${WAPP_NATIVE_EXACT_FILE_LAUNCHER_OUTPUT:-$ROOT/libexec/wapp-native-exact-file-quarantine-ephemeral-memfd-launcher-linux-x86_64.b64.txt}"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-native-exact-file-launcher-build)"
trap 'rm -rf "$TMP"' EXIT
ZIG_BIN="${WAPP_ZIG_BIN:-}"
[[ "$ZIG_BIN" == /*&&-f "$ZIG_BIN"&&! -L "$ZIG_BIN"&&-x "$ZIG_BIN"&&"$($ZIG_BIN version)" == 0.15.2 ]]||{ printf 'native-exact-file-launcher-build: exact Zig 0.15.2 required\n' >&2;exit 20;}
env ZIG_GLOBAL_CACHE_DIR="$TMP/global" ZIG_LOCAL_CACHE_DIR="$TMP/local" "$ZIG_BIN" cc -target x86_64-linux-musl -O2 -s -std=gnu11 -Wall -Wextra -Werror "$SOURCE" -o "$TMP/launcher"
identity="$(LC_ALL=C file "$TMP/launcher")"
[[ "$identity" == *'ELF 64-bit LSB executable, x86-64'*&&"$identity" == *'statically linked'* ]]||{ printf 'native-exact-file-launcher-build: unexpected output identity\n' >&2;exit 20;}
[[ "$(wc -c <"$TMP/launcher"|tr -d ' ')" -le 262144 ]]||{ printf 'native-exact-file-launcher-build: output byte cap exceeded\n' >&2;exit 20;}
/usr/bin/openssl base64 -A -in "$TMP/launcher" >"$TMP/launcher.b64"
printf '\n' >>"$TMP/launcher.b64"
mv "$TMP/launcher.b64" "$OUTPUT"
printf 'NATIVE_EXACT_FILE_LAUNCHER_BUILD_PASS\n'
