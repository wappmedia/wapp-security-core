#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)";TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-exact-file-rebuild)";trap 'rm -rf "$TMP"' EXIT
if [[ -z "${WAPP_ZIG_BIN:-}" ]];then printf 'PASS: native exact-file reproducible rebuild reserved for canonical pinned-toolchain validation\n';exit 0;fi
env WAPP_NATIVE_EXACT_FILE_HELPER_OUTPUT="$TMP/helper.b64.txt" /bin/bash "$ROOT/native/build-exact-file-quarantine-helper.sh" >/dev/null
cmp "$TMP/helper.b64.txt" "$ROOT/libexec/wapp-native-exact-file-quarantine-linux-x86_64.b64.txt"
env WAPP_NATIVE_EXACT_FILE_LAUNCHER_OUTPUT="$TMP/launcher.b64.txt" /bin/bash "$ROOT/native/build-exact-file-quarantine-ephemeral-memfd-launcher.sh" >/dev/null
cmp "$TMP/launcher.b64.txt" "$ROOT/libexec/wapp-native-exact-file-quarantine-ephemeral-memfd-launcher-linux-x86_64.b64.txt"
printf 'PASS: native exact-file helper and launcher rebuild byte-identically\n'
