#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t fmfw-policy)"
trap 'rm -rf "$TMP"' EXIT
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }
write(){ printf '%s\n' "$2" > "$TMP/$1"; }
field(){ python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
run(){ /bin/bash "$ROOT/bin/wapp-plugin-policy" "$TMP/$1"; }

exact='{"activation_status":"ACTIVE","author":"Your Name","inventory_sha256":"08f697068f2b2b3758e8a9e8088d88c3e60e6f1c643dd6d9bab84dfbd0166e6c","provenance":"UNKNOWN","schema":1,"slug":"file-manager-for-work","tool":"wapp-plugin-inventory-record","version":"4.2.5"}'
write exact.json "$exact"
out="$(run exact.json)" || fail exact
[[ "$(printf '%s' "$out" | field disposition)" == REMOVE_REQUIRED ]] || fail disposition
[[ "$(printf '%s' "$out" | field flagged)" == True ]] || fail flagged
[[ "$(printf '%s' "$out" | field malware_classification)" == NOT_ESTABLISHED ]] || fail malware
for key in mutation_authority prepare_authority apply_authority closure_authority; do
  [[ "$(printf '%s' "$out" | field "$key")" == False ]] || fail "$key"
done

write inactive.json "${exact/ACTIVE/INACTIVE}"
[[ "$(run inactive.json | field disposition)" == REMOVE_REQUIRED ]] || fail inactive
write drift.json "${exact/08f697068f2b2b3758e8a9e8088d88c3e60e6f1c643dd6d9bab84dfbd0166e6c/18f697068f2b2b3758e8a9e8088d88c3e60e6f1c643dd6d9bab84dfbd0166e6c}"
[[ "$(run drift.json | field disposition)" == PROVENANCE_REVIEW_REQUIRED ]] || fail fingerprint-drift
write provenance.json "${exact/\"UNKNOWN\"/\"KNOWN\"}"
[[ "$(run provenance.json | field disposition)" == PROVENANCE_REVIEW_REQUIRED ]] || fail provenance-drift
write other.json "${exact/file-manager-for-work/synthetic-plugin}"
[[ "$(run other.json | field disposition)" == NOT_APPLICABLE ]] || fail unrelated
write malformed.json '{"slug":"file-manager-for-work"}'
if run malformed.json >/dev/null 2>&1; then fail malformed; fi
ln -s exact.json "$TMP/link.json"
if /bin/bash "$ROOT/bin/wapp-plugin-policy" "$TMP/link.json" >/dev/null 2>&1; then fail symlink; fi
printf 'PASS: file-manager-for-work exact policy remains flagged and non-authorizing\n'
