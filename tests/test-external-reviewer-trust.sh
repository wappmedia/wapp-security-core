#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODEL="$ROOT/lib/emergency-operator-v1.py"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t reviewer-trust)"
cleanup(){ rm -f "$TMP/trust.json" "$TMP/trust-link.json" "$TMP/probe.py" "$TMP/private.pem" "$TMP/public.pem" "$TMP/external.json" "$TMP/substitute.json"; rmdir "$TMP" 2>/dev/null || true; }
trap cleanup EXIT
fail(){ printf 'FAIL: %s\n' "$1" >&2; exit 1; }
cat > "$TMP/probe.py" <<'PY'
import importlib.util,sys
spec=importlib.util.spec_from_file_location("emergency_operator",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
try: module.reviewer_trust_anchors()
except module.ContractError as error: print(str(error),file=sys.stderr);raise SystemExit(20)
PY
probe(){ /usr/bin/python3 -I "$TMP/probe.py" "$MODEL"; }
external_probe(){
  WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_FILE="$1" \
  WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_SHA256="$2" \
  WAPP_EMERGENCY_REVIEWER_ID="$3" \
  WAPP_EMERGENCY_REVIEWER_KEY_ID="$4" probe
}
probe || fail built-in
cp "$ROOT/config/reviewer-trust-anchors.json" "$TMP/trust.json"
sha="$(/usr/bin/shasum -a 256 "$TMP/trust.json" | /usr/bin/awk '{print $1}')"
if external_probe "$TMP/trust.json" "$sha" reviewer key-v1 >/dev/null 2>&1; then fail wrong-owner; fi
ln -s "$TMP/trust.json" "$TMP/trust-link.json"
if external_probe "$TMP/trust-link.json" "$sha" reviewer key-v1 >/dev/null 2>&1; then fail symlink; fi
if WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_FILE="$TMP/trust.json" probe >/dev/null 2>&1; then fail incomplete-config; fi
if WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_FILE='' probe >/dev/null 2>&1; then fail empty-present-single; fi
if WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_FILE='' \
   WAPP_EMERGENCY_REVIEWER_TRUST_ANCHORS_SHA256='' \
   WAPP_EMERGENCY_REVIEWER_ID='' \
   WAPP_EMERGENCY_REVIEWER_KEY_ID='' probe >/dev/null 2>&1; then fail empty-present-all; fi

# GitHub-hosted Ubuntu and macOS runners provide passwordless sudo. Local runs
# skip the root-owned positive matrix without prompting; private activation
# repeats it with explicit administrator authorization.
if /usr/bin/sudo -n true >/dev/null 2>&1; then
  if [[ "$(uname -s)" == Darwin ]]; then
    trusted_parent=/private/etc; trusted_group=wheel; chown_bin=/usr/sbin/chown
  else
    trusted_parent=/etc; trusted_group=root; chown_bin=/usr/bin/chown
  fi
  fixture="$trusted_parent/wapp-security-core-reviewer-test-$$"
  anchor="$fixture/trust.json"
  link="$fixture/trust-link.json"
  private="$fixture/private-key.pem"
  cleanup_root(){
    /usr/bin/sudo /bin/rm -f "$anchor" "$link" "$private" 2>/dev/null || true
    /usr/bin/sudo /bin/rmdir "$fixture" 2>/dev/null || true
  }
  trap 'cleanup_root; cleanup' EXIT
  /usr/bin/sudo /bin/mkdir -p "$fixture"
  /usr/bin/sudo /bin/chmod 755 "$fixture"
  /usr/bin/openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/private.pem" >/dev/null 2>&1
  /usr/bin/openssl pkey -in "$TMP/private.pem" -pubout -out "$TMP/public.pem" >/dev/null 2>&1
  /usr/bin/python3 - "$TMP/public.pem" "$TMP/external.json" <<'PY'
import json,sys
public,out=sys.argv[1:]
value={'tool':'wapp-security-reviewer-trust-anchors','schema':1,'reviewers':[{'reviewer_id':'human-reviewer-v1','key_id':'p256-v1','algorithm':'ECDSA_P256_SHA256','public_key_pem':open(public).read()}]}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  /usr/bin/sudo /usr/bin/install -o root -g "$trusted_group" -m 644 "$TMP/external.json" "$anchor"
  root_sha="$(/usr/bin/shasum -a 256 "$anchor" | /usr/bin/awk '{print $1}')"
  /usr/bin/sudo /usr/bin/install -o root -g "$trusted_group" -m 600 "$TMP/private.pem" "$private"
  external_probe "$anchor" "$root_sha" human-reviewer-v1 p256-v1 || fail valid-external
  /usr/bin/sudo /bin/ln -s "$anchor" "$link"
  if external_probe "$link" "$root_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail root-symlink; fi
  /usr/bin/sudo /bin/chmod 666 "$anchor"
  if external_probe "$anchor" "$root_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail writable-file; fi
  /usr/bin/sudo /bin/chmod 644 "$anchor"
  /usr/bin/sudo "$chown_bin" "$(/usr/bin/id -u):$(/usr/bin/id -g)" "$anchor"
  if external_probe "$anchor" "$root_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail wrong-owner; fi
  /usr/bin/sudo /usr/bin/install -o root -g "$trusted_group" -m 644 "$TMP/external.json" "$anchor"
  /usr/bin/sudo /bin/chmod 777 "$fixture"
  if external_probe "$anchor" "$root_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail writable-parent; fi
  /usr/bin/sudo /bin/chmod 755 "$fixture"
  bad_sha="${root_sha%?}0"; [[ "$bad_sha" != "$root_sha" ]] || bad_sha="${root_sha%?}1"
  if external_probe "$anchor" "$bad_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail hash-mismatch; fi
  if external_probe "$anchor" "$root_sha" wrong-reviewer p256-v1 >/dev/null 2>&1; then fail reviewer-mismatch; fi
  /usr/bin/python3 - "$TMP/public.pem" "$TMP/substitute.json" <<'PY'
import json,sys
public,out=sys.argv[1:]
value={'tool':'wapp-security-reviewer-trust-anchors','schema':1,'reviewers':[{'reviewer_id':'substituted','key_id':'p256-v2','algorithm':'ECDSA_P256_SHA256','public_key_pem':open(public).read()}]}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  /usr/bin/sudo /usr/bin/install -o root -g "$trusted_group" -m 644 "$TMP/substitute.json" "$anchor"
  if external_probe "$anchor" "$root_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail anchor-substitution; fi
  /usr/bin/sudo /bin/rm -f "$anchor"
  if external_probe "$anchor" "$root_sha" human-reviewer-v1 p256-v1 >/dev/null 2>&1; then fail missing-anchor; fi
  ! rg -q 'WAPP_EMERGENCY_REVIEWER_PRIVATE|private.pem|private-key' "$ROOT/lib/emergency-operator-v1.py" || fail private-key-interface
  cleanup_root
fi
printf 'PASS: external reviewer trust is explicit, root-owned, hash-pinned and public-key-only\n'
