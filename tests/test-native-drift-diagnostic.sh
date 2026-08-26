#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
TOOL="$ROOT/bin/wapp-signed-drift-diagnostic"
POLICY="$ROOT/config/native-filesystem-helper.json"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-signed-drift-test)"
cleanup(){ [[ -f "$TMP/loader.original" ]]&&cp "$TMP/loader.original" "$ROOT/lib/native-displaced-inventory-loader.sh"||true;rm -rf "$TMP"; }
trap cleanup EXIT
source "$ROOT/tests/helpers/recovery-keychain-fixture.sh"
wapp_test_setup_recovery_keychain "$TMP/keychain"
fail(){ printf 'FAIL: %s\n' "$1" >&2;exit 1; }
expect_fail(){ local name="$1";shift;if "$@" >"$TMP/$name.out" 2>"$TMP/$name.err";then fail "$name accepted";fi; }

operation="$(printf diagnostic-operation|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
root_path=/tmp/provider-neutral/site-root
root_hex="$(printf %s "$root_path"|/usr/bin/xxd -p -c 9999)"
path_hex="$(printf %s 'wp-content/cache/runtime.log'|/usr/bin/xxd -p -c 9999)"
helper_sha="$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binary_sha256"])' "$POLICY")"
pass1="$(printf pass1|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
pass2="$(printf pass2|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
file_sha="$(printf file-bytes-not-exported|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
runtime_identity="loader=/usr/bin/perl|loader_sha=$(printf perl|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')|loader_meta=0:0:755:1:2:3|helper_sha=$helper_sha|transport=sealed_memfd_execveat_v1"
runtime_hex="$(printf %s "$runtime_identity"|/usr/bin/xxd -p -c 9999)"
runtime="$(printf %s "$runtime_identity"|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
/bin/bash "$ROOT/bin/wapp-product-seal" "$TMP/product-seal.json" >/dev/null
{
  printf 'CAPTURE_NONCE\t%s\n' "$operation"
  printf 'DRIFT_DIAGNOSTIC\tSIGNED_DRIFT_DIAGNOSTIC_MODE_V1\t%s\t11\t22\t11\t22\t%s\t%s\t%s\t%s\t%s\t1\t0\tREAD_ONLY\tNON_AUTHORIZING\n' "$root_hex" "$pass1" "$pass2" "$helper_sha" "$runtime" "$runtime_hex"
  printf 'DRIFT\t%s\tCREATED\tfalse\ttrue\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\tREGULAR\t11\t33\t23\t0644\t1000\t1000\t1\t44\t55\t%s\t-\t0\n' "$path_hex" "$file_sha"
} >"$TMP/raw.tsv"

create(){ "$TOOL" create --raw "$TMP/raw.tsv" --root "$root_path" --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$1"; }
create "$TMP/one.json" >/dev/null
create "$TMP/two.json" >/dev/null
cmp -s "$TMP/one.json" "$TMP/two.json"||fail deterministic_artifact
cmp -s "$TMP/one.json.hmac" "$TMP/two.json.hmac"||fail deterministic_signature
"$TOOL" verify --artifact "$TMP/one.json"|grep -Fq VERIFIED_NON_AUTHORIZING
mkdir "$TMP/read-only-artifact";cp "$TMP/one.json" "$TMP/one.json.hmac" "$TMP/read-only-artifact/";chmod 500 "$TMP/read-only-artifact"
"$TOOL" verify --artifact "$TMP/read-only-artifact/one.json"|grep -Fq VERIFIED_NON_AUTHORIZING||fail read_only_artifact_parent
chmod 700 "$TMP/read-only-artifact"
/usr/bin/python3 - "$TMP/one.json" "$operation" "$helper_sha" "$path_hex" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]))
assert value['inventory_operation_id']==sys.argv[2]
assert value['helper_sha256']==sys.argv[3]
assert value['deltas'][0]['normalized_path_hex']==sys.argv[4]
assert value['deltas'][0]['pass2']['uid']==1000 and value['deltas'][0]['pass2']['nlink']==1
assert value['decision_eligible'] is False and value['descriptor_bound'] is True
assert value['authority']=={'apply':False,'clean':False,'closure':False,'mutation':False,'prepare':False,'ready':False}
assert 'file-bytes-not-exported' not in open(sys.argv[1],encoding='utf-8').read()
PY

cp "$TMP/one.json" "$TMP/tampered.json";cp "$TMP/one.json.hmac" "$TMP/tampered.json.hmac"
/usr/bin/python3 - "$TMP/tampered.json" <<'PY'
import json,sys
p=sys.argv[1];v=json.load(open(p));v['authority']['clean']=True;open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail modified_delta "$TOOL" verify --artifact "$TMP/tampered.json"

cp "$TMP/raw.tsv" "$TMP/raw.original"
printf '\n' >>"$TMP/raw.tsv"
expect_fail raw_substitution "$TOOL" verify --artifact "$TMP/one.json"
mv "$TMP/raw.original" "$TMP/raw.tsv"

make_bad(){ /usr/bin/python3 - "$TMP/raw.tsv" "$1" "$2" <<'PY'
import pathlib,sys
source,out,kind=pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3]
text=source.read_text()
if kind=='helper': text=text.replace(text.splitlines()[1].split('\t')[9],'f'*64,1)
elif kind=='snapshot': text=text.replace(text.splitlines()[1].split('\t')[7],'-',1)
elif kind=='path': text=text.replace(text.splitlines()[2].split('\t')[1],'2e2e2f657363617065',1)
elif kind=='runtime': text=text.replace(text.splitlines()[1].split('\t')[10],'e'*64,1)
elif kind=='invented': text=text.replace('\t1\t0\tREAD_ONLY','\t2\t0\tREAD_ONLY',1)
out.write_text(text)
PY
}
for kind in helper snapshot path runtime invented;do
  make_bad "$TMP/$kind.tsv" "$kind"
  expect_fail "$kind" "$TOOL" create --raw "$TMP/$kind.tsv" --root "$root_path" --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/$kind.json"
done
expect_fail wrong_root "$TOOL" create --raw "$TMP/raw.tsv" --root /tmp/provider-neutral/other --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/wrong-root.json"
expect_fail wrong_operation "$TOOL" create --raw "$TMP/raw.tsv" --root "$root_path" --operation-id "$(printf wrong|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/wrong-operation.json"
expect_fail invalid_time "$TOOL" create --raw "$TMP/raw.tsv" --root "$root_path" --operation-id "$operation" --observed-at now --product-seal "$TMP/product-seal.json" --output "$TMP/invalid-time.json"

# Issue-only mismatches remain explanatory; SUMMARY-only mismatches cannot be signed.
{
  printf 'CAPTURE_NONCE\t%s\n' "$operation"
  printf 'DRIFT_DIAGNOSTIC\tSIGNED_DRIFT_DIAGNOSTIC_MODE_V1\t%s\t11\t22\t11\t22\t%s\t%s\t%s\t%s\t%s\t0\t1\tREAD_ONLY\tNON_AUTHORIZING\n' "$root_hex" "$pass1" "$pass2" "$helper_sha" "$runtime" "$runtime_hex"
  printf 'DRIFT_ISSUE\t%s\tFILE_IDENTITY_RACE\t%s\ttrue\tfalse\n' "$path_hex" "$file_sha"
} >"$TMP/issue-only.tsv"
"$TOOL" create --raw "$TMP/issue-only.tsv" --root "$root_path" --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/issue-only.json" >/dev/null
"$TOOL" verify --artifact "$TMP/issue-only.json" >/dev/null
sed '/^DRIFT_ISSUE/d;s/\t0\t1\tREAD_ONLY/\t0\t0\tREAD_ONLY/' "$TMP/issue-only.tsv" >"$TMP/summary-only.tsv"
expect_fail summary_only "$TOOL" create --raw "$TMP/summary-only.tsv" --root "$root_path" --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/summary-only.json"

# A declared over-cap diagnostic fails before any artifact can be signed.
sed 's/\t1\t0\tREAD_ONLY/\t200001\t0\tREAD_ONLY/' "$TMP/raw.tsv" >"$TMP/over-cap.tsv"
expect_fail over_cap "$TOOL" create --raw "$TMP/over-cap.tsv" --root "$root_path" --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/over-cap.json"

# A previously signed Product Seal cannot bless dirty/substituted runtime code.
cp "$ROOT/lib/native-displaced-inventory-loader.sh" "$TMP/loader.original"
printf '\n# substituted\n' >>"$ROOT/lib/native-displaced-inventory-loader.sh"
expect_fail loader_drift "$TOOL" create --raw "$TMP/raw.tsv" --root "$root_path" --operation-id "$operation" --observed-at 2026-08-24T12:00:00Z --product-seal "$TMP/product-seal.json" --output "$TMP/loader-drift.json"
cp "$TMP/loader.original" "$ROOT/lib/native-displaced-inventory-loader.sh"

printf 'PASS: signed drift diagnostic is deterministic, bounded, derived, and non-authorizing\n'
