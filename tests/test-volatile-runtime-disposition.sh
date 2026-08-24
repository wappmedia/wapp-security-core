#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
TOOL="$ROOT/bin/wapp-volatile-runtime-disposition"
DIAG="$ROOT/bin/wapp-signed-drift-diagnostic"
POLICY="$ROOT/config/native-filesystem-helper.json"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-volatile-runtime-test)"
trap 'rm -rf "$TMP"' EXIT
source "$ROOT/tests/helpers/recovery-keychain-fixture.sh"
wapp_test_setup_recovery_keychain "$TMP/keychain"
source "$ROOT/lib/recovery-integrity.sh"
fail(){ printf 'FAIL: %s\n' "$1" >&2;exit 1; }
expect_fail(){ local name="$1";shift;if "$@" >"$TMP/$name.out" 2>"$TMP/$name.err";then fail "$name accepted";fi; }
sha_text(){ printf %s "$1"|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}'; }

operation1="$(sha_text operation-one)";operation2="$(sha_text operation-two)"
read -r OBS1 OBS2 PROVENANCE_TIME ISSUED FUTURE_OBS1 FUTURE_OBS2 FUTURE_PROVENANCE FUTURE_ISSUED <<<"$(/usr/bin/python3 - <<'PY'
import datetime as d
n=d.datetime.now(d.timezone.utc).replace(microsecond=0)
f=lambda x:x.strftime('%Y-%m-%dT%H:%M:%SZ')
print(*(f(n+d.timedelta(seconds=s)) for s in (-180,-120,-60,0,-30,30,45,60)))
PY
)"
root_path=/tmp/provider-neutral/site-root
root_hex="$(printf %s "$root_path"|/usr/bin/xxd -p -c 9999)"
log_path='wp-content/uploads/wc-logs/runtime-2026-08-24.log';log_hex="$(printf %s "$log_path"|/usr/bin/xxd -p -c 9999)"
waf_path='wp-content/wflogs/config-livewaf.php';waf_hex="$(printf %s "$waf_path"|/usr/bin/xxd -p -c 9999)"
uploads_root_hex="$(printf %s 'wp-content/uploads/wc-logs'|/usr/bin/xxd -p -c 9999)"
waf_root_hex="$(printf %s 'wp-content/wflogs'|/usr/bin/xxd -p -c 9999)"
helper_sha="$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binary_sha256"])' "$POLICY")"
runtime_identity="loader=/usr/bin/perl|loader_sha=$(sha_text perl)|loader_meta=0:0:755:1:2:3|helper_sha=$helper_sha|transport=sealed_memfd_execveat_v1"
runtime_hex="$(printf %s "$runtime_identity"|/usr/bin/xxd -p -c 9999)";runtime_sha="$(sha_text "$runtime_identity")"
/bin/bash "$ROOT/bin/wapp-product-seal" "$TMP/product-seal.json" >/dev/null

make_raw(){
  local output="$1" operation="$2" seed="$3" log_before="$4" log_after="$5" ctime_before="$6" ctime_after="$7" log_mode="${8:-0644}" waf_mode="${9:-0644}" log_before_state="${10:-log-zero}" log_after_state="${11:-log-one}" log_mtime_before="${12:-100}" log_mtime_after="${13:-200}"
  local pass1 pass2 log_sha1 log_sha2 waf_sha
  pass1="$(sha_text "pass1-$seed")";pass2="$(sha_text "pass2-$seed")";log_sha1="$(sha_text "$log_before_state")";log_sha2="$(sha_text "$log_after_state")";waf_sha="$(sha_text waf-stable)"
  {
    printf 'CAPTURE_NONCE\t%s\n' "$operation"
    printf 'DRIFT_DIAGNOSTIC\tSIGNED_DRIFT_DIAGNOSTIC_MODE_V1\t%s\t11\t22\t11\t22\t%s\t%s\t%s\t%s\t%s\t2\t0\tREAD_ONLY\tNON_AUTHORIZING\n' "$root_hex" "$pass1" "$pass2" "$helper_sha" "$runtime_sha" "$runtime_hex"
    printf 'DRIFT\t%s\tMODIFIED\ttrue\ttrue\tREGULAR\t11\t101\t%s\t%s\t1000\t1000\t1\t%s\t%s\t%s\t-\t1\tREGULAR\t11\t101\t%s\t%s\t1000\t1000\t1\t%s\t%s\t%s\t-\t1\n' "$log_hex" "$log_before" "$log_mode" "$log_mtime_before" "$ctime_before" "$log_sha1" "$log_after" "$log_mode" "$log_mtime_after" "$ctime_after" "$log_sha2"
    printf 'DRIFT\t%s\tMODIFIED\ttrue\ttrue\tREGULAR\t11\t202\t77\t%s\t1000\t1000\t1\t300\t%s\t%s\t-\t0\tREGULAR\t11\t202\t77\t%s\t1000\t1000\t1\t300\t%s\t%s\t-\t0\n' "$waf_hex" "$waf_mode" "$ctime_before" "$waf_sha" "$waf_mode" "$ctime_after" "$waf_sha"
  } >"$output"
}

make_raw "$TMP/raw1.tsv" "$operation1" one 10 20 100 101 0644 0644 log-zero log-one
make_raw "$TMP/raw2.tsv" "$operation2" two 20 30 101 201 0644 0644 log-one log-two 200 300
"$DIAG" create --raw "$TMP/raw1.tsv" --root "$root_path" --operation-id "$operation1" --observed-at "$OBS1" --product-seal "$TMP/product-seal.json" --output "$TMP/diag1.json" >/dev/null
"$DIAG" create --raw "$TMP/raw2.tsv" --root "$root_path" --operation-id "$operation2" --observed-at "$OBS2" --product-seal "$TMP/product-seal.json" --output "$TMP/diag2.json" >/dev/null

make_provenance(){
  local output="$1" variant="${2:-valid}" generated="${3:-$PROVENANCE_TIME}"
  /usr/bin/python3 - "$output" "$root_hex" "$log_hex" "$waf_hex" "$uploads_root_hex" "$waf_root_hex" "$variant" "$generated" <<'PY'
import hashlib,json,pathlib,sys
out,root,log,waf,logroot,wafroot,variant,generated=sys.argv[1:]
h=lambda s:hashlib.sha256(s.encode()).hexdigest()
def row(path,root,slug,version,kind,role):
 return {'normalized_path_hex':path,'component':{'component_type':kind,'slug':slug,'component_version':version,'component_identity_sha256':h(slug+version),'component_evidence_sha256':h('evidence-'+slug),'component_root_path_hex':root},'runtime_role':role,'ioc_correlation':{'evidence_sha256':h('ioc-'+slug),'matches':0},'incident_persistence':{'evidence_sha256':h('persistence-'+slug),'related':False}}
rows=[row(log,logroot,'woocommerce','10.0.0','WORDPRESS_PLUGIN_RUNTIME','APPEND_ONLY_LOG'),row(waf,wafroot,'wordfence','8.0.0','WORDPRESS_PLUGIN_RUNTIME','GENERATED_RUNTIME_STATE')]
if variant=='ioc':rows[0]['ioc_correlation']['matches']=1
elif variant=='persistence':rows[0]['incident_persistence']['related']=True
elif variant=='unknown':rows[0]['component']['component_type']='UNKNOWN_RUNTIME'
elif variant=='extra':rows.append(row('77702d636f6e74656e742f63616368652f757365722e6c6f67','77702d636f6e74656e742f6361636865','user-added','1','WORDPRESS_PLUGIN_RUNTIME','APPEND_ONLY_LOG'))
value={'tool':'wapp-security-runtime-provenance-evidence','schema':1,'generated_at':generated,'root_path_hex':root,'target_product_identity_sha256':h('target-product'),'paths':rows}
pathlib.Path(out).write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  recovery_sign_file "$output" "$output.hmac" >/dev/null
}

make_provenance "$TMP/provenance.json"
"$TOOL" create --diagnostic-one "$TMP/diag1.json" --diagnostic-two "$TMP/diag2.json" --runtime-provenance "$TMP/provenance.json" --issued-at "$ISSUED" --output "$TMP/disposition.json" >/dev/null
"$TOOL" verify --artifact "$TMP/disposition.json"|grep -Fq VERIFIED_NON_AUTHORIZING
policy_value="$("$TOOL" policy-token --artifact "$TMP/disposition.json")"
[[ "$policy_value" == "A:$log_hex,C:$waf_hex" ]]||fail policy_value
/usr/bin/python3 - "$TMP/disposition.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['contract']=='BOUNDED_VOLATILE_RUNTIME_DISPOSITION_V1'
assert v['disposition']=='VOLATILE_RUNTIME_VERIFIED' and v['paths_remain_visible'] is True and v['filesystem_coverage_weakened'] is False
assert v['decision_eligible'] is False and set(v['authority'].values())=={False}
assert [x['behavior'] for x in v['paths']]==['APPEND_PREFIX_REQUIRED_UPLOAD_LOG_GROWTH','CTIME_ONLY']
PY

for variant in ioc persistence unknown extra;do make_provenance "$TMP/$variant.json" "$variant";expect_fail "$variant" "$TOOL" create --diagnostic-one "$TMP/diag1.json" --diagnostic-two "$TMP/diag2.json" --runtime-provenance "$TMP/$variant.json" --issued-at "$ISSUED" --output "$TMP/$variant-disposition.json";done

# Content/hash change in a non-log runtime file and an executable log both fail.
cp "$TMP/raw2.tsv" "$TMP/hash-change.tsv";sed -i.bak "s/77\\t0644/78\\t0644/2" "$TMP/hash-change.tsv";rm -f "$TMP/hash-change.tsv.bak"
"$DIAG" create --raw "$TMP/hash-change.tsv" --root "$root_path" --operation-id "$operation2" --observed-at "$OBS2" --product-seal "$TMP/product-seal.json" --output "$TMP/hash-change.json" >/dev/null
expect_fail hash_change "$TOOL" create --diagnostic-one "$TMP/diag1.json" --diagnostic-two "$TMP/hash-change.json" --runtime-provenance "$TMP/provenance.json" --issued-at "$ISSUED" --output "$TMP/hash-change-disposition.json"
make_raw "$TMP/executable.tsv" "$operation2" exec 20 30 101 201 0755 0755 log-one log-two 200 300
"$DIAG" create --raw "$TMP/executable.tsv" --root "$root_path" --operation-id "$operation2" --observed-at "$OBS2" --product-seal "$TMP/product-seal.json" --output "$TMP/executable.json" >/dev/null
expect_fail executable_runtime "$TOOL" create --diagnostic-one "$TMP/diag1.json" --diagnostic-two "$TMP/executable.json" --runtime-provenance "$TMP/provenance.json" --issued-at "$ISSUED" --output "$TMP/executable-disposition.json"

# Continuity is exact between observation one pass-2 and observation two pass-1.
make_raw "$TMP/boundary-drift.tsv" "$operation2" boundary 20 30 101 201 0644 0644 wrong-boundary log-two 200 300
"$DIAG" create --raw "$TMP/boundary-drift.tsv" --root "$root_path" --operation-id "$operation2" --observed-at "$OBS2" --product-seal "$TMP/product-seal.json" --output "$TMP/boundary-drift.json" >/dev/null
expect_fail boundary_drift "$TOOL" create --diagnostic-one "$TMP/diag1.json" --diagnostic-two "$TMP/boundary-drift.json" --runtime-provenance "$TMP/provenance.json" --issued-at "$ISSUED" --output "$TMP/boundary-disposition.json"

# A valid but future-issued disposition can be derived, but cannot be consumed.
make_raw "$TMP/future1.tsv" "$(sha_text future-one)" future1 10 20 100 101 0644 0644 log-zero log-one
make_raw "$TMP/future2.tsv" "$(sha_text future-two)" future2 20 30 101 201 0644 0644 log-one log-two 200 300
"$DIAG" create --raw "$TMP/future1.tsv" --root "$root_path" --operation-id "$(sha_text future-one)" --observed-at "$FUTURE_OBS1" --product-seal "$TMP/product-seal.json" --output "$TMP/future1.json" >/dev/null
"$DIAG" create --raw "$TMP/future2.tsv" --root "$root_path" --operation-id "$(sha_text future-two)" --observed-at "$FUTURE_OBS2" --product-seal "$TMP/product-seal.json" --output "$TMP/future2.json" >/dev/null
make_provenance "$TMP/future-provenance.json" valid "$FUTURE_PROVENANCE"
"$TOOL" create --diagnostic-one "$TMP/future1.json" --diagnostic-two "$TMP/future2.json" --runtime-provenance "$TMP/future-provenance.json" --issued-at "$FUTURE_ISSUED" --output "$TMP/future-disposition.json" >/dev/null
expect_fail future_disposition "$TOOL" policy-token --artifact "$TMP/future-disposition.json"

# The helper output is only an unverified candidate. A separately signed
# binder consumes it together with the exact current signed disposition.
abs_log_hex="$(printf %s "$root_path/$log_path"|/usr/bin/xxd -p -c 9999)";abs_waf_hex="$(printf %s "$root_path/$waf_path"|/usr/bin/xxd -p -c 9999)"
other_hex="$(printf %s index.php|/usr/bin/xxd -p -c 9999)";abs_other_hex="$(printf %s "$root_path/index.php"|/usr/bin/xxd -p -c 9999)";other_sha="$(sha_text other-current)"
token_sha="$(sha_text "$policy_value")";log_current_sha="$(sha_text log-current)";waf_current_sha="$(sha_text waf-stable)"
{
  printf 'CAPTURE_NONCE\t%s\n' "$(sha_text inventory-operation)"
  printf 'ENTRY\t\t%s\tDIRECTORY\t4096\t0755\t1000\t1000\t1\t1\t11\t22\t1\t-\t-\t0\n' "$root_hex"
  printf 'ENTRY\t%s\t%s\tREGULAR\t5\t0644\t1000\t1000\t300\t301\t11\t303\t1\t-\t%s\t0\n' "$other_hex" "$abs_other_hex" "$other_sha"
  printf 'ENTRY\t%s\t%s\tREGULAR\t30\t0644\t1000\t1000\t300\t301\t11\t101\t1\t-\t%s\t1\n' "$log_hex" "$abs_log_hex" "$log_current_sha"
  printf 'ENTRY\t%s\t%s\tREGULAR\t77\t0644\t1000\t1000\t300\t301\t11\t202\t1\t-\t%s\t0\n' "$waf_hex" "$abs_waf_hex" "$waf_current_sha"
  printf 'ROOT\t%s\t%s\t11\t22\t0755\t1000\t1000\t1\t1\t1\n' "$root_hex" "$root_hex"
  printf 'RUNTIME\tPRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1\t6d656d66643a776170702d6e61746976652d646973706c616365642d696e76656e746f72792d6c696e75782d7838365f36342d7631\t%s\t%s\n' "$helper_sha" "$runtime_sha"
  printf 'SUMMARY\t4\t1\t3\t3\t112\t1\t0\t0\ttrue\t%s\t200000\t50000\t100000\t1073741824\t8589934592\t64\t300\t4096\t125829120\n' "$(sha_text inventory-summary)"
  printf 'VOLATILE_RUNTIME_CANDIDATE\tBOUNDED_VOLATILE_RUNTIME_CANDIDATE_V1\t%s\t2\tVISIBLE\tUNVERIFIED_NON_AUTHORIZING\n' "$token_sha"
  printf 'VOLATILE_RUNTIME_CANDIDATE_PATH\t%s\tAPPEND_PREFIX_VERIFIED_UPLOAD_LOG_GROWTH\tOBSERVED_DRIFT\n' "$log_hex"
  printf 'VOLATILE_RUNTIME_CANDIDATE_PATH\t%s\tCTIME_ONLY\tOBSERVED_DRIFT\n' "$waf_hex"
} >"$TMP/candidate.tsv"
/usr/bin/python3 - "$TMP/candidate.tsv" <<'PY'
import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1]);lines=p.read_text().splitlines();entries=sorted(x for x in lines if x.startswith('ENTRY\t'))
digest=hashlib.sha256(''.join(x+'\n' for x in entries).encode('ascii')).hexdigest()
lines=[x if not x.startswith('SUMMARY\t') else x.split('\t',10)[0]+'\t'+'\t'.join(x.split('\t')[1:10])+'\t'+digest+'\t'+'\t'.join(x.split('\t')[11:]) for x in lines]
p.write_text('\n'.join(lines)+'\n')
PY
"$TOOL" inventory-create --raw-candidate "$TMP/candidate.tsv" --disposition "$TMP/disposition.json" --output "$TMP/inventory.json" >/dev/null
"$TOOL" inventory-verify --artifact "$TMP/inventory.json"|grep -Fq VERIFIED_NON_AUTHORIZING
/usr/bin/python3 - "$TMP/inventory.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['contract']=='BOUNDED_VOLATILE_RUNTIME_INVENTORY_V1'
assert v['paths_remain_visible'] is True and v['filesystem_coverage_weakened'] is False and v['decision_eligible'] is False
assert set(v['authority'].values())=={False} and len(v['paths'])==2
PY
cp "$TMP/candidate.tsv" "$TMP/candidate-extra.tsv";printf 'VOLATILE_RUNTIME_CANDIDATE_PATH\t757365722d6164646564\tCTIME_ONLY\tOBSERVED_STABLE\n' >>"$TMP/candidate-extra.tsv"
expect_fail candidate_scope "$TOOL" inventory-create --raw-candidate "$TMP/candidate-extra.tsv" --disposition "$TMP/disposition.json" --output "$TMP/candidate-extra.json"
cp "$TMP/candidate.tsv" "$TMP/candidate-executable.tsv";sed -i.bak "s/${waf_hex}\\t${abs_waf_hex}\\tREGULAR\\t77\\t0644/${waf_hex}\\t${abs_waf_hex}\\tREGULAR\\t77\\t0755/" "$TMP/candidate-executable.tsv";rm -f "$TMP/candidate-executable.tsv.bak"
expect_fail candidate_executable "$TOOL" inventory-create --raw-candidate "$TMP/candidate-executable.tsv" --disposition "$TMP/disposition.json" --output "$TMP/candidate-executable.json"
cp "$TMP/candidate.tsv" "$TMP/candidate-truncated.tsv";sed -i.bak "/^ENTRY\\t${other_hex}\\t/d" "$TMP/candidate-truncated.tsv";rm -f "$TMP/candidate-truncated.tsv.bak"
expect_fail candidate_truncated "$TOOL" inventory-create --raw-candidate "$TMP/candidate-truncated.tsv" --disposition "$TMP/disposition.json" --output "$TMP/candidate-truncated.json"
cp "$TMP/candidate.tsv" "$TMP/candidate-root.tsv";sed -i.bak 's/^ROOT\t\([^\t]*\)\t\([^\t]*\)\t11\t22/ROOT\t\1\t\2\t11\t999/' "$TMP/candidate-root.tsv";rm -f "$TMP/candidate-root.tsv.bak"
expect_fail candidate_root "$TOOL" inventory-create --raw-candidate "$TMP/candidate-root.tsv" --disposition "$TMP/disposition.json" --output "$TMP/candidate-root.json"
cp "$TMP/candidate.tsv" "$TMP/candidate-summary.tsv";sed -i.bak 's/^SUMMARY\t4\t1\t3\t3\t112/SUMMARY\t4\t1\t2\t2\t107/' "$TMP/candidate-summary.tsv";rm -f "$TMP/candidate-summary.tsv.bak"
expect_fail candidate_summary "$TOOL" inventory-create --raw-candidate "$TMP/candidate-summary.tsv" --disposition "$TMP/disposition.json" --output "$TMP/candidate-summary.json"

cp "$TMP/disposition.json" "$TMP/tampered.json";cp "$TMP/disposition.json.hmac" "$TMP/tampered.json.hmac";printf ' ' >>"$TMP/tampered.json"
expect_fail tampered "$TOOL" verify --artifact "$TMP/tampered.json"
printf 'PASS: bounded volatile runtime disposition is exact, repeated, visible, and non-authorizing\n'
