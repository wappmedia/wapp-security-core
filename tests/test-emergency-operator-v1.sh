#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
if [[ "${WAPP_EMERGENCY_TEST_INNER:-}" != 1 ]]; then
  OUTER_TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-emergency-outer)"
  mkdir -p "$OUTER_TMP/repo"
  (cd "$SOURCE_ROOT" && tar -cf - --exclude .git .) | (cd "$OUTER_TMP/repo" && tar -xf -)
  /usr/bin/openssl ecparam -name prime256v1 -genkey -noout -out "$OUTER_TMP/reviewer-private-key" >/dev/null 2>&1
  /usr/bin/openssl pkey -in "$OUTER_TMP/reviewer-private-key" -pubout -out "$OUTER_TMP/reviewer-public-key" >/dev/null 2>&1
  /usr/bin/openssl rand -hex 32 > "$OUTER_TMP/recovery-integrity-test-key"
  chmod 600 "$OUTER_TMP/reviewer-private-key" "$OUTER_TMP/reviewer-public-key" "$OUTER_TMP/recovery-integrity-test-key"
  /usr/bin/python3 - "$OUTER_TMP/reviewer-public-key" "$OUTER_TMP/repo/config/reviewer-trust-anchors.json" <<'PY'
import json,sys
public_key,out=sys.argv[1:]
value={'tool':'wapp-security-reviewer-trust-anchors','schema':1,'reviewers':[{'reviewer_id':'synthetic-independent-reviewer','key_id':'synthetic-p256-key-1','algorithm':'ECDSA_P256_SHA256','public_key_pem':open(public_key).read()}]}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  mv "$OUTER_TMP/repo/lib/recovery-integrity.sh" "$OUTER_TMP/repo/lib/recovery-integrity-production.sh"
  cat > "$OUTER_TMP/repo/lib/recovery-integrity.sh" <<'EOF'
#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recovery-integrity-production.sh"
recovery_integrity_key(){
  local key_file key
  key_file="${WAPP_TEST_RECOVERY_INTEGRITY_KEY_FILE:?test key file required}"
  [[ "$key_file" == /* && -f "$key_file" && ! -L "$key_file" ]] || return 1
  key="$(tr -d '[:space:]' < "$key_file")"
  [[ "$key" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  printf '%s' "$key"
}
EOF
  chmod 755 "$OUTER_TMP/repo/lib/recovery-integrity.sh"
  git -C "$OUTER_TMP/repo" init -q
  git -C "$OUTER_TMP/repo" config user.name synthetic
  git -C "$OUTER_TMP/repo" config user.email synthetic
  git -C "$OUTER_TMP/repo" add -- .
  git -C "$OUTER_TMP/repo" commit -qm 'synthetic emergency contract test runtime'
  exec env WAPP_EMERGENCY_TEST_INNER=1 WAPP_EMERGENCY_TEST_OUTER_TMP="$OUTER_TMP" \
    WAPP_EMERGENCY_TEST_REVIEW_PRIVATE="$OUTER_TMP/reviewer-private-key" \
    WAPP_TEST_RECOVERY_INTEGRITY_KEY_FILE="$OUTER_TMP/recovery-integrity-test-key" \
    /bin/bash "$OUTER_TMP/repo/tests/test-emergency-operator-v1.sh"
fi

ROOT="$SOURCE_ROOT"
MODEL="$ROOT/lib/emergency-operator-v1.py"
CLI="$ROOT/bin/wapp-emergency-clean"
CLOSURE="$ROOT/bin/wapp-closure-check"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-emergency-v1)";trap 'rm -rf "$TMP" "${WAPP_EMERGENCY_TEST_OUTER_TMP:-}"' EXIT
source "$ROOT/lib/recovery-integrity.sh"
export WAPP_EMERGENCY_REPORTS_ROOT="$TMP/reports"
domain='operator-fixture.test';run="$TMP/run with spaces";mkdir -p "$run" "$WAPP_EMERGENCY_REPORTS_ROOT/.control/emergency-operator-v1"
fail(){ printf 'FAIL: %s\n' "$1" >&2;exit 1; };pass(){ printf 'PASS: %s\n' "$1"; };sign(){ chmod 600 "$1";recovery_sign_file "$1">/dev/null; }
expect_fail(){ local label="$1";shift;if "$@" >/dev/null 2>&1;then fail "$label accepted";fi;pass "$label"; }
expect_exact_fail(){ local label="$1" expected="$2" output;shift 2;output="$TMP/$label.err";if "$@" >/dev/null 2>"$output";then fail "$label accepted";fi;grep -Fqx "$expected" "$output"||fail "$label wrong failure class";pass "$label"; }
verify_review_signature_direct(){
  python3 - "$MODEL" "$1" <<'PY'
import importlib.util,json,sys
model_path,review_path=sys.argv[1:]
spec=importlib.util.spec_from_file_location('emergency_operator_v1',model_path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
try:
    module.verify_review_signature(json.load(open(review_path)))
except module.ContractError as error:
    print(str(error),file=sys.stderr);raise SystemExit(20)
PY
}
verify_current_dispatch_at(){
  python3 - "$MODEL" "$package" "$domain" "$1" <<'PY'
import importlib.util,sys
from pathlib import Path
model_path,package,domain,now=sys.argv[1:]
spec=importlib.util.spec_from_file_location('emergency_operator_v1',model_path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.verify_package(Path(package),domain,now=int(now),current_dispatch=True)
PY
}

[[ -x "$(recovery_trusted_fixed_python)" ]] || fail trusted_fixed_python
pass trusted_fixed_python
runtime_fixture="$TMP/runtime/bin";mkdir -p "$runtime_fixture"
printf '#!/bin/sh\nexit 0\n' > "$runtime_fixture/python3.12";chmod 777 "$runtime_fixture/python3.12"
ln -s python3.12 "$runtime_fixture/python3"
expect_fail writable_symlink_target recovery_trusted_python_candidate "$runtime_fixture/python3"
rm "$runtime_fixture/python3";ln -s ../outside-python3.12 "$runtime_fixture/python3"
expect_fail substituted_symlink_target recovery_trusted_python_candidate "$runtime_fixture/python3"

review_private="${WAPP_EMERGENCY_TEST_REVIEW_PRIVATE:?review private key required}"
make_review(){
  local package="$1" out="$2" payload="$TMP/review-payload" signature="$TMP/review-signature"
  python3 - "$package" "$out" "$payload" <<'PY'
import hashlib,json,sys
package,out,payload=sys.argv[1:]
value={'tool':'wapp-security-emergency-package-review','schema':1,'result':'PASS_NO_P0_P1_P2','package_sha256':hashlib.sha256(open(package,'rb').read()).hexdigest(),'reviewer_id':'synthetic-independent-reviewer','key_id':'synthetic-p256-key-1','signature_algorithm':'ECDSA_P256_SHA256'}
open(payload,'wb').write(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  /usr/bin/openssl dgst -sha256 -sign "$review_private" -out "$signature" "$payload"
  python3 - "$out" "$signature" <<'PY'
import base64,json,sys
out,signature=sys.argv[1:];value=json.load(open(out));value['signature_b64']=base64.b64encode(open(signature,'rb').read()).decode();open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$out"
}

/bin/bash "$ROOT/bin/wapp-product-seal" "$run/product.json" >/dev/null
current_commit="$(git -C "$ROOT" rev-parse HEAD)"
for name in incident prestate rollback-index forensic rollback;do
  printf '{"tool":"synthetic","schema":1,"domain":"%s","root":"/home/user_42/app_42","name":"%s"}\n' "$domain" "$name" >"$run/$name.json"
done
cat >"$run/launcher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == --execute && "${2:-}" =~ ^[a-f0-9]{64}$ ]]||exit 20
if [[ -n "${WAPP_TEST_CLOSURE_REPLAY_PROBE:-}" ]];then
  : >"$WAPP_TEST_CLOSURE_REPLAY_PROBE"
fi
printf 'SYNTHETIC REVIEWED LAUNCHER — NO TARGET ACCESS\n'
EOF
chmod 700 "$run/launcher"
for file in "$run/incident.json" "$run/prestate.json" "$run/rollback-index.json" "$run/forensic.json" "$run/rollback.json" "$run/launcher";do sign "$file";done
chmod 700 "$run/launcher"

now="$(date -u +%s)";package="$run/package.json"
python3 - "$run" "$package" "$domain" "$now" "$current_commit" <<'PY'
import hashlib,json,os,sys
run,package,domain,now,commit=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5]
def ref(name):
 p=os.path.join(run,name);return {'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}
zero='0'*64;one='1'*64;two='2'*64;three='3'*64
actions=[
 {'order':1,'primitive':'QUARANTINE_EXACT_FILE','stage':'EXECUTABLE','target':{'path':'/home/user_42/app_42/wp-content/malicious file.php','parent_device':'1','parent_inode':'2','device':'1','inode':'3','mode':'0644'},'before':{'sha256':one,'bytes':10},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':2,'primitive':'REPLACE_EXACT_FILE','stage':'CONFIG','target':{'path':'/home/user_42/app_42/wp-content/.user.ini','parent_device':'1','parent_inode':'2','device':'1','inode':'4','mode':'0644'},'before':{'sha256':two,'bytes':20},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':3,'primitive':'REMOVE_EXACT_ACTIVE_PLUGIN','stage':'DATABASE','target':{'table':'options','option_id':33,'option_name':'active_plugins','member':'malicious/plugin.php','integer_key':7},'before':{'sha256':one,'bytes':100},'after':{'sha256':two,'bytes':80},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':4,'primitive':'REMOVE_EXACT_OPTION','stage':'DATABASE','target':{'table':'options','option_id':44,'option_name':'_incident_marker','autoload':'auto'},'before':{'sha256':two,'bytes':2},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':5,'primitive':'QUARANTINE_IDENTITY_ACCESS','stage':'IDENTITY','target':{'table':'usermeta','user_id':42,'session_policy':'NEVER_EXPORT_OR_RESTORE','incident_marker_policy':'NEVER_RESTORE','meta_rows':[{'umeta_id':101,'key_sha256':one,'value_sha256':two,'bytes':31,'disposition':'REMOVE_ROLE'},{'umeta_id':102,'key_sha256':two,'value_sha256':three,'bytes':1,'disposition':'REMOVE_LEVEL'},{'umeta_id':103,'key_sha256':three,'value_sha256':one,'bytes':64,'disposition':'INVALIDATE_SESSION'},{'umeta_id':104,'key_sha256':one,'value_sha256':three,'bytes':2,'disposition':'REMOVE_INCIDENT_MARKER'}]},'before':{'sha256':three,'bytes':98},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'ROLE_LEVEL_ONLY','automatic':False}},
]
v={'tool':'wapp-security-emergency-operator-package','schema':1,'state':'LOCKED_REVIEWED_STOP_BEFORE_HUMAN_DECISION','phase':'REMEDIATION','contract':'HUMAN_OPERATOR_EMERGENCY_SELF_ISOLATED','classification':'YELLOW_SELF_REMEDIATION','domain':domain,'operation_id':'a'*32,'generated_at_epoch':now,'expires_at_epoch':now+3600,'site':{'site_id':'42','root':'/home/user_42/app_42','root_device':'1','root_inode':'2','ssh_endpoint':'user_42@192.0.2.42:22042','origin_ip':'192.0.2.42'},'product':{'commit':commit,'seal':ref('product.json')},'evidence':{'incident':ref('incident.json'),'prestate':ref('prestate.json'),'rollback_index':ref('rollback-index.json')},'isolation':{'method':'SELF_MANAGED_ATOMIC_DOCROOT_ISOLATION','public_origin_required':True,'accepted_https_statuses':[401,403,404,410,503],'stability_seconds':600,'exact_reverse_reopen':True},'actions':actions,'continuation':None,'human_gate':{'required':True,'phrase_format':'RENSA <DOMAIN> <PACKAGE_SHA256_12>'},'one_shot':{'required':True,'consumption_marker':os.path.join(run,'consumed')},'forensic_record':ref('forensic.json'),'independent_review':{'required_result':'PASS_NO_P0_P1_P2'},'launcher':ref('launcher'),'portability':{'bash_3_2':True,'db_integrity':'NATIVE_READ_ONLY_FALLBACK','blocked_http':'STATUS_SEMANTICS_NO_MIN_BODY'},'failure_policy':{'recurrence':'ABORT_RED_EXTERNAL_REQUIRED','partial_execution':'RECONCILE_NO_RETRY','blind_retry':False,'scope_expansion':False},'authority':{'canonical_ready':False,'provider_authorized':False,'autonomous_mutation':False,'closure':False}}
open(package,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$package";package_sha="$(recovery_sha256_file "$package")"
review="$run/review.json";make_review "$package" "$review"
postcheck="$run/execution-postcheck.json";python3 - "$package" "$postcheck" "$domain" "$now" <<'PY'
import hashlib,json,sys
package,out,domain,now=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]);v=json.load(open(package));canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode();isolation=hashlib.sha256(canonical({'site':v['site'],'isolation':v['isolation']})).hexdigest()
p={'tool':'wapp-security-emergency-execution-postcheck','schema':1,'state':'APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW','domain':domain,'root':v['site']['root'],'remediation_operation_id':v['operation_id'],'remediation_package_sha256':hashlib.sha256(open(package,'rb').read()).hexdigest(),'isolation_identity_sha256':isolation,'isolated_root':'/home/user_42/.wapp-security/human-emergency/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/app_42','isolation_active':True,'recurrence':False,'incident_targets_absent':True,'generated_at_epoch':now};open(out,'w').write(json.dumps(p,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$postcheck"
reopen="$run/reopen-package.json";python3 - "$package" "$review" "$postcheck" "$reopen" "$run" <<'PY'
import hashlib,json,os,sys
src,review,postcheck,out,run=sys.argv[1:];v=json.load(open(src));ref=lambda p:{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()};p=json.load(open(postcheck));v['phase']='REOPEN';v['operation_id']='b'*32;v['actions']=[{'order':1,'primitive':'REOPEN_ATOMIC_DOCROOT','stage':'REOPEN','target':{'canonical_root':'/home/user_42/app_42','isolated_root':p['isolated_root'],'device':'1','inode':'2'},'before':{'sha256':'1'*64,'bytes':1},'after':{'sha256':'2'*64,'bytes':1},'rollback':{'artifact':v['evidence']['rollback_index'],'restores':'EXACT_ORIGINAL','automatic':True}}];v['continuation']={'remediation_package':ref(src),'remediation_review':ref(review),'execution_postcheck':ref(postcheck),'isolation_identity_sha256':p['isolation_identity_sha256']};v['human_gate']['phrase_format']='ÅTERÖPPNA <DOMAIN> <PACKAGE_SHA256_12>';v['one_shot']['consumption_marker']=os.path.join(run,'reopen-consumed');open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$reopen";reopen_sha="$(recovery_sha256_file "$reopen")";reopen_review="$run/reopen-review.json";make_review "$reopen" "$reopen_review"

reopen_postcheck="$run/reopen-postcheck.json";python3 - "$package" "$reopen" "$reopen_postcheck" "$domain" "$now" <<'PY'
import hashlib,json,sys
remediation,reopen,out,domain,now=sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],int(sys.argv[5]);rem=json.load(open(remediation));rep=json.load(open(reopen));value={'tool':'wapp-security-emergency-reopen-postcheck','schema':1,'state':'POSTOPEN_VERIFIED_YELLOW','domain':domain,'root':rem['site']['root'],'reopen_operation_id':rep['operation_id'],'reopen_package_sha256':hashlib.sha256(open(reopen,'rb').read()).hexdigest(),'remediation_operation_id':rem['operation_id'],'remediation_package_sha256':hashlib.sha256(open(remediation,'rb').read()).hexdigest(),'generated_at_epoch':now,'isolation_reversed':True,'post_open_verified':True,'recurrence':False,'incident_targets_absent':True};open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$reopen_postcheck"

closure="$run/closure.json"
python3 - "$run" "$closure" "$domain" "$now" "$package" "$review" "$reopen" "$reopen_review" "$reopen_postcheck" <<'PY'
import hashlib,json,os,sys
run,out,domain,now,package,review,reopen,reopen_review,reopen_postcheck=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),*sys.argv[5:];ref=lambda p:{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()};rem=json.load(open(package));p=os.path.join(run,'closure-evidence.json');checks={'critical':0,'high':0,'filesystem_complete':True,'database_complete':True,'runtime_ok':True,'recurrence':False,'unknown_executable_persistence':False,'unresolved_malicious_privileged_access':False,'incident_targets_absent':True};e={'tool':'wapp-security-emergency-closure-evidence','schema':1,'domain':domain,'root':rem['site']['root'],'operation_id':rem['operation_id'],'product_commit':rem['product']['commit'],'generated_at_epoch':now,'scan':{'critical':checks['critical'],'high':checks['high']},'coverage':{'filesystem_complete':checks['filesystem_complete'],'database_complete':checks['database_complete'],'runtime_ok':checks['runtime_ok']},'recurrence':{'detected':checks['recurrence'],'unknown_executable_persistence':checks['unknown_executable_persistence'],'incident_targets_absent':checks['incident_targets_absent']},'identity':{'unresolved_malicious_privileged_access':checks['unresolved_malicious_privileged_access']}};open(p,'w').write(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n')
v={'tool':'wapp-security-emergency-closure-record','schema':1,'domain':domain,'root':rem['site']['root'],'operation_id':rem['operation_id'],'generated_at_epoch':now,'fresh_until_epoch':now+3600,'product':rem['product'],'remediation':{'package':ref(package),'review':ref(review)},'reopen':{'package':ref(reopen),'review':ref(reopen_review),'execution_postcheck':ref(reopen_postcheck)},'evidence':[ref(p)],'checks':checks,'assurance_limitations':[],'hardening_findings':['synthetic permission hardening'],'authority':False}
open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$run/closure-evidence.json"
sign "$closure"
registry="$WAPP_EMERGENCY_REPORTS_ROOT/.control/emergency-operator-v1/$domain.json"
python3 - "$package" "$review" "$reopen" "$reopen_review" "$closure" "$registry" "$domain" <<'PY'
import hashlib,json,sys
package,review,reopen,reopen_review,closure,out,domain=sys.argv[1:]
def ref(p):return {'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}
v={'tool':'wapp-security-emergency-operator-registry','schema':1,'domain':domain,'remediation':{'package':ref(package),'review':ref(review)},'reopen':{'package':ref(reopen),'review':ref(reopen_review)},'closure':{'record':ref(closure)}}
open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$registry"

out="$TMP/review.out";bash "$CLI" "$domain" >"$out";grep -Fq 'YELLOW_SELF_REMEDIATION' "$out"||fail review_class;grep -Fq 'malicious file.php' "$out"||fail path_with_spaces;grep -Fq 'Authority: HUMAN OPERATOR ONLY' "$out"||fail noncanonical_label;pass valid_package_review
python3 - "$review" "$run/hmac-only-review.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]));value['signature_b64']='AA==';open(sys.argv[2],'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$run/hmac-only-review.json";expect_fail automation_hmac_cannot_review python3 "$MODEL" verify-review --review "$run/hmac-only-review.json" --package "$package" --domain "$domain"
trust_config="$ROOT/config/reviewer-trust-anchors.json";cp "$trust_config" "$TMP/reviewer-trust-original.json"
for spec in rsa secp384r1; do
  alternate_private="$TMP/$spec-private-key";alternate_public="$TMP/$spec-public-key"
  if [[ "$spec" == rsa ]]; then
    /usr/bin/openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$alternate_private" >/dev/null 2>&1
  else
    /usr/bin/openssl ecparam -name "$spec" -genkey -noout -out "$alternate_private" >/dev/null 2>&1
  fi
  /usr/bin/openssl pkey -in "$alternate_private" -pubout -out "$alternate_public" >/dev/null 2>&1
  python3 - "$alternate_public" "$trust_config" <<'PY'
import json,sys
public_key,out=sys.argv[1:]
value={'tool':'wapp-security-reviewer-trust-anchors','schema':1,'reviewers':[{'reviewer_id':'synthetic-independent-reviewer','key_id':'synthetic-p256-key-1','algorithm':'ECDSA_P256_SHA256','public_key_pem':open(public_key).read()}]}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  original_review_private="$review_private";review_private="$alternate_private";make_review "$package" "$run/$spec-review.json";review_private="$original_review_private"
  expect_exact_fail "reviewer_key_type_$spec" 'reviewer public key is not ECDSA P-256' verify_review_signature_direct "$run/$spec-review.json"
done
cp "$TMP/reviewer-trust-original.json" "$trust_config"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] || fail reviewer_trust_restore
pass reviewer_key_type_and_curve
expect_fail human_gate_noninteractive bash "$CLI" "$domain" --execute
python3 - "$CLI" "$domain" "$run/incident.json" "RENSA $domain ${package_sha:0:12}" <<'PY'
import errno,os,pty,select,subprocess,sys,time
cli,domain,dependency,phrase=sys.argv[1:]
master,slave=pty.openpty();process=subprocess.Popen(['/bin/bash',cli,domain,'--execute'],stdin=slave,stdout=slave,stderr=slave,env=os.environ.copy(),close_fds=True);os.close(slave);output=b'';deadline=time.time()+15
while b'tryck Enter:' not in output and time.time()<deadline:
 ready,_,_=select.select([master],[],[],0.2)
 if ready:
  try: output+=os.read(master,4096)
  except OSError as error:
   if error.errno!=errno.EIO: raise
if b'tryck Enter:' not in output:
 process.kill();raise SystemExit('interactive prompt missing')
with open(dependency,'ab') as target: target.write(b'tamper-during-human-think-time\n')
os.write(master,(phrase+'\n').encode())
deadline=time.time()+15
while process.poll() is None and time.time()<deadline:
 ready,_,_=select.select([master],[],[],0.2)
 if ready:
  try: output+=os.read(master,4096)
  except OSError as error:
   if error.errno!=errno.EIO: raise
if process.poll() is None: process.kill();process.wait();raise SystemExit('CLI did not fail closed')
for _ in range(20):
 ready,_,_=select.select([master],[],[],0.05)
 if not ready: break
 try: output+=os.read(master,4096)
 except OSError as error:
  if error.errno!=errno.EIO: raise
  break
os.close(master)
if process.returncode==0 or b'SYNTHETIC REVIEWED LAUNCHER' in output: raise SystemExit('dependency drift launched')
PY
pass post_human_dependency_drift
printf '{"tool":"synthetic","schema":1,"domain":"%s","root":"/home/user_42/app_42","name":"incident"}\n' "$domain" >"$run/incident.json";sign "$run/incident.json"
python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$(recovery_sha256_file "$run/launcher")" --package-sha256 "$package_sha" >"$TMP/execute.out";grep -Fq 'SYNTHETIC REVIEWED LAUNCHER — NO TARGET ACCESS' "$TMP/execute.out"||fail pinned_launcher_execution;pass pinned_launcher_execution
[[ "$(python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now" | python3 -c 'import json,sys;print(json.load(sys.stdin)["human_phrase"])')" == "ÅTERÖPPNA $domain ${reopen_sha:0:12}" ]] || fail reopen_phrase;pass separate_reopen_contract
bash "$CLOSURE" "$domain" >"$TMP/closure.out";grep -Fq 'CLEAN_WITH_HARDENING_REMAINING' "$TMP/closure.out"||fail closure_hardening;pass closure_semantics
/bin/bash --version >/dev/null 2>&1||true;/bin/bash -n "$CLI" "$CLOSURE";pass bash_3_2_syntax_contract

variant(){ local name="$1" code="$2";python3 - "$package" "$run/$name.json" "$code" <<'PY'
import json,sys
src,out,code=sys.argv[1:];v=json.load(open(src));exec(code);open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
}
variant wrong-domain "v['domain']='other.test'";expect_fail wrong_site python3 "$MODEL" verify-package --package "$run/wrong-domain.json" --domain "$domain" --now-epoch "$now"
variant wrong-root "v['site']['root']='/home/user_99/app_99'";expect_fail wrong_root python3 "$MODEL" verify-package --package "$run/wrong-root.json" --domain "$domain" --now-epoch "$now"
variant sparse-string "v['actions'][2]['target']['integer_key']='7'";expect_fail sparse_key_type python3 "$MODEL" verify-package --package "$run/sparse-string.json" --domain "$domain" --now-epoch "$now"
variant unsafe-order "v['actions'][0]['stage']='DATABASE'";expect_fail dependency_order python3 "$MODEL" verify-package --package "$run/unsafe-order.json" --domain "$domain" --now-epoch "$now"
variant recurrence "v['failure_policy']['recurrence']='CONTINUE'";expect_fail recurrence_abort python3 "$MODEL" verify-package --package "$run/recurrence.json" --domain "$domain" --now-epoch "$now"
variant retry "v['failure_policy']['blind_retry']=True";expect_fail blind_retry python3 "$MODEL" verify-package --package "$run/retry.json" --domain "$domain" --now-epoch "$now"
variant mariadb "v['portability']['db_integrity']='MARIADB_CHECK_REQUIRED'";expect_fail missing_mariadb_fallback python3 "$MODEL" verify-package --package "$run/mariadb.json" --domain "$domain" --now-epoch "$now"
variant body "v['portability']['blocked_http']='MIN_BODY_REQUIRED'";expect_fail short_404_body python3 "$MODEL" verify-package --package "$run/body.json" --domain "$domain" --now-epoch "$now"
variant rawsecret "v['actions'][4]['target']['meta_rows'][0]['raw_value']='secret'";expect_fail identity_secret_export python3 "$MODEL" verify-package --package "$run/rawsecret.json" --domain "$domain" --now-epoch "$now"
variant scope "v['actions'].append(v['actions'][0].copy())";expect_fail scope_widening python3 "$MODEL" verify-package --package "$run/scope.json" --domain "$domain" --now-epoch "$now"
variant authority "v['authority']['canonical_ready']=True";expect_fail fabricated_ready python3 "$MODEL" verify-package --package "$run/authority.json" --domain "$domain" --now-epoch "$now"
variant reverse_false "v['isolation']['exact_reverse_reopen']=False";expect_fail reverse_reopen_required python3 "$MODEL" verify-package --package "$run/reverse_false.json" --domain "$domain" --now-epoch "$now"
variant file_no_rollback "v['actions'][0]['rollback']['restores']='NONE_IRREVERSIBLE_SECURITY_STATE';v['actions'][0]['rollback']['automatic']=False";expect_fail file_rollback_matrix python3 "$MODEL" verify-package --package "$run/file_no_rollback.json" --domain "$domain" --now-epoch "$now"
variant identity_exact_rollback "v['actions'][4]['rollback']['restores']='EXACT_ORIGINAL';v['actions'][4]['rollback']['automatic']=True";expect_fail identity_rollback_matrix python3 "$MODEL" verify-package --package "$run/identity_exact_rollback.json" --domain "$domain" --now-epoch "$now"
variant product_commit "v['product']['commit']='b'*40";expect_fail product_commit_binding python3 "$MODEL" verify-package --package "$run/product_commit.json" --domain "$domain" --now-epoch "$now"
python3 - "$run/product.json" "$run/product-drift.json" "$package" "$run/product-runtime-drift.json" <<'PY'
import hashlib,json,sys
source_product,drift_product,source_package,drift_package=sys.argv[1:]
product=json.load(open(source_product));product['components'][0]['sha256']='9'*64;open(drift_product,'w').write(json.dumps(product,sort_keys=True,separators=(',',':'))+'\n')
package=json.load(open(source_package));raw=open(drift_product,'rb').read();package['product']['seal']={'path':drift_product,'sha256':hashlib.sha256(raw).hexdigest()};open(drift_package,'w').write(json.dumps(package,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail dispatcher_runtime_drift python3 "$MODEL" verify-package --package "$run/product-runtime-drift.json" --domain "$domain" --now-epoch "$now"
expect_fail launcher_hash_substitution python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$(printf '9%.0s' {1..64})" --package-sha256 "$package_sha"
ln -s "$run/launcher" "$run/launcher-link";expect_fail launcher_symlink_substitution python3 "$MODEL" exec-launcher --launcher "$run/launcher-link" --sha256 "$(recovery_sha256_file "$run/launcher")" --package-sha256 "$package_sha"
variant red "v['classification']='RED_EXTERNAL_REQUIRED';v['actions']=[]";python3 "$MODEL" verify-package --package "$run/red.json" --domain "$domain" --now-epoch "$now" | grep -Fq 'RED_EXTERNAL_REQUIRED' || fail red_classification;pass red_external_required
python3 - "$reopen" "$run/reopen-no-continuation.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));v['continuation']=None;open(sys.argv[2],'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail reopen_without_remediation python3 "$MODEL" verify-package --package "$run/reopen-no-continuation.json" --domain "$domain" --now-epoch "$now"
python3 - "$postcheck" "$run/postcheck-recurrence.json" "$reopen" "$run/reopen-recurrence.json" <<'PY'
import hashlib,json,sys
source_postcheck,bad_postcheck,source_reopen,bad_reopen=sys.argv[1:];p=json.load(open(source_postcheck));p['recurrence']=True;open(bad_postcheck,'w').write(json.dumps(p,sort_keys=True,separators=(',',':'))+'\n');v=json.load(open(source_reopen));v['continuation']['execution_postcheck']={'path':bad_postcheck,'sha256':hashlib.sha256(open(bad_postcheck,'rb').read()).hexdigest()};open(bad_reopen,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail reopen_after_recurrence python3 "$MODEL" verify-package --package "$run/reopen-recurrence.json" --domain "$domain" --now-epoch "$now"
expect_fail expired python3 "$MODEL" verify-package --package "$package" --domain "$domain" --now-epoch "$((now+7200))"
expect_fail current_dispatch_missing_marker python3 "$MODEL" verify-current-dispatch --package "$package" --review "$review" --domain "$domain" --package-sha256 "$package_sha"
mkdir -m 700 "$run/consumed";printf '%s\n' "$package_sha" >"$run/consumed/package-sha256";chmod 600 "$run/consumed/package-sha256"
python3 "$MODEL" verify-current-dispatch --package "$package" --review "$review" --domain "$domain" --package-sha256 "$package_sha" >/dev/null || fail current_dispatch_exact_marker
pass current_dispatch_exact_marker
expect_fail one_shot_replay python3 "$MODEL" verify-package --package "$package" --domain "$domain" --now-epoch "$now"
expect_fail current_dispatch_time_override python3 "$MODEL" verify-current-dispatch --package "$package" --review "$review" --domain "$domain" --package-sha256 "$package_sha" --now-epoch "$now"
expect_fail current_dispatch_wrong_package_sha python3 "$MODEL" verify-current-dispatch --package "$package" --review "$review" --domain "$domain" --package-sha256 "$(printf '9%.0s' {1..64})"
expect_fail current_dispatch_expired verify_current_dispatch_at "$((now+7200))"
chmod 777 "$run/consumed";expect_fail current_dispatch_writable_marker python3 "$MODEL" verify-current-dispatch --package "$package" --review "$review" --domain "$domain" --package-sha256 "$package_sha";chmod 700 "$run/consumed"
mv "$run/consumed/package-sha256" "$run/consumed/package-sha256.real";ln -s package-sha256.real "$run/consumed/package-sha256"
expect_fail current_dispatch_symlink_identity python3 "$MODEL" verify-current-dispatch --package "$package" --review "$review" --domain "$domain" --package-sha256 "$package_sha"
rm "$run/consumed/package-sha256";mv "$run/consumed/package-sha256.real" "$run/consumed/package-sha256"
expect_fail current_dispatch_wrong_review python3 "$MODEL" verify-current-dispatch --package "$package" --review "$run/hmac-only-review.json" --domain "$domain" --package-sha256 "$package_sha"
rm -rf "$run/consumed"
printf tamper >>"$run/incident.json";expect_fail evidence_tamper bash "$CLI" "$domain"
printf '{"tool":"synthetic","schema":1,"domain":"%s","root":"/home/user_42/app_42","name":"incident"}\n' "$domain" >"$run/incident.json";sign "$run/incident.json"
pass forensic_dependency_integrity

python3 - "$closure" "$run/closure-evidence.json" "$reopen_postcheck" "$run/incomplete-closure.json" "$run/incomplete-evidence.json" "$run/incomplete-reopen-postcheck.json" <<'PY'
import hashlib,json,sys
source_closure,source_evidence,source_postcheck,out_closure,out_evidence,out_postcheck=sys.argv[1:];e=json.load(open(source_evidence));e['recurrence']['detected']=True;open(out_evidence,'w').write(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n');p=json.load(open(source_postcheck));p['recurrence']=True;open(out_postcheck,'w').write(json.dumps(p,sort_keys=True,separators=(',',':'))+'\n');v=json.load(open(source_closure));v['checks']['recurrence']=True;v['evidence']=[{'path':out_evidence,'sha256':hashlib.sha256(open(out_evidence,'rb').read()).hexdigest()}];v['reopen']['execution_postcheck']={'path':out_postcheck,'sha256':hashlib.sha256(open(out_postcheck,'rb').read()).hexdigest()};open(out_closure,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
python3 "$MODEL" verify-closure --record "$run/incomplete-closure.json" --domain "$domain" | grep -Fq 'STILL_INCOMPLETE' || fail closure_recurrence
pass closure_recurrence
python3 - "$run/closure-evidence.json" "$run/arbitrary-closure-evidence.json" "$closure" "$run/arbitrary-closure.json" <<'PY'
import hashlib,json,sys
source,out_evidence,source_closure,out_closure=sys.argv[1:];e=json.load(open(source));e['tool']='synthetic-arbitrary-evidence';open(out_evidence,'w').write(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n');v=json.load(open(source_closure));v['evidence']=[{'path':out_evidence,'sha256':hashlib.sha256(open(out_evidence,'rb').read()).hexdigest()}];open(out_closure,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail arbitrary_closure_evidence python3 "$MODEL" verify-closure --record "$run/arbitrary-closure.json" --domain "$domain" --now-epoch "$now"
python3 - "$closure" "$run/closure-without-postopen.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1]));del value['reopen']['execution_postcheck'];open(sys.argv[2],'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail closure_without_postopen_receipt python3 "$MODEL" verify-closure --record "$run/closure-without-postopen.json" --domain "$domain" --now-epoch "$now"
python3 - "$closure" "$run/limited-closure.json" "$run/clean-closure.json" <<'PY'
import json,sys
src,limited,clean=sys.argv[1:];v=json.load(open(src));v['hardening_findings']=[];v['assurance_limitations']=['synthetic host-wide limitation'];open(limited,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n');v['assurance_limitations']=[];open(clean,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
python3 "$MODEL" verify-closure --record "$run/limited-closure.json" --domain "$domain" | grep -Fq 'CLEAN_WITH_DOCUMENTED_ASSURANCE_LIMITATIONS' || fail closure_limitations
python3 "$MODEL" verify-closure --record "$run/clean-closure.json" --domain "$domain" | grep -Fq 'WORDPRESS_INCIDENT_VERIFIED_CLEAN' || fail closure_clean
python3 "$MODEL" verify-closure --record "$run/clean-closure.json" --domain "$domain" --now-epoch "$((now+7200))" | grep -Fq 'STILL_INCOMPLETE' || fail closure_stale
python3 - "$run/closure-evidence.json" "$run/cross-site-evidence.json" "$closure" "$run/cross-site-closure.json" <<'PY'
import hashlib,json,sys
source_evidence,bad_evidence,source_closure,bad_closure=sys.argv[1:];e=json.load(open(source_evidence));e['domain']='other.test';open(bad_evidence,'w').write(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n');v=json.load(open(source_closure));v['evidence']=[{'path':bad_evidence,'sha256':hashlib.sha256(open(bad_evidence,'rb').read()).hexdigest()}];open(bad_closure,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail closure_cross_site python3 "$MODEL" verify-closure --record "$run/cross-site-closure.json" --domain "$domain" --now-epoch "$now"
python3 - "$closure" "$run/control-closure.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));v['assurance_limitations']=['bad\x1b[2J'];open(sys.argv[2],'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail closure_terminal_control python3 "$MODEL" verify-closure --record "$run/control-closure.json" --domain "$domain" --now-epoch "$now"
pass closure_all_statuses

# Executed packages are deliberately expired and consumed before a later,
# read-only closure is evaluated.  The fresh closure binds the immutable
# historical operation; it must never turn that operation into replay authority.
history_now="$((now+7200))"
mkdir -m 700 "$run/consumed" "$run/historical-reopen-consumed"
printf '%s\n' "$package_sha" >"$run/consumed/package-sha256";chmod 600 "$run/consumed/package-sha256"
historical_reopen="$run/historical-reopen-package.json"
python3 - "$historical_reopen" "$domain" "$package_sha" "$run" <<'PY'
import json,os,sys
out,domain,remediation_sha,run=sys.argv[1:]
value={'tool':'wapp-security-private-emergency-reopen-package','schema':1,'domain':domain,'reopen_operation_id':'c'*32,'remediation_operation_id':'a'*32,'evidence':{'remediation_package_sha256':remediation_sha},'exact_mutation':{'destination':'/home/user_42/app_42','expected_root_device':'1','expected_root_inode':'2'},'one_shot':{'required':True,'consumption_marker':os.path.join(run,'historical-reopen-consumed')},'authority':{'canonical_ready':False,'provider_authorized':False,'verified_clean':False,'closure':False}}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$historical_reopen";historical_reopen_sha="$(recovery_sha256_file "$historical_reopen")"
printf '%s\n' "$historical_reopen_sha" >"$run/historical-reopen-consumed/package-sha256";chmod 600 "$run/historical-reopen-consumed/package-sha256"
historical_reopen_review="$run/historical-reopen-review.json";make_review "$historical_reopen" "$historical_reopen_review"
remediation_audit_source="$run/historical-remediation-audit-source.txt";printf '%s\n' "$domain operation=$(printf 'a%.0s' {1..32}) package=$package_sha EXECUTED" >"$remediation_audit_source";sign "$remediation_audit_source"
remediation_poststate_source="$run/historical-remediation-poststate-source.txt";printf '%s\n' "$domain operation=$(printf 'a%.0s' {1..32}) APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW" >"$remediation_poststate_source";sign "$remediation_poststate_source"
reopen_audit_source="$run/historical-reopen-audit-source.txt";printf '%s\n' "reopen=$(printf 'c%.0s' {1..32}) remediation=$(printf 'a%.0s' {1..32}) package=$historical_reopen_sha EXECUTED" >"$reopen_audit_source";sign "$reopen_audit_source"
postopen_source="$run/historical-postopen-source.txt";printf '%s\n' "$domain reopen=$(printf 'c%.0s' {1..32}) remediation=$(printf 'a%.0s' {1..32}) APPLIED_EXACT_AND_POSTOPEN_VERIFIED_YELLOW" >"$postopen_source";sign "$postopen_source"
remediation_audit="$run/historical-remediation-audit.json";remediation_poststate="$run/historical-remediation-poststate.json";reopen_audit="$run/historical-reopen-audit.json";postopen="$run/historical-postopen.json"
python3 - "$remediation_audit" "$remediation_poststate" "$reopen_audit" "$postopen" "$remediation_audit_source" "$remediation_poststate_source" "$reopen_audit_source" "$postopen_source" "$domain" "$history_now" "$package_sha" "$historical_reopen_sha" "$postcheck" <<'PY'
import hashlib,json,sys
rem_audit,rem_state,rep_audit,postopen,rem_source,state_source,rep_source,post_source,domain,now,rem_sha,rep_sha,postcheck=sys.argv[1:];now=int(now);ref=lambda p:{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()};pc=json.load(open(postcheck));root='/home/user_42/app_42';rem_op='a'*32;rep_op='c'*32
audit={'tool':'wapp-security-emergency-historical-execution-audit','schema':1,'phase':'REMEDIATION','domain':domain,'root':root,'operation_id':rem_op,'package_sha256':rem_sha,'started_at_epoch':now-400,'completed_at_epoch':now-300,'source_audit':ref(rem_source),'human_operator_confirmed':True,'actions_completed':True,'read_only_validation':True,'authority':False};open(rem_audit,'w').write(json.dumps(audit,sort_keys=True,separators=(',',':'))+'\n')
state={'tool':'wapp-security-emergency-historical-remediation-poststate','schema':1,'state':'APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW','domain':domain,'root':root,'root_device':'1','root_inode':'2','operation_id':rem_op,'package_sha256':rem_sha,'isolation_identity_sha256':pc['isolation_identity_sha256'],'generated_at_epoch':now-250,'isolation_active':True,'recurrence':False,'incident_targets_absent':True,'source_poststate':ref(state_source),'read_only_validation':True,'authority':False};open(rem_state,'w').write(json.dumps(state,sort_keys=True,separators=(',',':'))+'\n')
audit={'tool':'wapp-security-emergency-historical-execution-audit','schema':1,'phase':'REOPEN','domain':domain,'root':root,'operation_id':rep_op,'package_sha256':rep_sha,'remediation_operation_id':rem_op,'remediation_package_sha256':rem_sha,'started_at_epoch':now-200,'completed_at_epoch':now-150,'source_audit':ref(rep_source),'human_operator_confirmed':True,'actions_completed':True,'read_only_validation':True,'authority':False};open(rep_audit,'w').write(json.dumps(audit,sort_keys=True,separators=(',',':'))+'\n')
state={'tool':'wapp-security-emergency-historical-post-open-verification','schema':1,'state':'APPLIED_EXACT_AND_POSTOPEN_VERIFIED_YELLOW','domain':domain,'root':root,'root_device':'1','root_inode':'2','remediation_operation_id':rem_op,'remediation_package_sha256':rem_sha,'reopen_operation_id':rep_op,'reopen_package_sha256':rep_sha,'generated_at_epoch':now-100,'isolation_reversed':True,'post_open_verified':True,'recurrence':False,'incident_targets_absent':True,'source_post_open':ref(post_source),'read_only_validation':True,'authority':False};open(postopen,'w').write(json.dumps(state,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$remediation_audit";sign "$remediation_poststate";sign "$reopen_audit";sign "$postopen"
historical_lineage="$run/historical-lineage.json"
python3 - "$historical_lineage" "$domain" "$history_now" "$package" "$review" "$run/consumed/package-sha256" "$remediation_audit" "$remediation_poststate" "$historical_reopen" "$historical_reopen_review" "$run/historical-reopen-consumed/package-sha256" "$reopen_audit" "$postopen" "$postcheck" <<'PY'
import hashlib,json,sys
out,domain,now,package,review,consumption,audit,poststate,reopen,reopen_review,reopen_consumption,reopen_audit,postopen,postcheck=sys.argv[1:]
now=int(now);ref=lambda p:{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()};rem=json.load(open(package));pc=json.load(open(postcheck));rep=json.load(open(reopen))
value={'tool':'wapp-security-emergency-historical-execution-lineage','schema':1,'state':'EXECUTED_AND_POSTOPEN_VERIFIED_HISTORICAL','domain':domain,'root':rem['site']['root'],'generated_at_epoch':now,'isolation_identity_sha256':pc['isolation_identity_sha256'],'remediation':{'package':ref(package),'review':ref(review),'operation_id':rem['operation_id'],'consumption_identity':ref(consumption),'execution_audit':ref(audit),'execution_poststate':ref(poststate)},'reopen':{'package':ref(reopen),'review':ref(reopen_review),'operation_id':rep['reopen_operation_id'],'remediation_operation_id':rem['operation_id'],'remediation_package_sha256':hashlib.sha256(open(package,'rb').read()).hexdigest(),'consumption_identity':ref(reopen_consumption),'execution_audit':ref(reopen_audit),'post_open_verification':ref(postopen)},'authority':False}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$historical_lineage";historical_lineage_review="$run/historical-lineage-review.json";make_review "$historical_lineage" "$historical_lineage_review"
historical_evidence="$run/historical-closure-evidence.json";historical_closure="$run/historical-closure.json"
historical_site_identity="$run/historical-current-site-identity.json"
python3 - "$historical_site_identity" "$domain" "$history_now" "$current_commit" <<'PY'
import json,sys
out,domain,now,commit=sys.argv[1:];value={'tool':'wapp-security-emergency-current-site-identity','schema':1,'domain':domain,'root':'/home/user_42/app_42','operation_id':'a'*32,'product_commit':commit,'generated_at_epoch':int(now),'root_device':'1','root_inode':'2','serving_root_verified':True,'read_only':True,'authority':False};open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$historical_site_identity"
python3 - "$historical_evidence" "$historical_closure" "$historical_lineage" "$historical_lineage_review" "$historical_site_identity" "$run/product.json" "$domain" "$history_now" "$current_commit" <<'PY'
import hashlib,json,sys
evidence,closure,lineage,lineage_review,site_identity,product,domain,now,commit=sys.argv[1:];now=int(now);ref=lambda p:{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()};lin=json.load(open(lineage));checks={'critical':0,'high':0,'filesystem_complete':True,'database_complete':True,'runtime_ok':True,'recurrence':False,'unknown_executable_persistence':False,'unresolved_malicious_privileged_access':False,'incident_targets_absent':True}
e={'tool':'wapp-security-emergency-closure-evidence','schema':1,'domain':domain,'root':lin['root'],'operation_id':lin['remediation']['operation_id'],'product_commit':commit,'generated_at_epoch':now,'scan':{'critical':0,'high':0},'coverage':{'filesystem_complete':True,'database_complete':True,'runtime_ok':True},'recurrence':{'detected':False,'unknown_executable_persistence':False,'incident_targets_absent':True},'identity':{'unresolved_malicious_privileged_access':False}};open(evidence,'w').write(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n')
v={'tool':'wapp-security-emergency-closure-record','schema':2,'domain':domain,'root':lin['root'],'operation_id':lin['remediation']['operation_id'],'generated_at_epoch':now,'fresh_until_epoch':now+3600,'product':{'commit':commit,'seal':ref(product)},'historical_execution':{'lineage':ref(lineage),'review':ref(lineage_review)},'current_site_identity':ref(site_identity),'evidence':[ref(evidence)],'checks':checks,'assurance_limitations':[],'hardening_findings':[],'authority':False};open(closure,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$historical_evidence";sign "$historical_closure"
python3 "$MODEL" verify-closure --record "$historical_closure" --domain "$domain" --now-epoch "$history_now" | grep -Fq WORDPRESS_INCIDENT_VERIFIED_CLEAN || fail historical_executed_closure
pass historical_expired_consumed_lineage

historical_variant(){
  local name="$1" code="$2" source="${3:-$historical_lineage}" out="$run/historical-$name-lineage.json" review_out="$run/historical-$name-review.json" closure_out="$run/historical-$name-closure.json"
  python3 - "$source" "$out" "$code" <<'PY'
import json,sys
source,out,code=sys.argv[1:];v=json.load(open(source));exec(code);open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$out";make_review "$out" "$review_out"
  python3 - "$historical_closure" "$closure_out" "$out" "$review_out" <<'PY'
import hashlib,json,sys
source,out,lineage,review=sys.argv[1:];v=json.load(open(source));ref=lambda p:{'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()};v['historical_execution']={'lineage':ref(lineage),'review':ref(review)};open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$closure_out"
}

mv "$run/consumed" "$run/consumed.saved"
expect_fail historical_expired_unexecuted python3 "$MODEL" verify-closure --record "$historical_closure" --domain "$domain" --now-epoch "$history_now"
mv "$run/consumed.saved" "$run/consumed"

historical_variant missing-audit "del v['remediation']['execution_audit']"
expect_fail historical_consumed_without_audit python3 "$MODEL" verify-closure --record "$run/historical-missing-audit-closure.json" --domain "$domain" --now-epoch "$history_now"

wrong_audit="$run/historical-wrong-audit.json";python3 - "$remediation_audit" "$wrong_audit" <<'PY'
import json,sys
source,out=sys.argv[1:];v=json.load(open(source));v['actions_completed']=False;open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$wrong_audit"
historical_variant wrong-audit "import hashlib;v['remediation']['execution_audit']={'path':'$wrong_audit','sha256':hashlib.sha256(open('$wrong_audit','rb').read()).hexdigest()}"
expect_fail historical_wrong_execution_audit python3 "$MODEL" verify-closure --record "$run/historical-wrong-audit-closure.json" --domain "$domain" --now-epoch "$history_now"

wrong_poststate="$run/historical-wrong-poststate.json";python3 - "$remediation_poststate" "$wrong_poststate" <<'PY'
import json,sys
source,out=sys.argv[1:];v=json.load(open(source));v['recurrence']=True;open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$wrong_poststate"
historical_variant wrong-poststate "import hashlib;v['remediation']['execution_poststate']={'path':'$wrong_poststate','sha256':hashlib.sha256(open('$wrong_poststate','rb').read()).hexdigest()}"
expect_fail historical_contradictory_poststate python3 "$MODEL" verify-closure --record "$run/historical-wrong-poststate-closure.json" --domain "$domain" --now-epoch "$history_now"

wrong_postopen="$run/historical-wrong-postopen.json";python3 - "$postopen" "$wrong_postopen" <<'PY'
import json,sys
source,out=sys.argv[1:];v=json.load(open(source));v['incident_targets_absent']=False;open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$wrong_postopen"
historical_variant wrong-postopen "import hashlib;v['reopen']['post_open_verification']={'path':'$wrong_postopen','sha256':hashlib.sha256(open('$wrong_postopen','rb').read()).hexdigest()}"
expect_fail historical_contradictory_postopen python3 "$MODEL" verify-closure --record "$run/historical-wrong-postopen-closure.json" --domain "$domain" --now-epoch "$history_now"

extra_audit="$run/historical-extra-audit.json";python3 - "$remediation_audit" "$extra_audit" <<'PY'
import json,sys
source,out=sys.argv[1:];v=json.load(open(source));v['unexpected']='token-bearing but invalid';open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$extra_audit"
historical_variant extra-audit "import hashlib;v['remediation']['execution_audit']={'path':'$extra_audit','sha256':hashlib.sha256(open('$extra_audit','rb').read()).hexdigest()}"
expect_fail historical_extra_audit_field python3 "$MODEL" verify-closure --record "$run/historical-extra-audit-closure.json" --domain "$domain" --now-epoch "$history_now"

historical_variant wrong-package-sha "v['remediation']['package']['sha256']='9'*64"
expect_fail historical_wrong_package_sha python3 "$MODEL" verify-closure --record "$run/historical-wrong-package-sha-closure.json" --domain "$domain" --now-epoch "$history_now"

historical_variant wrong-operation "v['remediation']['operation_id']='d'*32"
expect_fail historical_wrong_operation python3 "$MODEL" verify-closure --record "$run/historical-wrong-operation-closure.json" --domain "$domain" --now-epoch "$history_now"

historical_variant wrong-reopen "v['reopen']['remediation_operation_id']='d'*32"
expect_fail historical_wrong_reopen_binding python3 "$MODEL" verify-closure --record "$run/historical-wrong-reopen-closure.json" --domain "$domain" --now-epoch "$history_now"

historical_variant wrong-root "v['root']='/home/user_99/app_99'"
expect_fail historical_wrong_site_root python3 "$MODEL" verify-closure --record "$run/historical-wrong-root-closure.json" --domain "$domain" --now-epoch "$history_now"

wrong_site_identity="$run/historical-wrong-current-site-identity.json";python3 - "$historical_site_identity" "$wrong_site_identity" <<'PY'
import json,sys
source,out=sys.argv[1:];v=json.load(open(source));v['root_inode']='999';open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$wrong_site_identity"
wrong_site_closure="$run/historical-wrong-current-site-closure.json";python3 - "$historical_closure" "$wrong_site_closure" "$wrong_site_identity" <<'PY'
import hashlib,json,sys
source,out,site=sys.argv[1:];v=json.load(open(source));v['current_site_identity']={'path':site,'sha256':hashlib.sha256(open(site,'rb').read()).hexdigest()};open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$wrong_site_closure"
expect_fail historical_same_path_root_substitution python3 "$MODEL" verify-closure --record "$wrong_site_closure" --domain "$domain" --now-epoch "$history_now"

substituted_package="$run/substituted-package.json";python3 - "$package" "$substituted_package" <<'PY'
import json,sys
source,out=sys.argv[1:];v=json.load(open(source));v['operation_id']='d'*32;open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$substituted_package";historical_variant substituted-package "import hashlib;v['remediation']['package']={'path':'$substituted_package','sha256':hashlib.sha256(open('$substituted_package','rb').read()).hexdigest()}"
expect_fail historical_substituted_package python3 "$MODEL" verify-closure --record "$run/historical-substituted-package-closure.json" --domain "$domain" --now-epoch "$history_now"

replay_probe="$run/closure-replay-probe";rm -f "$replay_probe"
WAPP_TEST_CLOSURE_REPLAY_PROBE="$replay_probe" python3 "$MODEL" verify-closure --record "$historical_closure" --domain "$domain" --now-epoch "$history_now" >/dev/null
[[ ! -e "$replay_probe" && -d "$run/consumed" && -d "$run/historical-reopen-consumed" ]] || fail historical_closure_replayed_mutation
pass historical_closure_no_replay_authority

# A legacy audit that was genuinely executed but unsigned at execution time is
# accepted only through the explicit, independently reviewed reconciliation
# protocol.  The normal historical path must remain strict and never fall back.
legacy_consumption="$run/legacy-operation/package-sha256";mkdir -m 700 "$run/legacy-operation"
printf '%s\n' "$package_sha" >"$legacy_consumption";chmod 600 "$legacy_consumption"
legacy_audit="$run/legacy-unsigned-execution-audit.log"
python3 - "$package" "$legacy_audit" <<'PY'
import datetime,json,sys
package,out=sys.argv[1:];p=json.load(open(package));op=p['operation_id'];sha=__import__('hashlib').sha256(open(package,'rb').read()).hexdigest();start=p['generated_at_epoch']+10
stamp=lambda value:datetime.datetime.fromtimestamp(value,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
lines=[f'{stamp(start)}\tBEGIN contract=HUMAN_OPERATOR_EMERGENCY_YELLOW_SELF_MANAGED_ISOLATION site={p["domain"]} operation={op} package={sha} operator=synthetic-operator',f'WAPP_SYNTHETIC_FILES_QUARANTINED_V1|{op}|1',f'WAPP_SYNTHETIC_FILES_TRANSFORMED_V1|{op}|1',f'{stamp(start+1)}\tWAPP_SYNTHETIC_DB_APPLY_V1|{op}|COMMITTED|active=1|options=1|identity=4|credential_neutral=1|sessions_restored=0',f'{stamp(start+2)}\tWAPP_SYNTHETIC_DB_AFTER_V1|{op}|EXACT|active=1|options=0|identity=0|user_preserved=1|sessions=0',f'{stamp(start+3)}\tWAPP_SYNTHETIC_REMEDIATION_COMPLETE_ISOLATION_REMAINS_ACTIVE']
open(out,'w').write('\n'.join(lines)+'\n')
PY
chmod 600 "$legacy_audit";legacy_preserved="$run/legacy-preserved-execution-audit.log";cp "$legacy_audit" "$legacy_preserved";chmod 600 "$legacy_preserved"
legacy_collector="$run/legacy-readonly-collector";printf '#!/bin/sh\nexit 20\n' >"$legacy_collector";chmod 600 "$legacy_collector";sign "$legacy_collector"
legacy_poststate="$run/legacy-current-poststate.log"
python3 - "$package" "$legacy_audit" "$legacy_poststate" <<'PY'
import datetime,hashlib,json,sys
package,audit,out=sys.argv[1:];p=json.load(open(package));op=p['operation_id'];sha=hashlib.sha256(open(package,'rb').read()).hexdigest();start=p['expires_at_epoch']+10
stamp=lambda value:datetime.datetime.fromtimestamp(value,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
lines=['WAPP_SYNTHETIC_LEGACY_RECONCILIATION_CURRENT_POSTSTATE_V1',f'domain={p["domain"]}',f'root={p["site"]["root"]}',f'root_device={p["site"]["root_device"]}',f'root_inode={p["site"]["root_inode"]}',f'operation_id={op}',f'package_sha256={sha}',f'original_audit_sha256={hashlib.sha256(open(audit,"rb").read()).hexdigest()}','original_audit_signed_at_execution=false','read_only=true','authority=false']
for index,when in enumerate((start,start+60)):
 lines.extend([f'{stamp(when)}\tOBSERVATION_BEGIN index={index}',f'WAPP_SYNTHETIC_ISOLATION_VERIFIED_V1|{op}',f'WAPP_SYNTHETIC_FILES_VERIFIED_V1|{op}|2',f'WAPP_SYNTHETIC_DB_AFTER_V1|{op}|EXACT|active=1|options=0|identity=0|user_preserved=1|sessions=0',f'{stamp(when+1)}\tHTTP_ISOLATION endpoint=public route=/ denied=1',f'{stamp(when+1)}\tHTTP_ISOLATION endpoint=origin route=/ denied=1',f'{stamp(when+2)}\tOBSERVATION_END index={index}'])
lines.append(f'{stamp(start+62)}\tRECONCILIATION_POSTSTATE_VERIFIED recurrence=false isolation_active=true')
open(out,'w').write('\n'.join(lines)+'\n')
PY
chmod 600 "$legacy_poststate";sign "$legacy_poststate"
legacy_attestation="$run/legacy-reconciliation.json";legacy_review="$run/legacy-reconciliation-review.json";legacy_reconciled_at="$((history_now-500))"
python3 - "$legacy_attestation" "$package" "$review" "$registry" "$legacy_consumption" "$legacy_audit" "$legacy_preserved" "$legacy_poststate" "$legacy_collector" "$domain" "$legacy_reconciled_at" <<'PY'
import hashlib,json,os,stat,sys
out,package,review,registry,consumption,audit,preserved,poststate,collector,domain,now=sys.argv[1:]
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
p=json.load(open(package));r=json.load(open(review));s=os.stat(audit);actions=p['actions'];active=[a for a in actions if a['primitive']=='REMOVE_EXACT_ACTIVE_PLUGIN'];identity=[a for a in actions if a['primitive']=='QUARANTINE_IDENTITY_ACCESS']
isolation=hashlib.sha256(json.dumps({'site':p['site'],'isolation':p['isolation']},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
action_contract={'actions_sha256':hashlib.sha256(json.dumps(actions,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'quarantine_file_targets':sum(a['primitive']=='QUARANTINE_EXACT_FILE' for a in actions),'replace_file_targets':sum(a['primitive']=='REPLACE_EXACT_FILE' for a in actions),'active_plugin_members':len(active),'active_plugin_rows':len({(a['target']['table'],a['target']['option_id'],a['target']['option_name']) for a in active}),'option_rows':sum(a['primitive']=='REMOVE_EXACT_OPTION' for a in actions),'identity_targets':len(identity),'identity_meta_rows':sum(len(a['target']['meta_rows']) for a in identity)}
value={'tool':'wapp-security-emergency-legacy-execution-reconciliation-attestation','schema':1,'state':'LEGACY_RECONCILED_EXECUTION','domain':domain,'root':p['site']['root'],'root_device':p['site']['root_device'],'root_inode':p['site']['root_inode'],'operation_id':p['operation_id'],'package_sha256':ref(package)['sha256'],'generated_at_epoch':int(now),'isolation_identity_sha256':isolation,'sources':{'package':ref(package),'package_review':ref(review),'signed_registry':ref(registry),'consumption_identity':ref(consumption),'original_execution_audit':ref(audit),'preserved_execution_audit':ref(preserved),'current_poststate':ref(poststate),'current_poststate_hmac':ref(poststate+'.hmac'),'collector':ref(collector),'collector_hmac':ref(collector+'.hmac')},'source_reviewer':{'reviewer_id':r['reviewer_id'],'key_id':r['key_id'],'signature_algorithm':r['signature_algorithm'],'package_review_sha256':ref(review)['sha256']},'original_execution_audit':{'sha256':ref(audit)['sha256'],'bytes':s.st_size,'device':str(s.st_dev),'inode':str(s.st_ino),'uid':s.st_uid,'gid':s.st_gid,'mode':format(stat.S_IMODE(s.st_mode),'04o'),'mtime_epoch':int(s.st_mtime),'signed_at_execution':False,'hmac_present_at_execution':False},'action_contract':action_contract,'verified_poststate':{'quarantine_exact':True,'active_plugins_exact':True,'incident_options_absent':True,'incident_identity_access_quarantined':True,'recurrence':False,'isolation_active':True,'site_identity_verified':True,'read_only':True},'statement':'AFTER_THE_FACT_VERIFICATION_ORIGINAL_EXECUTION_AUDIT_UNSIGNED','authority':False}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
chmod 600 "$legacy_attestation";sign "$legacy_attestation";make_review "$legacy_attestation" "$legacy_review"
mv "$run/consumed" "$run/consumed.legacy-test"
python3 "$MODEL" verify-legacy-reconciliation --attestation "$legacy_attestation" --review "$legacy_review" --domain "$domain" --now-epoch "$history_now" | grep -Fq '"state":"LEGACY_RECONCILED_EXECUTION"' || fail legacy_reconciled_execution
expect_fail legacy_no_silent_normal_fallback python3 - "$MODEL" "$package" "$domain" "$history_now" <<'PY'
import importlib.util,pathlib,sys
model,package,domain,now=sys.argv[1:];spec=importlib.util.spec_from_file_location('m',model);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.verify_package(pathlib.Path(package),domain,now=int(now),historical_execution=True)
PY
mv "$run/consumed.legacy-test" "$run/consumed"

# Closure may consume the explicit legacy reconciliation only through a typed
# lineage whose remediation branch is visibly classified as legacy.  The
# normal signed-execution branch remains a different exact-key contract.
legacy_historical_lineage="$run/legacy-historical-lineage.json"
python3 - "$legacy_historical_lineage" "$domain" "$history_now" "$package" "$review" "$run/consumed/package-sha256" "$legacy_attestation" "$legacy_review" "$historical_reopen" "$historical_reopen_review" "$run/historical-reopen-consumed/package-sha256" "$reopen_audit" "$postopen" "$postcheck" <<'PY'
import hashlib,json,sys
out,domain,now,package,review,consumption,reconciliation,reconciliation_review,reopen,reopen_review,reopen_consumption,reopen_audit,postopen,postcheck=sys.argv[1:]
ref=lambda path:{'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()};rem=json.load(open(package));rep=json.load(open(reopen));pc=json.load(open(postcheck));rec=json.load(open(reconciliation))
value={'tool':'wapp-security-emergency-historical-execution-lineage','schema':1,'state':'LEGACY_RECONCILED_EXECUTION_AND_POSTOPEN_VERIFIED_HISTORICAL','domain':domain,'root':rem['site']['root'],'generated_at_epoch':int(now),'isolation_identity_sha256':pc['isolation_identity_sha256'],'remediation':{'package':ref(package),'review':ref(review),'operation_id':rem['operation_id'],'consumption_identity':ref(consumption),'provenance_class':'LEGACY_RECONCILED_EXECUTION','legacy_reconciliation':ref(reconciliation),'legacy_reconciliation_review':ref(reconciliation_review),'original_execution_audit_sha256':rec['original_execution_audit']['sha256']},'reopen':{'package':ref(reopen),'review':ref(reopen_review),'operation_id':rep['reopen_operation_id'],'remediation_operation_id':rem['operation_id'],'remediation_package_sha256':hashlib.sha256(open(package,'rb').read()).hexdigest(),'consumption_identity':ref(reopen_consumption),'execution_audit':ref(reopen_audit),'post_open_verification':ref(postopen)},'authority':False}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$legacy_historical_lineage";legacy_historical_review="$run/legacy-historical-lineage-review.json";make_review "$legacy_historical_lineage" "$legacy_historical_review"
legacy_historical_closure="$run/legacy-historical-closure.json"
python3 - "$historical_closure" "$legacy_historical_closure" "$legacy_historical_lineage" "$legacy_historical_review" <<'PY'
import hashlib,json,sys
source,out,lineage,review=sys.argv[1:];ref=lambda path:{'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()};value=json.load(open(source));value['historical_execution']={'lineage':ref(lineage),'review':ref(review)};open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$legacy_historical_closure"
python3 "$MODEL" verify-closure --record "$legacy_historical_closure" --domain "$domain" --now-epoch "$history_now" | grep -Fq WORDPRESS_INCIDENT_VERIFIED_CLEAN || fail legacy_reconciled_historical_closure
pass legacy_reconciled_execution_to_typed_closure

legacy_lineage_variant(){
  local name="$1" code="$2" out="$run/legacy-lineage-$name.json" review_out="$run/legacy-lineage-$name-review.json" closure_out="$run/legacy-lineage-$name-closure.json"
  python3 - "$legacy_historical_lineage" "$out" "$code" <<'PY'
import json,sys
source,out,code=sys.argv[1:];value=json.load(open(source));exec(code);open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$out";make_review "$out" "$review_out"
  python3 - "$legacy_historical_closure" "$closure_out" "$out" "$review_out" <<'PY'
import hashlib,json,sys
source,out,lineage,review=sys.argv[1:];ref=lambda path:{'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()};value=json.load(open(source));value['historical_execution']={'lineage':ref(lineage),'review':ref(review)};open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$closure_out";expect_fail "legacy_lineage_$name" python3 "$MODEL" verify-closure --record "$closure_out" --domain "$domain" --now-epoch "$history_now"
}
legacy_lineage_variant missing_reconciliation "del value['remediation']['legacy_reconciliation']"
legacy_lineage_variant wrong_package "value['remediation']['package']['sha256']='9'*64"
legacy_lineage_variant wrong_operation "value['remediation']['operation_id']='d'*32"
legacy_lineage_variant wrong_reopen "value['reopen']['remediation_operation_id']='d'*32"
legacy_lineage_variant wrong_site "value['root']='/home/user_99/app_99'"
legacy_lineage_variant fake_reconciliation "value['remediation']['legacy_reconciliation']=value['reopen']['execution_audit']"
legacy_lineage_variant normal_signed_pretence "value['state']='EXECUTED_AND_POSTOPEN_VERIFIED_HISTORICAL'"
legacy_lineage_variant wrong_provenance_class "value['remediation']['provenance_class']='SIGNED_EXECUTION_AUDIT'"
legacy_lineage_variant wrong_original_audit_sha "value['remediation']['original_execution_audit_sha256']='8'*64"
legacy_variant(){
  local name="$1" code="$2" out="$run/legacy-$name.json" out_review="$run/legacy-$name-review.json"
  python3 - "$legacy_attestation" "$out" "$code" <<'PY'
import json,sys
source,out,code=sys.argv[1:];value=json.load(open(source));exec(code);open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  chmod 600 "$out";sign "$out";make_review "$out" "$out_review"
  expect_fail "legacy_$name" python3 "$MODEL" verify-legacy-reconciliation --attestation "$out" --review "$out_review" --domain "$domain" --now-epoch "$history_now"
}
legacy_variant wrong_package_sha "value['package_sha256']='9'*64"
legacy_variant wrong_operation "value['operation_id']='d'*32"
legacy_variant missing_audit "del value['sources']['original_execution_audit']"
legacy_variant missing_poststate "del value['sources']['current_poststate']"
legacy_variant unverifiable_poststate "value['verified_poststate']['recurrence']=True"
legacy_variant authority "value['authority']=True"
legacy_variant action_contract_drift "value['action_contract']['identity_meta_rows']+=1"
legacy_variant reconciliation_before_expiry "value['generated_at_epoch']=json.load(open(value['sources']['package']['path']))['expires_at_epoch']-1"
legacy_chronology_variant(){
  local name="$1" audit_code="$2" poststate_code="$3" audit_out="$run/legacy-$name-audit.log" preserved_out="$run/legacy-$name-preserved.log" poststate_out="$run/legacy-$name-poststate.log" attestation_out="$run/legacy-$name-attestation.json" review_out="$run/legacy-$name-review.json"
  python3 - "$legacy_audit" "$audit_out" "$legacy_poststate" "$poststate_out" "$audit_code" "$poststate_code" <<'PY'
import hashlib,sys
audit_source,audit_out,post_source,post_out,audit_code,post_code=sys.argv[1:];audit=open(audit_source).read().splitlines();exec(audit_code);open(audit_out,'w').write('\n'.join(audit)+'\n');poststate=open(post_source).read().splitlines();poststate=[('original_audit_sha256='+hashlib.sha256(open(audit_out,'rb').read()).hexdigest()) if line.startswith('original_audit_sha256=') else line for line in poststate];exec(post_code);open(post_out,'w').write('\n'.join(poststate)+'\n')
PY
  chmod 600 "$audit_out" "$poststate_out";/bin/cp "$audit_out" "$preserved_out";chmod 600 "$preserved_out";sign "$poststate_out"
  python3 - "$legacy_attestation" "$attestation_out" "$audit_out" "$preserved_out" "$poststate_out" <<'PY'
import hashlib,json,os,stat,sys
source,out,audit,preserved,poststate=sys.argv[1:];value=json.load(open(source));ref=lambda path:{'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()};state=os.stat(audit);value['sources']['original_execution_audit']=ref(audit);value['sources']['preserved_execution_audit']=ref(preserved);value['sources']['current_poststate']=ref(poststate);value['sources']['current_poststate_hmac']=ref(poststate+'.hmac');value['original_execution_audit'].update({'sha256':ref(audit)['sha256'],'bytes':state.st_size,'device':str(state.st_dev),'inode':str(state.st_ino),'uid':state.st_uid,'gid':state.st_gid,'mode':format(stat.S_IMODE(state.st_mode),'04o'),'mtime_epoch':int(state.st_mtime)});open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  chmod 600 "$attestation_out";sign "$attestation_out";make_review "$attestation_out" "$review_out"
  expect_fail "legacy_$name" python3 "$MODEL" verify-legacy-reconciliation --attestation "$attestation_out" --review "$review_out" --domain "$domain" --now-epoch "$history_now"
}
legacy_chronology_variant marker_outside_audit_bounds "line=next(item for item in audit if '_FILES_QUARANTINED_V1|' in item);audit.remove(line);audit.insert(0,line)" "pass"
legacy_chronology_variant reversed_database_markers "a=next(i for i,item in enumerate(audit) if '_DB_APPLY_V1|' in item);b=next(i for i,item in enumerate(audit) if '_DB_AFTER_V1|' in item);audit[a],audit[b]=audit[b],audit[a]" "pass"
legacy_chronology_variant observation_end_before_begin "pass" "i=next(i for i,item in enumerate(poststate) if 'OBSERVATION_END index=0' in item);poststate[i]='2000-01-01T00:00:00Z\\tOBSERVATION_END index=0'"
legacy_chronology_variant future_http_evidence "pass" "i=next(i for i,item in enumerate(poststate) if 'HTTP_ISOLATION endpoint=public' in item);poststate[i]='2099-01-01T00:00:00Z\\tHTTP_ISOLATION endpoint=public route=/ denied=1'"
legacy_chronology_variant future_unknown_audit_record "audit.insert(-1,'2099-01-01T00:00:00Z\\tOPEN endpoint=public route=/ frame=403||0')" "pass"
legacy_chronology_variant timestamped_abort_record "stamp=audit[-1].split('\\t',1)[0];audit.insert(-1,stamp+'\\tABORT reason=synthetic')" "pass"
legacy_no_origin="$run/legacy-no-origin-poststate.log"
python3 - "$legacy_poststate" "$legacy_no_origin" <<'PY'
import sys
source,out=sys.argv[1:];lines=open(source).read().splitlines();open(out,'w').write('\n'.join(line for line in lines if 'endpoint=origin ' not in line)+'\n')
PY
chmod 600 "$legacy_no_origin";sign "$legacy_no_origin"
legacy_no_origin_attestation="$run/legacy-no-origin-attestation.json";legacy_no_origin_review="$run/legacy-no-origin-review.json"
python3 - "$legacy_attestation" "$legacy_no_origin_attestation" "$legacy_no_origin" <<'PY'
import hashlib,json,sys
source,out,poststate=sys.argv[1:];value=json.load(open(source));ref=lambda path:{'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()};value['sources']['current_poststate']=ref(poststate);value['sources']['current_poststate_hmac']=ref(poststate+'.hmac');open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
chmod 600 "$legacy_no_origin_attestation";sign "$legacy_no_origin_attestation";make_review "$legacy_no_origin_attestation" "$legacy_no_origin_review"
expect_fail legacy_observation_without_origin python3 "$MODEL" verify-legacy-reconciliation --attestation "$legacy_no_origin_attestation" --review "$legacy_no_origin_review" --domain "$domain" --now-epoch "$history_now"
cp "$legacy_audit" "$run/legacy-audit-backup";printf 'tampered\n' >>"$legacy_audit"
expect_fail legacy_tampered_original_audit python3 "$MODEL" verify-legacy-reconciliation --attestation "$legacy_attestation" --review "$legacy_review" --domain "$domain" --now-epoch "$history_now"
expect_fail legacy_lineage_tampered_original_audit python3 "$MODEL" verify-closure --record "$legacy_historical_closure" --domain "$domain" --now-epoch "$history_now"
mv "$run/legacy-audit-backup" "$legacy_audit"
pass legacy_reconciled_execution_explicit_weaker_path
printf 'PASS: Emergency Operator Mode v1 targeted matrix\n'
