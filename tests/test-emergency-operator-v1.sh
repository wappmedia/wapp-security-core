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
  expect_fail "reviewer_key_type_$spec" python3 "$MODEL" verify-review --review "$run/$spec-review.json" --package "$package" --domain "$domain"
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
touch "$run/consumed";expect_fail one_shot_replay python3 "$MODEL" verify-package --package "$package" --domain "$domain" --now-epoch "$now";rm "$run/consumed"
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
printf 'PASS: Emergency Operator Mode v1 targeted matrix\n'
