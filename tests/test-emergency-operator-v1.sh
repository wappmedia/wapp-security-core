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
TMP_RAW="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-emergency-v1)"
TMP="$(cd "$TMP_RAW"&&pwd -P)";trap 'rm -rf "$TMP" "${WAPP_EMERGENCY_TEST_OUTER_TMP:-}"' EXIT
source "$ROOT/lib/recovery-integrity.sh"
runtime_root="$TMP/reviewed private release"
export WAPP_EMERGENCY_REPORTS_ROOT="$runtime_root/reports"
domain='operator-fixture.test';run="$runtime_root/run with spaces";mkdir -p "$run" "$WAPP_EMERGENCY_REPORTS_ROOT/.control/emergency-operator-v1"
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
[[ "${WAPP_EMERGENCY_REPORTS_ROOT:-}" == /*/reports ]]||exit 20
if [[ -n "${WAPP_TEST_CLOSURE_REPLAY_PROBE:-}" ]];then
  : >"$WAPP_TEST_CLOSURE_REPLAY_PROBE"
fi
printf 'SYNTHETIC REVIEWED LAUNCHER — NO TARGET ACCESS\nREPORTS_ROOT=%s\n' "$WAPP_EMERGENCY_REPORTS_ROOT"
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
 {'order':1,'primitive':'QUARANTINE_EXACT_FILE','stage':'EXECUTABLE','target':{'path':'/home/user_42/app_42/wp-content/malicious file.php','parent_device':'1','parent_inode':'2','device':'1','inode':'3','mode':'0644','uid':'100042','gid':'100042','file_type':'REGULAR'},'before':{'sha256':one,'bytes':10},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':2,'primitive':'QUARANTINE_EXACT_FILE','stage':'EXECUTABLE','target':{'path':'/home/user_42/app_42/wp-content/z-malicious.php','parent_device':'1','parent_inode':'2','device':'1','inode':'4','mode':'0644','uid':'100042','gid':'100042','file_type':'REGULAR'},'before':{'sha256':two,'bytes':20},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':3,'primitive':'REPLACE_EXACT_FILE','stage':'CONFIG','target':{'path':'/home/user_42/app_42/wp-content/.user.ini','parent_device':'1','parent_inode':'2','device':'1','inode':'5','mode':'0644','uid':'100042','gid':'100042','file_type':'REGULAR'},'before':{'sha256':two,'bytes':20},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':4,'primitive':'REMOVE_EXACT_ACTIVE_PLUGIN','stage':'DATABASE','target':{'table':'options','option_id':33,'option_name':'active_plugins','member':'malicious/plugin.php','integer_key':7},'before':{'sha256':one,'bytes':100},'after':{'sha256':two,'bytes':80},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':5,'primitive':'REMOVE_EXACT_OPTION','stage':'DATABASE','target':{'table':'options','option_id':44,'option_name':'_incident_marker','autoload':'auto'},'before':{'sha256':two,'bytes':2},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'EXACT_ORIGINAL','automatic':True}},
 {'order':6,'primitive':'QUARANTINE_IDENTITY_ACCESS','stage':'IDENTITY','target':{'table':'usermeta','user_id':42,'session_policy':'NEVER_EXPORT_OR_RESTORE','incident_marker_policy':'NEVER_RESTORE','meta_rows':[{'umeta_id':101,'key_sha256':one,'value_sha256':two,'bytes':31,'disposition':'REMOVE_ROLE'},{'umeta_id':102,'key_sha256':two,'value_sha256':three,'bytes':1,'disposition':'REMOVE_LEVEL'},{'umeta_id':103,'key_sha256':three,'value_sha256':one,'bytes':64,'disposition':'INVALIDATE_SESSION'},{'umeta_id':104,'key_sha256':one,'value_sha256':three,'bytes':2,'disposition':'REMOVE_INCIDENT_MARKER'}]},'before':{'sha256':three,'bytes':98},'after':{'sha256':zero,'bytes':0},'rollback':{'artifact':ref('rollback.json'),'restores':'ROLE_LEVEL_ONLY','automatic':False}},
]
v={'tool':'wapp-security-emergency-operator-package','schema':1,'state':'LOCKED_REVIEWED_STOP_BEFORE_HUMAN_DECISION','phase':'REMEDIATION','contract':'HUMAN_OPERATOR_EMERGENCY_SELF_ISOLATED','classification':'YELLOW_SELF_REMEDIATION','domain':domain,'operation_id':'a'*32,'generated_at_epoch':now,'expires_at_epoch':now+3600,'site':{'site_id':'42','root':'/home/user_42/app_42','root_device':'1','root_inode':'2','ssh_endpoint':'user_42@192.0.2.42:22042','origin_ip':'192.0.2.42'},'product':{'commit':commit,'seal':ref('product.json')},'evidence':{'incident':ref('incident.json'),'prestate':ref('prestate.json'),'rollback_index':ref('rollback-index.json')},'isolation':{'method':'SELF_MANAGED_ATOMIC_DOCROOT_ISOLATION','public_origin_required':True,'accepted_https_statuses':[401,403,404,410,503],'stability_seconds':600,'exact_reverse_reopen':True},'actions':actions,'continuation':None,'human_gate':{'required':True,'phrase_format':'RENSA <DOMAIN> <PACKAGE_SHA256_12>'},'one_shot':{'required':True,'consumption_marker':os.path.join(run,'consumed')},'forensic_record':ref('forensic.json'),'independent_review':{'required_result':'PASS_NO_P0_P1_P2'},'launcher':ref('launcher'),'portability':{'bash_3_2':True,'db_integrity':'NATIVE_READ_ONLY_FALLBACK','blocked_http':'STATUS_SEMANTICS_NO_MIN_BODY'},'failure_policy':{'recurrence':'ABORT_RED_EXTERNAL_REQUIRED','partial_execution':'RECONCILE_NO_RETRY','blind_retry':False,'scope_expansion':False},'authority':{'canonical_ready':False,'provider_authorized':False,'autonomous_mutation':False,'closure':False}}
open(package,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$package";package_sha="$(recovery_sha256_file "$package")"
review="$run/review.json";make_review "$package" "$review"
postcheck="$run/execution-postcheck.json";reopen="$run/reopen-package.json";reopen_review="$run/reopen-review.json";reopen_postcheck="$run/reopen-postcheck.json";closure="$run/closure.json"
registry="$WAPP_EMERGENCY_REPORTS_ROOT/.control/emergency-operator-v1/$domain.json"
python3 - "$package" "$review" "$registry" "$domain" <<'PY'
import hashlib,json,sys
package,review,out,domain=sys.argv[1:]
def ref(p):return {'path':p,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}
v={'tool':'wapp-security-emergency-operator-registry','schema':1,'domain':domain,'remediation':{'package':ref(package),'review':ref(review)},'reopen':None,'closure':None}
open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$registry"

build_consumed_reopen_fixture(){
  local plan="$run/coherent-plan.json" audit="$run/coordinator-execution-audit.log"
  local observation="$run/current-isolated-observation.json" source_registry="$run/source-registry.json"
  local predecessor_reservation="$run/consumed/reopen-reservation.json"
  local predecessor_reopen="$run/predecessor-reopen-package.json" predecessor_review="$run/predecessor-reopen-review.json"
  local predecessor_consumed="$run/predecessor-reopen-consumed/package-sha256"
  local disposition="$run/predecessor-reopen-disposition.json" disposition_review="$run/predecessor-reopen-disposition-review.json"
  mkdir -m 700 "$run/consumed"
  printf '%s\n' "$package_sha" >"$run/consumed/package-sha256";chmod 600 "$run/consumed/package-sha256";sign "$run/consumed/package-sha256"
  python3 - "$package" "$review" "$run" "$plan" "$audit" "$observation" "$source_registry" "$predecessor_reservation" "$postcheck" "$predecessor_reopen" "$predecessor_consumed" "$domain" "$now" <<'PY'
import datetime,hashlib,json,os,sys
package,review,run,plan_path,audit_path,observation_path,registry_path,reservation_path,postcheck_path,reopen_path,predecessor_consumed,domain,now=sys.argv[1:]
now=int(now);source=json.load(open(package));source_sha=hashlib.sha256(open(package,'rb').read()).hexdigest()
def dump(path,value): open(path,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
def ref(path): return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
consumer_for={'QUARANTINE_EXACT_FILE':'BOUNDED_QUARANTINE_EXACT_FILE','REPLACE_EXACT_FILE':'BOUNDED_REPLACE_EXACT_FILE','REMOVE_EXACT_ACTIVE_PLUGIN':'BOUNDED_REMOVE_EXACT_ACTIVE_PLUGIN','REMOVE_EXACT_OPTION':'BOUNDED_REMOVE_EXACT_OPTION','QUARANTINE_IDENTITY_ACCESS':'BOUNDED_IDENTITY_QUARANTINE'}
dispatch=[]
for index,action in enumerate(source['actions'],1):
    if action['primitive']=='QUARANTINE_EXACT_FILE' and any(item['consumer']=='BOUNDED_QUARANTINE_EXACT_FILE' for item in dispatch):
        continue
    binding=os.path.join(run,f'dispatch-binding-{index}.json')
    if action['primitive']=='QUARANTINE_EXACT_FILE':
        grouped=[item for item in source['actions'] if item['primitive']=='QUARANTINE_EXACT_FILE'];orders=[item['order'] for item in grouped];target_rows=[];parent_rows=[]
        for item in grouped:
            target=item['target'];relative=target['path'][len(source['site']['root'])+1:]
            target_rows.append('\t'.join((relative.encode().hex(),item['before']['sha256'],str(item['before']['bytes']),str(int(target['mode'],8)),target['uid'],target['gid'],target['device'],target['inode'])))
            parent_rows.append(f"{target['parent_device']}\t{target['parent_inode']}")
        target_raw=('\n'.join(target_rows)+'\n').encode();parent_raw=('\n'.join(parent_rows)+'\n').encode();product=json.load(open(source['product']['seal']['path']));components={item['path']:item['sha256'] for item in product['components']}
        dump(binding,{'tool':'wapp-security-bounded-exact-file-binding','schema':1,'state':'PREPARED_NO_MUTATION','domain':domain,'canonical_root':source['site']['root'],'operation_id':source['operation_id'],'package_sha256':source_sha,'action_orders':orders,'target_count':len(orders),'target_manifest_sha256':hashlib.sha256(target_raw).hexdigest(),'parent_manifest_sha256':hashlib.sha256(parent_raw).hexdigest(),'helper_artifact_sha256':components['libexec/wapp-native-exact-file-quarantine-linux-x86_64.b64.txt'],'launcher_artifact_sha256':components['libexec/wapp-native-exact-file-quarantine-ephemeral-memfd-launcher-linux-x86_64.b64.txt'],'loader_sha256':components['lib/native-exact-file-quarantine-ephemeral-loader.sh'],'authority':False})
    else:
        dump(binding,{'tool':'synthetic-bounded-dispatch-binding','schema':1,'operation_id':source['operation_id'],'action_order':index,'primitive':action['primitive'],'authority':False})
        orders=[index]
    dispatch.append({'order':len(dispatch)+1,'stage':action['stage'],'consumer':consumer_for[action['primitive']],'action_count':len(orders),'action_orders':orders,'binding':ref(binding)})
plan={'tool':'wapp-security-human-operator-emergency-coordinator-plan','schema':1,'state':'PREPARED_NO_MUTATION','domain':domain,'operation_id':source['operation_id'],'root':source['site']['root'],'site_identity':{'domain':domain,'wordpress_root':source['site']['root']},'package':ref(package),'private_product_commit':source['product']['commit'],'public_core_commit':source['product']['commit'],'coordinator':ref(os.path.join(run,'launcher')),'sites_config_sha256':'1'*64,'action_contract_sha256':hashlib.sha256(canonical(source['actions'])+b'\n').hexdigest(),'action_count':len(source['actions']),'dispatch_count':len(dispatch),'dispatch':dispatch,'apply_order':[item['consumer'] for item in dispatch],'rollback_order':[item['consumer'] for item in reversed(dispatch)],'stages':['PREPARED','FILES_APPLIED','DB_APPLIED','IDENTITY_APPLIED','POSTCHECK_VERIFIED'],'human_operator_required':True,'bounded_consumers_own_exact_mutations':True,'filesystem_database_acid_claimed':False,'scope_expansion_allowed':False,'arbitrary_sql_allowed':False,'canonical_ready_claimed':False,'mutation_authority':False}
dump(plan_path,plan)
isolated='/home/user_42/.wapp-security/human-emergency/'+source['operation_id']+'/app_42'
result_hashes=[];native_receipts=[]
for index,item in enumerate(dispatch,1):
    if item['consumer']=='BOUNDED_QUARANTINE_EXACT_FILE':
        binding=json.load(open(item['binding']['path']));receipt_path=os.path.join(run,f'exact-file-receipt-{index}.json')
        receipt={'tool':'wapp-security-bounded-exact-file-result','schema':1,'state':'QUARANTINED_EXACT','domain':domain,'canonical_root':source['site']['root'],'execution_root':isolated,'root_device':source['site']['root_device'],'root_inode':source['site']['root_inode'],'operation_id':source['operation_id'],'package_sha256':source_sha,'action_orders':item['action_orders'],'target_count':item['action_count'],'target_manifest_sha256':binding['target_manifest_sha256'],'parent_manifest_sha256':binding['parent_manifest_sha256'],'quarantine_device':'1','quarantine_inode':'6','helper_artifact_sha256':binding['helper_artifact_sha256'],'launcher_artifact_sha256':binding['launcher_artifact_sha256'],'loader_sha256':binding['loader_sha256'],'runtime_identity_sha256':'6'*64,'source_paths_absent':True,'quarantine_objects_exact':True,'target_cardinality_verified':True,'poststate_verified':True,'reconciliation_used':False,'isolation_remains':True,'generated_at_epoch':now,'authority':False};dump(receipt_path,receipt);result_hashes.append(ref(receipt_path)['sha256']);native_receipts.append(ref(receipt_path))
    else: result_hashes.append(str(index%10)*64);native_receipts.append(None)
stamp=datetime.datetime.fromtimestamp(now,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
lines=[f'{stamp}\tPREPARED package={source_sha} operation={source["operation_id"]} plan={hashlib.sha256(open(plan_path,"rb").read()).hexdigest()} one_shot_claimed=true incident_mutation_started=false',f'{stamp}\tISOLATION_VERIFIED rebind_sha256={"3"*64} canonical_root_absent=true public_origin_denied=true incident_mutation_started=false']
for index,item in enumerate(dispatch,1): lines.append(f'{stamp}\tDISPATCH_VERIFIED order={index} consumer={item["consumer"]} result_sha256={result_hashes[index-1]}')
lines.append(f'{stamp}\tPOSTCHECK_VERIFIED completed={len(dispatch)} isolation_remains=true separate_reopen_authority_required=true')
open(audit_path,'w').write('\n'.join(lines)+'\n')
observation={'tool':'wapp-security-isolated-root-observation','schema':2,'state':'ISOLATED_EXACT','domain':domain,'operation_id':source['operation_id'],'canonical_root':source['site']['root'],'isolated_root':isolated,'canonical_root_present':False,'isolated_root_present':True,'path_chain_no_symlinks':True,'root':{'device':'1','inode':'2','type':'directory','nlink':'2','uid':'42','gid':'42','mode':'0755','size':'4096','mtime_ns':'1','ctime_ns':'2'},'wp_config':{'relative_path':'wp-config.php','device':'1','inode':'4','type':'file','nlink':'1','uid':'42','gid':'42','mode':'0644','size':'100','mtime_ns':'1','ctime_ns':'2','sha256':'4'*64,'symlink':False},'private_parents':[{'path':'/home/user_42/.wapp-security','device':'1','inode':'5','type':'directory','uid':'42','gid':'42','mode':'0700','mtime_ns':'1','ctime_ns':'1','symlink':False}], 'capture_nonce':'5'*64,'captured_at_epoch':now}
dump(observation_path,observation)
registry={'tool':'wapp-security-emergency-operator-registry','schema':1,'domain':domain,'remediation':{'package':ref(package),'review':ref(review)},'reopen':None,'closure':None};dump(registry_path,registry)
isolation=hashlib.sha256(canonical({'site':source['site'],'isolation':source['isolation']})).hexdigest()
results=[{'order':index,'consumer':item['consumer'],'result_sha256':result_hashes[index-1],'primitive_orders':item['action_orders'],'mutation_state':'COMPLETED_AS_DECLARED','poststate_verified':True,'target_cardinality_verified':True,'native_receipt':native_receipts[index-1]} for index,item in enumerate(dispatch,1)]
postcheck={'tool':'wapp-security-emergency-execution-postcheck','schema':2,'state':'APPLIED_EXACT_AND_POSTCHECK_VERIFIED_YELLOW','domain':domain,'root':source['site']['root'],'remediation_operation_id':source['operation_id'],'remediation_package_sha256':source_sha,'isolation_identity_sha256':isolation,'isolated_root':isolated,'isolation_active':True,'recurrence':False,'incident_targets_absent':True,'coherent_plan_sha256':hashlib.sha256(open(plan_path,'rb').read()).hexdigest(),'execution_audit_sha256':hashlib.sha256(open(audit_path,'rb').read()).hexdigest(),'expected_dispatch_count':len(dispatch),'dispatch_results':results,'exact_mutation_state':'COMPLETED_AS_DECLARED','generated_at_epoch':now,'authority':False};dump(postcheck_path,postcheck)
reopen=json.loads(json.dumps(source));reopen['phase']='REOPEN';reopen['operation_id']='b'*32;reopen['generated_at_epoch']=now;reopen['expires_at_epoch']=now+3600
reopen['actions']=[{'order':1,'primitive':'REOPEN_ATOMIC_DOCROOT','stage':'REOPEN','target':{'canonical_root':source['site']['root'],'isolated_root':isolated,'device':'1','inode':'2'},'before':{'sha256':'1'*64,'bytes':1},'after':{'sha256':'2'*64,'bytes':1},'rollback':{'artifact':source['evidence']['rollback_index'],'restores':'EXACT_ORIGINAL','automatic':True}}]
reopen['continuation']={'remediation_package':ref(package),'remediation_review':ref(review),'remediation_registry':ref(registry_path),'remediation_consumption_identity':ref(os.path.join(run,'consumed/package-sha256')),'coherent_plan':ref(plan_path),'execution_audit':ref(audit_path),'execution_postcheck':ref(postcheck_path),'current_isolation':ref(observation_path),'reopen_reservation':{'path':reservation_path,'sha256':'0'*64},'isolation_identity_sha256':isolation}
reopen['human_gate']['phrase_format']='ÅTERÖPPNA <DOMAIN> <PACKAGE_SHA256_12>';reopen['one_shot']['consumption_marker']=os.path.dirname(predecessor_consumed)
committed=json.loads(json.dumps(reopen));del committed['continuation']['reopen_reservation'];authority_sha=hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
reservation={'tool':'wapp-security-emergency-reopen-reservation','schema':1,'state':'RESERVED_FOR_DISTINCT_REOPEN','domain':domain,'root':source['site']['root'],'source_operation_id':source['operation_id'],'source_package_sha256':source_sha,'reopen_operation_id':reopen['operation_id'],'created_at_epoch':now,'expires_at_epoch':now+3600,'reopen_authority_sha256':authority_sha,'source_replay_allowed':False,'authority':False};dump(reservation_path,reservation)
reopen['continuation']['reopen_reservation']=ref(reservation_path);dump(reopen_path,reopen)
PY
  for file in "$run"/dispatch-binding-*.json "$run"/exact-file-receipt-*.json "$plan" "$audit" "$observation" "$source_registry" "$predecessor_reservation" "$postcheck" "$predecessor_reopen";do sign "$file";done
  make_review "$predecessor_reopen" "$predecessor_review"
  mkdir -m 700 "$(dirname "$predecessor_consumed")"
  recovery_sha256_file "$predecessor_reopen" >"$predecessor_consumed";chmod 600 "$predecessor_consumed";sign "$predecessor_consumed"
  python3 - "$package" "$predecessor_reopen" "$predecessor_reservation" "$predecessor_consumed" "$disposition" "$domain" "$now" <<'PY'
import hashlib,json,sys
source_path,predecessor_path,reservation_path,consumption_path,out,domain,now=sys.argv[1:]
source=json.load(open(source_path));predecessor=json.load(open(predecessor_path))
sha=lambda path:hashlib.sha256(open(path,'rb').read()).hexdigest()
value={'tool':'wapp-security-emergency-reopen-predecessor-disposition','schema':1,'state':'CONSUMED_PRE_REMOTE_ABORT_VERIFIED_UNMUTATED','domain':domain,'root':source['site']['root'],'source_operation_id':source['operation_id'],'source_package_sha256':sha(source_path),'predecessor_reopen_operation_id':predecessor['operation_id'],'predecessor_reopen_package_sha256':sha(predecessor_path),'predecessor_reservation_sha256':sha(reservation_path),'predecessor_consumption_sha256':sha(consumption_path),'abort_stage':'PRE_REMOTE_SITE_IDENTITY_BINDING','remote_access_started':False,'isolation_activated':False,'customer_mutation_state':'NONE','replay_allowed':False,'supersession_authority':'NEW_REOPEN_PACKAGE_ONLY','generated_at_epoch':int(now),'authority':False}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$disposition";make_review "$disposition" "$disposition_review"
  local reservation="$run/consumed/reopen-successors/$(recovery_sha256_file "$predecessor_reservation").json"
  mkdir -m 700 "$run/consumed/reopen-successors"
  python3 - "$predecessor_reopen" "$predecessor_review" "$predecessor_consumed" "$predecessor_reservation" "$disposition" "$disposition_review" "$reservation" "$reopen" "$now" <<'PY'
import hashlib,json,os,sys
predecessor_path,predecessor_review,consumption,reservation_before,disposition,disposition_review,reservation_path,out,now=sys.argv[1:]
now=int(now);reopen=json.load(open(predecessor_path))
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
reopen['operation_id']='c'*32;reopen['generated_at_epoch']=now;reopen['expires_at_epoch']=now+3600
reopen['one_shot']['consumption_marker']=os.path.join(os.path.dirname(out),'successor-reopen-consumed')
committed=json.loads(json.dumps(reopen));del committed['continuation']['reopen_reservation']
authority_sha=hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
predecessor={'reservation':ref(reservation_before),'package':ref(predecessor_path),'review':ref(predecessor_review),'consumption_identity':ref(consumption),'disposition':ref(disposition),'disposition_review':ref(disposition_review)}
reservation={'tool':'wapp-security-emergency-reopen-reservation','schema':2,'state':'RESERVED_FOR_DISTINCT_REOPEN','domain':reopen['domain'],'root':reopen['site']['root'],'source_operation_id':json.load(open(reopen['continuation']['remediation_package']['path']))['operation_id'],'source_package_sha256':reopen['continuation']['remediation_package']['sha256'],'reopen_operation_id':reopen['operation_id'],'created_at_epoch':now,'expires_at_epoch':now+3600,'reopen_authority_sha256':authority_sha,'source_replay_allowed':False,'authority':False,'predecessor':predecessor}
open(reservation_path,'w').write(json.dumps(reservation,sort_keys=True,separators=(',',':'))+'\n')
reopen['continuation']['reopen_reservation']=ref(reservation_path)
open(out,'w').write(json.dumps(reopen,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$reservation";sign "$reopen"
  reopen_sha="$(recovery_sha256_file "$reopen")";make_review "$reopen" "$reopen_review"
  python3 - "$run" "$closure" "$domain" "$now" "$package" "$review" "$reopen" "$reopen_review" "$reopen_postcheck" "$registry" <<'PY'
import hashlib,json,os,sys
run,out,domain,now,package,review,reopen,reopen_review,reopen_postcheck,registry=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),*sys.argv[5:]
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
rem=json.load(open(package));rep=json.load(open(reopen));checks={'critical':0,'high':0,'filesystem_complete':True,'database_complete':True,'runtime_ok':True,'recurrence':False,'unknown_executable_persistence':False,'unresolved_malicious_privileged_access':False,'incident_targets_absent':True}
evidence=os.path.join(run,'closure-evidence.json');value={'tool':'wapp-security-emergency-closure-evidence','schema':1,'domain':domain,'root':rem['site']['root'],'operation_id':rem['operation_id'],'product_commit':rem['product']['commit'],'generated_at_epoch':now,'scan':{'critical':0,'high':0},'coverage':{'filesystem_complete':True,'database_complete':True,'runtime_ok':True},'recurrence':{'detected':False,'unknown_executable_persistence':False,'incident_targets_absent':True},'identity':{'unresolved_malicious_privileged_access':False}};open(evidence,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
post={'tool':'wapp-security-emergency-reopen-postcheck','schema':1,'state':'POSTOPEN_VERIFIED_YELLOW','domain':domain,'root':rem['site']['root'],'reopen_operation_id':rep['operation_id'],'reopen_package_sha256':ref(reopen)['sha256'],'remediation_operation_id':rem['operation_id'],'remediation_package_sha256':ref(package)['sha256'],'generated_at_epoch':now,'isolation_reversed':True,'post_open_verified':True,'recurrence':False,'incident_targets_absent':True};open(reopen_postcheck,'w').write(json.dumps(post,sort_keys=True,separators=(',',':'))+'\n')
closure={'tool':'wapp-security-emergency-closure-record','schema':1,'domain':domain,'root':rem['site']['root'],'operation_id':rem['operation_id'],'generated_at_epoch':now,'fresh_until_epoch':now+3600,'product':rem['product'],'remediation':{'package':ref(package),'review':ref(review)},'reopen':{'package':ref(reopen),'review':ref(reopen_review),'execution_postcheck':ref(reopen_postcheck)},'evidence':[ref(evidence)],'checks':checks,'assurance_limitations':[],'hardening_findings':['synthetic permission hardening'],'authority':False};open(out,'w').write(json.dumps(closure,sort_keys=True,separators=(',',':'))+'\n')
active={'tool':'wapp-security-emergency-operator-registry','schema':1,'domain':domain,'remediation':{'package':ref(package),'review':ref(review)},'reopen':{'package':ref(reopen),'review':ref(reopen_review)},'closure':{'record':ref(out)}};open(registry,'w').write(json.dumps(active,sort_keys=True,separators=(',',':'))+'\n')
PY
  for file in "$run/closure-evidence.json" "$reopen_postcheck" "$closure" "$registry";do sign "$file";done
}

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
launcher_sha="$(recovery_sha256_file "$run/launcher")"
python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha" >"$TMP/execute.out"
grep -Fq 'SYNTHETIC REVIEWED LAUNCHER — NO TARGET ACCESS' "$TMP/execute.out"||fail pinned_launcher_execution
grep -Fqx "REPORTS_ROOT=$WAPP_EMERGENCY_REPORTS_ROOT" "$TMP/execute.out"||fail package_bound_reports_handoff
pass pinned_launcher_execution
pass package_bound_reports_handoff
expect_fail missing_reports_handoff env -u WAPP_EMERGENCY_REPORTS_ROOT python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
expect_fail nonnormalized_reports_handoff env WAPP_EMERGENCY_REPORTS_ROOT="$runtime_root/./reports" python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
mkdir -p "$TMP/outside-runtime";cp "$run/launcher" "$TMP/outside-runtime/launcher";chmod 700 "$TMP/outside-runtime/launcher"
expect_fail launcher_outside_package_runtime python3 "$MODEL" exec-launcher --launcher "$TMP/outside-runtime/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
mkdir -p "$runtime_root/physical-parent";cp "$run/launcher" "$runtime_root/physical-parent/launcher";chmod 700 "$runtime_root/physical-parent/launcher";ln -s physical-parent "$runtime_root/symlink-parent"
expect_fail launcher_symlink_parent python3 "$MODEL" exec-launcher --launcher "$runtime_root/symlink-parent/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
rm "$runtime_root/symlink-parent"
chmod 0777 "$runtime_root/physical-parent"
expect_fail writable_launcher_parent python3 "$MODEL" exec-launcher --launcher "$runtime_root/physical-parent/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
chmod 0755 "$runtime_root/physical-parent"
mv "$WAPP_EMERGENCY_REPORTS_ROOT" "$runtime_root/reports.physical";ln -s reports.physical "$WAPP_EMERGENCY_REPORTS_ROOT"
expect_fail reports_handoff_symlink python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
rm "$WAPP_EMERGENCY_REPORTS_ROOT";mv "$runtime_root/reports.physical" "$WAPP_EMERGENCY_REPORTS_ROOT"
read -r _runtime_owner runtime_mode <<<"$(recovery_stat_owner_mode "$runtime_root")";chmod 0777 "$runtime_root"
expect_fail writable_package_runtime python3 "$MODEL" exec-launcher --launcher "$run/launcher" --sha256 "$launcher_sha" --package-sha256 "$package_sha"
chmod "$runtime_mode" "$runtime_root"
build_consumed_reopen_fixture
expect_fail consumed_remediation_replay python3 "$MODEL" verify-package --package "$package" --domain "$domain" --now-epoch "$now"
[[ "$(python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now" | python3 -c 'import json,sys;print(json.load(sys.stdin)["human_phrase"])')" == "ÅTERÖPPNA $domain ${reopen_sha:0:12}" ]] || fail reopen_phrase;pass separate_reopen_contract
python3 - "$MODEL" <<'PY'
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('contract',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
value=[{'order':1,'primitive':'REMOVE_EXACT_OPTION'}]
assert module.canonical_digest(value) != module.canonical_line_digest(value)
assert module.canonical_digest(value) == __import__('hashlib').sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
assert module.canonical_line_digest(value) == __import__('hashlib').sha256((json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()).hexdigest()
PY
pass reopen_action_contract_digest_forms
python3 - "$MODEL" <<'PY'
import importlib.util,sys
spec=importlib.util.spec_from_file_location('contract',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
ts=r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z';stamp='2026-08-29T05:04:49Z';operation='a'*32;previous='b'*32;sha='3'*64
normal=f'{stamp}\tISOLATION_VERIFIED rebind_sha256={sha} canonical_root_absent=true public_origin_denied=true incident_mutation_started=false'
continuation=f'{stamp}\tCONTINUATION_ISOLATION_VERIFIED rebind_sha256={sha} previous_operation={previous} completed_file_replay_forbidden=true canonical_root_absent=true incident_mutation_started=false'
assert module.execution_audit_isolation_line_matches(normal,ts,operation,['BOUNDED_REMOVE_EXACT_OPTION'])
assert module.execution_audit_isolation_line_matches(continuation,ts,operation,['BOUNDED_REMOVE_EXACT_OPTION','BOUNDED_REMOVE_EXACT_CRON_EVENT','BOUNDED_IDENTITY_QUARANTINE'])
assert not module.execution_audit_isolation_line_matches(continuation.replace(previous,operation),ts,operation,['BOUNDED_REMOVE_EXACT_OPTION'])
assert not module.execution_audit_isolation_line_matches(continuation,ts,operation,['BOUNDED_QUARANTINE_EXACT_FILE'])
assert not module.execution_audit_isolation_line_matches(continuation.replace('completed_file_replay_forbidden=true ','') ,ts,operation,['BOUNDED_REMOVE_EXACT_OPTION'])
assert not module.execution_audit_isolation_line_matches(continuation.replace('canonical_root_absent=true','canonical_root_absent=false'),ts,operation,['BOUNDED_REMOVE_EXACT_OPTION'])
PY
pass reopen_continuation_isolation_audit_compatibility
reservation_namespace="$run/consumed/reopen-successors"
chmod 0777 "$reservation_namespace"
expect_fail reopen_reservation_writable_parent python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now"
chmod 0700 "$reservation_namespace"
mv "$reservation_namespace" "$reservation_namespace.physical";ln -s "$reservation_namespace.physical" "$reservation_namespace"
expect_fail reopen_reservation_symlink_parent python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now"
rm "$reservation_namespace";mv "$reservation_namespace.physical" "$reservation_namespace"
current_reservation="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["continuation"]["reopen_reservation"]["path"])' "$reopen")"
chmod 0666 "$current_reservation"
expect_fail reopen_reservation_writable_file python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now"
chmod 0600 "$current_reservation"
mv "$current_reservation" "$current_reservation.physical";ln -s "$current_reservation.physical" "$current_reservation"
expect_fail reopen_reservation_symlink_file python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now"
rm "$current_reservation";mv "$current_reservation.physical" "$current_reservation"
nested_reservation="$run/consumed/reopen-successors/$(recovery_sha256_file "$current_reservation").json";nested_reopen="$run/reopen-nested-successor.json"
python3 - "$reopen" "$reopen_review" "$current_reservation" "$nested_reservation" "$nested_reopen" <<'PY'
import hashlib,json,os,sys
source,review,current,reservation_path,out=sys.argv[1:]
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
package=json.load(open(source));package['operation_id']='d'*32;package['one_shot']['consumption_marker']=os.path.join(os.path.dirname(out),'nested-consumed')
reservation=json.load(open(current));reservation['reopen_operation_id']=package['operation_id'];reservation['predecessor']={'reservation':ref(current),'package':ref(source),'review':ref(review),'consumption_identity':ref(source),'disposition':ref(current),'disposition_review':ref(review)}
open(reservation_path,'w').write(json.dumps(reservation,sort_keys=True,separators=(',',':'))+'\n')
package['continuation']['reopen_reservation']=ref(reservation_path);open(out,'w').write(json.dumps(package,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$nested_reservation";sign "$nested_reopen"
expect_fail reopen_schema2_predecessor_chain python3 "$MODEL" verify-package --package "$nested_reopen" --domain "$domain" --now-epoch "$now"
rm "$nested_reservation" "$nested_reservation.hmac" "$nested_reopen" "$nested_reopen.hmac"
unconsumed_registry="$run/unconsumed-successor-registry.json"
unconsumed_disposition="$run/unconsumed-successor-disposition.json"
unconsumed_disposition_review="$run/unconsumed-successor-disposition-review.json"
schema3_reservation="$run/consumed/reopen-successors/$(recovery_sha256_file "$current_reservation").json"
schema3_reopen="$run/reopen-schema3-unconsumed-successor.json"
schema3_observation="$run/schema3-current-isolated-observation.json"
python3 - "$reopen" "$reopen_review" "$current_reservation" "$unconsumed_registry" "$unconsumed_disposition" "$schema3_reservation" "$schema3_reopen" "$schema3_observation" "$now" <<'PY'
import hashlib,json,os,sys
source,review,current,registry_path,disposition_path,reservation_path,out,observation_out,now=sys.argv[1:];now=int(now);successor_now=now+3601
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
def write(path,value):open(path,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
package=json.load(open(source));source_sha=ref(source)['sha256'];current_ref=ref(current)
registry={'tool':'wapp-security-emergency-operator-registry','schema':1,'domain':package['domain'],'remediation':json.load(open(package['continuation']['remediation_registry']['path']))['remediation'],'reopen':{'package':ref(source),'review':ref(review)},'closure':None};write(registry_path,registry)
remediation=json.load(open(package['continuation']['remediation_package']['path']))
disposition={'tool':'wapp-security-emergency-reopen-unconsumed-predecessor-disposition','schema':1,'state':'REGISTERED_UNCONSUMED_PRECONSUMPTION_ABORT_VERIFIED_UNMUTATED','domain':package['domain'],'root':package['site']['root'],'source_operation_id':remediation['operation_id'],'source_package_sha256':package['continuation']['remediation_package']['sha256'],'predecessor_reopen_operation_id':package['operation_id'],'predecessor_reopen_package_sha256':source_sha,'predecessor_reservation_sha256':current_ref['sha256'],'predecessor_registry_sha256':'0'*64,'predecessor_expires_at_epoch':package['expires_at_epoch'],'predecessor_expired_before_successor':True,'consumption_marker_absent':True,'runtime_directory_absent':True,'remote_access_started':False,'reverse_rename_started':False,'customer_mutation_state':'NONE','replay_allowed':False,'supersession_authority':'NEW_REOPEN_PACKAGE_ONLY','generated_at_epoch':successor_now,'authority':False}
write(registry_path,registry);disposition['predecessor_registry_sha256']=ref(registry_path)['sha256'];write(disposition_path,disposition)
observation_path=package['continuation']['current_isolation']['path'];observation=json.load(open(observation_path));observation['captured_at_epoch']=successor_now;write(observation_out,observation)
successor=json.loads(json.dumps(package));successor['operation_id']='e'*32;successor['generated_at_epoch']=successor_now;successor['expires_at_epoch']=successor_now+3600;successor['one_shot']['consumption_marker']=os.path.join(os.path.dirname(out),'schema3-consumed');successor['continuation']['current_isolation']=ref(observation_out)
committed=json.loads(json.dumps(successor));del committed['continuation']['reopen_reservation'];authority=hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
predecessor={'reservation':current_ref,'package':ref(source),'review':ref(review),'registry':ref(registry_path),'disposition':ref(disposition_path),'disposition_review':{'path':sys.argv[0] if False else '', 'sha256':'0'*64}}
reservation={'tool':'wapp-security-emergency-reopen-reservation','schema':3,'state':'RESERVED_FOR_DISTINCT_REOPEN','domain':successor['domain'],'root':successor['site']['root'],'source_operation_id':remediation['operation_id'],'source_package_sha256':successor['continuation']['remediation_package']['sha256'],'reopen_operation_id':successor['operation_id'],'created_at_epoch':successor_now,'expires_at_epoch':successor_now+3600,'reopen_authority_sha256':authority,'source_replay_allowed':False,'authority':False,'unconsumed_predecessor':predecessor}
write(reservation_path,reservation);successor['continuation']['reopen_reservation']=ref(reservation_path);write(out,successor)
PY
sign "$unconsumed_registry";sign "$unconsumed_disposition";sign "$schema3_observation";make_review "$unconsumed_disposition" "$unconsumed_disposition_review"
python3 - "$schema3_reservation" "$unconsumed_disposition_review" "$schema3_reopen" <<'PY'
import hashlib,json,sys
reservation_path,review_path,package_path=sys.argv[1:]
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
reservation=json.load(open(reservation_path));reservation['unconsumed_predecessor']['disposition_review']=ref(review_path);open(reservation_path,'w').write(json.dumps(reservation,sort_keys=True,separators=(',',':'))+'\n')
package=json.load(open(package_path));package['continuation']['reopen_reservation']=ref(reservation_path);open(package_path,'w').write(json.dumps(package,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$schema3_reservation";sign "$schema3_reopen"
schema3_now="$((now+3601))"
overlap_backup="$run/schema3-overlap-backup";mkdir "$overlap_backup"
for artifact in "$unconsumed_disposition" "$unconsumed_disposition.hmac" "$unconsumed_disposition_review" "$unconsumed_disposition_review.hmac" "$schema3_reservation" "$schema3_reservation.hmac" "$schema3_reopen" "$schema3_reopen.hmac";do /bin/cp "$artifact" "$overlap_backup/$(basename "$artifact")";done
python3 - "$reopen" "$unconsumed_disposition" "$schema3_reservation" "$schema3_reopen" "$now" <<'PY'
import hashlib,json,sys
predecessor_path,disposition_path,reservation_path,package_path,now=sys.argv[1:];now=int(now)
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
def write(path,value):open(path,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
predecessor=json.load(open(predecessor_path))
disposition=json.load(open(disposition_path));disposition['generated_at_epoch']=now;write(disposition_path,disposition)
package=json.load(open(package_path));package['generated_at_epoch']=now;package['expires_at_epoch']=now+1800;package['continuation']['current_isolation']=predecessor['continuation']['current_isolation']
committed=json.loads(json.dumps(package));del committed['continuation']['reopen_reservation'];authority=hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
reservation=json.load(open(reservation_path));reservation['created_at_epoch']=now;reservation['expires_at_epoch']=now+1800;reservation['reopen_authority_sha256']=authority;write(reservation_path,reservation)
package['continuation']['reopen_reservation']=ref(reservation_path);write(package_path,package)
PY
sign "$unconsumed_disposition";make_review "$unconsumed_disposition" "$unconsumed_disposition_review"
python3 - "$schema3_reservation" "$unconsumed_disposition_review" "$schema3_reopen" <<'PY'
import hashlib,json,sys
reservation_path,review_path,package_path=sys.argv[1:]
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
reservation=json.load(open(reservation_path));reservation['unconsumed_predecessor']['disposition_review']=ref(review_path);open(reservation_path,'w').write(json.dumps(reservation,sort_keys=True,separators=(',',':'))+'\n')
package=json.load(open(package_path));package['continuation']['reopen_reservation']=ref(reservation_path);open(package_path,'w').write(json.dumps(package,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$schema3_reservation";sign "$schema3_reopen"
expect_exact_fail reopen_schema3_overlapping_predecessor 'emergency-operator-v1: reopen unconsumed predecessor package lineage mismatch' python3 "$MODEL" verify-package --package "$schema3_reopen" --domain "$domain" --now-epoch "$now"
for artifact in "$unconsumed_disposition" "$unconsumed_disposition.hmac" "$unconsumed_disposition_review" "$unconsumed_disposition_review.hmac" "$schema3_reservation" "$schema3_reservation.hmac" "$schema3_reopen" "$schema3_reopen.hmac";do /bin/cp "$overlap_backup/$(basename "$artifact")" "$artifact";done
python3 "$MODEL" verify-package --package "$schema3_reopen" --domain "$domain" --now-epoch "$schema3_now" >/dev/null||fail reopen_schema3_unconsumed_successor
pass reopen_schema3_unconsumed_successor
expect_fail reopen_schema2_predecessor_after_expiry python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$schema3_now"
mkdir "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["one_shot"]["consumption_marker"])' "$reopen")"
expect_fail reopen_schema3_consumed_predecessor python3 "$MODEL" verify-package --package "$schema3_reopen" --domain "$domain" --now-epoch "$schema3_now"
rmdir "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["one_shot"]["consumption_marker"])' "$reopen")"
python3 - "$unconsumed_disposition" <<'PY'
import json,sys
p=sys.argv[1];v=json.load(open(p));v['remote_access_started']=True;open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$unconsumed_disposition"
expect_fail reopen_schema3_remote_started python3 "$MODEL" verify-package --package "$schema3_reopen" --domain "$domain" --now-epoch "$schema3_now"
legacy_reservation="$run/consumed/reopen-reservation.json";legacy_reopen="$run/reopen-legacy-reservation.json"
cp "$run/predecessor-reopen-package.json" "$legacy_reopen";sign "$legacy_reopen"
mv "$run/predecessor-reopen-consumed" "$run/predecessor-reopen-consumed.hidden"
python3 "$MODEL" verify-package --package "$legacy_reopen" --domain "$domain" --now-epoch "$now" >/dev/null||fail legacy_reopen_reservation_schema1
mv "$run/predecessor-reopen-consumed.hidden" "$run/predecessor-reopen-consumed"
pass legacy_reopen_reservation_schema1
wrong_reservation="$run/consumed/reopen-successors/$(printf 'c%.0s' {1..64}).json";wrong_reopen="$run/reopen-wrong-versioned-reservation-path.json"
cp "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["continuation"]["reopen_reservation"]["path"])' "$reopen")" "$wrong_reservation";sign "$wrong_reservation"
python3 - "$reopen" "$wrong_reservation" "$wrong_reopen" <<'PY'
import hashlib,json,sys
source,reservation_path,output=sys.argv[1:];value=json.load(open(source));value['continuation']['reopen_reservation']={'path':reservation_path,'sha256':hashlib.sha256(open(reservation_path,'rb').read()).hexdigest()};open(output,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$wrong_reopen";expect_fail parallel_successor_same_predecessor python3 "$MODEL" verify-package --package "$wrong_reopen" --domain "$domain" --now-epoch "$now"
mv "$run/consumed" "$run/consumed.hidden";expect_fail reopen_unconsumed_source python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now";mv "$run/consumed.hidden" "$run/consumed"
mv "$run/coordinator-execution-audit.log" "$run/coordinator-execution-audit.log.hidden";expect_fail reopen_consumed_without_audit python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now";mv "$run/coordinator-execution-audit.log.hidden" "$run/coordinator-execution-audit.log"
mv "$postcheck" "$postcheck.hidden";expect_fail reopen_consumed_without_postcheck python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now";mv "$postcheck.hidden" "$postcheck"
python3 - "$reopen" "$run" "$run/hmac-only-review.json" <<'PY'
import hashlib,json,os,sys
source,run,wrong_review=sys.argv[1:]
def dump(path,value):open(path,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
def ref(path):return {'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
base=json.load(open(source))
def artifact_variant(name,key,mutate):
    original=base['continuation'][key]['path'];out=os.path.join(run,name+'-artifact')
    if original.endswith('.json'):
        value=json.load(open(original));mutate(value);dump(out,value)
    else:
        lines=open(original).read().splitlines();mutate(lines);open(out,'w').write('\n'.join(lines)+'\n')
    package=json.loads(json.dumps(base));package['continuation'][key]=ref(out);dump(os.path.join(run,name+'.json'),package)
artifact_variant('reopen-failed-execution','execution_audit',lambda lines: lines.__setitem__(-1,lines[-1].replace('POSTCHECK_VERIFIED','POSTCHECK_FAILED')))
artifact_variant('reopen-partial-dispatch','execution_audit',lambda lines: lines.pop(-2))
artifact_variant('reopen-wrong-dispatch-count','execution_audit',lambda lines: lines.__setitem__(-1,lines[-1].replace('completed=5','completed=4')))
artifact_variant('reopen-audit-package-mismatch','execution_audit',lambda lines: lines.__setitem__(0,lines[0].replace(base['continuation']['remediation_package']['sha256'],'9'*64)))
artifact_variant('reopen-conflicting-rollback','execution_audit',lambda lines: lines.insert(-1,lines[-1].split('\t',1)[0]+'\tROLLBACK_STARTED reason=unexpected'))
artifact_variant('reopen-audit-before-package','execution_audit',lambda lines: lines.__setitem__(0,'2000-01-01T00:00:00Z\t'+lines[0].split('\t',1)[1]))
artifact_variant('reopen-audit-after-expiry','execution_audit',lambda lines: lines.__setitem__(-1,'2099-01-01T00:00:00Z\t'+lines[-1].split('\t',1)[1]))
artifact_variant('reopen-postcheck-recurrence','execution_postcheck',lambda value:value.__setitem__('recurrence',True))
artifact_variant('reopen-postcheck-result-mismatch','execution_postcheck',lambda value:value['dispatch_results'][0].__setitem__('result_sha256','9'*64))
artifact_variant('reopen-postcheck-cardinality-unverified','execution_postcheck',lambda value:value['dispatch_results'][0].__setitem__('target_cardinality_verified',False))
artifact_variant('reopen-postcheck-package-mismatch','execution_postcheck',lambda value:value.__setitem__('remediation_package_sha256','9'*64))
artifact_variant('reopen-current-root-present','current_isolation',lambda value:value.__setitem__('canonical_root_present',True))
artifact_variant('reopen-current-wrong-inode','current_isolation',lambda value:value['root'].__setitem__('inode','999'))
artifact_variant('reopen-current-wrong-operation','current_isolation',lambda value:value.__setitem__('operation_id','c'*32))
artifact_variant('reopen-plan-target-mismatch','coherent_plan',lambda value:value['dispatch'][0].__setitem__('action_orders',[2]))
artifact_variant('reopen-plan-action-contract-mismatch','coherent_plan',lambda value:value.__setitem__('action_contract_sha256','9'*64))
artifact_variant('reopen-registry-mismatch','remediation_registry',lambda value:value['remediation'].__setitem__('review',ref(wrong_review)))
artifact_variant('reopen-reservation-substitution','reopen_reservation',lambda value:value.__setitem__('reopen_operation_id','c'*32))
def receipt_variant(name,mutate):
    post=json.load(open(base['continuation']['execution_postcheck']['path']));entry=post['dispatch_results'][0];receipt=json.load(open(entry['native_receipt']['path']));mutate(receipt)
    receipt_path=os.path.join(run,name+'-receipt.json');dump(receipt_path,receipt);entry['native_receipt']=ref(receipt_path);entry['result_sha256']=entry['native_receipt']['sha256']
    post_path=os.path.join(run,name+'-postcheck.json');dump(post_path,post);package=json.loads(json.dumps(base));package['continuation']['execution_postcheck']=ref(post_path);dump(os.path.join(run,name+'.json'),package)
receipt_variant('reopen-receipt-operation-mismatch',lambda value:value.__setitem__('operation_id','c'*32))
receipt_variant('reopen-receipt-manifest-mismatch',lambda value:value.__setitem__('target_manifest_sha256','9'*64))
receipt_variant('reopen-receipt-parent-manifest-mismatch',lambda value:value.__setitem__('parent_manifest_sha256','9'*64))
receipt_variant('reopen-receipt-quarantine-identity-missing',lambda value:value.__setitem__('quarantine_inode','0'))
receipt_variant('reopen-receipt-artifact-mismatch',lambda value:value.__setitem__('helper_artifact_sha256','9'*64))
receipt_variant('reopen-receipt-poststate-unverified',lambda value:value.__setitem__('poststate_verified',False))
def binding_variant(name,mutate):
    plan=json.load(open(base['continuation']['coherent_plan']['path']));entry=plan['dispatch'][0];binding=json.load(open(entry['binding']['path']));mutate(binding)
    binding_path=os.path.join(run,name+'-binding.json');dump(binding_path,binding);entry['binding']=ref(binding_path)
    plan_path=os.path.join(run,name+'-plan.json');dump(plan_path,plan);package=json.loads(json.dumps(base));package['continuation']['coherent_plan']=ref(plan_path);dump(os.path.join(run,name+'.json'),package)
binding_variant('reopen-binding-manifest-mismatch',lambda value:value.__setitem__('target_manifest_sha256','9'*64))
binding_variant('reopen-binding-artifact-mismatch',lambda value:value.__setitem__('launcher_artifact_sha256','9'*64))
plan=json.load(open(base['continuation']['coherent_plan']['path']));source=json.load(open(base['continuation']['remediation_package']['path']));template=json.load(open(plan['dispatch'][0]['binding']['path']));split=[]
for action in source['actions'][:2]:
    target=action['target'];relative=target['path'][len(source['site']['root'])+1:];target_raw=('\t'.join((relative.encode().hex(),action['before']['sha256'],str(action['before']['bytes']),str(int(target['mode'],8)),target['uid'],target['gid'],target['device'],target['inode']))+'\n').encode();parent_raw=f"{target['parent_device']}\t{target['parent_inode']}\n".encode();binding=dict(template);binding['action_orders']=[action['order']];binding['target_count']=1;binding['target_manifest_sha256']=hashlib.sha256(target_raw).hexdigest();binding['parent_manifest_sha256']=hashlib.sha256(parent_raw).hexdigest();binding_path=os.path.join(run,f'reopen-split-exact-file-{action["order"]}-binding.json');dump(binding_path,binding);split.append({'order':len(split)+1,'stage':'EXECUTABLE','consumer':'BOUNDED_QUARANTINE_EXACT_FILE','action_count':1,'action_orders':[action['order']],'binding':ref(binding_path)})
split.extend(plan['dispatch'][1:])
for index,item in enumerate(split,1):item['order']=index
plan['dispatch']=split;plan['dispatch_count']=len(split);plan['apply_order']=[item['consumer'] for item in split];plan['rollback_order']=list(reversed(plan['apply_order']));plan_path=os.path.join(run,'reopen-split-exact-file-dispatch-plan.json');dump(plan_path,plan);package=json.loads(json.dumps(base));package['continuation']['coherent_plan']=ref(plan_path);dump(os.path.join(run,'reopen-split-exact-file-dispatch.json'),package)
package=json.loads(json.dumps(base));package['continuation']['remediation_review']=ref(wrong_review);dump(os.path.join(run,'reopen-review-substitution.json'),package)
package=json.loads(json.dumps(base));package['continuation']['remediation_consumption_identity']=ref(base['continuation']['remediation_package']['path']);dump(os.path.join(run,'reopen-consumption-substitution.json'),package)
package=json.loads(json.dumps(base));package['site']['site_id']='other';dump(os.path.join(run,'reopen-cross-site.json'),package)
package=json.loads(json.dumps(base));package['operation_id']='d'*32;dump(os.path.join(run,'reopen-duplicate-operation.json'),package)
package=json.loads(json.dumps(base));package['one_shot']['consumption_marker']=os.path.join(run,'another-reopen-consumed');dump(os.path.join(run,'reopen-distinct-marker-same-reservation.json'),package)
PY
for case in failed-execution partial-dispatch wrong-dispatch-count audit-package-mismatch conflicting-rollback audit-before-package audit-after-expiry postcheck-recurrence postcheck-result-mismatch postcheck-cardinality-unverified postcheck-package-mismatch current-root-present current-wrong-inode current-wrong-operation plan-target-mismatch plan-action-contract-mismatch registry-mismatch reservation-substitution receipt-operation-mismatch receipt-manifest-mismatch receipt-parent-manifest-mismatch receipt-quarantine-identity-missing receipt-artifact-mismatch receipt-poststate-unverified binding-manifest-mismatch binding-artifact-mismatch split-exact-file-dispatch review-substitution consumption-substitution cross-site duplicate-operation distinct-marker-same-reservation;do
  expect_fail "$case" python3 "$MODEL" verify-package --package "$run/reopen-$case.json" --domain "$domain" --now-epoch "$now"
done
reopen_consumed="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["one_shot"]["consumption_marker"])' "$reopen")"
mkdir -m 700 "$reopen_consumed";printf '%s\n' "$reopen_sha" >"$reopen_consumed/package-sha256";chmod 600 "$reopen_consumed/package-sha256"
expect_fail completed_reopen_cannot_reopen_again python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now"
rm -rf "$reopen_consumed"
printf '%s\n' "$reopen_sha" >"$run/consumed/reopen-completed";chmod 600 "$run/consumed/reopen-completed"
expect_fail source_lineage_completed_reopen python3 "$MODEL" verify-package --package "$reopen" --domain "$domain" --now-epoch "$now"
rm "$run/consumed/reopen-completed"
bash "$CLOSURE" "$domain" >"$TMP/closure.out";grep -Fq 'CLEAN_WITH_HARDENING_REMAINING' "$TMP/closure.out"||fail closure_hardening;pass closure_semantics
python3 - "$reopen" "$run/reopen-reused-operation.json" "$run/reopen-reused-marker.json" <<'PY'
import json,sys
source,reused_operation,reused_marker=sys.argv[1:];value=json.load(open(source));value['operation_id']='a'*32;open(reused_operation,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n');value=json.load(open(source));value['one_shot']['consumption_marker']=value['continuation']['remediation_package']['path'].rsplit('/',1)[0]+'/consumed';open(reused_marker,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail reopen_reuses_source_operation python3 "$MODEL" verify-package --package "$run/reopen-reused-operation.json" --domain "$domain" --now-epoch "$now"
expect_fail reopen_reuses_source_marker python3 "$MODEL" verify-package --package "$run/reopen-reused-marker.json" --domain "$domain" --now-epoch "$now"
/bin/bash --version >/dev/null 2>&1||true;/bin/bash -n "$CLI" "$CLOSURE";pass bash_3_2_syntax_contract

variant(){ local name="$1" code="$2";python3 - "$package" "$run/$name.json" "$code" <<'PY'
import json,os,sys
src,out,code=sys.argv[1:];v=json.load(open(src));v['one_shot']['consumption_marker']=os.path.join(os.path.dirname(out),'variant-consumed');exec(code);open(out,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
}
variant wrong-domain "v['domain']='other.test'";expect_fail wrong_site python3 "$MODEL" verify-package --package "$run/wrong-domain.json" --domain "$domain" --now-epoch "$now"
variant wrong-root "v['site']['root']='/home/user_99/app_99'";expect_fail wrong_root python3 "$MODEL" verify-package --package "$run/wrong-root.json" --domain "$domain" --now-epoch "$now"
variant sparse-string "v['actions'][3]['target']['integer_key']='7'";expect_fail sparse_key_type python3 "$MODEL" verify-package --package "$run/sparse-string.json" --domain "$domain" --now-epoch "$now"
variant unsafe-order "v['actions'][0]['stage']='DATABASE'";expect_fail dependency_order python3 "$MODEL" verify-package --package "$run/unsafe-order.json" --domain "$domain" --now-epoch "$now"
variant recurrence "v['failure_policy']['recurrence']='CONTINUE'";expect_fail recurrence_abort python3 "$MODEL" verify-package --package "$run/recurrence.json" --domain "$domain" --now-epoch "$now"
variant retry "v['failure_policy']['blind_retry']=True";expect_fail blind_retry python3 "$MODEL" verify-package --package "$run/retry.json" --domain "$domain" --now-epoch "$now"
variant mariadb "v['portability']['db_integrity']='MARIADB_CHECK_REQUIRED'";expect_fail missing_mariadb_fallback python3 "$MODEL" verify-package --package "$run/mariadb.json" --domain "$domain" --now-epoch "$now"
variant body "v['portability']['blocked_http']='MIN_BODY_REQUIRED'";expect_fail short_404_body python3 "$MODEL" verify-package --package "$run/body.json" --domain "$domain" --now-epoch "$now"
variant rawsecret "v['actions'][5]['target']['meta_rows'][0]['raw_value']='secret'";expect_fail identity_secret_export python3 "$MODEL" verify-package --package "$run/rawsecret.json" --domain "$domain" --now-epoch "$now"
variant cron_valid "v['actions']=[{'order':1,'primitive':'REMOVE_EXACT_CRON_EVENT','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on','events':[{'timestamp':1770000000,'hook':'m18rieeekhz64wflm8zpr','event_key':'0123456789abcdef0123456789abcdef'}],'semantic_scope':'EXACT_SELECTED_EVENTS_ONLY'},'before':{'sha256':'3'*64,'bytes':128},'after':{'sha256':'2'*64,'bytes':64},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}}]";python3 "$MODEL" verify-package --package "$run/cron_valid.json" --domain "$domain" --now-epoch "$now" >/dev/null||fail cron_valid;pass cron_valid
variant cron_duplicate "v['actions']=[{'order':1,'primitive':'REMOVE_EXACT_CRON_EVENT','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on','events':[{'timestamp':1770000000,'hook':'x','event_key':'y'},{'timestamp':1770000000,'hook':'x','event_key':'y'}],'semantic_scope':'EXACT_SELECTED_EVENTS_ONLY'},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}}]";expect_fail cron_duplicate_selector python3 "$MODEL" verify-package --package "$run/cron_duplicate.json" --domain "$domain" --now-epoch "$now"
variant cron_multiple_actions "v['actions']=[{'order':1,'primitive':'REMOVE_EXACT_CRON_EVENT','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on','events':[{'timestamp':1770000000,'hook':'x','event_key':'a'}],'semantic_scope':'EXACT_SELECTED_EVENTS_ONLY'},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}},{'order':2,'primitive':'REMOVE_EXACT_CRON_EVENT','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on','events':[{'timestamp':1770000001,'hook':'x','event_key':'b'}],'semantic_scope':'EXACT_SELECTED_EVENTS_ONLY'},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}}]";expect_fail cron_multiple_actions python3 "$MODEL" verify-package --package "$run/cron_multiple_actions.json" --domain "$domain" --now-epoch "$now"
variant cron_option_overlap "v['actions']=[{'order':1,'primitive':'REMOVE_EXACT_OPTION','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on'},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}},{'order':2,'primitive':'REMOVE_EXACT_CRON_EVENT','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on','events':[{'timestamp':1770000000,'hook':'x','event_key':'a'}],'semantic_scope':'EXACT_SELECTED_EVENTS_ONLY'},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}}]";expect_exact_fail cron_option_overlap 'emergency-operator-v1: cron option authority overlaps another option-row action' python3 "$MODEL" verify-package --package "$run/cron_option_overlap.json" --domain "$domain" --now-epoch "$now"
variant cron_active_plugins_row_overlap "v['actions']=[{'order':1,'primitive':'REMOVE_EXACT_ACTIVE_PLUGIN','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'active_plugins','member':'bad/plugin.php','integer_key':0},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}},{'order':2,'primitive':'REMOVE_EXACT_CRON_EVENT','stage':'DATABASE','target':{'table':'options','option_id':45,'option_name':'cron','autoload':'on','events':[{'timestamp':1770000000,'hook':'x','event_key':'a'}],'semantic_scope':'EXACT_SELECTED_EVENTS_ONLY'},'before':{'sha256':'3'*64,'bytes':3},'after':{'sha256':'2'*64,'bytes':2},'rollback':{'artifact':v['actions'][0]['rollback']['artifact'],'restores':'EXACT_ORIGINAL','automatic':True}}]";expect_exact_fail cron_active_plugins_row_overlap 'emergency-operator-v1: cron option authority overlaps another option-row action' python3 "$MODEL" verify-package --package "$run/cron_active_plugins_row_overlap.json" --domain "$domain" --now-epoch "$now"
grep -Fq 'exact_cron_dispatch_orders != [expected_exact_cron_orders]' "$MODEL" || fail cron_reopen_single_dispatch_regression; pass cron_reopen_single_dispatch_regression
grep -Fq 'semantic_scope=' "$CLI" && grep -Fq 'event=' "$CLI" || fail cron_cli_scope_regression; pass cron_cli_scope_regression
variant scope "v['actions'].append(v['actions'][0].copy())";expect_fail scope_widening python3 "$MODEL" verify-package --package "$run/scope.json" --domain "$domain" --now-epoch "$now"
variant duplicate_file_object "v['actions'][1]['target']['device']=v['actions'][0]['target']['device'];v['actions'][1]['target']['inode']=v['actions'][0]['target']['inode']";expect_fail duplicate_file_object python3 "$MODEL" verify-package --package "$run/duplicate_file_object.json" --domain "$domain" --now-epoch "$now"
variant nonregular_file "v['actions'][0]['target']['file_type']='SYMLINK'";expect_fail nonregular_file python3 "$MODEL" verify-package --package "$run/nonregular_file.json" --domain "$domain" --now-epoch "$now"
variant authority "v['authority']['canonical_ready']=True";expect_fail fabricated_ready python3 "$MODEL" verify-package --package "$run/authority.json" --domain "$domain" --now-epoch "$now"
variant reverse_false "v['isolation']['exact_reverse_reopen']=False";expect_fail reverse_reopen_required python3 "$MODEL" verify-package --package "$run/reverse_false.json" --domain "$domain" --now-epoch "$now"
variant file_no_rollback "v['actions'][0]['rollback']['restores']='NONE_IRREVERSIBLE_SECURITY_STATE';v['actions'][0]['rollback']['automatic']=False";expect_fail file_rollback_matrix python3 "$MODEL" verify-package --package "$run/file_no_rollback.json" --domain "$domain" --now-epoch "$now"
variant identity_exact_rollback "v['actions'][5]['rollback']['restores']='EXACT_ORIGINAL';v['actions'][5]['rollback']['automatic']=True";expect_fail identity_rollback_matrix python3 "$MODEL" verify-package --package "$run/identity_exact_rollback.json" --domain "$domain" --now-epoch "$now"
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
python3 - "$reopen" "$run/reopen-recurrence.json" <<'PY'
import json,sys
source,out=sys.argv[1:];value=json.load(open(source));value['continuation']['execution_postcheck']={'path':'/tmp/not-allowed','sha256':'0'*64};open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
expect_fail reopen_after_recurrence python3 "$MODEL" verify-package --package "$run/reopen-recurrence.json" --domain "$domain" --now-epoch "$now"
expect_fail expired python3 "$MODEL" verify-package --package "$package" --domain "$domain" --now-epoch "$((now+7200))"
variant dispatch_missing_marker "pass";make_review "$run/dispatch_missing_marker.json" "$run/dispatch-missing-review.json"
expect_fail current_dispatch_missing_marker python3 "$MODEL" verify-current-dispatch --package "$run/dispatch_missing_marker.json" --review "$run/dispatch-missing-review.json" --domain "$domain" --package-sha256 "$(recovery_sha256_file "$run/dispatch_missing_marker.json")"
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
mkdir -m 700 "$run/historical-reopen-consumed"
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
lines=[f'{stamp(start)}\tBEGIN contract=HUMAN_OPERATOR_EMERGENCY_YELLOW_SELF_MANAGED_ISOLATION site={p["domain"]} operation={op} package={sha} operator=synthetic-operator',f'WAPP_SYNTHETIC_FILES_QUARANTINED_V1|{op}|2',f'WAPP_SYNTHETIC_FILES_TRANSFORMED_V1|{op}|1',f'{stamp(start+1)}\tWAPP_SYNTHETIC_DB_APPLY_V1|{op}|COMMITTED|active=1|options=1|identity=4|credential_neutral=1|sessions_restored=0',f'{stamp(start+2)}\tWAPP_SYNTHETIC_DB_AFTER_V1|{op}|EXACT|active=1|options=0|identity=0|user_preserved=1|sessions=0',f'{stamp(start+3)}\tWAPP_SYNTHETIC_REMEDIATION_COMPLETE_ISOLATION_REMAINS_ACTIVE']
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
 lines.extend([f'{stamp(when)}\tOBSERVATION_BEGIN index={index}',f'WAPP_SYNTHETIC_ISOLATION_VERIFIED_V1|{op}',f'WAPP_SYNTHETIC_FILES_VERIFIED_V1|{op}|3',f'WAPP_SYNTHETIC_DB_AFTER_V1|{op}|EXACT|active=1|options=0|identity=0|user_preserved=1|sessions=0',f'{stamp(when+1)}\tHTTP_ISOLATION endpoint=public route=/ denied=1',f'{stamp(when+1)}\tHTTP_ISOLATION endpoint=origin route=/ denied=1',f'{stamp(when+2)}\tOBSERVATION_END index={index}'])
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

# Closure may consume the explicit legacy reconciliation only through a typed
# lineage whose remediation branch is visibly classified as legacy.  The
# normal signed-execution branch remains a different exact-key contract.
legacy_historical_lineage="$run/legacy-historical-lineage.json"
python3 - "$legacy_historical_lineage" "$domain" "$history_now" "$package" "$review" "$legacy_consumption" "$legacy_attestation" "$legacy_review" "$historical_reopen" "$historical_reopen_review" "$run/historical-reopen-consumed/package-sha256" "$reopen_audit" "$postopen" "$postcheck" <<'PY'
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
[[ ! -e "$run/consumed" ]] || fail legacy_declared_old_marker_unexpectedly_restored
pass legacy_reconciled_execution_to_typed_closure

legacy_cli_reports="$TMP/legacy-cli-reports";mkdir -m 700 -p "$legacy_cli_reports/.control/emergency-operator-v1"
legacy_cli_registry="$legacy_cli_reports/.control/emergency-operator-v1/$domain.json"
python3 - "$legacy_cli_registry" "$domain" "$legacy_historical_closure" <<'PY'
import hashlib,json,sys
out,domain,closure=sys.argv[1:];ref=lambda path:{'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest()}
value={'tool':'wapp-security-emergency-operator-registry','schema':1,'domain':domain,'remediation':None,'reopen':None,'closure':{'record':ref(closure)}}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$legacy_cli_registry"
legacy_closure_cli="$ROOT/bin/wapp-closure-check-legacy-test-now"
python3 - "$CLOSURE" "$legacy_closure_cli" "$history_now" <<'PY'
import sys
source,out,now=sys.argv[1:];value=open(source).read();needle='verify-closure --record "$RECORD" --domain "$DOMAIN"'
if value.count(needle) != 2: raise SystemExit('closure verifier call count drift')
open(out,'w').write(value.replace(needle,needle+' --now-epoch '+now))
PY
chmod 700 "$legacy_closure_cli"
WAPP_EMERGENCY_REPORTS_ROOT="$legacy_cli_reports" "$legacy_closure_cli" "$domain" | grep -Fq WORDPRESS_INCIDENT_VERIFIED_CLEAN || fail legacy_reconciled_closure_cli
pass legacy_reconciled_closure_cli

legacy_cli_collision_variant(){
  local name="$1" field="$2" source="$3"
  local collided_source="$run/legacy-collision-$name-source.json"
  local collided_lineage="$run/legacy-collision-$name-lineage.json"
  local collided_review="$run/legacy-collision-$name-lineage-review.json"
  local collided_closure="$run/legacy-collision-$name-closure.json"
  python3 - "$source" "$collided_source" "$field" "$legacy_audit" <<'PY'
import hashlib,json,sys
source,out,field,collision=sys.argv[1:]
value=json.load(open(source))
value[field]={"path":collision,"sha256":hashlib.sha256(open(collision,"rb").read()).hexdigest()}
open(out,"w").write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
PY
  sign "$collided_source"
  python3 - "$legacy_historical_lineage" "$collided_lineage" "$name" "$collided_source" <<'PY'
import hashlib,json,sys
source,out,name,replacement=sys.argv[1:]
value=json.load(open(source));ref={"path":replacement,"sha256":hashlib.sha256(open(replacement,"rb").read()).hexdigest()}
value["reopen"]["execution_audit" if name == "reopen-audit" else "post_open_verification"]=ref
open(out,"w").write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
PY
  sign "$collided_lineage";make_review "$collided_lineage" "$collided_review"
  python3 - "$legacy_historical_closure" "$collided_closure" "$collided_lineage" "$collided_review" <<'PY'
import hashlib,json,sys
source,out,lineage,review=sys.argv[1:]
value=json.load(open(source));ref=lambda path:{"path":path,"sha256":hashlib.sha256(open(path,"rb").read()).hexdigest()}
value["historical_execution"]={"lineage":ref(lineage),"review":ref(review)}
open(out,"w").write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
PY
  sign "$collided_closure"
  python3 - "$legacy_cli_registry" "$domain" "$collided_closure" <<'PY'
import hashlib,json,sys
out,domain,closure=sys.argv[1:]
ref=lambda path:{"path":path,"sha256":hashlib.sha256(open(path,"rb").read()).hexdigest()}
value={"tool":"wapp-security-emergency-operator-registry","schema":1,"domain":domain,"remediation":None,"reopen":None,"closure":{"record":ref(closure)}}
open(out,"w").write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
PY
  sign "$legacy_cli_registry"
  expect_fail "legacy_cli_${name}_path_collision" env WAPP_EMERGENCY_REPORTS_ROOT="$legacy_cli_reports" "$legacy_closure_cli" "$domain"
}
legacy_cli_collision_variant reopen-audit source_audit "$reopen_audit"
legacy_cli_collision_variant post-open source_post_open "$postopen"
/bin/rm "$legacy_closure_cli"
pass legacy_reconciled_closure_dependency_role_collisions

mv "$legacy_consumption" "$legacy_consumption.missing"
expect_fail legacy_lineage_missing_preserved_consumption python3 "$MODEL" verify-closure --record "$legacy_historical_closure" --domain "$domain" --now-epoch "$history_now"
mv "$legacy_consumption.missing" "$legacy_consumption"

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
legacy_lineage_variant substituted_consumption "value['remediation']['consumption_identity']=value['reopen']['consumption_identity']"
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
