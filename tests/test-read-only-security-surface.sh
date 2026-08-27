#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
TOOL="$ROOT/bin/wapp-read-only-security-surface"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-readonly-surface-test)"
trap 'rm -rf "$TMP"' EXIT
source "$ROOT/tests/helpers/recovery-keychain-fixture.sh"
wapp_test_setup_recovery_keychain "$TMP/keychain"
source "$ROOT/lib/recovery-integrity.sh"
fail(){ printf 'FAIL: %s\n' "$1" >&2;exit 1; }
pass(){ printf 'PASS: %s\n' "$1"; }
expect_fail(){ local label="$1";shift;if "$@" >"$TMP/$label.out" 2>"$TMP/$label.err";then fail "$label accepted";fi;pass "$label"; }
read -r OBS EXPIRES STALE <<<"$(/usr/bin/python3 - <<'PY'
import datetime as d
n=d.datetime.now(d.timezone.utc).replace(microsecond=0);f=lambda x:x.strftime('%Y-%m-%dT%H:%M:%SZ')
print(f(n),f(n+d.timedelta(minutes=20)),f(n-d.timedelta(minutes=1)))
PY
)"
NONCE="$(printf synthetic-capture|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)";VERSION="$(tr -d '[:space:]'<"$ROOT/VERSION")"
HELPER_SHA="$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binary_sha256"])' "$ROOT/config/native-filesystem-helper.json")"

sign(){ recovery_sign_file "$1" "$1.hmac" >/dev/null; }

make_product_seal(){
  /usr/bin/python3 - "$ROOT" "$TMP/product.json" "$COMMIT" "$VERSION" <<'PY'
import hashlib,json,pathlib,sys
root,out,commit,version=sys.argv[1:];root=pathlib.Path(root)
paths=[line for line in (root/'config/canonical-components.txt').read_text().splitlines() if line and not line.startswith('#')]
paths=sorted(set(paths)|{'VERSION','bin/wapp-package-audit','bin/wapp-public-data-boundary','bin/wapp-release-check','bin/wapp-test','config/canonical-components.txt'})
components=[]
for path in sorted(paths):
 raw=(root/path).read_bytes();components.append({'path':path,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
value={'tool':'wapp-security-product-seal','schema':2,'generated_at':'2026-01-01T00:00:00Z','version':version,'git':{'branch':'synthetic','commit':commit,'clean':True},'discovery_policy':'tracked runtime toolchain: root launchers + install/update + bin/wapp dispatcher + bin/wapp-* + lib runtime + native helper source/build/encoded artifact/policy + release-sealed trust policy + VERSION + canonical surface manifest; sites.csv excluded','component_count':len(components),'components':components,'local_only':True,'site_credentials_used':False}
pathlib.Path(out).write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$TMP/product.json"
}

make_rows(){
  local output="$1" variant="$2"
  /usr/bin/python3 - "$output" "$variant" "$HELPER_SHA" <<'PY'
import hashlib,sys
out,variant,helper=sys.argv[1:];root=b'/srv/synthetic/site';dev=11
webshell=b"<?php eval($_POST['cmd']); ?>\n"
files={b'wp-admin/core.php':b'<?php /* official core */\n',b'wp-content/plugins/sample/plugin.php':b'<?php /* official plugin */\n',b'wp-content/themes/sample/functions.php':b'<?php /* official theme */\n',b'wp-config.php':b'<?php /* exact config */\n',b'.htaccess':b'Deny from all\n',b'wp-content/uploads/image.jpg':b'jpeg-synthetic'}
if variant=='upload':files[b'wp-content/uploads/bad.php']=b'<?php echo 1;\n'
elif variant=='unknown':files[b'custom.php']=b'<?php echo 2;\n'
elif variant=='malicious':files[b'backdoor.php']=webshell
elif variant=='disguised':files[b'wp-content/uploads/icon.ico']=b'<?php echo "hidden";\n'
elif variant=='prepend':files[b'.user.ini']=b'auto_prepend_file=/tmp/persist.php\n'
elif variant=='append':files[b'.user.ini']=b'auto_append_file=/tmp/persist.php\n'
entries=[]
hx=lambda v:v.hex();h=lambda v:hashlib.sha256(v).hexdigest()
def entry(rel,kind,size,mode,inode,digest='-',uploads=0):
 absolute=root if not rel else root+b'/'+rel
 return '\t'.join(('ENTRY',hx(rel),hx(absolute),kind,str(size),mode,'1000','1000','100','101',str(dev),str(inode),'1','-',digest,str(uploads)))
entries.append(entry(b'','DIRECTORY',0,'0755',100));dirs=set()
for rel in files:
 parts=rel.split(b'/')[:-1]
 for i in range(1,len(parts)+1):dirs.add(b'/'.join(parts[:i]))
for i,rel in enumerate(sorted(dirs),200):entries.append(entry(rel,'DIRECTORY',0,'0755',i,uploads=int(b'uploads' in rel.split(b'/'))))
for i,(rel,data) in enumerate(sorted(files.items()),1000):entries.append(entry(rel,'REGULAR',len(data),'0644',i,h(data),int(b'uploads' in rel.split(b'/'))))
issues=[]
if variant=='incomplete':issues=['UNRESOLVED\tENTRY_OPEN_UNRESOLVED\t'+b'wp-content/cache/missing.php'.hex()+'\t'+h(b'open')]
entries=sorted(entries);inventory=h(('\n'.join(entries)+'\n').encode());directories=1+len(dirs);regular=len(files);hashed_bytes=sum(map(len,files.values()));uploads=sum(b'uploads' in rel.split(b'/') for rel in list(dirs)+list(files))
rootrow='\t'.join(('ROOT',hx(root),hx(root),str(dev),'100','0755','1000','1000','1','100','101'))
runtime='\t'.join(('RUNTIME','PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1',hx(b'memfd:wapp-native-displaced-inventory-linux-x86_64-v1'),helper,h(b'loader=/usr/bin/perl|helper_sha='+helper.encode())))
summary='\t'.join(('SUMMARY',str(len(entries)),str(directories),str(regular),str(regular),str(hashed_bytes),str(uploads),'0',str(len(issues)),'false' if issues else 'true',inventory,'200000','50000','150000','1073741824','34359738368','64','900','4096','125829120'))
open(out,'w',encoding='ascii').write('\n'.join(sorted([rootrow,runtime,summary,*entries,*issues]))+'\n')
PY
  sign "$output"
}

make_capture(){
  local rows="$1" output="$2"
  /usr/bin/python3 - "$rows" "$output" "$TMP/product.json" "$ROOT/config/native-filesystem-helper.json" "$OBS" "$EXPIRES" "$NONCE" "$COMMIT" "$VERSION" <<'PY'
import hashlib,json,pathlib,sys
rows,out,product,policy,observed,expires,nonce,commit,version=sys.argv[1:]
raw=pathlib.Path(rows).read_bytes();lines=raw.decode('ascii').splitlines();entry=[x.split('\t') for x in lines if x.startswith('ENTRY\t')];root=[x.split('\t') for x in lines if x.startswith('ROOT\t')][0];runtime=[x.split('\t') for x in lines if x.startswith('RUNTIME\t')][0];summary=[x.split('\t') for x in lines if x.startswith('SUMMARY\t')][0]
ref=lambda p:{'path':str(pathlib.Path(p).resolve()),'sha256':hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(),'bytes':len(pathlib.Path(p).read_bytes())}
authority={'apply':False,'clean':False,'closure':False,'mutation':False,'prepare':False,'ready':False,'remediation':False}
lifecycle={'bootstrap_assurance':'TRUSTED_MEMFD_LAUNCHER','server_temp_files_created':False,'target_host_ephemeral_bootstrap_modified':False,'target_filesystem_modified':False,'wordpress_filesystem_modified':False,'database_modified':False,'customer_configuration_modified':False,'ephemeral_cleanup_verified':True,'wordpress_executed':False,'php_executed':False}
identity={'device':int(root[3]),'inode':int(root[4]),'mode':root[5],'uid':int(root[6]),'gid':int(root[7]),'nlink':int(root[8]),'mtime_ns':int(root[9]),'ctime_ns':int(root[10])}
common={'observed_at':observed,'expires_at':expires,'capture_nonce':nonce,'inventory_rows':ref(rows),'root_path_hex':root[1],'physical_root_hex':root[2],'root_identity':identity,'runtime_mode':runtime[1],'runtime_path_hex':runtime[2],'helper_sha256':runtime[3],'runtime_identity_sha256':runtime[4],'inventory_commitment_sha256':summary[10],'collection_lifecycle':lifecycle}
source={'tool':'wapp-security-native-inventory-collection-evidence','schema':1,'contract':'COMPLETE_BOUNDED_DESCRIPTOR_NOFOLLOW_TWO_PASS_V1',**common,'authority':authority}
source_path=pathlib.Path(out+'.source.json');source_path.write_text(json.dumps(source,sort_keys=True,separators=(',',':'))+'\n')
capture={'tool':'wapp-security-native-inventory-capture-binding','schema':1,'contract':'COMPLETE_BOUNDED_DESCRIPTOR_NOFOLLOW_TWO_PASS_V1','classification_scope':'INVENTORY_ONLY_NO_DISPOSITION_V1',**common,'public_core':{'commit':commit,'version':version},'public_product_seal':ref(product),'source_collection_evidence':ref(source_path),'native_policy':ref(policy),'entry_count':int(summary[1]),'unresolved_count':int(summary[8]),'uncovered_path_count':int(summary[8]),'coverage_complete':summary[9]=='true','authority':authority}
pathlib.Path(out).write_text(json.dumps(capture,sort_keys=True,separators=(',',':'))+'\n')
PY
  sign "$output.source.json";sign "$output"
}

make_provenance(){
  local capture="$1" rows="$2" output="$3" variant="${4:-valid}"
  /usr/bin/python3 - "$capture" "$rows" "$output" "$OBS" "$EXPIRES" "$variant" <<'PY'
import hashlib,json,pathlib,sys
capture,rows,out,generated,expires,variant=sys.argv[1:];capture_raw=pathlib.Path(capture).read_bytes();capture_ref={'path':capture,'sha256':hashlib.sha256(capture_raw).hexdigest(),'bytes':len(capture_raw)}
entries={}
for line in open(rows,encoding='ascii'):
 f=line.rstrip('\n').split('\t')
 if f[0]=='ENTRY' and f[3]=='REGULAR':entries[f[1]]=f[14]
authority={'apply':False,'clean':False,'closure':False,'mutation':False,'prepare':False,'ready':False,'remediation':False};records=[]
skip=[]
skip_names={'action':{b'wp-content/uploads/bad.php',b'backdoor.php'},'unknown':{b'custom.php'},'disguised':{b'wp-content/uploads/icon.ico'},'prepend':{b'.user.ini'},'append':{b'.user.ini'}}
if variant in skip_names:skip=[key for key in entries if bytes.fromhex(key) in skip_names[variant]]
if variant=='omit-official':skip=[b'wp-content/uploads/image.jpg'.hex()]
for index,path_hex in enumerate(sorted(entries)):
 if path_hex in skip:continue
 digest=entries[path_hex]
 if variant=='wrong-hash' and bytes.fromhex(path_hex)==b'wp-admin/core.php':digest='0'*64
 source={'tool':'wapp-security-read-only-surface-source-evidence','schema':1,'contract':'READ_ONLY_SECURITY_SURFACE_SOURCE_EVIDENCE_V1','observed_at':generated,'expires_at':expires,'capture':capture_ref,'path_hex':path_hex,'sha256':digest,'disposition':'OFFICIAL_UPSTREAM_EXACT','source_kind':'WORDPRESS_ORG_RELEASE_ARCHIVE_V1','authority':authority}
 source_path=pathlib.Path(out+f'.source-{index}.json');source_path.write_text(json.dumps(source,sort_keys=True,separators=(',',':'))+'\n');raw=source_path.read_bytes()
 records.append({'path_hex':path_hex,'sha256':digest,'disposition':'OFFICIAL_UPSTREAM_EXACT','source_kind':'WORDPRESS_ORG_RELEASE_ARCHIVE_V1','source_identity_sha256':hashlib.sha256(raw).hexdigest(),'source_artifact':{'path':str(source_path.resolve()),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}})
regular='\n'.join(sorted(k+'\t'+v for k,v in entries.items()))+'\n'
value={'tool':'wapp-security-read-only-surface-provenance','schema':1,'contract':'READ_ONLY_SECURITY_SURFACE_PROVENANCE_V1','scope_mode':'COMPLETE_CURRENT_REGULAR_FILE_SET_V1','regular_file_set_sha256':hashlib.sha256(regular.encode('ascii')).hexdigest(),'record_set_sha256':hashlib.sha256((json.dumps(records,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest(),'generated_at':generated,'expires_at':expires,'capture':capture_ref,'authority':authority,'records':records}
pathlib.Path(out).write_text(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  for source in "$output".source-*.json;do sign "$source";done
  sign "$output"
}

make_case(){
  local name="$1" variant="$2" provenance_variant="${3:-valid}"
  make_rows "$TMP/$name.rows" "$variant";make_capture "$TMP/$name.rows" "$TMP/$name.capture.json"
  "$TOOL" capture-verify --artifact "$TMP/$name.capture.json" >/dev/null
  make_provenance "$TMP/$name.capture.json" "$TMP/$name.rows" "$TMP/$name.provenance.json" "$provenance_variant"
  "$TOOL" create --capture "$TMP/$name.capture.json" --provenance "$TMP/$name.provenance.json" --generated-at "$OBS" --output "$TMP/$name.surface.json" >/dev/null
  "$TOOL" verify --artifact "$TMP/$name.surface.json" >/dev/null
}

make_product_seal
make_case clean clean
/usr/bin/python3 - "$TMP/clean.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='COMPLETE_NO_ACTION' and v['coverage_complete'] is True and v['terminal_clean_candidate'] is True
assert v['counts']['unresolved']==0 and v['counts']['action_required']==0 and v['counts']['pass']==6 and v['counts']['applicable']==6
assert all(o['result']=='PASS' for o in v['objects']);assert v['read_only'] is True and v['non_authorizing'] is True and v['authority']['clean'] is False
raw=open(sys.argv[1],'rb').read();assert b'official core' not in raw and b'exact config' not in raw
PY
pass complete_all_regular_files

"$TOOL" create --capture "$TMP/clean.capture.json" --provenance "$TMP/clean.provenance.json" --generated-at "$OBS" --output "$TMP/clean-repeat.surface.json" >/dev/null
cmp -s "$TMP/clean.surface.json" "$TMP/clean-repeat.surface.json"||fail deterministic_surface;pass deterministic_surface

make_case upload upload action
/usr/bin/python3 - "$TMP/upload.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='COMPLETE_ACTION_REQUIRED';assert any(o['disposition']=='EXECUTABLE_UPLOAD' and o['result']=='ACTION_REQUIRED' for o in v['objects'])
PY
pass executable_upload_action_required

make_case malicious malicious action
/usr/bin/python3 - "$TMP/malicious.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert any('KNOWN_EXACT_PHP_WEBSHELL_V1' in o['rule_ids'] and o['result']=='ACTION_REQUIRED' for o in v['objects'])
PY
pass malicious_exact_action_required

make_case malicious-provenance malicious valid
/usr/bin/python3 - "$TMP/malicious-provenance.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));target=[o for o in v['objects'] if 'KNOWN_EXACT_PHP_WEBSHELL_V1' in o['rule_ids']][0]
assert target['result']=='ACTION_REQUIRED' and target['disposition']=='KNOWN_MALICIOUS_EXACT'
assert 'PROVENANCE_CANNOT_DOWNGRADE_ACTION_REQUIRED' in target['rule_ids']
PY
pass provenance_cannot_downgrade_malicious

for case_name in unknown disguised prepend append;do make_case "$case_name" "$case_name" "$case_name";done
/usr/bin/python3 - "$TMP/unknown.surface.json" "$TMP/disguised.surface.json" "$TMP/prepend.surface.json" "$TMP/append.surface.json" <<'PY'
import json,sys
for path in sys.argv[1:]:
 v=json.load(open(path));assert v['state']=='UNRESOLVED_NON_CLEAN' and v['coverage_complete'] is False and v['counts']['unresolved']==1
assert any(bytes.fromhex(o['path_hex']).endswith(b'icon.ico') and o['result']=='UNRESOLVED' for o in json.load(open(sys.argv[2]))['objects'])
assert any(bytes.fromhex(o['path_hex'])==b'.user.ini' and o['result']=='UNRESOLVED' for o in json.load(open(sys.argv[3]))['objects'])
assert any(bytes.fromhex(o['path_hex'])==b'.user.ini' and o['result']=='UNRESOLVED' for o in json.load(open(sys.argv[4]))['objects'])
PY
pass disguised_executable_and_prepend_fail_closed

make_case mismatch clean wrong-hash
/usr/bin/python3 - "$TMP/mismatch.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='UNRESOLVED_NON_CLEAN';assert any(o['disposition']=='CONTRADICTORY_PROVENANCE' for o in v['objects'])
PY
pass replaced_official_unresolved

make_case omitted clean omit-official
/usr/bin/python3 - "$TMP/omitted.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='UNRESOLVED_NON_CLEAN';assert any(bytes.fromhex(o['path_hex'])==b'wp-content/uploads/image.jpg' and o['result']=='UNRESOLVED' for o in v['objects'])
PY
pass omitted_non_php_official_unresolved

make_case incomplete incomplete
/usr/bin/python3 - "$TMP/incomplete.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['coverage_complete'] is False and v['counts']['inventory_unresolved']==1
PY
pass incomplete_inventory_nonclean

cp "$TMP/clean.capture.json" "$TMP/bad-helper.capture.json"
/usr/bin/python3 - "$TMP/bad-helper.capture.json" <<'PY'
import json,sys
p=sys.argv[1];v=json.load(open(p));v['helper_sha256']='0'*64;open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$TMP/bad-helper.capture.json";expect_fail helper_substitution "$TOOL" capture-verify --artifact "$TMP/bad-helper.capture.json"

cp "$TMP/product.json" "$TMP/bad-product.json"
/usr/bin/python3 - "$TMP/bad-product.json" <<'PY'
import json,sys
p=sys.argv[1];v=json.load(open(p));v['components'][0]['sha256']='0'*64;open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$TMP/bad-product.json";cp "$TMP/clean.capture.json" "$TMP/bad-product.capture.json"
/usr/bin/python3 - "$TMP/bad-product.capture.json" "$TMP/bad-product.json" <<'PY'
import hashlib,json,pathlib,sys
p,q=sys.argv[1:];v=json.load(open(p));raw=pathlib.Path(q).read_bytes();v['public_product_seal']={'path':str(pathlib.Path(q).resolve()),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)};open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$TMP/bad-product.capture.json";expect_fail product_substitution "$TOOL" capture-verify --artifact "$TMP/bad-product.capture.json"

cp "$TMP/clean.capture.json" "$TMP/bad-runtime.capture.json"
/usr/bin/python3 - "$TMP/bad-runtime.capture.json" <<'PY'
import json,sys
p=sys.argv[1];v=json.load(open(p));v['runtime_identity_sha256']='1'*64;open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$TMP/bad-runtime.capture.json";expect_fail runtime_substitution "$TOOL" capture-verify --artifact "$TMP/bad-runtime.capture.json"

expect_fail stale_surface "$TOOL" create --capture "$TMP/clean.capture.json" --provenance "$TMP/clean.provenance.json" --generated-at "$STALE" --output "$TMP/stale.surface.json"

cp "$TMP/clean.surface.json" "$TMP/tampered.surface.json"
/usr/bin/python3 - "$TMP/tampered.surface.json" <<'PY'
import json,sys
p=sys.argv[1];v=json.load(open(p));v['objects'][0]['result']='ACTION_REQUIRED';open(p,'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
sign "$TMP/tampered.surface.json";expect_fail classification_substitution "$TOOL" verify --artifact "$TMP/tampered.surface.json"

printf 'READ_ONLY_SECURITY_SURFACE_TESTS: PASS\n'
