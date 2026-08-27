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
n=d.datetime.now(d.timezone.utc).replace(microsecond=0)
f=lambda x:x.strftime('%Y-%m-%dT%H:%M:%SZ')
print(f(n),f(n+d.timedelta(minutes=20)),f(n-d.timedelta(minutes=1)))
PY
)"
NONCE="$(printf synthetic-capture|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"

make_rows(){
  local output="$1" variant="$2"
  /usr/bin/python3 - "$output" "$variant" <<'PY'
import hashlib,sys
out,variant=sys.argv[1:]
root=b'/srv/synthetic/site';dev=11
webshell=b"<?php eval($_POST['cmd']); ?>\n"
files={
 b'wp-admin/core.php':b'<?php /* official core */\n',
 b'wp-content/plugins/sample/plugin.php':b'<?php /* official plugin */\n',
 b'wp-content/themes/sample/functions.php':b'<?php /* official theme */\n',
 b'wp-config.php':b'<?php /* exact config */\n',
 b'.htaccess':b'Deny from all\n',
 b'wp-content/uploads/image.jpg':b'jpeg-synthetic',
}
if variant=='upload':files[b'wp-content/uploads/bad.php']=b'<?php echo 1;\n'
elif variant=='unknown':files[b'custom.php']=b'<?php echo 2;\n'
elif variant=='malicious':files[b'backdoor.php']=webshell
entries=[]
def hx(v):return v.hex()
def h(v):return hashlib.sha256(v).hexdigest()
def entry(rel,kind,size,mode,inode,digest='-',uploads=0):
 absolute=root if not rel else root+b'/'+rel
 return '\t'.join(('ENTRY',hx(rel),hx(absolute),kind,str(size),mode,'1000','1000','100','101',str(dev),str(inode),'1','-',digest,str(uploads)))
entries.append(entry(b'', 'DIRECTORY',0,'0755',100))
dirs=set()
for rel in files:
 parts=rel.split(b'/')[:-1]
 for i in range(1,len(parts)+1):dirs.add(b'/'.join(parts[:i]))
for i,rel in enumerate(sorted(dirs),200):entries.append(entry(rel,'DIRECTORY',0,'0755',i,uploads=int(b'uploads' in rel.split(b'/'))))
for i,(rel,data) in enumerate(sorted(files.items()),1000):entries.append(entry(rel,'REGULAR',len(data),'0644',i,h(data),int(b'uploads' in rel.split(b'/'))))
issues=[]
if variant=='incomplete':issues=['UNRESOLVED\tENTRY_OPEN_UNRESOLVED\t'+b'wp-content/cache/missing.php'.hex()+'\t'+h(b'open')]
entries=sorted(entries);all_rows=entries+issues
inventory=h(('\n'.join(entries)+'\n').encode())
directories=1+len(dirs);regular=len(files);hashed_bytes=sum(map(len,files.values()));uploads=sum(b'uploads' in rel.split(b'/') for rel in list(dirs)+list(files))
rootrow='\t'.join(('ROOT',hx(root),hx(root),str(dev),'100','0755','1000','1000','1','100','101'))
runtime='\t'.join(('RUNTIME','PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1',hx(b'memfd:wapp-native-displaced-inventory-linux-x86_64-v1'),h(b'helper'),h(b'runtime')))
summary='\t'.join(('SUMMARY',str(len(entries)),str(directories),str(regular),str(regular),str(hashed_bytes),str(uploads),'0',str(len(issues)),'false' if issues else 'true',inventory,'200000','50000','150000','1073741824','34359738368','64','900','4096','125829120'))
open(out,'w',encoding='ascii').write('\n'.join(sorted([rootrow,runtime,summary,*all_rows]))+'\n')
PY
}

make_provenance(){
  local capture="$1" rows="$2" output="$3" variant="${4:-valid}"
  /usr/bin/python3 - "$capture" "$rows" "$output" "$OBS" "$EXPIRES" "$variant" <<'PY'
import hashlib,json,sys
capture,rows,out,generated,expires,variant=sys.argv[1:]
raw=open(capture,'rb').read();entries={}
for line in open(rows,encoding='ascii'):
 f=line.rstrip('\n').split('\t')
 if f[0]=='ENTRY' and f[3]=='REGULAR':entries[f[1]]=f[14]
paths=['wp-admin/core.php','wp-content/plugins/sample/plugin.php','wp-content/themes/sample/functions.php','wp-config.php','.htaccess']
records=[]
for path in paths:
 key=path.encode().hex()
 if key not in entries:continue
 digest=entries[key]
 if variant=='wrong-hash' and path=='wp-admin/core.php':digest='0'*64
 records.append({'path_hex':key,'sha256':digest,'disposition':'OFFICIAL_UPSTREAM_EXACT','source_kind':'WORDPRESS_ORG_RELEASE_ARCHIVE_V1','source_identity_sha256':hashlib.sha256(('source-'+path).encode()).hexdigest()})
value={'tool':'wapp-security-read-only-surface-provenance','schema':1,'contract':'READ_ONLY_SECURITY_SURFACE_PROVENANCE_V1','generated_at':generated,'expires_at':expires,'capture':{'path':capture,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)},'authority':{'apply':False,'clean':False,'closure':False,'mutation':False,'prepare':False,'ready':False,'remediation':False},'records':sorted(records,key=lambda x:x['path_hex'])}
open(out,'w').write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n')
PY
  recovery_sign_file "$output" "$output.hmac" >/dev/null
}

make_case(){
  local name="$1" variant="$2" provenance_variant="${3:-valid}"
  make_rows "$TMP/$name.rows" "$variant"
  "$TOOL" capture-create --inventory-rows "$TMP/$name.rows" --observed-at "$OBS" --expires-at "$EXPIRES" --capture-nonce "$NONCE" --output "$TMP/$name.capture.json" >/dev/null
  "$TOOL" capture-verify --artifact "$TMP/$name.capture.json" >/dev/null
  make_provenance "$TMP/$name.capture.json" "$TMP/$name.rows" "$TMP/$name.provenance.json" "$provenance_variant"
  "$TOOL" create --capture "$TMP/$name.capture.json" --provenance "$TMP/$name.provenance.json" --generated-at "$OBS" --output "$TMP/$name.surface.json" >/dev/null
  "$TOOL" verify --artifact "$TMP/$name.surface.json" >/dev/null
}

make_case clean clean
/usr/bin/python3 - "$TMP/clean.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['contract']=='READ_ONLY_SECURITY_SURFACE_V1'
assert v['state']=='COMPLETE_NO_ACTION' and v['coverage_complete'] is True and v['terminal_clean_candidate'] is True
assert v['counts']['unresolved']==0 and v['counts']['action_required']==0 and v['counts']['pass']==5
assert v['authority']=={'apply':False,'clean':False,'closure':False,'mutation':False,'prepare':False,'ready':False,'remediation':False}
assert v['read_only'] is True and v['non_authorizing'] is True and v['raw_customer_source_exported'] is False
raw=open(sys.argv[1],'rb').read();assert b'official core' not in raw and b'exact config' not in raw
PY
pass official_clean_complete

cp "$TMP/clean.surface.json" "$TMP/clean-repeat.surface.json";cp "$TMP/clean.surface.json.hmac" "$TMP/clean-repeat.surface.json.hmac"
rm "$TMP/clean-repeat.surface.json" "$TMP/clean-repeat.surface.json.hmac"
"$TOOL" create --capture "$TMP/clean.capture.json" --provenance "$TMP/clean.provenance.json" --generated-at "$OBS" --output "$TMP/clean-repeat.surface.json" >/dev/null
cmp -s "$TMP/clean.surface.json" "$TMP/clean-repeat.surface.json"||fail deterministic_surface
pass deterministic_surface

make_case upload upload
/usr/bin/python3 - "$TMP/upload.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='COMPLETE_ACTION_REQUIRED' and v['coverage_complete'] is True and v['terminal_clean_candidate'] is False
assert any(o['disposition']=='EXECUTABLE_UPLOAD' and o['result']=='ACTION_REQUIRED' for o in v['objects'])
PY
pass executable_upload_action_required

make_case malicious malicious
/usr/bin/python3 - "$TMP/malicious.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert any('KNOWN_EXACT_PHP_WEBSHELL_V1' in o['rule_ids'] and o['result']=='ACTION_REQUIRED' for o in v['objects'])
PY
pass malicious_exact_action_required

make_case unknown unknown
/usr/bin/python3 - "$TMP/unknown.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='UNRESOLVED_NON_CLEAN' and v['coverage_complete'] is False and v['counts']['unresolved']==1
PY
pass unknown_php_unresolved

make_case mismatch clean wrong-hash
/usr/bin/python3 - "$TMP/mismatch.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['state']=='UNRESOLVED_NON_CLEAN'
assert any(o['disposition']=='CONTRADICTORY_PROVENANCE' for o in v['objects'])
PY
pass official_hash_mismatch_unresolved

make_case incomplete incomplete
/usr/bin/python3 - "$TMP/incomplete.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert v['coverage_complete'] is False and v['counts']['inventory_unresolved']==1
PY
pass incomplete_inventory_nonclean

expect_fail stale_surface "$TOOL" create --capture "$TMP/clean.capture.json" --provenance "$TMP/clean.provenance.json" --generated-at "$STALE" --output "$TMP/stale.surface.json"

/usr/bin/python3 - "$TMP/clean.capture.json" "$TMP/cross.capture.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));v['public_core']['commit']='1'*40
open(sys.argv[2],'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
recovery_sign_file "$TMP/cross.capture.json" "$TMP/cross.capture.json.hmac" >/dev/null
make_provenance "$TMP/cross.capture.json" "$TMP/clean.rows" "$TMP/cross.provenance.json"
expect_fail cross_release "$TOOL" create --capture "$TMP/cross.capture.json" --provenance "$TMP/cross.provenance.json" --generated-at "$OBS" --output "$TMP/cross.surface.json"

/usr/bin/python3 - "$TMP/clean.surface.json" "$TMP/tampered.surface.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));v['objects'][0]['result']='PASS' if v['objects'][0]['result']!='PASS' else 'ACTION_REQUIRED'
open(sys.argv[2],'w').write(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n')
PY
recovery_sign_file "$TMP/tampered.surface.json" "$TMP/tampered.surface.json.hmac" >/dev/null
expect_fail classification_substitution "$TOOL" verify --artifact "$TMP/tampered.surface.json"

printf 'READ_ONLY_SECURITY_SURFACE_TESTS: PASS\n'
