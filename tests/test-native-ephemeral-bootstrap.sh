#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
POLICY="$ROOT/config/native-ephemeral-bootstrap.json"
LOADER="$ROOT/lib/native-displaced-inventory-ephemeral-loader.sh"
LAUNCHER="$ROOT/libexec/wapp-native-ephemeral-memfd-launcher-linux-x86_64.b64.txt"
HELPER="$ROOT/libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt"
SOURCE="$ROOT/native/ephemeral-memfd-launcher.c"
BUILD="$ROOT/native/build-ephemeral-memfd-launcher.sh"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-native-ephemeral-test)"
trap 'chmod -R u+rwX "$TMP" 2>/dev/null||true;rm -rf "$TMP"' EXIT
fail(){ printf 'FAIL: %s\n' "$1" >&2;exit 1; }

bash -n "$LOADER" "$BUILD"
python3 - "$ROOT" "$POLICY" "$LAUNCHER" <<'PY'
import base64,hashlib,json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]).resolve();policy=json.loads(pathlib.Path(sys.argv[2]).read_text());encoded=pathlib.Path(sys.argv[3]).read_bytes()
keys={'artifact_encoding','authority','bootstrap_assurance','build_tool','customer_configuration_modified','database_modified','execution_contract','helper_policy_path','launcher_binary_bytes','launcher_binary_sha256','launcher_encoded_bytes','launcher_encoded_path','launcher_encoded_sha256','launcher_source_path','loader_template_path','platform','residual_risk','schema','staging_contract','target_host_ephemeral_bootstrap_modified','tool','wordpress_filesystem_modified'}
assert set(policy)==keys and policy['tool']=='wapp-security-native-ephemeral-bootstrap-policy' and policy['schema']==1
assert policy['platform']=='linux-x86_64' and policy['bootstrap_assurance']=='DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP'
assert policy['staging_contract']=='OPERATION_BOUND_SIBLING_PRIVATE_DIRECTORY_V1' and policy['execution_contract']=='SEALED_MEMFD_EXECVEAT_PINNED_HELPER_V1'
assert policy['residual_risk']=='SAME_PRINCIPAL_TOCTOU_RISK_ACCEPTED_BY_HUMAN_OPERATOR'
assert policy['target_host_ephemeral_bootstrap_modified'] is True and policy['wordpress_filesystem_modified'] is False and policy['database_modified'] is False and policy['customer_configuration_modified'] is False
assert policy['authority']=={'apply':False,'closure':False,'mutation':False,'prepare':False,'ready':False}
assert policy['build_tool']=='zig-0.15.2' and policy['artifact_encoding']=='base64-rfc4648-no-wrap-v1'
assert re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}\n',encoded)
binary=base64.b64decode(encoded.strip(),validate=True)
assert len(encoded)==policy['launcher_encoded_bytes']==47929 and hashlib.sha256(encoded).hexdigest()==policy['launcher_encoded_sha256']=='ae4a6b01526273512cedb5a1a44b8884ae5973fba1a09ec51f48073bfcd19941'
assert len(binary)==policy['launcher_binary_bytes']==35944 and hashlib.sha256(binary).hexdigest()==policy['launcher_binary_sha256']=='73b81536d5a4ba079907eed7bffeca191e7b3ac7a8fced0de74dd228618f47d2'
for field in ('helper_policy_path','launcher_encoded_path','launcher_source_path','loader_template_path'):
 path=(root/policy[field]).resolve();assert path.is_file() and not path.is_symlink() and str(path).startswith(str(root)+'/')
PY
python3 - "$LOADER" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text()
assignments={name:path for name,path in re.findall(r'^(STAT|OPENSSL|MKDIR|CHMOD|RM|RMDIR)=(/[^\n]+)$',text,re.M)}
assert assignments=={
 'STAT':'/usr/bin/stat','OPENSSL':'/usr/bin/openssl',
 'MKDIR':'/bin/mkdir','CHMOD':'/bin/chmod','RM':'/bin/rm','RMDIR':'/bin/rmdir',
}
assert '/usr/bin/stat|/usr/bin/openssl) trusted_physical_file "$path";;' in text
assert '/bin/mkdir|/bin/chmod|/bin/rm|/bin/rmdir)' in text
for logical,physical in (
 ('/bin/mkdir','/usr/bin/mkdir'),('/bin/chmod','/usr/bin/chmod'),
 ('/bin/rm','/usr/bin/rm'),('/bin/rmdir','/usr/bin/rmdir')):
 assert f'{logical}) physical={physical};;' in text
assert '"\'/bin\' -> \'usr/bin\'"|"\'/bin\' -> \'/usr/bin\'"' in text
assert 'command -v' not in text and 'which ' not in text
assert '[[ -f "$path"&&! -L "$path"&&-x "$path" ]]' in text
assert '"$uid" == 0&&"$gid" == 0' in text and '(8#$mode & 022)==0' in text
assert '"$logical" -ef "$physical"' in text and '"$logical_meta" == "$physical_meta"' in text
PY
grep -Fq '#define HELPER_BYTES 94152U' "$SOURCE"||fail helper_size_not_compiled
grep -Fq '#define HELPER_SHA256 "bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52"' "$SOURCE"||fail helper_sha_not_compiled
grep -Fq '!strcmp(argv[1],"inventory")||!strcmp(argv[1],"diagnostic")' "$SOURCE"||fail diagnostic_mode_not_allowlisted
grep -Fq 'strcmp(argv[1],"inventory")&&strcmp(argv[1],"diagnostic")&&strcmp(argv[1],"rollback")&&strcmp(argv[1],"volatile-inventory")' "$SOURCE"||fail arbitrary_mode_guard_missing
grep -Fq 'SYS_memfd_create' "$SOURCE"&&grep -Fq 'F_ADD_SEALS' "$SOURCE"&&grep -Fq 'SYS_execveat' "$SOURCE"||fail descriptor_launch_contract_missing
grep -Fq 'stage_parent="${target_root%/*}"' "$LOADER"||fail stage_not_outside_webroot
grep -Fq 'set -C' "$LOADER"||fail exclusive_create_missing
grep -Fq 'staged launcher drift after execution' "$LOADER"||fail postexecution_identity_missing
grep -Fq 'cleanup identity drift; staged path retained fail-closed' "$LOADER"||fail cleanup_drift_guard_missing
grep -Fq 'launcher cleanup absence failed' "$LOADER"&&grep -Fq 'operation directory cleanup absence failed' "$LOADER"||fail cleanup_absence_missing
if grep -Eq '(^|[^A-Za-z_])(eval|wp|wp-cli|php)([^A-Za-z_]|$)' "$LOADER";then fail arbitrary_or_customer_runtime_surface;fi

if [[ -n "${WAPP_ZIG_BIN:-}" ]];then
  rebuilt="$TMP/rebuilt-launcher.b64.txt"
  ZIG_GLOBAL_CACHE_DIR="$TMP/zig-global" ZIG_LOCAL_CACHE_DIR="$TMP/zig-local" WAPP_EPHEMERAL_LAUNCHER_OUTPUT="$rebuilt" /bin/bash "$BUILD" >/dev/null
  cmp -s "$LAUNCHER" "$rebuilt"||fail source_artifact_reproducibility_drift
fi

bad="$TMP/bad.b64";python3 - "$LAUNCHER" "$bad" <<'PY'
import base64,hashlib,pathlib,sys
source,out=map(pathlib.Path,sys.argv[1:]);original=base64.b64decode(source.read_bytes().strip(),validate=True);changed=bytearray(original);changed[0]^=1;out.write_bytes(base64.b64encode(changed)+b'\n')
assert len(changed)==len(original) and hashlib.sha256(changed).digest()!=hashlib.sha256(original).digest()
PY

# Exercise the exact usrmerge target and ownership/mode predicates on every
# release platform without changing any host system path.
python3 - "$LOADER" "$TMP/trust-functions.sh" <<'PY'
import pathlib,sys
text=pathlib.Path(sys.argv[1]).read_text();start=text.index('meta(){');end=text.index('\nsha(){',start)
pathlib.Path(sys.argv[2]).write_text(text[start:end]+'\n')
PY
STAT=/usr/bin/stat
source "$TMP/trust-functions.sh"
trusted_usrmerge_link "'/bin' -> 'usr/bin'"||fail relative_standard_usrmerge_rejected
trusted_usrmerge_link "'/bin' -> '/usr/bin'"||fail absolute_standard_usrmerge_rejected
for invalid in "'/bin' -> '/tmp/bin'" "'/bin' -> '../tmp/bin'" "'/bin' -> 'usr/local/bin'" "'/bin' -> '/opt/user/bin'";do
  if trusted_usrmerge_link "$invalid";then fail arbitrary_usrmerge_target_accepted;fi
done
trusted_metadata '0:0:755:1:2:3'||fail trusted_metadata_rejected
if trusted_metadata '0:0:777:1:2:3';then fail writable_metadata_accepted;fi
if trusted_metadata '1000:1000:755:1:2:3';then fail nonroot_metadata_accepted;fi

if [[ "$(uname -s)" != Linux ]];then
  printf 'PASS: native degraded ephemeral bootstrap policy, source, artifact and fail-closed macOS boundary\n'
  exit 0
fi

build_probe(){
  local launcher="$1" output="$2"
  python3 - "$LOADER" "$launcher" "$HELPER" "$output" <<'PY'
import os,sys
template,launcher,helper,out=sys.argv[1:];raw=open(template,'rb').read();raw=raw.replace(b'__WAPP_EPHEMERAL_LAUNCHER_BASE64_PAYLOAD__',open(launcher,'rb').read().strip()).replace(b'__WAPP_NATIVE_HELPER_BASE64_PAYLOAD__',open(helper,'rb').read().strip());open(out,'wb').write(raw);os.chmod(out,0o700)
PY
}

ROOT_PARENT="$TMP/private-home";SITE="$ROOT_PARENT/site-root"
mkdir -m 700 -p "$SITE/wp-content/plugins/synthetic"
printf 'synthetic\n' >"$SITE/wp-content/plugins/synthetic/plugin.php"
nonce="$(printf positive|sha256sum|awk '{print $1}')";probe="$TMP/probe.sh";build_probe "$LAUNCHER" "$probe"
launcher_direct="$TMP/launcher.direct"
python3 - "$LAUNCHER" "$launcher_direct" <<'PY'
import base64,os,pathlib,sys
source,target=map(pathlib.Path,sys.argv[1:]);target.write_bytes(base64.b64decode(source.read_bytes().strip(),validate=True));os.chmod(target,0o700)
PY
before="$(find "$SITE" -print0|sort -z|xargs -0 stat -c '%n:%F:%s:%a:%u:%g:%d:%i'|sha256sum|awk '{print $1}')";out="$TMP/out.tsv"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash --noprofile --norc "$probe" "$SITE" "$nonce" bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52 94152 inventory '' >"$out"
grep -Fq $'CAPTURE_NONCE\t'"$nonce" "$out"&&grep -Fq 'EPHEMERAL_BOOTSTRAP_AUDIT_V2' "$out"&&grep -Fq 'CLEANUP_VERIFIED' "$out"||fail correct_staged_launcher
after="$(find "$SITE" -print0|sort -z|xargs -0 stat -c '%n:%F:%s:%a:%u:%g:%d:%i'|sha256sum|awk '{print $1}')";[[ "$before" == "$after" ]]||fail webroot_modified
[[ ! -e "$ROOT_PARENT/.wapp-security-ephemeral-bootstrap-$nonce" ]]||fail cleanup_not_absent

# A stable diagnostic has no delta and must fail in the helper, not at the
# launcher's exact mode/argument boundary. This proves the release-pinned
# degraded path accepted and descriptor-launched diagnostic mode.
diagnostic_nonce="$(printf diagnostic-stable|sha256sum|awk '{print $1}')";diagnostic_err="$TMP/diagnostic.err"
if /bin/bash "$probe" "$SITE" "$diagnostic_nonce" bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52 94152 diagnostic '' >"$TMP/diagnostic.out" 2>"$diagnostic_err";then fail stable_diagnostic_unexpected_success;fi
grep -Fq 'wapp-native-displaced-inventory: diagnostic mode requires two-pass mismatch' "$diagnostic_err"||fail degraded_diagnostic_not_descriptor_launched
[[ ! -e "$ROOT_PARENT/.wapp-security-ephemeral-bootstrap-$diagnostic_nonce" ]]||fail diagnostic_cleanup_not_absent

arbitrary_nonce="$(printf arbitrary-mode|sha256sum|awk '{print $1}')";arbitrary_err="$TMP/arbitrary.err"
runtime_identity='loader=DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1|launcher_sha=73b81536d5a4ba079907eed7bffeca191e7b3ac7a8fced0de74dd228618f47d2|launcher_meta=0:0:700:1:2:35944|helper_sha=bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52|transport=sealed_memfd_execveat_v1'
if "$launcher_direct" arbitrary "$SITE" "$arbitrary_nonce" "$runtime_identity" </dev/null >/dev/null 2>"$arbitrary_err";then fail arbitrary_mode_accepted;fi
grep -Fq 'wapp-ephemeral-memfd-launcher: invalid bounded mode' "$arbitrary_err"||fail arbitrary_mode_not_rejected_by_launcher

cardinality_nonce="$(printf diagnostic-cardinality|sha256sum|awk '{print $1}')";cardinality_err="$TMP/cardinality.err"
if "$launcher_direct" diagnostic "$SITE" "$cardinality_nonce" "$runtime_identity" 61 </dev/null >/dev/null 2>"$cardinality_err";then fail diagnostic_extra_argument_accepted;fi
grep -Fq 'wapp-ephemeral-memfd-launcher: invalid bounded invocation' "$cardinality_err"||fail diagnostic_cardinality_not_rejected_by_launcher

bad_nonce="$(printf bad|sha256sum|awk '{print $1}')";build_probe "$bad" "$TMP/bad-probe.sh"
if /bin/bash "$TMP/bad-probe.sh" "$SITE" "$bad_nonce" bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52 94152 inventory '' >/dev/null 2>&1;then fail hash_mismatch_accepted;fi

collision_nonce="$(printf collision|sha256sum|awk '{print $1}')";mkdir -m 700 "$ROOT_PARENT/.wapp-security-ephemeral-bootstrap-$collision_nonce"
if /bin/bash "$probe" "$SITE" "$collision_nonce" bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52 94152 inventory '' >/dev/null 2>&1;then fail preexisting_directory_accepted;fi
rm -rf "$ROOT_PARENT/.wapp-security-ephemeral-bootstrap-$collision_nonce";ln -s "$SITE" "$ROOT_PARENT/.wapp-security-ephemeral-bootstrap-$collision_nonce"
if /bin/bash "$probe" "$SITE" "$collision_nonce" bf692cebb99e8bfb440bba29981dc943df74d90125a904ed787835ccdd239a52 94152 inventory '' >/dev/null 2>&1;then fail symlink_accepted;fi
rm "$ROOT_PARENT/.wapp-security-ephemeral-bootstrap-$collision_nonce"

mkdir -m 777 "$TMP/writable-parent";if trusted_directory "$TMP/writable-parent";then fail writable_directory_accepted;fi
ln -s /bin/mkdir "$TMP/substituted-mkdir";if trusted_physical_file "$TMP/substituted-mkdir";then fail symlink_tool_accepted;fi
cp /bin/mkdir "$TMP/writable-mkdir";chmod 777 "$TMP/writable-mkdir";if trusted_physical_file "$TMP/writable-mkdir";then fail writable_tool_accepted;fi

printf 'PASS: native staged launcher, hash/collision/symlink rejection, exact cleanup and no-webroot-write\n'
