#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
POLICY="$ROOT/config/native-exact-file-quarantine.json"
ARTIFACT="$ROOT/libexec/wapp-native-exact-file-quarantine-linux-x86_64.b64.txt"
SOURCE="$ROOT/native/exact-file-quarantine-helper.c"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-exact-file-test)"
trap 'rm -rf "$TMP"' EXIT
fail(){ printf 'FAIL: native exact-file quarantine: %s\n' "$1" >&2;exit 1; }
python3 - "$POLICY" "$ARTIFACT" "$SOURCE" <<'PY'
import base64,hashlib,json,pathlib,sys
p=json.load(open(sys.argv[1])); raw=base64.b64decode(pathlib.Path(sys.argv[2]).read_text().strip(),validate=True)
assert p['tool']=='wapp-security-native-exact-file-quarantine-policy' and p['schema']==1
assert p['authority']=={'apply':False,'closure':False,'mutation':False,'prepare':False,'ready':False}
assert p['maximum_targets']==64 and p['ordering']=='CANONICAL_RELATIVE_PATH_LEXICAL_BYTES_V1' and 'reconcile-rollback' in p['modes']
assert p['binary_bytes']==len(raw) and p['binary_sha256']==hashlib.sha256(raw).hexdigest()
assert p['encoded_bytes']==pathlib.Path(sys.argv[2]).stat().st_size and p['encoded_sha256']==hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
s=pathlib.Path(sys.argv[3]).read_text();
for needle in ['RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS','SYS_renameat2','RENAME_NOREPLACE','duplicate physical target','automatic compensation failed','PARTIAL_OR_DIVERGED','0x4a7484aa,0x5cb0a9dc,0x76f988da']:
    assert needle in s
PY
if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]];then printf 'PASS: native exact-file quarantine policy/source/artifact; Linux execution reserved for canonical matrix\n';exit 0;fi
/usr/bin/openssl base64 -d -A -in "$ARTIFACT" -out "$TMP/helper";chmod 700 "$TMP/helper"
mkdir -m 755 "$TMP/home";mkdir -m 755 "$TMP/home/site";mkdir -m 755 "$TMP/home/site/a" "$TMP/home/site/b"
printf alpha >"$TMP/home/site/a/one.php";printf beta >"$TMP/home/site/b/two.php";chmod 640 "$TMP/home/site/a/one.php";chmod 600 "$TMP/home/site/b/two.php"
operation=0123456789abcdef0123456789abcdef
python3 - "$TMP/home/site" "$TMP/manifest" "$TMP/parents" <<'PY'
import hashlib,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);rows=[];parents=[]
for rel in ['a/one.php','b/two.php']:
 p=root/rel;s=p.stat();ps=p.parent.stat();rows.append('\t'.join([rel.encode().hex(),hashlib.sha256(p.read_bytes()).hexdigest(),str(s.st_size),str(stat.S_IMODE(s.st_mode)),str(s.st_uid),str(s.st_gid),str(s.st_dev),str(s.st_ino)]));parents.append(f'{ps.st_dev}\t{ps.st_ino}')
pathlib.Path(sys.argv[2]).write_text('\n'.join(rows)+'\n')
pathlib.Path(sys.argv[3]).write_text('\n'.join(parents)+'\n')
PY
manifest_sha="$(shasum -a 256 "$TMP/manifest"|awk '{print $1}')";manifest_hex="$(xxd -p "$TMP/manifest"|tr -d '\n')";parent_sha="$(shasum -a 256 "$TMP/parents"|awk '{print $1}')";parent_hex="$(xxd -p "$TMP/parents"|tr -d '\n')";root_dev="$(stat -c %d "$TMP/home/site")";root_ino="$(stat -c %i "$TMP/home/site")";runtime='loader=HUMAN_OPERATOR_EMERGENCY_NATIVE_EXACT_FILE_V1|test=canonical-linux'
apply_out="$("$TMP/helper" apply "$TMP/home/site" "$operation" "$root_dev" "$root_ino" "$manifest_sha" "$manifest_hex" "$parent_sha" "$parent_hex" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1)";grep -Fq $'QUARANTINED_EXACT\t2' <<<"$apply_out";qdev="$(cut -f5 <<<"$apply_out")";qino="$(cut -f6 <<<"$apply_out")"
[[ ! -e "$TMP/home/site/a/one.php"&&! -e "$TMP/home/site/b/two.php" ]]||fail source_not_absent
q="$TMP/home/.wapp-security-exact-file-$operation/files";cmp "$q/a/one.php" <(printf alpha);cmp "$q/b/two.php" <(printf beta)
[[ "$(stat -c %a "$q/a/one.php")" == 400&&"$(stat -c %a "$q/b/two.php")" == 400 ]]||fail quarantine_not_non_executable
"$TMP/helper" observe-quarantined "$TMP/home/site" "$operation" "$root_dev" "$root_ino" "$manifest_sha" "$manifest_hex" "$parent_sha" "$parent_hex" "$qdev" "$qino" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'QUARANTINED_EXACT\t2'
"$TMP/helper" rollback "$TMP/home/site" "$operation" "$root_dev" "$root_ino" "$manifest_sha" "$manifest_hex" "$parent_sha" "$parent_hex" "$qdev" "$qino" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'ORIGINAL_EXACT\t2'
[[ "$(cat "$TMP/home/site/a/one.php")" == alpha&&"$(cat "$TMP/home/site/b/two.php")" == beta&&"$(stat -c %a "$TMP/home/site/a/one.php")" == 640&&"$(stat -c %a "$TMP/home/site/b/two.php")" == 600 ]]||fail rollback_not_exact
"$TMP/helper" observe-original "$TMP/home/site" "$operation" "$root_dev" "$root_ino" "$manifest_sha" "$manifest_hex" "$parent_sha" "$parent_hex" "$qdev" "$qino" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'ORIGINAL_EXACT\t2'

# Drift, ordering, symlink, hardlink, collision, manifest, parent-identity,
# recovery and reconciliation adversarial contracts.
expect_fail(){ local label="$1";shift;if "$@" >"$TMP/$label.out" 2>"$TMP/$label.err";then fail "$label";fi; }
prepare_case(){
  CASE="$TMP/case-$1";mkdir -m 755 -p "$CASE/home/site/a" "$CASE/home/site/b"
  printf alpha >"$CASE/home/site/a/one.php";printf beta >"$CASE/home/site/b/two.php";chmod 640 "$CASE/home/site/a/one.php";chmod 600 "$CASE/home/site/b/two.php"
  python3 - "$CASE/home/site" "$CASE/manifest" "$CASE/parents" <<'PY'
import hashlib,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);rows=[];parents=[]
for rel in ['a/one.php','b/two.php']:
 p=root/rel;s=p.stat();ps=p.parent.stat();rows.append('\t'.join([rel.encode().hex(),hashlib.sha256(p.read_bytes()).hexdigest(),str(s.st_size),str(stat.S_IMODE(s.st_mode)),str(s.st_uid),str(s.st_gid),str(s.st_dev),str(s.st_ino)]));parents.append(f'{ps.st_dev}\t{ps.st_ino}')
pathlib.Path(sys.argv[2]).write_text('\n'.join(rows)+'\n');pathlib.Path(sys.argv[3]).write_text('\n'.join(parents)+'\n')
PY
  M="$CASE/manifest";P="$CASE/parents";MS="$(shasum -a 256 "$M"|awk '{print $1}')";MH="$(xxd -p "$M"|tr -d '\n')";PS="$(shasum -a 256 "$P"|awk '{print $1}')";PH="$(xxd -p "$P"|tr -d '\n')";RD="$(stat -c %d "$CASE/home/site")";RI="$(stat -c %i "$CASE/home/site")"
}
apply_case(){
  local op="$1" out
  out="$("$TMP/helper" apply "$CASE/home/site" "$op" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1)"
  QD="$(cut -f5 <<<"$out")";QI="$(cut -f6 <<<"$out")";Q="$CASE/home/.wapp-security-exact-file-$op"
  grep -Fq $'QUARANTINED_EXACT\t2' <<<"$out"||fail apply_case
}

prepare_case drift;printf changed >"$CASE/home/site/a/one.php";expect_fail sha_drift "$TMP/helper" apply "$CASE/home/site" 1123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1
prepare_case symlink;mv "$CASE/home/site/a/one.php" "$CASE/home/site/a/real";ln -s real "$CASE/home/site/a/one.php";expect_fail symlink "$TMP/helper" apply "$CASE/home/site" 2123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'target exact prestate drift' "$TMP/symlink.err"||fail symlink_reason

prepare_case unordered;sed '1!G;h;$!d' "$M" >"$CASE/unordered";sed '1!G;h;$!d' "$P" >"$CASE/unordered-parents";UMS="$(shasum -a 256 "$CASE/unordered"|awk '{print $1}')";UMH="$(xxd -p "$CASE/unordered"|tr -d '\n')";UPS="$(shasum -a 256 "$CASE/unordered-parents"|awk '{print $1}')";UPH="$(xxd -p "$CASE/unordered-parents"|tr -d '\n')";expect_fail unordered "$TMP/helper" apply "$CASE/home/site" 3123456789abcdef0123456789abcdef "$RD" "$RI" "$UMS" "$UMH" "$UPS" "$UPH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'canonical lexical order' "$TMP/unordered.err"||fail unordered_reason

prepare_case hardlink;rm "$CASE/home/site/b/two.php";ln "$CASE/home/site/a/one.php" "$CASE/home/site/b/two.php";python3 - "$CASE/home/site" "$M" "$P" <<'PY'
import hashlib,pathlib,stat,sys
r=pathlib.Path(sys.argv[1]);rows=[];parents=[]
for rel in ['a/one.php','b/two.php']:
 p=r/rel;s=p.stat();ps=p.parent.stat();rows.append('\t'.join([rel.encode().hex(),hashlib.sha256(p.read_bytes()).hexdigest(),str(s.st_size),str(stat.S_IMODE(s.st_mode)),str(s.st_uid),str(s.st_gid),str(s.st_dev),str(s.st_ino)]));parents.append(f'{ps.st_dev}\t{ps.st_ino}')
pathlib.Path(sys.argv[2]).write_text('\n'.join(rows)+'\n');pathlib.Path(sys.argv[3]).write_text('\n'.join(parents)+'\n')
PY
MS="$(shasum -a 256 "$M"|awk '{print $1}')";MH="$(xxd -p "$M"|tr -d '\n')";expect_fail hardlink "$TMP/helper" apply "$CASE/home/site" 4123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'target exact prestate drift' "$TMP/hardlink.err"||fail hardlink_reason

prepare_case collision;mkdir -m 700 "$CASE/home/.wapp-security-exact-file-5123456789abcdef0123456789abcdef";expect_fail quarantine_collision "$TMP/helper" apply "$CASE/home/site" 5123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'quarantine destination collision' "$TMP/quarantine_collision.err"||fail collision_reason

prepare_case crossfs;python3 - "$M" <<'PY'
import pathlib
p=pathlib.Path(__import__('sys').argv[1]);rows=[]
for row in p.read_text().splitlines():
 f=row.split('\t');f[6]=str(int(f[6])+1);rows.append('\t'.join(f))
p.write_text('\n'.join(rows)+'\n')
PY
MS="$(shasum -a 256 "$M"|awk '{print $1}')";MH="$(xxd -p "$M"|tr -d '\n')";expect_fail cross_filesystem "$TMP/helper" apply "$CASE/home/site" 6123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'filesystem drift' "$TMP/cross_filesystem.err"||fail cross_filesystem_reason

prepare_case wrongq;apply_case 7123456789abcdef0123456789abcdef;expect_fail wrong_q_identity "$TMP/helper" observe-quarantined "$CASE/home/site" 7123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$((QI+1))" "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'quarantine root identity drift' "$TMP/wrong_q_identity.err"||fail wrong_q_identity_reason

prepare_case manifest_substitution;apply_case 8123456789abcdef0123456789abcdef;chmod 600 "$Q/manifest.hex";printf 0 |dd of="$Q/manifest.hex" bs=1 seek=0 conv=notrunc status=none;chmod 400 "$Q/manifest.hex";expect_fail persisted_manifest "$TMP/helper" observe-quarantined "$CASE/home/site" 8123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'manifest substitution' "$TMP/persisted_manifest.err"||fail persisted_manifest_reason

prepare_case parent_substitution;apply_case 9123456789abcdef0123456789abcdef;mv "$CASE/home/site/a" "$CASE/home/site/a-displaced";mkdir -m 755 "$CASE/home/site/a";expect_fail parent_identity "$TMP/helper" observe-quarantined "$CASE/home/site" 9123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'parent identity drift' "$TMP/parent_identity.err"||fail parent_identity_reason

prepare_case rollback_collision;apply_case a123456789abcdef0123456789abcdef;printf collision >"$CASE/home/site/a/one.php";expect_fail rollback_collision "$TMP/helper" rollback "$CASE/home/site" a123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1;grep -Fq 'PARTIAL_OR_DIVERGED' "$TMP/rollback_collision.out"||fail rollback_collision_state

prepare_case reconcile;apply_case b123456789abcdef0123456789abcdef;chmod 640 "$Q/files/a/one.php";mv "$Q/files/a/one.php" "$CASE/home/site/a/one.php";"$TMP/helper" reconcile-rollback "$CASE/home/site" b123456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'ORIGINAL_EXACT_RECONCILED\t2';[[ "$(cat "$CASE/home/site/a/one.php")" == alpha&&"$(cat "$CASE/home/site/b/two.php")" == beta ]]||fail reconcile_bytes
prepare_case duplicate_crash;apply_case b223456789abcdef0123456789abcdef;ln "$Q/files/a/one.php" "$CASE/home/site/a/one.php";"$TMP/helper" reconcile-rollback "$CASE/home/site" b223456789abcdef0123456789abcdef "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'ORIGINAL_EXACT_RECONCILED\t2';[[ "$(stat -c %h "$CASE/home/site/a/one.php")" == 1&&"$(stat -c %a "$CASE/home/site/a/one.php")" == 640 ]]||fail duplicate_crash_recovery

# Exercise the shipped loader -> staged launcher -> sealed memfd -> helper path.
LOADER_TEMPLATE="$ROOT/lib/native-exact-file-quarantine-ephemeral-loader.sh";LAUNCHER_ARTIFACT="$ROOT/libexec/wapp-native-exact-file-quarantine-ephemeral-memfd-launcher-linux-x86_64.b64.txt"
python3 - "$LOADER_TEMPLATE" "$LAUNCHER_ARTIFACT" "$ARTIFACT" "$TMP/loader" <<'PY'
import pathlib,sys
template,launcher,helper,out=map(pathlib.Path,sys.argv[1:]);value=template.read_text();value=value.replace('__WAPP_EXACT_FILE_LAUNCHER_BASE64_PAYLOAD__',launcher.read_text().strip()).replace('__WAPP_EXACT_FILE_HELPER_BASE64_PAYLOAD__',helper.read_text().strip());out.write_text(value)
PY
chmod 700 "$TMP/loader";prepare_case shipped;shipop=c123456789abcdef0123456789abcdef
ship_out="$("$TMP/loader" "$CASE/home/site" "$shipop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 apply)";grep -Fq 'EXACT_FILE_EPHEMERAL_RUNTIME_AUDIT_V1' <<<"$ship_out"||fail shipped_loader_audit;QD="$(awk -F '\t' '$2=="QUARANTINED_EXACT"{print $5}' <<<"$ship_out")";QI="$(awk -F '\t' '$2=="QUARANTINED_EXACT"{print $6}' <<<"$ship_out")";[[ "$QD" =~ ^[0-9]+$&&"$QI" =~ ^[0-9]+$ ]]||fail shipped_receipt_identity
"$TMP/loader" "$CASE/home/site" "$shipop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" observe-quarantined |grep -Fq $'QUARANTINED_EXACT\t2'
"$TMP/loader" "$CASE/home/site" "$shipop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" rollback |grep -Fq $'ORIGINAL_EXACT\t2';[[ ! -e "$CASE/home/.wapp-security-exact-file-launcher-$shipop" ]]||fail shipped_stage_cleanup

# A test-only build crashes exactly after the durable destination fsync.  The
# released helper must reconcile both apply-side and rollback-side mixed state.
[[ "${WAPP_ZIG_BIN:-}" == /*&&-x "$WAPP_ZIG_BIN"&&"$($WAPP_ZIG_BIN version)" == 0.15.2 ]]||fail test_zig_unavailable
ZIG_GLOBAL_CACHE_DIR="$TMP/zig-global" ZIG_LOCAL_CACHE_DIR="$TMP/zig-local" "$WAPP_ZIG_BIN" cc -target x86_64-linux-musl -O2 -s -std=gnu11 -Wall -Wextra -Werror -DWAPP_TEST_FAULT_INJECTION "$SOURCE" -o "$TMP/fault-helper"
expect_crash(){ local label="$1";shift;set +e;"$@" >"$TMP/$label.out" 2>"$TMP/$label.err";local rc=$?;set -e;[[ "$rc" == 99 ]]||fail "$label"; }
prepare_case apply_crash;crashop=d123456789abcdef0123456789abcdef;expect_crash apply_destination_durable env WAPP_TEST_CRASH_POINT=apply_after_destination_fsync "$TMP/fault-helper" apply "$CASE/home/site" "$crashop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1;Q="$CASE/home/.wapp-security-exact-file-$crashop";QD="$(stat -c %d "$Q")";QI="$(stat -c %i "$Q")";"$TMP/helper" reconcile-rollback "$CASE/home/site" "$crashop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'ORIGINAL_EXACT_RECONCILED\t2'
prepare_case rollback_crash;crashop=e123456789abcdef0123456789abcdef;apply_case "$crashop";expect_crash restore_destination_durable env WAPP_TEST_CRASH_POINT=restore_after_destination_fsync "$TMP/fault-helper" rollback "$CASE/home/site" "$crashop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1;"$TMP/helper" reconcile-rollback "$CASE/home/site" "$crashop" "$RD" "$RI" "$MS" "$MH" "$PS" "$PH" "$QD" "$QI" "$runtime" QUARANTINE_EXACT_FILE_V1 |grep -Fq $'ORIGINAL_EXACT_RECONCILED\t2'

printf 'PASS: native exact-file bounded multi-target transaction and adversarial lifecycle matrix\n'
