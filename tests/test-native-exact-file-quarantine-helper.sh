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
for needle in ['RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS','SYS_renameat2','RENAME_NOREPLACE','duplicate physical target','automatic compensation failed','PARTIAL_OR_DIVERGED']:
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

# Drift, ordering, symlink, duplicate-inode and collision adversarial contracts.
expect_fail(){ local label="$1";shift;if "$@" >"$TMP/$label.out" 2>"$TMP/$label.err";then fail "$label";fi; }
badop=1123456789abcdef0123456789abcdef;cp "$TMP/manifest" "$TMP/drift";printf changed >"$TMP/home/site/a/one.php";badhex="$(xxd -p "$TMP/drift"|tr -d '\n')";expect_fail sha_drift "$TMP/helper" apply "$TMP/home/site" "$badop" "$root_dev" "$root_ino" "$manifest_sha" "$badhex" "$parent_sha" "$parent_hex" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1
mv "$TMP/home/site/a/one.php" "$TMP/home/site/a/real";ln -s real "$TMP/home/site/a/one.php";badop=2123456789abcdef0123456789abcdef;expect_fail symlink "$TMP/helper" apply "$TMP/home/site" "$badop" "$root_dev" "$root_ino" "$manifest_sha" "$badhex" "$parent_sha" "$parent_hex" 0 0 "$runtime" QUARANTINE_EXACT_FILE_V1
grep -Fq 'target exact prestate drift' "$TMP/symlink.err"||fail symlink_reason
printf 'PASS: native exact-file bounded multi-target apply/observe/rollback and adversarial drift\n'
