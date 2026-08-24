#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
SOURCE="$ROOT/native/displaced-inventory-helper.c"
ARTIFACT="$ROOT/libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt"
POLICY="$ROOT/config/native-filesystem-helper.json"
LOADER="$ROOT/lib/native-displaced-inventory-loader.sh"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-native-filesystem-helper-test)"
cleanup(){ chmod 700 "$TMP/provider-neutral/site-root/permission-denied" 2>/dev/null||true;rm -rf "$TMP"; }
trap cleanup EXIT
fail(){ printf 'FAIL: %s\n' "$1" >&2;exit 1; }
expect_fail(){ local name="$1";shift;if "$@" >"$TMP/$name.out" 2>"$TMP/$name.err";then fail "$name accepted";fi; }
sha(){ /usr/bin/shasum -a 256 "$1"|/usr/bin/awk '{print $1}'; }

for path in "$SOURCE" "$ARTIFACT" "$POLICY" "$LOADER";do [[ -f "$path"&&! -L "$path" ]]||fail release_files;done
/usr/bin/python3 - "$POLICY" "$ARTIFACT" "$TMP/helper" <<'PY'
import base64,hashlib,json,pathlib,sys
policy,artifact,output=map(pathlib.Path,sys.argv[1:])
value=json.loads(policy.read_text(encoding='utf-8'))
expected={'tool','schema','platform','runtime_mode','loader_path','encoded_path','encoded_sha256','encoded_bytes','binary_sha256','binary_bytes','artifact_encoding','build_tool','root_contract'}
assert set(value)==expected and value['tool']=='wapp-security-native-filesystem-helper-policy' and value['schema']==1
assert value['platform']=='linux-x86_64' and value['loader_path']=='/usr/bin/perl'
assert value['runtime_mode']=='PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1'
assert value['root_contract']=='PROVIDER_NEUTRAL_ABSOLUTE_DESCRIPTOR_ROOT_V1'
assert value['encoded_path']=='libexec/wapp-native-displaced-inventory-linux-x86_64.b64.txt'
assert value['artifact_encoding']=='base64-rfc4648-no-wrap-v1' and value['build_tool']=='zig-0.15.2'
encoded=artifact.read_bytes();raw=base64.b64decode(encoded.strip(),validate=True)
assert encoded.endswith(b'\n') and b'\n' not in encoded[:-1]
assert value['encoded_sha256']==hashlib.sha256(encoded).hexdigest() and value['encoded_bytes']==len(encoded)
assert value['binary_sha256']==hashlib.sha256(raw).hexdigest() and value['binary_bytes']==len(raw)
output.write_bytes(raw);output.chmod(0o700)
PY
BINARY_SHA="$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binary_sha256"])' "$POLICY")"
BINARY_BYTES="$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binary_bytes"])' "$POLICY")"
/usr/bin/python3 - "$LOADER" "$ARTIFACT" "$TMP/probe" <<'PY'
import os,pathlib,sys
loader,artifact,output=map(pathlib.Path,sys.argv[1:])
raw=loader.read_bytes();marker=b'__WAPP_NATIVE_HELPER_BASE64_PAYLOAD__'
assert raw.count(marker)==1
assert b'syscall(319,"wapp-native-displaced-inventory",2)' not in raw
assert b'syscall(322,$fd,"",$ptr,$env,0x1000)' not in raw
assert b'my $memfd_name="wapp-native-displaced-inventory";my $fd=syscall(319,$memfd_name,2)' in raw
assert b'my $empty_path="";syscall(322,$fd,$empty_path,$ptr,$env,0x1000)' in raw
output.write_bytes(raw.replace(marker,artifact.read_bytes().strip()));output.chmod(0o700)
PY

# Perl's syscall() forces string arguments to writable scalars. A literal is
# read-only on the canonical Ubuntu Perl and fails before memfd_create. Keep a
# direct portability regression before the platform-specific helper checks.
case "$(uname -s):$(uname -m)" in
  Darwin:*) perl_getpid=20;;
  Linux:x86_64) perl_getpid=39;;
  *) perl_getpid='';;
esac
if [[ -n "$perl_getpid" ]];then
  expect_fail perl_syscall_literal /usr/bin/perl -e 'my $n=shift;syscall($n,"wapp-native-displaced-inventory")' "$perl_getpid"
  grep -Fq 'Modification of a read-only value attempted' "$TMP/perl_syscall_literal.err"||fail perl_literal_failure_changed
  /usr/bin/perl -e 'my $n=shift;my $arg="wapp-native-displaced-inventory";my $got=syscall($n,$arg);die "mutable syscall argument failed\n" unless $got==$$' "$perl_getpid"
fi

if [[ "$(uname -s)" == Darwin ]];then
  /usr/bin/clang -std=c11 -Wall -Wextra -Werror "$SOURCE" -o "$TMP/native-macos"
  set +e;"$TMP/native-macos" >"$TMP/macos.out" 2>"$TMP/macos.err";rc=$?;set -e
  [[ $rc -eq 78 ]]&&grep -Fq 'unsupported platform' "$TMP/macos.err"||fail macos_faked_linux_parity
  /usr/bin/python3 - "$TMP/helper" <<'PY'
import pathlib,sys
raw=pathlib.Path(sys.argv[1]).read_bytes();assert raw[:4]==b'\x7fELF' and raw[4:6]==b'\x02\x01'
PY
  grep -Fq 'SYS_openat2' "$SOURCE"&&grep -Fq 'SYS_getdents64' "$SOURCE"&&grep -Fq 'O_NOFOLLOW|O_NOATIME' "$SOURCE"||fail linux_syscall_contract
  printf 'PASS: native helper is release-pinned and macOS remains explicitly unsupported\n'
  exit 0
fi

[[ "$(uname -s):$(uname -m)" == Linux:x86_64 ]]||fail unsupported_test_platform
TEST_ROOT="$TMP/provider-neutral/site-root"
mkdir -p "$TEST_ROOT/wp-content/plugins/synthetic/deep/a/b/c" "$TEST_ROOT/wp-content/uploads/2026/08" "$TEST_ROOT/permission-denied"
printf 'plugin bytes\n' >"$TEST_ROOT/wp-content/plugins/synthetic/plugin.php"
printf 'deep bytes\n' >"$TEST_ROOT/wp-content/plugins/synthetic/deep/a/b/c/deep.php"
printf 'upload bytes\n' >"$TEST_ROOT/wp-content/uploads/2026/08/media.bin"
printf 'malformed-name bytes\n' >"$TEST_ROOT/wp-content/plugins/synthetic/line
break.php"
/usr/bin/python3 - "$TEST_ROOT/wp-content/plugins/synthetic/large.bin" <<'PY'
import sys
open(sys.argv[1],'wb').write(b'0123456789abcdef'*131072)
PY
printf 'unreadable\n' >"$TEST_ROOT/permission-denied/hidden";chmod 000 "$TEST_ROOT/permission-denied"
touch -a -t 200001010000 "$TEST_ROOT/wp-content/plugins/synthetic/plugin.php"
atime_before="$(stat -c %X "$TEST_ROOT/wp-content/plugins/synthetic/plugin.php")"
NONCE="$(printf native-helper-public-test|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
run_inventory(){ /bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory ''; }
run_inventory >"$TMP/first.tsv"
run_inventory >"$TMP/second.tsv"
cmp -s "$TMP/first.tsv" "$TMP/second.tsv"||fail nondeterministic_output
[[ "$(stat -c %X "$TEST_ROOT/wp-content/plugins/synthetic/plugin.php")" == "$atime_before" ]]||fail noatime_contract
/usr/bin/python3 - "$TMP/first.tsv" <<'PY'
import hashlib,sys
lines=open(sys.argv[1],encoding='ascii').read().splitlines();assert lines[0].startswith('CAPTURE_NONCE\t')
payload=lines[1:];assert payload==sorted(set(payload));entries={}
for line in payload:
 fields=line.split('\t')
 if fields[0]=='ENTRY':entries[bytes.fromhex(fields[1])]=fields
assert entries[b'wp-content/plugins/synthetic/plugin.php'][14]==hashlib.sha256(b'plugin bytes\n').hexdigest()
assert entries[b'wp-content/plugins/synthetic/large.bin'][4]==str(2*1024*1024)
assert b'wp-content/plugins/synthetic/line\nbreak.php' in entries
assert any(line.startswith('UNRESOLVED\tDIRECTORY_OPEN_UNRESOLVED\t') for line in payload)
assert not any('plugin bytes' in line or 'upload bytes' in line for line in payload)
runtime=[line for line in payload if line.startswith('RUNTIME\t')]
assert len(runtime)==1 and runtime[0].split('\t')[1]=='PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1'
PY
chmod 700 "$TEST_ROOT/permission-denied"

REL='wp-content/plugins/synthetic/plugin.php';REL_HEX="$(python3 -c 'import sys;print(sys.argv[1].encode().hex())' "$REL")"
/bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" rollback "$REL_HEX" >"$TMP/rollback.tsv"
/usr/bin/python3 - "$TMP/rollback.tsv" "$TEST_ROOT/$REL" <<'PY'
import hashlib,sys
rows=open(sys.argv[1],encoding='ascii').read().splitlines();selected=[x.split('\t') for x in rows if x.startswith('SELECTED_ROLLBACK\t')];assert len(selected)==1
fields=selected[0];expected=open(sys.argv[2],'rb').read();assert len(fields)==14 and fields[12]==hashlib.sha256(expected).hexdigest() and bytes.fromhex(fields[13])==expected
paths=[x.split('\t') for x in rows if x.startswith('ROLLBACK_PATH\t')]
assert paths[0][1]=='ROOT' and [bytes.fromhex(x[2]) for x in paths[1:]]==[b'wp-content',b'wp-content/plugins',b'wp-content/plugins/synthetic']
PY

for bad in relative / /tmp//site /tmp/./site /tmp/../site "$TEST_ROOT/";do expect_fail "bad_root_$(printf %s "$bad"|shasum|cut -c1-8)" /bin/bash "$TMP/probe" "$bad" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory '';done
ln -s "$TEST_ROOT" "$TMP/symlink-root";expect_fail symlink_root /bin/bash "$TMP/probe" "$TMP/symlink-root" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory ''
ln -s ../../uploads "$TEST_ROOT/wp-content/plugins/synthetic/link";run_inventory >"$TMP/symlink.tsv";grep -Fq $'UNRESOLVED\tSYMLINK_UNRESOLVED\t' "$TMP/symlink.tsv"||fail symlink_not_unresolved;rm "$TEST_ROOT/wp-content/plugins/synthetic/link"
ln "$TEST_ROOT/wp-content/plugins/synthetic/plugin.php" "$TEST_ROOT/wp-content/plugins/synthetic/hardlink.php";run_inventory >"$TMP/hardlink.tsv";grep -Fq $'UNRESOLVED\tHARDLINK_UNRESOLVED\t' "$TMP/hardlink.tsv"||fail hardlink_not_unresolved;rm "$TEST_ROOT/wp-content/plugins/synthetic/hardlink.php"
dd if=/dev/zero of="$TEST_ROOT/wp-content/plugins/synthetic/too-large.bin" bs=1048576 count=17 status=none
TOO_HEX="$(python3 -c 'print(b"wp-content/plugins/synthetic/too-large.bin".hex())')"
expect_fail selected_byte_cap /bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" rollback "$TOO_HEX";rm "$TEST_ROOT/wp-content/plugins/synthetic/too-large.bin"
cp "$TMP/helper" "$TMP/substituted";printf X >>"$TMP/substituted"
SUB_SHA="$(sha "$TMP/substituted")";[[ "$SUB_SHA" != "$BINARY_SHA" ]]||fail substitution_fixture
/usr/bin/python3 - "$LOADER" "$TMP/substituted" "$TMP/substituted-probe" <<'PY'
import base64,pathlib,sys
loader,binary,output=map(pathlib.Path,sys.argv[1:]);marker=b'__WAPP_NATIVE_HELPER_BASE64_PAYLOAD__';raw=loader.read_bytes();output.write_bytes(raw.replace(marker,base64.b64encode(binary.read_bytes())));output.chmod(0o700)
PY
expect_fail helper_substitution /bin/bash "$TMP/substituted-probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory ''
printf 'PASS: provider-neutral native helper enforces descriptor/no-follow/no-atime/two-pass/rollback contracts\n'
