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
expected={'tool','schema','platform','runtime_mode','loader_path','encoded_path','encoded_sha256','encoded_bytes','binary_sha256','binary_bytes','artifact_encoding','build_tool','root_contract','capture_modes','diagnostic_contract','volatile_runtime_contract'}
assert set(value)==expected and value['tool']=='wapp-security-native-filesystem-helper-policy' and value['schema']==3
assert value['platform']=='linux-x86_64' and value['loader_path']=='/usr/bin/perl'
assert value['runtime_mode']=='PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1'
assert value['root_contract']=='PROVIDER_NEUTRAL_ABSOLUTE_DESCRIPTOR_ROOT_V1'
assert value['capture_modes']==['diagnostic','inventory','rollback','volatile-inventory'] and value['diagnostic_contract']=='SIGNED_DRIFT_DIAGNOSTIC_MODE_V1'
assert value['volatile_runtime_contract']=='BOUNDED_VOLATILE_RUNTIME_DISPOSITION_V1'
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
assert b'"$PERL" -T -e' in raw
assert b'syscall(319,"wapp-native-displaced-inventory",2)' not in raw
assert b'syscall(322,$fd,"",$ptr,$env,0x1000)' not in raw
assert b'my $memfd_name="wapp-native-displaced-inventory";my $fd=syscall(319,$memfd_name,2)' in raw
assert b'my $empty_path="";syscall(322,$fd,$empty_path,$ptr,$env,0x1000)' in raw
output.write_bytes(raw.replace(marker,artifact.read_bytes().strip()));output.chmod(0o700)
PY

/usr/bin/python3 - "$LOADER" "$TMP/taint-contract.pl" <<'PY'
import pathlib,sys
loader,output=map(pathlib.Path,sys.argv[1:])
raw=loader.read_text(encoding='utf-8')
body=raw.split('"$PERL" -T -e \'\n',1)[1].split('\n\' "$native_sha"',1)[0]
marker='my $memfd_name="wapp-native-displaced-inventory";'
assert body.count(marker)==1
body=body.split(marker,1)[0]+r'''use Scalar::Util qw(tainted);
my $memfd_name="wapp-native-displaced-inventory";my $empty_path="";
my @args=("wapp-native-displaced-inventory",$mode,$root,$nonce,$expected,$identity,"7");push @args,$selected if $mode eq "rollback"||$mode eq "volatile-inventory";my @hold=map "$_\0",@args;my $ptr="";$ptr.=pack("p",$_) for @hold;$ptr.=pack("J",0);my $env=pack("J",0);
die "tainted validated syscall input\n" if grep {tainted($_)} ($memfd_name,$empty_path,$ptr,$env,@hold);
print "TAINT_CONTRACT_PASS\n";
'''
output.write_text(body,encoding='utf-8');output.chmod(0o700)
PY
TAINT_NONCE="$(printf native-helper-taint-contract|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
RUNTIME_IDENTITY="loader=/usr/bin/perl|loader_sha=$(sha /usr/bin/perl)|loader_meta=0:0:755:1:2:3|helper_sha=$BINARY_SHA|transport=sealed_memfd_execveat_v1"
/usr/bin/perl -T "$TMP/taint-contract.pl" "$BINARY_SHA" "$BINARY_BYTES" /tmp/provider-neutral-root "$TAINT_NONCE" "$RUNTIME_IDENTITY" inventory '' <"$ARTIFACT" |grep -Fxq TAINT_CONTRACT_PASS
expect_fail taint_arbitrary_identity /usr/bin/perl -T "$TMP/taint-contract.pl" "$BINARY_SHA" "$BINARY_BYTES" /tmp/provider-neutral-root "$TAINT_NONCE" arbitrary-tainted-value inventory ''
expect_fail taint_arbitrary_root /usr/bin/perl -T "$TMP/taint-contract.pl" "$BINARY_SHA" "$BINARY_BYTES" /tmp/../arbitrary "$TAINT_NONCE" "$RUNTIME_IDENTITY" inventory ''

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

# The diagnostic mode preserves the ordinary inventory failure and emits only
# a bounded metadata/hash delta for the same two descriptor-bound passes.
truncate -s 536870912 "$TEST_ROOT/z-drift-slow.bin"
printf 'delete-before\n' >"$TEST_ROOT/a-delete.php"
printf 'modify-before\n' >"$TEST_ROOT/b-modify.php"
printf 'replace-before\n' >"$TEST_ROOT/c-replace.php"
(
  sleep 0.2
  rm -- "$TEST_ROOT/a-delete.php"
  printf 'modify-after\n' >"$TEST_ROOT/b-modify.php"
  printf 'replace-after\n' >"$TEST_ROOT/c-replacement.tmp"
  mv -- "$TEST_ROOT/c-replacement.tmp" "$TEST_ROOT/c-replace.php"
  printf 'create-after\n' >"$TEST_ROOT/d-create.php"
) & mutator=$!
/bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" diagnostic '' >"$TMP/diagnostic.tsv"
wait "$mutator"
/usr/bin/python3 - "$TMP/diagnostic.tsv" <<'PY'
import sys
lines=open(sys.argv[1],encoding='ascii').read().splitlines()
assert lines[0].startswith('CAPTURE_NONCE\t')
header=lines[1].split('\t')
assert len(header)==16 and header[0:2]==['DRIFT_DIAGNOSTIC','SIGNED_DRIFT_DIAGNOSTIC_MODE_V1']
assert header[-2:]==['READ_ONLY','NON_AUTHORIZING']
deltas={bytes.fromhex(row[1]):row for row in (line.split('\t') for line in lines[2:] if line.startswith('DRIFT\t'))}
assert deltas[b'a-delete.php'][2]=='DELETED'
assert deltas[b'b-modify.php'][2]=='MODIFIED'
assert deltas[b'c-replace.php'][2]=='REPLACED'
assert deltas[b'd-create.php'][2]=='CREATED'
assert int(header[12])==len(deltas)
assert int(header[13])==sum(line.startswith('DRIFT_ISSUE\t') for line in lines)
assert all(len(row)==31 for row in deltas.values())
assert any(line.startswith('DRIFT_ISSUE\t') for line in lines)
assert not any('before' in line or 'after' in line for line in lines)
PY
expect_fail stable_diagnostic /bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" diagnostic ''

# The ordinary inventory remains strictly closed-world. Real modification,
# replacement, delete/create and symlink substitution during the two passes
# must abort rather than converting diagnostic knowledge into clearance.
printf 'delete-again\n' >"$TEST_ROOT/a-delete.php"
printf 'symlink-before\n' >"$TEST_ROOT/e-symlink.php"
rm -f "$TEST_ROOT/d-create.php"
(
  sleep 0.2
  rm -- "$TEST_ROOT/a-delete.php"
  printf 'modify-again\n' >"$TEST_ROOT/b-modify.php"
  printf 'replace-again\n' >"$TEST_ROOT/c-replacement.tmp"
  mv -- "$TEST_ROOT/c-replacement.tmp" "$TEST_ROOT/c-replace.php"
  printf 'create-again\n' >"$TEST_ROOT/d-create.php"
  rm -- "$TEST_ROOT/e-symlink.php"
  ln -s b-modify.php "$TEST_ROOT/e-symlink.php"
) & inventory_mutator=$!
expect_fail inventory_real_drift run_inventory
wait "$inventory_mutator"
grep -Fq 'inventory drift between passes' "$TMP/inventory_real_drift.err"||fail inventory_drift_not_fail_closed
rm -f "$TEST_ROOT/d-create.php" "$TEST_ROOT/e-symlink.php"
printf 'delete-stable\n' >"$TEST_ROOT/a-delete.php"
printf 'symlink-stable\n' >"$TEST_ROOT/e-symlink.php"
run_inventory >"$TMP/post-drift-stable.tsv"

# Capacity regression: one bounded fixture simultaneously crosses the former
# 100,000-file and 8 GiB aggregate ceilings without weakening any per-file,
# output, memory or wall-clock guardrail. Allocate and sync the large fixture
# files before capture so the Linux regression proves hashing capacity without
# depending on runner-specific sparse-extent metadata transitions.
CAPACITY_ROOT="$TMP/provider-neutral/capacity-root"
mkdir -p "$CAPACITY_ROOT"
/usr/bin/python3 - "$CAPACITY_ROOT" <<'PY'
import os, pathlib, sys
root=pathlib.Path(sys.argv[1])
for index in range(99992):
    fd=os.open(root/f'e{index:06d}',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
for index in range(9):
    fd=os.open(root/f'large-{index}',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.posix_fallocate(fd,0,1024*1024*1024);os.fsync(fd);os.close(fd)
dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dirfd);os.close(dirfd)
items=list(root.iterdir());stats=[item.stat(follow_symlinks=False) for item in items]
assert len(items)==100001 and sum(item.st_size for item in stats)==9*1024*1024*1024
assert all(item.st_nlink==1 for item in stats)
assert all(item.st_blocks>0 for item in stats if item.st_size)
PY
/bin/bash "$TMP/probe" "$CAPACITY_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory '' >"$TMP/capacity.tsv"
/usr/bin/python3 - "$TMP/capacity.tsv" "$SOURCE" <<'PY'
import hashlib,pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text(encoding='ascii').splitlines();payload=lines[1:]
assert lines[0].startswith('CAPTURE_NONCE\t') and payload==sorted(set(payload))
summary=[line.split('\t') for line in payload if line.startswith('SUMMARY\t')]
assert len(summary)==1
s=summary[0]
expected=['100002','1','100001','100001',str(9*1024*1024*1024),'0','0','0','true']
assert s[1:10]==expected,(s[1:10],expected)
assert s[11:]==['200000','50000','150000','1073741824','34359738368','64','900','4096','125829120']
entries=[line for line in payload if line.startswith('ENTRY\t')]
h=hashlib.sha256()
for line in entries:h.update(line.encode()+b'\n')
assert h.hexdigest()==s[10]
source=pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
assert 'file_bytes>MAX_TOTAL_BYTES-s->hashed_bytes' in source
assert 's->hashed_bytes+file_bytes>MAX_TOTAL_BYTES' not in source
assert 'n>=ENTRY_CAP-s->entries' not in source
assert 'if(n>=ENTRY_CAP)' in source
PY
rm -rf "$CAPACITY_ROOT"

# Genuine bounded-resource failures remain incomplete/fail-closed. The helper
# must also surface output-device exhaustion instead of returning success.
truncate -s 1073741825 "$TEST_ROOT/over-file-cap.bin"
run_inventory >"$TMP/over-file-cap.tsv"
grep -Fq $'UNRESOLVED\tFILE_BYTE_CAP\t' "$TMP/over-file-cap.tsv"||fail file_byte_cap_missing
/usr/bin/python3 - "$TMP/over-file-cap.tsv" <<'PY'
import pathlib,sys
s=[x.split('\t') for x in pathlib.Path(sys.argv[1]).read_text().splitlines() if x.startswith('SUMMARY\t')]
assert len(s)==1 and s[0][9]=='false' and int(s[0][8])>=1
PY
rm "$TEST_ROOT/over-file-cap.bin"
run_to_full(){ /bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory '' >/dev/full; }
expect_fail output_disk_exhaustion run_to_full
run_under_tight_address_space(){
  (
    ulimit -v 131072
    /bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" inventory ''
  )
}
expect_fail address_space_exhaustion run_under_tight_address_space
grep -Fq 'wapp-native-displaced-inventory: process limits unavailable' "$TMP/address_space_exhaustion.err"||fail address_space_exhaustion_not_fail_closed

# A disposition-aware inventory keeps every path visible and accepts only the
# exact bounded metadata behavior encoded by the already verified policy token.
printf 'log-before\n' >"$TEST_ROOT/a-runtime.log";printf 'runtime-state\n' >"$TEST_ROOT/b-runtime.php"
chmod 0644 "$TEST_ROOT/a-runtime.log" "$TEST_ROOT/b-runtime.php"
LOG_HEX="$(python3 -c 'print(b"a-runtime.log".hex())')";STATE_HEX="$(python3 -c 'print(b"b-runtime.php".hex())')";VOLATILE_POLICY="L:$LOG_HEX,C:$STATE_HEX"
(
  sleep 0.2
  printf 'log-after\n' >>"$TEST_ROOT/a-runtime.log"
  chmod 0644 "$TEST_ROOT/b-runtime.php"
) & volatile_mutator=$!
/bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" volatile-inventory "$VOLATILE_POLICY" >"$TMP/volatile.tsv"
wait "$volatile_mutator"
/usr/bin/python3 - "$TMP/volatile.tsv" "$LOG_HEX" "$STATE_HEX" "$VOLATILE_POLICY" <<'PY'
import hashlib,sys
lines=open(sys.argv[1],encoding='ascii').read().splitlines();assert lines[0].startswith('CAPTURE_NONCE\t')
assert any(line.startswith('ENTRY\t'+sys.argv[2]+'\t') for line in lines)
assert any(line.startswith('ENTRY\t'+sys.argv[3]+'\t') for line in lines)
summary=[line.split('\t') for line in lines if line.startswith('VOLATILE_RUNTIME_CANDIDATE\t')];assert len(summary)==1
assert summary[0][1:] == ['BOUNDED_VOLATILE_RUNTIME_CANDIDATE_V1',hashlib.sha256(sys.argv[4].encode()).hexdigest(),'2','VISIBLE','UNVERIFIED_NON_AUTHORIZING']
assert 'VOLATILE_RUNTIME_CANDIDATE_PATH\t'+sys.argv[2]+'\tAPPEND_PREFIX_VERIFIED_LOG_GROWTH\tOBSERVED_DRIFT' in lines
assert 'VOLATILE_RUNTIME_CANDIDATE_PATH\t'+sys.argv[3]+'\tCTIME_ONLY\tOBSERVED_DRIFT' in lines
PY
expect_fail arbitrary_volatile_path /bin/bash "$TMP/probe" "$TEST_ROOT" "$NONCE" "$BINARY_SHA" "$BINARY_BYTES" volatile-inventory "L:$LOG_HEX,C:$STATE_HEX,C:757365722d61646465642e6c6f67"
rm "$TEST_ROOT/z-drift-slow.bin"
printf 'PASS: provider-neutral native helper enforces descriptor/no-follow/no-atime/two-pass/rollback contracts\n'
