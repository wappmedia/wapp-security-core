#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
MODEL="$ROOT/lib/native-drift-diagnostic.py"
POLICY="$ROOT/config/native-filesystem-helper.json"
TMP="$(mktemp -d 2>/dev/null||mktemp -d -t wapp-drift-memory-test)"
trap 'rm -rf "$TMP"' EXIT
source "$ROOT/tests/helpers/recovery-keychain-fixture.sh"
wapp_test_setup_recovery_keychain "$TMP/keychain"

operation="$(printf bounded-parser-maximum|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
root_path=/tmp/provider-neutral/site-root
helper_sha="$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binary_sha256"])' "$POLICY")"
pass1="$(printf pass1|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
pass2="$(printf pass2|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"
runtime_identity="loader=/usr/bin/perl|loader_sha=$(printf perl|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')|loader_meta=0:0:755:1:2:3|helper_sha=$helper_sha|transport=sealed_memfd_execveat_v1"
runtime_sha="$(printf %s "$runtime_identity"|/usr/bin/openssl dgst -sha256|/usr/bin/awk '{print $NF}')"

/bin/bash "$ROOT/bin/wapp-product-seal" "$TMP/product-seal.json" >/dev/null
/usr/bin/python3 - "$TMP/raw.tsv" "$operation" "$root_path" "$helper_sha" "$pass1" "$pass2" "$runtime_identity" "$runtime_sha" <<'PY'
import sys
out,operation,root,helper,pass1,pass2,runtime,runtime_sha=sys.argv[1:]
count=200_000
with open(out,'w',encoding='ascii',newline='') as handle:
    handle.write('CAPTURE_NONCE\t'+operation+'\n')
    handle.write('\t'.join(('DRIFT_DIAGNOSTIC','SIGNED_DRIFT_DIAGNOSTIC_MODE_V1',root.encode().hex(),'11','22','11','22',pass1,pass2,helper,runtime_sha,runtime.encode().hex(),str(count),'0','READ_ONLY','NON_AUTHORIZING'))+'\n')
    absent=['-']*13
    for index in range(count):
        path=('wp-content/cache/%06d.log'%index).encode().hex()
        present=['REGULAR','11',str(1000+index),'1','0644','1000','1000','1','44','55','a'*64,'-','0']
        handle.write('\t'.join(['DRIFT',path,'CREATED','false','true',*absent,*present])+'\n')
PY

run_model(){
  if [[ "$(uname -s)" == Linux ]];then
    (ulimit -v 262144;PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$MODEL" "$@")
  else
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$MODEL" "$@"
  fi
}

run_model create "$TMP/raw.tsv" "$root_path" "$operation" 2026-08-27T00:00:00Z "$TMP/product-seal.json" "$TMP/artifact.json"
run_model verify "$TMP/artifact.json" | /usr/bin/grep -Fq 'VERIFIED_NON_AUTHORIZING'

# The compact parser must not silently truncate the maximum declared set.
/usr/bin/python3 - "$TMP/artifact.json" <<'PY'
import sys
needle=b'"change_type":"CREATED"';count=0;tail=b'';last=b''
with open(sys.argv[1],'rb') as handle:
    while True:
        chunk=handle.read(1024*1024)
        if not chunk:break
        current=tail+chunk;count+=current.count(needle);tail=current[-len(needle)+1:];last=chunk[-1:]
assert count==200_000 and last==b'\n'
PY

printf 'PASS: maximum bounded diagnostic parses and rederives below the unchanged 256 MiB Linux limit\n'
