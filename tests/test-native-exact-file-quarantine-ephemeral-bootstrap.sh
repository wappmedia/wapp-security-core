#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."&&pwd)"
python3 - "$ROOT/config/native-exact-file-quarantine-ephemeral-bootstrap.json" "$ROOT/libexec/wapp-native-exact-file-quarantine-ephemeral-memfd-launcher-linux-x86_64.b64.txt" "$ROOT/native/exact-file-quarantine-ephemeral-memfd-launcher.c" "$ROOT/lib/native-exact-file-quarantine-ephemeral-loader.sh" <<'PY'
import base64,hashlib,json,pathlib,sys
p=json.load(open(sys.argv[1]));raw=base64.b64decode(pathlib.Path(sys.argv[2]).read_text().strip(),validate=True)
assert p['authority']=={'apply':False,'closure':False,'mutation':False,'prepare':False,'ready':False}
assert p['residual_risk']=='SAME_PRINCIPAL_TOCTOU_RISK_REQUIRES_EXPLICIT_LIVE_GO'
assert len(raw)==p['launcher_binary_bytes'] and hashlib.sha256(raw).hexdigest()==p['launcher_binary_sha256']
assert pathlib.Path(sys.argv[2]).stat().st_size==p['launcher_encoded_bytes'] and hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()==p['launcher_encoded_sha256']
s=pathlib.Path(sys.argv[3]).read_text();l=pathlib.Path(sys.argv[4]).read_text()
for needle in ['apply','observe-quarantined','rollback','observe-original','F_ADD_SEALS','SYS_execveat','HELPER_SHA256']:
 assert needle in s
for needle in ['__WAPP_EXACT_FILE_LAUNCHER_BASE64_PAYLOAD__','__WAPP_EXACT_FILE_HELPER_BASE64_PAYLOAD__','SAME_PRINCIPAL_TOCTOU_RISK_REQUIRES_LIVE_GO','CLEANUP_VERIFIED']:
 assert needle in l
PY
printf 'PASS: exact-file ephemeral mutation runtime is release-pinned, non-authorizing and risk-gated\n'
