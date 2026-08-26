#!/usr/bin/env bash
# Operation-bound transport for the release-pinned exact-file helper. This
# template has mutation capability but no standalone authority: the private
# reviewed package, signed registry and explicit human GO are mandatory.
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH NPM_CONFIG_PREFIX PYTHONPATH PYTHONHOME
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
set -eEuo pipefail
umask 077
fail(){ printf 'native-exact-file-loader: %s\n' "$1" >&2;exit 20; }
STAT=/usr/bin/stat;OPENSSL=/usr/bin/openssl;MKDIR=/bin/mkdir;CHMOD=/bin/chmod;RM=/bin/rm;RMDIR=/bin/rmdir
LAUNCHER_SHA=5e5d00496a9ab1d855c6ff9b4a8ffbcbe8d344043d5da3877115313dff523484
LAUNCHER_BYTES=35288
HELPER_SHA=7f26561679d52085aad5bedf244c6cdfa23cb176d1f7e760348b732d5331f111
HELPER_BYTES=52016
meta(){ "$STAT" -c '%u:%g:%a:%d:%i:%s' "$1" 2>/dev/null; }
trusted_metadata(){ local v="$1" u g m;IFS=: read -r u g m _ <<<"$v";[[ "$u" == 0&&"$g" == 0&&"$m" =~ ^[0-7]{3,4}$ ]]&&(( (8#$m&022)==0 )); }
trusted_directory(){ [[ -d "$1"&&! -L "$1" ]]&&trusted_metadata "$(meta "$1")"; }
trusted_physical_file(){ local p="$1" d;[[ -f "$p"&&! -L "$p"&&-x "$p" ]]||return 1;trusted_metadata "$(meta "$p")"||return 1;d="${p%/*}";while :;do trusted_directory "$d"||return 1;[[ "$d" == / ]]&&break;d="${d%/*}";[[ -n "$d" ]]||d=/;done; }
trusted_usrmerge(){ local l="$1" p description;case "$l" in /bin/mkdir)p=/usr/bin/mkdir;;/bin/chmod)p=/usr/bin/chmod;;/bin/rm)p=/usr/bin/rm;;/bin/rmdir)p=/usr/bin/rmdir;;*)return 1;;esac;[[ -L /bin ]]||return 1;description="$(LC_ALL=C QUOTING_STYLE=shell-always "$STAT" -c '%N' -- /bin 2>/dev/null)"||return 1;[[ "$description" == "'/bin' -> 'usr/bin'"||"$description" == "'/bin' -> '/usr/bin'" ]]||return 1;trusted_directory /&&trusted_directory /usr&&trusted_directory /usr/bin&&trusted_physical_file "$p"&&[[ -f "$l"&&! -L "$l"&&-x "$l"&&"$l" -ef "$p"&&"$(meta "$l")" == "$(meta "$p")" ]]; }
trusted_file(){ case "$1" in /usr/bin/stat|/usr/bin/openssl)trusted_physical_file "$1";;/bin/mkdir|/bin/chmod|/bin/rm|/bin/rmdir)if [[ -d /bin&&! -L /bin ]];then trusted_physical_file "$1";else trusted_usrmerge "$1";fi;;*)return 1;;esac; }
sha(){ local v;v="$(LC_ALL=C "$OPENSSL" dgst -sha256 -r "$1" 2>/dev/null)"||fail 'SHA-256 failed';v="${v%% *}";[[ "$v" =~ ^[a-f0-9]{64}$ ]]||fail 'malformed SHA-256';printf %s "$v"; }
hash_text(){ local v;v="$(LC_ALL=C "$OPENSSL" dgst -sha256 2>/dev/null)"||fail 'stream SHA-256 failed';v="${v##* }";[[ "$v" =~ ^[a-f0-9]{64}$ ]]||fail 'malformed stream SHA-256';printf %s "$v"; }

root="${1:-}";operation="${2:-}";root_dev="${3:-}";root_ino="${4:-}";manifest_sha="${5:-}";manifest_hex="${6:-}";parent_sha="${7:-}";parent_hex="${8:-}";qdev="${9:-}";qino="${10:-}";mode="${11:-}"
[[ "$root" == /*&&"$root" != /&&${#root} -le 4096&&"$root" != */&&"$root" != *//* ]]||fail 'invalid canonical root'
[[ "$operation" =~ ^[a-f0-9]{32}$&&"$root_dev" =~ ^[0-9]+$&&"$root_ino" =~ ^[0-9]+$&&"$manifest_sha" =~ ^[a-f0-9]{64}$&&"$manifest_hex" =~ ^[a-f0-9]+$&&$((${#manifest_hex}%2)) -eq 0&&${#manifest_hex} -le 131072&&"$parent_sha" =~ ^[a-f0-9]{64}$&&"$parent_hex" =~ ^[a-f0-9]+$&&$((${#parent_hex}%2)) -eq 0&&${#parent_hex} -le 131072&&"$qdev" =~ ^[0-9]+$&&"$qino" =~ ^[0-9]+$ ]]||fail 'invalid bounded operation identity'
[[ "$mode" == apply||"$mode" == observe-quarantined||"$mode" == rollback||"$mode" == reconcile-rollback||"$mode" == observe-original ]]||fail 'invalid bounded mode'
for tool in "$STAT" "$OPENSSL" "$MKDIR" "$CHMOD" "$RM" "$RMDIR";do trusted_file "$tool"||fail 'trusted base tools unavailable';done
[[ -d "$root"&&! -L "$root" ]]||fail 'canonical root unavailable'
stage_parent="${root%/*}";[[ "$stage_parent" == /*&&"$stage_parent" != /&&-d "$stage_parent"&&! -L "$stage_parent" ]]||fail 'staging parent unavailable'
stage="$stage_parent/.wapp-security-exact-file-launcher-$operation";launcher="$stage/launcher-$operation"
[[ ! -e "$stage"&&! -L "$stage"&&"$stage" != "$root"&&"$stage" != "$root/"* ]]||fail 'operation staging collision'
root_meta="$(meta "$root")"||fail 'root metadata unavailable';IFS=: read -r root_uid root_gid _ <<<"$root_meta"
created=false;launcher_meta=''
cleanup(){ local rc=$? current;if [[ "$created" == true ]];then if [[ -e "$launcher"||-L "$launcher" ]];then current="$(meta "$launcher" 2>/dev/null||true)";[[ -n "$launcher_meta"&&"$current" == "$launcher_meta"&&"$(sha "$launcher" 2>/dev/null||true)" == "$LAUNCHER_SHA" ]]||{ printf 'native-exact-file-loader: staged launcher identity drift; retained fail-closed\n' >&2;exit 20;};"$RM" -- "$launcher"||exit 20;fi;[[ ! -e "$launcher"&&! -L "$launcher" ]]||exit 20;"$RMDIR" -- "$stage"||exit 20;fi;return "$rc"; }
trap cleanup EXIT
"$MKDIR" -m 700 -- "$stage"||fail 'exclusive staging create failed';created=true
dir_meta="$(meta "$stage")"||fail 'staging metadata unavailable';IFS=: read -r du dg dm _ <<<"$dir_meta";[[ "$du" == "$root_uid"&&"$dg" == "$root_gid"&&"$dm" == 700 ]]||fail 'staging identity mismatch'
set -C
"$OPENSSL" base64 -d -A >"$launcher" <<'WAPP_EXACT_FILE_LAUNCHER_BASE64_V1'
__WAPP_EXACT_FILE_LAUNCHER_BASE64_PAYLOAD__
WAPP_EXACT_FILE_LAUNCHER_BASE64_V1
set +C
"$CHMOD" 700 -- "$launcher"||fail 'launcher mode failed'
launcher_meta="$(meta "$launcher")"||fail 'launcher metadata unavailable';IFS=: read -r fu fg fm fd fi fb <<<"$launcher_meta";[[ "$fu" == "$root_uid"&&"$fg" == "$root_gid"&&"$fm" == 700&&"$fb" == "$LAUNCHER_BYTES"&&"$(sha "$launcher")" == "$LAUNCHER_SHA" ]]||fail 'launcher identity mismatch'
runtime="loader=HUMAN_OPERATOR_EMERGENCY_NATIVE_EXACT_FILE_V1|launcher_sha=$LAUNCHER_SHA|launcher_meta=$launcher_meta|helper_sha=$HELPER_SHA|transport=sealed_memfd_execveat_v1|risk=SAME_PRINCIPAL_TOCTOU_RISK_REQUIRES_LIVE_GO"
"$OPENSSL" base64 -d -A <<'WAPP_EXACT_FILE_HELPER_BASE64_V1' | "$launcher" "$mode" "$root" "$operation" "$root_dev" "$root_ino" "$manifest_sha" "$manifest_hex" "$parent_sha" "$parent_hex" "$qdev" "$qino" "$runtime" QUARANTINE_EXACT_FILE_V1
__WAPP_EXACT_FILE_HELPER_BASE64_PAYLOAD__
WAPP_EXACT_FILE_HELPER_BASE64_V1
[[ "$(meta "$launcher")" == "$launcher_meta"&&"$(sha "$launcher")" == "$LAUNCHER_SHA" ]]||fail 'launcher drift after execution'
"$RM" -- "$launcher"||fail 'launcher cleanup failed';[[ ! -e "$launcher"&&! -L "$launcher" ]]||fail 'launcher cleanup absence failed'
"$RMDIR" -- "$stage"||fail 'staging cleanup failed';[[ ! -e "$stage"&&! -L "$stage" ]]||fail 'staging cleanup absence failed'
created=false;trap - EXIT
printf 'EXACT_FILE_EPHEMERAL_RUNTIME_AUDIT_V1\t%s\t%s\t%s\t%s\t%s\tCLEANUP_VERIFIED\n' "$operation" "$LAUNCHER_SHA" "$launcher_meta" "$HELPER_SHA" "$(printf %s "$runtime"|hash_text)"
