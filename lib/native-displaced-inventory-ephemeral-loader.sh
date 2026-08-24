#!/usr/bin/env bash
# Degraded-assurance, operation-bound staging loader for the release-pinned
# Public Core native filesystem helper. Only the launcher touches disk.
unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH NPM_CONFIG_PREFIX PYTHONPATH PYTHONHOME
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
set -eEuo pipefail
umask 077

fail(){ printf 'native-ephemeral-loader: %s\n' "$1" >&2;exit 20; }
STAT=/usr/bin/stat
OPENSSL=/usr/bin/openssl
MKDIR=/bin/mkdir
CHMOD=/bin/chmod
RM=/bin/rm
RMDIR=/bin/rmdir
LAUNCHER_SHA=ae64295bd05299f8b35605d6ae3bee6d9a8a06c8da5caa373fc97a8889cba66a
LAUNCHER_BYTES=35576

meta(){ "$STAT" -c '%u:%g:%a:%d:%i:%s' "$1" 2>/dev/null; }
trusted_metadata(){
  local value="$1" uid gid mode
  IFS=: read -r uid gid mode _ <<<"$value"
  [[ "$uid" == 0&&"$gid" == 0&&"$mode" =~ ^[0-7]{3,4}$ ]]||return 1
  (( (8#$mode & 022)==0 ))||return 1
}
trusted_directory(){
  local path="$1" value
  [[ -d "$path"&&! -L "$path" ]]||return 1
  value="$(meta "$path")"||return 1
  trusted_metadata "$value"
}
trusted_physical_file(){
  local path="$1" value parent
  [[ -f "$path"&&! -L "$path"&&-x "$path" ]]||return 1
  value="$(meta "$path")"||return 1
  trusted_metadata "$value"||return 1
  parent="${path%/*}"
  while :;do
    trusted_directory "$parent"||return 1
    [[ "$parent" == / ]]&&break;parent="${parent%/*}";[[ -n "$parent" ]]||parent=/
  done
}
trusted_usrmerge_link(){
  case "$1" in
    "'/bin' -> 'usr/bin'"|"'/bin' -> '/usr/bin'") return 0;;
    *) return 1;;
  esac
}
trusted_usrmerge_tool(){
  local logical="$1" physical description logical_meta physical_meta bin_meta uid gid _
  case "$logical" in
    /bin/mkdir) physical=/usr/bin/mkdir;;
    /bin/chmod) physical=/usr/bin/chmod;;
    /bin/rm) physical=/usr/bin/rm;;
    /bin/rmdir) physical=/usr/bin/rmdir;;
    *) return 1;;
  esac
  [[ -L /bin ]]||return 1
  description="$(LC_ALL=C QUOTING_STYLE=shell-always "$STAT" -c '%N' -- /bin 2>/dev/null)"||return 1
  trusted_usrmerge_link "$description"||return 1
  bin_meta="$(meta /bin)"||return 1;IFS=: read -r uid gid _ <<<"$bin_meta"
  [[ "$uid" == 0&&"$gid" == 0 ]]||return 1
  trusted_directory /||return 1
  trusted_directory /usr||return 1
  trusted_directory /usr/bin||return 1
  trusted_physical_file "$physical"||return 1
  [[ -f "$logical"&&! -L "$logical"&&-x "$logical"&&"$logical" -ef "$physical" ]]||return 1
  logical_meta="$(meta "$logical")"||return 1;physical_meta="$(meta "$physical")"||return 1
  [[ "$logical_meta" == "$physical_meta" ]]||return 1
}
trusted_file(){
  local path="$1"
  case "$path" in
    /usr/bin/stat|/usr/bin/openssl) trusted_physical_file "$path";;
    /bin/mkdir|/bin/chmod|/bin/rm|/bin/rmdir)
      if [[ -d /bin&&! -L /bin ]];then trusted_physical_file "$path";else trusted_usrmerge_tool "$path";fi
      ;;
    *) return 1;;
  esac
}
sha(){
  local value
  value="$(LC_ALL=C "$OPENSSL" dgst -sha256 -r "$1" 2>/dev/null)"||fail 'SHA-256 failed'
  value="${value%% *}";[[ "$value" =~ ^[a-f0-9]{64}$ ]]||fail 'malformed SHA-256';printf %s "$value"
}
hash_text(){ local value;value="$(LC_ALL=C "$OPENSSL" dgst -sha256 2>/dev/null)"||fail 'SHA-256 stream failed';value="${value##* }";[[ "$value" =~ ^[a-f0-9]{64}$ ]]||fail 'malformed stream SHA-256';printf %s "$value"; }

target_root="${1:-}";capture_nonce="${2:-}";native_sha="${3:-}";native_bytes="${4:-}";capture_mode="${5:-inventory}";selected_rel_hex="${6:-}"
[[ "$target_root" == /*&&"$target_root" != /&&${#target_root} -le 4096&&"$target_root" != */&&"$target_root" != *//* ]]||fail 'invalid bounded target'
IFS=/ read -r -a root_parts <<<"${target_root#/}";for part in "${root_parts[@]}";do [[ -n "$part"&&"$part" != .&&"$part" != .. ]]||fail 'unsafe target component';done
[[ "$capture_nonce" =~ ^[a-f0-9]{64}$&&"$native_sha" == 8a02bd728929c50a201ed3f322dfee1c3bf7cf424c21b13f47b6ab7069c91fb5&&"$native_bytes" == 84376 ]]||fail 'invalid release binding'
[[ ( "$capture_mode" == inventory||"$capture_mode" == diagnostic )&&-z "$selected_rel_hex"||"$capture_mode" == rollback&&"$selected_rel_hex" =~ ^[a-f0-9]{2,8192}$&&$((${#selected_rel_hex}%2)) -eq 0 ]]||fail 'invalid bounded capture mode'
for tool in "$STAT" "$OPENSSL" "$MKDIR" "$CHMOD" "$RM" "$RMDIR";do trusted_file "$tool"||fail 'trusted base tools unavailable';done
[[ -d "$target_root"&&! -L "$target_root" ]]||fail 'exact target root unavailable'

stage_parent="${target_root%/*}";[[ "$stage_parent" == /*&&"$stage_parent" != /&&-d "$stage_parent"&&! -L "$stage_parent" ]]||fail 'private staging parent unavailable'
stage_dir="$stage_parent/.wapp-security-ephemeral-bootstrap-$capture_nonce"
launcher="$stage_dir/wapp-native-launcher-$capture_nonce"
[[ "$stage_dir" != "$target_root"&&"$stage_dir" != "$target_root/"*&&! -e "$stage_dir"&&! -L "$stage_dir" ]]||fail 'operation staging collision or webroot overlap'
root_meta="$(meta "$target_root")"||fail 'target root metadata unavailable';IFS=: read -r root_uid root_gid _ <<<"$root_meta"

created=false;launcher_meta='';cleanup_done=false
cleanup(){
  local rc=$? current
  if [[ "$created" == true ]];then
    if [[ -e "$launcher"||-L "$launcher" ]];then
      current="$(meta "$launcher" 2>/dev/null||true)"
      if [[ -z "$launcher_meta"||"$current" != "$launcher_meta"||"$(sha "$launcher" 2>/dev/null||true)" != "$LAUNCHER_SHA" ]];then
        printf 'native-ephemeral-loader: cleanup identity drift; staged path retained fail-closed\n' >&2
        exit 20
      fi
      "$RM" -- "$launcher"||exit 20
    fi
    [[ ! -e "$launcher"&&! -L "$launcher" ]]||exit 20
    "$RMDIR" -- "$stage_dir"||exit 20
    [[ ! -e "$stage_dir"&&! -L "$stage_dir" ]]||exit 20
    cleanup_done=true
  fi
  return "$rc"
}
trap cleanup EXIT

"$MKDIR" -m 700 -- "$stage_dir"||fail 'exclusive operation staging create failed';created=true
dir_meta="$(meta "$stage_dir")"||fail 'staging metadata unavailable';IFS=: read -r dir_uid dir_gid dir_mode _ <<<"$dir_meta"
[[ "$dir_uid" == "$root_uid"&&"$dir_gid" == "$root_gid"&&"$dir_mode" == 700 ]]||fail 'private staging identity mismatch'

set -C
"$OPENSSL" base64 -d -A >"$launcher" <<'WAPP_EPHEMERAL_LAUNCHER_BASE64_V1'
__WAPP_EPHEMERAL_LAUNCHER_BASE64_PAYLOAD__
WAPP_EPHEMERAL_LAUNCHER_BASE64_V1
set +C
"$CHMOD" 700 -- "$launcher"||fail 'launcher mode failed'
launcher_meta="$(meta "$launcher")"||fail 'launcher metadata unavailable';IFS=: read -r file_uid file_gid file_mode file_dev file_inode file_bytes <<<"$launcher_meta"
[[ "$file_uid" == "$root_uid"&&"$file_gid" == "$root_gid"&&"$file_mode" == 700&&"$file_bytes" == "$LAUNCHER_BYTES"&&"$(sha "$launcher")" == "$LAUNCHER_SHA" ]]||fail 'staged launcher identity mismatch'
launcher_identity="$(printf '%s\0%s' "$launcher_meta" "$LAUNCHER_SHA"|hash_text)";[[ "$launcher_identity" =~ ^[a-f0-9]{64}$ ]]||fail 'launcher identity hash failed'
stage_identity="$(printf '%s\0%s\0%s' "$stage_dir" "$dir_meta" "$capture_nonce"|hash_text)";[[ "$stage_identity" =~ ^[a-f0-9]{64}$ ]]||fail 'stage identity hash failed'
runtime_identity="loader=DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1|launcher_sha=$LAUNCHER_SHA|launcher_meta=$launcher_meta|helper_sha=$native_sha|transport=sealed_memfd_execveat_v1"

launcher_args=("$capture_mode" "$target_root" "$capture_nonce" "$runtime_identity");[[ -z "$selected_rel_hex" ]]||launcher_args+=("$selected_rel_hex")
"$OPENSSL" base64 -d -A <<'WAPP_NATIVE_HELPER_BASE64_V1' | "$launcher" "${launcher_args[@]}"
__WAPP_NATIVE_HELPER_BASE64_PAYLOAD__
WAPP_NATIVE_HELPER_BASE64_V1

[[ "$(meta "$launcher")" == "$launcher_meta"&&"$(sha "$launcher")" == "$LAUNCHER_SHA" ]]||fail 'staged launcher drift after execution'
"$RM" -- "$launcher"||fail 'exact launcher unlink failed';[[ ! -e "$launcher"&&! -L "$launcher" ]]||fail 'launcher cleanup absence failed'
"$RMDIR" -- "$stage_dir"||fail 'operation directory cleanup failed';[[ ! -e "$stage_dir"&&! -L "$stage_dir" ]]||fail 'operation directory cleanup absence failed'
created=false;cleanup_done=true;trap - EXIT
printf 'EPHEMERAL_BOOTSTRAP_AUDIT_V1\t%s\t%s\t%s\t%s\t%s\tCLEANUP_VERIFIED\n' "$capture_nonce" "$LAUNCHER_SHA" "$LAUNCHER_BYTES" "$launcher_identity" "$stage_identity"
exit 0
