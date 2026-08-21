#!/usr/bin/env bash
set -euo pipefail

RECOVERY_INTEGRITY_SERVICE="Wapp Security Recovery Integrity"

recovery_integrity_fail(){ printf 'Fel: %s\n' "$1" >&2; return 1; }

recovery_stat_owner_mode(){
  local path="$1"
  if /usr/bin/stat -f '%u %Lp' "$path" >/dev/null 2>&1; then
    /usr/bin/stat -f '%u %Lp' "$path"
  else
    /usr/bin/stat -c '%u %a' "$path"
  fi
}

recovery_root_owned_nonwritable(){
  local identity uid mode permissions
  identity="$(recovery_stat_owner_mode "$1" 2>/dev/null)" || return 1
  [[ "$identity" =~ ^[0-9]+\ [0-7]{3,4}$ ]] || return 1
  uid="${identity%% *}";mode="${identity#* }"
  [[ "$uid" == 0 ]] || return 1
  permissions=$((8#$mode))
  (( (permissions & 8#022) == 0 ))
}

recovery_trusted_python_candidate(){
  local requested="$1" parent component link_target resolved link_identity
  [[ "$requested" == /* && "${requested##*/}" == python3 ]] || return 1
  parent="${requested%/*}";[[ -n "$parent" ]] || return 1
  if [[ -L "$requested" ]]; then
    link_target="$(/usr/bin/readlink "$requested" 2>/dev/null)" || return 1
    [[ "$link_target" =~ ^python3\.[0-9]+$ ]] || return 1
    resolved="$parent/$link_target"
  else
    resolved="$requested"
  fi
  [[ -f "$resolved" && ! -L "$resolved" && -x "$resolved" ]] || return 1
  recovery_root_owned_nonwritable "$resolved" || return 1
  if [[ -L "$requested" ]]; then
    link_identity="$(recovery_stat_owner_mode "$requested" 2>/dev/null)" || return 1
    [[ "${link_identity%% *}" == 0 ]] || return 1
  fi
  component="$parent"
  while :; do
    [[ -d "$component" && ! -L "$component" ]] || return 1
    recovery_root_owned_nonwritable "$component" || return 1
    [[ "$component" == / ]] && break
    component="${component%/*}";[[ -n "$component" ]] || component=/
  done
  printf '%s' "$resolved"
}

recovery_trusted_fixed_python(){
  recovery_trusted_python_candidate /usr/bin/python3
}

# Lexical path containment for signed recovery/remediation artifacts. Prefix
# matching alone accepts paths such as /allowed/root/../outside; reject every
# path that requires normalization before it can be compared to its root.
recovery_path_is_within(){
  local root="$1" path="$2"
  [[ "$root" == /* && "$root" != */ && "$path" == "$root"/* ]] || return 1
  case "$path" in
    *$'\n'*|*$'\r'*|*$'\t'*|*//*|*/./*|*/../*|*/.|*/..) return 1 ;;
  esac
  return 0
}

recovery_integrity_key(){
  local account key
  account="${USER:-$(id -un 2>/dev/null || printf unknown)}"
  command -v security >/dev/null 2>&1 || recovery_integrity_fail "macOS Keychain-kommandot security saknas"
  command -v openssl >/dev/null 2>&1 || recovery_integrity_fail "openssl krävs för recovery-integritet"
  key="$(security find-generic-password -s "$RECOVERY_INTEGRITY_SERVICE" -a "$account" -w 2>/dev/null || true)"
  if [[ ! "$key" =~ ^[a-fA-F0-9]{64}$ ]]; then
    key="$(openssl rand -hex 32 2>/dev/null)"
    [[ "$key" =~ ^[a-fA-F0-9]{64}$ ]] || recovery_integrity_fail "Kunde inte skapa recovery-integritetsnyckel"
    security add-generic-password -U -s "$RECOVERY_INTEGRITY_SERVICE" -a "$account" -w "$key" >/dev/null 2>&1 || recovery_integrity_fail "Kunde inte spara recovery-integritetsnyckeln i macOS Keychain"
  fi
  printf '%s' "$key"
}

recovery_sha256_file(){
  local file
  file="$1"
  [[ -f "$file" ]] || recovery_integrity_fail "Kan inte hasha saknad fil: $file"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  fi
}

recovery_hmac_file(){
  local file key
  file="$1"; key="$(recovery_integrity_key)"
  [[ -f "$file" ]] || recovery_integrity_fail "Kan inte signera saknad fil: $file"
  openssl dgst -sha256 -hmac "$key" "$file" 2>/dev/null | awk '{print $NF}' | tr '[:upper:]' '[:lower:]'
}

recovery_sign_file(){
  local file sig_file sig
  file="$1"; sig_file="${2:-${file}.hmac}"
  sig="$(recovery_hmac_file "$file")"
  [[ "$sig" =~ ^[a-f0-9]{64}$ ]] || recovery_integrity_fail "Ogiltig HMAC genererades för $file"
  umask 077
  printf '%s\n' "$sig" > "$sig_file"
  chmod 600 "$sig_file" 2>/dev/null || true
  printf '%s' "$sig_file"
}

recovery_verify_file(){
  local file sig_file expected actual
  file="$1"; sig_file="${2:-${file}.hmac}"
  [[ -f "$file" && -f "$sig_file" ]] || recovery_integrity_fail "Manifest eller HMAC saknas: $file"
  expected="$(tr -d '[:space:]' < "$sig_file" | tr '[:upper:]' '[:lower:]')"
  [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || recovery_integrity_fail "Ogiltig HMAC-fil: $sig_file"
  actual="$(recovery_hmac_file "$file")"
  [[ "$actual" == "$expected" ]] || recovery_integrity_fail "Recovery-manifestets HMAC verifierar inte: $file"
}

recovery_session_id(){
  local client seed digest
  client="$1"
  seed="${client}|$(date -u '+%Y%m%dT%H%M%SZ')|$$|$(openssl rand -hex 8 2>/dev/null || printf '%s' "$RANDOM")"
  if command -v shasum >/dev/null 2>&1; then
    digest="$(printf '%s' "$seed" | shasum -a 256 | awk '{print $1}')"
  else
    digest="$(printf '%s' "$seed" | openssl dgst -sha256 | awk '{print $NF}')"
  fi
  printf 'wrs-%s-%s' "$(date -u '+%Y%m%dT%H%M%SZ')" "$(printf '%s' "$digest" | cut -c1-16)"
}
