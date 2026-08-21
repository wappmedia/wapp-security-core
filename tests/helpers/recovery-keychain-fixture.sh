#!/usr/bin/env bash

# Test-only implementation of the macOS `security` commands used by
# recovery-integrity.sh. Production code still requires the real Keychain.
wapp_test_setup_recovery_keychain() {
  local fixture_root mock_bin
  fixture_root="$1"
  mock_bin="${fixture_root}/recovery-keychain-bin"
  mkdir -p "$mock_bin"
  export WAPP_TEST_RECOVERY_KEYCHAIN_DB="${fixture_root}/recovery-keychain-key"

  cat > "${mock_bin}/security" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  find-generic-password)
    [[ -f "$WAPP_TEST_RECOVERY_KEYCHAIN_DB" ]] || exit 44
    if [[ " $* " == *" -w "* ]]; then
      cat "$WAPP_TEST_RECOVERY_KEYCHAIN_DB"
    fi
    ;;
  add-generic-password)
    password=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "-w" ]]; then
        password="${2:-}"
        break
      fi
      shift
    done
    [[ "$password" =~ ^[a-fA-F0-9]{64}$ ]]
    printf '%s' "$password" > "$WAPP_TEST_RECOVERY_KEYCHAIN_DB"
    ;;
  *)
    exit 64
    ;;
esac
EOF
  chmod +x "${mock_bin}/security"
  PATH="${mock_bin}:${PATH}"
  export PATH
}
