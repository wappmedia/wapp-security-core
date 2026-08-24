#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="$ROOT/tests/public-data-boundary.py"
tmp="$(mktemp -d 2>/dev/null || mktemp -d -t wapp-public-boundary)"
trap 'rm -rf "$tmp"' EXIT

pass(){ printf 'PASS: %s\n' "$1"; }
expect_fail(){ local label="$1"; shift; if "$@" >/dev/null 2>&1; then printf 'FAIL: %s accepted\n' "$label" >&2; exit 1; fi; pass "$label"; }

mkdir -p "$tmp/safe"
printf 'example.test /var/www/example 192.0.2.42 synthetic-backdoor.php\n' > "$tmp/safe/fixture.txt"
python3 "$SCANNER" --root "$tmp/safe" --worktree-only >/dev/null
pass synthetic_fixture

mkdir -p "$tmp/infrastructure";printf 'https://ziglang.org/download/toolchain\n' > "$tmp/infrastructure/source.txt"
python3 "$SCANNER" --root "$tmp/infrastructure" --worktree-only >/dev/null
pass exact_infrastructure_domain
printf 'https://mirror.%s/download/toolchain\n' 'ziglang.org' > "$tmp/infrastructure/source.txt"
expect_fail infrastructure_subdomain python3 "$SCANNER" --root "$tmp/infrastructure" --worktree-only

mkdir -p "$tmp/ip"; printf '203.0.%s.8\n' '114' > "$tmp/ip/value.txt"
expect_fail customer_ip python3 "$SCANNER" --root "$tmp/ip" --worktree-only
mkdir -p "$tmp/domain"; printf 'customer-site.%s\n' 'com' > "$tmp/domain/value.txt"
expect_fail customer_domain python3 "$SCANNER" --root "$tmp/domain" --worktree-only
mkdir -p "$tmp/email"; printf 'operator@sample.%s\n' 'com' > "$tmp/email/value.txt"
expect_fail email python3 "$SCANNER" --root "$tmp/email" --worktree-only
mkdir -p "$tmp/path"; printf '/%s/operator/Documents/private/report.json\n' 'Users' > "$tmp/path/value.txt"
expect_fail local_path python3 "$SCANNER" --root "$tmp/path" --worktree-only
mkdir -p "$tmp/key"; printf '%s%s%s\n' '-----BEGIN ' 'PRIVATE ' 'KEY-----' > "$tmp/key/value.txt"
expect_fail private_key python3 "$SCANNER" --root "$tmp/key" --worktree-only
mkdir -p "$tmp/report/reports"; printf '{}\n' > "$tmp/report/reports/scan.json"
expect_fail report_artifact python3 "$SCANNER" --root "$tmp/report" --worktree-only

mkdir -p "$tmp/history";git -C "$tmp/history" init -q;git -C "$tmp/history" config user.name synthetic;git -C "$tmp/history" config user.email synthetic
printf 'synthetic safe\n' > "$tmp/history/value.txt";git -C "$tmp/history" add -- value.txt;git -C "$tmp/history" commit -qm safe
printf 'historical-customer.%s\n' 'com' > "$tmp/history/value.txt";git -C "$tmp/history" add -- value.txt;git -C "$tmp/history" commit -qm unsafe
printf 'synthetic safe again\n' > "$tmp/history/value.txt";git -C "$tmp/history" add -- value.txt;git -C "$tmp/history" commit -qm removed
expect_fail deleted_history_blob python3 "$SCANNER" --root "$tmp/history"

mkdir -p "$tmp/metadata";git -C "$tmp/metadata" init -q;git -C "$tmp/metadata" config user.name synthetic;git -C "$tmp/metadata" config user.email synthetic
printf 'synthetic safe\n' > "$tmp/metadata/value.txt";git -C "$tmp/metadata" add -- value.txt;git -C "$tmp/metadata" commit -qm safe
unsafe_message="historical-customer.";unsafe_message="${unsafe_message}com";git -C "$tmp/metadata" commit --allow-empty -qm "$unsafe_message"
expect_fail commit_metadata python3 "$SCANNER" --root "$tmp/metadata"

python3 "$SCANNER" --root "$ROOT" >/dev/null
pass repository_boundary
printf 'PASS: Public data boundary regression matrix\n'
