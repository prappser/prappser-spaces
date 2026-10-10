#!/usr/bin/env bash
# Smoke test for backup.sh with fake sources and a local rclone destination.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

fail() { echo "FAIL: $*" >&2; exit 1; }
pubkey() { openssl pkey -pubout -outform DER | tail -c 32 | base64; }

age-keygen -o id.txt 2>/dev/null
AGE_RECIPIENT="$(age-keygen -y id.txt)"
export AGE_RECIPIENT
export RCLONE_DEST=":local:$tmp/dest/space"

mkdir -p src/.space dest/space
openssl genpkey -algorithm ed25519 -out src/.space/identity.key
want="$(pubkey < src/.space/identity.key)"
echo data > src/file.txt

export DUMP_CMD='printf "CREATE TABLE t();\n-- PostgreSQL database dump complete\n"'
export STORAGE_CMD="tar czf - -C $tmp/src ."

touch -d '100 days ago' dest/space/unrelated.txt dest/space/space-20000101T000000Z.tar.age

"$here/backup.sh"

[[ ! -e dest/space/space-20000101T000000Z.tar.age ]] || fail "old backup not pruned"
[[ -e dest/space/unrelated.txt ]] || fail "unrelated file was deleted"
mapfile -t new < <(find dest/space -name 'space-*.tar.age')
[[ ${#new[@]} -eq 1 ]] || fail "expected exactly one backup, got ${#new[@]}"

mkdir out
age -d -i id.txt "${new[0]}" | tar xf - -C out
gunzip -c out/db.sql.gz | grep -q 'dump complete' || fail "dump missing"
mkdir out/storage
tar xzf out/storage.tar.gz -C out/storage
[[ "$(pubkey < out/storage/.space/identity.key)" == "$want" ]] || fail "identity key mismatch"

expect_no_upload() {
  local label="$1"
  if "$here/backup.sh" 2>/dev/null; then fail "$label: exited zero"; fi
  [[ "$(find dest/space -name 'space-*.tar.age' | wc -l)" -eq 1 ]] || fail "$label: uploaded something"
}

STORAGE_CMD=false expect_no_upload "failing storage"

mkdir nokey
echo data > nokey/file.txt
STORAGE_CMD="tar czf - -C $tmp/nokey ." expect_no_upload "no identity key"

DUMP_CMD='printf "CREATE TABLE t();\n"' expect_no_upload "truncated dump"

echo "OK"
