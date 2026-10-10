#!/usr/bin/env bash
# Encrypted off-site backup: one age-encrypted bundle (DB dump + storage volume) per run.
set -euo pipefail

: "${AGE_RECIPIENT:?set AGE_RECIPIENT to the age public key}"
: "${RCLONE_DEST:?set RCLONE_DEST to remote:path}"
KEEP_DAYS="${KEEP_DAYS:-56}"
DUMP_CMD="${DUMP_CMD:-docker compose exec -T postgres pg_dump -U prappser --no-owner --no-acl prappser}"
STORAGE_CMD="${STORAGE_CMD:-docker compose exec -T prappser-spaces sh -c 'test -s /app/storage/.space/identity.key && tar czf - -C /app/storage .'}"

# An empty path would make the prune below act on the whole remote.
[[ "$RCLONE_DEST" == ?*:?* ]] || { echo "RCLONE_DEST needs a path after the remote" >&2; exit 1; }
for bin in age rclone; do
  command -v "$bin" >/dev/null || { echo "$bin not found" >&2; exit 1; }
done

cd "$(dirname "$0")"
umask 077
tmp="$(mktemp -d -p "${TMPDIR:-/var/tmp}")"
trap 'rm -rf "$tmp"' EXIT

bash -c "set -o pipefail; $DUMP_CMD" | gzip > "$tmp/db.sql.gz"
bash -c "set -o pipefail; $STORAGE_CMD" > "$tmp/storage.tar.gz"

# Fail closed: never upload a bundle that could not restore the space.
gunzip -c "$tmp/db.sql.gz" | tail -n 5 | grep -q 'PostgreSQL database dump complete' \
  || { echo "dump is incomplete" >&2; exit 1; }
gzip -t "$tmp/storage.tar.gz"
tar tzf "$tmp/storage.tar.gz" | grep -E '^(\./)?\.space/identity\.key$' >/dev/null \
  || { echo "storage archive has no .space/identity.key" >&2; exit 1; }

name="space-$(date -u +%Y%m%dT%H%M%SZ).tar.age"
tar cf - -C "$tmp" db.sql.gz storage.tar.gz | age -r "$AGE_RECIPIENT" > "$tmp/$name"

rclone copy "$tmp/$name" "$RCLONE_DEST"
rclone delete "$RCLONE_DEST" --min-age "${KEEP_DAYS}d" --include 'space-*.tar.age'
