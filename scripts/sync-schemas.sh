#!/usr/bin/env bash
set -euo pipefail

app="$(cd "${1:?usage: sync-schemas.sh <app-checkout> [ref]}" && pwd)"
ref="${2:-origin/main}"

cd "$(git rev-parse --show-toplevel)"

git -C "$app" fetch --quiet origin

sha="$(git -C "$app" rev-parse "$ref^{commit}")"

tmp="$(mktemp -d internal/component/.schemas-sync.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
git -C "$app" archive "$ref" schemas | tar -x -C "$tmp"

if [ -d internal/component/schemas ]; then
  mv internal/component/schemas "$tmp/old"
fi
mv "$tmp/schemas" internal/component/schemas

{
  echo "# prappser-app $sha"
  (cd internal/component/schemas && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed 's|  \./|  |')
} > internal/component/schemas.sha256

echo "Synced schemas from prappser-app ${sha:0:7}"
