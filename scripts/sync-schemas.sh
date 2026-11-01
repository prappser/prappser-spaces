#!/usr/bin/env bash
set -euo pipefail

app="$(cd "${1:?usage: sync-schemas.sh <app-checkout> [ref]}" && pwd)"
ref="${2:-origin/main}"

cd "$(git rev-parse --show-toplevel)"

git -C "$app" fetch --quiet origin

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$app" archive "$ref" schemas | tar -x -C "$tmp"

mkdir -p internal/component
rm -rf internal/component/schemas
mv "$tmp/schemas" internal/component/schemas

(cd internal/component/schemas && find . -type f | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum) > internal/component/schemas.sha256

echo "Synced schemas from prappser-app $(git -C "$app" rev-parse --short "$ref")"
