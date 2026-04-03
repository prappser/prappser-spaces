#!/usr/bin/env bash
set -euo pipefail

TEMPLATE_CODE="5MCVV7"
TEMPLATE_FILE="zeabur-template.yaml"

cd "$(git rev-parse --show-toplevel)"

if ! command -v zeabur &>/dev/null && ! npx zeabur --version &>/dev/null 2>&1; then
  echo "zeabur CLI not found. Install with: npm i -g zeabur"
  exit 1
fi

echo "Updating Zeabur template ${TEMPLATE_CODE}..."
npx zeabur template update -f "$TEMPLATE_FILE" -c "$TEMPLATE_CODE"
echo "Done."
