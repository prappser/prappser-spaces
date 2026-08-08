#!/usr/bin/env bash
# Interactive setup for deploy/.env. Prompts for the values needed to run
# `docker compose up -d`, auto-generating POSTGRES_PASSWORD and, if the
# operator leaves MASTER_PASSWORD blank, a MASTER_PASSWORD too.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [[ -f "$ENV_FILE" && "$FORCE" -ne 1 ]]; then
  echo "Error: $ENV_FILE already exists. Re-run with --force to overwrite it." >&2
  exit 1
fi

validate_secret() {
  # Rejects characters that would break the KEY='value' .env format written
  # below. Every value we write is single-quoted so that compose's dotenv
  # parser does not try to interpolate $VAR references inside it (an
  # unquoted "myp$ecret123" silently truncates to "myp" and gets baked into
  # the encrypted space keys forever) -- so a literal single quote can't be
  # part of the value either, alongside '|' and newlines.
  local value="$1" label="$2"
  if [[ "$value" == *"'"* ]]; then
    echo "Error: $label cannot contain a single quote (')." >&2
    return 1
  fi
  if [[ "$value" == *"|"* ]]; then
    echo "Error: $label cannot contain '|'." >&2
    return 1
  fi
  if [[ "$value" == *$'\n'* ]]; then
    echo "Error: $label cannot contain a newline." >&2
    return 1
  fi
  return 0
}

read -r -p "Domain (e.g. spaces.example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
  echo "Error: domain is required." >&2
  exit 1
fi
if ! validate_secret "$DOMAIN" "Domain"; then
  exit 1
fi

echo
echo "Set MASTER_PASSWORD, used to encrypt this space's Ed25519 keys."
echo "Press Enter with no input to auto-generate a strong password."
read -rs -p "Master password: " MASTER_PASSWORD_INPUT
echo

if [[ -z "$MASTER_PASSWORD_INPUT" ]]; then
  MASTER_PASSWORD="$(openssl rand -hex 32)"
  echo "!!! Generated MASTER_PASSWORD: $MASTER_PASSWORD"
  echo "!!! Back this up somewhere safe now. It is not stored anywhere but"
  echo "!!! deploy/.env, and losing it after first boot means this space's"
  echo "!!! keys can never be decrypted again."
else
  read -rs -p "Confirm master password: " MASTER_PASSWORD_CONFIRM
  echo
  if [[ "$MASTER_PASSWORD_INPUT" != "$MASTER_PASSWORD_CONFIRM" ]]; then
    echo "Error: passwords did not match." >&2
    exit 1
  fi
  if ! validate_secret "$MASTER_PASSWORD_INPUT" "MASTER_PASSWORD"; then
    exit 1
  fi
  MASTER_PASSWORD="$MASTER_PASSWORD_INPUT"
fi

POSTGRES_PASSWORD="$(openssl rand -hex 24)"
if ! validate_secret "$POSTGRES_PASSWORD" "POSTGRES_PASSWORD"; then
  exit 1
fi

echo
read -r -p "Allowed CORS origins [https://prappser.app]: " ALLOWED_ORIGINS_INPUT
ALLOWED_ORIGINS="${ALLOWED_ORIGINS_INPUT:-https://prappser.app}"
if ! validate_secret "$ALLOWED_ORIGINS" "ALLOWED_ORIGINS"; then
  exit 1
fi

# Single-quote every value: compose's dotenv parser expands $VAR references
# inside unquoted values (see comment on validate_secret above), so quoting
# is what actually keeps these values intact once docker compose reads them.
umask 177
{
  printf "DOMAIN='%s'\n" "$DOMAIN"
  printf "POSTGRES_PASSWORD='%s'\n" "$POSTGRES_PASSWORD"
  printf "MASTER_PASSWORD='%s'\n" "$MASTER_PASSWORD"
  printf "ALLOWED_ORIGINS='%s'\n" "$ALLOWED_ORIGINS"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo
echo "Wrote $ENV_FILE (mode 600):"
echo "  DOMAIN=$DOMAIN"
echo "  ALLOWED_ORIGINS=$ALLOWED_ORIGINS"
echo "  POSTGRES_PASSWORD=(generated, not shown)"
echo "  MASTER_PASSWORD=(set, not shown)"
echo
echo "IMPORTANT: MASTER_PASSWORD encrypts this space's keys on first boot."
echo "It cannot be changed afterward without wiping the database. Back it"
echo "up now if it was just generated above."
