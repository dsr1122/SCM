#!/usr/bin/env bash
# Generate RS256 key pair and write base64-encoded values to .env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/.env.example" "$ENV_FILE"
fi

PRIVATE_KEY=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 2>/dev/null)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | openssl rsa -pubout 2>/dev/null)

PRIVATE_B64=$(echo "$PRIVATE_KEY" | base64 | tr -d '\n')
PUBLIC_B64=$(echo "$PUBLIC_KEY" | base64 | tr -d '\n')

# Replace in .env (macOS-safe sed)
sed -i.bak "s|^JWT_PRIVATE_KEY_B64=.*|JWT_PRIVATE_KEY_B64=${PRIVATE_B64}|" "$ENV_FILE"
sed -i.bak "s|^JWT_PUBLIC_KEY_B64=.*|JWT_PUBLIC_KEY_B64=${PUBLIC_B64}|" "$ENV_FILE"
rm -f "$ENV_FILE.bak"

echo "RS256 key pair written to $ENV_FILE"
