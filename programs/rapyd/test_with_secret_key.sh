#!/bin/bash
# Rapyd API Testing Script with Private Key
# Uses the secret key for API authentication

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env.rapyd"

# Load credentials
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
else
    echo "Error: .env.rapyd file not found"
    exit 1
fi

# Check if secret key is set
if [ -z "$RAPYD_SECRET_KEY" ]; then
    echo "Error: RAPYD_SECRET_KEY not set"
    exit 1
fi

echo "=== Rapyd API Testing ==="
echo "Base URL: $RAPYD_BASE_URL"
echo "Secret Key: ${RAPYD_SECRET_KEY:0:20}... (hidden)"
echo ""

# Test authentication bypass (no API key needed)
echo "Test 1: Authentication Bypass"
curl -X POST "$RAPYD_BASE_URL/v1/payments/create" \
  -H "X-Bugcrowd: $BUGCROWD_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"currency":"USD"}' \
  -v

echo ""
echo "=== Test Complete ==="

