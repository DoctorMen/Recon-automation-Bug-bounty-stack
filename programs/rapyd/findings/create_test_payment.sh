#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Manual IDOR Test - Create Test Payment First
# This simulates creating a payment via API, then manual testing in browser

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
source credentials.sh

echo "=== Manual IDOR Test Setup ==="
echo "Sandbox Mode: ACTIVE"
echo ""

# Create a test payment using API
echo "Step 1: Creating test payment via API..."
echo ""

PAYMENT_RESPONSE=$(curl -s -X POST "https://sandboxapi.rapyd.net/v1/payments" \
  -H "X-Bugcrowd: $BUGCROWD_HEADER" \
  -H "Content-Type: application/json" \
  -H "access_key: $RAPYD_SECRET_KEY" \
  -d '{
    "amount": 100,
    "currency": "USD",
    "payment_method": {
      "type": "us_debit_visa_card",
      "fields": {
        "number": "4111111111111111",
        "expiration_month": "12",
        "expiration_year": "2025",
        "cvv": "123",
        "name": "Test User"
      }
    },
    "capture": true
  }' 2>&1)

echo "API Response:"
echo "$PAYMENT_RESPONSE" | head -20
echo ""

# Extract payment ID if available
PAYMENT_ID=$(echo "$PAYMENT_RESPONSE" | grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

if [ -z "$PAYMENT_ID" ]; then
    echo "⚠️  Could not create payment via API (expected in sandbox)"
    echo "This is normal - we'll test with manual navigation instead"
    echo ""
    echo "Manual Testing Steps:"
    echo "1. Navigate to: https://dashboard.rapyd.net/collect/payments/list"
    echo "2. Create a payment manually using 'Create payment link'"
    echo "3. Click on the payment to view details"
    echo "4. Note the payment ID in the URL"
    echo "5. Modify the payment ID in the URL"
    echo "6. Test IDOR access"
else
    echo "✅ Test Payment Created!"
    echo "Payment ID: $PAYMENT_ID"
    echo ""
    echo "📋 Next Steps (Manual Testing):"
    echo "1. Navigate to: https://dashboard.rapyd.net/collect/payments/list"
    echo "2. Click on payment ID: $PAYMENT_ID"
    echo "3. Check URL bar for exact endpoint path"
    echo "4. Modify payment ID in URL to test IDOR"
fi

echo ""
echo "=== Ready for Manual IDOR Test ==="





