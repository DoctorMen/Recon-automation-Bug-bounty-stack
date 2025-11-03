#!/bin/bash
# Create Test Customers & Payments for IDOR Testing
# This script creates test data via API, then tests IDOR vulnerability

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
source credentials.sh

echo "=== Creating Test Data for IDOR Testing ==="
echo ""

# Test customer endpoint structure first
echo "Step 1: Testing customer endpoint structure..."
echo "Navigating to customer detail page with test ID..."

# We'll test in browser, but first let's document what we're doing
echo ""
echo "Test plan:"
echo "1. Create customer via dashboard (manual)"
echo "2. Access customer detail page"
echo "3. Test IDOR by modifying customer ID"
echo "4. Create payment linked to customer"
echo "5. Test payment IDOR"
echo ""

# Since we can't easily create via API without proper auth setup,
# let's test the endpoint structure first
echo "Testing IDOR endpoint pattern: /collect/customers/{customer_id}"
echo ""

# Navigate to test customer URL
echo "Ready to test in browser..."



