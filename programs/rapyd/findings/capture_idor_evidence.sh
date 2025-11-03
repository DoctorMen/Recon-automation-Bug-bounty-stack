#!/bin/bash
# IDOR Evidence Capture Script
# This script helps capture all required evidence for IDOR submission

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
TIMESTAMP=$(date -u +%Y-%m-%d_%H%M%S)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

echo "=========================================="
echo "IDOR Evidence Capture Tool"
echo "=========================================="
echo ""

# Step 1: Account Information
log "Step 1: Account Information"
echo ""

read -p "Account A Email: " ACCOUNT_A_EMAIL
read -p "Account A ID (optional): " ACCOUNT_A_ID
read -p "Account B Email (will be redacted): " ACCOUNT_B_EMAIL
read -p "Account B ID (optional): " ACCOUNT_B_ID

echo ""
log "Step 2: Payment Information"
read -p "Account B Payment ID: " PAYMENT_ID
read -p "Payment Creation Timestamp (UTC): " PAYMENT_CREATED_UTC

echo ""
log "Step 3: IDOR Access Information"
read -p "IDOR Access Timestamp (UTC): " IDOR_ACCESS_UTC
read -p "Operation ID (from API response): " OPERATION_ID

# Save account information
cat > "$EVIDENCE_DIR/account_info.txt" <<EOF
Account A:
- Email: $ACCOUNT_A_EMAIL
- Account ID: ${ACCOUNT_A_ID:-Not captured}
- Login Timestamp: $(date -u +%Y-%m-%d_%H:%M:%S)

Account B:
- Email: [REDACTED]
- Account ID: ${ACCOUNT_B_ID:-Not captured}
- Payment ID: $PAYMENT_ID
- Payment Creation: $PAYMENT_CREATED_UTC

IDOR Access:
- Access Timestamp: $IDOR_ACCESS_UTC
- Payment ID Accessed: $PAYMENT_ID
- Operation ID: $OPERATION_ID
EOF

success "Account information saved to: $EVIDENCE_DIR/account_info.txt"

# Step 4: Network Capture
echo ""
log "Step 4: Network Capture"
echo ""
echo "Please paste the cURL command from DevTools (Copy as cURL):"
echo "Press Ctrl+D when finished, or type 'skip' to skip"
echo ""

if read -t 300 -r CURL_CMD || [ $? -eq 1 ]; then
    if [ "$CURL_CMD" != "skip" ]; then
        echo "$CURL_CMD" > "$EVIDENCE_DIR/idor_request_curl.txt"
        success "cURL request saved to: $EVIDENCE_DIR/idor_request_curl.txt"
    else
        warning "Skipping cURL capture"
    fi
else
    warning "Timeout waiting for cURL input"
fi

# Step 5: API Response
echo ""
log "Step 5: API Response"
echo ""
echo "Please paste the raw JSON response from DevTools:"
echo "Press Ctrl+D when finished, or type 'skip' to skip"
echo ""

if read -t 300 -r JSON_RESPONSE || [ $? -eq 1 ]; then
    if [ "$JSON_RESPONSE" != "skip" ]; then
        echo "$JSON_RESPONSE" > "$EVIDENCE_DIR/idor_response_raw.json"
        success "Raw JSON response saved to: $EVIDENCE_DIR/idor_response_raw.json"
        
        # Create redacted version
        log "Creating redacted version..."
        python3 <<EOF
import json
import re
import sys

# Read raw response
with open('$EVIDENCE_DIR/idor_response_raw.json', 'r') as f:
    data = json.load(f)

# Redaction function
def redact_sensitive(obj):
    if isinstance(obj, dict):
        return {k: redact_sensitive(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_sensitive(item) for item in obj]
    elif isinstance(obj, str):
        # Redact emails
        if '@' in obj and '.' in obj:
            return '[REDACTED]'
        # Redact card numbers (16 digits)
        if re.match(r'^\d{16}$', obj.replace(' ', '')):
            return '[REDACTED]'
        # Redact phone numbers
        if re.match(r'^\+?\d{10,15}$', obj.replace('-', '').replace(' ', '')):
            return '[REDACTED]'
        return obj
    else:
        return obj

# Redact sensitive fields
redacted = redact_sensitive(data)

# Fields to always redact
fields_to_redact = ['email', 'phone', 'phone_number', 'cvv', 'ssn', 'card_number', 'name', 'full_name', 'last4', 'expiration_month', 'expiration_year']

def deep_redact(obj, path=''):
    if isinstance(obj, dict):
        return {k: deep_redact(v, f"{path}.{k}" if path else k) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [deep_redact(item, path) for item in obj]
    elif isinstance(obj, str) and any(field in path.lower() for field in fields_to_redact):
        return '[REDACTED]'
    else:
        return obj

final_redacted = deep_redact(redacted)

# Save redacted version
with open('$EVIDENCE_DIR/idor_response_redacted.json', 'w') as f:
    json.dump(final_redacted, f, indent=2)

print("Redacted JSON saved")
EOF
        
        success "Redacted JSON saved to: $EVIDENCE_DIR/idor_response_redacted.json"
    else
        warning "Skipping JSON response capture"
    fi
else
    warning "Timeout waiting for JSON input"
fi

# Step 6: Screenshot Checklist
echo ""
log "Step 6: Screenshot Checklist"
echo ""
echo "Please ensure you have captured the following screenshots:"
echo ""
echo "  [ ] account_a_dashboard.png - Account A logged in (username visible)"
echo "  [ ] account_b_payment_created.png - Payment created in Account B"
echo "  [ ] idor_access_screenshot.png - Account A viewing Account B's payment"
echo "  [ ] idor_url_bar.png - URL bar showing payment ID"
echo ""
echo "Screenshots should be saved to: $EVIDENCE_DIR/"
echo ""

# Step 7: Video (optional)
echo ""
log "Step 7: Video Recording (Optional)"
echo ""
read -p "Create video proof? (y/n): " CREATE_VIDEO
if [ "$CREATE_VIDEO" = "y" ]; then
    echo ""
    echo "Video Requirements:"
    echo "  - Duration: 20-30 seconds"
    echo "  - Show Account A dashboard"
    echo "  - Navigate to Account B's payment URL"
    echo "  - Show payment details loading"
    echo "  - Show URL bar with payment ID"
    echo ""
    echo "Save video as: $EVIDENCE_DIR/idor_proof_video.mp4"
    echo ""
fi

# Summary
echo ""
echo "=========================================="
echo "Evidence Capture Summary"
echo "=========================================="
echo ""
echo "Files created:"
ls -lh "$EVIDENCE_DIR/" | tail -n +2 | awk '{print "  - " $9 " (" $5 ")"}'
echo ""
echo "Next Steps:"
echo "  1. Review all captured evidence"
echo "  2. Ensure screenshots are captured"
echo "  3. Update SUBMISSION_READY_REPORT.md with actual values"
echo "  4. Replace [TO BE CAPTURED] placeholders"
echo "  5. Submit to Bugcrowd"
echo ""
success "Evidence capture complete!"



