#!/bin/bash
# Browser-Based Evidence Capture - Idempotent Workflow
# This script guides you through browser-based evidence capture

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
STATE_FILE="$EVIDENCE_DIR/.capture_state.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

# Initialize state file if it doesn't exist
init_state() {
    if [ ! -f "$STATE_FILE" ]; then
        cat > "$STATE_FILE" <<EOF
{
  "account_a": {
    "email": "",
    "username": "",
    "login_timestamp": "",
    "screenshot": "",
    "status": "pending"
  },
  "account_b": {
    "email": "",
    "username": "",
    "creation_timestamp": "",
    "screenshot": "",
    "status": "pending"
  },
  "payment": {
    "payment_id": "",
    "creation_timestamp": "",
    "amount": 0,
    "currency": "USD",
    "screenshot": "",
    "status": "pending"
  },
  "idor_access": {
    "timestamp": "",
    "payment_id": "",
    "operation_id": "",
    "status_code": 0,
    "screenshots": [],
    "network_capture": "",
    "raw_response": "",
    "status": "pending"
  }
}
EOF
        log "Initialized state file: $STATE_FILE"
    fi
}

# Load state
load_state() {
    if [ -f "$STATE_FILE" ]; then
        ACCOUNT_A_EMAIL=$(jq -r '.account_a.email // ""' "$STATE_FILE" 2>/dev/null || echo "")
        ACCOUNT_B_EMAIL=$(jq -r '.account_b.email // ""' "$STATE_FILE" 2>/dev/null || echo "")
        PAYMENT_ID=$(jq -r '.payment.payment_id // ""' "$STATE_FILE" 2>/dev/null || echo "")
        IDOR_STATUS=$(jq -r '.idor_access.status // "pending"' "$STATE_FILE" 2>/dev/null || echo "pending")
    else
        ACCOUNT_A_EMAIL=""
        ACCOUNT_B_EMAIL=""
        PAYMENT_ID=""
        IDOR_STATUS="pending"
    fi
}

# Update state
update_state() {
    local key=$1
    local value=$2
    if command -v jq &> /dev/null; then
        jq ".$key = $value" "$STATE_FILE" > "$STATE_FILE.tmp" && mv "$STATE_FILE.tmp" "$STATE_FILE"
    else
        warning "jq not installed, state update skipped"
    fi
}

# Main workflow
main() {
    init_state
    load_state
    
    echo "=========================================="
    echo "Browser-Based IDOR Evidence Capture"
    echo "=========================================="
    echo ""
    echo "This workflow guides you through capturing evidence"
    echo "using your browser. Each step saves progress."
    echo ""
    
    # Step 1: Account A
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 1: Account A Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "In your browser:"
    echo "  1. Navigate to: https://dashboard.rapyd.net/login"
    echo "  2. Log in with: DoctorMen@bugcrowdninja.com"
    echo "  3. Take screenshot: $EVIDENCE_DIR/account_a_dashboard.png"
    echo "  4. Note Account A username from dashboard"
    echo ""
    read -p "Account A Email [DoctorMen@bugcrowdninja.com]: " email_a
    email_a=${email_a:-DoctorMen@bugcrowdninja.com}
    read -p "Account A Username: " username_a
    read -p "Login Timestamp (UTC): " timestamp_a
    read -p "Screenshot saved? (y/n): " screenshot_a
    
    if [ "$screenshot_a" = "y" ]; then
        success "Account A setup complete"
        update_state "account_a" "{\"email\": \"$email_a\", \"username\": \"$username_a\", \"login_timestamp\": \"$timestamp_a\", \"screenshot\": \"evidence/account_a_dashboard.png\", \"status\": \"complete\"}"
    fi
    
    # Step 2: Account B
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 2: Account B Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "In your browser (incognito/private window):"
    echo "  1. Navigate to: https://dashboard.rapyd.net/signup"
    echo "  2. Create new account OR log in to existing Account B"
    echo "  3. Take screenshot: $EVIDENCE_DIR/account_b_created.png"
    echo ""
    read -p "Account B Email (will be redacted): " email_b
    read -p "Account B Username: " username_b
    read -p "Account Creation Timestamp (UTC): " timestamp_b
    read -p "Screenshot saved? (y/n): " screenshot_b
    
    if [ "$screenshot_b" = "y" ]; then
        success "Account B setup complete"
        update_state "account_b" "{\"email\": \"$email_b\", \"username\": \"$username_b\", \"creation_timestamp\": \"$timestamp_b\", \"screenshot\": \"evidence/account_b_created.png\", \"status\": \"complete\"}"
    fi
    
    # Step 3: Create Payment in Account B
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 3: Create Payment in Account B"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "In Account B session:"
    echo "  1. Navigate to: https://dashboard.rapyd.net/collect/payments/list"
    echo "  2. Create a test payment (use sandbox test card)"
    echo "  3. Copy Payment ID from URL (e.g., pay_abc123...)"
    echo "  4. Take screenshot: $EVIDENCE_DIR/account_b_payment_created.png"
    echo ""
    read -p "Payment ID: " payment_id
    read -p "Payment Creation Timestamp (UTC): " payment_timestamp
    read -p "Payment Amount: " payment_amount
    read -p "Screenshot saved? (y/n): " screenshot_payment
    
    if [ "$screenshot_payment" = "y" ]; then
        success "Payment created in Account B"
        update_state "payment" "{\"payment_id\": \"$payment_id\", \"creation_timestamp\": \"$payment_timestamp\", \"amount\": $payment_amount, \"currency\": \"USD\", \"screenshot\": \"evidence/account_b_payment_created.png\", \"status\": \"complete\"}"
    fi
    
    # Step 4: IDOR Access
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 4: Capture IDOR Access (CRITICAL)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "In Account A session with DevTools open (F12):"
    echo "  1. Navigate to: https://dashboard.rapyd.net/collect/payments/$payment_id"
    echo "  2. In DevTools Network tab, find API request"
    echo "  3. Right-click → Copy as cURL → Save to: $EVIDENCE_DIR/idor_request_curl.txt"
    echo "  4. Click request → Response tab → Copy JSON → Save to: $EVIDENCE_DIR/idor_response_raw.json"
    echo "  5. Take screenshots:"
    echo "     - Account context: $EVIDENCE_DIR/idor_account_context.png"
    echo "     - Payment details: $EVIDENCE_DIR/idor_payment_details.png"
    echo "     - URL bar: $EVIDENCE_DIR/idor_url_bar.png"
    echo ""
    read -p "IDOR Access Timestamp (UTC): " idor_timestamp
    read -p "Operation ID (from API response): " operation_id
    read -p "cURL request saved? (y/n): " curl_saved
    read -p "JSON response saved? (y/n): " json_saved
    read -p "Screenshots saved? (y/n): " screenshots_saved
    
    if [ "$curl_saved" = "y" ] && [ "$json_saved" = "y" ] && [ "$screenshots_saved" = "y" ]; then
        success "IDOR access captured"
        update_state "idor_access" "{\"timestamp\": \"$idor_timestamp\", \"payment_id\": \"$payment_id\", \"operation_id\": \"$operation_id\", \"status_code\": 200, \"screenshots\": [\"evidence/idor_account_context.png\", \"evidence/idor_payment_details.png\", \"evidence/idor_url_bar.png\"], \"network_capture\": \"evidence/idor_request_curl.txt\", \"raw_response\": \"evidence/idor_response_raw.json\", \"status\": \"complete\"}"
    fi
    
    # Step 5: Redact JSON
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "STEP 5: Redact Sensitive Data"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    if [ -f "$EVIDENCE_DIR/idor_response_raw.json" ]; then
        echo "Running redaction script..."
        python3 <<'PYEOF'
import json
import re

# Load raw response
with open('evidence/idor_response_raw.json', 'r') as f:
    data = json.load(f)

SENSITIVE_FIELDS = ['email', 'phone', 'phone_number', 'cvv', 'ssn', 'card_number', 
                    'name', 'full_name', 'last_name', 'first_name', 'last4', 
                    'expiration_month', 'expiration_year', 'billing_address', 
                    'shipping_address', 'street', 'city', 'zip']

def redact_value(obj, path=''):
    if isinstance(obj, dict):
        return {k: redact_value(v, f"{path}.{k}" if path else k) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_value(item, path) for item in obj]
    elif isinstance(obj, str):
        if '@' in obj and '.' in obj:
            return '[REDACTED]'
        if re.match(r'^\+?\d{10,15}$', obj.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')):
            return '[REDACTED]'
        if re.match(r'^\d{13,19}$', obj.replace(' ', '').replace('-', '')):
            return '[REDACTED]'
        return obj
    else:
        return obj

def deep_redact(obj, path=''):
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            field_path = f"{path}.{k}" if path else k
            if any(field in k.lower() for field in SENSITIVE_FIELDS):
                result[k] = '[REDACTED]'
            else:
                result[k] = deep_redact(v, field_path)
        return result
    elif isinstance(obj, list):
        return [deep_redact(item, path) for item in obj]
    else:
        return obj

redacted = deep_redact(redact_value(data))

with open('evidence/idor_response_redacted.json', 'w') as f:
    json.dump(redacted, f, indent=2)

print("✅ Redacted JSON saved")
PYEOF
        success "Redaction complete: $EVIDENCE_DIR/idor_response_redacted.json"
    else
        warning "Raw JSON not found, skipping redaction"
    fi
    
    # Summary
    echo ""
    echo "=========================================="
    echo "Evidence Capture Summary"
    echo "=========================================="
    echo ""
    echo "Files created:"
    ls -lh "$EVIDENCE_DIR/" 2>/dev/null | tail -n +2 | awk '{print "  - " $9 " (" $5 ")"}' || echo "  (none yet)"
    echo ""
    echo "Next Steps:"
    echo "  1. Review all evidence files"
    echo "  2. Update SUBMISSION_READY_REPORT.md with actual values"
    echo "  3. Submit to Bugcrowd"
    echo ""
    success "Browser-based evidence capture complete!"
}

main "$@"



