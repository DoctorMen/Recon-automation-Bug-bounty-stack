#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick Setup Helper - Loads credentials and provides instructions
# Usage: bash setup_tokens.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "Rapyd IDOR Testing - Token Setup"
echo "============================================================"
echo ""

# Check if credentials.sh exists
if [ -f "../credentials.sh" ]; then
    echo "[*] Loading credentials from ../credentials.sh"
    source ../credentials.sh
elif [ -f "../../../programs/rapyd/credentials.sh" ]; then
    echo "[*] Loading credentials from ../../../programs/rapyd/credentials.sh"
    source ../../../programs/rapyd/credentials.sh
else
    echo "[!] credentials.sh not found"
fi

echo ""
echo "Current Token Status:"
echo "===================="

if [ -n "${TOKEN_A:-}" ]; then
    echo "✓ TOKEN_A: ${TOKEN_A:0:30}... (set)"
else
    echo "✗ TOKEN_A: Not set"
fi

if [ -n "${TOKEN_B:-}" ]; then
    echo "✓ TOKEN_B: ${TOKEN_B:0:30}... (set)"
else
    echo "✗ TOKEN_B: Not set"
fi

if [ -n "${RAPYD_SECRET_KEY:-}" ]; then
    echo "✓ RAPYD_SECRET_KEY: ${RAPYD_SECRET_KEY:0:30}... (set)"
else
    echo "✗ RAPYD_SECRET_KEY: Not set"
fi

echo ""

# Check if tokens are set
if [ -z "${TOKEN_A:-}" ] || [ -z "${TOKEN_B:-}" ]; then
    echo "⚠️  Missing tokens for IDOR testing"
    echo ""
    echo "To set up tokens:"
    echo ""
    echo "Option 1: Edit credentials.sh"
    echo "  nano ../credentials.sh"
    echo "  # Add these lines:"
    echo "  export TOKEN_A='your_account_a_token'"
    echo "  export TOKEN_B='your_account_b_token'"
    echo ""
    echo "Option 2: Set manually (temporary for this session):"
    echo "  export TOKEN_A='your_account_a_token'"
    echo "  export TOKEN_B='your_account_b_token'"
    echo ""
    echo "Option 3: Use RAPYD_SECRET_KEY for both (single account, limited testing):"
    echo "  export TOKEN_A=\"\$RAPYD_SECRET_KEY\""
    echo "  export TOKEN_B=\"\$RAPYD_SECRET_KEY\""
    echo ""
    echo "How to get tokens:"
    echo "1. Log into https://dashboard.rapyd.net"
    echo "2. Go to Settings → API Keys"
    echo "3. Generate or copy your API token"
    echo "4. For IDOR testing: Get tokens from TWO different accounts"
    echo ""
    
    # Offer to set tokens interactively
    if [ -z "${TOKEN_A:-}" ]; then
        echo "Set TOKEN_A now (or press Enter to skip):"
        read -r TOKEN_A
        if [ -n "$TOKEN_A" ]; then
            export TOKEN_A="$TOKEN_A"
            echo "✓ TOKEN_A set"
        fi
    fi
    
    if [ -z "${TOKEN_B:-}" ]; then
        echo "Set TOKEN_B now (or press Enter to skip):"
        read -r TOKEN_B
        if [ -n "$TOKEN_B" ]; then
            export TOKEN_B="$TOKEN_B"
            echo "✓ TOKEN_B set"
        fi
    fi
    
    echo ""
fi

# Final check
if [ -z "${TOKEN_A:-}" ] || [ -z "${TOKEN_B:-}" ]; then
    echo "❌ Cannot proceed without both TOKEN_A and TOKEN_B"
    echo ""
    echo "Please set them and run this script again, or run:"
    echo "  export TOKEN_A='your_token'"
    echo "  export TOKEN_B='your_token'"
    exit 1
fi

echo "============================================================"
echo "✅ Tokens Ready!"
echo "============================================================"
echo ""
echo "Now you can:"
echo ""
echo "1. Get payment IDs from Account B:"
echo "   python3 get_payment_ids.py \"\$TOKEN_B\" 10"
echo ""
echo "2. Run IDOR test:"
echo "   python3 quick_api_test.py \"\$TOKEN_A\" \"\$TOKEN_B\" \"PAYMENT_ID\""
echo ""
echo "3. Or use the helper script:"
echo "   bash run_idor_test.sh PAYMENT_ID"
echo ""

