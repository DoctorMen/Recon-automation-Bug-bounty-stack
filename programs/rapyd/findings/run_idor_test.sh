#!/bin/bash
# Quick IDOR Test Helper - Run this from Ubuntu terminal
# Usage: bash run_idor_test.sh [PAYMENT_ID]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "Quick API IDOR Test - Rapyd"
echo "============================================================"
echo ""

# Check if we're in the right directory
if [ ! -f "quick_api_test.py" ]; then
    echo "Error: quick_api_test.py not found!"
    echo "Current directory: $(pwd)"
    echo "Please run: cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings"
    exit 1
fi

# Try to load credentials
if [ -f "../credentials.sh" ]; then
    echo "[*] Loading credentials..."
    source ../credentials.sh
elif [ -f "../../../programs/rapyd/credentials.sh" ]; then
    echo "[*] Loading credentials..."
    source ../../../programs/rapyd/credentials.sh
fi

# Check if tokens are set
if [ -z "${TOKEN_A:-}" ]; then
    echo ""
    echo "TOKEN_A not set. Please set it:"
    echo "  export TOKEN_A='your_token_here'"
    echo ""
    read -p "Enter TOKEN_A now (or press Enter to skip): " TOKEN_A
fi

if [ -z "${TOKEN_B:-}" ]; then
    echo ""
    echo "TOKEN_B not set. Please set it:"
    echo "  export TOKEN_B='your_token_here'"
    echo ""
    read -p "Enter TOKEN_B now (or press Enter to skip): " TOKEN_B
fi

if [ -z "${TOKEN_A:-}" ] || [ -z "${TOKEN_B:-}" ]; then
    echo ""
    echo "Error: Both TOKEN_A and TOKEN_B must be set"
    echo ""
    echo "Set them manually:"
    echo "  export TOKEN_A='your_token_a'"
    echo "  export TOKEN_B='your_token_b'"
    echo "  bash run_idor_test.sh PAYMENT_ID"
    exit 1
fi

# Get payment ID
PAYMENT_ID="${1:-PAYMENT_ID}"
if [ "$PAYMENT_ID" = "PAYMENT_ID" ]; then
    echo ""
    read -p "Enter Payment ID to test: " PAYMENT_ID
    PAYMENT_ID="${PAYMENT_ID:-PAYMENT_ID}"
fi

echo ""
echo "[*] Testing Payment ID: $PAYMENT_ID"
echo "[*] Token A: ${TOKEN_A:0:20}..."
echo "[*] Token B: ${TOKEN_B:0:20}..."
echo ""

# Check if payment ID is placeholder
if [ "$PAYMENT_ID" = "PAYMENT_ID" ]; then
    echo ""
    echo "⚠️  Warning: Using placeholder PAYMENT_ID"
    echo ""
    echo "Getting real payment IDs from Account B..."
    if [ -f "get_payment_ids.py" ]; then
        python3 get_payment_ids.py "$TOKEN_B" 10
        echo ""
        echo "If payment IDs were found, use one of them:"
        echo "  bash run_idor_test.sh <real_payment_id>"
        exit 0
    else
        echo "⚠️  get_payment_ids.py not found"
        echo ""
        echo "To get a payment ID manually:"
        echo "1. Log into dashboard.rapyd.net with Account B"
        echo "2. Navigate to Collect → Payments"
        echo "3. Create or find a payment"
        echo "4. Copy the payment ID from URL or payment details"
        echo "5. Run: bash run_idor_test.sh <payment_id>"
        exit 1
    fi
fi

# Run the test
python3 quick_api_test.py "$TOKEN_A" "$TOKEN_B" "$PAYMENT_ID"

EXIT_CODE=$?
echo ""
echo "============================================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "Test completed successfully!"
    if [ -d "evidence" ]; then
        echo "Evidence saved in: evidence/"
        ls -lh evidence/ | tail -5
    fi
else
    echo "Test completed (check output above for results)"
fi
echo "============================================================"
