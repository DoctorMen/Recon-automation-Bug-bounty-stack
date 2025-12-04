#!/bin/bash
# LEGAL SHIELD WRAPPER - Protects all scanning scripts
# Copyright © 2025 DoctorMen. All Rights Reserved.
#
# ⚠️  CRITICAL: This wrapper MUST be called before ANY scanning operation
# Usage: ./LEGAL_SHIELD_WRAPPER.sh <target> <script_to_run> [script_args...]

set -e

TARGET="$1"
SCRIPT="$2"
shift 2
SCRIPT_ARGS="$@"

echo "============================================================"
echo "🛡️  LEGAL AUTHORIZATION SHIELD"
echo "============================================================"
echo "Target: $TARGET"
echo "Script: $SCRIPT"
echo ""

# Check if legal authorization system exists
if [ ! -f "./LEGAL_AUTHORIZATION_SYSTEM.py" ]; then
    echo "❌ CRITICAL ERROR: Legal Authorization Shield not found!"
    echo "   All scanning operations are DISABLED"
    echo "   Required file: LEGAL_AUTHORIZATION_SYSTEM.py"
    exit 1
fi

# Check authorization using Python shield
python3 - <<EOF
import sys
sys.path.insert(0, '.')
from LEGAL_AUTHORIZATION_SYSTEM import LegalAuthorizationShield

shield = LegalAuthorizationShield()
authorized, reason, auth_data = shield.check_authorization('$TARGET')

if not authorized:
    print(f"\n🚫 SCAN BLOCKED BY LEGAL SHIELD")
    print(f"   Script: $SCRIPT")
    print(f"   Target: $TARGET")
    print(f"   Reason: {reason}")
    print(f"\n⚠️  TO AUTHORIZE:")
    print(f"   python3 CREATE_AUTHORIZATION.py --target $TARGET --client 'CLIENT_NAME'")
    sys.exit(1)

print(f"\n✅ AUTHORIZATION VERIFIED")
print(f"   Client: {auth_data.get('client_name', 'Unknown')}")
print(f"   Authorized until: {auth_data.get('end_date', 'Unknown')}")
print(f"   Proceeding with scan...")
print("")
EOF

AUTH_STATUS=$?

if [ $AUTH_STATUS -ne 0 ]; then
    echo ""
    echo "============================================================"
    echo "🚫 EXECUTION BLOCKED - NO AUTHORIZATION"
    echo "============================================================"
    exit 1
fi

echo "============================================================"
echo "▶️  Executing authorized scan..."
echo "============================================================"
echo ""

# Execute the protected script
if [ -f "$SCRIPT" ]; then
    bash "$SCRIPT" "$TARGET" $SCRIPT_ARGS
else
    echo "❌ Script not found: $SCRIPT"
    exit 1
fi
