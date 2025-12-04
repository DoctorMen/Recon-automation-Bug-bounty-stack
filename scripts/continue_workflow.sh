#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Continue Workflow - Prioritize and Test Discovered Endpoints

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "============================================================"
echo "Continuing Bug Bounty Workflow"
echo "============================================================"
echo ""

# Step 1: Prioritize endpoints
echo "[*] Step 1: Prioritizing discovered endpoints..."
python3 scripts/prioritize_endpoints.py

echo ""
echo "[*] Step 2: Check what Nuclei found..."
if [ -f "output/immediate_roi/high_roi_findings.json" ]; then
    echo "Found Nuclei findings file"
    if command -v jq &> /dev/null; then
        COUNT=$(jq 'length' output/immediate_roi/high_roi_findings.json 2>/dev/null || wc -l < output/immediate_roi/high_roi_findings.json)
        echo "Findings count: $COUNT"
    else
        COUNT=$(wc -l < output/immediate_roi/high_roi_findings.json)
        echo "Findings count (lines): $COUNT"
    fi
else
    echo "No Nuclei findings file yet"
fi

echo ""
echo "[*] Step 3: Review priority endpoints..."
if [ -f "output/immediate_roi/priority_endpoints.json" ]; then
    echo "Priority endpoints saved: output/immediate_roi/priority_endpoints.json"
    echo "Testing plan: output/immediate_roi/MANUAL_TESTING_PLAN.md"
    echo ""
    echo "Opening testing plan..."
    if command -v cat &> /dev/null; then
        cat output/immediate_roi/MANUAL_TESTING_PLAN.md | head -50
    fi
else
    echo "Run: python3 scripts/prioritize_endpoints.py"
fi

echo ""
echo "============================================================"
echo "Ready for Manual Testing!"
echo "============================================================"
echo ""
echo "Next steps:"
echo "1. Review: output/immediate_roi/MANUAL_TESTING_PLAN.md"
echo "2. Start manual testing top priority endpoints"
echo "3. Use Burp Suite or browser for manual testing"
echo "4. Focus on one program (e.g., Rapyd or Mastercard)"
echo ""








