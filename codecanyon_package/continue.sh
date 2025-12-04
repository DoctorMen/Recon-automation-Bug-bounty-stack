#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick Continue - Prioritize and Start Manual Testing

cd ~/Recon-automation-Bug-bounty-stack

echo "============================================================"
echo "Continuing Bug Bounty Workflow"
echo "============================================================"
echo ""

echo "[*] Step 1: Prioritizing endpoints..."
python3 scripts/prioritize_endpoints.py

echo ""
echo "[*] Step 2: Showing top priority endpoints..."
if [ -f "output/immediate_roi/priority_endpoints.json" ]; then
    echo "Top 10 Priority Endpoints:"
    python3 -c "
import json
with open('output/immediate_roi/priority_endpoints.json') as f:
    data = json.load(f)
    for i, item in enumerate(data[:10], 1):
        print(f\"{i}. Score: {item['score']} - {item['url']}\")
        print(f\"   Reasons: {', '.join(item['reasons'])}\")
        print()
"
else
    echo "Priority file not found. Run: python3 scripts/prioritize_endpoints.py"
fi

echo ""
echo "============================================================"
echo "Next Steps:"
echo "============================================================"
echo "1. Review: output/immediate_roi/MANUAL_TESTING_PLAN.md"
echo "2. Start manual testing with top priority endpoints"
echo "3. Focus on Rapyd first (highest reward potential)"
echo "4. Use Burp Suite or browser for manual testing"
echo ""
echo "See: CONTINUE_WORKFLOW.md for detailed guide"
echo "============================================================"






