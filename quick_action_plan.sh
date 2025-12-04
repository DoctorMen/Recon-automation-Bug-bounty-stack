#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Fastest Time-to-Dollar Action Plan
# Run this to see what to do RIGHT NOW

cd ~/Recon-automation-Bug-bounty-stack

echo "============================================================"
echo "FASTEST TIME-TO-DOLLAR ACTION PLAN"
echo "============================================================"
echo ""

echo "🎯 GOAL: Convert Discovery → Bugs → Money"
echo ""

# Step 1: Check for secrets (FASTEST MONEY)
echo "============================================================"
echo "STEP 1: Check for Exposed Secrets (15 min → $50-$500)"
echo "============================================================"
echo ""

if [ -f "output/potential-secrets.txt" ]; then
    echo "Found secrets file:"
    head -10 output/potential-secrets.txt
    echo ""
    echo "✅ ACTION: Review and submit to Open Bug Bounty"
    echo "   https://www.openbugbounty.org (no signup needed)"
else
    echo "⚠️  No secrets file found"
fi

echo ""

# Step 2: Check Nuclei findings
echo "============================================================"
echo "STEP 2: Check Nuclei Findings (15 min → $100-$1,000)"
echo "============================================================"
echo ""

if [ -f "output/nuclei-findings.json" ]; then
    SIZE=$(wc -c < output/nuclei-findings.json)
    if [ "$SIZE" -gt 10 ]; then
        echo "Found Nuclei findings file ($SIZE bytes)"
        echo "✅ ACTION: Review and submit findings"
        echo ""
        echo "Quick preview:"
        head -5 output/nuclei-findings.json 2>/dev/null || echo "NDJSON format - use jq to parse"
    else
        echo "⚠️  Nuclei findings file is empty"
    fi
else
    echo "⚠️  No Nuclei findings file found"
fi

echo ""

# Step 3: Generate Rapyd endpoints (HIGHEST VALUE)
echo "============================================================"
echo "STEP 3: Generate Rapyd Endpoints (2 min → $1,500-$5,000)"
echo "============================================================"
echo ""

if [ -f "scripts/generate_rapyd_endpoints.py" ]; then
    echo "Generating Rapyd endpoint priority list..."
    python3 scripts/generate_rapyd_endpoints.py
    
    if [ -f "output/immediate_roi/RAPYD_MANUAL_TESTING_PLAN.md" ]; then
        echo ""
        echo "✅ ACTION: Review testing plan:"
        echo "   cat output/immediate_roi/RAPYD_MANUAL_TESTING_PLAN.md"
    fi
else
    echo "⚠️  Rapyd endpoint generator not found"
fi

echo ""

# Step 4: Show priority summary
echo "============================================================"
echo "PRIORITY ACTION SUMMARY"
echo "============================================================"
echo ""
echo "🥇 FASTEST MONEY (Do First):"
echo "   1. Submit secrets → Open Bug Bounty (24-48hr payout)"
echo "   2. Submit Nuclei findings → Programs (3-7 day payout)"
echo ""
echo "🥈 HIGHEST VALUE (Do Second):"
echo "   1. Test Rapyd IDOR → Dashboard payment endpoints"
echo "   2. Test Rapyd auth bypass → API endpoints"
echo "   3. Submit to Bugcrowd → $1,500-$5,000 per finding"
echo ""
echo "🥉 BULK SUBMISSION (Do Third):"
echo "   1. Submit all findings at once"
echo "   2. Multiple programs"
echo "   3. Diversify risk"
echo ""

echo "============================================================"
echo "NEXT STEPS"
echo "============================================================"
echo ""
echo "1. Check secrets: cat output/potential-secrets.txt"
echo "2. Review Rapyd plan: cat output/immediate_roi/RAPYD_MANUAL_TESTING_PLAN.md"
echo "3. Start manual testing with Rapyd endpoints"
echo "4. Submit findings as you find them"
echo ""
echo "See: FASTEST_TIME_TO_DOLLAR.md for complete guide"
echo "============================================================"








