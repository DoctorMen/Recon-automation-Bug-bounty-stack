#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Ultimate First Dollar ROI - Quick Start Script
# Run this to check what you can submit RIGHT NOW

cd ~/Recon-automation-Bug-bounty-stack || exit 1

echo "============================================================"
echo "⚡ ULTIMATE FIRST DOLLAR ROI - QUICK CHECK"
echo "============================================================"
echo ""

# Step 1: Check for secrets
echo "============================================================"
echo "STEP 1: Check for Secrets (15 min → $50-$500)"
echo "============================================================"
echo ""

if [ -f "output/potential-secrets.txt" ]; then
    SECRET_COUNT=$(wc -l < output/potential-secrets.txt)
    echo "✅ Found $SECRET_COUNT potential secrets"
    echo ""
    echo "First 5 secrets:"
    head -5 output/potential-secrets.txt
    echo ""
    echo "📋 ACTION: Submit to https://www.openbugbounty.org"
    echo "   (No signup needed, instant submission)"
    echo "   Reward: $50-$500 per secret"
    echo "   Validation: 24-48 hours"
else
    echo "⚠️  No secrets file found"
fi

echo ""

# Step 2: Check Nuclei findings
echo "============================================================"
echo "STEP 2: Check Nuclei Findings (30 min → $100-$1,000)"
echo "============================================================"
echo ""

if [ -f "output/nuclei-findings.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        FINDING_COUNT=$(jq 'length' output/nuclei-findings.json 2>/dev/null || echo "0")
        echo "✅ Found $FINDING_COUNT Nuclei findings"
        echo ""
        echo "Top 10 findings:"
        jq -r '.[] | "\(.matched-at) - \(.info.name) [\(.info.severity)]"' output/nuclei-findings.json 2>/dev/null | head -10
        echo ""
        echo "📋 ACTION: Format and submit to Bugcrowd/HackerOne"
    else
        echo "⚠️  jq not installed - install with: sudo apt install jq"
        echo "   Found nuclei-findings.json - review manually"
    fi
else
    echo "⚠️  No Nuclei findings file found"
fi

echo ""

# Step 3: Check submission-ready reports
echo "============================================================"
echo "STEP 3: Check Submission-Ready Reports"
echo "============================================================"
echo ""

if [ -d "output/immediate_roi/submission_reports" ]; then
    REPORT_COUNT=$(ls -1 output/immediate_roi/submission_reports/*.md 2>/dev/null | wc -l)
    if [ "$REPORT_COUNT" -gt 0 ]; then
        echo "✅ Found $REPORT_COUNT submission-ready reports"
        echo ""
        echo "Reports:"
        ls -1 output/immediate_roi/submission_reports/*.md 2>/dev/null | head -10
        echo ""
        echo "📋 ACTION: Review and submit these reports"
    else
        echo "⚠️  No submission reports found"
    fi
else
    echo "⚠️  No submission_reports directory found"
fi

echo ""

# Step 4: Check Upwork profile status
echo "============================================================"
echo "STEP 4: Upwork Profile Status"
echo "============================================================"
echo ""

if [ -f "output/upwork_business/UPWORK_COMPLETE_PACKAGE.md" ]; then
    echo "✅ Upwork profile content ready"
    echo ""
    echo "📋 ACTION: Copy to Upwork profile"
    echo "   File: output/upwork_business/UPWORK_COMPLETE_PACKAGE.md"
    echo ""
    echo "Steps:"
    echo "1. Open Upwork.com"
    echo "2. Complete profile to 100%"
    echo "3. Set hourly rate: \$75/hour"
    echo "4. Apply to 20 projects (use template)"
    echo ""
    echo "Expected: First project in 24-48 hours"
    echo "Revenue: \$200-\$500 per project"
else
    echo "⚠️  Upwork profile content not found"
fi

echo ""

# Summary
echo "============================================================"
echo "📊 SUMMARY - NEXT STEPS"
echo "============================================================"
echo ""
echo "IMMEDIATE ACTIONS (Next 30 minutes):"
echo "1. Submit secrets to Open Bug Bounty (if found)"
echo "2. Submit Nuclei findings to Bugcrowd/HackerOne (if found)"
echo "3. Setup Upwork profile (30 minutes)"
echo ""
echo "NEXT 2 HOURS:"
echo "1. Apply to 20 Upwork projects"
echo "2. Format and submit existing findings"
echo "3. Test scan workflow"
echo ""
echo "EXPECTED RESULTS:"
echo "- Day 1: First project won"
echo "- Day 2: First \$200-\$500 earned"
echo "- Week 1: \$1,000-\$3,000 revenue"
echo ""
echo "🚀 Ready to make money? Start with the actions above!"
echo ""

