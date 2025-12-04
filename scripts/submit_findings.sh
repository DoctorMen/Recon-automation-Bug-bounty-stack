#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Submit Findings Helper - Quick check and submit guide
# Usage: ./scripts/submit_findings.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "============================================================"
echo "📋 CHECKING FOR FINDINGS TO SUBMIT"
echo "============================================================"
echo ""

# Check secrets
echo "1. Checking for secrets..."
if [ -f "output/potential-secrets.txt" ]; then
    SECRET_COUNT=$(wc -l < output/potential-secrets.txt)
    echo "   ✅ Found $SECRET_COUNT potential secrets"
    echo ""
    echo "   First 5:"
    head -5 output/potential-secrets.txt | sed 's/^/      /'
    echo ""
    echo "   📋 Submit to: https://www.openbugbounty.org"
    echo "      (No signup needed, instant submission)"
    echo "      Reward: \$50-\$500 per secret"
    echo "      Validation: 24-48 hours"
else
    echo "   ⚠️  No secrets file found"
fi

echo ""

# Check Nuclei findings
echo "2. Checking Nuclei findings..."
if [ -f "output/nuclei-findings.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        FINDING_COUNT=$(jq 'length' output/nuclei-findings.json 2>/dev/null || echo "0")
        if [ "$FINDING_COUNT" -gt 0 ]; then
            echo "   ✅ Found $FINDING_COUNT findings"
            echo ""
            echo "   Top 10:"
            jq -r '.[] | "      \(.matched-at) - \(.info.name) [\(.info.severity)]"' output/nuclei-findings.json 2>/dev/null | head -10
            echo ""
            echo "   📋 Submit to: Bugcrowd/HackerOne"
            echo "      Format: Use existing templates"
            echo "      Reward: \$100-\$1,000 per finding"
        else
            echo "   ⚠️  No findings in file"
        fi
    else
        echo "   ⚠️  jq not installed - install with: sudo apt install jq"
        echo "      Found nuclei-findings.json - review manually"
    fi
else
    echo "   ⚠️  No Nuclei findings file found"
fi

echo ""

# Check submission reports
echo "3. Checking submission-ready reports..."
if [ -d "output/immediate_roi/submission_reports" ]; then
    REPORT_COUNT=$(ls -1 output/immediate_roi/submission_reports/*.md 2>/dev/null | wc -l)
    if [ "$REPORT_COUNT" -gt 0 ]; then
        echo "   ✅ Found $REPORT_COUNT reports"
        echo ""
        echo "   Reports:"
        ls -1 output/immediate_roi/submission_reports/*.md 2>/dev/null | head -10 | sed 's/^/      /'
        echo ""
        echo "   📋 Action: Review and submit these reports"
    else
        echo "   ⚠️  No reports found"
    fi
else
    echo "   ⚠️  No submission_reports directory found"
fi

echo ""
echo "============================================================"
echo "✅ CHECK COMPLETE"
echo "============================================================"
echo ""
echo "Next steps:"
echo "1. Submit secrets to Open Bug Bounty (if found)"
echo "2. Format and submit Nuclei findings (if found)"
echo "3. Review and submit ready reports (if found)"
echo ""

