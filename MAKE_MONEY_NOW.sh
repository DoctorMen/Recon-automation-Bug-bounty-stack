#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# 🚀 MAKE MONEY NOW - Complete Automated System
# Uses Windsurf's new features + all your repositories
# Idempotent: Safe to run multiple times

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 MONEY-MAKING MASTER - COMPLETE AUTOMATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Leveraging:"
echo "  ✅ Windsurf's new Codemaps"
echo "  ✅ Improved Summarization"
echo "  ✅ MCP Enhancements"
echo "  ✅ All your repository assets"
echo ""

cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)

# Create output directories
mkdir -p output/money_master
mkdir -p output/proposals
mkdir -p output/reports
mkdir -p output/analytics

echo "📁 Directories ready"
echo ""

# Check if proposals exist
if [ ! -f "output/proposals/proposal_300.txt" ]; then
    echo "📝 Generating proposal templates..."
    bash CASCADE_SUCCESS_LAUNCHER.sh
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1: Running Money-Making Cycle"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python3 MONEY_MAKING_MASTER.py --mode once

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2: Checking Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "output/money_master/state.json" ]; then
    echo "📊 Current Status:"
    python3 -c "
import json
with open('output/money_master/state.json', 'r') as f:
    state = json.load(f)
    print(f\"  Applications sent: {len(state.get('jobs_applied', []))}\")
    print(f\"  Jobs won: {len(state.get('jobs_won', []))}\")
    print(f\"  Revenue earned: \${state.get('revenue_earned', 0)}\")
    print(f\"  Scans completed: {state.get('scans_completed', 0)}\")
"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ CYCLE COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📖 Next Steps:"
echo ""
echo "1️⃣  MANUAL APPLICATION (Until MCP integrated):"
echo "   - Open Upwork: https://www.upwork.com/nx/search/jobs/?q=security%20scan"
echo "   - Use proposals from: output/money_master/proposal_*.txt"
echo "   - Apply to 10 jobs (3 minutes each)"
echo ""
echo "2️⃣  WHEN YOU WIN A JOB:"
echo "   python3 MONEY_MAKING_MASTER.py --deliver domain.com:ClientName"
echo ""
echo "3️⃣  RUN CONTINUOUSLY (24/7 monitoring):"
echo "   python3 MONEY_MAKING_MASTER.py --mode continuous --interval 60"
echo ""
echo "4️⃣  VIEW ANALYTICS:"
echo "   cat output/money_master/money_master.log"
echo ""
echo "💰 Expected Results TODAY:"
echo "   - Apply to 10-20 jobs: 30-60 minutes"
echo "   - Win 1-3 jobs: $200-$1,000"
echo "   - Deliver in 2 hours: Automated"
echo "   - Get paid + reviews: Build momentum"
echo ""
echo "🚀 YOUR SYSTEM IS READY TO MAKE MONEY!"
echo ""
