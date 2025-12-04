#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
#
# 1-CLICK BUG HUNT - Tonight's Ethical Bug Bounty Hunt
# Safe, legal, profitable.

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              🎯 BUG HUNT TONIGHT 🎯                          ║"
echo "║                                                               ║"
echo "║  Automated ethical bug bounty hunting on authorized programs ║"
echo "║                                                               ║"
echo "║  ✅ LEGAL: Public bug bounty programs only                   ║"
echo "║  ✅ ETHICAL: Responsible disclosure                          ║"
echo "║  ✅ PROFITABLE: $250-2000 per valid bug                      ║"
echo "║                                                               ║"
echo "║  Copyright © 2025 DoctorMen. All Rights Reserved.           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [ ! -f "BUG_HUNT_TONIGHT.py" ]; then
    echo "❌ Error: Must run from Recon-automation-Bug-bounty-stack directory"
    echo "📂 Run: cd ~/Recon-automation-Bug-bounty-stack && ./hunt_tonight.sh"
    exit 1
fi

# Make sure Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found"
    echo "💡 Install: sudo apt install python3"
    exit 1
fi

echo "🚀 Starting bug hunt..."
echo "⏰ Time: $(date)"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Run the bug hunt
python3 BUG_HUNT_TONIGHT.py

# Show results summary
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "✅ Bug hunt complete!"
echo ""
echo "📋 NEXT STEPS:"
echo ""
echo "1️⃣  Check findings:"
echo "   cat output/hunt_*/nuclei_results.txt"
echo ""
echo "2️⃣  Verify manually:"
echo "   curl -v [vulnerable_url]"
echo ""
echo "3️⃣  Submit:"
echo "   cat SUBMIT_NOW.md"
echo ""
echo "💰 Expected value: \$250-2000 per valid bug"
echo "⏰ Timeline to payout: 30-45 days"
echo ""
echo "═══════════════════════════════════════════════════════════════"
