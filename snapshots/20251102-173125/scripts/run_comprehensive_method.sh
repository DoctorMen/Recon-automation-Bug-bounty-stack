#!/bin/bash
# Quick Start - Comprehensive Bug Bounty Method
# Runs the unified PDF-enhanced bug bounty method

echo "============================================================"
echo "🎯 Comprehensive Bug Bounty Method v2.0"
echo "============================================================"
echo ""
echo "📚 Knowledge Sources:"
echo "  ✅ Crypto Dictionary PDF"
echo "  ✅ Hacking APIs PDF"
echo "  ✅ Penetration Testing PDF"
echo "  ✅ Practical IoT Hacking PDF"
echo "  ✅ Designing Secure Software PDF"
echo "  ✅ OPSEC Best Practices"
echo ""
echo "============================================================"
echo ""

cd ~/Recon-automation-Bug-bounty-stack

# Run comprehensive method
python3 scripts/comprehensive_bug_bounty_method.py --targets targets.txt --output output/comprehensive_method

echo ""
echo "============================================================"
echo "✅ Method Complete!"
echo "============================================================"
echo ""
echo "Check results in: output/comprehensive_method/"
echo ""

