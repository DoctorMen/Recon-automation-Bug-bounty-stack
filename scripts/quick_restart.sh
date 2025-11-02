#!/bin/bash
# Quick Restart Script - Uses Optimized Code

echo "=========================================="
echo "🛑 Stopping Current Scan"
echo "=========================================="
pkill -f amass 2>/dev/null
pkill -f subfinder 2>/dev/null
sleep 2

echo ""
echo "🧹 Clearing Status"
echo "=========================================="
cd ~/Recon-automation-Bug-bounty-stack
rm -f output/immediate_roi/.status

echo ""
echo "✅ Ready to restart with optimized code"
echo "=========================================="
echo ""
echo "🚀 Starting optimized scan..."
echo ""

python3 scripts/immediate_roi_hunter.py

