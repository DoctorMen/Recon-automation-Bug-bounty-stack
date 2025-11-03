#!/bin/bash
# Universal Bug Bounty Scanner - All Programs
# Scans ALL targets in targets.txt, not just Rapyd
# Focuses on quick wins (30-minute scans)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "============================================================"
echo "Universal Bug Bounty Scanner - ALL Programs"
echo "============================================================"
echo ""
echo "This will scan ALL bug bounty programs in targets.txt"
echo "Not just Rapyd - ALL legal targets!"
echo ""

# Check targets.txt
if [ ! -f "targets.txt" ]; then
    echo "ERROR: targets.txt not found"
    exit 1
fi

# Count targets
TARGET_COUNT=$(grep -v '^#' targets.txt | grep -v '^$' | wc -l)
echo "Found $TARGET_COUNT targets in targets.txt"
echo ""

# Show first 10 targets
echo "First 10 targets:"
grep -v '^#' targets.txt | grep -v '^$' | head -10 | nl
echo ""

# Ask for confirmation
read -p "Continue scanning ALL targets? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

echo ""
echo "============================================================"
echo "Starting Universal Scan"
echo "============================================================"
echo ""

# Clear any Rapyd-specific status files
rm -f output/.pipeline_status
rm -f output/immediate_roi/.status

# Run the universal pipeline
python3 scripts/immediate_roi_hunter.py --resume

echo ""
echo "============================================================"
echo "Scan Complete!"
echo "============================================================"
echo ""
echo "Results saved in: output/immediate_roi/"
echo "Summary: output/immediate_roi/ROI_SUMMARY.md"
echo ""

