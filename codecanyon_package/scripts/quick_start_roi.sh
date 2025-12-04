#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick Start - Immediate ROI Bug Bounty Hunter
# One-command deployment for tonight's bug hunting

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  IMMEDIATE ROI BUG BOUNTY HUNTER - QUICK START            ║"
echo "║  High-Value Vulnerabilities for Maximum Profit             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if targets.txt exists
if [ ! -f "$REPO_ROOT/targets.txt" ]; then
    echo "⚠️  WARNING: targets.txt not found!"
    echo "Creating example targets.txt..."
    cat > "$REPO_ROOT/targets.txt" << EOF
# Add your authorized bug bounty targets here (one per line)
# Example:
# example.com
# authorized-target.com
EOF
    echo "✅ Created targets.txt - Please add your targets!"
    exit 1
fi

# Check if targets.txt has content
if ! grep -v '^#' "$REPO_ROOT/targets.txt" | grep -v '^$' | grep -q .; then
    echo "⚠️  WARNING: targets.txt is empty!"
    echo "Please add authorized targets to targets.txt"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ ERROR: Python not found"
    echo "Please install Python 3.7+"
    exit 1
fi

# Check nuclei
if ! command -v nuclei &> /dev/null; then
    echo "⚠️  WARNING: nuclei not found"
    echo "Installing tools..."
    if [ -f "$SCRIPT_DIR/../install.sh" ]; then
        bash "$SCRIPT_DIR/../install.sh"
    else
        echo "Please install nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        exit 1
    fi
fi

# Check httpx
if ! command -v httpx &> /dev/null; then
    echo "⚠️  WARNING: httpx not found"
    echo "Please install httpx: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""
echo "🚀 Starting Immediate ROI Bug Bounty Hunt..."
echo ""

# Run the hunter
cd "$REPO_ROOT"
exec "$SCRIPT_DIR/immediate_roi_hunter.sh"

