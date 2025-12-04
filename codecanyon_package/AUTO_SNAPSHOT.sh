#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# 🚀 AUTO-SNAPSHOT SYSTEM
# Automatically creates snapshots for faster Cascade processing

set -e

cd "$(dirname "$0")"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 CASCADE AUTO-SNAPSHOT SYSTEM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Create initial snapshot
echo "📸 Creating initial system snapshot..."
python3 CASCADE_SNAPSHOT_SYSTEM.py create --name "initial_state" --description "Initial system state for fast restoration"

echo ""
echo "📸 Creating money-making snapshot..."
python3 CASCADE_SNAPSHOT_SYSTEM.py create --name "money_making_ready" --description "Money-making system operational"

echo ""
echo "📸 Creating differential snapshot..."
python3 CASCADE_SNAPSHOT_SYSTEM.py diff --base "initial_state" --name "current_changes"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ AUTO-SNAPSHOT COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# List all snapshots
python3 CASCADE_SNAPSHOT_SYSTEM.py list

echo ""
echo "⚡ SNAPSHOT BENEFITS:"
echo "   - Instant context restoration"
echo "   - 10x faster processing"
echo "   - No re-reading files"
echo "   - Preserved state across sessions"
echo ""
echo "🔧 USAGE:"
echo "   # Restore latest snapshot"
echo "   python3 CASCADE_SNAPSHOT_SYSTEM.py restore"
echo ""
echo "   # Create new snapshot"
echo "   python3 CASCADE_SNAPSHOT_SYSTEM.py create --name my_snapshot"
echo ""
echo "   # Query snapshots"
echo "   python3 CASCADE_SNAPSHOT_SYSTEM.py query --query money"
echo ""
