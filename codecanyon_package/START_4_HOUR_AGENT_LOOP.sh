#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.

###############################################################################
# START 4-HOUR AUTONOMOUS AGENT LOOP
# 
# This script starts the autonomous agent loop system with:
# - 4-hour continuous runtime
# - Idempotent task execution
# - Self-healing error recovery
# - Real-time monitoring dashboard
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║       AUTONOMOUS AGENT LOOP - 4 HOUR RUNTIME             ║"
echo "║                                                          ║"
echo "║  ✓ Idempotent Operations                                ║"
echo "║  ✓ Self-Healing Recovery                                ║"
echo "║  ✓ Multi-Agent Coordination                             ║"
echo "║  ✓ Real-Time Monitoring                                 ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check dependencies
echo "🔍 Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Install Python dependencies if needed
if ! python3 -c "import psutil" 2>/dev/null; then
    echo "📦 Installing psutil..."
    pip3 install psutil
fi

echo "✅ Dependencies OK"
echo ""

# Create logs directory
mkdir -p logs

# Ask for confirmation
echo "🤖 This will start the autonomous agent loop for 4 hours."
echo "   Tasks will run automatically on intervals:"
echo "   - Recon scan (every 30 min)"
echo "   - HTTPx probe (every 40 min)"
echo "   - Nuclei scan (every 1 hour)"
echo "   - Reports (every 20 min)"
echo "   - Performance monitoring (every 5 min)"
echo ""
echo "   Press Ctrl+C to stop at any time."
echo ""
read -p "Start now? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 0
fi

echo ""
echo "🚀 Starting 4-hour agent loop..."
echo "📊 Opening monitoring dashboard..."
echo ""

# Open dashboard in background (if on WSL with Windows browser)
if command -v explorer.exe &> /dev/null; then
    explorer.exe "AGENT_LOOP_DASHBOARD.html" 2>/dev/null &
elif command -v xdg-open &> /dev/null; then
    xdg-open "AGENT_LOOP_DASHBOARD.html" 2>/dev/null &
elif command -v open &> /dev/null; then
    open "AGENT_LOOP_DASHBOARD.html" 2>/dev/null &
fi

# Start the agent loop
python3 scripts/autonomous_agent_loop.py --hours 4.0

echo ""
echo "🏁 Agent loop completed!"
echo "📊 Check logs/agent_loop.log for details"
echo "💾 State saved in .agent_loop_state.db"
echo ""
