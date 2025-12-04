#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.

###############################################################################
# UPWORK AUTO-SOLVER LAUNCHER
# 
# Automatically solves Upwork jobs with 100% accuracy validation
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║       UPWORK AUTO-SOLVER                                 ║"
echo "║       Instant Solution Generation & Submission           ║"
echo "║                                                          ║"
echo "║  ✓ 5 Problem Types Supported                            ║"
echo "║  ✓ 100% Accuracy Validation                             ║"
echo "║  ✓ Idempotent Operations                                ║"
echo "║  ✓ Revenue Tracking                                     ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

echo "✅ Python 3 found"
echo ""

# Create directories
mkdir -p upwork_solutions upwork_templates logs

# Show menu
echo "Choose an option:"
echo "1) Process test job (quick demo)"
echo "2) Run 4-hour autonomous loop"
echo "3) Open monitoring dashboard"
echo "4) View statistics"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "🧪 Processing test job..."
        python3 scripts/integrate_upwork_with_agents.py --test
        echo ""
        echo "✅ Test complete! Check upwork_solutions/ for generated files"
        ;;
    2)
        echo ""
        read -p "Runtime in hours (default 4): " hours
        hours=${hours:-4}
        echo ""
        echo "🚀 Starting $hours-hour autonomous loop..."
        echo "📊 Opening dashboard..."
        
        # Open dashboard
        if command -v explorer.exe &> /dev/null; then
            explorer.exe "UPWORK_AUTO_SOLVER_DASHBOARD.html" 2>/dev/null &
        elif command -v xdg-open &> /dev/null; then
            xdg-open "UPWORK_AUTO_SOLVER_DASHBOARD.html" 2>/dev/null &
        elif command -v open &> /dev/null; then
            open "UPWORK_AUTO_SOLVER_DASHBOARD.html" 2>/dev/null &
        fi
        
        python3 scripts/integrate_upwork_with_agents.py --standalone --hours "$hours"
        ;;
    3)
        echo ""
        echo "📊 Opening dashboard..."
        
        if command -v explorer.exe &> /dev/null; then
            explorer.exe "UPWORK_AUTO_SOLVER_DASHBOARD.html"
        elif command -v xdg-open &> /dev/null; then
            xdg-open "UPWORK_AUTO_SOLVER_DASHBOARD.html"
        elif command -v open &> /dev/null; then
            open "UPWORK_AUTO_SOLVER_DASHBOARD.html"
        else
            echo "❌ Cannot open browser automatically"
            echo "   Please open UPWORK_AUTO_SOLVER_DASHBOARD.html manually"
        fi
        ;;
    4)
        echo ""
        echo "📊 Statistics:"
        python3 -c "
import sys
sys.path.insert(0, 'scripts')
from upwork_auto_solver import UpworkAutoSolver
solver = UpworkAutoSolver()
stats = solver.get_stats()
print(f\"  Jobs Processed: {stats['total_jobs']}\")
print(f\"  Solutions Ready: {stats['ready_solutions']}\")
print(f\"  Potential Revenue: \${stats['potential_revenue']:.2f}\")
"
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo ""
