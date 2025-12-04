#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Start Medium-to-High Severity Bug Bounty Scan
# This script runs the full pipeline focused on medium+ severity findings

set -e

echo "============================================================"
echo "Starting Bug Bounty Scan - Medium+ Severity Focus"
echo "============================================================"
echo ""

# Set environment variables for medium+ severity focus
export NUCLEI_SEVERITY="medium,high,critical"
export TRIAGE_MIN_SEVERITY="medium"
export NUCLEI_RATE_LIMIT=50
export NUCLEI_SCAN_TIMEOUT=7200  # 2 hours

cd "$(dirname "$0")"

# Check if targets.txt has valid targets
TARGETS=$(grep -v '^#' targets.txt | grep -v '^$' | wc -l)
if [ "$TARGETS" -eq 0 ]; then
    echo "ERROR: No valid targets found in targets.txt"
    echo "Please add authorized domains to targets.txt"
    exit 1
fi

echo "✓ Found $TARGETS target(s) in targets.txt"
echo ""

# Check if subs.txt exists, if not run recon
if [ ! -f "output/subs.txt" ] || [ ! -s "output/subs.txt" ]; then
    echo ">>> Step 1/5: Running Recon Scanner..."
    python3 run_recon.py || echo "WARNING: Recon failed, but continuing..."
    echo ""
fi

# Check if http.json exists, if not run httpx
if [ ! -f "output/http.json" ] || [ ! -s "output/http.json" ]; then
    echo ">>> Step 2/5: Running Web Mapper (httpx)..."
    python3 run_httpx.py || echo "WARNING: httpx failed, but continuing..."
    echo ""
else
    echo "✓ http.json exists, skipping httpx"
    echo ""
fi

# Run Nuclei with medium+ severity focus
echo ">>> Step 3/5: Running Vulnerability Hunter (Nuclei - Medium+ Only)..."
python3 run_nuclei.py
echo ""

# Run Triage
echo ">>> Step 4/5: Running Triage (Filtering Medium+ Findings)..."
python3 scripts/triage.py
echo ""

# Generate Reports
echo ">>> Step 5/5: Generating Reports..."
python3 scripts/generate_report.py || echo "WARNING: Report generation failed"
echo ""

echo "============================================================"
echo "Scan Complete!"
echo "============================================================"
echo ""
echo "Results:"
echo "  - Findings: output/nuclei-findings.json"
echo "  - Triaged: output/triage.json"
echo "  - Reports: output/reports/"
echo ""
echo "View summary: cat output/reports/summary.md"
echo ""

