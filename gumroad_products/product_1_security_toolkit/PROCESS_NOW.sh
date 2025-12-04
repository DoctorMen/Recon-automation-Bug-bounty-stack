#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick command to process your nuclei results - RUN THIS NOW!

cd ~/recon-stack || cd /home/ubuntu/recon-stack || exit 1

echo "=========================================="
echo "Processing Your 772 Nuclei Results"
echo "=========================================="
echo ""

# Find the results file
RESULTS_FILE="$HOME/nuclei-templates/results_web_scan.txt"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "ERROR: Cannot find results_web_scan.txt"
    echo "Expected location: $RESULTS_FILE"
    echo ""
    echo "Please run:"
    echo "  bash PROCESS_NOW.sh"
    echo ""
    echo "Or provide the path:"
    echo "  python3 scripts/parse_nuclei_text_results.py /path/to/results_web_scan.txt"
    exit 1
fi

echo "Found results file: $RESULTS_FILE"
echo ""

# Step 1: Parse
echo ">>> Step 1/3: Parsing text to JSON..."
python3 scripts/parse_nuclei_text_results.py "$RESULTS_FILE"

if [ $? -ne 0 ]; then
    echo "ERROR: Parsing failed"
    exit 1
fi

# Step 2: Triage
echo ""
echo ">>> Step 2/3: Triaging findings..."
python3 scripts/triage.py

if [ $? -ne 0 ]; then
    echo "ERROR: Triage failed"
    exit 1
fi

# Step 3: Reports
echo ""
echo ">>> Step 3/3: Generating reports..."
python3 scripts/generate_report.py

if [ $? -ne 0 ]; then
    echo "ERROR: Report generation failed"
    exit 1
fi

# Show results
echo ""
echo "=========================================="
echo "COMPLETE!"
echo "=========================================="
echo ""

if command -v jq >/dev/null 2>&1 && [ -f "output/triage.json" ]; then
    TOTAL=$(jq 'length' output/triage.json 2>/dev/null || echo "0")
    CRITICAL=$(jq '[.[] | select(.info.severity == "critical")] | length' output/triage.json 2>/dev/null || echo "0")
    HIGH=$(jq '[.[] | select(.info.severity == "high")] | length' output/triage.json 2>/dev/null || echo "0")
    MEDIUM=$(jq '[.[] | select(.info.severity == "medium")] | length' output/triage.json 2>/dev/null || echo "0")
    LOW=$(jq '[.[] | select(.info.severity == "low")] | length' output/triage.json 2>/dev/null || echo "0")
    INFO=$(jq '[.[] | select(.info.severity == "info")] | length' output/triage.json 2>/dev/null || echo "0")
    
    echo "Results Summary:"
    echo "  Total Findings: $TOTAL"
    echo "  - Critical: $CRITICAL"
    echo "  - High: $HIGH"
    echo "  - Medium: $MEDIUM"
    echo "  - Low: $LOW"
    echo "  - Info: $INFO"
    echo ""
fi

echo "View your reports:"
echo "  Summary: cat output/reports/summary.md"
echo "  All reports: ls output/reports/"
echo ""
echo "Files created:"
echo "  - output/nuclei-findings.json (parsed results)"
echo "  - output/triage.json (scored findings)"
echo "  - output/reports/*.md (individual reports)"
echo ""

