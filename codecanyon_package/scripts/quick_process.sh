#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick process script - handles file location automatically

cd "$(dirname "$0")/.." || exit 1

NUCLEI_FILE="${1:-$HOME/nuclei-templates/results_web_scan.txt}"

echo "=== Processing Nuclei Results ==="
echo "Looking for: $NUCLEI_FILE"

# Try multiple locations
if [ ! -f "$NUCLEI_FILE" ]; then
    # Try alternative locations
    for alt in "$HOME/nuclei-templates/results_web_scan.txt" \
               "./results_web_scan.txt" \
               "../nuclei-templates/results_web_scan.txt"; do
        if [ -f "$alt" ]; then
            NUCLEI_FILE="$alt"
            echo "Found at: $NUCLEI_FILE"
            break
        fi
    done
fi

if [ ! -f "$NUCLEI_FILE" ]; then
    echo "ERROR: File not found. Please provide path:"
    echo "  bash scripts/quick_process.sh /path/to/results_web_scan.txt"
    exit 1
fi

echo "Processing: $NUCLEI_FILE"
echo ""

# Step 1: Parse
echo ">>> Step 1: Parsing text to JSON..."
python3 scripts/parse_nuclei_text_results.py "$NUCLEI_FILE" || exit 1

# Step 2: Triage
echo ""
echo ">>> Step 2: Triaging findings..."
python3 scripts/triage.py || exit 1

# Step 3: Reports
echo ""
echo ">>> Step 3: Generating reports..."
python3 scripts/generate_report.py || exit 1

# Summary
echo ""
echo "=== Complete ==="
if [ -f "output/triage.json" ] && command -v jq >/dev/null 2>&1; then
    TOTAL=$(jq 'length' output/triage.json 2>/dev/null || echo "0")
    echo "Total findings: $TOTAL"
    echo "Summary: output/reports/summary.md"
fi

