#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Process Nuclei Text Results
# Converts nuclei text output to JSON and processes through triage/reporting

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"

# Default nuclei results file
NUCLEI_TEXT_FILE="${1:-$HOME/nuclei-templates/results_web_scan.txt}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "=== Processing Nuclei Text Results ==="
log "Input file: $NUCLEI_TEXT_FILE"

# Check if file exists
if [ ! -f "$NUCLEI_TEXT_FILE" ]; then
    log "ERROR: File not found: $NUCLEI_TEXT_FILE"
    log "Usage: $0 [path-to-nuclei-text-output]"
    exit 1
fi

LINE_COUNT=$(wc -l < "$NUCLEI_TEXT_FILE")
log "Found $LINE_COUNT lines in input file"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Step 1: Parse text to JSON
log ""
log ">>> Step 1/4: Parsing nuclei text output to JSON..."
if python3 "$SCRIPT_DIR/parse_nuclei_text_results.py" "$NUCLEI_TEXT_FILE"; then
    log "✓ Parsing completed"
else
    log "ERROR: Parsing failed"
    exit 1
fi

# Step 2: Run triage
log ""
log ">>> Step 2/4: Running triage (scoring & filtering)..."
if python3 "$SCRIPT_DIR/triage.py"; then
    log "✓ Triage completed"
else
    log "ERROR: Triage failed"
    exit 1
fi

# Step 3: Generate reports
log ""
log ">>> Step 3/4: Generating reports..."
if python3 "$SCRIPT_DIR/generate_report.py"; then
    log "✓ Report generation completed"
else
    log "ERROR: Report generation failed"
    exit 1
fi

# Step 4: Show summary
log ""
log ">>> Step 4/4: Summary"

if [ -f "$OUTPUT_DIR/triage.json" ] && command -v jq >/dev/null 2>&1; then
    TOTAL=$(jq 'length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    CRITICAL=$(jq '[.[] | select(.info.severity == "critical")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    HIGH=$(jq '[.[] | select(.info.severity == "high")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    MEDIUM=$(jq '[.[] | select(.info.severity == "medium")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    LOW=$(jq '[.[] | select(.info.severity == "low")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    INFO=$(jq '[.[] | select(.info.severity == "info")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    
    log ""
    log "=== Results ==="
    log "Total Findings: $TOTAL"
    log "  - Critical: $CRITICAL"
    log "  - High: $HIGH"
    log "  - Medium: $MEDIUM"
    log "  - Low: $LOW"
    log "  - Info: $INFO"
    log ""
    log "Files generated:"
    log "  - nuclei-findings.json: $OUTPUT_DIR/nuclei-findings.json"
    log "  - triage.json: $OUTPUT_DIR/triage.json"
    log "  - Reports: $OUTPUT_DIR/reports/"
    log "  - Summary: $OUTPUT_DIR/reports/summary.md"
fi

log ""
log "=== Complete ==="
log "View summary: $OUTPUT_DIR/reports/summary.md"

