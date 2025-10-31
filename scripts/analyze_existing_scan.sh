#!/bin/bash
# Analyze Existing Scan Results
# Processes existing subs.txt to generate full pipeline results

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
SUBS_FILE="$OUTPUT_DIR/subs.txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "=== Analyzing Existing Scan Results ==="

# Check if subs.txt exists and has content
if [ ! -f "$SUBS_FILE" ] || [ ! -s "$SUBS_FILE" ]; then
    log "ERROR: subs.txt not found or empty"
    exit 1
fi

SUB_COUNT=$(wc -l < "$SUBS_FILE")
log "Found $SUB_COUNT subdomains in subs.txt"

# Check for existing results
if [ -f "$OUTPUT_DIR/http.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        HTTP_COUNT=$(jq 'length' "$OUTPUT_DIR/http.json" 2>/dev/null || echo "0")
        log "Existing http.json found with $HTTP_COUNT endpoints"
    else
        log "Existing http.json found"
    fi
fi

if [ -f "$OUTPUT_DIR/nuclei-findings.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        NUCLEI_COUNT=$(jq 'length' "$OUTPUT_DIR/nuclei-findings.json" 2>/dev/null || echo "0")
        log "Existing nuclei-findings.json found with $NUCLEI_COUNT findings"
    else
        log "Existing nuclei-findings.json found"
    fi
fi

log ""
log "Would you like to:"
log "1. Process existing subs.txt through full pipeline (httpx → nuclei → triage → reports)"
log "2. Just analyze what's already there"
log "3. Convert nuclei.txt to JSON format (if exists)"

echo ""
read -p "Enter choice (1/2/3) [default: 1]: " choice
choice=${choice:-1}

case $choice in
    1)
        log "Running full pipeline from existing subs.txt..."
        if [ -f "$SCRIPT_DIR/post_scan_processor.sh" ]; then
            bash "$SCRIPT_DIR/post_scan_processor.sh"
        else
            log "Running pipeline stages..."
            bash "$SCRIPT_DIR/run_httpx.sh"
            bash "$SCRIPT_DIR/run_nuclei.sh"
            python3 "$SCRIPT_DIR/triage.py"
            python3 "$SCRIPT_DIR/generate_report.py"
        fi
        ;;
    2)
        log "Analyzing existing results..."
        if command -v jq >/dev/null 2>&1; then
            if [ -f "$OUTPUT_DIR/triage.json" ]; then
                log ""
                log "=== Triage Results ==="
                jq 'group_by(.info.severity) | map({severity: .[0].info.severity, count: length})' "$OUTPUT_DIR/triage.json"
            fi
        fi
        ;;
    3)
        if [ -f "$OUTPUT_DIR/nuclei.txt" ] && [ -s "$OUTPUT_DIR/nuclei.txt" ]; then
            log "Converting nuclei.txt to JSON..."
            # If nuclei.txt contains JSON lines, convert to array
            jq -s '.' "$OUTPUT_DIR/nuclei.txt" > "$OUTPUT_DIR/nuclei-findings.json" 2>/dev/null || {
                log "ERROR: nuclei.txt doesn't appear to be valid JSON"
            }
        else
            log "nuclei.txt not found or empty"
        fi
        ;;
esac

log "Analysis complete!"

