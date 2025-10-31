#!/bin/bash
# Process Existing Scan Results
# Takes existing subs.txt and processes through full pipeline or locates existing results

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
SUBS_FILE="$OUTPUT_DIR/subs.txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "=== Processing Existing Scan Results ==="

# Check for existing subs.txt
if [ ! -f "$SUBS_FILE" ] || [ ! -s "$SUBS_FILE" ]; then
    log "ERROR: subs.txt not found or empty"
    exit 1
fi

SUB_COUNT=$(wc -l < "$SUBS_FILE")
log "Found $SUB_COUNT subdomains in subs.txt"

# Check for existing JSON results
if [ -f "$OUTPUT_DIR/nuclei-findings.json" ] && [ -s "$OUTPUT_DIR/nuclei-findings.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        NUCLEI_COUNT=$(jq 'length' "$OUTPUT_DIR/nuclei-findings.json" 2>/dev/null || echo "0")
        log "Found existing nuclei-findings.json with $NUCLEI_COUNT findings"
        
        if [ "$NUCLEI_COUNT" -gt 0 ]; then
            log ""
            log "Existing findings found! Would you like to:"
            log "1. Re-triage existing findings (with improved scoring)"
            log "2. Generate reports from existing findings"
            log "3. Process subs.txt through full pipeline (may take time)"
            echo ""
            read -p "Choice [1/2/3, default: 1]: " choice
            choice=${choice:-1}
            
            case $choice in
                1)
                    log "Re-triaging existing findings..."
                    python3 "$SCRIPT_DIR/triage.py"
                    python3 "$SCRIPT_DIR/generate_report.py"
                    ;;
                2)
                    log "Generating reports from existing findings..."
                    python3 "$SCRIPT_DIR/generate_report.py"
                    ;;
                3)
                    log "Running full pipeline..."
                    bash "$SCRIPT_DIR/post_scan_processor.sh" || {
                        bash "$SCRIPT_DIR/run_httpx.sh"
                        bash "$SCRIPT_DIR/run_nuclei.sh"
                        python3 "$SCRIPT_DIR/triage.py"
                        python3 "$SCRIPT_DIR/generate_report.py"
                    }
                    ;;
            esac
            exit 0
        fi
    fi
fi

# No existing findings, process through pipeline
log ""
log "No existing nuclei findings found. Processing $SUB_COUNT subdomains through pipeline..."
log "This will:"
log "  1. Probe subdomains with httpx"
log "  2. Scan with nuclei"
log "  3. Triage and score findings"
log "  4. Generate reports"
log ""
read -p "Continue? [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    log "Cancelled"
    exit 0
fi

# Run pipeline
log "Starting pipeline..."
if [ -f "$SCRIPT_DIR/post_scan_processor.sh" ]; then
    bash "$SCRIPT_DIR/post_scan_processor.sh"
else
    log "Running httpx..."
    bash "$SCRIPT_DIR/run_httpx.sh"
    
    log "Running nuclei (this may take a while with $SUB_COUNT subdomains)..."
    bash "$SCRIPT_DIR/run_nuclei.sh"
    
    log "Triaging findings..."
    python3 "$SCRIPT_DIR/triage.py"
    
    log "Generating reports..."
    python3 "$SCRIPT_DIR/generate_report.py"
fi

# Show results
log ""
log "=== Results Summary ==="
if [ -f "$OUTPUT_DIR/triage.json" ] && command -v jq >/dev/null 2>&1; then
    TOTAL=$(jq 'length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    CRITICAL=$(jq '[.[] | select(.info.severity == "critical")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    HIGH=$(jq '[.[] | select(.info.severity == "high")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    MEDIUM=$(jq '[.[] | select(.info.severity == "medium")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    
    log "Total Findings: $TOTAL"
    log "  - Critical: $CRITICAL"
    log "  - High: $HIGH"
    log "  - Medium: $MEDIUM"
    log ""
    log "Reports: $OUTPUT_DIR/reports/"
    log "Summary: $OUTPUT_DIR/reports/summary.md"
fi

log "Done!"

