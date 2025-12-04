#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Post Scan Processor
# Processes scan results from subs.txt through the full pipeline
# Input: ~/recon-stack/output/subs.txt
# Output: Summary of live hosts and high-severity findings

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
SUBS_FILE="$OUTPUT_DIR/subs.txt"
HTTP_FILE="$OUTPUT_DIR/http.json"
NUCLEI_FILE="$OUTPUT_DIR/nuclei-findings.json"
TRIAGE_FILE="$OUTPUT_DIR/triage.json"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"
SUMMARY_FILE="$OUTPUT_DIR/summary.md"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Auto-install missing tools
install_missing_tools() {
    log "Checking for required tools..."
    
    # Ensure GOPATH/bin is in PATH
    export PATH="$PATH:$HOME/go/bin"
    
    # Check and install httpx
    if ! command -v httpx >/dev/null 2>&1; then
        log "httpx not found, installing..."
        if command -v go >/dev/null 2>&1; then
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | tee -a "$LOG_FILE" || {
                log "ERROR: Failed to install httpx"
                return 1
            }
            export PATH="$PATH:$HOME/go/bin"
            log "✓ httpx installed"
        else
            log "ERROR: Go not installed, cannot install httpx"
            return 1
        fi
    else
        log "✓ httpx already installed"
    fi
    
    # Check and install nuclei
    if ! command -v nuclei >/dev/null 2>&1; then
        log "nuclei not found, installing..."
        if command -v go >/dev/null 2>&1; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tee -a "$LOG_FILE" || {
                log "ERROR: Failed to install nuclei"
                return 1
            }
            export PATH="$PATH:$HOME/go/bin"
            log "✓ nuclei installed"
        else
            log "ERROR: Go not installed, cannot install nuclei"
            return 1
        fi
    else
        log "✓ nuclei already installed"
    fi
    
    # Check and install jq (optional but recommended)
    if ! command -v jq >/dev/null 2>&1; then
        log "jq not found, attempting to install..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -qq && sudo apt-get install -y jq 2>&1 | tee -a "$LOG_FILE" || {
                log "WARNING: Failed to install jq (continuing without it)"
            }
        else
            log "WARNING: Cannot auto-install jq (apt-get not available)"
        fi
    else
        log "✓ jq already installed"
    fi
    
    # Verify Python3
    if ! command -v python3 >/dev/null 2>&1; then
        log "ERROR: python3 is not installed"
        log "Please install: sudo apt-get install python3"
        return 1
    else
        log "✓ python3 installed"
    fi
    
    return 0
}

log "=========================================="
log "Post Scan Processor Starting"
log "=========================================="

# Auto-install missing tools
log ""
if ! install_missing_tools; then
    log "ERROR: Tool installation failed or incomplete"
    exit 1
fi

# Ensure PATH is updated after installations
export PATH="$PATH:$HOME/go/bin"

# Check if subs.txt exists
if [ ! -f "$SUBS_FILE" ]; then
    log "ERROR: subs.txt not found at $SUBS_FILE"
    log "Please run recon scanner first (scripts/run_recon.sh)"
    exit 1
fi

# Check if subs.txt has content
if [ ! -s "$SUBS_FILE" ]; then
    log "WARNING: subs.txt is empty. No subdomains to process."
    exit 0
fi

SUB_COUNT=$(wc -l < "$SUBS_FILE")
log "Processing $SUB_COUNT subdomains from $SUBS_FILE"

# Source config if available
[ -f "$SCRIPT_DIR/config.sh" ] && source "$SCRIPT_DIR/config.sh"

# Step 1: Run httpx
log ""
log ">>> Step 1/4: Running httpx (Web Mapper)"
export PATH="$PATH:$HOME/go/bin"
if bash "$SCRIPT_DIR/run_httpx.sh"; then
    log "✓ httpx completed successfully"
else
    log "ERROR: httpx failed"
    exit 1
fi

# Step 2: Run nuclei
log ""
log ">>> Step 2/4: Running nuclei (Vulnerability Hunter)"
export PATH="$PATH:$HOME/go/bin"
if bash "$SCRIPT_DIR/run_nuclei.sh"; then
    log "✓ nuclei completed successfully"
else
    log "ERROR: nuclei failed"
    exit 1
fi

# Step 3: Run triage
log ""
log ">>> Step 3/4: Running triage (Scoring & Filtering)"
if python3 "$SCRIPT_DIR/triage.py"; then
    log "✓ triage completed successfully"
else
    log "ERROR: triage failed"
    exit 1
fi

# Step 4: Generate reports
log ""
log ">>> Step 4/4: Generating reports"
if python3 "$SCRIPT_DIR/generate_report.py"; then
    log "✓ report generation completed successfully"
else
    log "ERROR: report generation failed"
    exit 1
fi

# Generate summary
log ""
log ">>> Generating Summary"

# Check if jq is available for JSON processing
if ! command -v jq >/dev/null 2>&1; then
    log "WARNING: jq not installed, generating basic summary without JSON stats"
    jq_available=false
else
    jq_available=true
fi

# Count live hosts
LIVE_HOSTS=0
if [ -f "$HTTP_FILE" ] && [ -s "$HTTP_FILE" ]; then
    if [ "$jq_available" = true ]; then
        LIVE_HOSTS=$(jq 'length' "$HTTP_FILE" 2>/dev/null || echo "0")
    else
        LIVE_HOSTS=$(wc -l < "$HTTP_FILE" 2>/dev/null || echo "0")
    fi
fi

# Count high-severity findings (critical + high)
HIGH_SEVERITY_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
TOTAL_FINDINGS=0

if [ -f "$TRIAGE_FILE" ] && [ -s "$TRIAGE_FILE" ]; then
    if [ "$jq_available" = true ]; then
        TOTAL_FINDINGS=$(jq 'length' "$TRIAGE_FILE" 2>/dev/null || echo "0")
        CRITICAL_COUNT=$(jq '[.[] | select(.info.severity == "critical")] | length' "$TRIAGE_FILE" 2>/dev/null || echo "0")
        HIGH_COUNT=$(jq '[.[] | select(.info.severity == "high")] | length' "$TRIAGE_FILE" 2>/dev/null || echo "0")
        MEDIUM_COUNT=$(jq '[.[] | select(.info.severity == "medium")] | length' "$TRIAGE_FILE" 2>/dev/null || echo "0")
        LOW_COUNT=$(jq '[.[] | select(.info.severity == "low")] | length' "$TRIAGE_FILE" 2>/dev/null || echo "0")
        INFO_COUNT=$(jq '[.[] | select(.info.severity == "info")] | length' "$TRIAGE_FILE" 2>/dev/null || echo "0")
    else
        # Fallback: count lines (less accurate but works without jq)
        TOTAL_FINDINGS=$(wc -l < "$TRIAGE_FILE" 2>/dev/null || echo "0")
    fi
    HIGH_SEVERITY_COUNT=$((CRITICAL_COUNT + HIGH_COUNT))
fi

# Generate summary markdown
cat > "$SUMMARY_FILE" << EOF
# Scan Summary Report

**Generated**: $(date '+%Y-%m-%d %H:%M:%S UTC')  
**Input**: $SUB_COUNT subdomains from subs.txt

---

## Results Overview

### Live Hosts
- **Total Live Hosts**: $LIVE_HOSTS

### Vulnerability Findings

- **Total Findings**: $TOTAL_FINDINGS
- **Critical**: $CRITICAL_COUNT 🔴
- **High**: $HIGH_COUNT 🟠
- **Medium**: $MEDIUM_COUNT 🟡
- **Low**: $LOW_COUNT 🟢
- **Info**: $INFO_COUNT ℹ️

### High-Severity Findings (Critical + High)
- **Total High-Severity**: $HIGH_SEVERITY_COUNT

---

## Next Steps

1. Review individual reports in: \`output/reports/\`
2. Check summary report: \`output/reports/summary.md\`
3. Review triaged findings: \`output/triage.json\`

---

## Output Files

- **Subdomains**: \`output/subs.txt\`
- **Live HTTP Endpoints**: \`output/http.json\`
- **Raw Findings**: \`output/nuclei-findings.json\`
- **Triaged Findings**: \`output/triage.json\`
- **Reports**: \`output/reports/\`

EOF

log ""
log "=========================================="
log "Post Scan Processor Complete"
log "=========================================="
log ""
log "=== SUMMARY ==="
log "Live Hosts: $LIVE_HOSTS"
log "High-Severity Findings (Critical + High): $HIGH_SEVERITY_COUNT"
log "  - Critical: $CRITICAL_COUNT"
log "  - High: $HIGH_COUNT"
log ""
log "Total Findings: $TOTAL_FINDINGS"
log "  - Medium: $MEDIUM_COUNT"
log "  - Low: $LOW_COUNT"
log "  - Info: $INFO_COUNT"
log ""
log "Summary report: $SUMMARY_FILE"
log "Detailed reports: $OUTPUT_DIR/reports/"
log ""

