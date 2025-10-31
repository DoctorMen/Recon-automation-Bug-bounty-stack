#!/bin/bash
# Main Pipeline Orchestrator
# Runs all agents in sequence: Recon → Mapper → Hunter → Triage → Report
# Supports resume capability and provides detailed statistics

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"

# Resume capability - skip completed stages
RESUME="${RESUME:-false}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"
STATUS_FILE="$OUTPUT_DIR/.pipeline_status"

# Source config if available
[ -f "$SCRIPT_DIR/config.sh" ] && source "$SCRIPT_DIR/config.sh"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

mark_stage_complete() {
    local stage="$1"
    echo "$stage" >> "$STATUS_FILE"
}

is_stage_complete() {
    local stage="$1"
    [ ! -f "$STATUS_FILE" ] && return 1
    grep -q "^$stage$" "$STATUS_FILE"
}

log "=========================================="
log "Recon Stack Pipeline - Full Run"
log "=========================================="
START_TIME=$(date +%s)

# Check if targets.txt exists
if [ ! -f "$REPO_ROOT/targets.txt" ]; then
    log "ERROR: targets.txt not found"
    log "Please create targets.txt with authorized domains (one per line)"
    exit 1
fi

# Verify targets.txt has content
if ! grep -v '^#' "$REPO_ROOT/targets.txt" | grep -v '^$' | grep -q .; then
    log "ERROR: No valid targets found in targets.txt"
    log "Please add at least one authorized domain"
    exit 1
fi

# Agent 1: Recon Scanner
log ""
log ">>> Starting Agent 1: Recon Scanner"
if [ "$RESUME" = "true" ] && is_stage_complete "recon"; then
    log "Skipping recon (already complete, use RESUME=false to rerun)"
else
    if "$SCRIPT_DIR/run_recon.sh"; then
        mark_stage_complete "recon"
    else
        log "ERROR: Recon scanner failed"
        exit 1
    fi
fi

# Agent 2: Web Mapper
log ""
log ">>> Starting Agent 2: Web Mapper"
if [ "$RESUME" = "true" ] && is_stage_complete "httpx"; then
    log "Skipping httpx (already complete, use RESUME=false to rerun)"
else
    if "$SCRIPT_DIR/run_httpx.sh"; then
        mark_stage_complete "httpx"
    else
        log "WARNING: Web mapper failed (continuing)"
    fi
fi

# Agent 3: Vulnerability Hunter (Comprehensive Nuclei Scan)
log ""
log ">>> Starting Agent 3: Vulnerability Hunter (Comprehensive)"
if [ "$RESUME" = "true" ] && is_stage_complete "nuclei"; then
    log "Skipping nuclei (already complete, use RESUME=false to rerun)"
else
    if "$SCRIPT_DIR/run_nuclei.sh"; then
        mark_stage_complete "nuclei"
    else
        log "WARNING: Vulnerability hunter failed (continuing)"
    fi
fi

# Specialized Scans (run in parallel after web mapping)
# These focus on specific bug bounty attack vectors

if [ "${SKIP_SPECIALIZED_SCANS:-false}" != "true" ]; then
    log ""
    log ">>> Starting Specialized Bug Bounty Scans"
    
    # API Discovery
    log ""
    log ">>> Running API Endpoint Discovery"
    if "$SCRIPT_DIR/run_api_discovery.sh"; then
        mark_stage_complete "api-discovery"
    else
        log "WARNING: API discovery failed (continuing)"
    fi
    
    # Subdomain Takeover
    log ""
    log ">>> Running Subdomain Takeover Scan"
    if "$SCRIPT_DIR/run_subdomain_takeover.sh"; then
        mark_stage_complete "subdomain-takeover"
    else
        log "WARNING: Subdomain takeover scan failed (continuing)"
    fi
    
    # Secrets Scan
    log ""
    log ">>> Running Secrets & Credentials Scan"
    if "$SCRIPT_DIR/run_secrets_scan.sh"; then
        mark_stage_complete "secrets-scan"
    else
        log "WARNING: Secrets scan failed (continuing)"
    fi
    
    # Cloud Misconfigurations
    log ""
    log ">>> Running Cloud Misconfiguration Scan"
    if "$SCRIPT_DIR/run_cloud_scan.sh"; then
        mark_stage_complete "cloud-scan"
    else
        log "WARNING: Cloud scan failed (continuing)"
    fi
else
    log ""
    log ">>> Skipping specialized scans (SKIP_SPECIALIZED_SCANS=true)"
fi

# Agent 4: Triage
log ""
log ">>> Starting Agent 4: Triage"
if [ "$RESUME" = "true" ] && is_stage_complete "triage"; then
    log "Skipping triage (already complete, use RESUME=false to rerun)"
else
    if python3 "$SCRIPT_DIR/triage.py"; then
        mark_stage_complete "triage"
    else
        log "WARNING: Triage failed (continuing)"
    fi
fi

# Agent 5: Report Writer
log ""
log ">>> Starting Agent 5: Report Writer"
if [ "$RESUME" = "true" ] && is_stage_complete "reports"; then
    log "Skipping reports (already complete, use RESUME=false to rerun)"
else
    if python3 "$SCRIPT_DIR/generate_report.py"; then
        mark_stage_complete "reports"
    else
        log "WARNING: Report generation failed (continuing)"
    fi
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

log ""
log "=========================================="
log "Pipeline Complete!"
log "=========================================="
log ""
log "Execution Time: ${MINUTES}m ${SECONDS}s"
log ""

# Generate statistics
log "=== Statistics ==="
if [ -f "$OUTPUT_DIR/subs.txt" ]; then
    SUB_COUNT=$(wc -l < "$OUTPUT_DIR/subs.txt" 2>/dev/null || echo "0")
    log "Subdomains Discovered: $SUB_COUNT"
fi

if [ -f "$OUTPUT_DIR/http.json" ] && command -v jq >/dev/null 2>&1; then
    HTTP_COUNT=$(jq 'length' "$OUTPUT_DIR/http.json" 2>/dev/null || echo "0")
    log "HTTP Endpoints: $HTTP_COUNT"
fi

if [ -f "$OUTPUT_DIR/nuclei-findings.json" ] && command -v jq >/dev/null 2>&1; then
    NUCLEI_COUNT=$(jq 'length' "$OUTPUT_DIR/nuclei-findings.json" 2>/dev/null || echo "0")
    log "Raw Findings: $NUCLEI_COUNT"
fi

if [ -f "$OUTPUT_DIR/triage.json" ] && command -v jq >/dev/null 2>&1; then
    TRIAGE_COUNT=$(jq 'length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    CRITICAL=$(jq '[.[] | select(.info.severity == "critical")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    HIGH=$(jq '[.[] | select(.info.severity == "high")] | length' "$OUTPUT_DIR/triage.json" 2>/dev/null || echo "0")
    log "Triaged Findings: $TRIAGE_COUNT"
    log "  - Critical: $CRITICAL"
    log "  - High: $HIGH"
fi

# Specialized scan results
if [ "${SKIP_SPECIALIZED_SCANS:-false}" != "true" ]; then
    log ""
    log "=== Specialized Scan Results ==="
    
    if [ -f "$OUTPUT_DIR/api-endpoints.json" ] && command -v jq >/dev/null 2>&1; then
        API_COUNT=$(jq 'length' "$OUTPUT_DIR/api-endpoints.json" 2>/dev/null || echo "0")
        log "API Endpoints Discovered: $API_COUNT"
    fi
    
    if [ -f "$OUTPUT_DIR/subdomain-takeover.json" ] && command -v jq >/dev/null 2>&1; then
        TAKEOVER_COUNT=$(jq 'length' "$OUTPUT_DIR/subdomain-takeover.json" 2>/dev/null || echo "0")
        if [ "$TAKEOVER_COUNT" -gt 0 ]; then
            log "⚠️  Subdomain Takeover Vulnerabilities: $TAKEOVER_COUNT"
        fi
    fi
    
    if [ -f "$OUTPUT_DIR/secrets-found.json" ] && command -v jq >/dev/null 2>&1; then
        SECRETS_COUNT=$(jq 'length' "$OUTPUT_DIR/secrets-found.json" 2>/dev/null || echo "0")
        if [ "$SECRETS_COUNT" -gt 0 ]; then
            log "⚠️  Exposed Secrets/Credentials: $SECRETS_COUNT"
        fi
    fi
    
    if [ -f "$OUTPUT_DIR/cloud-misconfigs.json" ] && command -v jq >/dev/null 2>&1; then
        CLOUD_COUNT=$(jq 'length' "$OUTPUT_DIR/cloud-misconfigs.json" 2>/dev/null || echo "0")
        if [ "$CLOUD_COUNT" -gt 0 ]; then
            log "⚠️  Cloud Misconfigurations: $CLOUD_COUNT"
        fi
    fi
fi

if [ -d "$OUTPUT_DIR/reports" ]; then
    REPORT_COUNT=$(find "$OUTPUT_DIR/reports" -name "*.md" ! -name "summary.md" | wc -l)
    log "Reports Generated: $REPORT_COUNT"
fi

log ""
log "=== Output Files ==="
log "  - Subdomains: $OUTPUT_DIR/subs.txt"
log "  - HTTP Endpoints: $OUTPUT_DIR/http.json"
log "  - Nuclei Findings: $OUTPUT_DIR/nuclei-findings.json"
if [ "${SKIP_SPECIALIZED_SCANS:-false}" != "true" ]; then
    log "  - API Endpoints: $OUTPUT_DIR/api-endpoints.json"
    log "  - Subdomain Takeover: $OUTPUT_DIR/subdomain-takeover.json"
    log "  - Secrets Found: $OUTPUT_DIR/secrets-found.json"
    log "  - Cloud Misconfigs: $OUTPUT_DIR/cloud-misconfigs.json"
fi
log "  - Triaged Findings: $OUTPUT_DIR/triage.json"
log "  - Reports: $OUTPUT_DIR/reports/"
log ""
log "View summary report: $OUTPUT_DIR/reports/summary.md"
log ""
log "To rerun from start: RESUME=false ./scripts/run_pipeline.sh"
log "To skip specialized scans: SKIP_SPECIALIZED_SCANS=true ./scripts/run_pipeline.sh"
log ""

