#!/bin/bash
# Subdomain Takeover Scanner
# Checks discovered subdomains for takeover vulnerabilities
# Uses nuclei and custom checks for common subdomain takeover vectors
# Input: ~/recon-stack/output/subs.txt
# Output: ~/recon-stack/output/subdomain-takeover.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
SUBS_FILE="$OUTPUT_DIR/subs.txt"
TAKEOVER_OUTPUT="$OUTPUT_DIR/subdomain-takeover.json"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Subdomain Takeover Scanner Starting ==="

# Check if nuclei is installed
command -v nuclei >/dev/null 2>&1 || { log "ERROR: nuclei not installed"; exit 1; }
command -v jq >/dev/null 2>&1 || { log "ERROR: jq not installed"; exit 1; }

# Check if subs.txt exists
if [ ! -f "$SUBS_FILE" ]; then
    log "ERROR: subs.txt not found at $SUBS_FILE"
    log "Please run recon scanner agent first (scripts/run_recon.sh)"
    exit 1
fi

# Check if we have subdomains
if [ ! -s "$SUBS_FILE" ]; then
    log "WARNING: subs.txt is empty. No subdomains to check."
    echo "[]" > "$TAKEOVER_OUTPUT"
    exit 0
fi

SUB_COUNT=$(wc -l < "$SUBS_FILE")
log "Checking $SUB_COUNT subdomains for takeover vulnerabilities..."

# Run Nuclei subdomain takeover templates
TEMP_TAKEOVER="$OUTPUT_DIR/temp_takeover.json"
log "Running Nuclei takeover templates..."
nuclei -l "$SUBS_FILE" \
    -tags takeover \
    -json \
    -rate-limit 50 \
    -timeout 10 \
    -retries 1 \
    -silent \
    -o "$TEMP_TAKEOVER" 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: Nuclei takeover scan encountered errors"
    touch "$TEMP_TAKEOVER"
}

# Convert NDJSON to JSON array if needed
if [ ! -f "$TEMP_TAKEOVER" ] || [ ! -s "$TEMP_TAKEOVER" ]; then
    log "No takeover vulnerabilities found"
    echo "[]" > "$TAKEOVER_OUTPUT"
else
    # Convert NDJSON to JSON array
    if jq -e 'type == "array"' "$TEMP_TAKEOVER" >/dev/null 2>&1; then
        mv "$TEMP_TAKEOVER" "$TAKEOVER_OUTPUT"
    else
        jq -s '.' "$TEMP_TAKEOVER" > "$TAKEOVER_OUTPUT" 2>/dev/null || {
            log "WARNING: Failed to parse takeover results"
            echo "[]" > "$TAKEOVER_OUTPUT"
        }
        rm -f "$TEMP_TAKEOVER"
    fi
fi

TAKEOVER_COUNT=$(jq 'length' "$TAKEOVER_OUTPUT" 2>/dev/null || echo "0")
if [ "$TAKEOVER_COUNT" -gt 0 ]; then
    log "⚠️  Found $TAKEOVER_COUNT potential subdomain takeover vulnerabilities!"
    # Extract high-risk ones
    HIGH_RISK=$(jq '[.[] | select(.info.severity == "high" or .info.severity == "critical")] | length' "$TAKEOVER_OUTPUT" 2>/dev/null || echo "0")
    if [ "$HIGH_RISK" -gt 0 ]; then
        log "  - High/Critical: $HIGH_RISK"
    fi
else
    log "No subdomain takeover vulnerabilities found"
fi

log "=== Subdomain Takeover Scanner Complete ==="
log "Output: $TAKEOVER_OUTPUT"

