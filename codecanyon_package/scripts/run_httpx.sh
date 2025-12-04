#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Web Mapper Agent
# Uses httpx to probe alive hosts and fingerprint technologies
# Input: ~/recon-stack/output/subs.txt
# Output: ~/recon-stack/output/http.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
SUBS_FILE="$OUTPUT_DIR/subs.txt"
HTTP_OUTPUT="$OUTPUT_DIR/http.json"
HTTP_TEMP="$OUTPUT_DIR/temp_httpx.json"

# Configuration
RATE_LIMIT="${HTTPX_RATE_LIMIT:-100}"
TIMEOUT="${HTTPX_TIMEOUT:-10}"
THREADS="${HTTPX_THREADS:-50}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Web Mapper Agent Starting ==="

# Check if httpx is installed
command -v httpx >/dev/null 2>&1 || { log "ERROR: httpx not installed"; exit 1; }
command -v jq >/dev/null 2>&1 || { log "ERROR: jq not installed"; exit 1; }

# Check if subs.txt exists
if [ ! -f "$SUBS_FILE" ]; then
    log "ERROR: subs.txt not found at $SUBS_FILE"
    log "Please run recon scanner agent first (scripts/run_recon.sh)"
    exit 1
fi

# Check if subs.txt has content
if [ ! -s "$SUBS_FILE" ]; then
    log "WARNING: subs.txt is empty. No subdomains to probe."
    echo "[]" > "$HTTP_OUTPUT"
    exit 0
fi

SUB_COUNT=$(wc -l < "$SUBS_FILE")
log "Probing $SUB_COUNT subdomains with httpx..."

# Run httpx with comprehensive bug bounty features
# Note: httpx outputs NDJSON (newline-delimited JSON), not a JSON array
log "Running httpx with comprehensive bug bounty scanning (rate-limit: $RATE_LIMIT, threads: $THREADS)..."
httpx -l "$SUBS_FILE" \
    -probe \
    -tech-detect \
    -status-code \
    -title \
    -json \
    -silent \
    -rate-limit "$RATE_LIMIT" \
    -threads "$THREADS" \
    -timeout "$TIMEOUT" \
    -retries 2 \
    -favicon \
    -hash \
    -server-header \
    -response-header \
    -location \
    -method \
    -asn \
    -cdn \
    -chain \
    -jarm \
    -o "$HTTP_TEMP" 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: httpx encountered errors (checking for partial output)"
}

# Note: Deep path scanning can be added later if needed via a separate script
# Keeping httpx focused on endpoint discovery and fingerprinting

# Convert NDJSON to JSON array
if [ ! -f "$HTTP_TEMP" ] || [ ! -s "$HTTP_TEMP" ]; then
    log "No results from httpx"
    echo "[]" > "$HTTP_OUTPUT"
else
    # Check if it's already valid JSON array
    if jq -e 'type == "array"' "$HTTP_TEMP" >/dev/null 2>&1; then
        # Already an array, just move it
        mv "$HTTP_TEMP" "$HTTP_OUTPUT"
    else
        # Convert NDJSON to JSON array
        log "Converting NDJSON to JSON array..."
        jq -s '.' "$HTTP_TEMP" > "$HTTP_OUTPUT" 2>/dev/null || {
            log "ERROR: Failed to convert httpx output to JSON array"
            # Try to create valid array from NDJSON manually
            echo "[" > "$HTTP_OUTPUT"
            sed 's/$/,/' "$HTTP_TEMP" | sed '$s/,$//' >> "$HTTP_OUTPUT" 2>/dev/null || true
            echo "]" >> "$HTTP_OUTPUT"
        }
        rm -f "$HTTP_TEMP"
    fi
fi

# Count results and extract statistics
HTTP_COUNT=$(jq 'length' "$HTTP_OUTPUT" 2>/dev/null || echo "0")
if [ "$HTTP_COUNT" -gt 0 ]; then
    # Extract statistics
    HTTPS_COUNT=$(jq '[.[] | select(.url != null and (.url | startswith("https://")))] | length' "$HTTP_OUTPUT" 2>/dev/null || echo "0")
    STATUS_200=$(jq '[.[] | select(.status-code == 200)] | length' "$HTTP_OUTPUT" 2>/dev/null || echo "0")
    log "Found $HTTP_COUNT alive HTTP/HTTPS endpoints"
    log "  - HTTPS: $HTTPS_COUNT"
    log "  - Status 200: $STATUS_200"
else
    log "No alive endpoints found"
fi

log "=== Web Mapper Agent Complete ==="
log "Output: $HTTP_OUTPUT"

