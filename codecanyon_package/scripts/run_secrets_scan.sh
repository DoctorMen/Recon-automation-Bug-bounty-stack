#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Secrets & Credentials Scanner
# Scans for exposed secrets, API keys, credentials, and sensitive data
# Uses nuclei templates and checks for common secret patterns
# Input: ~/recon-stack/output/http.json
# Output: ~/recon-stack/output/secrets-found.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
HTTP_FILE="$OUTPUT_DIR/http.json"
SECRETS_OUTPUT="$OUTPUT_DIR/secrets-found.json"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Secrets & Credentials Scanner Starting ==="

# Check if nuclei is installed
command -v nuclei >/dev/null 2>&1 || { log "ERROR: nuclei not installed"; exit 1; }
command -v jq >/dev/null 2>&1 || { log "ERROR: jq not installed"; exit 1; }

# Check if http.json exists
if [ ! -f "$HTTP_FILE" ]; then
    log "ERROR: http.json not found at $HTTP_FILE"
    log "Please run web mapper agent first (scripts/run_httpx.sh)"
    exit 1
fi

# Extract URLs from http.json
TEMP_URLS="$OUTPUT_DIR/temp_secrets_urls.txt"
jq -r '.[] | select(.url != null) | .url' "$HTTP_FILE" > "$TEMP_URLS" 2>/dev/null || touch "$TEMP_URLS"

# Check if we have URLs
if [ ! -s "$TEMP_URLS" ]; then
    log "WARNING: No URLs found in http.json"
    echo "[]" > "$SECRETS_OUTPUT"
    rm -f "$TEMP_URLS"
    exit 0
fi

URL_COUNT=$(wc -l < "$TEMP_URLS")
log "Scanning $URL_COUNT endpoints for exposed secrets and credentials..."

# Run Nuclei secret/credential disclosure templates
TEMP_SECRETS="$OUTPUT_DIR/temp_secrets.json"
log "Running Nuclei secrets and credential disclosure templates..."
nuclei -l "$TEMP_URLS" \
    -tags credential-disclosure,exposed,secrets,api-key,github-token,aws-key,azure-key \
    -json \
    -rate-limit 30 \
    -timeout 10 \
    -retries 1 \
    -silent \
    -o "$TEMP_SECRETS" 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: Nuclei secrets scan encountered errors"
    touch "$TEMP_SECRETS"
}

# Convert NDJSON to JSON array if needed
if [ ! -f "$TEMP_SECRETS" ] || [ ! -s "$TEMP_SECRETS" ]; then
    log "No exposed secrets found"
    echo "[]" > "$SECRETS_OUTPUT"
else
    # Convert NDJSON to JSON array
    if jq -e 'type == "array"' "$TEMP_SECRETS" >/dev/null 2>&1; then
        mv "$TEMP_SECRETS" "$SECRETS_OUTPUT"
    else
        jq -s '.' "$TEMP_SECRETS" > "$SECRETS_OUTPUT" 2>/dev/null || {
            log "WARNING: Failed to parse secrets results"
            echo "[]" > "$SECRETS_OUTPUT"
        }
        rm -f "$TEMP_SECRETS"
    fi
fi

SECRETS_COUNT=$(jq 'length' "$SECRETS_OUTPUT" 2>/dev/null || echo "0")
if [ "$SECRETS_COUNT" -gt 0 ]; then
    log "⚠️  Found $SECRETS_COUNT exposed secrets/credentials!"
    # Breakdown by type
    API_KEYS=$(jq '[.[] | select(.info.name | contains("API") or contains("api-key") or contains("token"))] | length' "$SECRETS_OUTPUT" 2>/dev/null || echo "0")
    CREDENTIALS=$(jq '[.[] | select(.info.name | contains("credential") or contains("password") or contains("secret"))] | length' "$SECRETS_OUTPUT" 2>/dev/null || echo "0")
    log "  - API Keys/Tokens: $API_KEYS"
    log "  - Credentials: $CREDENTIALS"
else
    log "No exposed secrets found"
fi

# Cleanup
rm -f "$TEMP_URLS"

log "=== Secrets & Credentials Scanner Complete ==="
log "Output: $SECRETS_OUTPUT"

