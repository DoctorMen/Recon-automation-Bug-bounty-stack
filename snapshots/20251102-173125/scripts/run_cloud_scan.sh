#!/bin/bash
# Cloud Misconfiguration Scanner
# Scans for cloud service misconfigurations (S3, Azure, GCP, etc.)
# Input: ~/recon-stack/output/http.json
# Output: ~/recon-stack/output/cloud-misconfigs.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
HTTP_FILE="$OUTPUT_DIR/http.json"
CLOUD_OUTPUT="$OUTPUT_DIR/cloud-misconfigs.json"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Cloud Misconfiguration Scanner Starting ==="

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
TEMP_URLS="$OUTPUT_DIR/temp_cloud_urls.txt"
jq -r '.[] | select(.url != null) | .url' "$HTTP_FILE" > "$TEMP_URLS" 2>/dev/null || touch "$TEMP_URLS"

# Check if we have URLs
if [ ! -s "$TEMP_URLS" ]; then
    log "WARNING: No URLs found in http.json"
    echo "[]" > "$CLOUD_OUTPUT"
    rm -f "$TEMP_URLS"
    exit 0
fi

URL_COUNT=$(wc -l < "$TEMP_URLS")
log "Scanning $URL_COUNT endpoints for cloud misconfigurations..."

# Run Nuclei cloud misconfiguration templates
TEMP_CLOUD="$OUTPUT_DIR/temp_cloud.json"
log "Running Nuclei cloud misconfiguration templates..."
nuclei -l "$TEMP_URLS" \
    -tags cloud,aws,s3-bucket,azure,gcp,gcp-bucket,kubernetes,docker \
    -json \
    -rate-limit 30 \
    -timeout 10 \
    -retries 1 \
    -silent \
    -o "$TEMP_CLOUD" 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: Nuclei cloud scan encountered errors"
    touch "$TEMP_CLOUD"
}

# Convert NDJSON to JSON array if needed
if [ ! -f "$TEMP_CLOUD" ] || [ ! -s "$TEMP_CLOUD" ]; then
    log "No cloud misconfigurations found"
    echo "[]" > "$CLOUD_OUTPUT"
else
    # Convert NDJSON to JSON array
    if jq -e 'type == "array"' "$TEMP_CLOUD" >/dev/null 2>&1; then
        mv "$TEMP_CLOUD" "$CLOUD_OUTPUT"
    else
        jq -s '.' "$TEMP_CLOUD" > "$CLOUD_OUTPUT" 2>/dev/null || {
            log "WARNING: Failed to parse cloud results"
            echo "[]" > "$CLOUD_OUTPUT"
        }
        rm -f "$TEMP_CLOUD"
    fi
fi

CLOUD_COUNT=$(jq 'length' "$CLOUD_OUTPUT" 2>/dev/null || echo "0")
if [ "$CLOUD_COUNT" -gt 0 ]; then
    log "⚠️  Found $CLOUD_COUNT cloud misconfigurations!"
    # Breakdown by cloud provider
    AWS=$(jq '[.[] | select(.info.name | contains("aws") or contains("s3") or contains("S3"))] | length' "$CLOUD_OUTPUT" 2>/dev/null || echo "0")
    AZURE=$(jq '[.[] | select(.info.name | contains("azure") or contains("Azure"))] | length' "$CLOUD_OUTPUT" 2>/dev/null || echo "0")
    GCP=$(jq '[.[] | select(.info.name | contains("gcp") or contains("GCP") or contains("google"))] | length' "$CLOUD_OUTPUT" 2>/dev/null || echo "0")
    K8S=$(jq '[.[] | select(.info.name | contains("kubernetes") or contains("k8s"))] | length' "$CLOUD_OUTPUT" 2>/dev/null || echo "0")
    log "  - AWS/S3: $AWS"
    log "  - Azure: $AZURE"
    log "  - GCP: $GCP"
    log "  - Kubernetes: $K8S"
else
    log "No cloud misconfigurations found"
fi

# Cleanup
rm -f "$TEMP_URLS"

log "=== Cloud Misconfiguration Scanner Complete ==="
log "Output: $CLOUD_OUTPUT"

