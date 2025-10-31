#!/bin/bash
# API Endpoint Discovery
# Discovers API endpoints, GraphQL, OpenAPI/Swagger docs, and API-related paths
# Input: ~/recon-stack/output/http.json
# Output: ~/recon-stack/output/api-endpoints.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
HTTP_FILE="$OUTPUT_DIR/http.json"
API_OUTPUT="$OUTPUT_DIR/api-endpoints.json"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== API Endpoint Discovery Starting ==="

# Check if httpx and nuclei are installed
command -v httpx >/dev/null 2>&1 || { log "ERROR: httpx not installed"; exit 1; }
command -v nuclei >/dev/null 2>&1 || { log "ERROR: nuclei not installed"; exit 1; }
command -v jq >/dev/null 2>&1 || { log "ERROR: jq not installed"; exit 1; }

# Check if http.json exists
if [ ! -f "$HTTP_FILE" ]; then
    log "ERROR: http.json not found at $HTTP_FILE"
    log "Please run web mapper agent first (scripts/run_httpx.sh)"
    exit 1
fi

# Extract base URLs from http.json
TEMP_URLS="$OUTPUT_DIR/temp_api_urls.txt"
jq -r '.[] | select(.url != null) | .url' "$HTTP_FILE" | sed 's|/$||' | sort -u > "$TEMP_URLS" 2>/dev/null || touch "$TEMP_URLS"

# Check if we have URLs
if [ ! -s "$TEMP_URLS" ]; then
    log "WARNING: No URLs found in http.json"
    echo "[]" > "$API_OUTPUT"
    rm -f "$TEMP_URLS"
    exit 0
fi

URL_COUNT=$(wc -l < "$TEMP_URLS")
log "Discovering API endpoints from $URL_COUNT base URLs..."

# Generate common API paths
TEMP_API_PATHS="$OUTPUT_DIR/temp_api_paths.txt"
while read -r base_url; do
    # Common API paths
    echo "${base_url}/api"
    echo "${base_url}/api/v1"
    echo "${base_url}/api/v2"
    echo "${base_url}/api/v3"
    echo "${base_url}/v1"
    echo "${base_url}/v2"
    echo "${base_url}/graphql"
    echo "${base_url}/graphql/v1"
    echo "${base_url}/graphiql"
    echo "${base_url}/.well-known/openapi.json"
    echo "${base_url}/.well-known/swagger.json"
    echo "${base_url}/swagger"
    echo "${base_url}/swagger.json"
    echo "${base_url}/swagger-ui"
    echo "${base_url}/api-docs"
    echo "${base_url}/api-docs/swagger.json"
    echo "${base_url}/openapi.json"
    echo "${base_url}/openapi.yaml"
    echo "${base_url}/api/swagger"
    echo "${base_url}/api/swagger.json"
done < "$TEMP_URLS" | sort -u > "$TEMP_API_PATHS"

PATH_COUNT=$(wc -l < "$TEMP_API_PATHS")
log "Generated $PATH_COUNT potential API endpoint paths"

# Probe API paths with httpx
TEMP_API_RESULTS="$OUTPUT_DIR/temp_api_results.json"
log "Probing API endpoints..."
httpx -l "$TEMP_API_PATHS" \
    -status-code \
    -title \
    -content-length \
    -json \
    -silent \
    -rate-limit 50 \
    -threads 50 \
    -timeout 10 \
    -retries 1 \
    -match-code "200,201,202,300,301,302" \
    -o "$TEMP_API_RESULTS" 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: API endpoint probing encountered errors"
    touch "$TEMP_API_RESULTS"
}

# Run Nuclei API-specific templates
TEMP_NUCLEI_API="$OUTPUT_DIR/temp_nuclei_api.json"
log "Running Nuclei API and GraphQL templates..."
nuclei -l "$TEMP_API_PATHS" \
    -tags api,graphql,swagger,openapi,graphql-introspection,rest \
    -json \
    -rate-limit 30 \
    -timeout 10 \
    -retries 1 \
    -silent \
    -o "$TEMP_NUCLEI_API" 2>&1 | tee -a "$LOG_FILE" || {
    log "WARNING: Nuclei API scan encountered errors"
    touch "$TEMP_NUCLEI_API"
}

# Combine results
API_FINDINGS=()

# Process httpx results
if [ -s "$TEMP_API_RESULTS" ]; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | jq -e '.url' >/dev/null 2>&1; then
            API_FINDINGS+=("$line")
        fi
    done < "$TEMP_API_RESULTS"
fi

# Process Nuclei results
if [ -s "$TEMP_NUCLEI_API" ]; then
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | jq -e '.matched-at' >/dev/null 2>&1; then
            API_FINDINGS+=("$line")
        fi
    done < "$TEMP_NUCLEI_API"
fi

# Convert to JSON array
if [ ${#API_FINDINGS[@]} -gt 0 ]; then
    printf '%s\n' "${API_FINDINGS[@]}" | jq -s '.' > "$API_OUTPUT" 2>/dev/null || {
        log "WARNING: Failed to combine API results"
        echo "[]" > "$API_OUTPUT"
    }
else
    echo "[]" > "$API_OUTPUT"
fi

API_COUNT=$(jq 'length' "$API_OUTPUT" 2>/dev/null || echo "0")
if [ "$API_COUNT" -gt 0 ]; then
    log "Found $API_COUNT API endpoints and related findings!"
    # Breakdown
    GRAPHQL=$(jq '[.[] | select(.url != null and (.url | contains("graphql"))) or select(.info.name | contains("graphql"))] | length' "$API_OUTPUT" 2>/dev/null || echo "0")
    SWAGGER=$(jq '[.[] | select(.url != null and (.url | contains("swagger"))) or select(.info.name | contains("swagger"))] | length' "$API_OUTPUT" 2>/dev/null || echo "0")
    OPENAPI=$(jq '[.[] | select(.url != null and (.url | contains("openapi"))) or select(.info.name | contains("openapi"))] | length' "$API_OUTPUT" 2>/dev/null || echo "0")
    log "  - GraphQL: $GRAPHQL"
    log "  - Swagger: $SWAGGER"
    log "  - OpenAPI: $OPENAPI"
else
    log "No API endpoints discovered"
fi

# Cleanup
rm -f "$TEMP_URLS" "$TEMP_API_PATHS" "$TEMP_API_RESULTS" "$TEMP_NUCLEI_API"

log "=== API Endpoint Discovery Complete ==="
log "Output: $API_OUTPUT"

