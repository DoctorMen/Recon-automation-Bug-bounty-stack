#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Recon Scanner Agent
# Runs Subfinder + Amass to enumerate subdomains, validates with DNSx
# Output: ~/recon-stack/output/subs.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"
TARGETS_FILE="$REPO_ROOT/targets.txt"

# Configuration (can be overridden via environment)
TIMEOUT="${RECON_TIMEOUT:-1800}"  # 30 minutes default
PARALLEL="${PARALLEL_RECON:-false}"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="$OUTPUT_DIR/recon-run.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Recon Scanner Agent Starting ==="

# Check if targets.txt exists
if [ ! -f "$TARGETS_FILE" ]; then
    log "ERROR: targets.txt not found at $TARGETS_FILE"
    log "Please create targets.txt with authorized domains (one per line)"
    exit 1
fi

# Check if tools are installed
command -v subfinder >/dev/null 2>&1 || { log "ERROR: subfinder not installed"; exit 1; }
command -v amass >/dev/null 2>&1 || { log "ERROR: amass not installed"; exit 1; }
command -v dnsx >/dev/null 2>&1 || { log "WARNING: dnsx not installed (will skip validation)"; }

# Read targets
TARGETS=$(cat "$TARGETS_FILE" | grep -v '^#' | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
if [ -z "$TARGETS" ]; then
    log "ERROR: No valid targets found in targets.txt"
    exit 1
fi

TARGET_COUNT=$(grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | wc -l)
log "Processing $TARGET_COUNT target(s): $TARGETS"

# Temporary files
TEMP_SUBFINDER="$OUTPUT_DIR/temp_subfinder.txt"
TEMP_AMASS="$OUTPUT_DIR/temp_amass.txt"
TEMP_COMBINED="$OUTPUT_DIR/temp_combined_subs.txt"
TEMP_VALIDATED="$OUTPUT_DIR/temp_validated_subs.txt"
FINAL_SUBS="$OUTPUT_DIR/subs.txt"

# Function to run with timeout
run_with_timeout() {
    local cmd="$1"
    local timeout_val="$2"
    timeout "$timeout_val" bash -c "$cmd" || {
        log "WARNING: Command timed out after ${timeout_val}s"
        return 1
    }
}

# Run Subfinder
log "Running Subfinder (timeout: ${TIMEOUT}s)..."
if run_with_timeout "subfinder -dL '$TARGETS_FILE' -silent -o '$TEMP_SUBFINDER' 2>&1" "$TIMEOUT"; then
    SUBFINDER_COUNT=$(wc -l < "$TEMP_SUBFINDER" 2>/dev/null || echo "0")
    log "Subfinder found $SUBFINDER_COUNT subdomains"
else
    log "WARNING: Subfinder encountered errors (continuing)"
    touch "$TEMP_SUBFINDER"
fi

# Run Amass (with passive mode for faster results, can be changed to active)
log "Running Amass enum (timeout: ${TIMEOUT}s)..."
if run_with_timeout "amass enum -passive -df '$TARGETS_FILE' -o '$TEMP_AMASS' 2>&1" "$TIMEOUT"; then
    AMASS_COUNT=$(wc -l < "$TEMP_AMASS" 2>/dev/null || echo "0")
    log "Amass found $AMASS_COUNT subdomains"
else
    log "WARNING: Amass encountered errors (continuing)"
    touch "$TEMP_AMASS"
fi

# Combine and deduplicate
log "Combining and deduplicating results..."
cat "$TEMP_SUBFINDER" "$TEMP_AMASS" 2>/dev/null | sort -u > "$TEMP_COMBINED" || touch "$TEMP_COMBINED"

COMBINED_COUNT=$(wc -l < "$TEMP_COMBINED" 2>/dev/null || echo "0")
log "Combined results: $COMBINED_COUNT unique subdomains"

# Validate with DNSx if available
if command -v dnsx >/dev/null 2>&1 && [ -s "$TEMP_COMBINED" ]; then
    log "Validating subdomains with DNSx..."
    if run_with_timeout "dnsx -l '$TEMP_COMBINED' -a -aaaa -cname -mx -ns -txt -soa -resp -o '$TEMP_VALIDATED' 2>&1" 600; then
        VALIDATED_COUNT=$(wc -l < "$TEMP_VALIDATED" 2>/dev/null || echo "0")
        log "DNSx validated $VALIDATED_COUNT subdomains"
        # Extract just the subdomain names from DNSx output (format: domain [A:ip])
        if [ -s "$TEMP_VALIDATED" ]; then
            cut -d' ' -f1 "$TEMP_VALIDATED" | sort -u > "$FINAL_SUBS"
        else
            # If DNSx found none, use original list
            cp "$TEMP_COMBINED" "$FINAL_SUBS"
            log "WARNING: DNSx validation found no live subdomains, using raw results"
        fi
    else
        log "WARNING: DNSx validation failed, using raw results"
        cp "$TEMP_COMBINED" "$FINAL_SUBS"
    fi
else
    # No DNSx, use raw results
    cp "$TEMP_COMBINED" "$FINAL_SUBS"
fi

# Final count and stats
SUB_COUNT=$(wc -l < "$FINAL_SUBS" 2>/dev/null || echo "0")
log "Final result: $SUB_COUNT validated subdomains"

# Cleanup temp files
rm -f "$TEMP_SUBFINDER" "$TEMP_AMASS" "$TEMP_COMBINED" "$TEMP_VALIDATED"

if [ "$SUB_COUNT" -eq 0 ]; then
    log "WARNING: No subdomains discovered. Check your targets and network connectivity."
fi

log "=== Recon Scanner Agent Complete ==="
log "Output: $FINAL_SUBS"

