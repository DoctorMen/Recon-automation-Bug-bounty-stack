#!/bin/bash
# Evidence Capture Helper Script
# Helps save HTTP requests/responses and organize screenshots

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
SCREENSHOTS_DIR="$SCRIPT_DIR/../screenshots"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Create directories
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$SCREENSHOTS_DIR"

log "=== Evidence Capture Helper ==="
log "Evidence directory: $EVIDENCE_DIR"
log "Screenshots directory: $SCREENSHOTS_DIR"
log ""
log "Use this script to save your findings:"
log ""
log "1. After testing IDOR in Burp Suite:"
log "   - Right-click request → Copy as cURL"
log "   - Save to: $EVIDENCE_DIR/request_001.txt"
log ""
log "2. Right-click response → Copy response"
log "   - Save to: $EVIDENCE_DIR/response_001.txt"
log ""
log "3. Save screenshots to: $SCREENSHOTS_DIR/"
log ""
log "4. Record operation ID (if present):"
log "   - Look for 'operation_id' in response headers/body"
log "   - Save to: $EVIDENCE_DIR/operation_id.txt"
log ""
log "Ready to capture evidence!"

# Interactive mode
read -p "Do you want to save a request now? (y/n): " save_request

if [ "$save_request" = "y" ]; then
    read -p "Enter request number (e.g., 001): " req_num
    read -p "Paste your HTTP request (press Enter, then paste, then Ctrl+D): " request_content
    
    echo "$request_content" > "$EVIDENCE_DIR/request_${req_num}.txt"
    log "Request saved to: $EVIDENCE_DIR/request_${req_num}.txt"
fi

read -p "Do you want to save a response now? (y/n): " save_response

if [ "$save_response" = "y" ]; then
    read -p "Enter response number (e.g., 001): " res_num
    read -p "Paste your HTTP response (press Enter, then paste, then Ctrl+D): " response_content
    
    echo "$response_content" > "$EVIDENCE_DIR/response_${res_num}.txt"
    log "Response saved to: $EVIDENCE_DIR/response_${res_num}.txt"
fi

log "Evidence capture complete!"
log "Check: $EVIDENCE_DIR/"



