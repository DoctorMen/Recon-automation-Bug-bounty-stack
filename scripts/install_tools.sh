#!/bin/bash
# Simple tool installation script for post_scan_processor
# Install missing tools needed for the pipeline

set -euo pipefail

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "Installing required tools for post_scan_processor..."

# Ensure GOPATH/bin is in PATH
export PATH="$PATH:$HOME/go/bin"

# Check if Go is installed
if ! command -v go >/dev/null 2>&1; then
    log "ERROR: Go is not installed"
    log "Please install Go first from: https://golang.org/doc/install"
    exit 1
fi

log "Go version: $(go version)"

# Install httpx
if ! command -v httpx >/dev/null 2>&1; then
    log "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    log "✓ httpx installed"
else
    log "✓ httpx already installed"
fi

# Install nuclei
if ! command -v nuclei >/dev/null 2>&1; then
    log "Installing nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    log "✓ nuclei installed"
else
    log "✓ nuclei already installed"
fi

# Install jq (if not available)
if ! command -v jq >/dev/null 2>&1; then
    log "Installing jq..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y jq
        log "✓ jq installed"
    else
        log "WARNING: Cannot auto-install jq (apt-get not available)"
        log "Please install jq manually"
    fi
else
    log "✓ jq already installed"
fi

# Verify Python3
if ! command -v python3 >/dev/null 2>&1; then
    log "ERROR: python3 is not installed"
    log "Please install: sudo apt-get install python3"
    exit 1
else
    log "✓ python3 is installed: $(python3 --version)"
fi

log ""
log "=========================================="
log "Installation complete!"
log ""
log "Verifying tools:"
for cmd in httpx nuclei jq python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        log "  ✓ $cmd"
    else
        log "  ✗ $cmd (may need to add ~/go/bin to PATH)"
    fi
done

log ""
log "Note: If tools are not found, add to your ~/.bashrc:"
log "  export PATH=\"\$PATH:\$HOME/go/bin\""
log "Then run: source ~/.bashrc"

