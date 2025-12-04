#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Fully automated: Install tools and run post_scan_processor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "=========================================="
log "Automated Installation and Execution"
log "=========================================="

# First, run installation script
log ""
log "Step 1: Installing required tools..."
if bash "$SCRIPT_DIR/install_tools.sh"; then
    log "✓ Tool installation completed"
else
    log "WARNING: Some tools may not be installed correctly"
    log "Continuing anyway..."
fi

# Ensure GOPATH/bin is in PATH
export PATH="$PATH:$HOME/go/bin"

# Verify critical tools
MISSING_TOOLS=()
for cmd in httpx nuclei python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_TOOLS+=("$cmd")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    log ""
    log "ERROR: Critical tools still missing: ${MISSING_TOOLS[*]}"
    log "Please install manually and try again"
    exit 1
fi

log ""
log "=========================================="
log "Step 2: Running Post Scan Processor"
log "=========================================="

# Now run the post scan processor
bash "$SCRIPT_DIR/post_scan_processor.sh"

