#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Check and install required tools for post_scan_processor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log "Checking required tools..."

# Check and install Go tools
check_go_tool() {
    local tool_name=$1
    local tool_path=$2
    
    if command -v "$tool_name" >/dev/null 2>&1; then
        log "✓ $tool_name is installed"
        return 0
    else
        log "✗ $tool_name is NOT installed"
        
        # Check if Go is installed
        if ! command -v go >/dev/null 2>&1; then
            log "ERROR: Go is not installed. Cannot install $tool_name"
            log "Please install Go first: https://golang.org/doc/install"
            return 1
        fi
        
        # Check if GOPATH/bin is in PATH
        if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
            log "WARNING: ~/go/bin is not in PATH. Adding it temporarily..."
            export PATH="$PATH:$HOME/go/bin"
        fi
        
        log "Installing $tool_name..."
        if go install "$tool_path@latest"; then
            log "✓ $tool_name installed successfully"
            return 0
        else
            log "ERROR: Failed to install $tool_name"
            return 1
        fi
    fi
}

# Check and install jq
check_jq() {
    if command -v jq >/dev/null 2>&1; then
        log "✓ jq is installed"
        return 0
    else
        log "✗ jq is NOT installed"
        
        # Try to install via apt (Ubuntu/Debian)
        if command -v apt-get >/dev/null 2>&1; then
            log "Installing jq via apt-get..."
            if sudo apt-get update && sudo apt-get install -y jq; then
                log "✓ jq installed successfully"
                return 0
            fi
        fi
        
        log "ERROR: Failed to install jq automatically"
        log "Please install jq manually: sudo apt-get install jq"
        return 1
    fi
}

# Check Python3
check_python3() {
    if command -v python3 >/dev/null 2>&1; then
        log "✓ python3 is installed"
        python3 --version
        return 0
    else
        log "ERROR: python3 is not installed"
        log "Please install Python 3: sudo apt-get install python3"
        return 1
    fi
}

# Check Go
check_go() {
    if command -v go >/dev/null 2>&1; then
        log "✓ go is installed"
        go version
        return 0
    else
        log "ERROR: go is not installed"
        log "Please install Go: https://golang.org/doc/install"
        return 1
    fi
}

# Main checks
MISSING=0

log ""
log "Checking Go..."
if ! check_go; then
    MISSING=$((MISSING + 1))
fi

log ""
log "Checking Python3..."
if ! check_python3; then
    MISSING=$((MISSING + 1))
fi

log ""
log "Checking Go tools..."
log "  (If GOPATH/bin is not in PATH, tools may be installed but not accessible)"
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$PATH:$HOME/go/bin"
    log "  Added ~/go/bin to PATH for this session"
fi

if ! check_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"; then
    MISSING=$((MISSING + 1))
fi

if ! check_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"; then
    MISSING=$((MISSING + 1))
fi

log ""
log "Checking jq..."
if ! check_jq; then
    MISSING=$((MISSING + 1))
fi

log ""
log "=========================================="
if [ $MISSING -eq 0 ]; then
    log "✓ All required tools are installed!"
    log ""
    log "Tools status:"
    for cmd in httpx nuclei jq python3 go; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "  ✓ $cmd"
        else
            echo "  ✗ $cmd (not in PATH, may need to add ~/go/bin to PATH)"
        fi
    done
    exit 0
else
    log "✗ $MISSING tool(s) missing or failed to install"
    log "Please install missing tools manually"
    exit 1
fi

