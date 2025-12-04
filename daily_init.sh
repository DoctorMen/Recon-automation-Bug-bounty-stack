#!/bin/bash
# Daily Initialization Script
# Runs system checks and updates for Recon-automation-Bug-bounty-stack
# Author: Auto-generated
# License: Proprietary - All Rights Reserved

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="$HOME/Recon-automation-Bug-bounty-stack/logs/daily_init_$(date +%Y%m%d).log"
mkdir -p "$HOME/Recon-automation-Bug-bounty-stack/logs"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Banner
echo -e "${GREEN}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        DAILY INITIALIZATION SCRIPT                        ║
║        Recon-automation-Bug-bounty-stack                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "Starting daily initialization - $(date)"

# Change to project directory
cd "$HOME/Recon-automation-Bug-bounty-stack" || exit 1

# 1. System Package Updates
log "Step 1/10: Updating system packages..."
if command -v apt &> /dev/null; then
    sudo apt update -qq && sudo apt upgrade -y -qq
    log "✓ System packages updated"
else
    warn "apt not found, skipping system updates"
fi

# 2. Update Python packages
log "Step 2/10: Updating Python packages..."
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    pip install --upgrade pip -q
    pip list --outdated --format=freeze 2>/dev/null | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip install -U -q 2>/dev/null || true
    log "✓ Python packages updated"
else
    warn "Virtual environment not found, skipping Python updates"
fi

# 3. Update Go tools
log "Step 3/10: Updating Go-based security tools..."
if command -v go &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || warn "Failed to update subfinder"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || warn "Failed to update nuclei"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || warn "Failed to update httpx"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || warn "Failed to update katana"
    log "✓ Go tools updated"
else
    warn "Go not installed, skipping Go tool updates"
fi

# 4. Update Nuclei templates
log "Step 4/10: Updating Nuclei templates..."
if command -v nuclei &> /dev/null; then
    nuclei -update-templates -silent 2>/dev/null || warn "Failed to update Nuclei templates"
    log "✓ Nuclei templates updated"
else
    warn "Nuclei not installed, skipping template updates"
fi

# 5. Run security checks
log "Step 5/10: Running security checks..."
if [ -f "scripts/security_checks.py" ]; then
    python3 scripts/security_checks.py 2>/dev/null || warn "Security checks failed"
    log "✓ Security checks completed"
else
    warn "security_checks.py not found, skipping"
fi

# 6. Backup important files
log "Step 6/10: Backing up configuration..."
BACKUP_DIR="$HOME/backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup config
if [ -d "config" ]; then
    cp -r config "$BACKUP_DIR/" 2>/dev/null || warn "Failed to backup config"
fi

# Backup scripts
if [ -d "scripts" ]; then
    cp -r scripts "$BACKUP_DIR/" 2>/dev/null || warn "Failed to backup scripts"
fi

# Backup authorizations
if [ -d "authorizations" ]; then
    cp -r authorizations "$BACKUP_DIR/" 2>/dev/null || warn "Failed to backup authorizations"
fi

# Backup important output
if [ -d "output" ]; then
    cp -r output/upwork_data "$BACKUP_DIR/" 2>/dev/null || true
    cp -r output/enterprise_sales "$BACKUP_DIR/" 2>/dev/null || true
fi

log "✓ Backup completed to $BACKUP_DIR"

# 7. Check disk space
log "Step 7/10: Checking disk space..."
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    error "Disk usage is ${DISK_USAGE}% - Consider cleaning up"
else
    info "Disk usage: ${DISK_USAGE}%"
fi

# 8. Clean old logs (keep last 30 days)
log "Step 8/10: Cleaning old logs..."
find logs/ -name "*.log" -mtime +30 -delete 2>/dev/null || true
find output/ -name "*.log" -mtime +30 -delete 2>/dev/null || true
log "✓ Old logs cleaned"

# 9. Clean old backups (keep last 7 days)
log "Step 9/10: Cleaning old backups..."
find "$HOME/backups/" -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \; 2>/dev/null || true
log "✓ Old backups cleaned"

# 10. System health check
log "Step 10/10: System health check..."

# Check if critical tools are installed
TOOLS=("subfinder" "nuclei" "httpx" "python3" "git")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    warn "Missing tools: ${MISSING_TOOLS[*]}"
else
    log "✓ All critical tools installed"
fi

# Check Python dependencies
if [ -f "requirements.txt" ]; then
    source venv/bin/activate 2>/dev/null || true
    pip check &>/dev/null && log "✓ Python dependencies OK" || warn "Python dependency conflicts detected"
fi

# Check Git status
if [ -d ".git" ]; then
    UNCOMMITTED=$(git status --porcelain | wc -l)
    if [ "$UNCOMMITTED" -gt 0 ]; then
        info "$UNCOMMITTED uncommitted changes in repository"
    else
        log "✓ Git repository clean"
    fi
fi

# Summary
echo ""
log "═══════════════════════════════════════════════════════════"
log "Daily initialization completed successfully!"
log "═══════════════════════════════════════════════════════════"
echo ""
info "System Status:"
info "  - Disk Usage: ${DISK_USAGE}%"
info "  - Backup Location: $BACKUP_DIR"
info "  - Log File: $LOG_FILE"
echo ""

# Optional: Display today's targets (if targets.txt exists)
if [ -f "targets.txt" ]; then
    TARGET_COUNT=$(wc -l < targets.txt)
    info "Active Targets: $TARGET_COUNT"
fi

# Optional: Display recent scan results
if [ -d "output" ]; then
    RECENT_SCANS=$(find output/ -name "*.json" -mtime -1 | wc -l)
    info "Recent Scans (24h): $RECENT_SCANS"
fi

echo ""
log "Ready for bug bounty hunting! 🎯"
echo ""

# Exit successfully
exit 0
