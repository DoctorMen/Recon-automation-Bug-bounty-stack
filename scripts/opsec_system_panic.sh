#!/bin/bash
# OPSEC System Panic Script
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Emergency response for security incidents

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}========================================"
echo "  EMERGENCY PANIC MODE ACTIVATED"
echo "========================================${NC}"
echo ""

# Confirm action
echo -e "${YELLOW}WARNING: This will:${NC}"
echo "  1. Disconnect network"
echo "  2. Kill suspicious processes"
echo "  3. Clear sensitive history"
echo "  4. Create forensic snapshot"
echo "  5. Lock system"
echo ""

read -p "Continue? (type YES in caps): " confirm

if [ "$confirm" != "YES" ]; then
    echo "Cancelled."
    exit 0
fi

LOG_FILE="/tmp/opsec_panic_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== PANIC MODE ACTIVATED ==="

# 1. DISCONNECT NETWORK
log "Step 1: Disconnecting network interfaces..."
for iface in $(ip link show | grep -E "^[0-9]" | awk '{print $2}' | sed 's/://'); do
    if [ "$iface" != "lo" ]; then
        sudo ip link set "$iface" down 2>/dev/null && log "Disconnected: $iface" || log "Failed: $iface"
    fi
done

# Alternative: Kill network manager
# sudo systemctl stop NetworkManager 2>/dev/null || true
# sudo systemctl stop networking 2>/dev/null || true

# 2. KILL SUSPICIOUS PROCESSES
log "Step 2: Terminating suspicious processes..."
SUSPICIOUS_PROCS=("nc" "ncat" "socat" "netcat" "cryptominer" "xmrig")

for proc in "${SUSPICIOUS_PROCS[@]}"; do
    if pgrep -x "$proc" &>/dev/null; then
        sudo pkill -9 "$proc"
        log "Killed: $proc"
    fi
done

# 3. CLEAR SENSITIVE HISTORY
log "Step 3: Clearing sensitive data..."

# Bash history
cat /dev/null > ~/.bash_history
history -c
unset HISTFILE
log "Cleared bash history"

# Browser history (if accessible)
rm -rf ~/.mozilla/firefox/*/sessionstore* 2>/dev/null || true
rm -rf ~/.config/google-chrome/*/History 2>/dev/null || true
log "Attempted browser history clear"

# Temporary files
rm -rf /tmp/* 2>/dev/null || true
rm -rf ~/.cache/* 2>/dev/null || true
log "Cleared temporary files"

# 4. DISMOUNT ENCRYPTED CONTAINERS
log "Step 4: Dismounting encrypted volumes..."
if command -v veracrypt &>/dev/null; then
    veracrypt -d 2>/dev/null && log "VeraCrypt dismounted" || log "No VeraCrypt volumes"
fi

# 5. CREATE FORENSIC SNAPSHOT
log "Step 5: Creating system snapshot..."
SNAPSHOT_DIR="/tmp/forensic_snapshot_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SNAPSHOT_DIR"

# Process list
ps aux > "$SNAPSHOT_DIR/processes.txt"

# Network connections
netstat -anp > "$SNAPSHOT_DIR/network.txt" 2>/dev/null || ss -anp > "$SNAPSHOT_DIR/network.txt"

# Open files
lsof > "$SNAPSHOT_DIR/open_files.txt" 2>/dev/null || true

# System logs (last 100 lines)
sudo tail -100 /var/log/syslog > "$SNAPSHOT_DIR/syslog.txt" 2>/dev/null || true
sudo tail -100 /var/log/auth.log > "$SNAPSHOT_DIR/auth.txt" 2>/dev/null || true

log "Snapshot created: $SNAPSHOT_DIR"

# 6. ENABLE MAXIMUM LOGGING
log "Step 6: Enabling maximum logging..."
sudo auditctl -e 2 2>/dev/null && log "Audit logging immutable" || log "Could not lock audit"

# 7. CLEAR RAM CACHE
log "Step 7: Clearing RAM cache..."
sudo sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null && log "RAM cache cleared" || log "Could not clear RAM"

# 8. LOCK USER SESSIONS
log "Step 8: Locking sessions..."
# Lock screen (X11)
if [ -n "$DISPLAY" ]; then
    xdg-screensaver lock 2>/dev/null || true
    gnome-screensaver-command -l 2>/dev/null || true
fi

# 9. CREATE INCIDENT REPORT
log "Step 9: Creating incident report..."
INCIDENT_REPORT="$SNAPSHOT_DIR/INCIDENT_REPORT.txt"
cat > "$INCIDENT_REPORT" <<EOF
OPSEC SECURITY INCIDENT REPORT
==============================

Timestamp: $(date)
Hostname: $(hostname)
User: $(whoami)

INCIDENT DETAILS:
- Panic mode triggered manually
- Network disconnected
- Suspicious processes terminated
- History cleared
- Forensic snapshot created

NEXT STEPS:
1. Do NOT reconnect to network
2. Review logs in: $SNAPSHOT_DIR
3. Run: sudo rkhunter --check
4. Run: sudo aide --check
5. Consider full system analysis
6. Contact security team if needed
7. Rotate all credentials

FORENSIC DATA:
- Process list: processes.txt
- Network connections: network.txt
- Open files: open_files.txt
- System logs: syslog.txt
- Authentication logs: auth.txt

CRITICAL ACTIONS:
☐ Analyze snapshot data
☐ Check for unauthorized access
☐ Review system integrity (AIDE)
☐ Scan for rootkits (rkhunter)
☐ Rotate all credentials
☐ Review and patch vulnerabilities
☐ Document incident
☐ Update security procedures

EOF

log "Incident report created: $INCIDENT_REPORT"

# SUMMARY
echo ""
echo -e "${RED}========================================"
echo "  PANIC MODE COMPLETE"
echo "========================================${NC}"
echo ""
echo "✓ Network disconnected"
echo "✓ Suspicious processes killed"
echo "✓ Sensitive data cleared"
echo "✓ Forensic snapshot created"
echo "✓ Maximum logging enabled"
echo ""
echo "Incident Report: $INCIDENT_REPORT"
echo "Panic Log: $LOG_FILE"
echo "Snapshot Directory: $SNAPSHOT_DIR"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  1. Do NOT reconnect to network yet"
echo "  2. Review forensic data"
echo "  3. Run integrity checks"
echo "  4. Investigate incident"
echo "  5. Rotate all credentials"
echo ""
echo -e "${RED}System is now in LOCKDOWN mode${NC}"
echo ""

# Optional: Power off
echo ""
read -p "Power off system now? (y/N): " poweroff_confirm
if [[ "$poweroff_confirm" =~ ^[Yy]$ ]]; then
    log "System shutdown initiated"
    sudo poweroff
fi

