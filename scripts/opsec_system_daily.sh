#!/bin/bash
# OPSEC Daily System Security Check
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Runs comprehensive daily security audit

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/../.opsec/system_daily_$(date +%Y%m%d).log"

mkdir -p "$SCRIPT_DIR/../.opsec"

log() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"
}

CHECKS_PASSED=0
CHECKS_FAILED=0

echo "========================================"
echo "  DAILY SYSTEM SECURITY CHECK"
echo "  Date: $(date)"
echo "========================================"
echo ""

# 1. CHECK FIREWALL
log "Check 1: Firewall Status"
if command -v ufw &>/dev/null; then
    if sudo ufw status | grep -q "Status: active"; then
        success "Firewall is active"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        error "Firewall is NOT active!"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    warn "UFW not installed"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# 2. CHECK FAILED LOGIN ATTEMPTS
log "Check 2: Failed Login Attempts"
if [ -f /var/log/auth.log ]; then
    FAILED_LOGINS=$(sudo grep "Failed password" /var/log/auth.log | tail -20 | wc -l)
    if [ "$FAILED_LOGINS" -gt 10 ]; then
        error "High number of failed logins: $FAILED_LOGINS"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    else
        success "Failed logins normal: $FAILED_LOGINS"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    fi
else
    warn "Auth log not found"
fi
echo ""

# 3. CHECK LISTENING PORTS
log "Check 3: Listening Ports"
LISTENING_PORTS=$(sudo netstat -tuln 2>/dev/null | grep LISTEN | wc -l || sudo ss -tuln | grep LISTEN | wc -l)
log "Listening ports: $LISTENING_PORTS"
if [ "$LISTENING_PORTS" -lt 20 ]; then
    success "Port count normal"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    warn "Many listening ports: $LISTENING_PORTS"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# 4. CHECK DISK USAGE
log "Check 4: Disk Usage"
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -lt 80 ]; then
    success "Disk usage: ${DISK_USAGE}%"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    warn "High disk usage: ${DISK_USAGE}%"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# 5. CHECK FOR ROOTKITS
log "Check 5: Rootkit Scan"
if command -v rkhunter &>/dev/null; then
    sudo rkhunter --update --quiet
    ROOTKIT_CHECK=$(sudo rkhunter --check --skip-keypress --report-warnings-only 2>&1 | grep -c "Warning" || echo "0")
    if [ "$ROOTKIT_CHECK" -eq 0 ]; then
        success "No rootkits detected"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        error "Rootkit warnings: $ROOTKIT_CHECK"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    warn "rkhunter not installed"
fi
echo ""

# 6. CHECK SUSPICIOUS PROCESSES
log "Check 6: Process Check"
# Look for suspicious process names
SUSPICIOUS=("nc" "ncat" "socat" "cryptominer")
FOUND=0
for proc in "${SUSPICIOUS[@]}"; do
    if pgrep -x "$proc" &>/dev/null; then
        error "Suspicious process found: $proc"
        FOUND=$((FOUND + 1))
    fi
done

if [ "$FOUND" -eq 0 ]; then
    success "No suspicious processes"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    error "Found $FOUND suspicious process(es)"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# 7. CHECK SYSTEM LOAD
log "Check 7: System Load"
LOAD=$(uptime | awk '{print $(NF-2)}' | sed 's/,//')
CPU_COUNT=$(nproc)
LOAD_PER_CPU=$(echo "$LOAD / $CPU_COUNT" | bc -l 2>/dev/null || echo "1")
if (( $(echo "$LOAD_PER_CPU < 2" | bc -l) )); then
    success "System load normal: $LOAD"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    warn "High system load: $LOAD"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# 8. CHECK ANTIVIRUS
log "Check 8: Antivirus Status"
if command -v freshclam &>/dev/null; then
    CLAM_DATE=$(stat -c %y /var/lib/clamav/daily.cvd 2>/dev/null | cut -d' ' -f1)
    TODAY=$(date +%Y-%m-%d)
    if [ "$CLAM_DATE" == "$TODAY" ]; then
        success "Antivirus definitions up to date"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        warn "Antivirus definitions outdated: $CLAM_DATE"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    warn "ClamAV not installed"
fi
echo ""

# 9. CHECK VPN STATUS (from bug bounty OPSEC)
log "Check 9: VPN Status"
if [ -f "$SCRIPT_DIR/opsec_check_vpn.sh" ]; then
    if bash "$SCRIPT_DIR/opsec_check_vpn.sh" &>/dev/null; then
        success "VPN is active"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        warn "VPN is not active"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
fi
echo ""

# 10. CHECK UPDATES AVAILABLE
log "Check 10: System Updates"
if command -v apt-get &>/dev/null; then
    UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo "0")
    if [ "$UPDATES" -eq 0 ]; then
        success "System up to date"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        warn "$UPDATES updates available"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
fi
echo ""

# SUMMARY
echo "========================================"
echo "  DAILY CHECK SUMMARY"
echo "========================================"
echo ""
echo "  Checks Passed: ${GREEN}$CHECKS_PASSED${NC}"
echo "  Checks Failed: ${RED}$CHECKS_FAILED${NC}"
echo ""

TOTAL=$((CHECKS_PASSED + CHECKS_FAILED))
if [ $TOTAL -gt 0 ]; then
    SCORE=$((CHECKS_PASSED * 100 / TOTAL))
else
    SCORE=0
fi

if [ $SCORE -ge 90 ]; then
    echo -e "${GREEN}  EXCELLENT${NC} - System security is optimal ✓"
elif [ $SCORE -ge 70 ]; then
    echo -e "${YELLOW}  GOOD${NC} - Minor issues detected"
elif [ $SCORE -ge 50 ]; then
    echo -e "${YELLOW}  FAIR${NC} - Several issues need attention"
else
    echo -e "${RED}  POOR${NC} - Critical security issues detected!"
fi

echo ""
echo "========================================"
echo ""
echo "Log saved to: $LOG_FILE"
echo ""

exit $CHECKS_FAILED

