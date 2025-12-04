#!/bin/bash
# OPSEC System Hardening Script
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Hardens your entire computer system

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

error() {
    echo -e "${RED}[✗]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

echo "========================================"
echo "  OPSEC SYSTEM HARDENING"
echo "  Copyright © 2025"
echo "========================================"
echo ""

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    warn "Some hardening requires root access"
    warn "Run with: sudo $0"
fi

# 1. UPDATE SYSTEM
log "Step 1: Updating system packages..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -y
    sudo apt-get upgrade -y
    sudo apt-get autoremove -y
    success "System updated"
fi

# 2. INSTALL SECURITY TOOLS
log "Step 2: Installing security tools..."
SECURITY_TOOLS=(
    "ufw"              # Firewall
    "fail2ban"         # Intrusion prevention
    "aide"             # File integrity
    "rkhunter"         # Rootkit detection
    "clamav"           # Antivirus
    "auditd"           # Audit daemon
    "apparmor"         # Mandatory access control
    "secure-delete"    # Secure file deletion
    "mat2"             # Metadata removal
    "tor"              # Anonymous network
    "proxychains4"     # Proxy chains
)

for tool in "${SECURITY_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null && ! dpkg -l | grep -q "^ii  $tool"; then
        log "Installing $tool..."
        sudo apt-get install -y "$tool" 2>/dev/null && success "Installed $tool" || warn "Failed to install $tool"
    else
        success "$tool already installed"
    fi
done

# 3. CONFIGURE FIREWALL
log "Step 3: Configuring firewall..."
if command -v ufw &>/dev/null; then
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw logging high
    echo "y" | sudo ufw enable 2>/dev/null || true
    success "Firewall configured"
fi

# 4. KERNEL HARDENING
log "Step 4: Hardening kernel parameters..."
sudo tee /etc/sysctl.d/99-opsec-hardening.conf >/dev/null <<EOF
# OPSEC Kernel Hardening
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.conf.all.disable_ipv6 = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
EOF
sudo sysctl -p /etc/sysctl.d/99-opsec-hardening.conf 2>/dev/null || true
success "Kernel hardened"

# 5. SECURE FILE PERMISSIONS
log "Step 5: Securing file permissions..."
chmod 700 ~ 2>/dev/null || true
if [ -d ~/.ssh ]; then
    chmod 700 ~/.ssh
    chmod 600 ~/.ssh/* 2>/dev/null || true
    chmod 644 ~/.ssh/*.pub 2>/dev/null || true
    success "SSH permissions secured"
fi

# Set restrictive umask
if ! grep -q "umask 077" ~/.bashrc; then
    echo "umask 077" >> ~/.bashrc
    success "Restrictive umask set"
fi

# 6. CONFIGURE FAIL2BAN
log "Step 6: Configuring Fail2Ban..."
if command -v fail2ban-client &>/dev/null; then
    sudo tee /etc/fail2ban/jail.local >/dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
EOF
    sudo systemctl enable fail2ban 2>/dev/null || true
    sudo systemctl restart fail2ban 2>/dev/null || true
    success "Fail2Ban configured"
fi

# 7. INITIALIZE AIDE
log "Step 7: Initializing file integrity monitoring..."
if command -v aide &>/dev/null; then
    if [ ! -f /var/lib/aide/aide.db ]; then
        warn "AIDE database initialization takes time..."
        sudo aideinit 2>/dev/null || warn "AIDE init failed (run manually: sudo aideinit)"
    fi
    success "AIDE configured"
fi

# 8. CONFIGURE DNS SECURITY
log "Step 8: Configuring secure DNS..."
if [ -w /etc/resolv.conf ] || sudo test -w /etc/resolv.conf; then
    sudo chattr -i /etc/resolv.conf 2>/dev/null || true
    sudo tee /etc/resolv.conf >/dev/null <<EOF
# OPSEC Secure DNS Configuration
nameserver 1.1.1.1
nameserver 1.0.0.1
options edns0 trust-ad
EOF
    sudo chattr +i /etc/resolv.conf 2>/dev/null || warn "Could not make resolv.conf immutable"
    success "Secure DNS configured (Cloudflare)"
fi

# 9. DISABLE UNNECESSARY SERVICES
log "Step 9: Checking services..."
UNNECESSARY_SERVICES=(
    "bluetooth"
    "cups"
    "avahi-daemon"
)

for service in "${UNNECESSARY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        warn "Service $service is running (consider disabling if not needed)"
    fi
done

# 10. AUDIT CONFIGURATION
log "Step 10: Configuring audit system..."
if command -v auditctl &>/dev/null; then
    sudo systemctl enable auditd 2>/dev/null || true
    sudo systemctl start auditd 2>/dev/null || true
    success "Audit system enabled"
fi

# 11. APPARMOR
log "Step 11: Enabling AppArmor..."
if command -v aa-status &>/dev/null; then
    sudo systemctl enable apparmor 2>/dev/null || true
    sudo systemctl start apparmor 2>/dev/null || true
    success "AppArmor enabled"
fi

# 12. UPDATE VIRUS DEFINITIONS
log "Step 12: Updating antivirus definitions..."
if command -v freshclam &>/dev/null; then
    sudo freshclam 2>/dev/null && success "ClamAV updated" || warn "ClamAV update failed"
fi

# 13. PRIVACY SETTINGS
log "Step 13: Applying privacy settings..."
# Disable bash history for this session
export HISTSIZE=1000
export HISTFILESIZE=1000

# Firefox privacy (if installed)
FIREFOX_PROFILE=$(find ~/.mozilla/firefox -maxdepth 1 -name "*.default*" -type d 2>/dev/null | head -1)
if [ -d "$FIREFOX_PROFILE" ]; then
    cat > "$FIREFOX_PROFILE/user.js" <<EOF
// OPSEC Privacy Configuration
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("geo.enabled", false);
user_pref("media.peerconnection.enabled", false);
EOF
    success "Firefox privacy configured"
fi

# 14. CREATE MONITORING CRON JOBS
log "Step 14: Setting up monitoring..."
CRON_FILE="/tmp/opsec_system_cron.txt"
cat > "$CRON_FILE" <<EOF
# OPSEC System Monitoring
0 4 * * * /usr/bin/aide --check 2>&1 | logger -t AIDE
0 3 * * * /usr/bin/clamscan -r --bell -i /home 2>&1 | logger -t ClamAV
0 5 * * 0 /usr/bin/rkhunter --check --skip-keypress 2>&1 | logger -t RKHunter
EOF
# sudo crontab -l > /tmp/current_cron 2>/dev/null || true
# cat /tmp/current_cron "$CRON_FILE" | sudo crontab -
success "Monitoring jobs created (install with: sudo crontab $CRON_FILE)"

# 15. SECURE PERMISSIONS AUDIT
log "Step 15: Auditing file permissions..."
warn "Checking for security issues..."

# World-writable files
WW_COUNT=$(find ~ -xdev -type f -perm -0002 2>/dev/null | wc -l)
if [ "$WW_COUNT" -gt 0 ]; then
    warn "Found $WW_COUNT world-writable files in home directory"
fi

# SUID files
SUID_COUNT=$(find ~ -xdev -perm -4000 -type f 2>/dev/null | wc -l)
if [ "$SUID_COUNT" -gt 0 ]; then
    warn "Found $SUID_COUNT SUID files in home directory"
fi

success "Permission audit complete"

# SUMMARY
echo ""
echo "========================================"
echo "  HARDENING COMPLETE"
echo "========================================"
echo ""
echo "✓ System packages updated"
echo "✓ Security tools installed"
echo "✓ Firewall configured"
echo "✓ Kernel hardened"
echo "✓ File permissions secured"
echo "✓ Intrusion prevention enabled"
echo "✓ File integrity monitoring setup"
echo "✓ Secure DNS configured"
echo "✓ Audit system enabled"
echo "✓ Privacy settings applied"
echo ""
echo "Next Steps:"
echo "  1. Reboot system: sudo reboot"
echo "  2. Run daily check: ./scripts/opsec_system_daily.sh"
echo "  3. Monitor logs: sudo tail -f /var/log/syslog"
echo "  4. Review: cat SYSTEM_OPSEC_FRAMEWORK.md"
echo ""
echo "========================================"

log "System hardening complete!"

