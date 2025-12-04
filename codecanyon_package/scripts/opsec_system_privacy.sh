#!/bin/bash
# OPSEC Privacy Protection Script
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Enhances system privacy and anti-tracking

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

echo "========================================"
echo "  OPSEC PRIVACY ENHANCEMENT"
echo "========================================"
echo ""

# 1. DISABLE TELEMETRY
log "Step 1: Disabling telemetry..."

# Ubuntu telemetry
if command -v ubuntu-report &>/dev/null; then
    ubuntu-report -f send no 2>/dev/null || true
    success "Ubuntu telemetry disabled"
fi

# Disable popularity contest
if dpkg -l | grep -q popularity-contest; then
    sudo apt-get purge -y popularity-contest 2>/dev/null || true
    success "Popularity contest removed"
fi

# 2. FIREFOX PRIVACY
log "Step 2: Configuring Firefox privacy..."
for profile in ~/.mozilla/firefox/*.default* ~/.mozilla/firefox/*.dev-edition-default*; do
    if [ -d "$profile" ]; then
        cat > "$profile/user.js" <<EOF
// OPSEC Privacy Configuration
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("geo.enabled", false);
user_pref("media.peerconnection.enabled", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("dom.security.https_only_mode", true);
user_pref("webgl.disabled", true);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
EOF
        success "Firefox privacy configured: $(basename "$profile")"
    fi
done

# 3. CHROME/CHROMIUM PRIVACY
log "Step 3: Creating Chrome privacy launcher..."
cat > ~/start-chrome-private.sh <<'EOF'
#!/bin/bash
google-chrome \
  --disable-background-networking \
  --disable-default-apps \
  --disable-sync \
  --disable-translate \
  --disable-webrtc-multiple-routes \
  --disable-webrtc-hw-decoding \
  --enforce-webrtc-ip-permission-check \
  --no-pings \
  --disable-remote-fonts \
  --incognito
EOF
chmod +x ~/start-chrome-private.sh
success "Chrome private launcher created: ~/start-chrome-private.sh"

# 4. METADATA REMOVAL
log "Step 4: Installing metadata removal tools..."
sudo apt-get install -y mat2 exiftool 2>/dev/null && success "Metadata tools installed" || warn "Failed to install tools"

# Create metadata cleaning script
cat > ~/clean-metadata.sh <<'EOF'
#!/bin/bash
# Clean metadata from files
if [ $# -eq 0 ]; then
    echo "Usage: $0 <file1> [file2] ..."
    exit 1
fi

for file in "$@"; do
    if [ -f "$file" ]; then
        # Backup
        cp "$file" "${file}.backup"
        
        # Clean with mat2
        mat2 --inplace "$file" 2>/dev/null && echo "✓ Cleaned: $file" || \
        # Fallback to exiftool
        exiftool -all= "$file" 2>/dev/null && echo "✓ Cleaned: $file"
    fi
done
EOF
chmod +x ~/clean-metadata.sh
success "Metadata cleaner created: ~/clean-metadata.sh"

# 5. DNS PRIVACY
log "Step 5: Configuring private DNS..."
sudo chattr -i /etc/resolv.conf 2>/dev/null || true
sudo tee /etc/resolv.conf >/dev/null <<EOF
# OPSEC Private DNS Configuration
# Using Quad9 (privacy-focused)
nameserver 9.9.9.9
nameserver 149.112.112.112
options edns0 trust-ad
EOF
sudo chattr +i /etc/resolv.conf 2>/dev/null || true
success "Private DNS configured (Quad9)"

# 6. DISABLE HISTORY
log "Step 6: Configuring history settings..."

# Limit history size
if ! grep -q "HISTSIZE=1000" ~/.bashrc; then
    cat >> ~/.bashrc <<EOF

# OPSEC History Limits
export HISTSIZE=1000
export HISTFILESIZE=1000
export HISTCONTROL=ignoredups:erasedups
EOF
    success "History limits configured"
fi

# 7. TOR INSTALLATION
log "Step 7: Installing Tor..."
if ! command -v tor &>/dev/null; then
    sudo apt-get install -y tor tor-geoipdb 2>/dev/null && success "Tor installed" || warn "Tor installation failed"
else
    success "Tor already installed"
fi

# Configure Tor
if [ -d /etc/tor ]; then
    sudo tee /etc/tor/torrc.d/opsec.conf >/dev/null <<EOF
# OPSEC Tor Configuration
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
EOF
    sudo systemctl enable tor 2>/dev/null || true
    sudo systemctl restart tor 2>/dev/null || true
    success "Tor configured"
fi

# 8. PROXYCHAINS
log "Step 8: Configuring ProxyChains..."
if command -v proxychains4 &>/dev/null || sudo apt-get install -y proxychains4 2>/dev/null; then
    sudo tee /etc/proxychains4.conf >/dev/null <<EOF
# OPSEC ProxyChains Configuration
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
EOF
    success "ProxyChains configured"
fi

# 9. SECURE DELETE
log "Step 9: Installing secure delete tools..."
sudo apt-get install -y secure-delete 2>/dev/null && success "Secure delete installed" || warn "Installation failed"

# Create secure delete wrapper
cat > ~/secure-delete.sh <<'EOF'
#!/bin/bash
# Secure file deletion
if [ $# -eq 0 ]; then
    echo "Usage: $0 <file1> [file2] ..."
    echo "WARNING: This permanently deletes files!"
    exit 1
fi

for file in "$@"; do
    if [ -f "$file" ]; then
        srm -vz "$file" && echo "✓ Securely deleted: $file"
    elif [ -d "$file" ]; then
        srm -vfz -r "$file" && echo "✓ Securely deleted directory: $file"
    fi
done
EOF
chmod +x ~/secure-delete.sh
success "Secure delete wrapper created: ~/secure-delete.sh"

# 10. PRIVACY CHECK SCRIPT
log "Step 10: Creating privacy check script..."
cat > ~/check-privacy.sh <<'EOF'
#!/bin/bash
echo "=== PRIVACY STATUS CHECK ==="
echo ""

# VPN
if ip link show | grep -qE "(tun|tap|wg)"; then
    echo "✓ VPN: Active"
else
    echo "✗ VPN: Inactive"
fi

# Tor
if pgrep -x tor >/dev/null; then
    echo "✓ Tor: Running"
else
    echo "✗ Tor: Not running"
fi

# DNS
echo "DNS Servers:"
cat /etc/resolv.conf | grep nameserver | sed 's/^/  /'

# Public IP
echo ""
echo "Public IP: $(curl -s ifconfig.me || echo 'Unknown')"

# WebRTC check
echo ""
echo "WebRTC Leak Check:"
echo "  Visit: https://browserleaks.com/webrtc"

echo ""
echo "=== END CHECK ==="
EOF
chmod +x ~/check-privacy.sh
success "Privacy checker created: ~/check-privacy.sh"

# SUMMARY
echo ""
echo "========================================"
echo "  PRIVACY ENHANCEMENT COMPLETE"
echo "========================================"
echo ""
echo "✓ Telemetry disabled"
echo "✓ Firefox privacy configured"
echo "✓ Chrome private launcher created"
echo "✓ Metadata removal tools installed"
echo "✓ Private DNS configured"
echo "✓ History limits set"
echo "✓ Tor installed and configured"
echo "✓ ProxyChains configured"
echo "✓ Secure delete tools installed"
echo "✓ Privacy check script created"
echo ""
echo "Utility Scripts Created:"
echo "  • ~/start-chrome-private.sh - Launch Chrome privately"
echo "  • ~/clean-metadata.sh - Remove file metadata"
echo "  • ~/secure-delete.sh - Securely delete files"
echo "  • ~/check-privacy.sh - Check privacy status"
echo ""
echo "Usage Examples:"
echo "  ./check-privacy.sh"
echo "  ./clean-metadata.sh photo.jpg document.pdf"
echo "  proxychains4 firefox"
echo "  ./secure-delete.sh sensitive_file.txt"
echo ""
echo "========================================"

