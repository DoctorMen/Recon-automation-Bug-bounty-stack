#!/bin/bash
# OPSEC VPN Connection Verifier
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Ensures VPN is active before running scans

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
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

log "=== OPSEC VPN Status Check ==="

# Get real IP
log "Checking IP address..."
REAL_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "UNKNOWN")
log "Current IP: $REAL_IP"

# Check if IP is private (not routed through VPN)
if [[ "$REAL_IP" =~ ^10\. ]] || \
   [[ "$REAL_IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
   [[ "$REAL_IP" =~ ^192\.168\. ]] || \
   [[ "$REAL_IP" == "UNKNOWN" ]]; then
    error "No public IP detected - VPN may not be active"
    exit 1
fi

# Check DNS for leaks
log "Checking DNS configuration..."
DNS_SERVERS=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | head -n 3 | tr '\n' ' ')
log "DNS Servers: $DNS_SERVERS"

# Check for common VPN indicators
VPN_DETECTED=false

# Check network interfaces for VPN
if ip link show 2>/dev/null | grep -E "(tun|tap|wg|vpn)" &>/dev/null; then
    success "VPN interface detected"
    VPN_DETECTED=true
fi

# Check for common VPN processes
if pgrep -x "openvpn|nordvpn|mullvad|protonvpn|wireguard" &>/dev/null; then
    success "VPN process detected"
    VPN_DETECTED=true
fi

# Check routing table
if ip route show 2>/dev/null | grep -E "(tun|tap)" &>/dev/null; then
    success "VPN routing detected"
    VPN_DETECTED=true
fi

# Get geolocation info
log "Checking geolocation..."
GEO_INFO=$(curl -s "https://ipapi.co/$REAL_IP/json/" 2>/dev/null || echo "{}")

if [ "$GEO_INFO" != "{}" ]; then
    COUNTRY=$(echo "$GEO_INFO" | grep -o '"country_name":"[^"]*"' | cut -d'"' -f4)
    CITY=$(echo "$GEO_INFO" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
    ORG=$(echo "$GEO_INFO" | grep -o '"org":"[^"]*"' | cut -d'"' -f4)
    
    log "Location: $CITY, $COUNTRY"
    log "ISP: $ORG"
    
    # Check if ISP is a known VPN provider
    if echo "$ORG" | grep -iE "(vpn|proxy|mullvad|nordvpn|proton|expressvpn|private|datacamp)" &>/dev/null; then
        success "VPN provider detected in ISP info"
        VPN_DETECTED=true
    fi
fi

# DNS leak test
log "Checking for DNS leaks..."
DNS_LEAK=$(curl -s "https://www.dnsleaktest.com/results.json" 2>/dev/null || echo "[]")

if [ "$DNS_LEAK" != "[]" ]; then
    DNS_ISP=$(echo "$DNS_LEAK" | grep -o '"isp":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$DNS_ISP" ]; then
        log "DNS ISP: $DNS_ISP"
        
        # Check if DNS ISP matches VPN
        if echo "$DNS_ISP" | grep -iE "(vpn|proxy|mullvad|nordvpn|proton)" &>/dev/null; then
            success "DNS routing through VPN"
        else
            warn "Possible DNS leak detected! DNS ISP: $DNS_ISP"
        fi
    fi
fi

# WebRTC leak check
log "Checking for WebRTC leaks..."
# Note: This requires a browser, so we just warn
warn "WebRTC leak check requires manual verification"
warn "Visit: https://browserleaks.com/webrtc"

# Final verdict
echo ""
echo "========================================"
if [ "$VPN_DETECTED" = true ]; then
    success "VPN CONNECTION DETECTED ✓"
    success "Safe to proceed with reconnaissance"
    echo ""
    echo "Connection Details:"
    echo "  IP: $REAL_IP"
    echo "  Location: ${CITY:-Unknown}, ${COUNTRY:-Unknown}"
    echo "  ISP: ${ORG:-Unknown}"
    echo ""
    echo "Additional Checks:"
    echo "  - Verify no DNS leaks: https://dnsleaktest.com"
    echo "  - Verify no WebRTC leaks: https://browserleaks.com/webrtc"
    echo "  - Verify no IPv6 leaks: https://test-ipv6.com"
    exit 0
else
    error "NO VPN DETECTED ✗"
    error "DO NOT proceed with reconnaissance!"
    echo ""
    echo "Action Required:"
    echo "  1. Connect to your VPN"
    echo "  2. Verify connection: nordvpn status / mullvad status"
    echo "  3. Run this check again"
    echo ""
    echo "Recommended VPN Providers:"
    echo "  - Mullvad VPN (no logs, anonymous)"
    echo "  - ProtonVPN (secure, private)"
    echo "  - NordVPN (fast, reliable)"
    exit 1
fi
echo "========================================"

