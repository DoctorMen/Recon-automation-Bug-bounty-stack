#!/bin/bash
# OPSEC System Real-Time Monitor
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Real-time system monitoring dashboard

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

while true; do
    clear
    echo "========================================"
    echo "  OPSEC SYSTEM MONITOR"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================"
    echo ""
    
    # SYSTEM INFO
    echo -e "${BLUE}[SYSTEM]${NC}"
    echo "  Uptime: $(uptime -p 2>/dev/null || echo 'N/A')"
    echo "  Load: $(uptime | awk '{print $(NF-2), $(NF-1), $NF}')"
    echo "  Users: $(who | wc -l)"
    echo ""
    
    # CPU & MEMORY
    echo -e "${BLUE}[RESOURCES]${NC}"
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100}')
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')
    
    echo "  CPU: ${CPU_USAGE}%"
    echo "  Memory: ${MEM_USAGE}%"
    echo "  Disk (/): $DISK_USAGE"
    echo ""
    
    # NETWORK
    echo -e "${BLUE}[NETWORK]${NC}"
    CONNECTIONS=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || ss -an | grep ESTAB | wc -l)
    echo "  Active connections: $CONNECTIONS"
    
    # Check VPN
    if ip link show 2>/dev/null | grep -qE "(tun|tap|wg)"; then
        echo -e "  VPN: ${GREEN}ACTIVE${NC}"
    else
        echo -e "  VPN: ${RED}INACTIVE${NC}"
    fi
    echo ""
    
    # SECURITY
    echo -e "${BLUE}[SECURITY]${NC}"
    
    # Firewall
    if command -v ufw &>/dev/null && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "  Firewall: ${GREEN}ACTIVE${NC}"
    else
        echo -e "  Firewall: ${RED}INACTIVE${NC}"
    fi
    
    # Fail2Ban
    if command -v fail2ban-client &>/dev/null && sudo systemctl is-active fail2ban &>/dev/null; then
        BANNED=$(sudo fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")
        echo "  Fail2Ban: Active ($BANNED banned)"
    fi
    
    # Failed logins
    FAILED=$(sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 | wc -l || echo "0")
    if [ "$FAILED" -gt 10 ]; then
        echo -e "  Failed logins: ${RED}$FAILED${NC}"
    else
        echo "  Failed logins: $FAILED"
    fi
    echo ""
    
    # TOP PROCESSES
    echo -e "${BLUE}[TOP PROCESSES]${NC}"
    ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "  %s: %.1f%% CPU\n", $11, $3}'
    echo ""
    
    # RECENT LOGS
    echo -e "${BLUE}[RECENT ALERTS]${NC}"
    sudo tail -3 /var/log/syslog 2>/dev/null | sed 's/^/  /' || echo "  No logs available"
    echo ""
    
    echo "========================================"
    echo "Press Ctrl+C to exit | Refreshing in 5s"
    echo "========================================"
    
    sleep 5
done

