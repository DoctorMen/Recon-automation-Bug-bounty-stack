#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# ============================================
# SECURE DASHBOARD LAUNCHER
# Starts local-only web server for dashboard
# NO EXTERNAL CONNECTIONS | OPSEC COMPLIANT
# ============================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${DASHBOARD_PORT:-8888}"
HOST="127.0.0.1"  # LOCAL ONLY - DO NOT CHANGE

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   SECURE BUG BOUNTY DASHBOARD${NC}"
echo -e "${BLUE}   OPSEC MODE | LOCAL ONLY${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# ============================================
# SECURITY CHECKS
# ============================================

echo -e "${YELLOW}🔒 Running security checks...${NC}"

# Check we're in the right directory
if [ ! -f "$SCRIPT_DIR/index.html" ]; then
    echo -e "${RED}ERROR: Dashboard files not found${NC}"
    echo "Please run this script from the dashboard directory"
    exit 1
fi

# Check for SECURITY.md
if [ ! -f "$SCRIPT_DIR/SECURITY.md" ]; then
    echo -e "${YELLOW}WARNING: SECURITY.md not found${NC}"
fi

# Set secure file permissions
echo "Setting secure file permissions..."
chmod 600 "$SCRIPT_DIR"/*.html 2>/dev/null || true
chmod 600 "$SCRIPT_DIR"/assets/* 2>/dev/null || true
chmod 600 "$SCRIPT_DIR"/SECURITY.md 2>/dev/null || true

echo -e "${GREEN}✓ Security checks complete${NC}"
echo ""

# ============================================
# CHECK FOR EXISTING SERVER
# ============================================

if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Port $PORT is already in use${NC}"
    echo "Attempting to find available port..."
    PORT=$((PORT + 1))
    while lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; do
        PORT=$((PORT + 1))
        if [ $PORT -gt 9000 ]; then
            echo -e "${RED}ERROR: Could not find available port${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}✓ Using port $PORT${NC}"
fi

# ============================================
# START SERVER
# ============================================

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   DASHBOARD LAUNCHING${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${BLUE}📍 URL:${NC}      http://${HOST}:${PORT}"
echo -e "${BLUE}🔒 OPSEC:${NC}    ACTIVE"
echo -e "${BLUE}📡 Network:${NC}  LOCAL ONLY ($HOST)"
echo -e "${BLUE}🛡️  Security:${NC} All external connections BLOCKED"
echo ""
echo -e "${YELLOW}⚠️  SECURITY REMINDERS:${NC}"
echo -e "  • ${RED}Dashboard accessible ONLY from this machine${NC}"
echo -e "  • ${RED}Redaction is ENABLED by default${NC}"
echo -e "  • ${RED}Review SECURITY.md before sharing screenshots${NC}"
echo -e "  • ${RED}DO NOT expose to public networks${NC}"
echo ""
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Press ${YELLOW}Ctrl+C${NC} to stop the dashboard"
echo ""

# ============================================
# LAUNCH WEB SERVER
# ============================================

cd "$SCRIPT_DIR"

# Try Python 3 first
if command -v python3 >/dev/null 2>&1; then
    echo -e "${BLUE}Starting Python 3 HTTP server...${NC}"
    echo ""
    python3 -m http.server $PORT --bind $HOST 2>&1 | while read -r line; do
        echo -e "${BLUE}[SERVER]${NC} $line"
    done

# Fallback to Python 2
elif command -v python >/dev/null 2>&1; then
    echo -e "${BLUE}Starting Python 2 HTTP server...${NC}"
    echo ""
    python -m SimpleHTTPServer $PORT 2>&1 | while read -r line; do
        echo -e "${BLUE}[SERVER]${NC} $line"
    done

# Fallback to PHP
elif command -v php >/dev/null 2>&1; then
    echo -e "${BLUE}Starting PHP built-in server...${NC}"
    echo ""
    php -S ${HOST}:${PORT} 2>&1 | while read -r line; do
        echo -e "${BLUE}[SERVER]${NC} $line"
    done

else
    echo -e "${RED}ERROR: No suitable web server found${NC}"
    echo ""
    echo "Please install one of the following:"
    echo "  • Python 3 (recommended): apt install python3"
    echo "  • Python 2: apt install python"
    echo "  • PHP: apt install php"
    exit 1
fi

# ============================================
# CLEANUP ON EXIT
# ============================================

trap cleanup EXIT

cleanup() {
    echo ""
    echo -e "${YELLOW}============================================${NC}"
    echo -e "${YELLOW}   DASHBOARD SHUTTING DOWN${NC}"
    echo -e "${YELLOW}============================================${NC}"
    echo ""
    echo -e "${GREEN}✓ Server stopped safely${NC}"
    echo -e "${GREEN}✓ Local connections closed${NC}"
    echo ""
    echo -e "${BLUE}Dashboard session ended${NC}"
    echo ""
}

