#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# ============================================
# MASTER SYSTEM DASHBOARD LAUNCHER
# Unified command center for ALL repositories
# ============================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${PURPLE}============================================${NC}"
echo -e "${PURPLE}   🎯 MASTER BUG BOUNTY COMMAND CENTER${NC}"
echo -e "${PURPLE}   Unified Dashboard for All Repositories${NC}"
echo -e "${PURPLE}============================================${NC}"
echo ""

# ============================================
# DISCOVER REPOSITORIES
# ============================================

echo -e "${CYAN}📁 Discovering repositories...${NC}"
echo ""

REPOS=()
REPO_PATHS=()

# Check for Recon-automation-Bug-bounty-stack
if [ -d "$HOME/Recon-automation-Bug-bounty-stack" ]; then
    REPOS+=("Recon-automation-Bug-bounty-stack")
    REPO_PATHS+=("$HOME/Recon-automation-Bug-bounty-stack")
    echo -e "${GREEN}✓${NC} Found: Recon-automation-Bug-bounty-stack"
fi

# Check for recon-stack
if [ -d "$HOME/recon-stack" ]; then
    REPOS+=("recon-stack")
    REPO_PATHS+=("$HOME/recon-stack")
    echo -e "${GREEN}✓${NC} Found: recon-stack"
fi

echo ""
echo -e "${GREEN}Found ${#REPOS[@]} repository(ies)${NC}"
echo ""

# ============================================
# MENU
# ============================================

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   SELECT DASHBOARD${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

echo "1. 🎯 Recon-automation-Bug-bounty-stack (Main Stack)"
echo "   Full pipeline, multi-agent, evidence capture"
echo ""
echo "2. 🔍 recon-stack (Analysis Stack)"
echo "   Existing scan analysis, post-processing"
echo ""
echo "3. 🌐 UNIFIED VIEW (All Repositories)"
echo "   Master dashboard showing everything"
echo ""
echo "4. 🚀 LAUNCH ALL (Multiple dashboards)"
echo "   Open all dashboards simultaneously"
echo ""
echo -e "0. ${RED}Exit${NC}"
echo ""

read -p "Enter choice (0-4) [default: 3]: " choice
choice=${choice:-3}

echo ""

# ============================================
# LAUNCH SELECTED
# ============================================

case $choice in
    1)
        echo -e "${GREEN}Launching Main Stack Dashboard...${NC}"
        if [ -d "$HOME/Recon-automation-Bug-bounty-stack/dashboard" ]; then
            cd "$HOME/Recon-automation-Bug-bounty-stack/dashboard"
            ./launch_dashboard.sh
        else
            echo -e "${RED}ERROR: Dashboard not found${NC}"
            exit 1
        fi
        ;;
    
    2)
        echo -e "${GREEN}Launching Analysis Stack Dashboard...${NC}"
        if [ -d "$HOME/recon-stack/dashboard" ]; then
            cd "$HOME/recon-stack/dashboard"
            ./launch_dashboard.sh
        else
            echo -e "${RED}ERROR: Dashboard not found${NC}"
            exit 1
        fi
        ;;
    
    3)
        echo -e "${GREEN}Launching UNIFIED Dashboard...${NC}"
        echo ""
        echo -e "${CYAN}Opening master view at: http://127.0.0.1:8888${NC}"
        echo ""
        
        if [ -d "$HOME/Recon-automation-Bug-bounty-stack/dashboard" ]; then
            cd "$HOME/Recon-automation-Bug-bounty-stack/dashboard"
            
            # Create unified index if it doesn't exist
            if [ ! -f "unified_index.html" ]; then
                echo -e "${YELLOW}Creating unified dashboard...${NC}"
                # The unified dashboard will be created separately
            fi
            
            # Launch main dashboard with unified view
            python3 -m http.server 8888 --bind 127.0.0.1 &
            MAIN_PID=$!
            
            echo -e "${GREEN}✓ Master dashboard running (PID: $MAIN_PID)${NC}"
            echo ""
            echo -e "${BLUE}📍 Main Dashboard:${NC}     http://127.0.0.1:8888"
            echo -e "${BLUE}📍 Recon-stack View:${NC}   http://127.0.0.1:8889"
            echo ""
            echo -e "${YELLOW}Press Ctrl+C to stop all dashboards${NC}"
            echo ""
            
            # Wait for Ctrl+C
            trap "kill $MAIN_PID 2>/dev/null; echo ''; echo 'Dashboards stopped'; exit" INT TERM
            wait $MAIN_PID
        else
            echo -e "${RED}ERROR: Dashboard not found${NC}"
            exit 1
        fi
        ;;
    
    4)
        echo -e "${GREEN}Launching ALL Dashboards...${NC}"
        echo ""
        
        PIDS=()
        
        # Launch main stack
        if [ -d "$HOME/Recon-automation-Bug-bounty-stack/dashboard" ]; then
            cd "$HOME/Recon-automation-Bug-bounty-stack/dashboard"
            python3 -m http.server 8888 --bind 127.0.0.1 &
            PIDS+=($!)
            echo -e "${GREEN}✓${NC} Main Stack:     http://127.0.0.1:8888"
        fi
        
        # Launch recon-stack
        if [ -d "$HOME/recon-stack/dashboard" ]; then
            cd "$HOME/recon-stack/dashboard"
            python3 -m http.server 8889 --bind 127.0.0.1 &
            PIDS+=($!)
            echo -e "${GREEN}✓${NC} recon-stack:    http://127.0.0.1:8889"
        fi
        
        echo ""
        echo -e "${GREEN}${#PIDS[@]} dashboards running${NC}"
        echo ""
        echo -e "${YELLOW}Press Ctrl+C to stop all${NC}"
        echo ""
        
        # Cleanup function
        cleanup() {
            echo ""
            echo -e "${YELLOW}Stopping all dashboards...${NC}"
            for pid in "${PIDS[@]}"; do
                kill $pid 2>/dev/null || true
            done
            echo -e "${GREEN}✓ All dashboards stopped${NC}"
            exit 0
        }
        
        trap cleanup INT TERM
        
        # Wait for any child to exit
        wait
        ;;
    
    0)
        echo "Goodbye!"
        exit 0
        ;;
    
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

