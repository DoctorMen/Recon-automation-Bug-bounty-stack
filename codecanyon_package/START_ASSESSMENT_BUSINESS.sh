#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
#
# START ASSESSMENT BUSINESS - Quick Launcher
# Get your first paying client in 7-14 days
#

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

clear

echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       PAYMENT-FIRST ASSESSMENT BUSINESS LAUNCHER              ║${NC}"
echo -e "${BOLD}║     Get Paid Upfront - Deliver Value - Scale Revenue         ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if required files exist
echo -e "${BLUE}[*] Checking system...${NC}"

files_needed=(
    "CLIENT_FINDER_AUTOMATION.py"
    "CLIENT_OUTREACH_GENERATOR.py"
    "ONE_CLICK_ASSESSMENT.py"
    "PAYMENT_SYSTEM.py"
    "AI_BUG_BOUNTY_SYSTEM.py"
)

all_good=true
for file in "${files_needed[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}  ✓ $file${NC}"
    else
        echo -e "${RED}  ✗ $file missing${NC}"
        all_good=false
    fi
done

if [ "$all_good" = false ]; then
    echo ""
    echo -e "${RED}[!] Some files are missing. Please ensure all tools are in this directory.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ All systems ready!${NC}"
echo ""

# Main menu
while true; do
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}                    MAIN MENU${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}[1]${NC} Find Clients (Day 1-2)"
    echo -e "${YELLOW}[2]${NC} Generate Outreach Emails (Day 3-4)"
    echo -e "${YELLOW}[3]${NC} Run Quick Assessment (Day 5-7)"
    echo -e "${YELLOW}[4]${NC} Create Invoice (Day 7-10)"
    echo -e "${YELLOW}[5]${NC} Run Full Assessment (After Payment)"
    echo ""
    echo -e "${BLUE}[6]${NC} View Complete Guide"
    echo -e "${BLUE}[7]${NC} Check Revenue Stats"
    echo ""
    echo -e "${RED}[0]${NC} Exit"
    echo ""
    echo -e -n "${BOLD}Select option: ${NC}"
    
    read choice
    
    case $choice in
        1)
            echo ""
            echo -e "${BLUE}[*] Launching Client Finder...${NC}"
            echo ""
            python3 CLIENT_FINDER_AUTOMATION.py
            echo ""
            echo -e "${GREEN}[+] Next: Use search queries to find 20-50 prospects${NC}"
            echo -e "${GREEN}[+] Fill out prospects_template.json with real companies${NC}"
            echo ""
            read -p "Press Enter to continue..."
            clear
            ;;
        2)
            echo ""
            echo -e "${BLUE}[*] Launching Outreach Generator...${NC}"
            echo ""
            python3 CLIENT_OUTREACH_GENERATOR.py
            echo ""
            echo -e "${GREEN}[+] Next: Send 10-20 emails per day${NC}"
            echo -e "${GREEN}[+] Expected: 20-30% response rate${NC}"
            echo ""
            read -p "Press Enter to continue..."
            clear
            ;;
        3)
            echo ""
            echo -e "${YELLOW}Quick Assessment (Free Scan)${NC}"
            echo ""
            read -p "Enter target domain (e.g., company.com): " target
            read -p "Enter client name: " client
            
            echo ""
            echo -e "${BLUE}[*] Running quick AI security scan...${NC}"
            echo ""
            
            python3 ONE_CLICK_ASSESSMENT.py \
                --target "$target" \
                --client "$client" \
                --ai-only \
                --price 0
            
            echo ""
            echo -e "${GREEN}[+] Scan complete! Send report to client.${NC}"
            echo -e "${GREEN}[+] Follow up: 'Want full report with fixes? \$1,500'${NC}"
            echo ""
            read -p "Press Enter to continue..."
            clear
            ;;
        4)
            echo ""
            echo -e "${YELLOW}Create Invoice${NC}"
            echo ""
            read -p "Enter client name: " client
            read -p "Enter service (e.g., AI Security Audit): " service
            read -p "Enter price (e.g., 1500): " price
            
            echo ""
            echo -e "${BLUE}[*] Creating invoice...${NC}"
            echo ""
            
            python3 PAYMENT_SYSTEM.py \
                --client "$client" \
                --service "$service" \
                --price "$price"
            
            echo ""
            echo -e "${GREEN}[+] Invoice created! Copy and send to client.${NC}"
            echo -e "${RED}[!] DO NOT START WORK until payment received!${NC}"
            echo ""
            read -p "Press Enter to continue..."
            clear
            ;;
        5)
            echo ""
            echo -e "${YELLOW}Full Paid Assessment${NC}"
            echo ""
            echo -e "${RED}⚠️  Only run this AFTER payment is received!${NC}"
            echo ""
            read -p "Has client paid? (yes/no): " paid
            
            if [ "$paid" != "yes" ]; then
                echo ""
                echo -e "${RED}[!] Wait for payment before starting work!${NC}"
                echo ""
                read -p "Press Enter to continue..."
                clear
                continue
            fi
            
            read -p "Enter target domain: " target
            read -p "Enter client name: " client
            read -p "Enter price charged: " price
            read -p "AI only or Full Stack? (ai/full): " type
            
            echo ""
            echo -e "${BLUE}[*] Running comprehensive assessment...${NC}"
            echo ""
            
            if [ "$type" = "ai" ]; then
                python3 ONE_CLICK_ASSESSMENT.py \
                    --target "$target" \
                    --client "$client" \
                    --ai-only \
                    --price "$price"
            else
                python3 ONE_CLICK_ASSESSMENT.py \
                    --target "$target" \
                    --client "$client" \
                    --price "$price"
            fi
            
            echo ""
            echo -e "${GREEN}[+] Assessment complete! Deliver report to client.${NC}"
            echo -e "${GREEN}[+] Ask for: Testimonial + 2-3 Referrals${NC}"
            echo ""
            read -p "Press Enter to continue..."
            clear
            ;;
        6)
            echo ""
            echo -e "${BLUE}[*] Opening Complete Guide...${NC}"
            echo ""
            if command -v cat &> /dev/null; then
                cat PAYMENT_FIRST_COMPLETE_GUIDE.md | less
            else
                echo "Please read: PAYMENT_FIRST_COMPLETE_GUIDE.md"
            fi
            clear
            ;;
        7)
            echo ""
            echo -e "${BLUE}[*] Loading revenue statistics...${NC}"
            echo ""
            python3 -c "
from PAYMENT_SYSTEM import PaymentSystem
ps = PaymentSystem()
stats = ps.get_revenue_stats()
print('=' * 60)
print('REVENUE DASHBOARD')
print('=' * 60)
print(f'Total Invoiced: \${stats[\"total_invoiced\"]:,.2f}')
print(f'Total Paid: \${stats[\"total_paid\"]:,.2f}')
print(f'Total Unpaid: \${stats[\"total_unpaid\"]:,.2f}')
print(f'')
print(f'Invoices: {stats[\"invoice_count\"]} total')
print(f'  - Paid: {stats[\"paid_count\"]}')
print(f'  - Unpaid: {stats[\"unpaid_count\"]}')
print('=' * 60)
"
            echo ""
            read -p "Press Enter to continue..."
            clear
            ;;
        0)
            echo ""
            echo -e "${GREEN}Good luck with your assessment business!${NC}"
            echo ""
            exit 0
            ;;
        *)
            echo ""
            echo -e "${RED}Invalid option. Please try again.${NC}"
            echo ""
            sleep 1
            clear
            ;;
    esac
done
