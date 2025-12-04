#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
#
# ADVANCED PAYPAL HUNTER
# Comprehensive automated testing for mature bug bounty programs
# Uses advanced tools to find bugs that automated scanners miss
#

set -e  # Exit on error

PROGRAM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$PROGRAM_DIR/tools"
RECON_DIR="$PROGRAM_DIR/recon"
FINDINGS_DIR="$PROGRAM_DIR/findings"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════"
echo "   ADVANCED PAYPAL HUNTER - Professional Bug Bounty Tools"
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Check if tools exist
check_tools() {
    echo -e "${YELLOW}[*] Checking tools...${NC}"
    
    if [ ! -f "$TOOLS_DIR/advanced_api_fuzzer.py" ]; then
        echo -e "${RED}[-] Advanced tools not found!${NC}"
        exit 1
    fi
    
    # Make tools executable
    chmod +x "$TOOLS_DIR"/*.py 2>/dev/null || true
    
    echo -e "${GREEN}[+] All tools ready${NC}"
}

# Step 1: Analyze subdomains intelligently
analyze_subdomains() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[*] Step 1: Intelligent Subdomain Analysis${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
    
    if [ ! -f "$RECON_DIR/shadowstep_paypal_live.txt" ]; then
        echo -e "${RED}[-] No live hosts found. Run recon first.${NC}"
        exit 1
    fi
    
    python3 "$TOOLS_DIR/smart_subdomain_analyzer.py" \
        --input "$RECON_DIR/shadowstep_paypal_live.txt"
    
    echo -e "${GREEN}[+] Subdomain analysis complete${NC}"
}

# Step 2: Run targeted nuclei scan on high-priority targets
targeted_scan() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[*] Step 2: Targeted Vulnerability Scan${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
    
    if [ ! -f "$RECON_DIR/high_priority_targets.txt" ]; then
        echo -e "${YELLOW}[!] No high-priority targets identified${NC}"
        echo -e "${YELLOW}[!] Using all live hosts instead${NC}"
        TARGET_FILE="$RECON_DIR/shadowstep_paypal_live.txt"
    else
        TARGET_FILE="$RECON_DIR/high_priority_targets.txt"
        echo -e "${GREEN}[+] Scanning $(wc -l < $TARGET_FILE) high-priority targets${NC}"
    fi
    
    # Run focused scan
    nuclei -l "$TARGET_FILE" \
        -tags exposure,config,misconfig,idor,auth-bypass \
        -severity high,critical \
        -rate-limit 15 \
        -o "$FINDINGS_DIR/targeted_scan_$(date +%Y%m%d_%H%M%S).txt" \
        -stats
    
    echo -e "${GREEN}[+] Targeted scan complete${NC}"
}

# Step 3: Analyze results intelligently
analyze_results() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[*] Step 3: Intelligent Result Analysis${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
    
    # Find most recent scan file
    LATEST_SCAN=$(ls -t "$FINDINGS_DIR"/targeted_scan_*.txt 2>/dev/null | head -1)
    
    if [ -z "$LATEST_SCAN" ]; then
        # Try the quick scan file
        LATEST_SCAN="$FINDINGS_DIR/shadowstep_quick_scan.txt"
    fi
    
    if [ -f "$LATEST_SCAN" ]; then
        echo -e "${GREEN}[+] Analyzing: $LATEST_SCAN${NC}"
        python3 "$TOOLS_DIR/intelligent_result_analyzer.py" \
            --scan-results "$LATEST_SCAN"
    else
        echo -e "${YELLOW}[!] No scan results found to analyze${NC}"
    fi
}

# Step 4: API Fuzzing on high-value endpoints
api_fuzzing() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[*] Step 4: Advanced API Fuzzing${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
    
    # Create endpoints file
    cat > "$RECON_DIR/api_endpoints.txt" << EOF
/v1/payments
/v1/users
/v1/transactions
/v1/accounts
/api/payments
/api/users
/api/transactions
EOF
    
    echo -e "${GREEN}[+] Testing PayPal Sandbox API${NC}"
    python3 "$TOOLS_DIR/advanced_api_fuzzer.py" \
        --target "https://api.sandbox.paypal.com" \
        --endpoints "$RECON_DIR/api_endpoints.txt" \
        --rate-limit 2
    
    echo -e "${GREEN}[+] API fuzzing complete${NC}"
}

# Step 5: Generate final report
generate_report() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}[*] Step 5: Generating Final Report${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
    
    REPORT_FILE="$FINDINGS_DIR/ADVANCED_HUNT_REPORT_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$REPORT_FILE" << EOF
# ADVANCED PAYPAL HUNT REPORT
**Generated:** $(date)

## Summary

**Targets Analyzed:** $(wc -l < "$RECON_DIR/shadowstep_paypal_live.txt" 2>/dev/null || echo "N/A")
**High Priority Targets:** $(wc -l < "$RECON_DIR/high_priority_targets.txt" 2>/dev/null || echo "0")

## Tools Used

1. **Smart Subdomain Analyzer** - Identified high-value targets
2. **Targeted Nuclei Scan** - Focused vulnerability detection
3. **Intelligent Result Analyzer** - False positive filtering
4. **Advanced API Fuzzer** - Business logic testing

## Findings

### Critical/High Severity
$(find "$FINDINGS_DIR" -name "verified_findings_*.json" -type f -exec cat {} \; 2>/dev/null | grep -c '"severity_score".*7[5-9]\|[8-9][0-9]\|1[0-9][0-9]' || echo "0") findings

### Manual Verification Required
Check: \`findings/manual_verification_checklist_*.txt\`

## Next Steps

1. Manually verify all critical/high findings
2. Document proof of concept for each
3. Prepare HackerOne reports
4. Submit valid vulnerabilities

## Files Generated

- Subdomain Analysis: \`findings/subdomain_analysis_*.json\`
- Scan Results: \`findings/targeted_scan_*.txt\`
- Verified Findings: \`findings/verified_findings_*.json\`
- API Fuzzing: \`findings/advanced_fuzzer_results_*.json\`

---
**Tools by: SHADOWSTEP131**
**Program: PayPal Bug Bounty**
EOF
    
    echo -e "${GREEN}[+] Report generated: $REPORT_FILE${NC}"
    cat "$REPORT_FILE"
}

# Main execution
main() {
    check_tools
    
    echo -e "\n${YELLOW}Select workflow:${NC}"
    echo "1) Full advanced hunt (all steps)"
    echo "2) Quick analysis only"
    echo "3) API fuzzing only"
    echo "4) Custom workflow"
    echo -n "Choice [1-4]: "
    read -r choice
    
    case $choice in
        1)
            analyze_subdomains
            targeted_scan
            analyze_results
            api_fuzzing
            generate_report
            ;;
        2)
            analyze_subdomains
            analyze_results
            ;;
        3)
            api_fuzzing
            ;;
        4)
            echo -e "\n${YELLOW}Custom workflow:${NC}"
            echo "a) Subdomain analysis"
            echo "b) Targeted scan"
            echo "c) Result analysis"
            echo "d) API fuzzing"
            echo -n "Steps (e.g., 'abc'): "
            read -r steps
            
            [[ $steps == *"a"* ]] && analyze_subdomains
            [[ $steps == *"b"* ]] && targeted_scan
            [[ $steps == *"c"* ]] && analyze_results
            [[ $steps == *"d"* ]] && api_fuzzing
            
            generate_report
            ;;
        *)
            echo -e "${RED}[-] Invalid choice${NC}"
            exit 1
            ;;
    esac
    
    echo -e "\n${GREEN}════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}   HUNT COMPLETE - Check findings/ directory${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════${NC}\n"
}

# Run main
main
