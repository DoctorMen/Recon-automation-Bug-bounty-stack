#!/bin/bash
# Henkel Bug Bounty - Quick Start Script
# Requires: subfinder, httpx, nuclei, ffuf

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  HENKEL BUG BOUNTY HUNTER${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if H1 username is provided
if [ -z "$1" ]; then
    echo -e "${RED}Usage: ./quick_start.sh <h1_username>${NC}"
    exit 1
fi

H1_USER=$1
HEADER="X-HackerOne-Research: $H1_USER"
OUTPUT_DIR="./output"
mkdir -p $OUTPUT_DIR

echo -e "${YELLOW}[*] Researcher: $H1_USER${NC}"
echo ""

# Step 1: Check alive hosts
echo -e "${GREEN}[STEP 1] Checking alive hosts...${NC}"
cat targets.txt | grep -v "^#" | grep -v "^$" > $OUTPUT_DIR/clean_targets.txt
httpx -l $OUTPUT_DIR/clean_targets.txt -silent -o $OUTPUT_DIR/alive_hosts.txt -H "$HEADER" 2>/dev/null || true
ALIVE_COUNT=$(wc -l < $OUTPUT_DIR/alive_hosts.txt 2>/dev/null || echo "0")
echo -e "${GREEN}[+] Found $ALIVE_COUNT alive hosts${NC}"

# Step 2: Technology detection
echo -e "${GREEN}[STEP 2] Technology detection...${NC}"
httpx -l $OUTPUT_DIR/alive_hosts.txt -silent -tech-detect -json -o $OUTPUT_DIR/tech_detect.json -H "$HEADER" 2>/dev/null || true

# Step 3: Nuclei scan for critical vulnerabilities
echo -e "${GREEN}[STEP 3] Scanning for SQLi, RCE, SSRF...${NC}"
nuclei -l $OUTPUT_DIR/alive_hosts.txt \
    -tags sqli,rce,lfi,ssrf,idor,exposure,cve \
    -severity critical,high \
    -H "$HEADER" \
    -o $OUTPUT_DIR/nuclei_findings.txt \
    -silent 2>/dev/null || true

# Step 4: Directory fuzzing on top targets
echo -e "${GREEN}[STEP 4] Directory fuzzing on priority targets...${NC}"

# Common sensitive paths
PATHS="/.git/config
/.env
/.env.backup
/api/swagger.json
/api/v1/users
/api/v2/users
/graphql
/admin
/debug
/phpinfo.php
/actuator/env
/actuator/health
/server-status
/.well-known/security.txt
/backup.sql
/db.sql
/dump.sql
/config.php.bak
/web.config
/.htaccess"

echo "$PATHS" > $OUTPUT_DIR/sensitive_paths.txt

# Fuzz first 5 alive hosts
head -5 $OUTPUT_DIR/alive_hosts.txt | while read url; do
    echo -e "${YELLOW}[*] Fuzzing: $url${NC}"
    ffuf -u "${url}FUZZ" -w $OUTPUT_DIR/sensitive_paths.txt \
        -H "$HEADER" \
        -mc 200,301,302,403 \
        -o $OUTPUT_DIR/ffuf_$(echo $url | md5sum | cut -d' ' -f1).json \
        -s 2>/dev/null || true
done

# Step 5: Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  SCAN COMPLETE${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Alive hosts: $OUTPUT_DIR/alive_hosts.txt"
echo -e "Tech detection: $OUTPUT_DIR/tech_detect.json"
echo -e "Nuclei findings: $OUTPUT_DIR/nuclei_findings.txt"
echo -e "FFuf results: $OUTPUT_DIR/ffuf_*.json"
echo ""

# Check for findings
if [ -s $OUTPUT_DIR/nuclei_findings.txt ]; then
    echo -e "${RED}[!!!] VULNERABILITIES FOUND:${NC}"
    cat $OUTPUT_DIR/nuclei_findings.txt
else
    echo -e "${YELLOW}[*] No critical vulnerabilities found by nuclei${NC}"
    echo -e "${YELLOW}[*] Manual testing recommended for:${NC}"
    echo -e "    - SQLi in login/search forms"
    echo -e "    - IDOR in API endpoints"
    echo -e "    - File upload for RCE"
fi

echo ""
echo -e "${GREEN}Next steps:${NC}"
echo -e "1. Review ffuf results for sensitive file exposure"
echo -e "2. Manual SQLi testing on login forms"
echo -e "3. Check API endpoints for IDOR"
echo -e "4. Test file upload functionality for RCE"
