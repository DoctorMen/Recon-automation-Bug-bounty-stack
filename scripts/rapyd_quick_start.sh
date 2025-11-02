#!/bin/bash

# Rapyd Bug Bounty Quick Start Script
# This script runs safe reconnaissance for Rapyd bug bounty program
# Created: November 1, 2025

set -e

echo "============================================"
echo "🎯 RAPYD BUG BOUNTY RECONNAISSANCE"
echo "============================================"
echo ""
echo "⚡ URGENT: Promotion ends November 29, 2025"
echo "💰 Bonus rewards: +\$500 to +\$1,000"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Set working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Configuration
TARGETS_FILE="programs/rapyd/targets.txt"
OUTPUT_DIR="output/rapyd"
PROGRAM_DIR="programs/rapyd"

# Step 1: Verify targets file exists
echo -e "${BLUE}[Step 1]${NC} Verifying targets file..."
if [ ! -f "$TARGETS_FILE" ]; then
    echo -e "${YELLOW}Warning:${NC} Targets file not found at $TARGETS_FILE"
    echo "Creating it now..."
    mkdir -p "$(dirname "$TARGETS_FILE")"
    cat > "$TARGETS_FILE" << 'EOF'
dashboard.rapyd.net
verify.rapyd.net
checkout.rapyd.net
sandboxapi.rapyd.net
api.rapyd.net
EOF
fi
echo -e "${GREEN}✓${NC} Targets file ready"

# Step 2: Create output directories
echo -e "${BLUE}[Step 2]${NC} Creating output directories..."
mkdir -p "$OUTPUT_DIR"
mkdir -p "$PROGRAM_DIR/recon"
mkdir -p "$PROGRAM_DIR/findings"
mkdir -p "$PROGRAM_DIR/reports"
mkdir -p "$PROGRAM_DIR/screenshots"
echo -e "${GREEN}✓${NC} Directories created"

# Step 3: Run reconnaissance
echo ""
echo -e "${BLUE}[Step 3]${NC} Starting reconnaissance..."
echo ""
echo "This will discover:"
echo "  • Subdomains and hidden endpoints"
echo "  • Live URLs and API routes"
echo "  • Technologies and frameworks"
echo ""
echo -e "${YELLOW}Note:${NC} This is PASSIVE reconnaissance only - safe for bug bounties"
echo ""

# Check if run_pipeline.py exists
if [ -f "run_pipeline.py" ]; then
    echo -e "${GREEN}Starting recon pipeline...${NC}"
    echo ""
    python3 run_pipeline.py --targets "$TARGETS_FILE" --output "$OUTPUT_DIR"
    
    # Copy results to program directory
    if [ -d "$OUTPUT_DIR" ]; then
        echo ""
        echo -e "${BLUE}[Step 4]${NC} Copying results to program directory..."
        cp -r "$OUTPUT_DIR"/* "$PROGRAM_DIR/recon/" 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Results copied"
    fi
    
    # Generate report
    if [ -f "scripts/generate_report.py" ]; then
        echo ""
        echo -e "${BLUE}[Step 5]${NC} Generating reconnaissance report..."
        python3 scripts/generate_report.py --input "$OUTPUT_DIR" --output "$PROGRAM_DIR/reports/recon_report.md" 2>/dev/null || echo "Report generation skipped"
    fi
else
    echo -e "${YELLOW}Warning:${NC} run_pipeline.py not found"
    echo "Running individual recon stages instead..."
    echo ""
    
    # Fallback: Run individual stages
    if [ -f "scripts/run_recon.sh" ]; then
        ./scripts/run_recon.sh "$TARGETS_FILE" "$OUTPUT_DIR"
    fi
    
    if [ -f "scripts/run_httpx.sh" ] && [ -f "$OUTPUT_DIR/subdomains.txt" ]; then
        ./scripts/run_httpx.sh "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR"
    fi
fi

# Step 4: Analyze results
echo ""
echo -e "${BLUE}[Step 6]${NC} Analyzing reconnaissance results..."
echo ""

# Check if results exist
if [ -f "$OUTPUT_DIR/live_urls.txt" ] || [ -f "$PROGRAM_DIR/recon/live_urls.txt" ]; then
    LIVE_FILE="$OUTPUT_DIR/live_urls.txt"
    [ -f "$PROGRAM_DIR/recon/live_urls.txt" ] && LIVE_FILE="$PROGRAM_DIR/recon/live_urls.txt"
    
    LIVE_URLS=$(wc -l < "$LIVE_FILE" 2>/dev/null || echo "0")
    echo -e "${GREEN}✓${NC} Found ${LIVE_URLS} live URLs"
    
    echo ""
    echo "High-priority targets for manual testing:"
    echo ""
    
    echo -e "${YELLOW}API Endpoints:${NC}"
    grep -E "(api|v1|v2|graphql)" "$LIVE_FILE" 2>/dev/null | head -10 || echo "  (run full recon to discover)"
    
    echo ""
    echo -e "${YELLOW}Authentication Endpoints:${NC}"
    grep -E "(auth|login|oauth|token)" "$LIVE_FILE" 2>/dev/null | head -10 || echo "  (run full recon to discover)"
    
    echo ""
    echo -e "${YELLOW}Business Logic Endpoints:${NC}"
    grep -E "(payment|transaction|wallet|refund|transfer)" "$LIVE_FILE" 2>/dev/null | head -10 || echo "  (run full recon to discover)"
else
    echo -e "${YELLOW}No live URLs found yet${NC}"
    echo "Run the full recon pipeline to discover endpoints"
fi

# Final summary
echo ""
echo "============================================"
echo -e "${GREEN}✅ RAPYD RECONNAISSANCE COMPLETE${NC}"
echo "============================================"
echo ""
echo -e "${YELLOW}📁 Your Workspace:${NC}"
echo "  • Targets: $TARGETS_FILE"
echo "  • Recon output: $OUTPUT_DIR"
echo "  • Program files: $PROGRAM_DIR/"
echo "  • Findings log: $PROGRAM_DIR/findings/FINDINGS_LOG.md"
echo "  • Testing checklist: $PROGRAM_DIR/TESTING_CHECKLIST.md"
echo ""
echo -e "${YELLOW}🎯 Next Steps:${NC}"
echo "  1. Review recon results in $OUTPUT_DIR/"
echo "  2. Complete API key generation at dashboard.rapyd.net"
echo "  3. Start manual testing on discovered endpoints"
echo "  4. Document findings in $PROGRAM_DIR/findings/FINDINGS_LOG.md"
echo ""
echo -e "${RED}⚡ REMINDER: Promotion ends November 29, 2025!${NC}"
echo ""

