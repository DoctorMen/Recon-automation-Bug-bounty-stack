#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
#
# NAHAMSEC-STYLE RECONNAISSANCE
# Integrates NahamSec's methodology into your system
#
# Usage: ./nahamsec_recon.sh target.com
#

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./nahamsec_recon.sh target.com"
    exit 1
fi

# Create dated output directory (LazyRecon style)
DATE=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_DIR="output/${DOMAIN}/${DATE}_nahamsec_recon"
mkdir -p "$OUTPUT_DIR"/{recon,discovery,screenshots,reports}

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║        NAHAMSEC-STYLE RECONNAISSANCE PIPELINE                 ║"
echo "║              Enhanced Bug Bounty Recon                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Target: $DOMAIN"
echo "[*] Output: $OUTPUT_DIR"
echo ""

# ============================================================
# PHASE 1: SUBDOMAIN ENUMERATION (NahamSec Style)
# ============================================================
echo "[1/8] Subdomain Enumeration..."

# Subfinder (fast, passive)
if command -v subfinder &> /dev/null; then
    echo "  → Running subfinder..."
    subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/recon/subfinder.txt" 2>/dev/null
fi

# Amass (comprehensive, network mapping)
if command -v amass &> /dev/null; then
    echo "  → Running amass (passive)..."
    amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/recon/amass.txt" 2>/dev/null
fi

# cert.sh (certificate transparency)
echo "  → Checking cert.sh..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$OUTPUT_DIR/recon/certsh.txt" 2>/dev/null

# Combine and deduplicate
cat "$OUTPUT_DIR/recon/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/recon/all_subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "$OUTPUT_DIR/recon/all_subdomains.txt")
echo "  ✓ Found $SUBDOMAIN_COUNT subdomains"

# ============================================================
# PHASE 2: LIVE HOST PROBING
# ============================================================
echo ""
echo "[2/8] Probing for live hosts..."

if command -v httpx &> /dev/null; then
    cat "$OUTPUT_DIR/recon/all_subdomains.txt" | httpx -silent -mc 200,201,301,302,303,307,308,401,403 -o "$OUTPUT_DIR/recon/live_hosts.txt" 2>/dev/null
    LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/recon/live_hosts.txt")
    echo "  ✓ Found $LIVE_COUNT live hosts"
else
    echo "  ⚠ httpx not installed, skipping live probe"
    cp "$OUTPUT_DIR/recon/all_subdomains.txt" "$OUTPUT_DIR/recon/live_hosts.txt"
fi

# ============================================================
# PHASE 3: WAYBACK MACHINE SCRAPING (NahamSec Signature)
# ============================================================
echo ""
echo "[3/8] Scraping Wayback Machine..."

# waybackurls
if command -v waybackurls &> /dev/null; then
    echo "  → Running waybackurls..."
    cat "$OUTPUT_DIR/recon/all_subdomains.txt" | waybackurls > "$OUTPUT_DIR/discovery/wayback_urls.txt" 2>/dev/null
    WAYBACK_COUNT=$(wc -l < "$OUTPUT_DIR/discovery/wayback_urls.txt")
    echo "  ✓ Found $WAYBACK_COUNT URLs from Wayback"
else
    echo "  ⚠ waybackurls not installed"
    echo "  Install: go install github.com/tomnomnom/waybackurls@latest"
fi

# gau (alternative)
if command -v gau &> /dev/null; then
    echo "  → Running gau..."
    echo "$DOMAIN" | gau --threads 5 >> "$OUTPUT_DIR/discovery/wayback_urls.txt" 2>/dev/null
fi

# ============================================================
# PHASE 4: JS FILE EXTRACTION
# ============================================================
echo ""
echo "[4/8] Extracting JavaScript files..."

if [ -f "$OUTPUT_DIR/discovery/wayback_urls.txt" ]; then
    cat "$OUTPUT_DIR/discovery/wayback_urls.txt" | grep -iE "\.js$|\.jsx$|\.json$" | sort -u > "$OUTPUT_DIR/discovery/js_files.txt"
    
    # Download live JS files
    if command -v httpx &> /dev/null; then
        echo "  → Checking which JS files are live..."
        cat "$OUTPUT_DIR/discovery/js_files.txt" | head -n 100 | httpx -silent -mc 200 -o "$OUTPUT_DIR/discovery/js_files_live.txt" 2>/dev/null
        JS_COUNT=$(wc -l < "$OUTPUT_DIR/discovery/js_files_live.txt")
        echo "  ✓ Found $JS_COUNT live JS files"
    fi
fi

# ============================================================
# PHASE 5: PARAMETER EXTRACTION (NahamSec Technique)
# ============================================================
echo ""
echo "[5/8] Extracting parameters from JS files..."

if [ -f "$OUTPUT_DIR/discovery/js_files_live.txt" ]; then
    # Simple regex extraction of common parameter patterns
    echo "  → Parsing JS for parameters..."
    
    # Download JS files and extract parameters
    while IFS= read -r js_url; do
        curl -s "$js_url" 2>/dev/null | \
        grep -oP '[\"\047][a-zA-Z0-9_-]{3,30}[\"\047]\s*:\s*' | \
        sed 's/[\":]//g' | sed 's/\x27//g' | \
        sort -u >> "$OUTPUT_DIR/discovery/parameters_raw.txt"
    done < "$OUTPUT_DIR/discovery/js_files_live.txt"
    
    # Clean and deduplicate
    if [ -f "$OUTPUT_DIR/discovery/parameters_raw.txt" ]; then
        cat "$OUTPUT_DIR/discovery/parameters_raw.txt" | sort -u | grep -E '^[a-zA-Z]' > "$OUTPUT_DIR/discovery/parameters.txt"
        PARAM_COUNT=$(wc -l < "$OUTPUT_DIR/discovery/parameters.txt")
        echo "  ✓ Extracted $PARAM_COUNT unique parameters"
    fi
fi

# ============================================================
# PHASE 6: SCREENSHOTS (NahamSec Visual Intelligence)
# ============================================================
echo ""
echo "[6/8] Taking screenshots..."

if command -v gowitness &> /dev/null; then
    echo "  → Running gowitness..."
    gowitness file -f "$OUTPUT_DIR/recon/live_hosts.txt" --destination "$OUTPUT_DIR/screenshots/" --screenshot-format png 2>/dev/null
    SCREENSHOT_COUNT=$(find "$OUTPUT_DIR/screenshots/" -name "*.png" 2>/dev/null | wc -l)
    echo "  ✓ Captured $SCREENSHOT_COUNT screenshots"
elif command -v aquatone &> /dev/null; then
    echo "  → Running aquatone..."
    cat "$OUTPUT_DIR/recon/live_hosts.txt" | aquatone -out "$OUTPUT_DIR/screenshots/" 2>/dev/null
else
    echo "  ⚠ gowitness/aquatone not installed"
    echo "  Install: go install github.com/sensepost/gowitness@latest"
fi

# ============================================================
# PHASE 7: SUBDOMAIN TAKEOVER DETECTION
# ============================================================
echo ""
echo "[7/8] Checking for subdomain takeovers..."

if command -v subjack &> /dev/null; then
    echo "  → Running subjack..."
    subjack -w "$OUTPUT_DIR/recon/all_subdomains.txt" -t 100 -timeout 30 -o "$OUTPUT_DIR/recon/takeovers.txt" -ssl -v 2>/dev/null
    
    if [ -f "$OUTPUT_DIR/recon/takeovers.txt" ] && [ -s "$OUTPUT_DIR/recon/takeovers.txt" ]; then
        TAKEOVER_COUNT=$(wc -l < "$OUTPUT_DIR/recon/takeovers.txt")
        echo "  ✓ Found $TAKEOVER_COUNT potential takeovers!"
    else
        echo "  ✓ No subdomain takeovers found"
    fi
else
    echo "  ⚠ subjack not installed"
    echo "  Install: go install github.com/haccer/subjack@latest"
fi

# ============================================================
# PHASE 8: HTML REPORT GENERATION (LazyRecon Style)
# ============================================================
echo ""
echo "[8/8] Generating HTML report..."

REPORT="$OUTPUT_DIR/reports/report.html"

cat > "$REPORT" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NahamSec-Style Recon Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 {
            color: #00d4ff;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0,212,255,0.5);
        }
        .timestamp {
            color: #888;
            font-size: 0.9em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 24px rgba(0,212,255,0.2);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 5px;
        }
        .stat-label {
            color: #999;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .section {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .section h2 {
            color: #00d4ff;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .file-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }
        .file-item {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #00d4ff;
            transition: all 0.3s ease;
        }
        .file-item:hover {
            background: rgba(0,212,255,0.1);
            transform: translateX(5px);
        }
        .file-name {
            color: #fff;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .file-count {
            color: #00d4ff;
            font-size: 1.2em;
        }
        .screenshots {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .screenshot {
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .screenshot img {
            width: 100%;
            border-radius: 4px;
        }
        .alert {
            background: rgba(255,100,100,0.2);
            border-left: 4px solid #ff6464;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .alert h3 {
            color: #ff6464;
            margin-bottom: 10px;
        }
        footer {
            text-align: center;
            padding: 40px 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 NahamSec-Style Recon Report</h1>
            <p class="timestamp">Generated: DATE_PLACEHOLDER</p>
            <p>Target: <strong>DOMAIN_PLACEHOLDER</strong></p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">SUBDOMAIN_COUNT</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">LIVE_COUNT</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">WAYBACK_COUNT</div>
                <div class="stat-label">Wayback URLs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">JS_COUNT</div>
                <div class="stat-label">JS Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">PARAM_COUNT</div>
                <div class="stat-label">Parameters</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">SCREENSHOT_COUNT</div>
                <div class="stat-label">Screenshots</div>
            </div>
        </div>

        TAKEOVER_ALERT

        <div class="section">
            <h2>📂 Output Files</h2>
            <div class="file-list">
                FILE_LIST_PLACEHOLDER
            </div>
        </div>

        <div class="section">
            <h2>📸 Screenshots Preview</h2>
            <div class="screenshots">
                SCREENSHOT_LIST_PLACEHOLDER
            </div>
        </div>

        <footer>
            <p>Generated by NahamSec-Enhanced Recon Pipeline</p>
            <p>Combining elite bug bounty methodology with AI-powered automation</p>
        </footer>
    </div>
</body>
</html>
EOF

# Replace placeholders
sed -i "s/DATE_PLACEHOLDER/$(date)/g" "$REPORT"
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" "$REPORT"
sed -i "s/SUBDOMAIN_COUNT/${SUBDOMAIN_COUNT:-0}/g" "$REPORT"
sed -i "s/LIVE_COUNT/${LIVE_COUNT:-0}/g" "$REPORT"
sed -i "s/WAYBACK_COUNT/${WAYBACK_COUNT:-0}/g" "$REPORT"
sed -i "s/JS_COUNT/${JS_COUNT:-0}/g" "$REPORT"
sed -i "s/PARAM_COUNT/${PARAM_COUNT:-0}/g" "$REPORT"
sed -i "s/SCREENSHOT_COUNT/${SCREENSHOT_COUNT:-0}/g" "$REPORT"

# Add takeover alert if found
if [ -f "$OUTPUT_DIR/recon/takeovers.txt" ] && [ -s "$OUTPUT_DIR/recon/takeovers.txt" ]; then
    TAKEOVER_ALERT='<div class="alert"><h3>⚠️ Potential Subdomain Takeovers Found!</h3><p>Check takeovers.txt for details</p></div>'
    sed -i "s|TAKEOVER_ALERT|$TAKEOVER_ALERT|g" "$REPORT"
else
    sed -i "s/TAKEOVER_ALERT//g" "$REPORT"
fi

echo "  ✓ HTML report generated: $REPORT"

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    RECON COMPLETE                             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo ""
echo "Key Files:"
echo "  • Subdomains: recon/all_subdomains.txt ($SUBDOMAIN_COUNT)"
echo "  • Live Hosts: recon/live_hosts.txt ($LIVE_COUNT)"
echo "  • Wayback URLs: discovery/wayback_urls.txt ($WAYBACK_COUNT)"
echo "  • JS Files: discovery/js_files_live.txt ($JS_COUNT)"
echo "  • Parameters: discovery/parameters.txt ($PARAM_COUNT)"
echo "  • Screenshots: screenshots/ ($SCREENSHOT_COUNT)"
echo "  • HTML Report: reports/report.html"
echo ""
echo "Next Steps:"
echo "  1. Review HTML report: firefox $REPORT"
echo "  2. Run vulnerability scanner: nuclei -l recon/live_hosts.txt"
echo "  3. Test parameters: ffuf -u TARGET -w discovery/parameters.txt"
echo "  4. Manual testing: burpsuite"
echo ""
