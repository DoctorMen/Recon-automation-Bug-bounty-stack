#!/bin/bash
# JavaScript Extractor and Analyzer for Bug Bounty
# Extracts JS files, API endpoints, secrets from target URLs

TARGET_URL="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET_URL" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <target_url> <output_dir>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Fetching page: $TARGET_URL"
curl -s "$TARGET_URL" -o "$OUTPUT_DIR/page.html"

echo "[*] Extracting JavaScript URLs..."
grep -oP 'src="[^"]+\.js[^"]*"' "$OUTPUT_DIR/page.html" | sed 's/src="//g;s/"//g' > "$OUTPUT_DIR/js_urls.txt"
grep -oP "src='[^']+\.js[^']*'" "$OUTPUT_DIR/page.html" | sed "s/src='//g;s/'//g" >> "$OUTPUT_DIR/js_urls.txt"

# Also extract from script tags with inline
grep -oP '<script[^>]+src="[^"]+"' "$OUTPUT_DIR/page.html" | grep -oP 'src="[^"]+"' | sed 's/src="//g;s/"//g' >> "$OUTPUT_DIR/js_urls.txt"

sort -u "$OUTPUT_DIR/js_urls.txt" -o "$OUTPUT_DIR/js_urls.txt"

echo "[*] Found $(wc -l < "$OUTPUT_DIR/js_urls.txt") JavaScript files"
cat "$OUTPUT_DIR/js_urls.txt"

echo ""
echo "[*] Downloading JavaScript files..."
mkdir -p "$OUTPUT_DIR/js_files"

while read -r js_url; do
    if [[ "$js_url" == //* ]]; then
        js_url="https:$js_url"
    elif [[ "$js_url" == /* ]]; then
        # Extract domain from target URL
        domain=$(echo "$TARGET_URL" | grep -oP 'https?://[^/]+')
        js_url="$domain$js_url"
    elif [[ ! "$js_url" == http* ]]; then
        domain=$(echo "$TARGET_URL" | grep -oP 'https?://[^/]+')
        js_url="$domain/$js_url"
    fi
    
    filename=$(echo "$js_url" | md5sum | cut -d' ' -f1).js
    echo "  Downloading: $js_url"
    curl -s "$js_url" -o "$OUTPUT_DIR/js_files/$filename" 2>/dev/null
done < "$OUTPUT_DIR/js_urls.txt"

echo ""
echo "[*] Analyzing JavaScript for secrets and endpoints..."

# Search for API endpoints
echo "=== API ENDPOINTS ===" > "$OUTPUT_DIR/analysis.txt"
grep -rhoP '"/api/[^"]+"|"/v[0-9]+/[^"]+"' "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"
grep -rhoP "'/api/[^']+'|'/v[0-9]+/[^']+'" "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"

# Search for potential secrets
echo "" >> "$OUTPUT_DIR/analysis.txt"
echo "=== POTENTIAL SECRETS ===" >> "$OUTPUT_DIR/analysis.txt"
grep -rhoiP '(api[_-]?key|apikey|secret|token|password|auth)["\s]*[:=]["\s]*["\047][^"\047]{8,}["\047]' "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"

# Search for AWS keys
echo "" >> "$OUTPUT_DIR/analysis.txt"
echo "=== AWS KEYS ===" >> "$OUTPUT_DIR/analysis.txt"
grep -rhoP 'AKIA[0-9A-Z]{16}' "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"

# Search for URLs and domains
echo "" >> "$OUTPUT_DIR/analysis.txt"
echo "=== INTERNAL URLS/DOMAINS ===" >> "$OUTPUT_DIR/analysis.txt"
grep -rhoP 'https?://[a-zA-Z0-9.-]+\.(robinhood|impact)\.(com|io|net)[^"\047\s]*' "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"

# Search for GraphQL endpoints
echo "" >> "$OUTPUT_DIR/analysis.txt"
echo "=== GRAPHQL ===" >> "$OUTPUT_DIR/analysis.txt"
grep -rhoiP 'graphql|mutation|query\s*{' "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"

# Search for Firebase/Google configs
echo "" >> "$OUTPUT_DIR/analysis.txt"
echo "=== FIREBASE/GOOGLE CONFIG ===" >> "$OUTPUT_DIR/analysis.txt"
grep -rhoP 'firebase[^"]*\.googleapis\.com|AIza[0-9A-Za-z_-]{35}' "$OUTPUT_DIR/js_files/" 2>/dev/null | sort -u >> "$OUTPUT_DIR/analysis.txt"

echo ""
echo "[*] Analysis complete. Results saved to $OUTPUT_DIR/analysis.txt"
cat "$OUTPUT_DIR/analysis.txt"
