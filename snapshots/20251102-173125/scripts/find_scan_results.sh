#!/bin/bash
# Find and analyze scan results from previous runs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/output"

echo "=== Searching for Scan Results ==="
echo ""

# Search for JSON files
echo "Searching for JSON result files..."
find "$REPO_ROOT" -type f -name "*.json" 2>/dev/null | grep -v ".git" | while read file; do
    if command -v jq >/dev/null 2>&1; then
        count=$(jq 'length' "$file" 2>/dev/null || echo "N/A")
        echo "  $file: $count items"
    else
        size=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo "  $file: $size lines"
    fi
done

echo ""
echo "=== Current Output Directory Contents ==="
ls -lh "$OUTPUT_DIR" 2>/dev/null || echo "Output directory not found"

echo ""
echo "=== Checking for nuclei results ==="
if [ -f "$OUTPUT_DIR/nuclei.txt" ]; then
    nuclei_lines=$(wc -l < "$OUTPUT_DIR/nuclei.txt")
    echo "nuclei.txt: $nuclei_lines lines"
    if [ "$nuclei_lines" -gt 0 ]; then
        echo "First few lines:"
        head -5 "$OUTPUT_DIR/nuclei.txt"
    fi
else
    echo "nuclei.txt not found"
fi

if [ -f "$OUTPUT_DIR/nuclei-findings.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        count=$(jq 'length' "$OUTPUT_DIR/nuclei-findings.json" 2>/dev/null || echo "0")
        echo "nuclei-findings.json: $count findings"
    else
        echo "nuclei-findings.json exists (jq not available for count)"
    fi
fi

echo ""
echo "=== Subdomain Count ==="
if [ -f "$OUTPUT_DIR/subs.txt" ]; then
    sub_count=$(wc -l < "$OUTPUT_DIR/subs.txt")
    echo "subs.txt: $sub_count subdomains"
else
    echo "subs.txt not found"
fi

echo ""
echo "=== Searching for files with ~700 results ==="
find "$REPO_ROOT" -type f \( -name "*.json" -o -name "*.txt" \) 2>/dev/null | while read file; do
    if command -v jq >/dev/null 2>&1 && [[ "$file" == *.json ]]; then
        count=$(jq 'length' "$file" 2>/dev/null || echo "0")
        if [ "$count" -ge 650 ] && [ "$count" -le 750 ]; then
            echo "  $file: $count items (matches ~700 range)"
        fi
    else
        lines=$(wc -l < "$file" 2>/dev/null || echo "0")
        if [ "$lines" -ge 650 ] && [ "$lines" -le 750 ]; then
            echo "  $file: $lines lines (matches ~700 range)"
        fi
    fi
done

