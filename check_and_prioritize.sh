#!/bin/bash
# Quick fix - Check what files exist and help prioritize

cd ~/Recon-automation-Bug-bounty-stack

echo "============================================================"
echo "Checking for Discovery Results"
echo "============================================================"
echo ""

# Check for files
echo "[*] Checking output directory..."
if [ -f "output/http.json" ]; then
    echo "✅ Found: output/http.json"
    echo "   Lines: $(wc -l < output/http.json)"
    echo "   Sample:"
    head -2 output/http.json | head -1
    echo ""
else
    echo "❌ Missing: output/http.json"
fi

if [ -d "output/immediate_roi" ]; then
    echo "[*] Checking output/immediate_roi/..."
    ls -lh output/immediate_roi/ 2>/dev/null | head -10
    echo ""
    
    if [ -f "output/immediate_roi/api_paths.txt" ]; then
        echo "✅ Found: output/immediate_roi/api_paths.txt"
        echo "   Lines: $(wc -l < output/immediate_roi/api_paths.txt)"
        echo ""
    fi
    
    if [ -f "output/immediate_roi/api_endpoints.json" ]; then
        echo "✅ Found: output/immediate_roi/api_endpoints.json"
        echo "   Lines: $(wc -l < output/immediate_roi/api_endpoints.json)"
        echo ""
    fi
else
    echo "❌ Missing: output/immediate_roi/"
fi

echo ""
echo "============================================================"
echo "Running Priority Selector..."
echo "============================================================"
echo ""

python3 scripts/prioritize_endpoints.py


