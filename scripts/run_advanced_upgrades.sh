#!/bin/bash
# run_advanced_upgrades.sh
# Runs the "Top Tier" upgrades (JSINT + GraphQL Scout) on a target list.

TARGET_LIST=$1
OUTPUT_DIR=$2

if [ -z "$TARGET_LIST" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: ./run_advanced_upgrades.sh <target_urls_file> <output_dir>"
    exit 1
fi

echo "[*] Starting Top Tier Upgrade Workflow..."
echo "[*] Target List: $TARGET_LIST"
echo "[*] Output Dir: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# 1. Run JS Intelligence Extractor
echo "---------------------------------------------------"
echo "[1/3] Running JS Intelligence Extractor..."
python3 scripts/js_intel_extractor.py --target "$TARGET_LIST" --output "$OUTPUT_DIR"

# 2. Run GraphQL & API Scout
echo "---------------------------------------------------"
echo "[2/3] Running GraphQL & API Scout..."
python3 scripts/graphql_api_scout.py --input "$OUTPUT_DIR/js_intel_report.json" --output "$OUTPUT_DIR"

# 3. Summary
echo "---------------------------------------------------"
echo "[3/3] Workflow Complete!"
echo "Check '$OUTPUT_DIR/IMMEDIATE_ACTIONS.md' for your manual testing checklist."
