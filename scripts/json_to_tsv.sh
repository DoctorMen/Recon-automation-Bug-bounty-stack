#!/bin/bash
# ==========================================
# JSON → TSV auto-parser for httpx output
# Author: Recon Automation Stack
# ==========================================
# Usage:
#   ./scripts/json_to_tsv.sh input.json output.tsv
# ==========================================

IN="$1"
OUT="$2"

if [ -z "$IN" ] || [ -z "$OUT" ]; then
  echo "Usage: $0 <input_json> <output_tsv>"
  exit 1
fi

if [ ! -f "$IN" ]; then
  echo "[ERROR] Input file not found: $IN"
  exit 2
fi

echo "[INFO] Parsing $IN → $OUT ..."
> "$OUT"

# Read JSONL safely and parse line by line
while read -r line; do
  echo "$line" | jq -r '[.url, (.status_code // "-"), (.title // "-"), ((.tech // []) | join(","))] | @tsv' >> "$OUT"
done < "$IN"

LINES=$(wc -l < "$OUT")
echo "[INFO] Done. Parsed $LINES lines."
