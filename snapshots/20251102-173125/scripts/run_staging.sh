#!/usr/bin/env bash
set -euo pipefail

OUT_ROOT="env/staging/output/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_ROOT"/{evidence,logs,reports}

echo "Starting staging dry‑run at $OUT_ROOT"

# Record config snapshot if exists
if [[ -f docs/config.js ]]; then cp docs/config.js "$OUT_ROOT/config.snapshot.js"; fi

# Simulate discovery and scanning (no network impact)
cp env/staging/targets.txt "$OUT_ROOT/targets.txt"
echo "httpx simulated fingerprint" > "$OUT_ROOT/logs/httpx.log"
echo "nuclei simulated safe scan" > "$OUT_ROOT/logs/nuclei.log"

# Produce a sample report referencing docs/sample_report.html
{
  echo "# Staging Summary"
  echo
  echo "- Run: $(date -Iseconds)"
  echo "- Targets: $(wc -l < env/staging/targets.txt)"
  echo "- Evidence: see evidence/ and logs/"
  echo "- Sample report: docs/sample_report.html"
} > "$OUT_ROOT/reports/summary.md"

echo "Done. See $OUT_ROOT/reports/summary.md"

