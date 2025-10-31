#!/usr/bin/env bash
set -euo pipefail

PROGRAM="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROGRAM_DIR="$REPO_ROOT/programs/$PROGRAM"
CFG="$PROGRAM_DIR/config.yaml"
PERM="$PROGRAM_DIR/permission.txt"

if [ -z "${ENABLE_AUTO_RUN:-}" ]; then
  echo "AUTO-RUN DISABLED: set ENABLE_AUTO_RUN=1 to enable program runs" >&2
  exit 2
fi

if [ ! -f "$CFG" ]; then
  echo "No config for $PROGRAM ($CFG)" >&2
  exit 2
fi

if [ ! -f "$PERM" ]; then
  echo "No permission file found for $PROGRAM — aborting." >&2
  exit 2
fi

OUTDIR="$REPO_ROOT/output/$PROGRAM/run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
cp "$PERM" "$OUTDIR/permission.txt"

# safe enumeration (conservative)
python3 run_pipeline.py --targets-file "$PROGRAM_DIR/targets.txt" --out "$OUTDIR" --only=subfinder,amass,httpx --concurrency 1 --rate-limit 0.5 || true

# passive nuclei
python3 run_pipeline.py --targets-file "$PROGRAM_DIR/targets.txt" --out "$OUTDIR" --only=nuclei --concurrency 1 --rate-limit 0.5 || true

echo "Finished program run. Logs: $OUTDIR"
