#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <program-slug>" >&2
  exit 2
fi

PROGRAM="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROGRAM_DIR="$REPO_ROOT/programs/$PROGRAM"
CFG="$PROGRAM_DIR/config.yaml"
PERM="$PROGRAM_DIR/permission.txt"

if [ ! -d "$PROGRAM_DIR" ]; then
  echo "Program directory not found: $PROGRAM_DIR" >&2
  exit 2
fi

# Basic guard: env var must be set manually at runtime
if [ -z "${ENABLE_AUTO_RUN:-}" ]; then
  echo "AUTO-RUN DISABLED: set ENABLE_AUTO_RUN=1 in env to allow program auto runs (safety gate)." >&2
  exit 3
fi

# Config and permission checks
if [ ! -f "$CFG" ]; then
  echo "Missing config.yaml for $PROGRAM" >&2
  exit 4
fi

if [ ! -f "$PERM" ]; then
  echo "Missing permission file for $PROGRAM - place programs/$PROGRAM/permission.txt" >&2
  exit 5
fi

# compute checksum and compare to config (if present)
PERM_SUM=\$(sha256sum "$PERM" | awk '{print \$1}')
EXPECTED=\$(python3 - <<PY
import yaml,sys
cfg='$CFG'
v=yaml.safe_load(open(cfg))
print(v.get('permission_checksum') or '')
PY
)

if [ -n "\$EXPECTED" ] && [ "\$EXPECTED" != "\$PERM_SUM" ]; then
  echo "Permission checksum mismatch for $PROGRAM. Expected \$EXPECTED but permission.txt is \$PERM_SUM" >&2
  exit 6
fi

# Append run metadata to outdir and copy permission for audit
OUTDIR="$REPO_ROOT/output/$PROGRAM/run_\$(date +%Y%m%d_%H%M%S)"
mkdir -p "\$OUTDIR"
cp "$PERM" "\$OUTDIR/permission.txt"
echo "permission_sha256: \$PERM_SUM" > "\$OUTDIR/metadata.txt"
echo "auto-run starting for $PROGRAM; logs in \$OUTDIR"

# Now call the safe pipeline wrappers (these should obey --targets-file and rate limits).
# We intentionally DO NOT perform any discovery here without explicit RUN parameters.
python3 run_pipeline.py --targets-file "$PROGRAM_DIR/targets.txt" --out "$OUTDIR" --concurrency 1 --rate-limit 0.5 --only=subfinder,amass,httpx || true
python3 run_pipeline.py --targets-file "$PROGRAM_DIR/targets.txt" --out "$OUTDIR" --only=nuclei --concurrency 1 --rate-limit 0.5 || true

echo "finished; check \$OUTDIR"
