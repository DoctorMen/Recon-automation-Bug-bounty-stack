#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <target> [confirm]"
  exit 2
fi

TARGET="$1"
CONFIRM="${2:-no}"

# call validation (sets DRY_RUN env var)
./scripts/validate_target.sh "$TARGET" "$CONFIRM"

OUTDIR="$HOME/recon/results/${TARGET}_policyscan_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUTDIR"

  fi
else
  echo "[WARN] httpx not installed; creating placeholder httpx.json"
  echo "[]" > "$OUTDIR/httpx.json"
fi

# prepare nuclei tag filters (nuclei supports -tags filter)
TAG_FILTER="$PREF_TAGS"
if [ -z "$TAG_FILTER" ]; then
  TAG_FILTER="auth,logic,misconfiguration"
fi

# run nuclei with tags (JSON output)
if command -v nuclei >/dev/null 2>&1; then
  if [ "${DRY_RUN:-1}" -eq 1 ]; then
    echo "DRY: nuclei -l $SUBS_FILE -tags \"$TAG_FILTER\" -json -o $OUTDIR/nuclei.json"
    echo "DRY" > "$OUTDIR/nuclei.json"
  else
    nuclei -l "$SUBS_FILE" -tags "$TAG_FILTER" -json -o "$OUTDIR/nuclei.json" || true
  fi
else
  echo "[WARN] nuclei not installed; creating empty nuclei.json"
  echo "[]" > "$OUTDIR/nuclei.json"
fi

# produce triage using parser (if exists)
if [ -f scripts/parse_nuclei_to_triage.py ]; then
  python3 scripts/parse_nuclei_to_triage.py "$OUTDIR/nuclei.json" "$OUTDIR/triage.md" "$TARGET" || true
else
  echo "No parser found; creating basic triage.md"
  cat > "$OUTDIR/triage.md" <<TRI
# Triage for $TARGET

No parser available. Nuclei: $OUTDIR/nuclei.json
HTTPX: $OUTDIR/httpx.json

TRI
fi

echo "[OK] Policy scan complete. Results in $OUTDIR"
# read preferred tags for this target (fallback to default)
PREF_TAGS=$(python3 - "$TARGET" <<'PY'
import sys, yaml
target = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    with open("config/target_policies.yaml") as f:
        cfg = yaml.safe_load(f)
    t = cfg.get("targets", {}).get(target, {}) or cfg.get("default", {})
    tags = t.get("preferred_nuclei_tags", [])
    print(" ".join(tags))
except Exception:
    print("")
PY
)
