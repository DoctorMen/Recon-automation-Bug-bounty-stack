#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

TARGETS_FILE="${1:-targets.txt}"
shift || true

if [ ! -f "$TARGETS_FILE" ]; then
  echo "ERROR: targets file not found: $TARGETS_FILE" >&2
  exit 2
fi

FIRST_LINE=$(sed -n '1p' "$TARGETS_FILE" | tr -d '\r\n')
if [ -z "$FIRST_LINE" ]; then
  echo "ERROR: targets file empty. Add authorized domain first line."
  exit 2
fi

echo "CONFIRM SCAN TARGET:"
echo " Authorized target: $FIRST_LINE"
read -p "Type domain to confirm: " CONFIRM
[ "$CONFIRM" = "$FIRST_LINE" ] || { echo "Mismatch — aborting."; exit 3; }

CONCURRENCY="${CONCURRENCY:-1}"
RATE_LIMIT="${RATE_LIMIT:-1}"

python3 run_pipeline.py --targets-file "$TARGETS_FILE" --concurrency "$CONCURRENCY" --rate-limit "$RATE_LIMIT" "$@"
