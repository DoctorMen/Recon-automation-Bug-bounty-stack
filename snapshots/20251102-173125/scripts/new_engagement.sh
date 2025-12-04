#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <DATE_YYYYMMDD> <CLIENT_CODE> [CONSENT_UUID]" >&2
  exit 1
fi

DATE="$1"; CLIENT="$2"; CONSENT="${3:-$(uuidgen 2>/dev/null || echo CONSENT-UUID)}"
ENG_ID="${DATE}-${CLIENT}"
ROOT="output/engagements/${ENG_ID}"

mkdir -p "$ROOT"/{evidence,logs,reports,artifacts}
if [[ -f docs/config.js ]]; then
  cp docs/config.js "$ROOT/artifacts/config.snapshot.js"
fi
echo "$CONSENT" > "$ROOT/artifacts/consent.id"
echo "$ENG_ID" > "$ROOT/artifacts/engagement.id"

echo "Created engagement at $ROOT"
echo "Consent ID: $CONSENT"

