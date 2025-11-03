#!/usr/bin/env bash
set -euo pipefail

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p dist
if command -v zip >/dev/null 2>&1; then
  OUT="dist/docs-${TS}.zip"
  zip -qr "$OUT" docs
  echo "$OUT"
else
  OUT="dist/docs-${TS}.tar.gz"
  tar -czf "$OUT" docs
  echo "$OUT"
fi


