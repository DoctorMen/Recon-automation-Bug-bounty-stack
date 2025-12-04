#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <snapshots/DATE-TIME or snapshots/DATE-TIME.tar.gz>" >&2
  exit 1
fi

SRC="$1"
if [[ -f "$SRC" && "$SRC" == *.tar.gz ]]; then
  TMPDIR=$(mktemp -d)
  tar -xzf "$SRC" -C "$TMPDIR"
  SRC="$TMPDIR/$(basename "${SRC%.tar.gz}")"
fi

[[ -d "$SRC" ]] || { echo "Snapshot directory not found: $SRC" >&2; exit 1; }

echo "Restoring from $SRC"
rsync -a --delete "$SRC/docs/" docs/
rsync -a --delete "$SRC/env/" env/
rsync -a "$SRC/scripts/" scripts/ 2>/dev/null || true

echo "Restore complete. Review changes before committing."

