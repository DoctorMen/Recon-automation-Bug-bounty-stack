#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

SNAP_DIR="snapshots/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SNAP_DIR"

echo "Creating snapshot at $SNAP_DIR"

# Copy key folders (lightweight)
cp -r docs "$SNAP_DIR/docs"
cp -r env "$SNAP_DIR/env"
mkdir -p "$SNAP_DIR/scripts"
cp scripts/*.sh "$SNAP_DIR/scripts/" 2>/dev/null || true

# Archive as tar.gz
tar -czf "$SNAP_DIR.tar.gz" -C snapshots "$(basename "$SNAP_DIR")"

echo "Snapshot saved: $SNAP_DIR and $SNAP_DIR.tar.gz"

