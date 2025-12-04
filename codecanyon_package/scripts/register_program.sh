#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail
if [ -z "${1:-}" ]; then
  echo "Usage: $0 <slug>" >&2
  exit 2
fi
SLUG="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO_ROOT/programs/template"
DEST="$REPO_ROOT/programs/$SLUG"

if [ -d "$DEST" ]; then
  echo "Program already exists: $DEST" >&2
  exit 3
fi

cp -r "$TEMPLATE" "$DEST"
# update slug and name placeholders
sed -i "s/<slug>/$SLUG/g" "$DEST/config.yaml"
sed -i "s/<ORG_NAME>/$SLUG/g" "$DEST/config.yaml"

echo "Created program skeleton: $DEST"
echo "IMPORTANT: replace $DEST/targets.txt with authorized domains and put permission file at $DEST/permission.txt"
echo "Then compute checksum and set permission_checksum in config.yaml:"
echo "  sha256sum $DEST/permission.txt | awk '{print \$1}'"
echo "Then edit $DEST/config.yaml -> permission_checksum: <that-sha256>"
