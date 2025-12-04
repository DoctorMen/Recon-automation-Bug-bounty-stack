#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <target> [confirm]"
  exit 2
fi

TARGET="$1"
CONFIRM_FLAG="${2:-no}"

# kill-switch
if [ -f "config/disable_automations" ]; then
  echo "[ERROR] Automations disabled (config/disable_automations exists)."
  exit 10
fi

ALLOWED="config/allowed_targets.txt"
PERM_DIR="config/permissions"
POLICY_FILE="config/scan_policy.yaml"

if [ ! -f "$ALLOWED" ]; then
  echo "[ERROR] $ALLOWED missing."
  exit 3
fi

# exact-match check
if ! grep -Fxq "$TARGET" "$ALLOWED"; then
  echo "[ERROR] $TARGET not listed in $ALLOWED."
  exit 4
fi

# permission file check
PERM_FILE="$PERM_DIR/${TARGET}.permission"
if [ ! -f "$PERM_FILE" ]; then
  echo "[ERROR] Permission file $PERM_FILE missing."
  exit 5
fi

# default dry-run unless confirm passed
if [ "$CONFIRM_FLAG" != "confirm" ]; then
  echo "[WARN] Dry-run mode for $TARGET. Pass 'confirm' to run live."
  export DRY_RUN=1
else
  export DRY_RUN=0
fi

export SCAN_POLICY_FILE="$POLICY_FILE"
echo "[OK] Target validated: $TARGET (dry_run=${DRY_RUN})"
