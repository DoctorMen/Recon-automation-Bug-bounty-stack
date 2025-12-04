#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# =====================================================
# Git auto-sync for recon results
# Author: Recon Automation Stack
# =====================================================
# Usage:
#   ./scripts/git_sync.sh "commit message"
# =====================================================

set -e
cd ~/Recon-automation-Bug-bounty-stack

MSG="${1:-Auto-sync recon results}"
BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "[INFO] Syncing recon outputs to GitHub ..."
git add output/ recon/output/ scripts/ || true
git commit -m "$MSG" || echo "[INFO] Nothing new to commit."
git pull origin "$BRANCH" --rebase
git push origin "$BRANCH"

echo "[INFO] ✅ Git sync complete."
