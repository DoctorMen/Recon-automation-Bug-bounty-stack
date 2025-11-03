#!/usr/bin/env bash
set -euo pipefail

if ! command -v powershell.exe >/dev/null 2>&1; then
  echo "powershell.exe not available from WSL. Open files from Windows Explorer: \\wsl$\\Ubuntu\\home\\ubuntu\\Recon-automation-Bug-bounty-stack\\docs" >&2
  exit 1
fi

ROOT="\\\\wsl$\\\\Ubuntu\\\\home\\\\ubuntu\\\\Recon-automation-Bug-bounty-stack\\\\docs\\\\"
for p in "$@"; do
  pp="${ROOT}${p}"
  powershell.exe -NoProfile -Command "Start-Process '${pp}'" >/dev/null 2>&1 || true
done

echo "Opened: $*"



