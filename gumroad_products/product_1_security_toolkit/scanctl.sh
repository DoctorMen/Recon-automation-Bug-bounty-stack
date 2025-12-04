#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
PROGRAMS_DIR="$REPO_ROOT/programs"

usage(){
  cat <<EOF
scanctl - lightweight program manager

Usage:
  ./scanctl.sh list                # list available programs
  ./scanctl.sh info <program>      # show program config summary
  ./scanctl.sh preflight <program> # show what will run (no tools executed)
  ./scanctl.sh run <program>       # interactive run (uses confirm_and_run.sh behind the scenes)
EOF
}

if [ $# -lt 1 ]; then usage; exit 1; fi

cmd="$1"; shift || true

list_programs(){
  if [ ! -d "$PROGRAMS_DIR" ]; then echo "No programs directory"; exit 0; fi
  for d in "$PROGRAMS_DIR"/*; do
    [ -d "$d" ] || continue
    pname=$(basename "$d")
    echo "- $pname"
  done
}

show_info(){
  prog="$1"
  cfg="$PROGRAMS_DIR/$prog/config.yaml"
  if [ ! -f "$cfg" ]; then echo "No config for $prog"; exit 2; fi
  echo "Program: $prog"
  echo
  echo "--- Config ---"
  sed -n '1,200p' "$cfg"
  echo
  echo "--- Targets ---"
  targetfile="$PROGRAMS_DIR/$prog/targets.txt"
  if [ -f "$targetfile" ]; then sed -n '1,200p' "$targetfile"; else echo "(no targets.txt found)"; fi
  echo
  echo "--- Permission File SHA256 ---"
  perm="$PROGRAMS_DIR/$prog/permission.txt"
  if [ -f "$perm" ]; then sha256sum "$perm" | awk '{print $1}'; else echo "(none)"; fi
}

preflight(){
  prog="$1"
  cfg="$PROGRAMS_DIR/$prog/config.yaml"
  tfile="$PROGRAMS_DIR/$prog/targets.txt"
  if [ ! -f "$cfg" ] || [ ! -f "$tfile" ]; then echo "Missing config or targets for $prog"; exit 2; fi

  echo "=== PREFLIGHT for $prog ==="
  echo "--- Targets ---"
  sed -n '1,50p' "$tfile"
  echo
  echo "--- Config Summary ---"
  python3 - <<PY
import yaml
cfg='$cfg'
v=yaml.safe_load(open(cfg))
for key,val in v.items():
    print(f"{key}: {val}")
PY
  echo
  echo "Use: ./scanctl.sh run $prog"
}

interactive_run(){
  prog="$1"
  prog_targets="$PROGRAMS_DIR/$prog/targets.txt"
  if [ ! -f "$prog_targets" ]; then echo "Missing $prog_targets"; exit 2; fi

  ./confirm_and_run.sh "$prog_targets" --out "output/$prog/run_$(date +%Y%m%d_%H%M%S)"
}

case "$cmd" in
  list) list_programs ;;
  info) show_info "$1" ;;
  preflight) preflight "$1" ;;
  run) interactive_run "$1" ;;
  *) usage; exit 1 ;;
esac
