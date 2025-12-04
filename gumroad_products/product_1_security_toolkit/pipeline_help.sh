#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
echo "=== SAFE RECON HELP MODE ==="
echo "This tool will not run any scans automatically."
echo
echo "✅ Tools auto-install"
echo "✅ Targets locked to targets.txt"
echo "✅ Human confirmation required for real scans"
echo
echo "To run a SAFE scan:"
echo "  ./confirm_and_run.sh targets.txt --out output/run_$(date +%Y%m%d_%H%M%S)"
echo
echo "Showing raw pipeline help (if supported):"
python3 run_pipeline.py --help --no-run 2>/dev/null || python3 run_pipeline.py --help 2>/dev/null || echo 'no help available'
