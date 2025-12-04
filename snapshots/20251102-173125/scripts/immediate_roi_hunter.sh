#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Immediate ROI Bug Bounty Hunter - Bash Wrapper
# Idempotent automation for high-value vulnerabilities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/immediate_roi_hunter.py"

# Parse arguments
RESUME=false
STAGE=0
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --resume)
            RESUME=true
            shift
            ;;
        --stage)
            STAGE="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo "ERROR: Python not found. Please install Python 3."
    exit 1
fi

# Build command
CMD="$PYTHON_CMD $PYTHON_SCRIPT"
if [ "$RESUME" = true ]; then
    CMD="$CMD --resume"
fi
if [ "$STAGE" -gt 0 ]; then
    CMD="$CMD --stage $STAGE"
fi
if [ "$FORCE" = true ]; then
    CMD="$CMD --force"
fi

# Run
echo "============================================================"
echo "Immediate ROI Bug Bounty Hunter (Bash)"
echo "============================================================"

eval $CMD

exit $?

