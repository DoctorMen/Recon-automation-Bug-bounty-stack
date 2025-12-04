#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Process Upwork Screenshot - Automatic Proposal Generation

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

if [ -z "$1" ]; then
    echo "📸 Upwork Screenshot Processor"
    echo ""
    echo "Usage: $0 <screenshot_path>"
    echo ""
    echo "This will:"
    echo "  1. Analyze the screenshot"
    echo "  2. Extract job details"
    echo "  3. Generate proposal automatically"
    echo "  4. Handle errors with retries"
    echo ""
    echo "Example:"
    echo "  $0 ~/Downloads/upwork_job.png"
    exit 1
fi

SCREENSHOT_PATH="$1"

echo "🤖 Processing Upwork screenshot..."
echo "📸 File: $SCREENSHOT_PATH"
echo ""

python3 scripts/screenshot_command.py "$SCREENSHOT_PATH"

