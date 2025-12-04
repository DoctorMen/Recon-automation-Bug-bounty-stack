#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Start Auto Copyright Guardian - Runs every 10 minutes

echo "========================================"
echo "AUTO COPYRIGHT GUARDIAN"
echo "========================================"
echo ""
echo "Starting automated copyright protection..."
echo "Checking every 10 minutes..."
echo ""
echo "Press Ctrl+C to stop"
echo ""

cd "$(dirname "$0")"
python3 AUTO_COPYRIGHT_GUARDIAN.py --daemon --interval 10
