#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Start Breach Guardian - Real-time security breach detection

echo "========================================"
echo "   BREACH GUARDIAN - SECURITY MONITOR"
echo "========================================"
echo ""
echo "Starting real-time breach detection..."
echo "Monitoring for security threats..."
echo ""
echo "Alerts will be sent immediately via:"
echo "- Discord webhook"
echo "- Email (if configured)"
echo "- SMS (if configured)"
echo ""
echo "Press Ctrl+C to stop"
echo ""

cd "$(dirname "$0")"
python3 BREACH_GUARDIAN.py --daemon --interval 5
