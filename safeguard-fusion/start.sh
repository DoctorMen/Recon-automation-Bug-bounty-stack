#!/bin/bash
# SafeGuard Fusion - Desktop Application Launcher
# Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.

echo ""
echo "================================"
echo " SafeGuard Fusion Desktop App"
echo "================================"
echo ""
echo "Starting SafeGuard Fusion..."
echo ""

cd "$(dirname "$0")"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
    echo ""
fi

# Start the Electron app
echo "Launching application..."
npm start
