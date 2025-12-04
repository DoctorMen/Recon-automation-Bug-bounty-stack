#!/bin/bash
# GHOST IDE™ Startup Script
# Owner: Khallid Hakeem Nurse

echo "========================================="
echo "🎯 GHOST IDE™ - Starting Live System"
echo "========================================="
echo ""

# Install dependencies if needed
echo "📦 Checking dependencies..."
pip3 install flask flask-cors 2>/dev/null

echo ""
echo "🚀 Starting API Server..."
echo "   URL: http://localhost:5000"
echo ""
echo "Opening GHOST IDE in browser..."
sleep 2

# Start API in background
python3 GHOST_API.py &
API_PID=$!

sleep 3

# Open browser
explorer.exe GHOST_IDE_LIVE.html

echo ""
echo "========================================="
echo "✅ GHOST IDE™ is LIVE!"
echo "========================================="
echo ""
echo "📊 Status:"
echo "   API Server: Running (PID: $API_PID)"
echo "   IDE: Opened in browser"
echo ""
echo "🎯 What's Happening:"
echo "   1. API server listening on port 5000"
echo "   2. IDE connected and showing LIVE status"
echo "   3. Click 'Start Real Scan' to execute"
echo ""
echo "⚠️  To stop:"
echo "   Press Ctrl+C or run: kill $API_PID"
echo ""
echo "========================================="
echo ""

# Keep script running
wait $API_PID
