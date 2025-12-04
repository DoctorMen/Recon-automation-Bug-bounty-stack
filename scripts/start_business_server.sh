#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
cd "$(dirname "$0")/.."
echo "🚀 Starting Business HTML Server..."
echo "📱 Opening browser..."
sleep 1
python3 -m http.server 8000 &
SERVER_PID=$!
sleep 2
echo ""
echo "✅ Server running at: http://localhost:8000/business.html"
echo ""
echo "Press Ctrl+C to stop the server"
echo "$SERVER_PID" > /tmp/business_server.pid
wait $SERVER_PID

