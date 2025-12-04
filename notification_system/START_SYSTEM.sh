#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.

echo "========================================"
echo " TIMELINE NOTIFICATION SYSTEM"
echo " Bleeding Edge UI - Enterprise Security"
echo "========================================"
echo ""

echo "[1/4] Installing Python dependencies..."
cd backend
pip3 install -r requirements.txt

echo ""
echo "[2/4] Starting API Server..."
python3 server.py &
API_PID=$!

echo ""
echo "[3/4] Starting Email Scheduler..."
python3 email_scheduler.py &
SCHEDULER_PID=$!

echo ""
echo "[4/4] Starting Frontend Server..."
cd ../frontend
python3 -m http.server 8080 &
FRONTEND_PID=$!

echo ""
echo "========================================"
echo " SYSTEM RUNNING!"
echo "========================================"
echo " API:       http://localhost:5000"
echo " Dashboard: http://localhost:8080"
echo "========================================"
echo ""
echo "Process IDs:"
echo " API Server: $API_PID"
echo " Scheduler:  $SCHEDULER_PID"
echo " Frontend:   $FRONTEND_PID"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for Ctrl+C
trap "kill $API_PID $SCHEDULER_PID $FRONTEND_PID; exit" INT
wait
