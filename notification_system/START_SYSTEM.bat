@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
echo ========================================
echo  TIMELINE NOTIFICATION SYSTEM
echo  Bleeding Edge UI - Enterprise Security
echo ========================================
echo.

echo [1/4] Installing Python dependencies...
cd backend
pip install -r requirements.txt

echo.
echo [2/4] Starting API Server...
start "Notification API" python server.py

echo.
echo [3/4] Starting Email Scheduler...
start "Email Scheduler" python email_scheduler.py

echo.
echo [4/4] Opening Dashboard...
cd ..\frontend
start "Dashboard" http://localhost:8080
python -m http.server 8080

echo.
echo ========================================
echo  SYSTEM RUNNING!
echo ========================================
echo  API:       http://localhost:5000
echo  Dashboard: http://localhost:8080
echo ========================================
echo.

pause
