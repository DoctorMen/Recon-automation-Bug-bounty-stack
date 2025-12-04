@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
REM Start Auto Copyright Guardian - Runs every 10 minutes

echo ========================================
echo AUTO COPYRIGHT GUARDIAN
echo ========================================
echo.
echo Starting automated copyright protection...
echo Checking every 10 minutes...
echo.
echo Press Ctrl+C to stop
echo.

cd /d "%~dp0"
python AUTO_COPYRIGHT_GUARDIAN.py --daemon --interval 10

pause
