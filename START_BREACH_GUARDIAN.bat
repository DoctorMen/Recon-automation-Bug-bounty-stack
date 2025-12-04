@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
REM Start Breach Guardian - Real-time security breach detection

echo ========================================
echo    BREACH GUARDIAN - SECURITY MONITOR
echo ========================================
echo.
echo Starting real-time breach detection...
echo Monitoring for security threats...
echo.
echo Alerts will be sent immediately via:
echo - Discord webhook
echo - Email (if configured)
echo - SMS (if configured)
echo.
echo Press Ctrl+C to stop
echo.

cd /d "%~dp0"
python BREACH_GUARDIAN.py --daemon --interval 5

pause
