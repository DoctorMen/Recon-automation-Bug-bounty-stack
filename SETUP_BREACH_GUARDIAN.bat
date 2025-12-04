@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
REM Setup Breach Guardian - Configure alerts and auto-start

echo ========================================
echo    BREACH GUARDIAN SETUP
echo ========================================
echo.
echo This will configure real-time security monitoring
echo and immediate breach alerts.
echo.
echo Setup Options:
echo 1. Configure Discord webhook (RECOMMENDED)
echo 2. Run test check
echo 3. Start continuous monitoring
echo 4. Setup Windows Task Scheduler (auto-start)
echo 5. Exit
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto discord
if "%choice%"=="2" goto test
if "%choice%"=="3" goto start
if "%choice%"=="4" goto scheduler
if "%choice%"=="5" goto end

:discord
echo.
echo ========================================
echo DISCORD WEBHOOK SETUP
echo ========================================
echo.
echo Discord webhooks provide the FASTEST breach alerts.
echo.
echo Steps to get your webhook URL:
echo 1. Open Discord
echo 2. Go to Server Settings ^> Integrations
echo 3. Create Webhook
echo 4. Copy webhook URL
echo.
set /p webhook="Paste your Discord webhook URL: "

if "%webhook%"=="" (
    echo Error: Webhook URL cannot be empty
    goto discord
)

python BREACH_GUARDIAN.py --setup-discord "%webhook%"
echo.
echo ✅ Discord alerts configured!
echo.
echo Test alert will be sent on next breach detection.
echo.
pause
goto end

:test
echo.
echo Running test security check...
python BREACH_GUARDIAN.py
echo.
pause
goto end

:start
echo.
echo Starting continuous monitoring...
call START_BREACH_GUARDIAN.bat
goto end

:scheduler
echo.
echo ========================================
echo WINDOWS TASK SCHEDULER SETUP
echo ========================================
echo.
echo This will create a task to run Breach Guardian
echo automatically at system startup.
echo.

schtasks /create /tn "BreachGuardian" /tr "\"%CD%\START_BREACH_GUARDIAN.bat\"" /sc onstart /ru "%USERNAME%" /f

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Task created successfully!
    echo.
    echo Breach Guardian will now run automatically:
    echo - At system startup
    echo - Continuous monitoring
    echo - Immediate breach alerts
    echo.
    echo To manage:
    echo - View: taskschd.msc
    echo - Stop: schtasks /end /tn "BreachGuardian"
    echo - Delete: schtasks /delete /tn "BreachGuardian" /f
    echo.
) else (
    echo.
    echo ❌ Failed to create task. Run as Administrator.
)
pause
goto end

:end
echo.
