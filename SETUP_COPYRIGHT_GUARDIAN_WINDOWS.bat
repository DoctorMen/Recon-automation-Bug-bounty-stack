@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
REM Setup Auto Copyright Guardian to run automatically on Windows

echo ========================================
echo SETUP AUTO COPYRIGHT GUARDIAN
echo ========================================
echo.
echo This will set up automated copyright protection
echo to run every 10 minutes in the background.
echo.
echo Options:
echo 1. Run manually (recommended for testing)
echo 2. Setup Windows Task Scheduler (auto-start)
echo 3. Run once and exit
echo.
set /p choice="Enter your choice (1-3): "

if "%choice%"=="1" goto manual
if "%choice%"=="2" goto scheduler
if "%choice%"=="3" goto once

:manual
echo.
echo Starting manually...
call START_COPYRIGHT_GUARDIAN.bat
goto end

:scheduler
echo.
echo Setting up Windows Task Scheduler...
echo.
echo Creating task: "AutoCopyrightGuardian"
echo Trigger: At startup, repeat every 10 minutes
echo.

schtasks /create /tn "AutoCopyrightGuardian" /tr "\"%CD%\START_COPYRIGHT_GUARDIAN.bat\"" /sc onstart /ru "%USERNAME%" /f

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Task created successfully!
    echo.
    echo The guardian will now run automatically:
    echo - At system startup
    echo - Every 10 minutes
    echo.
    echo To manage:
    echo - View: taskschd.msc
    echo - Stop: schtasks /end /tn "AutoCopyrightGuardian"
    echo - Delete: schtasks /delete /tn "AutoCopyrightGuardian" /f
    echo.
) else (
    echo.
    echo ❌ Failed to create task. Run as Administrator.
)
goto end

:once
echo.
echo Running single scan...
python AUTO_COPYRIGHT_GUARDIAN.py
echo.
echo Scan complete. Run this again anytime to update copyrights.
goto end

:end
echo.
pause
