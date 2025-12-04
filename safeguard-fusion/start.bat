@echo off
title SafeGuard Fusion
echo.
echo  ================================
echo   SafeGuard Fusion Desktop App
echo  ================================
echo.
echo  Starting SafeGuard Fusion...
echo.

cd /d "%~dp0"

:: Check if node_modules exists
if not exist "node_modules" (
    echo  Installing dependencies...
    call npm install
    echo.
)

:: Start the Electron app
echo  Launching application...
call npm start

pause
