@echo off
REM Visual Business Representation Launcher
REM Copyright 2025 DoctorMen. All Rights Reserved.

echo ========================================
echo Opening Visual Business Representations
echo ========================================
echo.

REM Convert WSL path to Windows path
set "WSL_PATH=\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack"

echo Opening 1/3: Complete System Showcase...
start "" "%WSL_PATH%\SHOWCASE_WEBPAGE.html"
timeout /t 2 /nobreak >nul

echo Opening 2/3: Mobile App Designs (iPhone + Android)...
start "" "%WSL_PATH%\MOBILE_APP_DESIGNS.html"
timeout /t 2 /nobreak >nul

echo Opening 3/3: 3D Interactive Money-Making Map...
start "" "%WSL_PATH%\3D_PARALLEL_MONEY_MAP.html"

echo.
echo ========================================
echo All visual representations opened!
echo ========================================
echo.
echo You should now see 3 browser tabs:
echo 1. SHOWCASE_WEBPAGE.html - Complete system overview
echo 2. MOBILE_APP_DESIGNS.html - iPhone and Android mockups
echo 3. 3D_PARALLEL_MONEY_MAP.html - Interactive 3D visualization
echo.
pause
