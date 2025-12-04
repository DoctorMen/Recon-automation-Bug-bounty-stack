@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
echo ========================================
echo Opening ALL Your Business Presentations
echo ========================================
echo.

set "PATH=%~dp0"

echo Opening Business #1: ParallelProfit (3D Money-Making System)
echo.
start "" "%PATH%SHOWCASE_WEBPAGE.html"
timeout /t 2 /nobreak >nul

start "" "%PATH%3D_PARALLEL_MONEY_MAP.html"
timeout /t 2 /nobreak >nul

start "" "%PATH%MOBILE_APP_DESIGNS.html"
timeout /t 2 /nobreak >nul

echo.
echo Opening Business #2: WorktreeManager (Git Tool)
echo.
start "" "%PATH%WORKTREE_BLEEDING_EDGE.html"

echo.
echo ========================================
echo ALL 4 BUSINESS PRESENTATIONS OPENED!
echo ========================================
echo.
echo You should now see:
echo 1. SHOWCASE_WEBPAGE.html - ParallelProfit overview
echo 2. 3D_PARALLEL_MONEY_MAP.html - THE 3D INTERACTIVE ONE
echo 3. MOBILE_APP_DESIGNS.html - iPhone and Android mockups
echo 4. WORKTREE_BLEEDING_EDGE.html - WorktreeManager bleeding edge UI
echo.
pause
