@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
echo ========================================
echo   GET PAID TODAY - AUTOMATED SYSTEM
echo ========================================
echo.
echo Starting automated proposal generator...
echo.

cd /d "%~dp0"

REM Generate 15 proposals
python GET_PAID_TODAY.py --generate 15

echo.
echo ========================================
echo   PROPOSALS GENERATED!
echo ========================================
echo.
echo NEXT STEPS:
echo 1. Open Upwork.com in your browser
echo 2. Search: "urgent security scan"
echo 3. Open proposals from: output/today_money/
echo 4. Apply to 15 jobs (2 minutes each)
echo.
echo Expected Result: $200-$500 by end of day
echo.
echo Press any key to open output folder...
pause > nul

start "" "%~dp0output\today_money"

echo.
echo Opening Upwork.com in browser...
start "" "https://www.upwork.com/nx/find-work/best-matches"

echo.
echo Good luck! Apply fast, win today! 
echo.
pause
