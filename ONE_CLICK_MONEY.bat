@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
REM ONE-CLICK MONEY MAKER
REM Opens everything you need to start earning

echo.
echo ============================================================
echo    💰 ONE-CLICK MONEY MAKER
echo ============================================================
echo.
echo Opening your money-making tools...
echo.

REM Open Money Dashboard
echo [1/4] Opening Money Dashboard...
start "" "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\MONEY_DASHBOARD.html"
timeout /t 2 /nobreak >nul

REM Open Zero Effort Guide
echo [2/4] Opening Zero-Effort Guide...
start "" notepad "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\ZERO_EFFORT_MONEY.md"
timeout /t 2 /nobreak >nul

REM Open Upwork Jobs
echo [3/4] Opening Upwork Jobs (Urgent Security)...
start "" "https://www.upwork.com/nx/search/jobs/?q=security%20scan%20urgent&sort=recency"
timeout /t 2 /nobreak >nul

REM Show Proposal in Terminal
echo [4/4] Your Winning Proposal:
echo.
echo ============================================================
type "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\output\proposals\proposal_300.txt"
echo ============================================================
echo.
echo.
echo ✅ READY TO MAKE MONEY!
echo.
echo NEXT STEPS:
echo 1. Use the Upwork tab to find jobs
echo 2. Copy the proposal above
echo 3. Paste into Upwork applications
echo 4. Change [CLIENT NAME] and price
echo 5. Submit 10 applications (20 minutes)
echo.
echo EXPECTED RESULT: $200-$1,000 TODAY
echo.
echo Press any key to close...
pause >nul
