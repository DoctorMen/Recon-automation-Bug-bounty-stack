@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
REM ============================================================================
REM START 4-HOUR AUTONOMOUS AGENT LOOP (Windows)
REM 
REM This script starts the autonomous agent loop system with:
REM - 4-hour continuous runtime
REM - Idempotent task execution
REM - Self-healing error recovery
REM - Real-time monitoring dashboard
REM ============================================================================

echo ╔══════════════════════════════════════════════════════════╗
echo ║                                                          ║
echo ║       AUTONOMOUS AGENT LOOP - 4 HOUR RUNTIME             ║
echo ║                                                          ║
echo ║  ✓ Idempotent Operations                                ║
echo ║  ✓ Self-Healing Recovery                                ║
echo ║  ✓ Multi-Agent Coordination                             ║
echo ║  ✓ Real-Time Monitoring                                 ║
echo ║                                                          ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo ✅ Python found
echo.

REM Install dependencies
echo 📦 Checking dependencies...
python -c "import psutil" 2>nul
if errorlevel 1 (
    echo 📦 Installing psutil...
    pip install psutil
)

echo ✅ Dependencies OK
echo.

REM Create logs directory
if not exist logs mkdir logs

REM Ask for confirmation
echo 🤖 This will start the autonomous agent loop for 4 hours.
echo    Tasks will run automatically on intervals:
echo    - Recon scan (every 30 min)
echo    - HTTPx probe (every 40 min)
echo    - Nuclei scan (every 1 hour)
echo    - Reports (every 20 min)
echo    - Performance monitoring (every 5 min)
echo.
echo    Press Ctrl+C to stop at any time.
echo.
set /p confirm="Start now? (y/n) "

if /i not "%confirm%"=="y" (
    echo ❌ Cancelled
    pause
    exit /b 0
)

echo.
echo 🚀 Starting 4-hour agent loop...
echo 📊 Opening monitoring dashboard...
echo.

REM Open dashboard
start "" "AGENT_LOOP_DASHBOARD.html"

REM Start the agent loop
python scripts\autonomous_agent_loop.py --hours 4.0

echo.
echo 🏁 Agent loop completed!
echo 📊 Check logs\agent_loop.log for details
echo 💾 State saved in .agent_loop_state.db
echo.
pause
