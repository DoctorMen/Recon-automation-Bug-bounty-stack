@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
cd /d %~dp0
echo Starting SecurityScore server...
start http://localhost:8000/standalone.html
python -m http.server 8000

