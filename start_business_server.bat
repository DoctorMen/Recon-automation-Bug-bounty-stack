@echo off
REM Copyright © 2025 DoctorMen. All Rights Reserved.
@echo off
cd /d %~dp0\..
echo Starting Business HTML server...
start http://localhost:8000/business.html
python -m http.server 8000

