@echo off
REM Generate all PlantUML diagrams in the current directory and subdirectories
REM Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.

echo Creating output directories...
if not exist "png" mkdir png

for /r %%f in (*.puml) do (
    echo Generating diagram for %%~nxf...
    set "relpath=%%~pf"
    set "relpath=!relpath:%CD%=!"
    set "relpath=!relpath:~1!"
    
    if not exist "png\!relpath!" mkdir "png\!relpath!"
    
    plantuml -tpng "%%f" -o "%CD%\png\!relpath!"
)

echo.
echo All diagrams generated in the png\ directory
pause
