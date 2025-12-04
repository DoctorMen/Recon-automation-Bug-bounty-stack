# SafeGuard Fusion - Windows PowerShell Launcher
# Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host " SafeGuard Fusion Desktop App" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Get the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Change to the safeguard-fusion directory
Set-Location $scriptDir

# Check if Node.js is installed
try {
    $nodeVersion = node --version
    Write-Host "Node.js version: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Node.js is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if node_modules exists
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    npm install
    Write-Host ""
}

# Start the Electron app
Write-Host "Launching SafeGuard Fusion..." -ForegroundColor Green
Write-Host ""
npm start
