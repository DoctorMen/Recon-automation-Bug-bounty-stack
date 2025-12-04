# ============================================
# SECURE DASHBOARD LAUNCHER (PowerShell)
# Starts local-only web server for dashboard
# NO EXTERNAL CONNECTIONS | OPSEC COMPLIANT
# ============================================

param(
    [int]$Port = 8888
)

$Host = "127.0.0.1"  # LOCAL ONLY - DO NOT CHANGE
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "============================================" -ForegroundColor Blue
Write-Host "   SECURE BUG BOUNTY DASHBOARD" -ForegroundColor Blue
Write-Host "   OPSEC MODE | LOCAL ONLY" -ForegroundColor Blue
Write-Host "============================================" -ForegroundColor Blue
Write-Host ""

# ============================================
# SECURITY CHECKS
# ============================================

Write-Host "🔒 Running security checks..." -ForegroundColor Yellow

# Check we're in the right directory
if (-not (Test-Path "$ScriptDir\index.html")) {
    Write-Host "ERROR: Dashboard files not found" -ForegroundColor Red
    Write-Host "Please run this script from the dashboard directory"
    exit 1
}

# Check for SECURITY.md
if (-not (Test-Path "$ScriptDir\SECURITY.md")) {
    Write-Host "WARNING: SECURITY.md not found" -ForegroundColor Yellow
}

Write-Host "✓ Security checks complete" -ForegroundColor Green
Write-Host ""

# ============================================
# CHECK FOR EXISTING SERVER
# ============================================

$UsedPort = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($UsedPort) {
    Write-Host "⚠️  Port $Port is already in use" -ForegroundColor Yellow
    Write-Host "Attempting to find available port..."
    $Port++
    while (Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue) {
        $Port++
        if ($Port -gt 9000) {
            Write-Host "ERROR: Could not find available port" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "✓ Using port $Port" -ForegroundColor Green
}

# ============================================
# START SERVER
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   DASHBOARD LAUNCHING" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "📍 URL:      http://$Host`:$Port" -ForegroundColor Blue
Write-Host "🔒 OPSEC:    ACTIVE" -ForegroundColor Blue
Write-Host "📡 Network:  LOCAL ONLY ($Host)" -ForegroundColor Blue
Write-Host "🛡️  Security: All external connections BLOCKED" -ForegroundColor Blue
Write-Host ""
Write-Host "⚠️  SECURITY REMINDERS:" -ForegroundColor Yellow
Write-Host "  • Dashboard accessible ONLY from this machine" -ForegroundColor Red
Write-Host "  • Redaction is ENABLED by default" -ForegroundColor Red
Write-Host "  • Review SECURITY.md before sharing screenshots" -ForegroundColor Red
Write-Host "  • DO NOT expose to public networks" -ForegroundColor Red
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the dashboard" -ForegroundColor Yellow
Write-Host ""

# ============================================
# LAUNCH WEB SERVER
# ============================================

Set-Location $ScriptDir

# Check for Python 3
$Python3 = Get-Command python3 -ErrorAction SilentlyContinue
$Python = Get-Command python -ErrorAction SilentlyContinue

if ($Python3) {
    Write-Host "Starting Python 3 HTTP server..." -ForegroundColor Blue
    Write-Host ""
    
    try {
        # Open browser automatically
        Start-Process "http://$Host`:$Port"
        
        # Start server
        & python3 -m http.server $Port --bind $Host
    }
    catch {
        Write-Host "Server stopped" -ForegroundColor Yellow
    }
}
elseif ($Python) {
    Write-Host "Starting Python HTTP server..." -ForegroundColor Blue
    Write-Host ""
    
    try {
        # Open browser automatically
        Start-Process "http://$Host`:$Port"
        
        # Start server
        & python -m http.server $Port --bind $Host
    }
    catch {
        Write-Host "Server stopped" -ForegroundColor Yellow
    }
}
else {
    Write-Host "ERROR: Python not found" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Python 3:" -ForegroundColor Yellow
    Write-Host "  • Download from: https://www.python.org/downloads/"
    Write-Host "  • Or use Chocolatey: choco install python"
    exit 1
}

# ============================================
# CLEANUP ON EXIT
# ============================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   DASHBOARD SHUTTING DOWN" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "✓ Server stopped safely" -ForegroundColor Green
Write-Host "✓ Local connections closed" -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard session ended" -ForegroundColor Blue
Write-Host ""

