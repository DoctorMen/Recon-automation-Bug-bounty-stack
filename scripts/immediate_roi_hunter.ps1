# Immediate ROI Bug Bounty Hunter - PowerShell Wrapper
# Cross-platform wrapper for Windows PowerShell users

param(
    [switch]$Resume,
    [int]$Stage = 0,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$PythonScript = Join-Path $ScriptDir "immediate_roi_hunter.py"

# Check if Python is available
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
} else {
    Write-Host "ERROR: Python not found. Please install Python 3." -ForegroundColor Red
    exit 1
}

# Build command
$args = @()
if ($Resume) {
    $args += "--resume"
}
if ($Stage -gt 0) {
    $args += "--stage"
    $args += $Stage.ToString()
}
if ($Force) {
    $args += "--force"
}

# Run Python script
Write-Host "=" * 60
Write-Host "Immediate ROI Bug Bounty Hunter (PowerShell)" -ForegroundColor Cyan
Write-Host "=" * 60

& $pythonCmd $PythonScript $args

if ($LASTEXITCODE -ne 0) {
    Write-Host "Script failed with exit code: $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

