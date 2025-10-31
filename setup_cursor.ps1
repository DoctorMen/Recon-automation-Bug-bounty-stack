# PowerShell Setup Script for Cursor
# Run this in PowerShell to set up the recon stack in Cursor

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Recon Stack - Cursor Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get current directory (where this script is)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "Working directory: $ScriptDir" -ForegroundColor Green
Write-Host ""

# Check Python
Write-Host "Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found! Install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Check tools
Write-Host ""
Write-Host "Checking recon tools..." -ForegroundColor Yellow

$tools = @("subfinder", "amass", "httpx", "nuclei", "dnsx")
$missing = @()

foreach ($tool in $tools) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "✓ $tool found" -ForegroundColor Green
    } else {
        Write-Host "✗ $tool not found" -ForegroundColor Red
        $missing += $tool
    }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "Missing tools: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host "Install via:" -ForegroundColor Yellow
    Write-Host "  go install -v github.com/projectdiscovery/$tool/..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Or download from GitHub releases" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "✓ All tools found!" -ForegroundColor Green
}

# Check targets.txt
Write-Host ""
Write-Host "Checking configuration..." -ForegroundColor Yellow
$targetsFile = Join-Path $ScriptDir "targets.txt"

if (Test-Path $targetsFile) {
    $targetCount = (Get-Content $targetsFile | Where-Object { $_ -and $_ -notmatch '^\s*#' }).Count
    Write-Host "✓ targets.txt found with $targetCount target(s)" -ForegroundColor Green
} else {
    Write-Host "✗ targets.txt not found" -ForegroundColor Yellow
    Write-Host "  Creating template..." -ForegroundColor Yellow
    @"
# Recon Stack Targets Configuration
# Add authorized domains for scanning (one per line)
# Lines starting with # are ignored
#
# IMPORTANT: Only include domains you are authorized to test!
#
# Example:
# example.com
# authorized-target.io
"@ | Out-File -FilePath $targetsFile -Encoding UTF8
    Write-Host "  ✓ Created template targets.txt" -ForegroundColor Green
    Write-Host "  Edit it and add your targets!" -ForegroundColor Yellow
}

# Create output directory
$outputDir = Join-Path $ScriptDir "output"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    Write-Host "✓ Created output directory" -ForegroundColor Green
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Edit targets.txt with your authorized domains" -ForegroundColor White
Write-Host "  2. Run: python run_pipeline.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or run individual agents:" -ForegroundColor Yellow
Write-Host "  python run_recon.py" -ForegroundColor Cyan
Write-Host "  python run_httpx.py" -ForegroundColor Cyan
Write-Host "  python run_nuclei.py" -ForegroundColor Cyan
Write-Host "  python scripts/triage.py" -ForegroundColor Cyan
Write-Host "  python scripts/generate_report.py" -ForegroundColor Cyan
Write-Host ""

