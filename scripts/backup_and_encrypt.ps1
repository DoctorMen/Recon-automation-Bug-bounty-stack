<#
Creates a timestamped backup of key project assets and encrypts it.

Priority encryption tools (auto-detected):
1) gpg (AES256, symmetric)
2) 7z (AES256, header-encrypted)
3) openssl (AES-256-CBC, PBKDF2)
4) DPAPI (machine/user-bound; last resort, Windows-only)

Usage (PowerShell):
  powershell -ExecutionPolicy Bypass -File scripts\backup_and_encrypt.ps1 -OutputDir backups
  powershell -ExecutionPolicy Bypass -File scripts\backup_and_encrypt.ps1 -OutputDir backups -ArchiveName myrun

If -Passphrase is omitted, you will be prompted securely.
#>

[CmdletBinding()]
param(
  [string]$OutputDir = "backups",
  [string]$ArchiveName,
  [SecureString]$Passphrase
)

function Convert-SecureStringToPlainText {
  param([SecureString]$Secure)
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  }
  finally {
    if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
  }
}

function Test-Cmd {
  param([string]$Name)
  try { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) } catch { return $false }
}

function New-DirectoryIfMissing {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { [void](New-Item -ItemType Directory -Path $Path) }
}

$ErrorActionPreference = "Stop"

# Resolve repo root as parent of scripts folder
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ([string]::IsNullOrWhiteSpace($ArchiveName)) { $ArchiveName = "recon-session-$timestamp" }

$stagingDir = Join-Path $env:TEMP "recon-session-$timestamp"
New-DirectoryIfMissing -Path $stagingDir

Write-Host "Staging files in: $stagingDir" -ForegroundColor Cyan

# Define items to include if present
$candidateItems = @(
  "output",
  "targets.txt",
  "agents.json",
  "README.md",
  "README_WINDOWS.md",
  "README_PROCESS_RESULTS.md",
  "SCAN_SUMMARY.md",
  "scripts",
  "ci",
  "workflows",
  "run_pipeline.py",
  "scripts/run_pipeline.sh",
  "scripts/agent_orchestrator.py",
  "docs"
)

# Copy existing items into staging
foreach ($item in $candidateItems) {
  $src = Join-Path $repoRoot $item
  if (Test-Path -LiteralPath $src) {
    $dest = Join-Path $stagingDir $item
    New-DirectoryIfMissing -Path (Split-Path -Parent $dest)
    Write-Host "Including: $item" -ForegroundColor Green
    Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# System/context summary
$metaDir = Join-Path $stagingDir "session_meta"
New-DirectoryIfMissing -Path $metaDir

@(
  "Date: $(Get-Date -Format o)",
  "User: $env:USERNAME",
  "Computer: $env:COMPUTERNAME",
  "OS: $([System.Environment]::OSVersion.VersionString)",
  "PWD: $(Get-Location)"
) | Out-File -FilePath (Join-Path $metaDir "system_info.txt") -Encoding UTF8

# Git summary if git repo
try {
  Push-Location $repoRoot
  if (Test-Cmd git) {
    git -c core.autocrlf=false status --porcelain=v1 2>$null | Out-File -FilePath (Join-Path $metaDir "git_status.txt") -Encoding UTF8
    git -c core.autocrlf=false log --oneline -n 50 2>$null | Out-File -FilePath (Join-Path $metaDir "git_log.txt") -Encoding UTF8
    git -c core.autocrlf=false diff --stat 2>$null | Out-File -FilePath (Join-Path $metaDir "git_diff_stat.txt") -Encoding UTF8
  }
}
finally {
  Pop-Location
}

# File manifest
Get-ChildItem -LiteralPath $stagingDir -Recurse | Where-Object { -not $_.PSIsContainer } |
  Select-Object FullName, Length, LastWriteTime |
  ConvertTo-Csv -NoTypeInformation |
  Out-File -FilePath (Join-Path $metaDir "file_manifest.csv") -Encoding UTF8

# Make output dir
$absOutputDir = if ([System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir } else { Join-Path $repoRoot $OutputDir }
New-DirectoryIfMissing -Path $absOutputDir

$zipPath = Join-Path $absOutputDir ("$ArchiveName.zip")
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

Write-Host "Creating archive: $zipPath" -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $zipPath -Force

# Passphrase handling
$passPlain = $null
if ($Passphrase) {
  $passPlain = Convert-SecureStringToPlainText -Secure $Passphrase
} else {
  $ss = Read-Host -AsSecureString -Prompt "Enter passphrase for encryption"
  $passPlain = Convert-SecureStringToPlainText -Secure $ss
}

function Clear-StringMemory { param([string]$s) if ($s) { Remove-Variable s -ErrorAction SilentlyContinue } }

$encryptedPath = $null

try {
  if (Test-Cmd gpg) {
    $encryptedPath = "$zipPath.gpg"
    Write-Host "Encrypting with gpg (AES256) -> $encryptedPath" -ForegroundColor Yellow
    & gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase $passPlain -o $encryptedPath $zipPath
  }
  elseif (Test-Cmd 7z) {
    $encryptedPath = "$zipPath.7z"
    Write-Host "Encrypting with 7z (AES256, header-encrypted) -> $encryptedPath" -ForegroundColor Yellow
    & 7z a -t7z $encryptedPath $zipPath -mhe=on -p$passPlain | Out-Null
  }
  elseif (Test-Cmd openssl) {
    $encryptedPath = "$zipPath.enc"
    Write-Host "Encrypting with openssl (AES-256-CBC, PBKDF2) -> $encryptedPath" -ForegroundColor Yellow
    & openssl enc -aes-256-cbc -salt -pbkdf2 -in $zipPath -out $encryptedPath -pass "pass:$passPlain"
  }
  else {
    $encryptedPath = "$zipPath.dpapi"
    Write-Host "Encrypting with Windows DPAPI (CurrentUser scope) -> $encryptedPath" -ForegroundColor Yellow
    $bytes = [System.IO.File]::ReadAllBytes($zipPath)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($encryptedPath, $enc)
  }
}
finally {
  # Remove plaintext zip
  if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
  Clear-StringMemory -s $passPlain
}

# Cleanup staging
Remove-Item -LiteralPath $stagingDir -Recurse -Force

Write-Host "Backup complete: $encryptedPath" -ForegroundColor Green
Write-Host "Store the passphrase securely. You will need it to restore." -ForegroundColor Magenta


