<#
Restores an encrypted backup created by backup_and_encrypt.ps1.

Supports:
- .zip.gpg  (gpg symmetric)
- .zip.7z   (7z strong AES; contains the .zip inside)
- .zip.enc  (openssl AES-256-CBC PBKDF2)
- .zip.dpapi (Windows DPAPI, user-bound)

Usage:
  powershell -ExecutionPolicy Bypass -File scripts\restore_from_backup.ps1 -BackupPath backups\recon-session-*.zip.gpg -Destination .
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string]$BackupPath,
  [string]$Destination = ".",
  [SecureString]$Passphrase
)

function Convert-SecureStringToPlainText {
  param([SecureString]$Secure)
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
}

function Test-Cmd { param([string]$Name) try { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) } catch { return $false } }

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $BackupPath)) { throw "Backup not found: $BackupPath" }

$destAbs = if ([System.IO.Path]::IsPathRooted($Destination)) { $Destination } else { Join-Path (Get-Location) $Destination }
if (-not (Test-Path -LiteralPath $destAbs)) { [void](New-Item -ItemType Directory -Path $destAbs) }

$tmp = Join-Path $env:TEMP ("restore-" + [IO.Path]::GetFileNameWithoutExtension([IO.Path]::GetFileName($BackupPath)) + "-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
[void](New-Item -ItemType Directory -Path $tmp)

$passPlain = $null

try {
  $lower = $BackupPath.ToLowerInvariant()
  $zipOut = Join-Path $tmp "archive.zip"

  if ($lower.EndsWith(".zip.gpg")) {
    if (-not (Test-Cmd gpg)) { throw "gpg not found in PATH" }
    if (-not $Passphrase) { $Passphrase = Read-Host -AsSecureString -Prompt "Enter passphrase" }
    $passPlain = Convert-SecureStringToPlainText -Secure $Passphrase
    & gpg --batch --yes --passphrase $passPlain -o $zipOut -d $BackupPath
  }
  elseif ($lower.EndsWith(".zip.7z")) {
    if (-not (Test-Cmd 7z)) { throw "7z not found in PATH" }
    if (-not $Passphrase) { $Passphrase = Read-Host -AsSecureString -Prompt "Enter passphrase" }
    $passPlain = Convert-SecureStringToPlainText -Secure $Passphrase
    & 7z x -y -o"$tmp" -p$passPlain $BackupPath | Out-Null
    # After extraction, we expect a .zip inside tmp
    $possibleZip = Get-ChildItem -LiteralPath $tmp -Filter *.zip | Select-Object -First 1
    if ($possibleZip) { $zipOut = $possibleZip.FullName } else { throw "Expected inner .zip not found after 7z extraction" }
  }
  elseif ($lower.EndsWith(".zip.enc")) {
    if (-not (Test-Cmd openssl)) { throw "openssl not found in PATH" }
    if (-not $Passphrase) { $Passphrase = Read-Host -AsSecureString -Prompt "Enter passphrase" }
    $passPlain = Convert-SecureStringToPlainText -Secure $Passphrase
    & openssl enc -d -aes-256-cbc -pbkdf2 -in $BackupPath -out $zipOut -pass "pass:$passPlain"
  }
  elseif ($lower.EndsWith(".zip.dpapi")) {
    $bytes = [System.IO.File]::ReadAllBytes($BackupPath)
    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($zipOut, $dec)
  }
  else {
    throw "Unsupported backup extension. Expected one of: .zip.gpg, .zip.7z, .zip.enc, .zip.dpapi"
  }

  Write-Host "Extracting archive to: $destAbs" -ForegroundColor Cyan
  Expand-Archive -LiteralPath $zipOut -DestinationPath $destAbs -Force
  Write-Host "Restore complete." -ForegroundColor Green
}
finally {
  if ($passPlain) { Remove-Variable passPlain -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}









