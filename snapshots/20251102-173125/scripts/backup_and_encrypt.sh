#!/usr/bin/env bash
set -euo pipefail

# Creates a timestamped backup of key project assets and encrypts it (Linux/WSL)
#
# Priority: gpg -> openssl -> 7z (if available)
#
# Usage:
#   bash scripts/backup_and_encrypt.sh backups myrun

OUTPUT_DIR="${1:-backups}"
ARCHIVE_NAME="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
[[ -z "$ARCHIVE_NAME" ]] && ARCHIVE_NAME="recon-session-$TIMESTAMP"

STAGING_DIR="$(mktemp -d)"
echo "Staging files in: $STAGING_DIR"

mkdir -p "$STAGING_DIR"

copy_if_exists() {
  local rel="$1"
  if [[ -e "$REPO_ROOT/$rel" ]]; then
    mkdir -p "$STAGING_DIR/$(dirname "$rel")"
    cp -R "$REPO_ROOT/$rel" "$STAGING_DIR/$rel"
    echo "Including: $rel"
  fi
}

copy_if_exists output
copy_if_exists targets.txt
copy_if_exists agents.json
copy_if_exists README.md
copy_if_exists README_WINDOWS.md
copy_if_exists README_PROCESS_RESULTS.md
copy_if_exists SCAN_SUMMARY.md
copy_if_exists scripts
copy_if_exists ci
copy_if_exists workflows
copy_if_exists run_pipeline.py
copy_if_exists scripts/run_pipeline.sh
copy_if_exists scripts/agent_orchestrator.py
copy_if_exists docs

META_DIR="$STAGING_DIR/session_meta"
mkdir -p "$META_DIR"
{
  echo "Date: $(date -Iseconds)"
  echo "User: $(whoami)"
  echo "Host: $(hostname)"
  echo "Kernel: $(uname -a)"
  echo "PWD: $(pwd)"
} > "$META_DIR/system_info.txt"

if command -v git >/dev/null 2>&1; then
  (cd "$REPO_ROOT" && git status --porcelain=v1 > "$META_DIR/git_status.txt" 2>/dev/null || true)
  (cd "$REPO_ROOT" && git log --oneline -n 50 > "$META_DIR/git_log.txt" 2>/dev/null || true)
  (cd "$REPO_ROOT" && git diff --stat > "$META_DIR/git_diff_stat.txt" 2>/dev/null || true)
fi

find "$STAGING_DIR" -type f -printf '%p,%s,%TY-%Tm-%Td %TH:%TM:%.2TS\n' > "$META_DIR/file_manifest.csv"

ABS_OUTPUT_DIR="$REPO_ROOT/$OUTPUT_DIR"
mkdir -p "$ABS_OUTPUT_DIR"

ZIP_PATH="$ABS_OUTPUT_DIR/$ARCHIVE_NAME.zip"
rm -f "$ZIP_PATH"

echo "Creating archive: $ZIP_PATH"
(cd "$STAGING_DIR" && zip -r -q "$ZIP_PATH" .)

read -s -p "Enter passphrase for encryption: " PASSPHRASE
echo

ENCRYPTED_PATH=""
if command -v gpg >/dev/null 2>&1; then
  ENCRYPTED_PATH="$ZIP_PATH.gpg"
  echo "Encrypting with gpg (AES256) -> $ENCRYPTED_PATH"
  gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase "$PASSPHRASE" -o "$ENCRYPTED_PATH" "$ZIP_PATH"
elif command -v openssl >/dev/null 2>&1; then
  ENCRYPTED_PATH="$ZIP_PATH.enc"
  echo "Encrypting with openssl (AES-256-CBC, PBKDF2) -> $ENCRYPTED_PATH"
  openssl enc -aes-256-cbc -salt -pbkdf2 -in "$ZIP_PATH" -out "$ENCRYPTED_PATH" -pass pass:"$PASSPHRASE"
elif command -v 7z >/dev/null 2>&1; then
  ENCRYPTED_PATH="$ZIP_PATH.7z"
  echo "Encrypting with 7z (AES256, header-encrypted) -> $ENCRYPTED_PATH"
  7z a -t7z "$ENCRYPTED_PATH" "$ZIP_PATH" -mhe=on -p"$PASSPHRASE" >/dev/null
else
  echo "No encryption tool found (gpg/openssl/7z). Aborting for safety." >&2
  rm -rf "$STAGING_DIR" "$ZIP_PATH"
  exit 1
fi

unset PASSPHRASE
rm -f "$ZIP_PATH"
rm -rf "$STAGING_DIR"

echo "Backup complete: $ENCRYPTED_PATH"
echo "Store the passphrase securely. You will need it to restore."


