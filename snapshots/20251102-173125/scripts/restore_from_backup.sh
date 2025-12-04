#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

# Restores an encrypted backup created by backup_and_encrypt.sh (Linux/WSL)
#
# Usage:
#   bash scripts/restore_from_backup.sh backups/recon-session-*.zip.gpg .

BACKUP_PATH="${1:?First arg must be path to encrypted backup}"
DESTINATION="${2:-.}"

TMP_DIR="$(mktemp -d)"
ZIP_OUT="$TMP_DIR/archive.zip"

read -r LOWER <<< "$(echo "$BACKUP_PATH" | tr '[:upper:]' '[:lower:]')"

mkdir -p "$DESTINATION"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ "$LOWER" == *.zip.gpg ]]; then
  command -v gpg >/dev/null 2>&1 || { echo "gpg not found" >&2; exit 1; }
  read -s -p "Enter passphrase: " PASSPHRASE; echo
  gpg --batch --yes --passphrase "$PASSPHRASE" -o "$ZIP_OUT" -d "$BACKUP_PATH"
  unset PASSPHRASE
elif [[ "$LOWER" == *.zip.enc ]]; then
  command -v openssl >/dev/null 2>&1 || { echo "openssl not found" >&2; exit 1; }
  read -s -p "Enter passphrase: " PASSPHRASE; echo
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$BACKUP_PATH" -out "$ZIP_OUT" -pass pass:"$PASSPHRASE"
  unset PASSPHRASE
elif [[ "$LOWER" == *.zip.7z ]]; then
  command -v 7z >/dev/null 2>&1 || { echo "7z not found" >&2; exit 1; }
  read -s -p "Enter passphrase: " PASSPHRASE; echo
  7z x -y -o"$TMP_DIR" -p"$PASSPHRASE" "$BACKUP_PATH" >/dev/null
  unset PASSPHRASE
  inner_zip=$(find "$TMP_DIR" -maxdepth 1 -type f -name '*.zip' | head -n1)
  [[ -n "$inner_zip" ]] || { echo "Expected inner .zip not found after 7z extraction" >&2; exit 1; }
  ZIP_OUT="$inner_zip"
else
  echo "Unsupported backup extension. Expected one of: .zip.gpg, .zip.enc, .zip.7z" >&2
  exit 1
fi

echo "Extracting archive to: $DESTINATION"
unzip -o -q "$ZIP_OUT" -d "$DESTINATION"
echo "Restore complete."


