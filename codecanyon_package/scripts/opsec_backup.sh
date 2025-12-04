#!/bin/bash
# OPSEC Automated Backup Script
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Creates encrypted backups of critical data

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/.backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="recon_backup_${TIMESTAMP}"
BACKUP_LOG="$BACKUP_DIR/backup.log"

mkdir -p "$BACKUP_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$BACKUP_LOG"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$BACKUP_LOG"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$BACKUP_LOG"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$BACKUP_LOG"
}

log "=== OPSEC Backup Started ==="
log "Repository: $(basename "$REPO_ROOT")"
log "Backup location: $BACKUP_DIR"

# Check if encryption is available
if ! command -v gpg &>/dev/null; then
    warn "GPG not found - backups will NOT be encrypted!"
    warn "Install GPG for encrypted backups: apt-get install gnupg"
    ENCRYPT=false
else
    ENCRYPT=true
    log "GPG found - backups will be encrypted"
fi

# Items to backup
declare -a BACKUP_ITEMS=(
    "scripts"
    "config"
    "programs/*/config.yaml"
    "programs/*/permission.txt"
    ".opsec"
    "OPSEC_FRAMEWORK.md"
    "agents.json"
    "targets.txt"
    "install.sh"
    "README*.md"
)

# Create temporary backup directory
TEMP_BACKUP="$BACKUP_DIR/temp_$TIMESTAMP"
mkdir -p "$TEMP_BACKUP"

# Copy files to backup
log "Copying files to backup..."
BACKUP_SIZE=0

for item in "${BACKUP_ITEMS[@]}"; do
    # Handle wildcards
    while IFS= read -r -d $'\0' file; do
        if [ -e "$file" ]; then
            # Get relative path
            rel_path="${file#$REPO_ROOT/}"
            target_dir="$TEMP_BACKUP/$(dirname "$rel_path")"
            
            mkdir -p "$target_dir"
            cp -r "$file" "$target_dir/" 2>/dev/null && log "  ✓ Backed up: $rel_path"
            
            # Calculate size
            if [ -f "$file" ]; then
                size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
                BACKUP_SIZE=$((BACKUP_SIZE + size))
            fi
        fi
    done < <(find "$REPO_ROOT" -path "$REPO_ROOT/$item" -print0 2>/dev/null)
done

# Backup .env files if they exist (encrypted only!)
if [ "$ENCRYPT" = true ]; then
    log "Checking for .env files..."
    while IFS= read -r -d $'\0' env_file; do
        if [ -f "$env_file" ]; then
            rel_path="${env_file#$REPO_ROOT/}"
            target_dir="$TEMP_BACKUP/$(dirname "$rel_path")"
            mkdir -p "$target_dir"
            cp "$env_file" "$target_dir/"
            log "  ✓ Backed up (will be encrypted): $rel_path"
        fi
    done < <(find "$REPO_ROOT" -maxdepth 2 -name ".env*" -print0 2>/dev/null)
fi

# Create backup manifest
MANIFEST="$TEMP_BACKUP/BACKUP_MANIFEST.txt"
cat > "$MANIFEST" <<EOF
OPSEC BACKUP MANIFEST
=====================

Backup Date: $(date)
Repository: $(basename "$REPO_ROOT")
Backup Size: $(numfmt --to=iec-i --suffix=B $BACKUP_SIZE 2>/dev/null || echo "$BACKUP_SIZE bytes")
Encrypted: $ENCRYPT

Files Included:
EOF

find "$TEMP_BACKUP" -type f | sed "s|$TEMP_BACKUP/||" | sort >> "$MANIFEST"

echo "" >> "$MANIFEST"
echo "Restore Instructions:" >> "$MANIFEST"
echo "1. Decrypt: gpg -d $BACKUP_NAME.tar.gz.gpg > $BACKUP_NAME.tar.gz" >> "$MANIFEST"
echo "2. Extract: tar -xzf $BACKUP_NAME.tar.gz" >> "$MANIFEST"
echo "3. Review files before restoring to production" >> "$MANIFEST"

log "Created backup manifest"

# Create tarball
log "Creating compressed archive..."
cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" -C "$TEMP_BACKUP" . 2>/dev/null

if [ $? -eq 0 ]; then
    success "Archive created: ${BACKUP_NAME}.tar.gz"
else
    error "Failed to create archive"
    rm -rf "$TEMP_BACKUP"
    exit 1
fi

# Encrypt backup if GPG is available
if [ "$ENCRYPT" = true ]; then
    log "Encrypting backup..."
    
    # Check if we have a GPG key
    if gpg --list-keys 2>/dev/null | grep -q "^pub"; then
        # Use first available key
        RECIPIENT=$(gpg --list-keys --keyid-format LONG 2>/dev/null | grep "^pub" | head -1 | awk '{print $2}' | cut -d'/' -f2)
        gpg --encrypt --recipient "$RECIPIENT" --output "${BACKUP_NAME}.tar.gz.gpg" "${BACKUP_NAME}.tar.gz"
        
        if [ $? -eq 0 ]; then
            success "Backup encrypted successfully"
            # Remove unencrypted version
            rm -f "${BACKUP_NAME}.tar.gz"
            FINAL_BACKUP="${BACKUP_NAME}.tar.gz.gpg"
        else
            warn "Encryption failed - keeping unencrypted backup"
            FINAL_BACKUP="${BACKUP_NAME}.tar.gz"
        fi
    else
        # Use symmetric encryption with passphrase
        warn "No GPG key found - using symmetric encryption"
        echo "Enter encryption passphrase (keep this safe!):"
        gpg --symmetric --cipher-algo AES256 --output "${BACKUP_NAME}.tar.gz.gpg" "${BACKUP_NAME}.tar.gz"
        
        if [ $? -eq 0 ]; then
            success "Backup encrypted with passphrase"
            rm -f "${BACKUP_NAME}.tar.gz"
            FINAL_BACKUP="${BACKUP_NAME}.tar.gz.gpg"
        else
            warn "Encryption failed - keeping unencrypted backup"
            FINAL_BACKUP="${BACKUP_NAME}.tar.gz"
        fi
    fi
else
    FINAL_BACKUP="${BACKUP_NAME}.tar.gz"
fi

# Clean up temp directory
rm -rf "$TEMP_BACKUP"

# Get final backup size
FINAL_SIZE=$(stat -f%z "$BACKUP_DIR/$FINAL_BACKUP" 2>/dev/null || stat -c%s "$BACKUP_DIR/$FINAL_BACKUP" 2>/dev/null || echo 0)

# Backup rotation - keep last 30 daily backups
log "Rotating old backups..."
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "recon_backup_*.tar.gz*" | wc -l)
if [ $BACKUP_COUNT -gt 30 ]; then
    find "$BACKUP_DIR" -name "recon_backup_*.tar.gz*" -type f -printf '%T+ %p\n' | sort | head -n -30 | cut -d' ' -f2- | while read old_backup; do
        log "Removing old backup: $(basename "$old_backup")"
        rm -f "$old_backup"
    done
fi

# Summary
echo ""
echo "========================================"
success "Backup completed successfully!"
echo "  Location: $BACKUP_DIR/$FINAL_BACKUP"
echo "  Size: $(numfmt --to=iec-i --suffix=B $FINAL_SIZE 2>/dev/null || echo "$FINAL_SIZE bytes")"
echo "  Encrypted: $ENCRYPT"
echo "  Files: $(tar -tzf "$BACKUP_DIR/$FINAL_BACKUP" 2>/dev/null | wc -l) items"
echo ""
echo "To restore:"
if [ "$ENCRYPT" = true ]; then
    echo "  1. gpg -d $FINAL_BACKUP | tar -xzf -"
else
    echo "  1. tar -xzf $FINAL_BACKUP"
fi
echo "========================================"

log "=== OPSEC Backup Complete ==="

# Optional: Verify backup integrity
if command -v tar &>/dev/null; then
    log "Verifying backup integrity..."
    if tar -tzf "$BACKUP_DIR/$FINAL_BACKUP" &>/dev/null || gpg -d "$BACKUP_DIR/$FINAL_BACKUP" 2>/dev/null | tar -tz &>/dev/null; then
        success "Backup integrity verified ✓"
    else
        error "Backup verification failed!"
        exit 1
    fi
fi

exit 0

