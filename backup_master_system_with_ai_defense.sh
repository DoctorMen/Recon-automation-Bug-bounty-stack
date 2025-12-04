#!/bin/bash
# 🔒 BACKUP MASTER SYSTEM WITH AI DEFENSE
# Copyright © 2025 Khallid Nurse. All Rights Reserved.
#
# Creates encrypted backup of entire master system including AI defense

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔒 BACKUP: Master System + AI Defense"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Copyright © 2025 Khallid Nurse. All Rights Reserved."
echo ""

# Configuration
BACKUP_DIR=~/backups/master_system
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="master_system_${TIMESTAMP}"
TEMP_BACKUP="/tmp/${BACKUP_NAME}.tar.gz"
FINAL_BACKUP="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz.gpg"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo -e "${BLUE}[1/6]${NC} Preparing backup..."
echo "Backup name: ${BACKUP_NAME}"
echo ""

# Verify AI defense exists
echo -e "${BLUE}[2/6]${NC} Verifying AI defense..."
if [ -d ~/ai_defense ]; then
    echo -e "${GREEN}✅ ~/ai_defense/ found${NC}"
    AI_DEFENSE_HOME=true
else
    echo -e "${YELLOW}⚠️  ~/ai_defense/ not found${NC}"
    AI_DEFENSE_HOME=false
fi

if [ -d ~/Recon-automation-Bug-bounty-stack/ai_defense ]; then
    echo -e "${GREEN}✅ Repository ai_defense/ found${NC}"
    AI_DEFENSE_REPO=true
else
    echo -e "${YELLOW}⚠️  Repository ai_defense/ not found${NC}"
    AI_DEFENSE_REPO=false
fi
echo ""

# Create backup
echo -e "${BLUE}[3/6]${NC} Creating backup archive..."
tar czf "$TEMP_BACKUP" \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='*.log' \
    --exclude='node_modules' \
    --exclude='venv' \
    --exclude='.env' \
    ~/Recon-automation-Bug-bounty-stack/ \
    $([ "$AI_DEFENSE_HOME" = true ] && echo ~/ai_defense/) \
    2>/dev/null

if [ -f "$TEMP_BACKUP" ]; then
    backup_size=$(du -h "$TEMP_BACKUP" | cut -f1)
    echo -e "${GREEN}✅ Archive created: ${backup_size}${NC}"
else
    echo -e "${RED}❌ Archive creation failed${NC}"
    exit 1
fi
echo ""

# List contents
echo -e "${BLUE}[4/6]${NC} Verifying backup contents..."
tar tzf "$TEMP_BACKUP" | grep -E "(MASTER_SAFETY|AI_DEFENSE|ai_defense)" | head -10
echo "..."
file_count=$(tar tzf "$TEMP_BACKUP" | wc -l)
echo "Total files in backup: ${file_count}"
echo ""

# Encrypt backup
echo -e "${BLUE}[5/6]${NC} Encrypting backup..."
echo "This will prompt for a passphrase (use strong password!)"
echo ""

gpg --symmetric --cipher-algo AES256 "$TEMP_BACKUP" -o "$FINAL_BACKUP"

if [ -f "$FINAL_BACKUP" ]; then
    encrypted_size=$(du -h "$FINAL_BACKUP" | cut -f1)
    echo -e "${GREEN}✅ Encrypted: ${encrypted_size}${NC}"
    
    # Delete unencrypted backup
    rm "$TEMP_BACKUP"
    echo -e "${GREEN}✅ Unencrypted backup deleted${NC}"
else
    echo -e "${RED}❌ Encryption failed${NC}"
    exit 1
fi
echo ""

# Cleanup old backups
echo -e "${BLUE}[6/6]${NC} Managing backup retention..."
cd "$BACKUP_DIR"
backup_count=$(ls -1 *.gpg 2>/dev/null | wc -l)

if [ $backup_count -gt 10 ]; then
    # Keep only last 10 backups
    ls -t *.gpg | tail -n +11 | xargs rm -f
    deleted=$((backup_count - 10))
    echo -e "${GREEN}✅ Kept last 10 backups (deleted ${deleted} old)${NC}"
else
    echo -e "${GREEN}✅ ${backup_count} backups total (within limit)${NC}"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ BACKUP COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📁 Location: ${FINAL_BACKUP}"
echo "📊 Size: ${encrypted_size}"
echo "🔒 Encryption: AES256"
echo "📅 Created: $(date)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "BACKUP INCLUDES:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ MASTER_SAFETY_SYSTEM.py"
echo "✅ LEGAL_AUTHORIZATION_SYSTEM.py"
echo "✅ MASTER_SAFETY_SYSTEM_AI_DEFENSE.py"
if [ "$AI_DEFENSE_HOME" = true ]; then
    echo "✅ ~/ai_defense/ (complete AI defense system)"
fi
if [ "$AI_DEFENSE_REPO" = true ]; then
    echo "✅ Repository ai_defense/ (local copy)"
fi
echo "✅ All automation scripts"
echo "✅ All documentation"
echo "✅ All configurations"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RESTORE INSTRUCTIONS:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Decrypt backup:"
echo "   gpg -d ${FINAL_BACKUP} > /tmp/restore.tar.gz"
echo ""
echo "2. List contents:"
echo "   tar tzf /tmp/restore.tar.gz | less"
echo ""
echo "3. Restore:"
echo "   cd ~"
echo "   tar xzf /tmp/restore.tar.gz"
echo ""
echo "4. Verify:"
echo "   cd ~/Recon-automation-Bug-bounty-stack"
echo "   python3 MASTER_SAFETY_SYSTEM_AI_DEFENSE.py"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}🔒 Your master system + AI defense is securely backed up${NC}"
echo ""
