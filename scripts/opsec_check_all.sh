#!/bin/bash
# OPSEC Complete Security Check
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Runs all OPSEC verification checks

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

error() {
    echo -e "${RED}[✗]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

CHECKS_PASSED=0
CHECKS_FAILED=0

echo "========================================"
echo "  OPSEC SECURITY POSTURE CHECK"
echo "  Repository: $(basename "$REPO_ROOT")"
echo "  Date: $(date)"
echo "========================================"
echo ""

# Check 1: VPN Status
log "Check 1: VPN Connection"
if bash "$SCRIPT_DIR/opsec_check_vpn.sh" &>/dev/null; then
    success "VPN is active"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    error "VPN is NOT active"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# Check 2: Sensitive Data Scan
log "Check 2: Sensitive Data Scan"
if bash "$SCRIPT_DIR/opsec_sanitize_all.sh" &>/dev/null; then
    success "No sensitive data detected"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    error "Sensitive data found!"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# Check 3: .gitignore Coverage
log "Check 3: .gitignore Coverage"
GITIGNORE="$REPO_ROOT/.gitignore"
if [ -f "$GITIGNORE" ]; then
    MISSING=0
    declare -a REQUIRED=(
        ".env"
        ".env.local"
        "*.key"
        "*.pem"
        "secrets/"
        ".secrets/"
        "*.log"
    )
    
    for item in "${REQUIRED[@]}"; do
        if ! grep -q "^$item" "$GITIGNORE"; then
            MISSING=$((MISSING + 1))
        fi
    done
    
    if [ $MISSING -eq 0 ]; then
        success ".gitignore properly configured"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        error ".gitignore missing $MISSING critical entries"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    error ".gitignore not found!"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# Check 4: Backup Status
log "Check 4: Backup Status"
BACKUP_DIR="$REPO_ROOT/.backups"
if [ -d "$BACKUP_DIR" ]; then
    BACKUP_COUNT=$(find "$BACKUP_DIR" -name "recon_backup_*.tar.gz*" 2>/dev/null | wc -l)
    if [ $BACKUP_COUNT -gt 0 ]; then
        LATEST=$(find "$BACKUP_DIR" -name "recon_backup_*.tar.gz*" -type f -printf '%T+ %p\n' | sort -r | head -1 | cut -d' ' -f2-)
        AGE=$(( ($(date +%s) - $(stat -c%Y "$LATEST" 2>/dev/null || echo 0)) / 86400 ))
        
        if [ $AGE -lt 7 ]; then
            success "Recent backup found ($AGE days old)"
            CHECKS_PASSED=$((CHECKS_PASSED + 1))
        else
            warn "Last backup is $AGE days old"
            CHECKS_FAILED=$((CHECKS_FAILED + 1))
        fi
    else
        warn "No backups found"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    warn "Backup directory not found"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# Check 5: File Permissions
log "Check 5: File Permissions"
PERMISSION_ISSUES=0

# Check for world-readable sensitive files
while IFS= read -r file; do
    if [ -f "$file" ]; then
        PERMS=$(stat -c%a "$file" 2>/dev/null || stat -f%Lp "$file" 2>/dev/null)
        if [[ "$PERMS" =~ [2367]$ ]]; then
            error "World-readable: $file ($PERMS)"
            PERMISSION_ISSUES=$((PERMISSION_ISSUES + 1))
        fi
    fi
done < <(find "$REPO_ROOT" -name ".env*" -o -name "*.key" -o -name "*.pem" 2>/dev/null)

if [ $PERMISSION_ISSUES -eq 0 ]; then
    success "File permissions secure"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    error "Found $PERMISSION_ISSUES files with insecure permissions"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# Check 6: Git History
log "Check 6: Git History Clean"
if [ -d "$REPO_ROOT/.git" ]; then
    # Check for large files in history
    LARGE_FILES=$(git -C "$REPO_ROOT" rev-list --all --objects | \
        git -C "$REPO_ROOT" cat-file --batch-check='%(objectsize) %(objectname) %(rest)' | \
        awk '$1 > 10485760' | wc -l 2>/dev/null || echo 0)
    
    if [ $LARGE_FILES -eq 0 ]; then
        success "No large files in git history"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        warn "Found $LARGE_FILES large files in git history"
        warn "Consider using: git filter-branch or BFG Repo-Cleaner"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    success "Not a git repository (no history to check)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
fi
echo ""

# Check 7: Environment Variables
log "Check 7: Environment Variables"
ENV_ISSUES=0

# Check for sensitive env vars not in .env files
declare -a SENSITIVE_VARS=(
    "API_KEY"
    "SECRET"
    "TOKEN"
    "PASSWORD"
    "AWS_ACCESS"
)

for var in "${SENSITIVE_VARS[@]}"; do
    if env | grep -i "$var" &>/dev/null; then
        if [ ! -f "$REPO_ROOT/.env" ] && [ ! -f "$REPO_ROOT/.env.local" ]; then
            warn "Sensitive variable $var set without .env file"
            ENV_ISSUES=$((ENV_ISSUES + 1))
        fi
    fi
done

if [ $ENV_ISSUES -eq 0 ]; then
    success "Environment variables properly managed"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
    warn "Found $ENV_ISSUES environment variable issues"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
echo ""

# Check 8: Authorization Documentation
log "Check 8: Authorization Documentation"
PROGRAMS_DIR="$REPO_ROOT/programs"
if [ -d "$PROGRAMS_DIR" ]; then
    PROGRAMS=$(find "$PROGRAMS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    DOCUMENTED=0
    
    for program_dir in "$PROGRAMS_DIR"/*; do
        if [ -d "$program_dir" ]; then
            if [ -f "$program_dir/permission.txt" ] || [ -f "$program_dir/config.yaml" ]; then
                DOCUMENTED=$((DOCUMENTED + 1))
            fi
        fi
    done
    
    if [ $PROGRAMS -eq 0 ] || [ $PROGRAMS -eq $DOCUMENTED ]; then
        success "All programs have authorization documentation"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        error "Missing authorization for $((PROGRAMS - DOCUMENTED)) programs"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi
else
    success "No programs directory (no authorization needed)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
fi
echo ""

# Final Summary
echo "========================================"
echo "  OPSEC CHECK SUMMARY"
echo "========================================"
echo ""
echo "  Checks Passed: ${GREEN}$CHECKS_PASSED${NC}"
echo "  Checks Failed: ${RED}$CHECKS_FAILED${NC}"
echo ""

TOTAL=$((CHECKS_PASSED + CHECKS_FAILED))
SCORE=$((CHECKS_PASSED * 100 / TOTAL))

if [ $SCORE -eq 100 ]; then
    echo -e "${GREEN}  EXCELLENT${NC} - Full OPSEC compliance ✓"
    echo "  Safe to proceed with operations"
elif [ $SCORE -ge 75 ]; then
    echo -e "${YELLOW}  GOOD${NC} - Minor issues found"
    echo "  Review warnings before proceeding"
elif [ $SCORE -ge 50 ]; then
    echo -e "${YELLOW}  FAIR${NC} - Several issues found"
    echo "  Address issues before operations"
else
    echo -e "${RED}  POOR${NC} - Critical issues found ✗"
    echo "  DO NOT proceed until issues are resolved!"
fi

echo ""
echo "========================================"
echo ""
echo "Recommendations:"
echo "  • Fix failed checks: Review errors above"
echo "  • Run sanitization: ./scripts/opsec_sanitize_all.sh"
echo "  • Create backup: ./scripts/opsec_backup.sh"
echo "  • Review framework: OPSEC_FRAMEWORK.md"
echo ""

exit $CHECKS_FAILED

