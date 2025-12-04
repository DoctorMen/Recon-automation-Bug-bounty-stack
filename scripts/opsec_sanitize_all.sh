#!/bin/bash
# OPSEC Data Sanitization Script
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Sanitizes sensitive data before sharing or committing

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SANITIZE_LOG="$REPO_ROOT/.opsec/sanitize.log"

mkdir -p "$REPO_ROOT/.opsec"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$SANITIZE_LOG"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$SANITIZE_LOG"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$SANITIZE_LOG"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$SANITIZE_LOG"
}

log "=== OPSEC Sanitization Started ==="

# Sensitive patterns to detect
declare -a PATTERNS=(
    # API Keys and Tokens
    "(?i)(api[_-]?key|apikey|api[_-]?token)['\"\s:=]+[a-zA-Z0-9_-]{20,}"
    "(?i)(bearer|token|auth)['\"\s:=]+[a-zA-Z0-9_.-]{20,}"
    "(?i)sk-[a-zA-Z0-9]{32,}" # OpenAI keys
    "(?i)xox[baprs]-[a-zA-Z0-9-]+" # Slack tokens
    "ghp_[a-zA-Z0-9]{36}" # GitHub personal access tokens
    "gho_[a-zA-Z0-9]{36}" # GitHub OAuth tokens
    
    # AWS Credentials
    "(?i)AKIA[0-9A-Z]{16}" # AWS Access Key ID
    "(?i)aws[_-]?secret[_-]?access[_-]?key"
    
    # Email addresses (except example.com)
    "[a-zA-Z0-9._%+-]+@(?!example\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    
    # Private IP addresses
    "\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    "\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b"
    "\b192\.168\.\d{1,3}\.\d{1,3}\b"
    
    # Discord webhooks
    "https://discord\.com/api/webhooks/[0-9]{18}/[a-zA-Z0-9_-]+"
    
    # JWT tokens
    "eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
    
    # Private keys
    "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"
)

# Directories to scan (relative to repo root)
SCAN_DIRS=(
    "scripts"
    "programs"
    "output"
    "config"
    "."
)

# Files to always check
CRITICAL_FILES=(
    "*.sh"
    "*.py"
    "*.js"
    "*.json"
    "*.yaml"
    "*.yml"
    "*.md"
    "*.txt"
    "*.log"
)

FINDINGS=0

# Function to scan a file
scan_file() {
    local file="$1"
    local basename=$(basename "$file")
    
    # Skip certain files
    if [[ "$basename" == "opsec_sanitize_all.sh" ]] || \
       [[ "$basename" == "OPSEC_FRAMEWORK.md" ]] || \
       [[ "$file" == *"node_modules"* ]] || \
       [[ "$file" == *"__pycache__"* ]] || \
       [[ "$file" == *".git"* ]]; then
        return
    fi
    
    for pattern in "${PATTERNS[@]}"; do
        if grep -P "$pattern" "$file" &>/dev/null; then
            error "Found sensitive pattern in: $file"
            echo "  Pattern: $pattern"
            FINDINGS=$((FINDINGS + 1))
        fi
    done
}

# Scan for sensitive data
log "Scanning for sensitive data patterns..."

for dir in "${SCAN_DIRS[@]}"; do
    if [ -d "$REPO_ROOT/$dir" ]; then
        log "Scanning directory: $dir"
        
        for ext_pattern in "${CRITICAL_FILES[@]}"; do
            while IFS= read -r -d '' file; do
                scan_file "$file"
            done < <(find "$REPO_ROOT/$dir" -maxdepth 3 -type f -name "$ext_pattern" -print0 2>/dev/null || true)
        done
    fi
done

# Check for large files that shouldn't be committed
log "Checking for large files..."
while IFS= read -r file; do
    size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
    if [ "$size" -gt 10485760 ]; then # 10MB
        warn "Large file detected: $file ($(numfmt --to=iec-i --suffix=B $size 2>/dev/null || echo "$size bytes"))"
        FINDINGS=$((FINDINGS + 1))
    fi
done < <(find "$REPO_ROOT" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/tools/*" 2>/dev/null || true)

# Check .gitignore coverage
log "Verifying .gitignore coverage..."
GITIGNORE="$REPO_ROOT/.gitignore"

declare -a REQUIRED_IGNORES=(
    ".env"
    ".env.local"
    ".env.*.local"
    "*.key"
    "*.pem"
    "*.p12"
    "*.pfx"
    "secrets/"
    ".secrets/"
    "credentials/"
    ".credentials/"
    "*.log"
    "*.gpg"
    "__pycache__/"
    "node_modules/"
    ".DS_Store"
)

if [ -f "$GITIGNORE" ]; then
    for ignore in "${REQUIRED_IGNORES[@]}"; do
        if ! grep -q "^$ignore" "$GITIGNORE"; then
            warn ".gitignore missing: $ignore"
        fi
    done
else
    error ".gitignore file not found!"
    FINDINGS=$((FINDINGS + 1))
fi

# Sanitize common sensitive files
log "Sanitizing known sensitive locations..."

# Sanitize targets.txt if it exists
if [ -f "$REPO_ROOT/targets.txt" ]; then
    log "Backing up and sanitizing targets.txt..."
    cp "$REPO_ROOT/targets.txt" "$REPO_ROOT/.opsec/targets.txt.backup"
    
    # Check if it contains real domains
    if grep -E '\.[a-z]{2,}$' "$REPO_ROOT/targets.txt" | grep -v "example.com" &>/dev/null; then
        warn "targets.txt contains real domains - consider sanitizing before sharing"
        FINDINGS=$((FINDINGS + 1))
    fi
fi

# Sanitize output directory
if [ -d "$REPO_ROOT/output" ]; then
    log "Checking output directory..."
    
    # List files that might contain sensitive data
    for file in http.json nuclei-findings.json subs.txt live.txt triage.json; do
        if [ -f "$REPO_ROOT/output/$file" ]; then
            warn "Output file exists: output/$file - ensure it's gitignored"
        fi
    done
fi

# Check for hardcoded credentials in Python files
log "Scanning Python files for hardcoded credentials..."
find "$REPO_ROOT" -name "*.py" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" -exec grep -l "password\s*=\s*['\"][^'\"]*['\"]" {} \; 2>/dev/null | while read file; do
    error "Possible hardcoded password in: $file"
    FINDINGS=$((FINDINGS + 1))
done

# Check for exposed API keys in JavaScript/Node
log "Scanning JavaScript files for API keys..."
find "$REPO_ROOT" -name "*.js" -o -name "*.json" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | while read file; do
    if grep -iE "(api[_-]?key|apikey|secret|token)" "$file" | grep -v "process.env" &>/dev/null; then
        warn "Possible exposed credential in: $file"
    fi
done

# Generate sanitization report
REPORT_FILE="$REPO_ROOT/.opsec/sanitization_report_$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" <<EOF
OPSEC SANITIZATION REPORT
Generated: $(date)
Repository: $(basename "$REPO_ROOT")

FINDINGS: $FINDINGS

RECOMMENDATIONS:
1. Review all flagged files and remove sensitive data
2. Use environment variables for all credentials
3. Ensure .gitignore covers all sensitive file types
4. Run this script before committing or sharing code
5. Consider using git-secrets for automatic pre-commit scanning

SENSITIVE DATA HANDLING:
- API Keys: Store in .env files (gitignored)
- Target Lists: Sanitize to example.com before sharing
- Scan Results: Never commit to public repos
- Personal Info: Use pseudonyms in all code

For detailed OPSEC guidelines, see: OPSEC_FRAMEWORK.md

EOF

log "Report saved to: $REPORT_FILE"

# Summary
echo ""
echo "========================================"
if [ $FINDINGS -eq 0 ]; then
    success "No sensitive data detected!"
    success "OPSEC sanitization passed ✓"
else
    error "Found $FINDINGS potential OPSEC issues!"
    error "Review the report: $REPORT_FILE"
    echo ""
    echo "Action required:"
    echo "1. Review flagged files"
    echo "2. Remove or sanitize sensitive data"
    echo "3. Run this script again"
    echo "4. Only then commit or share code"
fi
echo "========================================"

log "=== OPSEC Sanitization Complete ==="

exit $FINDINGS

