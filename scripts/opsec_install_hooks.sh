#!/bin/bash
# OPSEC Git Hooks Installer
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Installs git hooks to prevent sensitive data commits

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

log "=== Installing OPSEC Git Hooks ==="

# Check if this is a git repository
if [ ! -d "$REPO_ROOT/.git" ]; then
    warn "Not a git repository - skipping hook installation"
    exit 0
fi

HOOKS_DIR="$REPO_ROOT/.git/hooks"
mkdir -p "$HOOKS_DIR"

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" <<'HOOK_EOF'
#!/bin/bash
# OPSEC Pre-Commit Hook
# Prevents committing sensitive data

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Patterns to block
declare -a BLOCK_PATTERNS=(
    "(?i)(api[_-]?key|apikey)['\"\s:=]+[a-zA-Z0-9_-]{20,}"
    "(?i)(bearer|token|auth)['\"\s:=]+[a-zA-Z0-9_.-]{20,}"
    "sk-[a-zA-Z0-9]{32,}"
    "xox[baprs]-[a-zA-Z0-9-]+"
    "ghp_[a-zA-Z0-9]{36}"
    "AKIA[0-9A-Z]{16}"
    "https://discord\.com/api/webhooks/"
    "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"
)

# Files to check
FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$FILES" ]; then
    exit 0
fi

VIOLATIONS=0

for file in $FILES; do
    if [ ! -f "$file" ]; then
        continue
    fi
    
    # Skip binary files
    if file "$file" | grep -q "executable\|binary"; then
        continue
    fi
    
    # Check for sensitive patterns
    for pattern in "${BLOCK_PATTERNS[@]}"; do
        if grep -P "$pattern" "$file" &>/dev/null; then
            echo -e "${RED}[BLOCKED]${NC} Sensitive data detected in: $file"
            echo "  Pattern matched: $pattern"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    done
    
    # Check file size (block large files)
    size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
    if [ $size -gt 10485760 ]; then  # 10MB
        echo -e "${YELLOW}[WARNING]${NC} Large file: $file ($(numfmt --to=iec-i --suffix=B $size 2>/dev/null))"
        echo "  Consider using Git LFS or excluding this file"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
    
    # Check for common sensitive filenames
    filename=$(basename "$file")
    if [[ "$filename" =~ \.(env|key|pem|p12|pfx)$ ]] || [[ "$filename" == "secrets.json" ]] || [[ "$filename" == "credentials.json" ]]; then
        echo -e "${RED}[BLOCKED]${NC} Sensitive filename: $file"
        echo "  This file type should never be committed"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done

if [ $VIOLATIONS -gt 0 ]; then
    echo ""
    echo -e "${RED}COMMIT BLOCKED!${NC} Found $VIOLATIONS OPSEC violation(s)"
    echo ""
    echo "Action required:"
    echo "  1. Remove sensitive data from staged files"
    echo "  2. Add sensitive files to .gitignore"
    echo "  3. Use environment variables for credentials"
    echo "  4. Review OPSEC_FRAMEWORK.md for guidelines"
    echo ""
    echo "To bypass this check (NOT RECOMMENDED):"
    echo "  git commit --no-verify"
    echo ""
    exit 1
fi

exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/pre-commit"
success "Installed pre-commit hook"

# Create pre-push hook
cat > "$HOOKS_DIR/pre-push" <<'HOOK_EOF'
#!/bin/bash
# OPSEC Pre-Push Hook
# Final check before pushing to remote

YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[OPSEC]${NC} Running pre-push security checks..."

# Run sanitization check
if [ -f "./scripts/opsec_sanitize_all.sh" ]; then
    if ! bash ./scripts/opsec_sanitize_all.sh; then
        echo ""
        echo "Pre-push check found OPSEC issues!"
        echo "Review the sanitization report before pushing."
        echo ""
        read -p "Do you want to continue pushing anyway? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Push cancelled."
            exit 1
        fi
    fi
fi

exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/pre-push"
success "Installed pre-push hook"

# Create commit-msg hook (add OPSEC tags)
cat > "$HOOKS_DIR/commit-msg" <<'HOOK_EOF'
#!/bin/bash
# OPSEC Commit Message Hook
# Adds security tags to commits

COMMIT_MSG_FILE=$1
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Check if message already has [OPSEC] tag
if echo "$COMMIT_MSG" | grep -q "^\[OPSEC"; then
    exit 0
fi

# Add OPSEC: SAFE tag if no violations detected
echo "[OPSEC: CHECKED] $COMMIT_MSG" > "$COMMIT_MSG_FILE"

exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/commit-msg"
success "Installed commit-msg hook"

# Update .gitignore
log "Updating .gitignore..."
GITIGNORE="$REPO_ROOT/.gitignore"

declare -a IGNORE_ENTRIES=(
    "# OPSEC Protection"
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
    ".opsec/"
    "*.log"
    "*.gpg"
    ".backups/"
    "__pycache__/"
    "node_modules/"
    ".DS_Store"
    "Thumbs.db"
)

# Create .gitignore if it doesn't exist
touch "$GITIGNORE"

# Add missing entries
for entry in "${IGNORE_ENTRIES[@]}"; do
    if ! grep -Fxq "$entry" "$GITIGNORE"; then
        echo "$entry" >> "$GITIGNORE"
        log "Added to .gitignore: $entry"
    fi
done

success "Updated .gitignore"

# Create .gitattributes for binary files
cat > "$REPO_ROOT/.gitattributes" <<'ATTR_EOF'
# OPSEC: Binary files should not be diffed
*.key binary
*.pem binary
*.p12 binary
*.pfx binary
*.gpg binary

# Large files should use LFS
*.tar.gz filter=lfs diff=lfs merge=lfs -text
*.zip filter=lfs diff=lfs merge=lfs -text
ATTR_EOF

success "Created .gitattributes"

echo ""
echo "========================================"
success "Git hooks installed successfully!"
echo ""
echo "Installed hooks:"
echo "  • pre-commit: Blocks sensitive data"
echo "  • pre-push: Final security check"
echo "  • commit-msg: Adds OPSEC tags"
echo ""
echo "These hooks will automatically:"
echo "  ✓ Scan for API keys and tokens"
echo "  ✓ Block large file commits"
echo "  ✓ Prevent sensitive filenames"
echo "  ✓ Run sanitization before push"
echo "========================================"

log "=== OPSEC Git Hooks Installation Complete ==="

