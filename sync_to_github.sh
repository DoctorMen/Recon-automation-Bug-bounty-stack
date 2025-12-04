#!/bin/bash
# Complete GitHub Sync Script
# Pushes all useful files from Recon Automation Bug Bounty Stack to GitHub
# Created: December 3, 2025

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Repository configuration
REPO_DIR="/home/ubuntu/Recon-automation-Bug-bounty-stack"
GITHUB_USER="DoctorMen"
REPO_NAME="Recon-automation-Bug-bounty-stack"
GITHUB_URL="https://github.com/${GITHUB_USER}/${REPO_NAME}.git"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  GitHub Sync Script${NC}"
echo -e "${BLUE}  Repository: ${REPO_NAME}${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Navigate to repository
cd "$REPO_DIR" || exit 1
echo -e "${GREEN}✓${NC} Changed to repository directory"

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo -e "${RED}✗${NC} Not a git repository. Initializing..."
    git init
    git remote add origin "$GITHUB_URL"
fi

# Update .gitignore to exclude sensitive/unnecessary files
echo -e "${YELLOW}→${NC} Updating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST
*.log

# Virtual environments
venv/
env/
ENV/
.venv

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Sensitive data
*.key
*.pem
*.p12
*.pfx
*.crt
*.cer
*.der
*.env
.env.local
secrets/
credentials/
authorizations/*.json
!authorizations/example_auth.json

# Large binaries (use Git LFS if needed)
*.tar.gz
*.zip
*.exe
*.dll
*.so
*.dylib
node_modules/
package-lock.json
pnpm-lock.yaml

# Temporary files
*.tmp
*.temp
*.cache
.cache/
tmp/
temp/

# Output and results
output/*/
results/
runs/
logs/*.log
*.db
*.sqlite
*.sqlite3

# OS files
Thumbs.db
.DS_Store
desktop.ini

# Git LFS
*.pdf
tools/bin/nuclei
tools/bin/httpx
tools/bin/subfinder
programs/*/go*.tar.gz
EOF

echo -e "${GREEN}✓${NC} .gitignore updated"

# Stage all files
echo -e "${YELLOW}→${NC} Staging all files..."
git add -A

# Show what's being committed
echo ""
echo -e "${BLUE}Files to be committed:${NC}"
git status --short | head -20
TOTAL_FILES=$(git status --short | wc -l)
echo -e "${BLUE}Total files: ${TOTAL_FILES}${NC}"
echo ""

# Check if there are changes to commit
if git diff --cached --quiet; then
    echo -e "${YELLOW}⚠${NC} No changes to commit"
    exit 0
fi

# Create commit
COMMIT_MSG="Complete sync: Recon automation stack with AI workflow, legal protection, and business systems - $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${YELLOW}→${NC} Creating commit..."
git commit -m "$COMMIT_MSG"
echo -e "${GREEN}✓${NC} Commit created"

# Ensure we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${YELLOW}→${NC} Switching to main branch..."
    git branch -M main
fi

# Push to GitHub
echo ""
echo -e "${YELLOW}→${NC} Pushing to GitHub..."
echo -e "${BLUE}This may take a few minutes for large repositories...${NC}"
echo ""

# Try normal push first
if git push origin main 2>&1 | tee /tmp/git_push.log; then
    echo -e "${GREEN}✓${NC} Successfully pushed to GitHub!"
else
    # If push fails due to divergent histories, force push
    if grep -q "rejected" /tmp/git_push.log || grep -q "fetch first" /tmp/git_push.log; then
        echo ""
        echo -e "${YELLOW}⚠${NC} Remote has diverged. Force pushing..."
        git push origin main --force
        echo -e "${GREEN}✓${NC} Force push completed!"
    else
        echo -e "${RED}✗${NC} Push failed. Check error above."
        exit 1
    fi
fi

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ GitHub Sync Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Repository: ${BLUE}https://github.com/${GITHUB_USER}/${REPO_NAME}${NC}"
echo -e "Branch: ${BLUE}main${NC}"
echo -e "Files synced: ${BLUE}${TOTAL_FILES}${NC}"
echo ""
echo -e "${GREEN}All useful files have been pushed to GitHub!${NC}"
echo ""
