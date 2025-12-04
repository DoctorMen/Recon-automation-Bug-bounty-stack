#!/bin/bash
# OPSEC Master Deployment Script
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Deploys OPSEC framework to all repositories

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

echo "========================================"
echo "  OPSEC FRAMEWORK DEPLOYMENT"
echo "  Copyright © 2025"
echo "========================================"
echo ""

log "Deploying from: $(basename "$REPO_ROOT")"

# Make all OPSEC scripts executable
log "Setting script permissions..."
chmod +x "$SCRIPT_DIR"/opsec_*.sh
success "Scripts are executable"

# Install git hooks in current repo
log "Installing git hooks..."
if bash "$SCRIPT_DIR/opsec_install_hooks.sh"; then
    success "Git hooks installed"
fi

# Find other repositories
declare -a OTHER_REPOS=()

# Check parent directory for sibling repositories
PARENT_DIR="$(dirname "$REPO_ROOT")"

for dir in "$PARENT_DIR"/*; do
    if [ -d "$dir" ] && [ "$dir" != "$REPO_ROOT" ]; then
        # Check if it's a git repo or looks like a project
        if [ -d "$dir/.git" ] || [ -f "$dir/install.sh" ] || [ -f "$dir/README.md" ]; then
            OTHER_REPOS+=("$dir")
        fi
    fi
done

# Display found repositories
if [ ${#OTHER_REPOS[@]} -gt 0 ]; then
    log "Found ${#OTHER_REPOS[@]} other repository/repositories:"
    for repo in "${OTHER_REPOS[@]}"; do
        echo "  • $(basename "$repo")"
    done
    echo ""
    
    read -p "Deploy OPSEC framework to all repositories? (Y/n): " confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
        for repo in "${OTHER_REPOS[@]}"; do
            log "Deploying to: $(basename "$repo")"
            
            # Create scripts directory if needed
            mkdir -p "$repo/scripts"
            
            # Copy OPSEC files
            cp "$REPO_ROOT/OPSEC_FRAMEWORK.md" "$repo/" 2>/dev/null && success "  ✓ Copied framework documentation"
            
            # Copy OPSEC scripts
            for script in opsec_*.sh; do
                if [ -f "$SCRIPT_DIR/$script" ]; then
                    cp "$SCRIPT_DIR/$script" "$repo/scripts/"
                    chmod +x "$repo/scripts/$script"
                fi
            done
            success "  ✓ Copied OPSEC scripts"
            
            # Install hooks in target repo
            if [ -d "$repo/.git" ]; then
                (cd "$repo" && bash scripts/opsec_install_hooks.sh &>/dev/null) && success "  ✓ Installed git hooks"
            fi
            
            success "Deployed to $(basename "$repo")"
            echo ""
        done
    fi
else
    warn "No other repositories found in $PARENT_DIR"
fi

# Create backups of all repositories
log "Creating initial backups..."
if bash "$SCRIPT_DIR/opsec_backup.sh"; then
    success "Backup created"
fi

# Run initial security check
log "Running initial security check..."
if bash "$SCRIPT_DIR/opsec_check_all.sh"; then
    success "Security check passed"
else
    warn "Security check found issues - review the output"
fi

# Create cron jobs for automated tasks
log "Setting up automated tasks..."

CRON_JOBS="
# OPSEC Automated Tasks - Copyright © 2025
# Daily backup at 2 AM
0 2 * * * cd $REPO_ROOT && bash scripts/opsec_backup.sh >> .opsec/backup.log 2>&1

# Weekly security audit on Sundays at 3 AM
0 3 * * 0 cd $REPO_ROOT && bash scripts/opsec_check_all.sh >> .opsec/audit.log 2>&1

# Monthly secrets audit on 1st of month at 4 AM
0 4 1 * * cd $REPO_ROOT && bash scripts/opsec_secrets_manager.sh audit >> .opsec/secrets_audit.log 2>&1
"

# Save cron jobs to file
echo "$CRON_JOBS" > "$REPO_ROOT/.opsec/cron_jobs.txt"
success "Cron jobs saved to .opsec/cron_jobs.txt"

echo ""
warn "To activate automated tasks, run:"
echo "  crontab -e"
echo "  # Then paste the contents of .opsec/cron_jobs.txt"
echo ""

# Create quick reference card
cat > "$REPO_ROOT/.opsec/QUICK_REFERENCE.md" <<'EOF'
# OPSEC Quick Reference Card

## Emergency Commands

```bash
# Check if VPN is active
./scripts/opsec_check_vpn.sh

# Run full security check
./scripts/opsec_check_all.sh

# Sanitize before committing
./scripts/opsec_sanitize_all.sh

# Create backup now
./scripts/opsec_backup.sh
```

## Secrets Management

```bash
# Initialize secrets storage
./scripts/opsec_secrets_manager.sh init

# Add a new API key
./scripts/opsec_secrets_manager.sh add HACKERONE_API_KEY

# Get a secret value
./scripts/opsec_secrets_manager.sh get HACKERONE_API_KEY

# List all secrets
./scripts/opsec_secrets_manager.sh list

# Export to .env file
./scripts/opsec_secrets_manager.sh export > .env.local

# Audit secret age
./scripts/opsec_secrets_manager.sh audit
```

## Before Each Operation

1. ✓ VPN connected and verified
2. ✓ Authorization documented
3. ✓ Scope verified
4. ✓ Audit logging enabled

## Before Committing Code

1. ✓ Run sanitization check
2. ✓ Review git hooks output
3. ✓ Verify no secrets in code
4. ✓ Check .gitignore coverage

## Before Sharing Results

1. ✓ Sanitize all target information
2. ✓ Remove internal tool references
3. ✓ Strip EXIF data from images
4. ✓ Use example domains

## Weekly Checklist

- [ ] Rotate VPN exit node
- [ ] Review audit logs
- [ ] Check backup integrity
- [ ] Update documentation

## Monthly Checklist

- [ ] Rotate API keys
- [ ] Security assessment
- [ ] Review incident reports
- [ ] Update threat model

## Emergency Contacts

- VPN Provider: [Your VPN support]
- Password Manager: [Your provider support]
- Legal Counsel: [If applicable]
- Bug Bounty Platform: security@platform

---

Copyright © 2025 Security Research Operations. All Rights Reserved.
EOF

success "Created quick reference card"

# Summary
echo ""
echo "========================================"
echo "  DEPLOYMENT COMPLETE"
echo "========================================"
echo ""
echo "✓ OPSEC framework deployed"
echo "✓ Git hooks installed"
echo "✓ Scripts made executable"
echo "✓ Initial backup created"
echo "✓ Security check completed"
echo ""
echo "Documentation:"
echo "  • Framework: OPSEC_FRAMEWORK.md"
echo "  • Quick ref: .opsec/QUICK_REFERENCE.md"
echo ""
echo "Next Steps:"
echo "  1. Initialize secrets: ./scripts/opsec_secrets_manager.sh init"
echo "  2. Add your API keys: ./scripts/opsec_secrets_manager.sh add <KEY_NAME>"
echo "  3. Setup cron jobs: cat .opsec/cron_jobs.txt | crontab -"
echo "  4. Review framework: less OPSEC_FRAMEWORK.md"
echo ""
echo "Daily Usage:"
echo "  • Before scanning: ./scripts/opsec_check_vpn.sh"
echo "  • Before commit: ./scripts/opsec_sanitize_all.sh"
echo "  • Weekly audit: ./scripts/opsec_check_all.sh"
echo ""
echo "========================================"

log "OPSEC Framework deployment complete!"

