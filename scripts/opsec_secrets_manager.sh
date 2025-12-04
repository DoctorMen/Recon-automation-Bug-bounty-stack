#!/bin/bash
# OPSEC Secrets Manager
# Copyright © 2025 Security Research Operations. All Rights Reserved.
# Manages API keys, tokens, and credentials securely

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECRETS_DIR="$REPO_ROOT/.secrets"
SECRETS_FILE="$SECRETS_DIR/credentials.enc"

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

# Ensure secrets directory exists and is secure
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# Usage function
usage() {
    cat <<EOF
OPSEC Secrets Manager - Secure Credential Storage

Usage: $0 <command> [options]

Commands:
  init                Initialize secrets storage
  add <name>          Add a new secret
  get <name>          Retrieve a secret
  list                List all secret names (not values)
  delete <name>       Delete a secret
  export              Export secrets to .env file
  rotate <name>       Rotate a secret (mark for renewal)
  audit               Audit secret age and usage

Examples:
  $0 init
  $0 add HACKERONE_API_KEY
  $0 get HACKERONE_API_KEY
  $0 export > .env.local
  $0 audit

Security:
  - Secrets are encrypted with GPG
  - Master passphrase required for access
  - Automatic expiration warnings
  - Audit trail maintained

EOF
    exit 1
}

# Check for GPG
if ! command -v gpg &>/dev/null; then
    error "GPG not found! Install with: apt-get install gnupg"
    exit 1
fi

# Initialize secrets storage
cmd_init() {
    log "Initializing OPSEC secrets storage..."
    
    if [ -f "$SECRETS_FILE" ]; then
        warn "Secrets file already exists"
        read -p "Overwrite existing secrets? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log "Cancelled"
            exit 0
        fi
    fi
    
    # Create empty secrets file
    echo "{}" | gpg --symmetric --cipher-algo AES256 --output "$SECRETS_FILE" -
    
    if [ $? -eq 0 ]; then
        chmod 600 "$SECRETS_FILE"
        success "Secrets storage initialized"
        success "Location: $SECRETS_FILE"
    else
        error "Failed to initialize secrets storage"
        exit 1
    fi
}

# Decrypt secrets file
decrypt_secrets() {
    if [ ! -f "$SECRETS_FILE" ]; then
        error "Secrets file not found. Run: $0 init"
        exit 1
    fi
    
    gpg --decrypt --quiet "$SECRETS_FILE" 2>/dev/null
}

# Encrypt and save secrets
encrypt_secrets() {
    local data="$1"
    echo "$data" | gpg --symmetric --cipher-algo AES256 --output "$SECRETS_FILE" --yes -
    chmod 600 "$SECRETS_FILE"
}

# Add a secret
cmd_add() {
    local name="$1"
    
    if [ -z "$name" ]; then
        error "Secret name required"
        usage
    fi
    
    # Get existing secrets
    if [ -f "$SECRETS_FILE" ]; then
        secrets=$(decrypt_secrets)
    else
        secrets="{}"
    fi
    
    # Prompt for secret value
    echo -n "Enter value for $name: "
    read -s value
    echo ""
    
    if [ -z "$value" ]; then
        error "Value cannot be empty"
        exit 1
    fi
    
    # Add secret with metadata
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    secrets=$(echo "$secrets" | jq --arg name "$name" --arg value "$value" --arg ts "$timestamp" \
        '. + {($name): {value: $value, created: $ts, accessed: $ts, rotations: 0}}')
    
    # Encrypt and save
    encrypt_secrets "$secrets"
    
    success "Secret '$name' added successfully"
}

# Get a secret
cmd_get() {
    local name="$1"
    
    if [ -z "$name" ]; then
        error "Secret name required"
        usage
    fi
    
    secrets=$(decrypt_secrets)
    value=$(echo "$secrets" | jq -r --arg name "$name" '.[$name].value // empty')
    
    if [ -z "$value" ]; then
        error "Secret '$name' not found"
        exit 1
    fi
    
    # Update last accessed timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    secrets=$(echo "$secrets" | jq --arg name "$name" --arg ts "$timestamp" \
        '.[$name].accessed = $ts')
    encrypt_secrets "$secrets"
    
    echo "$value"
}

# List secrets
cmd_list() {
    if [ ! -f "$SECRETS_FILE" ]; then
        warn "No secrets stored yet. Run: $0 init"
        exit 0
    fi
    
    secrets=$(decrypt_secrets)
    
    echo "Stored Secrets:"
    echo "==============="
    echo "$secrets" | jq -r 'keys[]' | while read name; do
        created=$(echo "$secrets" | jq -r --arg name "$name" '.[$name].created')
        accessed=$(echo "$secrets" | jq -r --arg name "$name" '.[$name].accessed')
        rotations=$(echo "$secrets" | jq -r --arg name "$name" '.[$name].rotations')
        
        echo "  • $name"
        echo "      Created: $created"
        echo "      Last accessed: $accessed"
        echo "      Rotations: $rotations"
    done
}

# Delete a secret
cmd_delete() {
    local name="$1"
    
    if [ -z "$name" ]; then
        error "Secret name required"
        usage
    fi
    
    secrets=$(decrypt_secrets)
    
    # Check if secret exists
    if ! echo "$secrets" | jq -e --arg name "$name" '.[$name]' &>/dev/null; then
        error "Secret '$name' not found"
        exit 1
    fi
    
    # Remove secret
    secrets=$(echo "$secrets" | jq --arg name "$name" 'del(.[$name])')
    encrypt_secrets "$secrets"
    
    success "Secret '$name' deleted"
}

# Export secrets to .env format
cmd_export() {
    if [ ! -f "$SECRETS_FILE" ]; then
        warn "No secrets to export"
        exit 0
    fi
    
    secrets=$(decrypt_secrets)
    
    echo "# OPSEC Secrets Export"
    echo "# Generated: $(date)"
    echo "# DO NOT COMMIT THIS FILE"
    echo ""
    
    echo "$secrets" | jq -r 'to_entries[] | "\(.key)=\"\(.value.value)\""'
}

# Rotate a secret (mark for renewal)
cmd_rotate() {
    local name="$1"
    
    if [ -z "$name" ]; then
        error "Secret name required"
        usage
    fi
    
    secrets=$(decrypt_secrets)
    
    # Check if secret exists
    if ! echo "$secrets" | jq -e --arg name "$name" '.[$name]' &>/dev/null; then
        error "Secret '$name' not found"
        exit 1
    fi
    
    # Increment rotation counter
    secrets=$(echo "$secrets" | jq --arg name "$name" \
        '.[$name].rotations += 1')
    
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    secrets=$(echo "$secrets" | jq --arg name "$name" --arg ts "$timestamp" \
        '.[$name].last_rotated = $ts')
    
    encrypt_secrets "$secrets"
    
    success "Secret '$name' marked for rotation"
    warn "Remember to update the actual credential in the platform!"
}

# Audit secrets
cmd_audit() {
    if [ ! -f "$SECRETS_FILE" ]; then
        warn "No secrets to audit"
        exit 0
    fi
    
    secrets=$(decrypt_secrets)
    
    echo "OPSEC Secrets Audit Report"
    echo "=========================="
    echo "Generated: $(date)"
    echo ""
    
    total=$(echo "$secrets" | jq 'length')
    echo "Total secrets: $total"
    echo ""
    
    # Check for old secrets (>90 days)
    echo "Rotation Status:"
    echo "----------------"
    
    now=$(date +%s)
    
    echo "$secrets" | jq -r 'to_entries[]' | while read -r entry; do
        name=$(echo "$entry" | jq -r '.key')
        created=$(echo "$entry" | jq -r '.value.created')
        rotations=$(echo "$entry" | jq -r '.value.rotations')
        
        # Calculate age in days
        created_ts=$(date -d "$created" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$created" +%s 2>/dev/null)
        age_days=$(( (now - created_ts) / 86400 ))
        
        if [ $age_days -gt 90 ]; then
            echo -e "  ${RED}✗${NC} $name (${age_days} days old) - ROTATION NEEDED"
        elif [ $age_days -gt 60 ]; then
            echo -e "  ${YELLOW}!${NC} $name (${age_days} days old) - Consider rotation"
        else
            echo -e "  ${GREEN}✓${NC} $name (${age_days} days old)"
        fi
    done
    
    echo ""
    echo "Recommendations:"
    echo "  • Rotate secrets older than 90 days"
    echo "  • Enable 2FA on all platforms"
    echo "  • Use IP whitelisting where possible"
    echo "  • Monitor access logs regularly"
}

# Main command dispatcher
case "${1:-}" in
    init)
        cmd_init
        ;;
    add)
        cmd_add "${2:-}"
        ;;
    get)
        cmd_get "${2:-}"
        ;;
    list)
        cmd_list
        ;;
    delete)
        cmd_delete "${2:-}"
        ;;
    export)
        cmd_export
        ;;
    rotate)
        cmd_rotate "${2:-}"
        ;;
    audit)
        cmd_audit
        ;;
    *)
        usage
        ;;
esac

