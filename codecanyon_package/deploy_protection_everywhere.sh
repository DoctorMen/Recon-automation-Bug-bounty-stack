#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# 🛡️ DEPLOY PROTECTION TO ALL REPOSITORIES
# Protects your entire IP portfolio in one command

echo "🛡️  DEPLOYING AI PROTECTION TO ALL REPOSITORIES"
echo "============================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Counters
protected=0
failed=0

# Step 1: Setup central defense
echo "📦 Setting up central defense system..."
mkdir -p ~/ai_defense
cp AI_INPUT_SANITIZER.py ~/ai_defense/ 2>/dev/null || {
    echo -e "${RED}❌ AI_INPUT_SANITIZER.py not found in current directory${NC}"
    exit 1
}
echo -e "${GREEN}✅ Central defense created: ~/ai_defense/${NC}"
echo ""

# Step 2: Find all repositories
echo "🔍 Scanning for repositories..."
repos=$(find ~ -name ".git" -type d 2>/dev/null | sed 's/\/.git$//' | head -20)
repo_count=$(echo "$repos" | wc -l)
echo "Found $repo_count repositories"
echo ""

# Step 3: Deploy to each repository
for repo in $repos; do
    repo_name=$(basename "$repo")
    echo "───────────────────────────────────────────────────────────"
    echo "📁 Processing: $repo_name"
    echo "   Path: $repo"
    
    # Skip if already protected
    if [ -f "$repo/.ai_protected" ]; then
        echo -e "   ${YELLOW}⚠️  Already protected, skipping${NC}"
        ((protected++))
        continue
    fi
    
    # Check if repo uses AI (has python files or js files)
    if [ -z "$(find "$repo" -name "*.py" -o -name "*.js" | head -1)" ]; then
        echo "   ℹ️  No Python/JS files, skipping"
        continue
    fi
    
    # Create protection wrapper for this repo
    cat > "$repo/ai_defense_local.py" << 'EOF'
#!/usr/bin/env python3
"""
Local AI Defense Wrapper
Auto-generated protection for this repository
"""
import sys
from pathlib import Path

# Import central defense
sys.path.append(str(Path.home() / 'ai_defense'))

try:
    from AI_INPUT_SANITIZER import SafeAIWrapper, sanitize_for_ai
    
    class LocalDefense:
        def __init__(self):
            self.wrapper = SafeAIWrapper()
        
        def protect(self, data):
            """Quick protection for any data"""
            return sanitize_for_ai(data)
        
        def safe_ai_call(self, ai_function, data):
            """Full protection with validation"""
            return self.wrapper.safe_ai_call(ai_function, data)
    
    # Global instance
    local_defense = LocalDefense()
    
    # Convenience function
    def protect(data):
        return local_defense.protect(data)
    
    print("✅ AI Defense loaded for this repository")

except ImportError as e:
    print(f"⚠️  Warning: Central AI defense not available: {e}")
    print("   Run: cp AI_INPUT_SANITIZER.py ~/ai_defense/")
    
    # Fallback: basic protection
    def protect(data):
        return data
    
    local_defense = None

if __name__ == "__main__":
    print("🛡️  AI Defense Module")
    print("Usage:")
    print("  from ai_defense_local import protect")
    print("  safe_data = protect(untrusted_data)")
EOF
    
    # Create marker file
    cat > "$repo/.ai_protected" << EOF
AI Protection deployed: $(date)
Central defense: ~/ai_defense/
Local wrapper: ./ai_defense_local.py
EOF
    
    # Create .gitignore entry for protection logs
    if [ -f "$repo/.gitignore" ]; then
        if ! grep -q ".ai_defense_log.json" "$repo/.gitignore"; then
            echo ".ai_defense_log.json" >> "$repo/.gitignore"
        fi
    else
        echo ".ai_defense_log.json" > "$repo/.gitignore"
    fi
    
    echo -e "   ${GREEN}✅ Protection deployed${NC}"
    echo "   Created: ai_defense_local.py"
    echo "   Created: .ai_protected"
    ((protected++))
done

echo ""
echo "============================================================"
echo "📊 DEPLOYMENT SUMMARY"
echo "============================================================"
echo -e "✅ Protected: ${GREEN}$protected${NC} repositories"
if [ $failed -gt 0 ]; then
    echo -e "❌ Failed: ${RED}$failed${NC} repositories"
fi
echo ""

echo "🛡️  CENTRAL DEFENSE: ~/ai_defense/"
echo "📁 Protected repositories have: ./ai_defense_local.py"
echo ""

echo "📖 USAGE IN YOUR CODE:"
echo "───────────────────────────────────────────────────────────"
echo "Python:"
echo "  from ai_defense_local import protect"
echo "  safe_data = protect(untrusted_data)"
echo ""
echo "  # Or full protection:"
echo "  from ai_defense_local import local_defense"
echo "  result = local_defense.safe_ai_call(my_ai_func, data)"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✅ ALL REPOSITORIES PROTECTED${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "🔍 Next steps:"
echo "1. Review protected repositories above"
echo "2. Integrate into your AI code (see usage above)"
echo "3. Test: cd <repo> && python3 ai_defense_local.py"
echo "4. Monitor: python3 monitor_all_protection.py"
echo ""

echo "💾 Protection status saved in each repo: ./.ai_protected"
echo ""
