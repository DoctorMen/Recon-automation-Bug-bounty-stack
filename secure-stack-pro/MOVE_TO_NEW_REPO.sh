#!/bin/bash
# Script to copy SecureStack CLI files to the new Secure-Stack-Pro repository
# Repository: https://github.com/DoctorMen/Secure-Stack-Pro

set -e

echo "=========================================="
echo "SecureStack CLI - Repository Migration"
echo "=========================================="
echo ""

# Target repository details
TARGET_REPO="https://github.com/DoctorMen/Secure-Stack-Pro.git"
TARGET_DIR="${1:-$HOME/Secure-Stack-Pro}"

echo "Target Repository: $TARGET_REPO"
echo "Local Directory: $TARGET_DIR"
echo ""

# Check if target directory already exists
if [ -d "$TARGET_DIR" ]; then
    echo "⚠️  Directory $TARGET_DIR already exists."
    echo "Options:"
    echo "  1. Remove it: rm -rf $TARGET_DIR"
    echo "  2. Use a different location: $0 /path/to/different/location"
    exit 1
fi

echo "Step 1: Cloning the target repository..."
git clone "$TARGET_REPO" "$TARGET_DIR"

echo ""
echo "Step 2: Copying SecureStack CLI files..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Files to copy (CLI-specific files only, excluding backend/frontend)
CLI_FILES=(
    "securestack_cli.py"
    "test_securestack.sh"
    "requirements.txt"
    "LICENSE_CLI"
    ".gitignore"
    "INDEX.md"
    "QUICK_START.md"
    "SECURESTACK_CLI_README.md"
    "EXTRACTION_GUIDE.md"
    "PROOF_OF_CONCEPT_SUMMARY.md"
    "README_COMPLETE.md"
    "VISUAL_DEMO.md"
)

# Copy files
for file in "${CLI_FILES[@]}"; do
    if [ -f "$SCRIPT_DIR/$file" ]; then
        cp "$SCRIPT_DIR/$file" "$TARGET_DIR/"
        echo "  ✅ Copied: $file"
    else
        echo "  ⚠️  Not found: $file"
    fi
done

# Copy reports directory structure
mkdir -p "$TARGET_DIR/reports"
touch "$TARGET_DIR/reports/.gitkeep"
echo "  ✅ Created: reports/.gitkeep"

# Rename LICENSE_CLI to LICENSE
if [ -f "$TARGET_DIR/LICENSE_CLI" ]; then
    mv "$TARGET_DIR/LICENSE_CLI" "$TARGET_DIR/LICENSE"
    echo "  ✅ Renamed: LICENSE_CLI -> LICENSE"
fi

# Rename SECURESTACK_CLI_README.md to README.md if README.md doesn't exist
if [ ! -f "$TARGET_DIR/README.md" ] && [ -f "$TARGET_DIR/SECURESTACK_CLI_README.md" ]; then
    mv "$TARGET_DIR/SECURESTACK_CLI_README.md" "$TARGET_DIR/README.md"
    echo "  ✅ Set as main README: SECURESTACK_CLI_README.md -> README.md"
elif [ -f "$TARGET_DIR/README.md" ]; then
    echo "  ℹ️  README.md already exists in target repo, keeping both"
fi

echo ""
echo "Step 3: Creating initial commit..."
cd "$TARGET_DIR"

git add .
git commit -m "Initial commit: SecureStack CLI v2.1

Migrated from DoctorMen/Recon-automation-Bug-bounty-stack

Features:
- Complete CLI tool for automated security assessment
- ASCII banner and professional output
- Legal authorization verification (CFAA/RoE)
- Passive reconnaissance simulation
- Neural risk scoring (ML-based)
- BOLA/IDOR vulnerability detection
- PDF + JSON report generation
- Comprehensive test suite (4/4 passing)
- Complete documentation (7 guides)

Ready for use and further development."

echo ""
echo "Step 4: Review changes before pushing..."
echo "Files added:"
git status --short

echo ""
echo "=========================================="
echo "✅ Migration Complete!"
echo "=========================================="
echo ""
echo "Next Steps:"
echo ""
echo "1. Review the files in: $TARGET_DIR"
echo "   cd $TARGET_DIR"
echo ""
echo "2. Test the tool:"
echo "   python3 securestack_cli.py"
echo "   ./test_securestack.sh"
echo ""
echo "3. Push to GitHub when ready:"
echo "   git push origin main"
echo ""
echo "4. (Optional) Create a release tag:"
echo "   git tag -a v2.1.0 -m 'SecureStack CLI v2.1.0 - Initial Release'"
echo "   git push origin v2.1.0"
echo ""
echo "Repository: $TARGET_REPO"
echo "Local copy: $TARGET_DIR"
echo ""
