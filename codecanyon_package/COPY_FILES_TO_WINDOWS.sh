#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Copy all new files to Windows Downloads folder

DEST="/mnt/c/Users/Doc Lab/Downloads/Work/"

echo "🚀 Copying files to Windows..."
echo "Destination: $DEST"
echo ""

# Guides
echo "📚 Copying guides..."
cp -v MASTER_SYSTEM_OVERVIEW.md "$DEST" 2>/dev/null && echo "✅ MASTER_SYSTEM_OVERVIEW.md" || echo "⚠️ MASTER_SYSTEM_OVERVIEW.md (may already exist)"
cp -v GET_PAID_TODAY_MULTIPLATFORM.md "$DEST" 2>/dev/null && echo "✅ GET_PAID_TODAY_MULTIPLATFORM.md" || echo "⚠️ GET_PAID_TODAY_MULTIPLATFORM.md (may already exist)"
cp -v IMMEDIATE_ACTION_MONEY_TODAY.md "$DEST" 2>/dev/null && echo "✅ IMMEDIATE_ACTION_MONEY_TODAY.md" || echo "⚠️ IMMEDIATE_ACTION_MONEY_TODAY.md (may already exist)"
cp -v MONEY_MAKING_QUICK_REFERENCE.md "$DEST" 2>/dev/null && echo "✅ MONEY_MAKING_QUICK_REFERENCE.md" || echo "⚠️ MONEY_MAKING_QUICK_REFERENCE.md (may already exist)"
cp -v NATURAL_LANGUAGE_GUIDE.md "$DEST" 2>/dev/null && echo "✅ NATURAL_LANGUAGE_GUIDE.md" || echo "⚠️ NATURAL_LANGUAGE_GUIDE.md (may already exist)"
cp -v COMPLETE_SYSTEM_INDEX.md "$DEST" 2>/dev/null && echo "✅ COMPLETE_SYSTEM_INDEX.md" || echo "⚠️ COMPLETE_SYSTEM_INDEX.md (may already exist)"

echo ""
echo "🤖 Copying Python scripts..."
cp -v scripts/multi_platform_domination.py "$DEST" 2>/dev/null && echo "✅ multi_platform_domination.py" || echo "⚠️ multi_platform_domination.py (may already exist)"
cp -v scripts/money_making_toolkit.py "$DEST" 2>/dev/null && echo "✅ money_making_toolkit.py" || echo "⚠️ money_making_toolkit.py (may already exist)"
cp -v scripts/natural_language_bridge.py "$DEST" 2>/dev/null && echo "✅ natural_language_bridge.py" || echo "⚠️ natural_language_bridge.py (may already exist)"

echo ""
echo "✅ DONE! Files are in: C:\\Users\\Doc Lab\\Downloads\\Work\\"
echo ""
echo "📂 Files ready to use:"
echo "  • IMMEDIATE_ACTION_MONEY_TODAY.md (READ THIS FIRST)"
echo "  • GET_PAID_TODAY_MULTIPLATFORM.md"
echo "  • MONEY_MAKING_QUICK_REFERENCE.md"
echo "  • NATURAL_LANGUAGE_GUIDE.md"
echo "  • MASTER_SYSTEM_OVERVIEW.md"
echo "  • COMPLETE_SYSTEM_INDEX.md"

