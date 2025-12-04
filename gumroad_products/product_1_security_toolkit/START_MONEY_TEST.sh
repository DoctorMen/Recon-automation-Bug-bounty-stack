#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Legal Money-Making Test - Quick Start Script
# Walks you through testing the smart pipeline on legal bug bounty targets

echo "============================================================"
echo "💰 SMART PIPELINE - LEGAL MONEY-MAKING TEST"
echo "============================================================"
echo ""
echo "This script will guide you through testing the smart pipeline"
echo "on LEGAL bug bounty targets to prove it works and makes money."
echo ""

# Check if smart pipeline exists
if [ ! -f "smart_pipeline.py" ]; then
    echo "❌ Error: smart_pipeline.py not found"
    echo "Make sure you're in the correct directory"
    exit 1
fi

echo "✅ Smart pipeline found"
echo ""

# Step 1: Show legal targets
echo "============================================================"
echo "STEP 1: LEGAL TARGETS"
echo "============================================================"
echo ""
echo "First, let's see which targets are legal to test..."
echo ""
read -p "Press ENTER to view legal targets..."

python3 test_legal_targets.py --list

echo ""
echo "⚠️  IMPORTANT: Before testing ANY target, you MUST:"
echo "   1. Verify it has a PUBLIC bug bounty program"
echo "   2. Read the program's policy"
echo "   3. Ensure your testing is within scope"
echo "   4. Commit to responsible disclosure"
echo ""
read -p "Do you understand these requirements? (yes/no): " understood

if [ "$understood" != "yes" ]; then
    echo ""
    echo "❌ Please review legal requirements before testing."
    echo "Read: LEGAL_MONEY_TEST.md"
    exit 1
fi

echo ""
echo "✅ Legal requirements understood"
echo ""

# Step 2: Enter target
echo "============================================================"
echo "STEP 2: CHOOSE TARGET"
echo "============================================================"
echo ""
echo "Enter a target from a PUBLIC bug bounty program."
echo "Example: hackerone.com (if they have a public program)"
echo ""
read -p "Enter target domain: " target

if [ -z "$target" ]; then
    echo "❌ No target entered"
    exit 1
fi

echo ""
echo "Target: $target"
echo ""

# Step 3: Verify authorization
echo "============================================================"
echo "STEP 3: VERIFY AUTHORIZATION"
echo "============================================================"
echo ""
echo "Before scanning $target, confirm:"
echo "1. ✓ This domain has a PUBLIC bug bounty program"
echo "2. ✓ You've read the program policy"
echo "3. ✓ Your testing is within scope"
echo "4. ✓ You will follow responsible disclosure"
echo ""
read -p "Can you confirm ALL of the above? (yes/no): " confirmed

if [ "$confirmed" != "yes" ]; then
    echo ""
    echo "❌ Authorization not confirmed. Test cancelled."
    echo "Please verify authorization before scanning."
    exit 1
fi

echo ""
echo "✅ Authorization confirmed"
echo ""

# Step 4: Choose test type
echo "============================================================"
echo "STEP 4: CHOOSE TEST TYPE"
echo "============================================================"
echo ""
echo "Select a test to run:"
echo "1. Speed Test (1 scan, prove it's faster)"
echo "2. Learning Test (3 scans, prove it learns)"
echo "3. Both (comprehensive test)"
echo ""
read -p "Choose (1/2/3): " test_type

echo ""

# Run tests
case $test_type in
    1)
        echo "🚀 Running Speed Test..."
        echo ""
        python3 test_legal_targets.py --speed "$target"
        ;;
    2)
        echo "🧠 Running Learning Test (3 iterations)..."
        echo ""
        python3 test_legal_targets.py --learning "$target" --iterations 3
        ;;
    3)
        echo "🚀 Running Speed Test..."
        echo ""
        python3 test_legal_targets.py --speed "$target"
        
        echo ""
        echo "Waiting 10 seconds before learning test..."
        sleep 10
        
        echo ""
        echo "🧠 Running Learning Test..."
        echo ""
        python3 test_legal_targets.py --learning "$target" --iterations 3
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

# Step 5: Analyze findings
echo ""
echo "============================================================"
echo "STEP 5: ANALYZE FINDINGS"
echo "============================================================"
echo ""
read -p "Analyze findings from the scan? (yes/no): " analyze

if [ "$analyze" = "yes" ]; then
    echo ""
    python3 test_legal_targets.py --analyze
fi

# Step 6: Next steps
echo ""
echo "============================================================"
echo "STEP 6: NEXT STEPS"
echo "============================================================"
echo ""
echo "✅ Test complete! Here's what to do next:"
echo ""
echo "1. Review findings in: output/triage.json"
echo "2. Manually verify any vulnerabilities found"
echo "3. Check test report: output/legal_test_report.json"
echo "4. If you found real bugs:"
echo "   - Document them properly"
echo "   - Submit to the bug bounty program"
echo "   - Follow responsible disclosure"
echo ""
echo "5. Track your submissions and earnings"
echo ""
echo "📖 Read full guide: LEGAL_MONEY_TEST.md"
echo ""
echo "============================================================"
echo "💰 GOOD LUCK FINDING BUGS AND MAKING MONEY!"
echo "============================================================"
echo ""
