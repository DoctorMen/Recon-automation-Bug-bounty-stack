#!/bin/bash
# Test script for SecureStack CLI
# Demonstrates various use cases and validates functionality

echo "========================================"
echo "SecureStack CLI - Test Suite"
echo "========================================"
echo ""

# Test 1: Default demo run
echo "TEST 1: Running default demo assessment..."
echo "----------------------------------------"
python3 securestack_cli.py
TEST1_EXIT=$?
echo ""
echo "Exit code: $TEST1_EXIT"
if [ $TEST1_EXIT -eq 0 ]; then
    echo "✅ TEST 1 PASSED: Default demo successful"
else
    echo "❌ TEST 1 FAILED: Exit code $TEST1_EXIT"
fi
echo ""

# Test 2: Custom target
echo "TEST 2: Running custom target assessment..."
echo "----------------------------------------"
python3 securestack_cli.py "*.example.com" "TEST-001-XYZ"
TEST2_EXIT=$?
echo ""
echo "Exit code: $TEST2_EXIT"
if [ $TEST2_EXIT -eq 0 ]; then
    echo "✅ TEST 2 PASSED: Custom target successful"
else
    echo "❌ TEST 2 FAILED: Exit code $TEST2_EXIT"
fi
echo ""

# Test 3: Verify report files exist
echo "TEST 3: Verifying report generation..."
echo "----------------------------------------"
if [ -d "reports" ]; then
    echo "✅ Reports directory exists"
    REPORT_COUNT=$(ls -1 reports/*.json 2>/dev/null | wc -l)
    echo "Found $REPORT_COUNT JSON report(s)"
    
    if [ $REPORT_COUNT -gt 0 ]; then
        echo "✅ TEST 3 PASSED: Reports generated successfully"
        echo ""
        echo "Sample report:"
        head -15 reports/SecureStack_Scan_*.json
    else
        echo "❌ TEST 3 FAILED: No reports found"
    fi
else
    echo "❌ TEST 3 FAILED: Reports directory not found"
fi
echo ""

# Test 4: Verify JSON structure
echo "TEST 4: Validating JSON report structure..."
echo "----------------------------------------"
if command -v python3 &> /dev/null; then
    LATEST_REPORT=$(ls -t reports/*.json 2>/dev/null | head -1)
    if [ -n "$LATEST_REPORT" ]; then
        python3 << EOF
import json
import sys

try:
    with open('$LATEST_REPORT', 'r') as f:
        data = json.load(f)
    
    required_fields = ['version', 'timestamp', 'target_scope', 'engagement_id', 
                      'duration_seconds', 'endpoints_discovered', 'vulnerabilities_found']
    
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        print(f"❌ Missing required fields: {', '.join(missing_fields)}")
        sys.exit(1)
    else:
        print("✅ All required fields present")
        print(f"   Version: {data['version']}")
        print(f"   Target: {data['target_scope']}")
        print(f"   Endpoints: {data['endpoints_discovered']}")
        print(f"   Vulnerabilities: {data['vulnerabilities_found']}")
        print("✅ TEST 4 PASSED: JSON structure valid")
        sys.exit(0)
except Exception as e:
    print(f"❌ TEST 4 FAILED: {e}")
    sys.exit(1)
EOF
        TEST4_EXIT=$?
    else
        echo "❌ TEST 4 FAILED: No report file found"
        TEST4_EXIT=1
    fi
else
    echo "⚠️  TEST 4 SKIPPED: Python3 not found"
    TEST4_EXIT=0
fi
echo ""

# Summary
echo "========================================"
echo "TEST SUMMARY"
echo "========================================"
TOTAL_TESTS=4
PASSED=0

[ $TEST1_EXIT -eq 0 ] && ((PASSED++))
[ $TEST2_EXIT -eq 0 ] && ((PASSED++))

# Test 3: Check if reports exist (not just directory)
if [ -d "reports" ] && [ $(ls -1 reports/*.json 2>/dev/null | wc -l) -gt 0 ]; then
    ((PASSED++))
fi

[ $TEST4_EXIT -eq 0 ] && ((PASSED++))

echo "Tests passed: $PASSED/$TOTAL_TESTS"
echo ""

if [ $PASSED -eq $TOTAL_TESTS ]; then
    echo "✅ ALL TESTS PASSED - SecureStack CLI is working correctly!"
    exit 0
else
    echo "⚠️  Some tests failed - see details above"
    exit 1
fi
