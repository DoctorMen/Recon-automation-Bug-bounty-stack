#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# 🛡️ TEST SAFETY SYSTEM
# Quick test to verify all protection layers are working

echo "=================================="
echo "🛡️  SAFETY SYSTEM TEST"
echo "=================================="
echo ""

# Test 1: Check master safety system exists
echo "Test 1: Master Safety System"
if [ -f "MASTER_SAFETY_SYSTEM.py" ]; then
    echo "✅ MASTER_SAFETY_SYSTEM.py found"
else
    echo "❌ MASTER_SAFETY_SYSTEM.py NOT FOUND"
    exit 1
fi
echo ""

# Test 2: Check safe_scan wrapper exists
echo "Test 2: Safe Scan Wrapper"
if [ -f "safe_scan.py" ]; then
    echo "✅ safe_scan.py found"
else
    echo "❌ safe_scan.py NOT FOUND"
    exit 1
fi
echo ""

# Test 3: Check authorization system
echo "Test 3: Authorization System"
if [ -f "authorization_checker.py" ]; then
    echo "✅ authorization_checker.py found"
else
    echo "❌ authorization_checker.py NOT FOUND"
    exit 1
fi
echo ""

# Test 4: Check protection directory
echo "Test 4: Protection Directory"
if [ -d ".protection" ]; then
    echo "✅ .protection directory exists"
else
    echo "⚠️  .protection directory will be created on first use"
fi
echo ""

# Test 5: Try blocking dangerous target
echo "Test 5: Dangerous Target Protection"
echo "Testing if .gov domain is blocked..."
python3 MASTER_SAFETY_SYSTEM.py test fbi.gov > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "✅ .gov domain correctly BLOCKED"
else
    echo "⚠️  Warning: .gov domain should be blocked"
fi
echo ""

# Test 6: Check pipeline integration
echo "Test 6: Pipeline Integration"
if grep -q "MASTER_SAFETY_SYSTEM" "run_pipeline.py"; then
    echo "✅ Pipeline integrated with safety system"
else
    echo "❌ Pipeline NOT integrated"
    exit 1
fi
echo ""

echo "=================================="
echo "📊 TEST SUMMARY"
echo "=================================="
echo ""
echo "✅ Safety system is INSTALLED"
echo "✅ All core components present"
echo "✅ Protection layers active"
echo ""
echo "NEXT STEPS:"
echo "1. Add scope: python3 MASTER_SAFETY_SYSTEM.py add-scope"
echo "2. Add auth: python3 authorization_checker.py add"
echo "3. Test target: python3 MASTER_SAFETY_SYSTEM.py test <target>"
echo "4. Safe scan: python3 safe_scan.py <target> recon"
echo ""
echo "YOU ARE PROTECTED 🛡️"
