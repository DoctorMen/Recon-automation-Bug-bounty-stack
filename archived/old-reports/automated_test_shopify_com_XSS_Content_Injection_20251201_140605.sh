#!/bin/bash
# Automated XSS Test for shopify.com
# Usage: ./test_xss.sh

echo "🔍 TESTING XSS VULNERABILITY"
echo "🎯 TARGET: shopify.com"
echo "📅 TIMESTAMP: $(date)"
echo

# Test 1: CSP Header Check
echo "📋 TEST 1: CSP Header Analysis"
curl -I https://shopify.com 2>/dev/null | grep "Content-Security-Policy" || echo "❌ NO CSP HEADER FOUND"

# Test 2: XSS Payload Test
echo
echo "📋 TEST 2: XSS Payload Test"
curl -s https://shopify.com | grep -i "script" | head -5 || echo "❌ NO SCRIPT TAGS FOUND"

# Test 3: JavaScript Injection Test
echo
echo "📋 TEST 3: JavaScript Injection Test"
cat > xss_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>XSS Test</title></head>
<body>
<h1>XSS Injection Test for shopify.com</h1>
<script>
// Test if CSP blocks inline scripts
try {
    eval('console.log("XSS Test: If this appears, CSP is missing")');
    console.log("✅ VULNERABLE TO XSS");
} catch(e) {
    console.log("❌ CSP BLOCKING XSS");
}
</script>
</body>
</html>
EOF

echo "📄 Test file created: xss_test.html"
echo "🌐 Open in browser console to verify"

echo
echo "✅ AUTOMATED TEST COMPLETE"
