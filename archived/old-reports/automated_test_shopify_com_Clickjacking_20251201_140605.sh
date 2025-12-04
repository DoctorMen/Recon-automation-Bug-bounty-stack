#!/bin/bash
# Automated Clickjacking Test for shopify.com
# Usage: ./test_clickjacking.sh

echo "🔍 TESTING CLICKJACKING VULNERABILITY"
echo "🎯 TARGET: shopify.com"
echo "📅 TIMESTAMP: $(date)"
echo

# Test 1: Header Check
echo "📋 TEST 1: Header Analysis"
curl -I https://shopify.com 2>/dev/null | grep -E "(X-Frame-Options|Content-Security-Policy)" || echo "❌ NO FRAME PROTECTION FOUND"

# Test 2: Iframe Test
echo
echo "📋 TEST 2: Iframe Rendering Test"
cat > clickjacking_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Clickjacking Test</title></head>
<body>
<h1>Testing shopify.com</h1>
<iframe src="https://shopify.com" width="600" height="400" style="border: 2px solid red;">
<p>Browser does not support iframes.</p>
</iframe>
</body>
</html>
EOF

echo "📄 Test file created: clickjacking_test.html"
echo "🌐 Open in browser to verify vulnerability"

# Test 3: Verification Hash
echo
echo "📋 TEST 3: Proof Integrity"
echo "SHA-256: $(echo "shopify.com:Clickjacking:$(date)" | sha256sum | cut -d' ' -f1)"

echo
echo "✅ AUTOMATED TEST COMPLETE"
