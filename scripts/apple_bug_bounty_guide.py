#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Apple Bug Bounty - Interactive Guide
Step-by-step guide for submitting findings
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

def interactive_guide():
    """Interactive guide for Apple bug bounty"""
    
    print("=" * 60)
    print("APPLE BUG BOUNTY - INTERACTIVE GUIDE")
    print("=" * 60)
    print()
    print("✅ Great! You have an Apple Security Bounty account")
    print("   Let's verify scope and prepare for testing")
    print()
    
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 1: VERIFY SCOPE")
    print("=" * 60)
    print()
    print("⚠️  CRITICAL: Apple's program focuses on:")
    print("   ✅ iOS, macOS, Safari security")
    print("   ✅ iCloud, Apple ID security")
    print("   ✅ Apple hardware security")
    print("   ❌ NOT web CDN endpoints")
    print()
    print("Your endpoints: 2b4a6b31ca2273bb.apple.com")
    print("   - These are CDN subdomains")
    print("   - Hash prefix = Content Delivery Network")
    print("   - Usually OUT OF SCOPE")
    print()
    
    verify = input("Have you checked Apple's scope? (yes/no): ").lower()
    if verify != "yes":
        print()
        print("📋 ACTION REQUIRED:")
        print("   1. Go to: https://security.apple.com/bounty/guidelines/")
        print("   2. Read the 'Scope' section carefully")
        print("   3. Check if web/CDN endpoints are listed")
        print("   4. Come back and run this guide again")
        print()
        return
    
    print()
    print("✅ Good! Let's continue...")
    print()
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 2: UNDERSTAND APPLE'S PROGRAM")
    print("=" * 60)
    print()
    print("Apple Security Bounty focuses on:")
    print()
    print("✅ IN SCOPE (Typical):")
    print("   - iOS vulnerabilities")
    print("   - macOS vulnerabilities")
    print("   - Safari security issues")
    print("   - iCloud security flaws")
    print("   - Apple ID authentication issues")
    print("   - Hardware security vulnerabilities")
    print()
    print("❌ OUT OF SCOPE (Typical):")
    print("   - CDN endpoints (like yours)")
    print("   - Third-party services")
    print("   - Denial of service (DoS)")
    print("   - Social engineering")
    print("   - Physical attacks")
    print()
    
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 3: CHECK YOUR ENDPOINTS")
    print("=" * 60)
    print()
    
    # Load Apple endpoints
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints_by_program.json"
    apple_endpoints = []
    
    if priority_file.exists():
        with open(priority_file, 'r') as f:
            data = json.load(f)
            apple_endpoints = data.get("apple", [])
    
    if apple_endpoints:
        print(f"Found {len(apple_endpoints)} Apple endpoints:")
        print()
        for idx, ep in enumerate(apple_endpoints[:5], 1):
            print(f"   {idx}. {ep.get('url', 'N/A')}")
        print()
    else:
        print("No Apple endpoints found in priority list")
        print()
    
    print("⚠️  ANALYSIS:")
    print("   Domain: 2b4a6b31ca2273bb.apple.com")
    print("   Type: CDN subdomain (hash prefix)")
    print("   Status: Likely OUT OF SCOPE")
    print()
    
    test_anyway = input("Do you want to test anyway? (yes/no): ").lower()
    print()
    
    if test_anyway != "yes":
        print("✅ Smart decision - Better safe than sorry!")
        print()
        print("RECOMMENDATION:")
        print("   Focus on Rapyd instead:")
        print("   - Confirmed in scope")
        print("   - Safe harbor protection")
        print("   - High rewards ($1,500-$4,500)")
        print()
        return
    
    print("=" * 60)
    print("STEP 4: SAFE TESTING PROTOCOL")
    print("=" * 60)
    print()
    print("⚠️  WARNING: Testing out of scope = RISKY")
    print("   But if you proceed, follow these rules:")
    print()
    print("SAFE TESTING RULES:")
    print("   1. ✅ Single requests only (no automation)")
    print("   2. ✅ No rate limiting abuse")
    print("   3. ✅ No data exfiltration")
    print("   4. ✅ Document everything")
    print("   5. ✅ Stop if you get 403/401 (protected)")
    print()
    
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 5: PREPARE TESTING")
    print("=" * 60)
    print()
    print("Testing checklist:")
    print()
    print("Before testing:")
    print("   [ ] Verified scope (you did this)")
    print("   [ ] Read Apple's guidelines")
    print("   [ ] Understand what's in scope")
    print("   [ ] Have screenshot tool ready")
    print("   [ ] Have note-taking ready")
    print()
    
    ready = input("Ready to test? (yes/no): ").lower()
    print()
    
    if ready != "yes":
        print("✅ Preparation is key!")
        print("   Come back when ready")
        return
    
    print("=" * 60)
    print("STEP 6: TESTING COMMANDS")
    print("=" * 60)
    print()
    print("Here are safe test commands:")
    print()
    print("1. Basic connectivity test:")
    print("   curl -v http://2b4a6b31ca2273bb.apple.com/api/checkout")
    print()
    print("2. Check headers:")
    print("   curl -I http://2b4a6b31ca2273bb.apple.com/api/checkout")
    print()
    print("3. Follow redirects:")
    print("   curl -L http://2b4a6b31ca2273bb.apple.com/api/checkout")
    print()
    print("⚠️  REMEMBER:")
    print("   - One request at a time")
    print("   - Document everything")
    print("   - Stop if you get 403/401")
    print()
    
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 7: IF YOU FIND A VULNERABILITY")
    print("=" * 60)
    print()
    print("Documentation requirements:")
    print()
    print("1. Clear title:")
    print("   'Vulnerability Type' in 'Specific Component'")
    print()
    print("2. Detailed description:")
    print("   - What the vulnerability is")
    print("   - Where it's located")
    print("   - How it works")
    print()
    print("3. Steps to reproduce:")
    print("   - Numbered steps")
    print("   - Exact URLs/endpoints")
    print("   - Request/response examples")
    print()
    print("4. Proof of concept:")
    print("   - Screenshots")
    print("   - HTTP requests/responses")
    print("   - Exploit code (if applicable)")
    print()
    print("5. Impact assessment:")
    print("   - What can an attacker do?")
    print("   - Who is affected?")
    print("   - What data is at risk?")
    print()
    
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 8: SUBMIT YOUR FINDING")
    print("=" * 60)
    print()
    print("Submission process:")
    print()
    print("1. Go to: https://security.apple.com/bounty/")
    print("2. Sign in with your Apple ID")
    print("3. Click 'Submit a Report'")
    print("4. Fill out the form:")
    print("   - Title")
    print("   - Description")
    print("   - Steps to reproduce")
    print("   - Impact")
    print("   - Attach screenshots/files")
    print("5. Submit")
    print()
    print("⚠️  IMPORTANT:")
    print("   - Be honest about scope")
    print("   - If out of scope, they'll reject it")
    print("   - But you won't get in trouble if you're honest")
    print()
    
    input("Press Enter to continue...")
    print()
    
    print("=" * 60)
    print("STEP 9: ALTERNATIVE - FOCUS ON RAPYD")
    print("=" * 60)
    print()
    print("💡 RECOMMENDATION:")
    print("   Instead of Apple CDN endpoints, focus on Rapyd:")
    print()
    print("Why Rapyd:")
    print("   ✅ Confirmed in scope")
    print("   ✅ Full safe harbor protection")
    print("   ✅ You already have API keys")
    print("   ✅ High rewards ($1,500-$4,500)")
    print("   ✅ Bonus rewards until Nov 29")
    print()
    print("Rapyd endpoints:")
    print("   - sandboxapi.rapyd.net/v1")
    print("   - dashboard.rapyd.net")
    print("   - verify.rapyd.net")
    print("   - checkout.rapyd.net")
    print()
    
    choice = input("Would you like to focus on Rapyd instead? (yes/no): ").lower()
    print()
    
    if choice == "yes":
        print("✅ Excellent choice!")
        print()
        print("Next steps for Rapyd:")
        print("   1. Review Rapyd scope: https://bugcrowd.com/engagements/rapyd")
        print("   2. Test sandboxapi.rapyd.net/v1 endpoints")
        print("   3. Focus on:")
        print("      - API authentication bypass")
        print("      - Transaction amount manipulation")
        print("      - Business logic flaws")
        print("   4. Document findings")
        print("   5. Submit to Bugcrowd")
        print()
    
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print()
    print("✅ You have Apple Security Bounty account")
    print("✅ You've verified scope")
    print("✅ You understand testing requirements")
    print()
    print("Next actions:")
    print("   1. Test endpoints (if in scope)")
    print("   2. Document findings")
    print("   3. Submit to Apple")
    print("   OR")
    print("   1. Focus on Rapyd (safer, higher ROI)")
    print("   2. Test Rapyd endpoints")
    print("   3. Submit to Bugcrowd")
    print()
    print("=" * 60)
    print("Good luck! 🎯")
    print("=" * 60)

if __name__ == "__main__":
    interactive_guide()








