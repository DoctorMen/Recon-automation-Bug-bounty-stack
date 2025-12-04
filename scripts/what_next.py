#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
What Should We Test Next?
Analyze what endpoints we have and recommend next steps
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

def analyze_and_recommend():
    """Analyze what we have and recommend next steps"""
    
    print("=" * 60)
    print("Current Status & Next Steps")
    print("=" * 60)
    print()
    
    # Load priority endpoints
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints.json"
    
    if not priority_file.exists():
        print("❌ No priority endpoints found")
        print("Run: python3 scripts/prioritize_endpoints.py")
        return
    
    with open(priority_file, 'r') as f:
        endpoints = json.load(f)
    
    print(f"Total priority endpoints: {len(endpoints)}")
    print()
    
    # Categorize
    paypal = []
    apple = []
    other = []
    
    for ep in endpoints:
        url = ep.get("url", "").lower()
        domain = ep.get("domain", "").lower()
        
        if "paypal" in url or "paypal" in domain:
            paypal.append(ep)
        elif "apple" in url or "apple" in domain:
            apple.append(ep)
        else:
            other.append(ep)
    
    print("=" * 60)
    print("WHAT WE HAVE")
    print("=" * 60)
    print()
    
    print(f"✅ PayPal endpoints: {len(paypal)}")
    if paypal:
        print("   Example:")
        print(f"   {paypal[0]['url']}")
        print("   ⚠️  These are CDN subdomains (hash prefix)")
        print("   ⚠️  May be out of scope for bug bounty")
    print()
    
    print(f"✅ Apple endpoints: {len(apple)}")
    if apple:
        print("   Example:")
        print(f"   {apple[0]['url']}")
        print("   ⚠️  These are CDN subdomains (hash prefix)")
        print("   ⚠️  Already tested - got 301 redirect")
        print("   ❌ Likely OUT OF SCOPE")
    print()
    
    print(f"❌ Mastercard endpoints: 0")
    print(f"❌ Atlassian endpoints: 0")
    print(f"❌ Kraken endpoints: 0")
    print(f"❌ Rapyd endpoints: 0")
    print()
    
    print("=" * 60)
    print("PROBLEM")
    print("=" * 60)
    print()
    print("⚠️  Discovery phase is finding CDN subdomains, not real APIs!")
    print("   CDN subdomains = cache endpoints = usually out of scope")
    print()
    print("Real API endpoints should be:")
    print("   ✅ api.mastercard.com")
    print("   ✅ developer.mastercard.com")
    print("   ✅ api.atlassian.com")
    print("   ✅ api.kraken.com")
    print("   ✅ api.rapyd.net")
    print()
    
    print("=" * 60)
    print("RECOMMENDATION: 3 OPTIONS")
    print("=" * 60)
    print()
    
    print("OPTION 1: Test PayPal CDN endpoints anyway")
    print("   - They might still be testable")
    print("   - Some CDN endpoints can have vulnerabilities")
    print("   - Test: python3 scripts/test_apple_auto.py")
    print("   - But change URL to PayPal endpoint")
    print()
    
    print("OPTION 2: Focus on REAL domains (BEST)")
    print("   - Test main domains directly:")
    print("   - developer.mastercard.com")
    print("   - api.atlassian.com")
    print("   - api.kraken.com")
    print("   - dashboard.rapyd.net (you already have access)")
    print()
    print("   Commands:")
    print("   # Test Mastercard developer portal")
    print("   curl -v https://developer.mastercard.com/api/")
    print()
    print("   # Test Atlassian API")
    print("   curl -v https://api.atlassian.com/")
    print()
    print("   # Test Kraken API")
    print("   curl -v https://api.kraken.com/0/public/Time")
    print()
    
    print("OPTION 3: Re-run discovery focusing on API subdomains")
    print("   - Update discovery to prioritize:")
    print("   - api.* domains")
    print("   - developer.* domains")
    print("   - dashboard.* domains")
    print()
    
    print("=" * 60)
    print("IMMEDIATE ACTION (FASTEST ROI)")
    print("=" * 60)
    print()
    print("🎯 FOCUS ON RAPYD (You already have access!)")
    print()
    print("Why Rapyd:")
    print("   ✅ You have API keys")
    print("   ✅ You have dashboard access")
    print("   ✅ Real endpoints (not CDN)")
    print("   ✅ High rewards: $1,500 - $4,500")
    print("   ✅ Promotion: +$500-$1,000 bonus until Nov 29")
    print()
    print("Test these Rapyd endpoints:")
    print("   1. https://sandboxapi.rapyd.net/v1/payments")
    print("   2. https://dashboard.rapyd.net (manual IDOR)")
    print("   3. https://verify.rapyd.net")
    print("   4. https://checkout.rapyd.net")
    print()
    print("Focus on:")
    print("   - IDOR in dashboard (manual testing)")
    print("   - API authentication bypass")
    print("   - Business logic flaws")
    print()
    
    print("=" * 60)

if __name__ == "__main__":
    analyze_and_recommend()








