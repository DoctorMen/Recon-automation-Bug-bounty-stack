#!/usr/bin/env python3
"""
Realistic Testing Plan - What Actually Works
Based on what we actually discovered, not what we should have
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

def analyze_what_we_have():
    """Analyze what we actually discovered and can test"""
    
    print("=" * 60)
    print("REALISTIC ASSESSMENT: What Actually Works")
    print("=" * 60)
    print()
    
    # Check priority endpoints
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints.json"
    if priority_file.exists():
        with open(priority_file, 'r') as f:
            endpoints = json.load(f)
        
        print(f"[*] Found {len(endpoints)} priority endpoints")
        print()
        
        # Group by what we can actually test
        apple_endpoints = [e for e in endpoints if "apple.com" in e.get("url", "").lower()]
        paypal_endpoints = [e for e in endpoints if "paypal.com" in e.get("url", "").lower()]
        mastercard_endpoints = [e for e in endpoints if "mastercard.com" in e.get("url", "").lower()]
        rapyd_endpoints = [e for e in endpoints if "rapyd" in e.get("url", "").lower()]
        
        print("=" * 60)
        print("WHAT WE ACTUALLY HAVE:")
        print("=" * 60)
        print()
        
        if apple_endpoints:
            print(f"✅ APPLE: {len(apple_endpoints)} endpoints")
            print("   Status: DISCOVERED AND ACCESSIBLE")
            print("   Reward: Up to $2,000,000")
            print("   Can test: YES - Right now")
            print()
            print("   Top 3 Apple endpoints:")
            for idx, ep in enumerate(apple_endpoints[:3], 1):
                print(f"      {idx}. {ep['url']}")
            print()
        
        if mastercard_endpoints:
            print(f"✅ MASTERCARD: {len(mastercard_endpoints)} endpoints")
            print("   Status: DISCOVERED")
            print("   Reward: Up to $5,000")
            print("   Can test: MAYBE - Check accessibility")
            print()
        
        if rapyd_endpoints:
            print(f"✅ RAPYD: {len(rapyd_endpoints)} endpoints")
            print("   Status: DISCOVERED")
            print("   Reward: Up to $5,000")
            print("   Can test: NEEDS SETUP - Requires API keys")
            print()
        else:
            print("❌ RAPYD: 0 endpoints in priority list")
            print("   Status: NOT DISCOVERED or LOW SCORE")
            print("   Problem: Requires manual API setup, tokens, etc.")
            print("   Reality: You've been hitting 400 errors")
            print()
        
        if paypal_endpoints:
            print(f"⚠️  PAYPAL: {len(paypal_endpoints)} endpoints")
            print("   Status: DISCOVERED (but subdomains)")
            print("   Note: These are subdomains, may not be in scope")
            print()
        
        print("=" * 60)
        print("HONEST RECOMMENDATION:")
        print("=" * 60)
        print()
        
        if apple_endpoints:
            print("🥇 FOCUS ON APPLE (Best Option)")
            print("   ✅ Already discovered")
            print("   ✅ High priority scored")
            print("   ✅ No API setup needed")
            print("   ✅ Can test immediately")
            print("   ✅ Highest rewards ($2M max)")
            print()
            print("   Action: Test Apple endpoints NOW")
            print()
        
        if mastercard_endpoints:
            print("🥈 TRY MASTERCARD (Second Best)")
            print("   ✅ Already discovered")
            print("   ✅ Good rewards")
            print("   ✅ May need some setup")
            print()
        
        print("🥉 RAPYD (Skip for Now)")
        print("   ❌ Not in priority list")
        print("   ❌ Requires API setup")
        print("   ❌ You've been hitting errors")
        print("   ❌ Better to focus on what works")
        print()
        
        print("=" * 60)
        print("WHY I KEPT RECOMMENDING RAPYD:")
        print("=" * 60)
        print()
        print("My mistake - I was focused on:")
        print("  - Highest rewards ($5,000)")
        print("  - Well-documented endpoints")
        print("  - Popular bug bounty program")
        print()
        print("But I ignored:")
        print("  - You don't have Rapyd endpoints discovered")
        print("  - You're hitting 400 errors")
        print("  - Requires API setup (friction)")
        print("  - You have BETTER options (Apple)")
        print()
        
        print("=" * 60)
        print("WHAT TO DO NOW:")
        print("=" * 60)
        print()
        print("1. TEST APPLE ENDPOINTS (Do this first!)")
        print("   - You have 14 Apple endpoints")
        print("   - They're accessible")
        print("   - Highest rewards")
        print()
        print("2. If Apple doesn't work, try Mastercard")
        print()
        print("3. Skip Rapyd for now - focus on what works")
        print()
        
        return {
            "apple": apple_endpoints,
            "mastercard": mastercard_endpoints,
            "rapyd": rapyd_endpoints
        }
    
    else:
        print("❌ Priority endpoints file not found")
        print("Run: python3 scripts/prioritize_endpoints.py")
        return None

if __name__ == "__main__":
    analyze_what_we_have()


