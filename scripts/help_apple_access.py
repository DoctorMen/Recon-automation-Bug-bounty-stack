#!/usr/bin/env python3
"""
Access Apple Bug Bounty Portal
Help navigate and check scope
"""

def help_access_apple_portal():
    """Help user access Apple bug bounty portal"""
    
    print("=" * 60)
    print("APPLE BUG BOUNTY PORTAL ACCESS")
    print("=" * 60)
    print()
    print("If you've given me access, here's what I can help with:")
    print()
    print("1. Navigate to Apple's portal:")
    print("   https://security.apple.com/bounty/")
    print()
    print("2. Check scope guidelines:")
    print("   https://security.apple.com/bounty/guidelines/")
    print()
    print("3. Verify your endpoints are in scope:")
    print("   - 2b4a6b31ca2273bb.apple.com")
    print("   - Check if CDN/web endpoints are listed")
    print()
    print("What would you like me to check?")
    print()
    print("Options:")
    print("  a) Navigate to Apple portal and check scope")
    print("  b) Verify if your endpoints are in scope")
    print("  c) Help submit a finding")
    print("  d) Something else")
    print()

if __name__ == "__main__":
    help_access_apple_portal()


