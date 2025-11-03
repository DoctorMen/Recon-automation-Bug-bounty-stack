#!/usr/bin/env python3
"""
Rapyd Endpoint Generator
Creates priority list of known Rapyd endpoints for manual testing
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

# Known Rapyd endpoints based on documentation and bug bounty scope
RAPYD_ENDPOINTS = [
    # Sandbox API - Payment endpoints (highest priority)
    {
        "url": "https://sandboxapi.rapyd.net/v1/payments",
        "method": "GET",
        "priority": "critical",
        "score": 100,
        "reasons": ["Payment API", "Sandbox API", "Tier 3 Premium rewards"],
        "test": "IDOR, auth bypass, amount manipulation"
    },
    {
        "url": "https://sandboxapi.rapyd.net/v1/payments/{payment_id}",
        "method": "GET",
        "priority": "critical",
        "score": 100,
        "reasons": ["Payment API", "IDOR potential", "Tier 3 Premium"],
        "test": "IDOR - test with different payment IDs"
    },
    {
        "url": "https://sandboxapi.rapyd.net/v1/payments",
        "method": "POST",
        "priority": "critical",
        "score": 95,
        "reasons": ["Payment creation", "Business logic", "Tier 3 Premium"],
        "test": "Amount manipulation, race conditions"
    },
    
    # Customer endpoints
    {
        "url": "https://sandboxapi.rapyd.net/v1/customers",
        "method": "GET",
        "priority": "high",
        "score": 90,
        "reasons": ["Customer API", "Data exposure"],
        "test": "IDOR, data exposure"
    },
    {
        "url": "https://sandboxapi.rapyd.net/v1/customers/{customer_id}",
        "method": "GET",
        "priority": "high",
        "score": 90,
        "reasons": ["Customer API", "IDOR potential"],
        "test": "IDOR - test with different customer IDs"
    },
    
    # Wallet endpoints
    {
        "url": "https://sandboxapi.rapyd.net/v1/wallets",
        "method": "GET",
        "priority": "high",
        "score": 85,
        "reasons": ["Wallet API", "Financial data"],
        "test": "IDOR, balance manipulation"
    },
    {
        "url": "https://sandboxapi.rapyd.net/v1/wallets/{wallet_id}",
        "method": "GET",
        "priority": "high",
        "score": 85,
        "reasons": ["Wallet API", "IDOR potential"],
        "test": "IDOR - test with different wallet IDs"
    },
    
    # Dashboard endpoints (IDOR testing)
    {
        "url": "https://dashboard.rapyd.net/collect/payments",
        "method": "GET",
        "priority": "high",
        "score": 80,
        "reasons": ["Dashboard", "Payment collection", "IDOR testing"],
        "test": "IDOR - access other users' payments"
    },
    {
        "url": "https://dashboard.rapyd.net/collect/payments/{payment_id}",
        "method": "GET",
        "priority": "critical",
        "score": 95,
        "reasons": ["Dashboard", "IDOR potential", "Tier 2 rewards"],
        "test": "IDOR - modify payment ID in URL"
    },
    {
        "url": "https://dashboard.rapyd.net/collect/customers",
        "method": "GET",
        "priority": "high",
        "score": 80,
        "reasons": ["Dashboard", "Customer data"],
        "test": "IDOR - access other users' customer data"
    },
    {
        "url": "https://dashboard.rapyd.net/collect/customers/{customer_id}",
        "method": "GET",
        "priority": "high",
        "score": 85,
        "reasons": ["Dashboard", "IDOR potential"],
        "test": "IDOR - modify customer ID in URL"
    },
    
    # Other API endpoints
    {
        "url": "https://sandboxapi.rapyd.net/v1/issuing/cards",
        "method": "GET",
        "priority": "high",
        "score": 85,
        "reasons": ["Issuing API", "Card data"],
        "test": "IDOR, data exposure"
    },
    {
        "url": "https://sandboxapi.rapyd.net/v1/disburse",
        "method": "POST",
        "priority": "critical",
        "score": 90,
        "reasons": ["Disbursement API", "Financial operation"],
        "test": "Amount manipulation, business logic"
    },
]

def generate_rapyd_priority_list():
    """Generate priority list for Rapyd endpoints"""
    
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("Rapyd Endpoint Priority List")
    print("=" * 60)
    print()
    print(f"Generated {len(RAPYD_ENDPOINTS)} known Rapyd endpoints")
    print()
    
    # Sort by score
    sorted_endpoints = sorted(RAPYD_ENDPOINTS, key=lambda x: x["score"], reverse=True)
    
    print("Top Priority Rapyd Endpoints for Manual Testing:")
    print()
    
    for idx, ep in enumerate(sorted_endpoints[:15], 1):
        print(f"{idx}. Score: {ep['score']} - {ep['priority'].upper()}")
        print(f"   URL: {ep['url']}")
        print(f"   Method: {ep['method']}")
        print(f"   Reasons: {', '.join(ep['reasons'])}")
        print(f"   Test: {ep['test']}")
        print()
    
    # Save to file
    output_file = ROI_OUTPUT_DIR / "rapyd_endpoints_priority.json"
    with open(output_file, 'w') as f:
        json.dump(sorted_endpoints, f, indent=2)
    
    print(f"[*] Saved to: {output_file}")
    print()
    
    # Generate testing plan
    plan_file = ROI_OUTPUT_DIR / "RAPYD_MANUAL_TESTING_PLAN.md"
    
    plan_content = f"""# Rapyd Manual Testing Plan

## Priority Endpoints ({len(sorted_endpoints)} total)

### Critical Priority (Payment APIs)

"""
    
    critical = [e for e in sorted_endpoints if e["priority"] == "critical"]
    for ep in critical:
        plan_content += f"""#### {ep['url']}
- **Method:** {ep['method']}
- **Score:** {ep['score']}
- **Reasons:** {', '.join(ep['reasons'])}
- **Testing Focus:** {ep['test']}

**Manual Testing Steps:**
1. Test IDOR - Try accessing with different IDs
2. Test Authentication - Remove/modify auth headers
3. Test Authorization - Test with different user tokens
4. Test Business Logic - Amount manipulation, race conditions

---

"""
    
    plan_content += """
### High Priority (Customer/Wallet APIs)

"""
    
    high = [e for e in sorted_endpoints if e["priority"] == "high"]
    for ep in high:
        plan_content += f"""#### {ep['url']}
- **Method:** {ep['method']}
- **Score:** {ep['score']}
- **Reasons:** {', '.join(ep['reasons'])}
- **Testing Focus:** {ep['test']}

---

"""
    
    plan_content += """
## Testing Methodology

### 1. IDOR Testing
- Test with different user IDs
- Test with other users' resource IDs
- Test with invalid/malformed IDs

### 2. Authentication Bypass
- Test without Authorization header
- Test with invalid tokens
- Test with expired tokens
- Test with tokens from other accounts

### 3. Authorization Testing
- Test with different user roles
- Test privilege escalation
- Test admin endpoints with user token

### 4. Business Logic
- Test payment amount manipulation
- Test negative amounts
- Test currency manipulation
- Test race conditions

### 5. API Security
- Test mass assignment (add `role: admin`)
- Test rate limiting bypass
- Test input validation

## Expected Rewards

- **Tier 3 Premium (API):** $1,500 - $5,000
- **Tier 2 (Dashboard):** $400 - $2,500
- **Critical bypasses:** Up to $7,500

## Next Steps

1. Set up Rapyd sandbox account
2. Generate API keys
3. Start manual testing with top priority endpoints
4. Document all findings
5. Submit via Bugcrowd

"""
    
    with open(plan_file, 'w') as f:
        f.write(plan_content)
    
    print(f"[*] Generated testing plan: {plan_file}")
    print()
    
    print("=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Review: output/immediate_roi/RAPYD_MANUAL_TESTING_PLAN.md")
    print("2. Set up Rapyd sandbox account at dashboard.rapyd.net")
    print("3. Generate API keys")
    print("4. Start manual testing with top priority endpoints")
    print("=" * 60)

if __name__ == "__main__":
    generate_rapyd_priority_list()


