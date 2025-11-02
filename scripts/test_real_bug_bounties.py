#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

"""
Test Real Bug Bounty Targets
Tests against actual in-scope bug bounty programs
"""

import json
import sys
from pathlib import Path
from typing import List

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

# Try to import ultra_fast_exploiter
try:
    from ultra_fast_exploiter import UltraFastExploiter, ASYNC_AVAILABLE
except ImportError:
    print("❌ Error: ultra_fast_exploiter.py not found")
    sys.exit(1)

# Real bug bounty targets (public, no vouchers needed)
REAL_TARGETS = {
    "rapyd": {
        "base_domains": ["rapyd.net", "api.rapyd.net", "dashboard.rapyd.net", "sandboxapi.rapyd.net"],
        "platform": "Bugcrowd",
        "max_reward": "$5,000",
        "scope": "API endpoints, dashboard, sandbox environment"
    },
    "kraken": {
        "base_domains": ["kraken.com", "api.kraken.com", "www.kraken.com"],
        "platform": "Direct Email",
        "max_reward": "$100,000",
        "scope": "Exchange APIs, trading APIs"
    },
    "whitebit": {
        "base_domains": ["whitebit.com", "api.whitebit.com", "trade.whitebit.com"],
        "platform": "Open Bug Bounty / Direct Email",
        "max_reward": "$10,000",
        "scope": "Exchange APIs, trading APIs"
    },
    "nicehash": {
        "base_domains": ["nicehash.com", "api.nicehash.com", "www.nicehash.com"],
        "platform": "Open Bug Bounty / Direct Email",
        "max_reward": "$22,500",
        "scope": "Mining APIs, platform APIs"
    }
}

def discover_endpoints_for_target(target_domain: str) -> List[str]:
    """Discover endpoints for a target domain"""
    print(f"\n[*] Discovering endpoints for {target_domain}...")
    
    # Common API endpoints to test
    common_endpoints = [
        f"https://{target_domain}/api",
        f"https://{target_domain}/api/v1",
        f"https://{target_domain}/api/v2",
        f"https://{target_domain}/api/accounts",
        f"https://{target_domain}/api/users",
        f"https://{target_domain}/api/auth",
        f"https://{target_domain}/api/login",
        f"https://{target_domain}/api/balance",
        f"https://{target_domain}/api/trades",
        f"https://{target_domain}/api/orders",
        f"https://{target_domain}/api/transactions",
        f"https://{target_domain}/api/wallet",
        f"https://{target_domain}/api/admin",
        f"https://{target_domain}/api/health",
        f"https://{target_domain}/api/status",
        f"https://{target_domain}/api/info",
        f"https://{target_domain}/api/me",
        f"https://{target_domain}/api/profile",
        f"https://{target_domain}/api/settings",
        f"https://{target_domain}/api/config",
        f"https://{target_domain}/api/deposit",
        f"https://{target_domain}/api/withdraw",
        f"https://{target_domain}/api/transfer",
        f"https://{target_domain}/api/history",
        f"https://{target_domain}/api/logs",
        f"https://{target_domain}/api/debug",
        f"https://{target_domain}/api/test",
        f"https://{target_domain}/api/dev",
        f"https://{target_domain}/api/staging",
        f"https://{target_domain}/api/backup",
        f"https://{target_domain}/api/export",
        f"https://{target_domain}/api/import",
        f"https://{target_domain}/api/files",
        f"https://{target_domain}/api/download",
        f"https://{target_domain}/api/upload",
        f"https://{target_domain}/api/data",
        f"https://{target_domain}/api/customers",
        f"https://{target_domain}/api/merchants",
        f"https://{target_domain}/api/payments",
        f"https://{target_domain}/api/invoice",
        f"https://{target_domain}/api/billing",
        f"https://{target_domain}/api/checkout",
        f"https://{target_domain}/api/graphql",
        f"https://{target_domain}/.well-known/openapi.json",
        f"https://{target_domain}/.well-known/swagger.json",
        f"https://{target_domain}/api-docs",
        f"https://{target_domain}/swagger",
        f"https://{target_domain}/openapi",
        f"https://{target_domain}/docs",
        f"https://{target_domain}/v1",
        f"https://{target_domain}/v2",
    ]
    
    # Also try HTTP
    http_endpoints = [e.replace("https://", "http://") for e in common_endpoints]
    
    return common_endpoints + http_endpoints

def main():
    """Test against real bug bounty targets"""
    print("=" * 70)
    print("🚀 TESTING REAL BUG BOUNTY TARGETS")
    print("=" * 70)
    print()
    print("Targets (Public, No Vouchers Needed):")
    for name, info in REAL_TARGETS.items():
        print(f"  • {name.upper()}: {info['platform']} - Max: {info['max_reward']}")
    print()
    
    all_endpoints = []
    all_results = {}
    
    # Test each target
    for target_name, target_info in REAL_TARGETS.items():
        print(f"\n{'='*70}")
        print(f"Target: {target_name.upper()}")
        print(f"Platform: {target_info['platform']}")
        print(f"Max Reward: {target_info['max_reward']}")
        print(f"Scope: {target_info['scope']}")
        print(f"{'='*70}")
        
        # Discover endpoints for all base domains
        target_endpoints = []
        for domain in target_info['base_domains']:
            endpoints = discover_endpoints_for_target(domain)
            target_endpoints.extend(endpoints)
        
        print(f"[*] Found {len(target_endpoints)} endpoints to test")
        
        if not target_endpoints:
            print(f"⚠️ No endpoints found for {target_name}")
            continue
        
        # Generate test cases
        test_cases = [
            {"type": "auth_bypass"},
            {"type": "idor"},
            {"type": "rate_limit"},
            {"type": "api_mass_assignment", "payload": {"role": "admin", "is_admin": True}},
            {"type": "generic"}
        ]
        
        # Create exploiter
        output_dir = REPO_ROOT / "output" / "real_bug_bounties" / target_name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        exploiter = UltraFastExploiter(output_dir, max_concurrent=100)
        
        # Run exploitation
        print(f"[*] Starting exploitation for {target_name}...")
        try:
            if ASYNC_AVAILABLE:
                import asyncio
                confirmed = asyncio.run(exploiter.exploit_all_async(target_endpoints, test_cases))
            else:
                confirmed = exploiter.exploit_all_sync(target_endpoints, test_cases)
        except Exception as e:
            print(f"⚠️ Error: {e}")
            confirmed = []
        
        # Store results
        all_results[target_name] = {
            "endpoints_tested": len(target_endpoints),
            "confirmed_vulnerabilities": len(confirmed),
            "estimated_value": sum(r.get("value", 0) for r in confirmed),
            "findings": confirmed
        }
        
        print(f"\n✅ {target_name.upper()} Complete:")
        print(f"   Endpoints tested: {len(target_endpoints)}")
        print(f"   Confirmed vulnerabilities: {len(confirmed)}")
        print(f"   Estimated value: ${sum(r.get('value', 0) for r in confirmed):,}")
        
        all_endpoints.extend(target_endpoints)
    
    # Overall summary
    print(f"\n{'='*70}")
    print("🎯 OVERALL SUMMARY")
    print(f"{'='*70}")
    print(f"Total targets tested: {len(REAL_TARGETS)}")
    print(f"Total endpoints tested: {len(all_endpoints)}")
    
    total_confirmed = sum(r["confirmed_vulnerabilities"] for r in all_results.values())
    total_value = sum(r["estimated_value"] for r in all_results.values())
    
    print(f"Total confirmed vulnerabilities: {total_confirmed}")
    print(f"Total estimated value: ${total_value:,}")
    print()
    
    # Save overall results
    summary_file = REPO_ROOT / "output" / "real_bug_bounties" / "overall_summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(summary_file, 'w') as f:
        json.dump({
            "total_targets": len(REAL_TARGETS),
            "total_endpoints": len(all_endpoints),
            "total_confirmed": total_confirmed,
            "total_value": total_value,
            "results_by_target": all_results
        }, f, indent=2)
    
    print(f"Results saved to: {summary_file}")
    print(f"{'='*70}")
    print("✅ TESTING COMPLETE")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
