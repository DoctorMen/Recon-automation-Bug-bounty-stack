#!/usr/bin/env python3
"""
Filter priority endpoints by program
Focus on Rapyd, Mastercard, and other high-value bug bounty programs
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

# High-value bug bounty programs to focus on
FOCUS_PROGRAMS = {
    "rapyd": ["rapyd.net", "rapyd.com"],
    "mastercard": ["mastercard.com", "developer.mastercard.com"],
    "apple": ["apple.com", "api.apple.com"],
    "microsoft": ["microsoft.com", "api.microsoft.com"],
    "atlassian": ["atlassian.com", "api.atlassian.com"],
    "kraken": ["kraken.com", "api.kraken.com"],
    "whitebit": ["whitebit.com", "api.whitebit.com"],
    "nicehash": ["nicehash.com", "api.nicehash.com"]
}

def filter_by_program():
    """Filter priority endpoints by bug bounty program"""
    
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints.json"
    if not priority_file.exists():
        print("❌ Priority endpoints file not found!")
        print("Run: python3 scripts/prioritize_endpoints.py")
        sys.exit(1)
    
    with open(priority_file, 'r') as f:
        endpoints = json.load(f)
    
    print("=" * 60)
    print("Filtering Priority Endpoints by Bug Bounty Program")
    print("=" * 60)
    print()
    
    # Group by program
    by_program = {}
    other_endpoints = []
    
    for endpoint in endpoints:
        url = endpoint.get("url", "")
        domain = endpoint.get("domain", "")
        
        matched = False
        for program, domains in FOCUS_PROGRAMS.items():
            if any(d in domain.lower() for d in domains):
                if program not in by_program:
                    by_program[program] = []
                by_program[program].append(endpoint)
                matched = True
                break
        
        if not matched:
            other_endpoints.append(endpoint)
    
    # Show results
    print(f"Total endpoints: {len(endpoints)}")
    print()
    
    for program, ep_list in sorted(by_program.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"✅ {program.upper()}: {len(ep_list)} endpoints")
        print(f"   Top 5:")
        for idx, ep in enumerate(ep_list[:5], 1):
            print(f"      {idx}. Score: {ep['score']} - {ep['url']}")
        print()
    
    if other_endpoints:
        print(f"⚠️  Other endpoints: {len(other_endpoints)}")
        print(f"   (Includes PayPal subdomains, etc.)")
        print()
    
    # Save filtered results
    filtered_file = ROI_OUTPUT_DIR / "priority_endpoints_by_program.json"
    with open(filtered_file, 'w') as f:
        json.dump(by_program, f, indent=2)
    
    print(f"[*] Saved filtered endpoints to: {filtered_file}")
    print()
    
    # Generate focused testing plan
    print("=" * 60)
    print("Recommended Focus: RAPYD")
    print("=" * 60)
    print()
    
    rapyd_endpoints = by_program.get("rapyd", [])
    if rapyd_endpoints:
        print(f"Found {len(rapyd_endpoints)} Rapyd endpoints!")
        print()
        print("Top 10 Rapyd Endpoints for Manual Testing:")
        print()
        for idx, ep in enumerate(rapyd_endpoints[:10], 1):
            print(f"{idx}. Score: {ep['score']}")
            print(f"   URL: {ep['url']}")
            print(f"   Reasons: {', '.join(ep['reasons'])}")
            print()
    else:
        print("⚠️  No Rapyd endpoints found in priority list")
        print("   Check: output/immediate_roi/api_paths.txt")
        print("   Filter for 'rapyd' domains")
    
    print()
    print("=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Focus on Rapyd endpoints (highest reward potential)")
    print("2. Manual testing checklist:")
    print("   - IDOR testing")
    print("   - Authentication bypass")
    print("   - Business logic flaws")
    print("3. See: output/immediate_roi/MANUAL_TESTING_PLAN.md")
    print("=" * 60)

if __name__ == "__main__":
    filter_by_program()


