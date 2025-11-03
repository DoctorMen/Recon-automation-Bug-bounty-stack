#!/usr/bin/env python3
"""
What Endpoints Do We Actually Have?
Find realistic endpoints from programs we can actually test
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

def analyze_realistic_endpoints():
    """Find endpoints we can actually test"""
    
    print("=" * 60)
    print("Realistic Endpoint Analysis")
    print("=" * 60)
    print()
    
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints.json"
    
    if not priority_file.exists():
        print("❌ Priority endpoints file not found")
        return
    
    with open(priority_file, 'r') as f:
        endpoints = json.load(f)
    
    print(f"Total priority endpoints: {len(endpoints)}")
    print()
    
    # Categorize endpoints
    realistic = []
    cdn_subdomains = []
    unknown = []
    
    for ep in endpoints:
        url = ep.get("url", "")
        domain = ep.get("domain", "")
        
        # Check if CDN subdomain (hash prefix)
        if domain and any(char.isdigit() and len(domain.split('.')[0]) > 15 for char in domain):
            cdn_subdomains.append(ep)
        # Check if realistic domain
        elif domain and any(x in domain.lower() for x in ["mastercard", "atlassian", "kraken", "rapyd", "api.", "developer."]):
            realistic.append(ep)
        else:
            unknown.append(ep)
    
    print("=" * 60)
    print("ENDPOINT ANALYSIS")
    print("=" * 60)
    print()
    
    print(f"✅ Realistic endpoints: {len(realistic)}")
    if realistic:
        print("   Top 5:")
        for idx, ep in enumerate(realistic[:5], 1):
            print(f"      {idx}. {ep['url']}")
    print()
    
    print(f"⚠️  CDN subdomains (likely out of scope): {len(cdn_subdomains)}")
    if cdn_subdomains:
        print("   Example:")
        print(f"      {cdn_subdomains[0]['url']}")
        print("   (Hash prefix = CDN, probably not in scope)")
    print()
    
    print(f"❓ Unknown endpoints: {len(unknown)}")
    print()
    
    # Check for specific programs
    print("=" * 60)
    print("PROGRAM-SPECIFIC ENDPOINTS")
    print("=" * 60)
    print()
    
    programs = {
        "mastercard": [],
        "atlassian": [],
        "kraken": [],
        "rapyd": [],
        "whitebit": [],
        "nicehash": []
    }
    
    for ep in endpoints:
        url = ep.get("url", "").lower()
        domain = ep.get("domain", "").lower()
        
        for program in programs.keys():
            if program in url or program in domain:
                programs[program].append(ep)
    
    for program, ep_list in programs.items():
        if ep_list:
            print(f"✅ {program.upper()}: {len(ep_list)} endpoints")
            print(f"   Top 3:")
            for idx, ep in enumerate(ep_list[:3], 1):
                print(f"      {idx}. {ep['url']}")
            print()
    
    # Save realistic endpoints
    if realistic:
        realistic_file = ROI_OUTPUT_DIR / "realistic_endpoints.json"
        with open(realistic_file, 'w') as f:
            json.dump(realistic, f, indent=2)
        
        print(f"[*] Saved realistic endpoints to: {realistic_file}")
        print()
    
    print("=" * 60)
    print("RECOMMENDATION")
    print("=" * 60)
    print()
    
    if realistic:
        print("✅ FOCUS ON REALISTIC ENDPOINTS:")
        print()
        for ep in realistic[:5]:
            print(f"   - {ep['url']}")
        print()
        print("   These are more likely to be:")
        print("   - In scope for bug bounty")
        print("   - Actually exploitable")
        print("   - Worth testing")
    else:
        print("⚠️  No realistic endpoints found")
        print()
        print("Options:")
        print("1. Re-run discovery with focus on main domains")
        print("2. Test CDN endpoints anyway (may find misconfigurations)")
        print("3. Focus on programs you know work (like Rapyd)")
    
    print()

if __name__ == "__main__":
    analyze_realistic_endpoints()


