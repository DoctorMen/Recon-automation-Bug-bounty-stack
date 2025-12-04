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
Quick Check - What Has Been Found So Far
"""

import json
from pathlib import Path

def check_results():
    repo_root = Path(__file__).parent.parent
    output_dir = repo_root / "output"
    roi_dir = output_dir / "immediate_roi"
    
    print("=" * 70)
    print("🔍 WHAT HAS BEEN FOUND SO FAR")
    print("=" * 70)
    print()
    
    # Stage 1: Subdomains
    print("📊 STAGE 1: Subdomains Discovered")
    print("-" * 70)
    subs_file = output_dir / "subs.txt"
    if subs_file.exists() and subs_file.stat().st_size > 0:
        try:
            with open(subs_file, "r") as f:
                subs = [l.strip() for l in f if l.strip()]
            
            print(f"✅ Found: {len(subs)} subdomains")
            print()
            
            # Analyze by domain
            domain_counts = {}
            for sub in subs:
                parts = sub.split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])  # Last 2 parts (domain.tld)
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            print("Breakdown by domain:")
            for domain, count in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {domain}: {count} subdomains")
            
            print()
            print("Sample subdomains found:")
            for sub in subs[:15]:
                print(f"   - {sub}")
            if len(subs) > 15:
                print(f"   ... and {len(subs) - 15} more")
            
            # Check for high-value targets
            print()
            print("🎯 High-Value Targets Found:")
            high_value_keywords = ['api', 'admin', 'dashboard', 'secure', 'vpn', 'staging', 'dev', 'test', 'sandbox', 'payment']
            found_high_value = []
            for sub in subs:
                for keyword in high_value_keywords:
                    if keyword in sub.lower():
                        found_high_value.append(sub)
                        break
            
            if found_high_value:
                print(f"   Found {len(found_high_value)} potentially high-value subdomains:")
                for sub in found_high_value[:10]:
                    print(f"   ⭐ {sub}")
            else:
                print("   (Scanning in progress...)")
                
        except Exception as e:
            print(f"❌ Error reading: {e}")
    else:
        print("⏳ No subdomains found yet (scanning in progress...)")
    print()
    
    # Stage 2: HTTP Endpoints
    print("🌐 STAGE 2: Alive Endpoints")
    print("-" * 70)
    http_file = output_dir / "http.json"
    if http_file.exists() and http_file.stat().st_size > 0:
        try:
            urls = []
            with open(http_file, "r") as f:
                content = f.read().strip()
                if content:
                    # Try JSON array
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            urls = [item.get("url") or item.get("input") or item.get("host", "") for item in data if isinstance(item, dict)]
                    except:
                        # Try NDJSON
                        f.seek(0)
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    data = json.loads(line)
                                    if isinstance(data, dict):
                                        url = data.get("url") or data.get("input") or data.get("host", "")
                                        if url:
                                            urls.append(url)
                                except:
                                    continue
            
            if urls:
                print(f"✅ Found: {len(urls)} alive endpoints")
                print()
                print("Sample URLs:")
                for url in urls[:10]:
                    print(f"   - {url}")
                if len(urls) > 10:
                    print(f"   ... and {len(urls) - 10} more")
            else:
                print("⏳ File exists but parsing... (scanning in progress)")
        except Exception as e:
            print(f"⏳ File exists ({http_file.stat().st_size} bytes) - scanning may be in progress")
    else:
        print("⏳ Not started yet")
    print()
    
    # Stage 3: Vulnerabilities
    print("🎯 STAGE 3: Vulnerabilities Found")
    print("-" * 70)
    findings_file = roi_dir / "high_roi_findings.json"
    if findings_file.exists():
        try:
            findings = []
            with open(findings_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except:
                            continue
            
            if findings:
                print(f"✅ Found: {len(findings)} vulnerabilities!")
                print()
                
                # Count by severity
                severity_count = {}
                for f in findings:
                    sev = f.get("info", {}).get("severity", "unknown").lower()
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                
                print("By Severity:")
                for sev, count in sorted(severity_count.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 4)):
                    print(f"   {sev.upper()}: {count}")
                
                print()
                print("Sample findings:")
                for f in findings[:5]:
                    name = f.get("info", {}).get("name", "Unknown")
                    severity = f.get("info", {}).get("severity", "unknown")
                    url = f.get("matched-at", "")[:60]
                    print(f"   [{severity.upper()}] {name}")
                    print(f"      {url}")
            else:
                print("⏳ No findings yet")
        except Exception as e:
            print(f"⏳ File exists but may be empty")
    else:
        print("⏳ Not started yet")
    print()
    
    # Summary
    print("=" * 70)
    print("💡 QUICK ASSESSMENT:")
    print("=" * 70)
    
    subs_count = 0
    if subs_file.exists():
        with open(subs_file, "r") as f:
            subs_count = len([l for l in f if l.strip()])
    
    urls_count = 0
    if http_file.exists():
        try:
            with open(http_file, "r") as f:
                content = f.read()
                urls_count = content.count('"url"') or content.count('"input"')
        except:
            pass
    
    findings_count = 0
    if findings_file.exists():
        try:
            with open(findings_file, "r") as f:
                findings_count = len([l for l in f if l.strip()])
        except:
            pass
    
    print()
    if subs_count > 0:
        print(f"✅ {subs_count} subdomains discovered - Good foundation!")
    if urls_count > 0:
        print(f"✅ {urls_count} alive endpoints found - Ready for scanning!")
    if findings_count > 0:
        print(f"🎯 {findings_count} vulnerabilities found - Valuable results!")
    
    if subs_count == 0:
        print("⏳ Still scanning subdomains...")
    elif urls_count == 0:
        print("⏳ Subdomains found, probing endpoints...")
    elif findings_count == 0:
        print("⏳ Endpoints found, scanning for vulnerabilities...")
    else:
        print("🎉 Scan progressing well!")
    
    print()
    print("=" * 70)

if __name__ == "__main__":
    check_results()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
