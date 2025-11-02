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
Quick Status Checker - See What's Been Found So Far
Shows results from completed stages without waiting for full scan
"""

import json
from pathlib import Path
from datetime import datetime

def check_scan_status():
    """Check what's been found so far"""
    repo_root = Path(__file__).parent.parent
    output_dir = repo_root / "output"
    roi_dir = output_dir / "immediate_roi"
    
    print("=" * 70)
    print("🔍 SCAN STATUS CHECK - What's Been Found So Far")
    print("=" * 70)
    print()
    
    # Stage 1: Reconnaissance
    print("📊 STAGE 1: Reconnaissance")
    print("-" * 70)
    subs_file = output_dir / "subs.txt"
    if subs_file.exists():
        try:
            with open(subs_file, "r") as f:
                subs = [l.strip() for l in f if l.strip()]
            print(f"✅ Found: {len(subs)} subdomains")
            if subs:
                print(f"   First 10: {', '.join(subs[:10])}")
                if len(subs) > 10:
                    print(f"   ... and {len(subs) - 10} more")
        except Exception as e:
            print(f"❌ Error reading subs.txt: {e}")
    else:
        print("⏳ Not started yet")
    print()
    
    # Stage 2: HTTP Probing
    print("🌐 STAGE 2: HTTP Probing")
    print("-" * 70)
    http_file = output_dir / "http.json"
    if http_file.exists():
        try:
            # Check file size
            size = http_file.stat().st_size
            if size == 0:
                print("⏳ Empty file - scanning in progress...")
            else:
                # Try to count URLs
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
                    print(f"   Sample URLs:")
                    for url in urls[:5]:
                        print(f"   - {url}")
                    if len(urls) > 5:
                        print(f"   ... and {len(urls) - 5} more")
                else:
                    print(f"⏳ File exists ({size} bytes) but parsing...")
                    print("   Scanning may still be in progress")
        except Exception as e:
            print(f"❌ Error reading http.json: {e}")
    else:
        print("⏳ Not started yet")
    print()
    
    # Stage 3: Nuclei Findings
    print("🎯 STAGE 3: Vulnerability Scan")
    print("-" * 70)
    nuclei_file = roi_dir / "high_roi_findings.json"
    if nuclei_file.exists():
        try:
            with open(nuclei_file, "r") as f:
                findings = []
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except:
                            continue
            if findings:
                print(f"✅ Found: {len(findings)} vulnerabilities")
                # Count by severity
                severity_count = {}
                for f in findings:
                    sev = f.get("info", {}).get("severity", "unknown").lower()
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                
                for sev, count in sorted(severity_count.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x[0], 5)):
                    print(f"   {sev.upper()}: {count}")
            else:
                print("⏳ File exists but no findings yet")
        except Exception as e:
            print(f"❌ Error reading findings: {e}")
    else:
        print("⏳ Not started yet")
    print()
    
    # Stage 4: Secrets
    print("🔑 STAGE 4: Secrets Scan")
    print("-" * 70)
    secrets_file = roi_dir / "secrets_found.json"
    if secrets_file.exists():
        try:
            with open(secrets_file, "r") as f:
                secrets = json.load(f)
            if isinstance(secrets, list) and secrets:
                print(f"✅ Found: {len(secrets)} secrets")
                for secret in secrets[:5]:
                    print(f"   - {secret.get('type', 'Unknown')}: {secret.get('match', '')[:50]}")
            else:
                print("⏳ No secrets found yet")
        except Exception as e:
            print(f"⏳ File exists but may be empty")
    else:
        print("⏳ Not started yet")
    print()
    
    # Stage 6: Reports
    print("📄 STAGE 6: Reports")
    print("-" * 70)
    reports_dir = roi_dir / "submission_reports"
    if reports_dir.exists():
        reports = list(reports_dir.glob("*.md"))
        if reports:
            print(f"✅ Generated: {len(reports)} reports")
            print(f"   Location: {reports_dir}")
        else:
            print("⏳ No reports generated yet")
    else:
        print("⏳ Not started yet")
    print()
    
    # Summary
    print("=" * 70)
    print("💡 QUICK COMMANDS:")
    print("=" * 70)
    print()
    print("# View subdomains found:")
    print("cat output/subs.txt | head -20")
    print()
    print("# View alive endpoints:")
    print("cat output/http.json | jq -r '.url' | head -20")
    print()
    print("# View vulnerabilities found:")
    print("cat output/immediate_roi/high_roi_findings.json | jq -r '.info.name' | head -20")
    print()
    print("# View reports:")
    print("ls -lh output/immediate_roi/submission_reports/")
    print()
    print("# View summary:")
    print("cat output/immediate_roi/ROI_SUMMARY.md 2>/dev/null || echo 'Not generated yet'")
    print()
    print("=" * 70)

if __name__ == "__main__":
    check_scan_status()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
