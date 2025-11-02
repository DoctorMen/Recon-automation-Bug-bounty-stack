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
Quick Check - Any Bugs Found Yet?
"""

import json
from pathlib import Path

def check_for_bugs():
    repo_root = Path(__file__).parent.parent
    output_dir = repo_root / "output"
    roi_dir = output_dir / "immediate_roi"
    
    print("=" * 70)
    print("🐛 BUG CHECK - Any Vulnerabilities Found Yet?")
    print("=" * 70)
    print()
    
    # Check current stage
    print("📊 CURRENT STAGE:")
    print("-" * 70)
    
    # Check log for latest activity
    log_file = roi_dir / "roi_hunter.log"
    if log_file.exists():
        with open(log_file, "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].lower()
                if "stage 1" in last_line or "reconnaissance" in last_line or "enumerating" in last_line:
                    print("⏳ Stage 1: Reconnaissance - Still discovering subdomains")
                    print("   Bugs will be found in Stage 3 (after HTTP probing)")
                elif "stage 2" in last_line or "http probing" in last_line:
                    print("⏳ Stage 2: HTTP Probing - Finding alive endpoints")
                    print("   Bugs will be found in Stage 3 (next)")
                elif "stage 3" in last_line or "nuclei" in last_line:
                    print("🔄 Stage 3: Vulnerability Scanning - Looking for bugs NOW!")
                else:
                    print("   Checking...")
    else:
        print("   Log file not found")
    
    print()
    print("=" * 70)
    print("🎯 VULNERABILITY SCAN RESULTS:")
    print("=" * 70)
    print()
    
    # Check for findings
    findings_file = roi_dir / "high_roi_findings.json"
    if findings_file.exists() and findings_file.stat().st_size > 0:
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
                print(f"✅ FOUND {len(findings)} VULNERABILITIES!")
                print()
                
                # Count by severity
                severity_count = {}
                for f in findings:
                    sev = f.get("info", {}).get("severity", "unknown").lower()
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                
                print("By Severity:")
                for sev, count in sorted(severity_count.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 4)):
                    print(f"   🔴 {sev.upper()}: {count}")
                
                print()
                print("Sample Findings:")
                for f in findings[:5]:
                    name = f.get("info", {}).get("name", "Unknown")
                    severity = f.get("info", {}).get("severity", "unknown")
                    url = f.get("matched-at", "")[:70]
                    print(f"   [{severity.upper()}] {name}")
                    print(f"      {url}")
                    print()
                
                if len(findings) > 5:
                    print(f"   ... and {len(findings) - 5} more")
            else:
                print("⏳ No bugs found yet")
                print("   Stage 3 (Vulnerability Scan) hasn't completed yet")
        except Exception as e:
            print(f"⏳ File exists but may be empty or parsing...")
    else:
        print("❌ No bugs found yet")
        print()
        print("REASON:")
        print("   Stage 3 (High-ROI Vulnerability Scan) hasn't run yet")
        print()
        print("PROGRESS:")
        print("   ✅ Stage 1: Reconnaissance - IN PROGRESS")
        print("   ⏳ Stage 2: HTTP Probing - Not started")
        print("   ⏳ Stage 3: Vulnerability Scan - Not started")
        print("   ⏳ Stage 4: Secrets Scan - Not started")
        print("   ⏳ Stage 5: API Discovery - Not started")
        print("   ⏳ Stage 6: Report Generation - Not started")
    
    print()
    print("=" * 70)
    print("💡 WHEN WILL BUGS BE FOUND?")
    print("=" * 70)
    print()
    print("Bugs are found in Stage 3, which runs AFTER:")
    print("   1. Stage 1: Reconnaissance (currently running)")
    print("   2. Stage 2: HTTP Probing (finds alive endpoints)")
    print("   3. Stage 3: Vulnerability Scan ⭐ BUGS FOUND HERE")
    print()
    print("Estimated time until bugs:")
    print("   - Stage 1 completion: ~20-30 minutes")
    print("   - Stage 2 completion: ~10-15 minutes")
    print("   - Stage 3 completion: ~30-60 minutes")
    print("   - Total: ~1-2 hours until first bugs appear")
    print()
    print("=" * 70)
    
    # Check what's been found so far
    print()
    print("📊 WHAT'S BEEN FOUND SO FAR:")
    print("-" * 70)
    
    subs_file = output_dir / "subs.txt"
    if subs_file.exists():
        with open(subs_file, "r") as f:
            subs_count = len([l for l in f if l.strip()])
        print(f"✅ {subs_count} subdomains discovered")
    else:
        print("⏳ No subdomains yet")
    
    http_file = output_dir / "http.json"
    if http_file.exists() and http_file.stat().st_size > 0:
        print(f"✅ Alive endpoints found (file size: {http_file.stat().st_size} bytes)")
    else:
        print("⏳ No alive endpoints yet (Stage 2 not started)")
    
    print()

if __name__ == "__main__":
    check_for_bugs()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
