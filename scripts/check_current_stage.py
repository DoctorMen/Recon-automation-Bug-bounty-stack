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
Quick Check - What Stage Is It On Now?
"""

import json
from pathlib import Path
from datetime import datetime

def check_current_status():
    repo_root = Path(__file__).parent.parent
    output_dir = repo_root / "output"
    roi_dir = output_dir / "immediate_roi"
    log_file = roi_dir / "roi_hunter.log"
    
    print("=" * 70)
    print("🔍 CURRENT SCAN STATUS")
    print("=" * 70)
    print()
    
    # Check log file for latest activity
    if log_file.exists():
        try:
            with open(log_file, "r") as f:
                lines = f.readlines()
                if lines:
                    print("📋 Latest Activity:")
                    print("-" * 70)
                    # Show last 10 lines
                    for line in lines[-10:]:
                        print(f"   {line.strip()}")
                    print()
                    
                    # Determine current stage
                    last_line = lines[-1].lower()
                    if "stage 1" in last_line or "reconnaissance" in last_line or "enumerating" in last_line or "subfinder" in last_line or "amass" in last_line:
                        print("🎯 CURRENT STAGE: Stage 1 - Reconnaissance")
                        print("   Discovering subdomains...")
                    elif "stage 2" in last_line or "http probing" in last_line or "httpx" in last_line:
                        print("🎯 CURRENT STAGE: Stage 2 - HTTP Probing")
                        print("   Finding alive endpoints...")
                    elif "stage 3" in last_line or "high-roi" in last_line or "nuclei" in last_line:
                        print("🎯 CURRENT STAGE: Stage 3 - Vulnerability Scanning")
                        print("   Scanning for bugs...")
                    elif "stage 4" in last_line or "secrets" in last_line:
                        print("🎯 CURRENT STAGE: Stage 4 - Secrets Scanning")
                        print("   Looking for exposed secrets...")
                    elif "stage 5" in last_line or "api" in last_line:
                        print("🎯 CURRENT STAGE: Stage 5 - API Discovery")
                        print("   Finding API endpoints...")
                    elif "stage 6" in last_line or "report" in last_line:
                        print("🎯 CURRENT STAGE: Stage 6 - Report Generation")
                        print("   Creating submission-ready reports...")
                    else:
                        print("🎯 CURRENT STAGE: Determining...")
        except Exception as e:
            print(f"Error reading log: {e}")
    else:
        print("⏳ Log file not found yet")
    
    print()
    print("=" * 70)
    print("📊 STAGE PROGRESS:")
    print("=" * 70)
    print()
    
    # Check which stages are complete
    status_file = roi_dir / ".status"
    completed_stages = []
    if status_file.exists():
        with open(status_file, "r") as f:
            completed_stages = [l.strip() for l in f if l.strip()]
    
    stages = [
        ("1", "Reconnaissance", "subs.txt"),
        ("2", "HTTP Probing", "http.json"),
        ("3", "Vulnerability Scan", "high_roi_findings.json"),
        ("4", "Secrets Scan", "secrets_found.json"),
        ("5", "API Discovery", "api_endpoints.json"),
        ("6", "Report Generation", "submission_reports")
    ]
    
    for stage_num, stage_name, check_file in stages:
        if stage_num in completed_stages:
            print(f"✅ Stage {stage_num}: {stage_name} - COMPLETE")
        else:
            # Check if file exists (might be in progress)
            if stage_num == "1":
                file_path = output_dir / check_file
            elif stage_num == "2":
                file_path = output_dir / check_file
            elif stage_num == "6":
                file_path = roi_dir / check_file
                if file_path.exists() and file_path.is_dir():
                    reports = list(file_path.glob("*.md"))
                    if reports:
                        print(f"✅ Stage {stage_num}: {stage_name} - COMPLETE ({len(reports)} reports)")
                        continue
            else:
                file_path = roi_dir / check_file
            
            if file_path.exists() and file_path.stat().st_size > 0:
                print(f"🔄 Stage {stage_num}: {stage_name} - IN PROGRESS")
            else:
                print(f"⏳ Stage {stage_num}: {stage_name} - PENDING")
    
    print()
    print("=" * 70)
    print("💡 QUICK COMMANDS:")
    print("=" * 70)
    print()
    print("# See full log:")
    print("tail -50 output/immediate_roi/roi_hunter.log")
    print()
    print("# Check if processes are running:")
    print("ps aux | grep -E '(subfinder|amass|httpx|nuclei)' | grep -v grep")
    print()
    print("# Check subdomains found:")
    print("wc -l output/subs.txt")
    print()

if __name__ == "__main__":
    check_current_status()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
