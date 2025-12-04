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
Scan Monitor & Status Dashboard
Real-time monitoring of scan progress and findings
Useful for tracking progress while scans run
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from collections import deque

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"

def format_size(size_bytes: int) -> str:
    """Format file size"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def get_file_info(file_path: Path) -> Dict:
    """Get file information with optimized line counting"""
    if not file_path.exists():
        return {"exists": False, "size": 0, "lines": 0, "modified": None}
    
    stat = file_path.stat()
    lines = 0
    try:
        # Optimized line counting using buffer reading (faster for large files)
        with open(file_path, "rb") as f:
            # Read file in chunks and count newlines
            buffer_size = 1024 * 1024  # 1MB chunks
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                lines += chunk.count(b'\n')
    except:
        pass
    
    return {
        "exists": True,
        "size": stat.st_size,
        "size_formatted": format_size(stat.st_size),
        "lines": lines,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
    }

def read_log_tail(file_path: Path, lines: int = 10) -> List[str]:
    """
    Read last N lines of log file efficiently.
    Uses deque with maxlen for memory-efficient tail reading.
    """
    if not file_path.exists():
        return []
    
    try:
        # Use deque with maxlen for efficient tail reading (O(1) per line vs O(n) for full read)
        with open(file_path, "r", encoding="utf-8") as f:
            tail = deque(f, maxlen=lines)
            return [line.strip() for line in tail]
    except:
        return []

def analyze_findings(file_path: Path) -> Dict:
    """Analyze findings file"""
    if not file_path.exists():
        return {"count": 0, "by_severity": {}, "total": 0}
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        
        if not isinstance(findings, list):
            findings = [findings] if findings else []
        
        by_severity = {}
        for finding in findings:
            severity = finding.get("info", {}).get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            "count": len(findings),
            "by_severity": by_severity,
            "total": len(findings)
        }
    except Exception as e:
        return {"count": 0, "error": str(e), "total": 0}

def main():
    """Main monitor function"""
    print("=" * 70)
    print("Scan Monitor & Status Dashboard")
    print("=" * 70)
    print()
    
    # Check pipeline status files
    status_file = OUTPUT_DIR / ".pipeline_status"
    completed_stages = []
    if status_file.exists():
        with open(status_file, "r", encoding="utf-8") as f:
            completed_stages = [line.strip() for line in f]
    
    print("📊 Pipeline Status:")
    stages = ["recon", "httpx", "nuclei", "triage", "reports"]
    for stage in stages:
        status = "✓" if stage in completed_stages else "⏸"
        print(f"   {status} {stage.capitalize()}")
    print()
    
    # File status
    print("📁 Output Files:")
    files_to_check = {
        "Subdomains": OUTPUT_DIR / "subs.txt",
        "HTTP Endpoints": OUTPUT_DIR / "http.json",
        "Nuclei Findings": OUTPUT_DIR / "nuclei-findings.json",
        "Triaged Findings": OUTPUT_DIR / "triage.json",
        "Target Validation": OUTPUT_DIR / "targets-validation.json",
    }
    
    for name, file_path in files_to_check.items():
        info = get_file_info(file_path)
        if info["exists"]:
            print(f"   ✓ {name}: {info['size_formatted']} ({info['lines']} lines)")
        else:
            print(f"   ✗ {name}: Not created yet")
    print()
    
    # Findings summary
    print("🔍 Findings Summary:")
    nuclei_file = OUTPUT_DIR / "nuclei-findings.json"
    triage_file = OUTPUT_DIR / "triage.json"
    
    if triage_file.exists():
        triage_data = analyze_findings(triage_file)
        print(f"   Total Findings: {triage_data['count']}")
        if triage_data.get("by_severity"):
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = triage_data["by_severity"].get(sev, 0)
                if count > 0:
                    print(f"      {sev.capitalize()}: {count}")
    elif nuclei_file.exists():
        nuclei_data = analyze_findings(nuclei_file)
        print(f"   Raw Findings: {nuclei_data['count']}")
        if nuclei_data.get("by_severity"):
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = nuclei_data["by_severity"].get(sev, 0)
                if count > 0:
                    print(f"      {sev.capitalize()}: {count}")
    else:
        print("   No findings yet")
    print()
    
    # Recent log entries
    log_file = OUTPUT_DIR / "recon-run.log"
    if log_file.exists():
        print("📝 Recent Log Entries:")
        recent_lines = read_log_tail(log_file, 5)
        for line in recent_lines:
            print(f"   {line}")
        print()
    
    # Reports
    reports_dir = OUTPUT_DIR / "reports"
    if reports_dir.exists():
        report_files = list(reports_dir.glob("*.md"))
        if report_files:
            print("📄 Reports:")
            for report in report_files:
                info = get_file_info(report)
                print(f"   ✓ {report.name} ({info['size_formatted']})")
            print()
    
    print("=" * 70)
    print("Run again to refresh status")
    print(f"Log file: {log_file}")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
