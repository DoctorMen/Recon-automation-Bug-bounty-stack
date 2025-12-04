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
All-in-One Nuclei Results Processor
Parses text results, triages, and generates reports in one run
"""

import json
import sys
import re
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Pre-compile regex patterns for better performance (avoid recompilation on each line)
NUCLEI_PATTERN_FULL = re.compile(r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] ([^\s]+(?:\s+[^\[]+)?)(?:\s+\[(.*)\])?$')
NUCLEI_PATTERN_SIMPLE = re.compile(r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.+)$')
EXTRACT_PATTERN = re.compile(r'"([^"]+)"|([^,]+)')

def parse_nuclei_text_line(line: str):
    """Parse a single line of nuclei text output (uses pre-compiled regex)"""
    line = line.strip()
    if not line or (line.startswith('[') and 'INF]' in line):
        return None
    if 'Scan completed' in line or 'matches found' in line:
        return None
    
    # Use pre-compiled patterns for better performance
    match = NUCLEI_PATTERN_FULL.match(line)
    
    if not match:
        match = NUCLEI_PATTERN_SIMPLE.match(line)
        if not match:
            return None
        tag, finding_type, severity, target = match.groups()
        extra_info = None
    else:
        tag, finding_type, severity, target, extra_info = match.groups()
    
    target = target.strip().strip('"')
    if ':' in target:
        pass
    elif ' ' in target:
        target = target.split()[0]
    
    extracted = []
    if extra_info:
        extra_info = extra_info.strip()
        if extra_info.startswith('[') and extra_info.endswith(']'):
            extra_info = extra_info[1:-1]
        if extra_info:
            parts = EXTRACT_PATTERN.findall(extra_info)
            extracted = [p[0] if p[0] else p[1].strip().strip('"') for p in parts if p[0] or p[1].strip()]
    
    matched_at = target
    if ':' not in matched_at:
        if finding_type == 'ssl':
            matched_at = f"{target}:443"
        elif finding_type == 'http':
            matched_at = f"http://{target}"
    
    finding = {
        "template-id": tag,
        "info": {
            "name": tag.replace('-', ' ').title(),
            "author": ["nuclei-templates"],
            "tags": [tag, finding_type],
            "severity": severity,
            "description": f"{tag} detected on {target}",
            "classification": {
                "cwe-id": [],
                "cvss-score": 0.0
            }
        },
        "type": finding_type,
        "host": target,
        "matched-at": matched_at,
        "extracted-results": extracted,
        "timestamp": datetime.now().isoformat()
    }
    
    if finding_type == "ssl" and extracted:
        finding["info"]["description"] = f"{tag} on {target}: {', '.join(extracted)}"
    if finding_type == "dns" and extracted:
        finding["info"]["description"] = f"{tag} on {target}: {', '.join(extracted)}"
    
    return finding

def main():
    print("=" * 60)
    print("Processing Nuclei Results - All-in-One")
    print("=" * 60)
    print()
    
    # Find input file
    default_input = Path.home() / "nuclei-templates" / "results_web_scan.txt"
    if len(sys.argv) > 1:
        input_file = Path(sys.argv[1])
    else:
        input_file = default_input
    
    if not input_file.exists():
        print(f"ERROR: File not found: {input_file}")
        print(f"\nUsage: python3 {sys.argv[0]} [path-to-results_web_scan.txt]")
        sys.exit(1)
    
    script_dir = Path(__file__).parent
    output_dir = script_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Parse
    print(f">>> Step 1/3: Parsing {input_file}...")
    findings = []
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            finding = parse_nuclei_text_line(line)
            if finding:
                findings.append(finding)
            if line_num % 100 == 0:
                print(f"  Processed {line_num} lines, found {len(findings)} findings...")
    
    if not findings:
        print("ERROR: No findings parsed!")
        sys.exit(1)
    
    print(f"✓ Parsed {len(findings)} findings")
    
    # Write JSON
    json_file = output_dir / "nuclei-findings.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"✓ Written to: {json_file}")
    
    # Step 2: Run triage script
    print()
    print(">>> Step 2/3: Running triage...")
    try:
        triage_script = script_dir / "scripts" / "triage.py"
        result = subprocess.run([sys.executable, str(triage_script)], 
                              capture_output=False, text=True, check=True)
        print("✓ Triage completed")
    except subprocess.CalledProcessError as e:
        print(f"ERROR in triage: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    
    # Step 3: Generate reports
    print()
    print(">>> Step 3/3: Generating reports...")
    try:
        report_script = script_dir / "scripts" / "generate_report.py"
        result = subprocess.run([sys.executable, str(report_script)], 
                              capture_output=False, text=True, check=True)
        print("✓ Reports generated")
    except subprocess.CalledProcessError as e:
        print(f"ERROR in report generation: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    
    # Summary
    print()
    print("=" * 60)
    print("COMPLETE!")
    print("=" * 60)
    
    triage_file = output_dir / "triage.json"
    if triage_file.exists():
        with open(triage_file, 'r') as f:
            triaged = json.load(f)
        
        severity_counts = {}
        for finding in triaged:
            sev = finding.get("info", {}).get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"\nTotal Findings: {len(triaged)}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                print(f"  {sev.upper()}: {count}")
    
    print(f"\nFiles created:")
    print(f"  - {json_file}")
    print(f"  - {triage_file}")
    print(f"  - {output_dir / 'reports' / 'summary.md'}")
    print(f"\nView summary: cat {output_dir / 'reports' / 'summary.md'}")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
