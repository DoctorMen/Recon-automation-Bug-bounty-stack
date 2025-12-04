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
Parse Nuclei Text Output to JSON Format
Converts nuclei text output (like results_web_scan.txt) to nuclei-findings.json format
"""

import json
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

def parse_nuclei_text_line(line: str):
    """Parse a single line of nuclei text output"""
    line = line.strip()
    if not line or (line.startswith('[') and 'INF]' in line):
        # Skip empty lines and scan info lines
        return None
    
    # Skip scan completion messages
    if 'Scan completed' in line or 'matches found' in line:
        return None
    
    # Pattern: [tag] [type] [severity] target ["additional info"]
    # Example: [caa-fingerprint] [dns] [info] api-checkfreenext.fiservapps.com
    # Example: [dns-saas-service-detection] [dns] [info] api-checkfreenext-cert.fiservapps.com ["api-checkfreenext-cert.fiservapps.us.cloud-fdc.com"]
    # Example with quotes: [tag] [type] [severity] target ["info1","info2"]
    
    # More flexible pattern that handles quoted strings properly
    # Format: [tag] [type] [severity] target [optional extra info]
    # The extra info can be: ["value"] or just value or multiple ["val1","val2"]
    pattern = r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] ([^\s]+(?:\s+[^\[]+)?)(?:\s+\[(.*)\])?$'
    match = re.match(pattern, line)
    
    if not match:
        # Try simpler pattern without extra info
        pattern2 = r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.+)$'
        match = re.match(pattern2, line)
        if not match:
            return None
        tag, finding_type, severity, target = match.groups()
        extra_info = None
    else:
        tag, finding_type, severity, target, extra_info = match.groups()
    
    # Extract target URL/host (remove quotes if present, handle spaces)
    target = target.strip().strip('"')
    # If target has multiple words (like with :443), take first part
    if ':' in target:
        # Already has port, good
        pass
    elif ' ' in target:
        # Multiple words, take first
        target = target.split()[0]
    
    # Extract additional info if present
    extracted = []
    if extra_info:
        # Handle different formats: ["value"], value, ["val1","val2"]
        extra_info = extra_info.strip()
        # Remove outer brackets if present
        if extra_info.startswith('[') and extra_info.endswith(']'):
            extra_info = extra_info[1:-1]
        # Remove quotes and split by comma
        if extra_info:
            # Split by comma, handling quoted strings
            parts = re.findall(r'"([^"]+)"|([^,]+)', extra_info)
            extracted = [p[0] if p[0] else p[1].strip().strip('"') for p in parts if p[0] or p[1].strip()]
    
    # Determine matched-at URL
    matched_at = target
    if ':' not in matched_at:
        # Add default port based on type
        if finding_type == 'ssl':
            matched_at = f"{target}:443"
        elif finding_type == 'http':
            matched_at = f"http://{target}"
    
    # Build finding structure
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
    
    # Add SSL-specific fields
    if finding_type == "ssl" and extracted:
        finding["info"]["description"] = f"{tag} on {target}: {', '.join(extracted)}"
    
    # Add DNS-specific fields
    if finding_type == "dns" and extracted:
        finding["info"]["description"] = f"{tag} on {target}: {', '.join(extracted)}"
    
    return finding


def parse_nuclei_text_file(input_file: Path) -> List[Dict[str, Any]]:
    """Parse entire nuclei text output file"""
    findings = []
    
    if not input_file.exists():
        print(f"ERROR: File not found: {input_file}")
        return findings
    
    print(f"Parsing {input_file}...")
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            finding = parse_nuclei_text_line(line)
            if finding:
                findings.append(finding)
            
            if line_num % 100 == 0:
                print(f"  Processed {line_num} lines, found {len(findings)} valid findings...")
    
    return findings


def main():
    """Main function"""
    # Default input file
    default_input = Path.home() / "nuclei-templates" / "results_web_scan.txt"
    
    # Check for command line argument
    if len(sys.argv) > 1:
        input_file = Path(sys.argv[1])
    else:
        input_file = default_input
    
    # Output file
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    output_file = repo_root / "output" / "nuclei-findings.json"
    
    # Parse file
    findings = parse_nuclei_text_file(input_file)
    
    if not findings:
        print(f"No findings parsed from {input_file}")
        sys.exit(1)
    
    print(f"\nParsed {len(findings)} findings from {input_file}")
    
    # Create output directory
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Write JSON output
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    
    print(f"Written to: {output_file}")
    
    # Show statistics
    severity_counts = {}
    type_counts = {}
    for finding in findings:
        severity = finding.get("info", {}).get("severity", "unknown")
        finding_type = finding.get("type", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
    
    print("\n=== Statistics ===")
    print("\nBy Severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"  {sev.upper()}: {count}")
    
    print("\nBy Type:")
    for ftype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {ftype}: {count}")
    
    print(f"\n✓ Ready for triage: python3 {script_dir}/triage.py")
    print(f"✓ Then generate reports: python3 {script_dir}/generate_report.py")


if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
