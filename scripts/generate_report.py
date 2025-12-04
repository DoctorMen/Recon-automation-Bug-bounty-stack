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
Report Writer Agent
Creates Markdown proof-of-concept and remediation reports
Input: ~/recon-stack/output/triage.json
Output: ~/recon-stack/output/reports/*.md
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
TRIAGE_FILE = OUTPUT_DIR / "triage.json"
REPORTS_DIR = OUTPUT_DIR / "reports"
LOG_FILE = OUTPUT_DIR / "recon-run.log"

# Severity emojis for better visibility
SEVERITY_EMOJIS = {
    "info": "ℹ️",
    "low": "🟢",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}


def log(message: str):
    """Write log message to both stdout and log file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as filename"""
    # Replace problematic characters
    sanitized = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in name)
    return sanitized[:200]  # Limit length


def format_timestamp(timestamp: str) -> str:
    """Format ISO timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return timestamp


def generate_poc(finding: Dict[str, Any]) -> str:
    """Generate proof-of-concept section"""
    info = finding.get("info", {})
    matched_at = finding.get("matched-at", finding.get("host", "Unknown"))
    template_id = finding.get("template-id", "unknown")
    
    poc = f"""## Proof of Concept

### Target URL
```
{matched_at}
```

### Template
- **Template ID**: `{template_id}`
- **Template Name**: {info.get("name", "Unknown")}

### Detection Method
{info.get("description", "Automated detection via Nuclei scan")}
"""
    
    # Add request/response if available
    if "request" in finding:
        poc += f"""
### Request
```http
{finding["request"]}
```
"""
    
    if "response" in finding:
        poc += f"""
### Response
```http
{finding["response"][:1000]}...
```
"""
    
    # Add extracted information
    extracted = finding.get("extracted-results", [])
    if extracted:
        poc += f"""
### Extracted Information
```
{chr(10).join(extracted)}
```
"""
    
    return poc


def generate_remediation(finding: Dict[str, Any]) -> str:
    """Generate remediation section"""
    info = finding.get("info", {})
    remediation = info.get("remediation", "")
    reference = info.get("reference", [])
    
    section = "## Remediation\n\n"
    
    if remediation:
        section += f"{remediation}\n\n"
    else:
        section += "### Recommended Actions\n\n"
        severity = info.get("severity", "unknown").lower()
        
        if severity in ["critical", "high"]:
            section += "1. **Immediate Action Required**: Address this vulnerability as soon as possible\n"
            section += "2. Apply security patches or updates if available\n"
            section += "3. Implement proper input validation and sanitization\n"
            section += "4. Review and strengthen security controls\n"
        elif severity == "medium":
            section += "1. Address this vulnerability in the next maintenance window\n"
            section += "2. Review security configuration\n"
            section += "3. Consider implementing additional security measures\n"
        else:
            section += "1. Review and consider addressing in future updates\n"
            section += "2. Monitor for any changes in severity\n"
    
    if reference:
        section += "\n### References\n\n"
        for ref in reference if isinstance(reference, list) else [reference]:
            section += f"- {ref}\n"
    
    # Add CVE/CWE if available
    cve = info.get("cve-id")
    cwe = info.get("cwe-id")
    
    if cve or cwe:
        section += "\n### Security References\n\n"
        if cve:
            section += f"- **CVE**: {cve} - [View on CVE Database](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve})\n"
        if cwe:
            # Handle both CWE-79 and CWE-ID:79 formats
            cwe_num = cwe
            if isinstance(cwe, str) and '-' in cwe:
                cwe_num = cwe.split('-')[-1]
            elif isinstance(cwe, list):
                cwe_num = cwe[0].split('-')[-1] if cwe else ""
            section += f"- **CWE**: {cwe} - [View on CWE Database](https://cwe.mitre.org/data/definitions/{cwe_num}.html)\n"
    
    return section


def generate_individual_report(finding: Dict[str, Any]) -> Path:
    """Generate a markdown report for a single finding"""
    info = finding.get("info", {})
    template_id = finding.get("template-id", "unknown")
    severity = info.get("severity", "info").lower()
    matched_at = finding.get("matched-at", finding.get("host", "unknown"))
    
    # Create filename
    domain = urlparse(matched_at).netloc if matched_at else "unknown"
    safe_domain = sanitize_filename(domain)
    safe_template = sanitize_filename(template_id)
    filename = f"{safe_domain}_{safe_template}_{severity}.md"
    report_path = REPORTS_DIR / filename
    
    # Generate report content
    emoji = SEVERITY_EMOJIS.get(severity, "ℹ️")
    triage = finding.get("triage", {})
    
    content = f"""# {emoji} {info.get("name", template_id)}

**Severity**: {severity.upper()}  
**Target**: `{matched_at}`  
**Discovered**: {format_timestamp(finding.get("timestamp", datetime.now().isoformat()))}  
**Exploitability Score**: {triage.get("exploitability_score", "N/A")}/10  
**CVSS Score**: {triage.get("cvss_score", "N/A")}

---

## Description

{info.get("description", "No description available")}

{generate_poc(finding)}

{generate_remediation(finding)}

---

## Metadata

- **Template ID**: `{template_id}`
- **Template Path**: `{finding.get("template-path", "N/A")}`
- **Author**: {info.get("author", "N/A")}
- **Tags**: {", ".join(info.get("tags", []))}
"""
    
    # Write report
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    return report_path


def generate_summary_report(findings: List[Dict[str, Any]]) -> Path:
    """Generate a summary report of all findings"""
    summary_path = REPORTS_DIR / "summary.md"
    
    # Count by severity using Counter for better performance
    from collections import Counter
    severity_counts = Counter(
        finding.get("info", {}).get("severity", "info").lower() 
        for finding in findings
    )
    
    # Sort findings by exploitability score
    sorted_findings = sorted(
        findings,
        key=lambda x: x.get("triage", {}).get("exploitability_score", 0),
        reverse=True
    )
    
    content = f"""# Security Scan Summary Report

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Total Findings**: {len(findings)}

---

## Severity Breakdown

"""
    
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            emoji = SEVERITY_EMOJIS.get(sev, "ℹ️")
            content += f"- {emoji} **{sev.upper()}**: {count}\n"
    
    content += f"""
---

## Top Findings by Exploitability

"""
    
    # Show top 10 findings
    for idx, finding in enumerate(sorted_findings[:10], 1):
        info = finding.get("info", {})
        template_id = finding.get("template-id", "unknown")
        severity = info.get("severity", "info").lower()
        matched_at = finding.get("matched-at", "unknown")
        exploit_score = finding.get("triage", {}).get("exploitability_score", 0)
        emoji = SEVERITY_EMOJIS.get(severity, "ℹ️")
        
        domain = urlparse(matched_at).netloc if matched_at else "unknown"
        safe_domain = sanitize_filename(domain)
        safe_template = sanitize_filename(template_id)
        individual_filename = f"{safe_domain}_{safe_template}_{severity}.md"
        
        content += f"""### {idx}. {emoji} {info.get("name", template_id)}

- **Severity**: {severity.upper()}
- **Target**: `{matched_at}`
- **Exploitability Score**: {exploit_score}/10
- **CVSS Score**: {finding.get("triage", {}).get("cvss_score", "N/A")}
- **Details**: [{individual_filename}]({individual_filename})

"""
    
    content += """
---

## Report Files

All individual finding reports are available in this directory. Each finding has been analyzed, scored, and includes proof-of-concept details and remediation recommendations.

"""
    
    # Write summary
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    return summary_path


def main():
    """Main report generation function"""
    log("=== Report Writer Agent Starting ===")
    
    # Ensure directories exist
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load triaged findings
    if not TRIAGE_FILE.exists():
        log(f"ERROR: {TRIAGE_FILE} not found")
        log("Please run triage agent first (scripts/triage.py)")
        sys.exit(1)
    
    try:
        with open(TRIAGE_FILE, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except json.JSONDecodeError as e:
        log(f"ERROR: Invalid JSON in {TRIAGE_FILE}: {e}")
        sys.exit(1)
    except Exception as e:
        log(f"ERROR: Failed to read {TRIAGE_FILE}: {e}")
        sys.exit(1)
    
    if not isinstance(findings, list):
        findings = [findings] if findings else []
    
    if not findings:
        log("No findings to report")
        # Create empty summary
        generate_summary_report([])
        sys.exit(0)
    
    log(f"Generating reports for {len(findings)} findings...")
    
    # Generate individual reports
    report_paths = []
    for finding in findings:
        try:
            path = generate_individual_report(finding)
            report_paths.append(path)
        except Exception as e:
            log(f"ERROR: Failed to generate report for finding: {e}")
    
    log(f"Generated {len(report_paths)} individual reports")
    
    # Generate summary report
    summary_path = generate_summary_report(findings)
    log(f"Generated summary report: {summary_path}")
    
    log("=== Report Writer Agent Complete ===")
    log(f"Reports available in: {REPORTS_DIR}")


if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
