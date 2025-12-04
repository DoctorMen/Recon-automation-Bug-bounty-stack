#!/usr/bin/env python3
"""
SSRF Report Factory Template
Generates clean, ready‑to‑submit SSRF reports from test results.

Usage:
1. After SSRF testing, create ssrf_findings.json with successful cases.
2. Run: python3 report_factory_ssrf.py
3. Review generated report in ssrf_report.md
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def load_findings(path):
    """Load SSRF test findings from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading ssrf_findings.json: {e}")
        sys.exit(1)

def generate_report(findings):
    """
    Generate a markdown report from findings.
    Expected findings format:
    [
        {
            "program": "Program Name",
            "host": "app.example.com",
            "endpoint": "/api/v1/fetch",
            "method": "POST",
            "parameter": "url",
            "payload": "https://example.com",
            "result": "internal_service_response",
            "impact": "High",
            "proof": {...}
        },
        ...
    ]
    """
    report_lines = []
    report_lines.append("# Server-Side Request Forgery (SSRF) Report")
    report_lines.append(f"**Program:** {findings[0].get('program', 'Unknown')}")
    report_lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    report_lines.append("")
    report_lines.append("## Summary")
    report_lines.append("A Server-Side Request Forgery (SSRF) vulnerability was identified allowing an attacker to make the application server send arbitrary requests to internal or external services on their behalf.")
    report_lines.append("")
    report_lines.append("## Affected Components")
    for f in findings:
        host = f.get("host", "unknown")
        endpoint = f.get("endpoint", "")
        method = f.get("method", "POST")
        report_lines.append(f"- URL: `https://{host}{endpoint}`")
        report_lines.append(f"  - Method: {method}")
        report_lines.append(f"  - Vulnerable parameter: {f.get('parameter', 'url')}")
    report_lines.append("")
    report_lines.append("## Steps to Reproduce")
    for i, f in enumerate(findings, 1):
        report_lines.append(f"{i}. Authenticate as a regular user (if required).")
        report_lines.append(f"{i+1}. Send a `{f.get('method', 'POST')}` request to:")
        report_lines.append(f"   ```http")
        report_lines.append(f"   {f.get('method', 'POST')} https://{f.get('host', 'app.example.com')}{f.get('endpoint', '')}")
        report_lines.append(f"   Content-Type: application/x-www-form-urlencoded")
        report_lines.append(f"   {f.get('parameter', 'url')}={f.get('payload', 'https://example.com')}")
        report_lines.append(f"   ```")
        report_lines.append(f"{i+2}. Observe that the server fetches the attacker‑controlled URL and reflects data from an internal service.")
        report_lines.append("")
    report_lines.append("## Proof of Concept")
    for i, f in enumerate(findings, 1):
        report_lines.append(f"### Finding {i}")
        report_lines.append(f"- **Endpoint:** `https://{f.get('host', 'app.example.com')}{f.get('endpoint', '')}`")
        report_lines.append(f"- **Parameter:** {f.get('parameter', 'url')}")
        report_lines.append(f"- **Payload:** `{f.get('payload', 'https://example.com')}`")
        report_lines.append(f"- **Result:** {f.get('result', 'Internal service response')}")
        report_lines.append(f"- **Impact:** {f.get('impact', 'High')}")
        proof = f.get("proof", {})
        if "request" in proof:
            report_lines.append("- **Request (sanitized):**")
            report_lines.append("  ```http")
            report_lines.append(f"  {proof['request']}")
            report_lines.append("  ```")
        if "response_snippet" in proof:
            report_lines.append("- **Response snippet (sanitized):**")
            report_lines.append("  ```")
            report_lines.append(f"  {proof['response_snippet']}")
            report_lines.append("  ```")
        report_lines.append("")
    report_lines.append("## Impact")
    report_lines.append("An attacker can:")
    report_lines.append("- Bypass network restrictions and access internal services (e.g., metadata services, databases, admin panels).")
    report_lines.append("- Exfiltrate sensitive data from internal networks.")
    report_lines.append("- Scan internal infrastructure or pivot to other internal systems.")
    report_lines.append("- Potentially achieve remote code execution via internal services.")
    report_lines.append("")
    report_lines.append("## Remediation")
    report_lines.append("1. **Allowlist URLs:** Restrict the URLs that can be fetched to a predefined allowlist.")
    report_lines.append("2. **Validate input:** Reject URLs that point to private/internal ranges (e.g., 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 192.168.0.0/16).")
    report_lines.append("3. **Disable redirects:** Do not follow server‑side redirects.")
    report_lines.append("4. **Use a dedicated library:** Employ a library designed for safe URL fetching (e.g., with built‑in SSRF protection).")
    report_lines.append("5. **Network segmentation:** Ensure the application cannot reach sensitive internal services.")
    report_lines.append("")
    report_lines.append("## Timeline")
    report_lines.append(f"- **Discovered:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    report_lines.append(f"- **Reported:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    report_lines.append("")
    return "\n".join(report_lines)

def save_report(report, path):
    """Save report to markdown file."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[+] Saved SSRF report to: {path}")

def main():
    findings_file = Path("ssrf_findings.json")
    report_file = Path("ssrf_report.md")
    if not findings_file.is_file():
        print("[!] ssrf_findings.json not found. Creating stub.")
        stub = [
            {
                "program": "Example Program",
                "host": "app.example.com",
                "endpoint": "/api/v1/fetch",
                "method": "POST",
                "parameter": "url",
                "payload": "https://example.com",
                "result": "internal_service_response",
                "impact": "High",
                "proof": {
                    "request": "POST /api/v1/fetch HTTP/1.1\\nHost: app.example.com\\nContent-Type: application/x-www-form-urlencoded\\n\\nurl=https://example.com",
                    "response_snippet": "Internal service metadata: ..."
                }
            }
        ]
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub ssrf_findings.json created at {findings_file}")
        print("[!] Edit it with real findings and re-run.")
        return

    findings = load_findings(findings_file)
    if not findings:
        print("[!] No findings in ssrf_findings.json; nothing to report.")
        return
    report = generate_report(findings)
    save_report(report, report_file)
    print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    main()
