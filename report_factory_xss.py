#!/usr/bin/env python3
"""
XSS Report Factory Template
Generates clean, ready‑to‑submit XSS reports from test results.

Usage:
1. After XSS testing, create xss_findings.json with successful cases.
2. Run: python3 report_factory_xss.py
3. Review generated report in xss_report.md
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def load_findings(path):
    """Load XSS test findings from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading xss_findings.json: {e}")
        sys.exit(1)

def generate_report(findings):
    """
    Generate a markdown report from findings.
    Expected findings format:
    [
        {
            "program": "Program Name",
            "host": "app.example.com",
            "endpoint": "/search",
            "method": "GET",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "result": "alert_executed",
            "impact": "Medium",
            "proof": {...}
        },
        ...
    ]
    """
    report_lines = []
    report_lines.append("# Cross‑Site Scripting (XSS) Report")
    report_lines.append(f"**Program:** {findings[0].get('program', 'Unknown')}")
    report_lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    report_lines.append("")
    report_lines.append("## Summary")
    report_lines.append("A Cross‑Site Scripting (XSS) vulnerability was identified allowing an attacker to inject and execute arbitrary JavaScript in the context of other users' sessions.")
    report_lines.append("")
    report_lines.append("## Affected Components")
    for f in findings:
        host = f.get("host", "unknown")
        endpoint = f.get("endpoint", "")
        method = f.get("method", "GET")
        report_lines.append(f"- URL: `https://{host}{endpoint}`")
        report_lines.append(f"  - Method: {method}")
        report_lines.append(f"  - Vulnerable parameter: {f.get('parameter', 'q')}")
    report_lines.append("")
    report_lines.append("## Steps to Reproduce")
    for i, f in enumerate(findings, 1):
        report_lines.append(f"{i}. Authenticate as a regular user (if required).")
        report_lines.append(f"{i+1}. Send a `{f.get('method', 'GET')}` request to:")
        report_lines.append(f"   ```http")
        report_lines.append(f"   {f.get('method', 'GET')} https://{f.get('host', 'app.example.com')}{f.get('endpoint', '')}?{f.get('parameter', 'q')}={f.get('payload', '<script>alert(1)</script>')}")
        report_lines.append(f"   ```")
        report_lines.append(f"{i+2}. Observe that the injected script executes in the browser (e.g., an alert appears).")
        report_lines.append("")
    report_lines.append("## Proof of Concept")
    for i, f in enumerate(findings, 1):
        report_lines.append(f"### Finding {i}")
        report_lines.append(f"- **Endpoint:** `https://{f.get('host', 'app.example.com')}{f.get('endpoint', '')}`")
        report_lines.append(f"- **Parameter:** {f.get('parameter', 'q')}")
        report_lines.append(f"- **Payload:** `{f.get('payload', '<script>alert(1)</script>')}`")
        report_lines.append(f"- **Result:** {f.get('result', 'alert_executed')}")
        report_lines.append(f"- **Impact:** {f.get('impact', 'Medium')}")
        proof = f.get("proof", {})
        if "request" in proof:
            report_lines.append("- **Request (sanitized):**")
            report_lines.append("  ```http")
            report_lines.append(f"  {proof['request']}")
            report_lines.append("  ```")
        if "response_snippet" in proof:
            report_lines.append("- **Response snippet (sanitized):**")
            report_lines.append("  ```html")
            report_lines.append(f"  {proof['response_snippet']}")
            report_lines.append("  ```")
        if "screenshot" in proof:
            report_lines.append(f"- **Screenshot:** {proof['screenshot']}")
        report_lines.append("")
    report_lines.append("## Impact")
    report_lines.append("An attacker can:")
    report_lines.append("- Steal session cookies or authentication tokens.")
    report_lines.append("- Perform actions on behalf of the victim (e.g., change account settings, make purchases).")
    report_lines.append("- Deface the site or deliver phishing content.")
    report_lines.append("- Capture keystrokes or sensitive input via injected scripts.")
    report_lines.append("")
    report_lines.append("## Remediation")
    report_lines.append("1. **Output encoding:** Encode all user‑supplied data before rendering in HTML (e.g., using context‑aware encoding).")
    report_lines.append("2. **Content Security Policy (CSP):** Deploy a strong CSP to restrict script execution.")
    report_lines.append("3. **Input validation:** Reject or sanitize dangerous characters/patterns where possible.")
    report_lines.append("4. **Use safe frameworks:** Leverage modern frameworks that auto‑escape content by default.")
    report_lines.append("5. **HTTPOnly cookies:** Mark session cookies as HttpOnly and Secure.")
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
    print(f"[+] Saved XSS report to: {path}")

def main():
    findings_file = Path("xss_findings.json")
    report_file = Path("xss_report.md")
    if not findings_file.is_file():
        print("[!] xss_findings.json not found. Creating stub.")
        stub = [
            {
                "program": "Example Program",
                "host": "app.example.com",
                "endpoint": "/search",
                "method": "GET",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "result": "alert_executed",
                "impact": "Medium",
                "proof": {
                    "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1\\nHost: app.example.com",
                    "response_snippet": "<script>alert(1)</script>",
                    "screenshot": "path/to/screenshot.png"
                }
            }
        ]
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub xss_findings.json created at {findings_file}")
        print("[!] Edit it with real findings and re-run.")
        return

    findings = load_findings(findings_file)
    if not findings:
        print("[!] No findings in xss_findings.json; nothing to report.")
        return
    report = generate_report(findings)
    save_report(report, report_file)
    print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    main()
