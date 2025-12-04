#!/usr/bin/env python3
"""
IDOR Report Factory Template
Generates clean, ready‑to‑submit IDOR/BOLA reports from test results.

Usage:
1. After running IDOR tests, create a findings.json with successful cases.
2. Run: python3 report_factory_idor.py
3. Review generated report in idor_report.md
"""

import json
import sys
from pathlib import Path
from datetime import datetime

def load_findings(path):
    """Load IDOR test findings from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading findings.json: {e}")
        sys.exit(1)

def generate_report(findings):
    """
    Generate a markdown report from findings.
    Expected findings format:
    [
        {
            "program": "Program Name",
            "host": "app.example.com",
            "method": "GET",
            "path": "/api/v1/users/12345",
            "auth_used": "user_token",
            "result": "access_to_other_user_data",
            "impact": "High",
            "proof": {...}
        },
        ...
    ]
    """
    report_lines = []
    report_lines.append("# IDOR/BOLA Vulnerability Report")
    report_lines.append(f"**Program:** {findings[0].get('program', 'Unknown')}")
    report_lines.append(f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}")
    report_lines.append("")
    report_lines.append("## Summary")
    report_lines.append("A direct object reference (IDOR) vulnerability was identified allowing an authenticated user to access or modify data belonging to another user or organization by manipulating predictable identifiers in API requests.")
    report_lines.append("")
    report_lines.append("## Affected Components")
    for f in findings:
        host = f.get("host", "unknown")
        method = f.get("method", "GET")
        path = f.get("path", "")
        report_lines.append(f"- URL: `https://{host}{path}`")
        report_lines.append(f"  - Method: {method}")
        report_lines.append(f"  - Auth used: {f.get('auth_used', 'N/A')}")
    report_lines.append("")
    report_lines.append("## Steps to Reproduce")
    for i, f in enumerate(findings, 1):
        report_lines.append(f"{i}. Authenticate as a regular user ({f.get('auth_used', 'user_token')}).")
        report_lines.append(f"{i+1}. Send a `{f.get('method', 'GET')}` request to:")
        report_lines.append(f"   ```http")
        report_lines.append(f"   {f.get('method', 'GET')} https://{f.get('host', 'app.example.com')}{f.get('path', '')}")
        report_lines.append(f"   Authorization: Bearer [REDACTED]")
        report_lines.append(f"   ```")
        report_lines.append(f"{i+2}. Observe that the response includes data belonging to another user/organization.")
        report_lines.append("")
    report_lines.append("## Proof of Concept")
    for i, f in enumerate(findings, 1):
        report_lines.append(f"### Finding {i}")
        report_lines.append(f"- **Endpoint:** `https://{f.get('host', 'app.example.com')}{f.get('path', '')}`")
        report_lines.append(f"- **Result:** {f.get('result', 'Access to unauthorized data')}")
        report_lines.append(f"- **Impact:** {f.get('impact', 'High')}")
        # Include sanitized proof snippet
        proof = f.get("proof", {})
        if "request" in proof:
            report_lines.append("- **Request (sanitized):**")
            report_lines.append("  ```http")
            report_lines.append(f"  {proof['request']}")
            report_lines.append("  ```")
        if "response_snippet" in proof:
            report_lines.append("- **Response snippet (sanitized):**")
            report_lines.append("  ```json")
            report_lines.append(f"  {proof['response_snippet']}")
            report_lines.append("  ```")
        report_lines.append("")
    report_lines.append("## Impact")
    report_lines.append("An attacker can:")
    report_lines.append("- Access or modify sensitive data belonging to other users or organizations.")
    report_lines.append("- Potentially escalate privileges or extract PII, financial data, or confidential business information.")
    report_lines.append("- Undermine the application’s access control model, leading to widespread data exposure.")
    report_lines.append("")
    report_lines.append("## Remediation")
    report_lines.append("1. **Validate ownership:** Ensure the server verifies that the authenticated user is authorized to access the requested resource.")
    report_lines.append("2. **Use non‑sequential identifiers:** Replace predictable numeric IDs with UUIDs or random tokens.")
    report_lines.append("3. **Implement proper access control checks:** Enforce role/permission checks at the API endpoint level.")
    report_lines.append("4. **Audit logs:** Log access attempts to sensitive resources for detection of abuse.")
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
    print(f"[+] Saved IDOR report to: {path}")

def main():
    findings_file = Path("findings.json")
    report_file = Path("idor_report.md")
    if not findings_file.is_file():
        print("[!] findings.json not found. Creating stub.")
        stub = [
            {
                "program": "Example Program",
                "host": "app.example.com",
                "method": "GET",
                "path": "/api/v1/users/12345",
                "auth_used": "user_token",
                "result": "access_to_other_user_data",
                "impact": "High",
                "proof": {
                    "request": "GET /api/v1/users/12345 HTTP/1.1\\nHost: app.example.com\\nAuthorization: Bearer [REDACTED]",
                    "response_snippet": '{\\"id\\":12345,\\"email\\":\\"victim@example.com\\",\\"role\\":\\"user\\"}'
                }
            }
        ]
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub findings.json created at {findings_file}")
        print("[!] Edit it with real findings and re-run.")
        return

    findings = load_findings(findings_file)
    if not findings:
        print("[!] No findings in findings.json; nothing to report.")
        return
    report = generate_report(findings)
    save_report(report, report_file)
    print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    main()
