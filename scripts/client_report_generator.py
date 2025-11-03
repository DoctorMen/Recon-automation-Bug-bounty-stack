#!/usr/bin/env python3
"""
Professional Client Report Generator
Generates business-friendly security scan reports for paying clients
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
CLIENT_REPORTS_DIR = OUTPUT_DIR / "client_reports"

# Severity emojis
SEVERITY_EMOJIS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "ℹ️"
}

# Business impact descriptions
IMPACT_DESCRIPTIONS = {
    "critical": {
        "business": "This vulnerability could lead to complete system compromise, data breach, or financial loss.",
        "example": "Hackers could access your customer database or take control of your website.",
        "urgency": "Fix immediately - within 24 hours"
    },
    "high": {
        "business": "This vulnerability could result in unauthorized access to sensitive data or system functions.",
        "example": "Hackers could steal customer information or manipulate your business operations.",
        "urgency": "Fix within 48-72 hours"
    },
    "medium": {
        "business": "This vulnerability could be exploited to gain limited unauthorized access or disrupt operations.",
        "example": "Hackers could potentially access some user accounts or cause minor disruptions.",
        "urgency": "Fix within 1-2 weeks"
    },
    "low": {
        "business": "This vulnerability has limited impact but should be addressed as part of security improvements.",
        "example": "Minor information disclosure that doesn't directly expose sensitive data.",
        "urgency": "Fix within 1 month"
    }
}


def calculate_security_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate security score out of 10"""
    if not findings:
        return 10
    
    critical = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "critical")
    high = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "high")
    medium = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "medium")
    low = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "low")
    
    # Score calculation: 10 - (critical*3 + high*2 + medium*1 + low*0.5)
    score = 10 - (critical * 3 + high * 2 + medium * 1 + low * 0.5)
    return max(0, min(10, int(score)))


def generate_client_report(
    client_name: str,
    client_email: str,
    website_url: str,
    findings: List[Dict[str, Any]],
    scan_id: str,
    scan_date: Optional[str] = None
) -> Path:
    """Generate professional client report"""
    
    CLIENT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    if not scan_date:
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Parse domain from URL
    parsed_url = urlparse(website_url)
    domain = parsed_url.netloc or parsed_url.path
    
    # Calculate security score
    security_score = calculate_security_score(findings)
    
    # Group findings by severity
    critical_findings = [f for f in findings if f.get("info", {}).get("severity", "").lower() == "critical"]
    high_findings = [f for f in findings if f.get("info", {}).get("severity", "").lower() == "high"]
    medium_findings = [f for f in findings if f.get("info", {}).get("severity", "").lower() == "medium"]
    low_findings = [f for f in findings if f.get("info", {}).get("severity", "").lower() == "low"]
    
    # Generate report content
    report_content = f"""══════════════════════════════════════════════
EMERGENCY SECURITY SCAN REPORT
══════════════════════════════════════════════

For: {client_name}
Website: {website_url}
Date: {scan_date}
Scan ID: {scan_id}
Security Score: {security_score}/10

══════════════════════════════════════════════

EXECUTIVE SUMMARY

This security scan identified {len(findings)} security issue(s) on your website that require attention.

"""

    # Critical findings
    if critical_findings:
        report_content += f"""
🔴 CRITICAL FINDINGS ({len(critical_findings)})

"""
        for idx, finding in enumerate(critical_findings[:5], 1):  # Limit to top 5
            info = finding.get("info", {})
            name = info.get("name", "Unknown Vulnerability")
            description = info.get("description", "No description available")
            matched_at = finding.get("matched-at", "Unknown location")
            
            impact = IMPACT_DESCRIPTIONS.get("critical", {})
            
            report_content += f"""
{idx}. {name}

Location: {matched_at}

Issue: {description}

Business Impact: {impact['business']}

Example: {impact['example']}

FIX IMMEDIATELY: {impact['urgency']}

"""
    
    # High findings
    if high_findings:
        report_content += f"""
🟠 HIGH PRIORITY FINDINGS ({len(high_findings)})

"""
        for idx, finding in enumerate(high_findings[:5], 1):
            info = finding.get("info", {})
            name = info.get("name", "Unknown Vulnerability")
            description = info.get("description", "No description available")
            matched_at = finding.get("matched-at", "Unknown location")
            
            impact = IMPACT_DESCRIPTIONS.get("high", {})
            
            report_content += f"""
{idx}. {name}

Location: {matched_at}

Issue: {description}

Business Impact: {impact['business']}

Recommendation: {impact['urgency']}

"""
    
    # Medium findings
    if medium_findings:
        report_content += f"""
🟡 MEDIUM PRIORITY FINDINGS ({len(medium_findings)})

"""
        for idx, finding in enumerate(medium_findings[:3], 1):  # Limit to top 3
            info = finding.get("info", {})
            name = info.get("name", "Unknown Vulnerability")
            matched_at = finding.get("matched-at", "Unknown location")
            
            report_content += f"""
{idx}. {name} at {matched_at}
"""
    
    # Low findings
    if low_findings:
        report_content += f"""
🟢 RECOMMENDATIONS ({len(low_findings)})

These are minor security improvements that should be addressed as part of regular security maintenance.
"""
    
    # Next steps
    report_content += f"""
══════════════════════════════════════════════

NEXT STEPS

1. Fix critical issues immediately (within 24 hours)
   - These pose the highest risk to your business
   - Consider temporary measures if full fix takes longer

2. Address high priority issues (within 48-72 hours)
   - These could lead to data breaches or unauthorized access

3. Plan fixes for medium priority issues (within 1-2 weeks)
   - Schedule these as part of your regular maintenance

4. Consider monthly security monitoring
   - Catch new vulnerabilities before hackers do
   - Receive alerts when new issues are discovered
   - Peace of mind knowing your site is monitored

══════════════════════════════════════════════

QUESTIONS OR NEED HELP?

If you have questions about fixing these issues or want to discuss monthly monitoring services, please reply to this email or call us.

Thank you for taking website security seriously.

Best regards,
Security Scan Team

══════════════════════════════════════════════
"""
    
    # Save report
    safe_client_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in client_name)
    safe_domain = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in domain)
    filename = f"{scan_id}_{safe_client_name}_{safe_domain}.md"
    report_path = CLIENT_REPORTS_DIR / filename
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    return report_path


def generate_report_from_scan_results(
    client_name: str,
    client_email: str,
    website_url: str,
    scan_output_dir: Optional[Path] = None
) -> Path:
    """Generate report from existing scan results"""
    
    if not scan_output_dir:
        scan_output_dir = OUTPUT_DIR
    
    # Try to find findings
    findings_files = [
        scan_output_dir / "triage.json",
        scan_output_dir / "nuclei-findings.json",
        scan_output_dir / "immediate_roi" / "high_roi_findings.json"
    ]
    
    findings = []
    for findings_file in findings_files:
        if findings_file.exists():
            try:
                with open(findings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        findings.extend(data)
                    elif isinstance(data, dict):
                        findings.append(data)
            except Exception as e:
                print(f"Warning: Could not read {findings_file}: {e}")
    
    if not findings:
        print("Warning: No findings found. Creating empty report.")
    
    # Generate scan ID
    scan_id = f"ES-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    return generate_client_report(
        client_name=client_name,
        client_email=client_email,
        website_url=website_url,
        findings=findings,
        scan_id=scan_id
    )


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate professional client security report")
    parser.add_argument("--client-name", required=True, help="Client business name")
    parser.add_argument("--client-email", required=True, help="Client email address")
    parser.add_argument("--website", required=True, help="Client website URL")
    parser.add_argument("--scan-dir", help="Directory containing scan results (default: output/)")
    parser.add_argument("--findings-json", help="JSON file with findings")
    
    args = parser.parse_args()
    
    findings = []
    
    # Load findings if provided
    if args.findings_json:
        findings_file = Path(args.findings_json)
        if findings_file.exists():
            with open(findings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict):
                    findings = [data]
    
    scan_dir = Path(args.scan_dir) if args.scan_dir else None
    
    if findings:
        scan_id = f"ES-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        report_path = generate_client_report(
            client_name=args.client_name,
            client_email=args.client_email,
            website_url=args.website,
            findings=findings,
            scan_id=scan_id
        )
    else:
        report_path = generate_report_from_scan_results(
            client_name=args.client_name,
            client_email=args.client_email,
            website_url=args.website,
            scan_output_dir=scan_dir
        )
    
    print(f"✅ Client report generated: {report_path}")
    return report_path


if __name__ == "__main__":
    main()

