"""
Report generator for vulnerability findings.

Generates Markdown reports with proof-of-concept details
and remediation recommendations.
"""

from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger
from recon_bounty_stack.utils.helpers import (
    format_timestamp,
    sanitize_filename,
    severity_to_emoji,
)


class ReportGenerator:
    """Generator for vulnerability reports.

    Creates:
    - Individual finding reports with POC details
    - Summary report with severity breakdown
    - Remediation recommendations

    Example:
        generator = ReportGenerator()
        results = generator.generate(findings)
    """

    def __init__(self, config: Config | None = None):
        """Initialize the report generator.

        Args:
            config: Configuration object
        """
        self.config = config or Config.from_env()
        self.logger = get_logger("recon.reports")
        self.reports_dir = self.config.output_dir / "reports"

    def generate(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate reports for all findings.

        Args:
            findings: List of triaged findings

        Returns:
            Dictionary containing generation results
        """
        self.logger.info(f"Generating reports for {len(findings)} findings")

        # Ensure reports directory exists
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Generate individual reports
        report_paths = []
        for finding in findings:
            try:
                path = self._generate_individual_report(finding)
                report_paths.append(path)
            except Exception as e:
                self.logger.error(f"Failed to generate report: {e}")

        self.logger.info(f"Generated {len(report_paths)} individual reports")

        # Generate summary report
        summary_path = self._generate_summary_report(findings)
        self.logger.info(f"Generated summary report: {summary_path}")

        return {
            "individual_reports": [str(p) for p in report_paths],
            "summary_report": str(summary_path),
            "count": len(report_paths),
        }

    def _generate_individual_report(self, finding: dict[str, Any]) -> Path:
        """Generate a report for a single finding."""
        info = finding.get("info", {})
        template_id = finding.get("template-id", "unknown")
        severity = info.get("severity", "info").lower()
        matched_at = finding.get("matched-at", finding.get("host", "unknown"))

        # Create filename
        domain = urlparse(matched_at).netloc if matched_at else "unknown"
        safe_domain = sanitize_filename(domain)
        safe_template = sanitize_filename(template_id)
        filename = f"{safe_domain}_{safe_template}_{severity}.md"
        report_path = self.reports_dir / filename

        # Generate content
        emoji = severity_to_emoji(severity)
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

{self._generate_poc_section(finding)}

{self._generate_remediation_section(finding)}

---

## Metadata

- **Template ID**: `{template_id}`
- **Template Path**: `{finding.get("template-path", "N/A")}`
- **Author**: {info.get("author", "N/A")}
- **Tags**: {", ".join(info.get("tags", []))}
"""

        # Write report
        report_path.write_text(content, encoding="utf-8")
        return report_path

    def _generate_poc_section(self, finding: dict[str, Any]) -> str:
        """Generate proof-of-concept section."""
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
            response = finding["response"]
            if len(response) > 1000:
                response = response[:1000] + "..."
            poc += f"""
### Response
```http
{response}
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

    def _generate_remediation_section(self, finding: dict[str, Any]) -> str:
        """Generate remediation section."""
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
            refs = reference if isinstance(reference, list) else [reference]
            for ref in refs:
                section += f"- {ref}\n"

        # Add CVE/CWE if available
        cve = info.get("cve-id")
        cwe = info.get("cwe-id")

        if cve or cwe:
            section += "\n### Security References\n\n"
            if cve:
                cve_id = cve if isinstance(cve, str) else cve[0] if cve else ""
                section += f"- **CVE**: {cve_id}\n"
            if cwe:
                cwe_id = cwe if isinstance(cwe, str) else cwe[0] if cwe else ""
                section += f"- **CWE**: {cwe_id}\n"

        return section

    def _generate_summary_report(self, findings: list[dict[str, Any]]) -> Path:
        """Generate summary report of all findings."""
        summary_path = self.reports_dir / "summary.md"

        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("info", {}).get("severity", "info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Sort findings by exploitability score
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get("triage", {}).get("exploitability_score", 0),
            reverse=True,
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
                emoji = severity_to_emoji(sev)
                content += f"- {emoji} **{sev.upper()}**: {count}\n"

        content += """
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
            emoji = severity_to_emoji(severity)

            content += f"""### {idx}. {emoji} {info.get("name", template_id)}

- **Severity**: {severity.upper()}
- **Target**: `{matched_at}`
- **Exploitability Score**: {exploit_score}/10

"""

        content += """
---

## Report Files

All individual finding reports are available in this directory. Each finding has been analyzed, scored, and includes proof-of-concept details and remediation recommendations.
"""

        summary_path.write_text(content, encoding="utf-8")
        return summary_path
