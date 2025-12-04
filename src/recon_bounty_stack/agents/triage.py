"""
Triage Agent for finding prioritization and filtering.

Scores and prioritizes vulnerability findings based on
severity, exploitability, and relevance.
"""

import json
import re
from datetime import datetime
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger


class TriageAgent:
    """Agent for triaging and prioritizing vulnerability findings.

    Features:
    - False positive filtering
    - Exploitability scoring
    - CVSS score extraction
    - Finding deduplication

    Example:
        agent = TriageAgent()
        triaged = agent.triage(findings)
    """

    SEVERITY_SCORES = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    SEVERITY_PRIORITY = ["critical", "high", "medium", "low", "info"]

    FP_INDICATORS = [
        r"test\.example\.com",
        r"localhost",
        r"127\.0\.0\.1",
        r"example\.com",
    ]

    def __init__(self, config: Config | None = None):
        """Initialize the triage agent.

        Args:
            config: Configuration object
        """
        self.config = config or Config.from_env()
        self.logger = get_logger("recon.triage")

    def triage(
        self,
        findings: list[dict[str, Any]],
        min_severity: str = "medium",
    ) -> dict[str, Any]:
        """Triage and prioritize findings.

        Args:
            findings: List of vulnerability findings
            min_severity: Minimum severity to include

        Returns:
            Dictionary containing:
                - findings: Triaged findings list
                - count: Number of triaged findings
                - summary: Severity breakdown
        """
        self.logger.info(f"Starting triage for {len(findings)} findings")

        # Filter by minimum severity
        if min_severity in self.SEVERITY_PRIORITY:
            min_idx = self.SEVERITY_PRIORITY.index(min_severity)
            allowed = self.SEVERITY_PRIORITY[: min_idx + 1]
            filtered = [
                f
                for f in findings
                if f.get("info", {}).get("severity", "info").lower() in allowed
            ]
            self.logger.info(
                f"Filtered to {len(filtered)} findings ({min_severity}+ severity)"
            )
            findings = filtered

        # Deduplicate
        findings = self._deduplicate(findings)
        self.logger.info(f"After deduplication: {len(findings)} findings")

        # Process and score each finding
        triaged = []
        fp_count = 0

        for finding in findings:
            # Skip false positives
            if self._is_false_positive(finding):
                fp_count += 1
                continue

            # Add triage data
            triaged_finding = finding.copy()
            triaged_finding["triage"] = {
                "exploitability_score": self._calculate_exploitability(finding),
                "cvss_score": self._extract_cvss(finding),
                "triaged_at": datetime.now().isoformat(),
                "priority": self._calculate_priority(finding),
            }
            triaged.append(triaged_finding)

        if fp_count > 0:
            self.logger.info(f"Filtered {fp_count} potential false positives")

        # Sort by exploitability score
        triaged.sort(
            key=lambda x: (
                x["triage"]["exploitability_score"],
                x["triage"]["cvss_score"],
            ),
            reverse=True,
        )

        # Write output
        output_file = self.config.output_dir / "triage.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(triaged, f, indent=2, ensure_ascii=False)

        # Generate summary
        summary = self._generate_summary(triaged)

        self.logger.info(f"Triage complete: {len(triaged)} findings")
        for sev, count in summary.items():
            if count > 0:
                self.logger.info(f"  - {sev.capitalize()}: {count}")

        return {
            "findings": triaged,
            "count": len(triaged),
            "summary": summary,
            "output_file": str(output_file),
        }

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            template_id = finding.get("template-id", "")
            matched_at = finding.get("matched-at", finding.get("host", ""))
            key = f"{template_id}:{matched_at}"

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _is_false_positive(self, finding: dict) -> bool:
        """Check if finding might be a false positive."""
        url = finding.get("matched-at", finding.get("host", ""))
        description = finding.get("info", {}).get("description", "")

        for indicator in self.FP_INDICATORS:
            if re.search(indicator, url, re.IGNORECASE):
                return True
            if re.search(indicator, description, re.IGNORECASE):
                return True

        return False

    def _calculate_exploitability(self, finding: dict) -> int:
        """Calculate exploitability score (1-10)."""
        score = 0
        info = finding.get("info", {})

        # Base score from severity
        severity = info.get("severity", "info").lower()
        score += self.SEVERITY_SCORES.get(severity, 1)

        # Bonus for verified findings
        if info.get("verified", False):
            score += 2

        # Bonus for CVE references
        if info.get("cve-id"):
            score += 1
            if isinstance(info.get("cve-id"), list) and len(info.get("cve-id", [])) > 1:
                score += 1

        # Bonus for CWE references
        if info.get("cwe-id"):
            score += 1

        # Bonus for exploit references
        reference = info.get("reference", [])
        if reference:
            ref_str = " ".join(reference if isinstance(reference, list) else [reference]).lower()
            if any(x in ref_str for x in ["exploit", "poc", "proof-of-concept"]):
                score += 1

        # Penalty for info-level
        if severity == "info":
            score = max(1, score - 1)

        return min(score, 10)

    def _extract_cvss(self, finding: dict) -> float:
        """Extract or estimate CVSS score."""
        info = finding.get("info", {})

        # If CVSS provided
        classification = info.get("classification", {})
        if classification and "cvss-score" in classification:
            return float(classification["cvss-score"])

        # Estimate from severity
        severity = info.get("severity", "info").lower()
        cvss_map = {
            "info": 0.0,
            "low": 3.0,
            "medium": 5.0,
            "high": 7.5,
            "critical": 9.5,
        }
        return cvss_map.get(severity, 0.0)

    def _calculate_priority(self, finding: dict) -> str:
        """Calculate priority level."""
        score = self._calculate_exploitability(finding)
        if score >= 7:
            return "high"
        elif score >= 4:
            return "medium"
        return "low"

    def _generate_summary(self, findings: list[dict]) -> dict[str, int]:
        """Generate severity breakdown summary."""
        summary = {}
        for finding in findings:
            sev = finding.get("info", {}).get("severity", "unknown").lower()
            summary[sev] = summary.get(sev, 0) + 1
        return summary
