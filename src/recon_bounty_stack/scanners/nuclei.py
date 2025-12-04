"""
Nuclei Scanner for vulnerability detection.

Uses Nuclei to scan web endpoints for known vulnerabilities
with template-based detection.
"""

import json
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.scanners.base import BaseScanner


class NucleiScanner(BaseScanner):
    """Scanner for vulnerability detection using Nuclei.

    Uses Nuclei to:
    - Scan for known CVEs
    - Detect misconfigurations
    - Find security issues

    Example:
        scanner = NucleiScanner()
        results = scanner.scan(["https://example.com"])
        print(f"Found {len(results['findings'])} vulnerabilities")
    """

    def __init__(self, config: Config | None = None):
        """Initialize the Nuclei scanner.

        Args:
            config: Configuration object
        """
        super().__init__(config=config, tool_name="nuclei")

    def scan(self, targets: list[str]) -> dict[str, Any]:
        """Scan targets for vulnerabilities.

        Args:
            targets: List of URLs to scan

        Returns:
            Dictionary containing:
                - findings: List of vulnerability findings
                - count: Total number of findings
                - severity_counts: Count by severity level
        """
        if not targets:
            self.logger.warning("No targets provided for vulnerability scanning")
            return {"findings": [], "count": 0, "severity_counts": {}}

        self.logger.info(f"Starting vulnerability scan for {len(targets)} target(s)")

        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Write targets to file
        targets_file = self.write_temp_file("\n".join(targets), "temp_nuclei_targets.txt")

        # Output file
        temp_output = self.config.output_dir / "temp_nuclei.json"
        final_output = self.config.output_dir / "nuclei-findings.json"

        # Update templates (best effort)
        self._update_templates()

        # Run Nuclei
        try:
            nuclei_path = self.config.tools.nuclei
            cmd = [
                nuclei_path,
                "-l", str(targets_file),
                "-json",
                "-o", str(temp_output),
                "-rate-limit", str(self.config.scan.rate_limit),
                "-concurrency", str(self.config.scan.threads),
                "-timeout", str(self.config.scan.timeout // 60),  # Convert to minutes
                "-retries", str(self.config.scan.retries),
                "-severity", self.config.scan.severity_filter,
                "-exclude-tags", "dos,fuzzing,malware",
                "-silent",
                "-follow-redirects",
            ]
            self.run_command(cmd, timeout=self.config.scan.timeout)

        except Exception as e:
            self.logger.error(f"Nuclei failed: {e}")
            self.cleanup_temp_files(targets_file, temp_output)
            return {"findings": [], "count": 0, "error": str(e)}

        # Parse NDJSON output
        findings = []
        if temp_output.exists() and temp_output.stat().st_size > 0:
            with open(temp_output, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        # Write as JSON array
        with open(final_output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)

        # Calculate severity counts
        severity_counts = {}
        for finding in findings:
            sev = finding.get("info", {}).get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        self.logger.info(f"Found {len(findings)} vulnerabilities")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                self.logger.info(f"  - {sev.capitalize()}: {count}")

        # Cleanup temp files
        self.cleanup_temp_files(targets_file, temp_output)

        return {
            "findings": findings,
            "count": len(findings),
            "severity_counts": severity_counts,
            "output_file": str(final_output),
        }

    def _update_templates(self) -> None:
        """Update Nuclei templates (best effort)."""
        try:
            nuclei_path = self.config.tools.nuclei
            self.run_command(
                [nuclei_path, "-update-templates", "-silent"],
                timeout=300,
            )
            self.logger.debug("Templates updated")
        except Exception as e:
            self.logger.debug(f"Template update failed: {e}")
