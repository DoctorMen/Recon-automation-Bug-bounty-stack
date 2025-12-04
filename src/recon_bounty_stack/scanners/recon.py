"""
Reconnaissance Scanner for subdomain enumeration.

Uses Subfinder and optionally Amass to enumerate subdomains,
with DNSx validation for live host verification.
"""

import subprocess
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.scanners.base import BaseScanner


class ReconScanner(BaseScanner):
    """Scanner for subdomain enumeration.

    Uses multiple tools:
    - Subfinder: Fast passive subdomain enumeration
    - Amass: Comprehensive subdomain enumeration (optional)
    - DNSx: DNS validation for live hosts

    Example:
        scanner = ReconScanner()
        results = scanner.scan(["example.com"])
        print(f"Found {len(results['subdomains'])} subdomains")
    """

    def __init__(self, config: Config | None = None):
        """Initialize the recon scanner.

        Args:
            config: Configuration object
        """
        super().__init__(config=config, tool_name="subfinder")

    def scan(self, targets: list[str]) -> dict[str, Any]:
        """Enumerate subdomains for the given targets.

        Args:
            targets: List of domain names to scan

        Returns:
            Dictionary containing:
                - subdomains: List of discovered subdomains
                - count: Number of subdomains found
                - validated: Number of validated (live) subdomains
        """
        self.logger.info(f"Starting subdomain enumeration for {len(targets)} target(s)")

        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Write targets to file
        targets_file = self.write_temp_file("\n".join(targets), "temp_targets.txt")

        # Output files
        subfinder_output = self.config.output_dir / "temp_subfinder.txt"
        amass_output = self.config.output_dir / "temp_amass.txt"
        final_output = self.config.output_dir / "subs.txt"

        all_subdomains = set()

        # Run Subfinder
        try:
            self.logger.info("Running Subfinder...")
            subfinder_path = self.config.tools.subfinder
            cmd = [
                subfinder_path,
                "-dL", str(targets_file),
                "-silent",
                "-o", str(subfinder_output),
                "-t", str(self.config.scan.threads),
                "-all",
            ]
            self.run_command(cmd, timeout=self.config.scan.timeout)

            if subfinder_output.exists():
                subs = subfinder_output.read_text(encoding="utf-8").strip().splitlines()
                all_subdomains.update(s for s in subs if s)
                self.logger.info(f"Subfinder found {len(subs)} subdomains")
        except subprocess.TimeoutExpired:
            self.logger.warning("Subfinder timed out")
        except Exception as e:
            self.logger.warning(f"Subfinder error: {e}")

        # Run Amass (optional)
        if self._check_amass():
            try:
                self.logger.info("Running Amass...")
                amass_path = self.config.tools.amass
                cmd = [
                    amass_path,
                    "enum",
                    "-passive",
                    "-df", str(targets_file),
                    "-o", str(amass_output),
                ]
                self.run_command(cmd, timeout=self.config.scan.timeout)

                if amass_output.exists():
                    subs = amass_output.read_text(encoding="utf-8").strip().splitlines()
                    all_subdomains.update(s for s in subs if s)
                    self.logger.info(f"Amass found {len(subs)} subdomains")
            except subprocess.TimeoutExpired:
                self.logger.warning("Amass timed out")
            except Exception as e:
                self.logger.warning(f"Amass error: {e}")
        else:
            self.logger.info("Amass not available, skipping")

        # Deduplicate and sort
        unique_subdomains = sorted(all_subdomains)
        self.logger.info(f"Total unique subdomains: {len(unique_subdomains)}")

        # Write combined results
        final_output.write_text("\n".join(unique_subdomains), encoding="utf-8")

        # Cleanup temp files
        self.cleanup_temp_files(
            targets_file,
            subfinder_output,
            amass_output,
        )

        return {
            "subdomains": unique_subdomains,
            "count": len(unique_subdomains),
            "output_file": str(final_output),
        }

    def _check_amass(self) -> bool:
        """Check if Amass is available."""
        import shutil
        amass_path = self.config.tools.amass
        return shutil.which(amass_path) is not None
