"""
HTTP Scanner for web endpoint probing.

Uses httpx to probe discovered subdomains and identify
live web endpoints with technology detection.
"""

import json
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.scanners.base import BaseScanner


class HttpxScanner(BaseScanner):
    """Scanner for HTTP endpoint probing.

    Uses httpx to:
    - Probe live web endpoints
    - Detect technologies
    - Extract response metadata

    Example:
        scanner = HttpxScanner()
        results = scanner.scan(["sub1.example.com", "sub2.example.com"])
        print(f"Found {len(results['endpoints'])} live endpoints")
    """

    def __init__(self, config: Config | None = None):
        """Initialize the HTTP scanner.

        Args:
            config: Configuration object
        """
        super().__init__(config=config, tool_name="httpx")

    def scan(self, targets: list[str]) -> dict[str, Any]:
        """Probe HTTP endpoints for the given targets.

        Args:
            targets: List of subdomains/hosts to probe

        Returns:
            Dictionary containing:
                - endpoints: List of live HTTP endpoints
                - count: Number of endpoints found
                - https_count: Number of HTTPS endpoints
        """
        if not targets:
            self.logger.warning("No targets provided for HTTP probing")
            return {"endpoints": [], "count": 0, "https_count": 0}

        self.logger.info(f"Starting HTTP probing for {len(targets)} target(s)")

        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Write targets to file
        targets_file = self.write_temp_file("\n".join(targets), "temp_httpx_targets.txt")

        # Output files
        temp_output = self.config.output_dir / "temp_httpx.json"
        final_output = self.config.output_dir / "http.json"

        # Run httpx
        try:
            httpx_path = self.config.tools.httpx
            cmd = [
                httpx_path,
                "-l", str(targets_file),
                "-probe",
                "-tech-detect",
                "-status-code",
                "-title",
                "-json",
                "-silent",
                "-rate-limit", str(self.config.scan.rate_limit),
                "-threads", str(self.config.scan.threads),
                "-timeout", "10",
                "-retries", str(self.config.scan.retries),
                "-follow-redirects",
                "-o", str(temp_output),
            ]
            self.run_command(cmd, timeout=self.config.scan.timeout)

        except Exception as e:
            self.logger.error(f"httpx failed: {e}")
            self.cleanup_temp_files(targets_file, temp_output)
            return {"endpoints": [], "count": 0, "error": str(e)}

        # Parse NDJSON output
        endpoints = []
        if temp_output.exists() and temp_output.stat().st_size > 0:
            with open(temp_output, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            endpoints.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        # Write as JSON array
        with open(final_output, "w", encoding="utf-8") as f:
            json.dump(endpoints, f, indent=2, ensure_ascii=False)

        # Calculate statistics
        https_count = sum(1 for e in endpoints if e.get("url", "").startswith("https://"))
        status_200 = sum(1 for e in endpoints if e.get("status-code") == 200)

        self.logger.info(f"Found {len(endpoints)} live HTTP endpoints")
        self.logger.info(f"  - HTTPS: {https_count}")
        self.logger.info(f"  - Status 200: {status_200}")

        # Cleanup temp files
        self.cleanup_temp_files(targets_file, temp_output)

        return {
            "endpoints": endpoints,
            "count": len(endpoints),
            "https_count": https_count,
            "status_200_count": status_200,
            "output_file": str(final_output),
        }
