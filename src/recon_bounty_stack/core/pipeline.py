"""
Main Pipeline Orchestrator for Recon Bounty Stack.

Coordinates the execution of all scan stages: Recon → HTTP → Nuclei → Triage → Report
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger
from recon_bounty_stack.utils.legal import LegalAuthorizationShield


class PipelineStage:
    """Represents a single stage in the pipeline."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.completed = False
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.results: dict = {}

    @property
    def duration(self) -> float:
        """Get stage duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class Pipeline:
    """Main pipeline orchestrator for reconnaissance automation.

    This class coordinates the execution of all scan stages:
    1. Recon - Subdomain enumeration
    2. HTTP - Web endpoint probing
    3. Nuclei - Vulnerability scanning
    4. Triage - Finding prioritization
    5. Report - Report generation

    Example:
        pipeline = Pipeline()
        results = pipeline.run(targets=["example.com"])
    """

    STAGES = [
        PipelineStage("recon", "Subdomain Enumeration"),
        PipelineStage("httpx", "HTTP Endpoint Probing"),
        PipelineStage("nuclei", "Vulnerability Scanning"),
        PipelineStage("triage", "Finding Prioritization"),
        PipelineStage("report", "Report Generation"),
    ]

    def __init__(
        self,
        config: Config | None = None,
        output_dir: Path | None = None,
        dry_run: bool = False,
    ):
        """Initialize the pipeline.

        Args:
            config: Configuration object (loads from env if not provided)
            output_dir: Override output directory
            dry_run: If True, simulate operations without executing
        """
        self.config = config or Config.from_env()
        if output_dir:
            self.config.output_dir = output_dir
        self.dry_run = dry_run
        self.logger = get_logger("recon.pipeline")
        self.legal_shield = LegalAuthorizationShield(str(self.config.auth_dir))

        # Initialize stage tracking
        self.stages = [PipelineStage(s.name, s.description) for s in self.STAGES]
        self._stage_index = 0

        # Status file for resume functionality
        self._status_file = self.config.output_dir / ".pipeline_status"

    def _load_status(self) -> set:
        """Load completed stages from status file."""
        if not self._status_file.exists():
            return set()
        return set(self._status_file.read_text().strip().splitlines())

    def _mark_complete(self, stage: str) -> None:
        """Mark a stage as complete."""
        self._status_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._status_file, "a") as f:
            f.write(f"{stage}\n")

    def check_authorization(self, targets: list[str]) -> tuple[bool, list[str]]:
        """Check authorization for all targets.

        Args:
            targets: List of target domains

        Returns:
            Tuple of (all_authorized, list of unauthorized targets)
        """
        unauthorized = []
        for target in targets:
            authorized, reason, _ = self.legal_shield.check_authorization(target)
            if not authorized:
                unauthorized.append(target)
                self.logger.warning(f"Unauthorized target: {target} - {reason}")

        return len(unauthorized) == 0, unauthorized

    def run(
        self,
        targets: list[str],
        resume: bool = False,
        skip_auth: bool = False,
    ) -> dict[str, Any]:
        """Run the full reconnaissance pipeline.

        Args:
            targets: List of target domains to scan
            resume: Continue from last completed stage
            skip_auth: Skip authorization check (NOT RECOMMENDED)

        Returns:
            Dictionary containing results from all stages
        """
        self.config.ensure_directories()
        start_time = datetime.now()
        results: dict[str, Any] = {
            "start_time": start_time.isoformat(),
            "targets": targets,
            "stages": {},
            "summary": {},
        }

        self.logger.info("=" * 60)
        self.logger.info("Recon Bounty Stack - Pipeline Starting")
        self.logger.info("=" * 60)
        self.logger.info(f"Targets: {', '.join(targets)}")
        self.logger.info(f"Dry Run: {self.dry_run}")

        # Authorization check
        if not skip_auth:
            self.logger.info("")
            self.logger.info("⚖️  Legal Authorization Check")
            self.logger.info("=" * 60)
            authorized, unauthorized = self.check_authorization(targets)
            if not authorized:
                self.logger.error("❌ Authorization check failed!")
                self.logger.error(f"Unauthorized targets: {unauthorized}")
                results["error"] = "Authorization check failed"
                results["unauthorized_targets"] = unauthorized
                return results
            self.logger.info("✅ All targets authorized")

        # Load completed stages if resuming
        completed_stages = self._load_status() if resume else set()

        # Run each stage
        for stage in self.stages:
            if resume and stage.name in completed_stages:
                self.logger.info(f"⏭️  Skipping {stage.description} (already complete)")
                continue

            self.logger.info("")
            self.logger.info(f">>> Stage: {stage.description}")
            stage.start_time = datetime.now()

            try:
                if self.dry_run:
                    self.logger.info(f"[DRY RUN] Would execute {stage.name}")
                    stage.results = {"dry_run": True}
                else:
                    stage.results = self._run_stage(stage.name, targets)

                stage.completed = True
                stage.end_time = datetime.now()
                self._mark_complete(stage.name)

                self.logger.info(
                    f"✅ {stage.description} complete ({stage.duration:.1f}s)"
                )

            except Exception as e:
                stage.end_time = datetime.now()
                self.logger.error(f"❌ {stage.description} failed: {e}")
                stage.results = {"error": str(e)}

            results["stages"][stage.name] = {
                "completed": stage.completed,
                "duration": stage.duration,
                "results": stage.results,
            }

        # Generate summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = duration
        results["summary"] = self._generate_summary()

        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info("Pipeline Complete!")
        self.logger.info("=" * 60)
        self.logger.info(f"Duration: {duration:.1f}s")

        return results

    def _run_stage(self, stage_name: str, targets: list[str]) -> dict:
        """Run a specific pipeline stage.

        Args:
            stage_name: Name of the stage to run
            targets: List of targets

        Returns:
            Stage results dictionary
        """
        from recon_bounty_stack.agents import TriageAgent
        from recon_bounty_stack.reports import ReportGenerator
        from recon_bounty_stack.scanners import HttpxScanner, NucleiScanner, ReconScanner

        if stage_name == "recon":
            scanner = ReconScanner(config=self.config)
            return scanner.scan(targets)

        elif stage_name == "httpx":
            scanner = HttpxScanner(config=self.config)
            subs_file = self.config.output_dir / "subs.txt"
            if not subs_file.exists():
                return {"error": "No subdomains file found"}
            subdomains = subs_file.read_text().strip().splitlines()
            return scanner.scan(subdomains)

        elif stage_name == "nuclei":
            scanner = NucleiScanner(config=self.config)
            http_file = self.config.output_dir / "http.json"
            if not http_file.exists():
                return {"error": "No HTTP endpoints file found"}
            with open(http_file) as f:
                endpoints = json.load(f)
            urls = [e.get("url") for e in endpoints if e.get("url")]
            return scanner.scan(urls)

        elif stage_name == "triage":
            agent = TriageAgent(config=self.config)
            findings_file = self.config.output_dir / "nuclei-findings.json"
            if not findings_file.exists():
                return {"error": "No findings file found"}
            with open(findings_file) as f:
                findings = json.load(f)
            return agent.triage(findings)

        elif stage_name == "report":
            generator = ReportGenerator(config=self.config)
            triage_file = self.config.output_dir / "triage.json"
            if not triage_file.exists():
                return {"error": "No triage file found"}
            with open(triage_file) as f:
                findings = json.load(f)
            return generator.generate(findings)

        return {"error": f"Unknown stage: {stage_name}"}

    def _generate_summary(self) -> dict:
        """Generate pipeline summary statistics."""
        summary = {
            "stages_completed": sum(1 for s in self.stages if s.completed),
            "stages_total": len(self.stages),
        }

        # Read output files for statistics
        subs_file = self.config.output_dir / "subs.txt"
        if subs_file.exists():
            summary["subdomains"] = len(subs_file.read_text().strip().splitlines())

        http_file = self.config.output_dir / "http.json"
        if http_file.exists():
            try:
                with open(http_file) as f:
                    summary["http_endpoints"] = len(json.load(f))
            except (json.JSONDecodeError, OSError):
                pass

        findings_file = self.config.output_dir / "nuclei-findings.json"
        if findings_file.exists():
            try:
                with open(findings_file) as f:
                    summary["raw_findings"] = len(json.load(f))
            except (json.JSONDecodeError, OSError):
                pass

        triage_file = self.config.output_dir / "triage.json"
        if triage_file.exists():
            try:
                with open(triage_file) as f:
                    findings = json.load(f)
                    summary["triaged_findings"] = len(findings)
                    # Count by severity
                    for finding in findings:
                        sev = finding.get("info", {}).get("severity", "unknown")
                        key = f"severity_{sev}"
                        summary[key] = summary.get(key, 0) + 1
            except (json.JSONDecodeError, OSError):
                pass

        return summary

    def status(self) -> dict:
        """Get current pipeline status.

        Returns:
            Dictionary with status information
        """
        completed = self._load_status()
        return {
            "stages": [
                {
                    "name": s.name,
                    "description": s.description,
                    "completed": s.name in completed,
                }
                for s in self.stages
            ],
            "summary": self._generate_summary(),
        }

    def reset(self) -> None:
        """Reset pipeline status (for re-running from scratch)."""
        if self._status_file.exists():
            self._status_file.unlink()
        self.logger.info("Pipeline status reset")
