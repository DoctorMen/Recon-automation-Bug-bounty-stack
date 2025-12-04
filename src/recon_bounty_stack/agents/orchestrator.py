"""
Agent Orchestrator for coordinating multi-agent workflows.

Manages the execution of different agent roles based on configuration.
"""

import json
from pathlib import Path

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger


class AgentOrchestrator:
    """Orchestrates multi-agent workflows.

    Coordinates different agent roles:
    - Strategist: Planning and task sequencing
    - Executor: Running scans and commands
    - Composer: Automation and optimization
    - Reporter: Documentation and reporting

    Example:
        orchestrator = AgentOrchestrator()
        orchestrator.run_task("Strategist", "plan")
    """

    ROLE_TASKS = {
        "Strategist": ["plan", "pipeline"],
        "Executor": ["full-run", "recon", "httpx", "nuclei"],
        "Composer 1 — Automation Engineer": ["recon", "post-scan"],
        "Composer 2 — Parallelization & Optimization": ["parallel-setup", "monitor"],
        "Composer 3 — Documentation & Reporting": ["reports", "summary"],
        "Composer 4 — CI/CD & Security Ops": ["ci-check"],
    }

    def __init__(self, config: Config | None = None, repo_root: Path | None = None):
        """Initialize the orchestrator.

        Args:
            config: Configuration object
            repo_root: Repository root directory
        """
        self.config = config or Config.from_env()
        self.repo_root = repo_root or Path.cwd()
        self.logger = get_logger("recon.orchestrator")

    def list_roles(self) -> dict[str, list[str]]:
        """List available roles and their tasks.

        Returns:
            Dictionary mapping role names to available tasks
        """
        return self.ROLE_TASKS.copy()

    def run_task(self, role: str, task: str) -> int:
        """Run a task for a specific role.

        Args:
            role: Role name
            task: Task name

        Returns:
            Exit code (0 for success)
        """
        if role not in self.ROLE_TASKS:
            self.logger.error(f"Unknown role: {role}")
            return 2

        if task not in self.ROLE_TASKS[role]:
            self.logger.error(f"Unknown task '{task}' for role '{role}'")
            return 2

        self.logger.info(f"Running task '{task}' for role '{role}'")

        # Dispatch to appropriate handler
        if role == "Strategist":
            return self._strategist_task(task)
        elif role == "Executor":
            return self._executor_task(task)
        elif role.startswith("Composer 1"):
            return self._composer1_task(task)
        elif role.startswith("Composer 2"):
            return self._composer2_task(task)
        elif role.startswith("Composer 3"):
            return self._composer3_task(task)
        elif role.startswith("Composer 4"):
            return self._composer4_task(task)

        return 2

    def _strategist_task(self, task: str) -> int:
        """Handle Strategist tasks."""
        if task == "plan":
            self.logger.info("Strategist plan:")
            self.logger.info("- Validate targets")
            self.logger.info("- Run pipeline")
            self.logger.info("- Review outputs and reports")
            self.logger.info("Suggested sequencing: recon → httpx → nuclei → triage → report")
            return 0
        elif task == "pipeline":
            from recon_bounty_stack.core.pipeline import Pipeline
            pipeline = Pipeline(config=self.config)
            # Would need targets from file
            targets_file = self.repo_root / "targets.txt"
            if targets_file.exists():
                targets = targets_file.read_text().strip().splitlines()
                targets = [t for t in targets if t and not t.startswith("#")]
                pipeline.run(targets)
                return 0
            else:
                self.logger.error("No targets.txt found")
                return 1
        return 2

    def _executor_task(self, task: str) -> int:
        """Handle Executor tasks."""
        from recon_bounty_stack.core.pipeline import Pipeline
        pipeline = Pipeline(config=self.config)

        if task == "full-run":
            targets_file = self.repo_root / "targets.txt"
            if targets_file.exists():
                targets = targets_file.read_text().strip().splitlines()
                targets = [t for t in targets if t and not t.startswith("#")]
                pipeline.run(targets)
                return 0
            return 1
        elif task == "recon":
            from recon_bounty_stack.scanners import ReconScanner
            scanner = ReconScanner(config=self.config)
            targets_file = self.repo_root / "targets.txt"
            if targets_file.exists():
                targets = targets_file.read_text().strip().splitlines()
                targets = [t for t in targets if t and not t.startswith("#")]
                scanner.scan(targets)
                return 0
            return 1
        elif task in ["httpx", "nuclei"]:
            self.logger.info(f"Running {task} stage...")
            return 0
        return 2

    def _composer1_task(self, task: str) -> int:
        """Handle Composer 1 (Automation Engineer) tasks."""
        if task == "recon":
            return self._executor_task("recon")
        elif task == "post-scan":
            self.logger.info("Running post-scan processing...")
            return 0
        return 2

    def _composer2_task(self, task: str) -> int:
        """Handle Composer 2 (Parallelization) tasks."""
        if task == "parallel-setup":
            self.logger.info("Setting up parallel processing...")
            return 0
        elif task == "monitor":
            self.logger.info("Starting scan monitor...")
            return 0
        return 2

    def _composer3_task(self, task: str) -> int:
        """Handle Composer 3 (Documentation) tasks."""
        if task == "reports":
            from recon_bounty_stack.reports import ReportGenerator
            generator = ReportGenerator(config=self.config)
            triage_file = self.config.output_dir / "triage.json"
            if triage_file.exists():
                with open(triage_file) as f:
                    findings = json.load(f)
                generator.generate(findings)
                return 0
            self.logger.error("No triage.json found")
            return 1
        elif task == "summary":
            summary_file = self.config.output_dir / "reports" / "summary.md"
            if summary_file.exists():
                print(summary_file.read_text(encoding="utf-8"))
                return 0
            self.logger.error("No summary.md found")
            return 1
        return 2

    def _composer4_task(self, task: str) -> int:
        """Handle Composer 4 (CI/CD) tasks."""
        if task == "ci-check":
            ci_file = self.repo_root / ".github" / "workflows" / "ci.yml"
            if ci_file.exists():
                self.logger.info("CI workflow file present")
                return 0
            self.logger.warning("No CI workflow file found")
            return 1
        return 2
