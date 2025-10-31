#!/usr/bin/env python3
"""
Agent Orchestrator
Runs repository tasks by agent role and task name, delegating to existing scripts.

Examples:
  python3 scripts/agent_orchestrator.py --list
  python3 scripts/agent_orchestrator.py --role Strategist --task plan
  python3 scripts/agent_orchestrator.py --role "Composer 1 — Automation Engineer" --task recon
  python3 scripts/agent_orchestrator.py --role Executor --task full-run
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_agents_config() -> Dict:
    config_path = REPO_ROOT / "agents.json"
    if not config_path.exists():
        raise FileNotFoundError(f"agents.json not found at {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_cmd(cmd: list[str], cwd: Optional[Path] = None) -> int:
    print(f"$ {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=str(cwd or REPO_ROOT))
        return result.returncode
    except FileNotFoundError:
        print("ERROR: Command not found. Ensure required tools are installed.")
        return 127


def has_file(path: str) -> bool:
    return (REPO_ROOT / path).exists()


def task_strategist(task: str) -> int:
    if task == "plan":
        targets = REPO_ROOT / "targets.txt"
        print("Strategist plan:\n- Validate targets.txt\n- Run pipeline\n- Review outputs and reports")
        if not targets.exists():
            print(f"WARNING: {targets} not found")
        print("Suggested sequencing: recon → httpx → nuclei → triage → report")
        return 0
    if task == "pipeline":
        if os.name == "nt" and has_file("run_pipeline.py"):
            return run_cmd([sys.executable, "run_pipeline.py"])
        if has_file("scripts/run_pipeline.sh"):
            return run_cmd(["bash", "scripts/run_pipeline.sh"])
        return run_cmd([sys.executable, "run_pipeline.py"]) if has_file("run_pipeline.py") else 1
    print("Unknown Strategist task. Use: plan | pipeline")
    return 2


def task_executor(task: str) -> int:
    if task == "full-run":
        if has_file("scripts/run_pipeline.sh"):
            return run_cmd(["bash", "scripts/run_pipeline.sh"])
        return run_cmd([sys.executable, "run_pipeline.py"]) if has_file("run_pipeline.py") else 1
    if task == "recon":
        return run_cmd(["bash", "scripts/run_recon.sh"]) if has_file("scripts/run_recon.sh") else 1
    if task == "httpx":
        return run_cmd(["bash", "scripts/run_httpx.sh"]) if has_file("scripts/run_httpx.sh") else 1
    if task == "nuclei":
        return run_cmd(["bash", "scripts/run_nuclei.sh"]) if has_file("scripts/run_nuclei.sh") else 1
    print("Unknown Executor task. Use: full-run | recon | httpx | nuclei")
    return 2


def task_composer1(task: str) -> int:
    if task == "recon":
        return run_cmd(["bash", "scripts/run_recon.sh"]) if has_file("scripts/run_recon.sh") else 1
    if task == "post-scan":
        return run_cmd(["bash", "scripts/post_scan_processor.sh"]) if has_file("scripts/post_scan_processor.sh") else 1
    print("Unknown Composer 1 task. Use: recon | post-scan")
    return 2


def task_composer2(task: str) -> int:
    if task == "parallel-setup":
        return run_cmd([sys.executable, "scripts/parallel_setup.py"]) if has_file("scripts/parallel_setup.py") else 1
    if task == "monitor":
        return run_cmd([sys.executable, "scripts/scan_monitor.py"]) if has_file("scripts/scan_monitor.py") else 1
    print("Unknown Composer 2 task. Use: parallel-setup | monitor")
    return 2


def task_composer3(task: str) -> int:
    if task == "reports":
        return run_cmd([sys.executable, "scripts/generate_report.py"]) if has_file("scripts/generate_report.py") else 1
    if task == "summary":
        summary = REPO_ROOT / "output" / "reports" / "summary.md"
        if summary.exists():
            print(summary.read_text(encoding="utf-8"))
            return 0
        print("No summary.md found. Run reports first.")
        return 1
    print("Unknown Composer 3 task. Use: reports | summary")
    return 2


def task_composer4(task: str) -> int:
    if task == "ci-check":
        path = REPO_ROOT / "ci" / "cursor-ci.yml"
        if not path.exists():
            print("ERROR: ci/cursor-ci.yml not found")
            return 1
        print("ci/cursor-ci.yml present. Validate with GitHub Actions UI.")
        return 0
    print("Unknown Composer 4 task. Use: ci-check")
    return 2


ROLE_DISPATCH: Dict[str, Callable[[str], int]] = {
    "Strategist": task_strategist,
    "Executor": task_executor,
    "Composer 1 — Automation Engineer": task_composer1,
    "Composer 2 — Parallelization & Optimization": task_composer2,
    "Composer 3 — Documentation & Reporting": task_composer3,
    "Composer 4 — CI/CD & Security Ops": task_composer4,
}


def list_roles() -> None:
    config = load_agents_config()
    agents = config.get("agents", [])
    print("Available roles and tasks:")
    for a in agents:
        name = a.get("name")
        if name in ROLE_DISPATCH:
            if name == "Strategist":
                tasks = ["plan", "pipeline"]
            elif name == "Executor":
                tasks = ["full-run", "recon", "httpx", "nuclei"]
            elif name.startswith("Composer 1"):
                tasks = ["recon", "post-scan"]
            elif name.startswith("Composer 2"):
                tasks = ["parallel-setup", "monitor"]
            elif name.startswith("Composer 3"):
                tasks = ["reports", "summary"]
            elif name.startswith("Composer 4"):
                tasks = ["ci-check"]
            else:
                tasks = []
            print(f"- {name}: {', '.join(tasks)}")
        else:
            print(f"- {name}: (no dispatcher)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run tasks by agent role")
    parser.add_argument("--role", help="Agent role name (as in agents.json)")
    parser.add_argument("--task", help="Task name for the role")
    parser.add_argument("--list", action="store_true", help="List roles and tasks")
    args = parser.parse_args()

    if args.list or (not args.role and not args.task):
        list_roles()
        return 0

    if args.role not in ROLE_DISPATCH:
        print(f"Unknown role: {args.role}")
        list_roles()
        return 2

    if not args.task:
        print("Missing --task")
        list_roles()
        return 2

    return ROLE_DISPATCH[args.role](args.task)


if __name__ == "__main__":
    sys.exit(main())


