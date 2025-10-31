## Multi-Agent Roles and Mappings

This repository supports a team-of-agents model to coordinate recon automation. The following roles are defined in `agents.json` and mapped to existing scripts.

- **Strategist (gpt-5)**: Plans workflow, task sequencing, and validates logic
  - Primary entrypoints: `run_pipeline.py`, `scripts/run_pipeline.sh`
  - Inputs/outputs: `targets.txt` → `output/*`

- **Executor (gpt-5)**: Runs commands, validates syntax, handles deployments
  - Full run: `python3 run_pipeline.py` or `./scripts/run_pipeline.sh`
  - Direct stages: `./scripts/run_recon.sh`, `./scripts/run_httpx.sh`, `./scripts/run_nuclei.sh`
  - Utilities: `scripts/scan_monitor.py`, `process_all.py`

- **Composer 1 — Automation Engineer (composer)**: Maintains recon and post-scan flows
  - Recon core: `scripts/run_recon.sh`
  - Post-scan: `scripts/post_scan_processor.sh`, `scripts/process_nuclei_results.sh`
  - Bootstrap: `scripts/auto_install_and_run.sh`, `install.sh`

- **Composer 2 — Parallelization & Optimization (composer)**: Concurrency and throughput
  - Parallel setup: `scripts/parallel_setup.py`, `scripts/run_parallel_setup.sh`
  - Monitoring: `scripts/scan_monitor.py`

- **Composer 3 — Documentation & Reporting (composer)**: Docs and analytics
  - Reports: `scripts/generate_report.py`, `SCAN_SUMMARY.md`, `output/reports/summary.md`
  - Docs: `README.md`, `README_PROCESS_RESULTS.md`, `README_WINDOWS.md`

- **Composer 4 — CI/CD & Security Ops (composer)**: CI workflows and hardening
  - CI: `ci/cursor-ci.yml`
  - Workflows helpers: `workflows/run_program.sh`

### Orchestrator (optional)

Use the orchestrator to trigger common tasks by role:

```bash
python3 scripts/agent_orchestrator.py --list
python3 scripts/agent_orchestrator.py --role Strategist --task plan
python3 scripts/agent_orchestrator.py --role "Composer 1 — Automation Engineer" --task recon
python3 scripts/agent_orchestrator.py --role Executor --task full-run
```

Tasks are routed to the appropriate scripts and will surface helpful errors if a dependency or file is missing.


