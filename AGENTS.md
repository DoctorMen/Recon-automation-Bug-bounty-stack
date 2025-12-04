<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
## Multi-Agent Roles and Mappings

This repository supports a team-of-agents model to coordinate recon automation. The following roles are defined in `agents.json` and mapped to existing scripts.

- **Strategist (gpt-5)**: Plans workflow, task sequencing, and validates logic
  - Primary entrypoints: `run_pipeline.py`, `scripts/run_pipeline.sh`
  - Inputs/outputs: `targets.txt` → `output/*`
  - Team categories: Product Management, Business Strategy

- **Executor (gpt-5)**: Runs commands, validates syntax, handles deployments
  - Full run: `python3 run_pipeline.py` or `./scripts/run_pipeline.sh`
  - Direct stages: `./scripts/run_recon.sh`, `./scripts/run_httpx.sh`, `./scripts/run_nuclei.sh`
  - Utilities: `scripts/scan_monitor.py`, `process_all.py`
  - Team categories: Full-Stack Engineering, DevOps

- **Composer 1 — Automation Engineer (composer)**: Maintains recon and post-scan flows
  - Recon core: `scripts/run_recon.sh`
  - Post-scan: `scripts/post_scan_processor.sh`, `scripts/process_nuclei_results.sh`
  - Bootstrap: `scripts/auto_install_and_run.sh`, `install.sh`
  - Team categories: Platform Engineering, Release Engineering

- **Composer 2 — Parallelization & Optimization (composer)**: Concurrency and throughput
  - Parallel setup: `scripts/parallel_setup.py`, `scripts/run_parallel_setup.sh`
  - Monitoring: `scripts/scan_monitor.py`
  - Team categories: Performance Engineering, Data Engineering

- **Composer 3 — Documentation & Reporting (composer)**: Docs and analytics
  - Reports: `scripts/generate_report.py`, `SCAN_SUMMARY.md`, `output/reports/summary.md`
  - Docs: `README.md`, `README_PROCESS_RESULTS.md`, `README_WINDOWS.md`
  - Team categories: Content Design, Analytics

- **Composer 4 — CI/CD & Security Ops (composer)**: CI workflows and hardening
  - CI: `ci/cursor-ci.yml`
  - Workflows helpers: `workflows/run_program.sh`
  - Team categories: DevOps, Product Security

- **Divergent Thinker (gpt-5)**: Creative exploration and alternative approaches
  - Engine: `DIVERGENT_THINKING_ENGINE.py`
  - Integration: `DIVERGENT_THINKING_INTEGRATION.py`
  - Documentation: `DIVERGENT_THINKING_EXPLAINED.md`
  - 7 Thinking Modes: lateral, parallel, associative, generative, combinatorial, perspective, constraint-free
  - Team categories: Offensive Security, Bug Bounty

### Orchestrator (optional)

Use the orchestrator to trigger common tasks by role:

```bash
python3 scripts/agent_orchestrator.py --list
python3 scripts/agent_orchestrator.py --role Strategist --task plan
python3 scripts/agent_orchestrator.py --role "Composer 1 — Automation Engineer" --task recon
python3 scripts/agent_orchestrator.py --role Executor --task full-run
```

Tasks are routed to the appropriate scripts and will surface helpful errors if a dependency or file is missing.

---

## Team Organization Taxonomy

For the complete team organization taxonomy including all team names and aliases, see [`TEAM_TAXONOMY.md`](TEAM_TAXONOMY.md).

The taxonomy covers the following domains:

| Domain | Teams |
|--------|-------|
| Product & Strategy | Product Management, Business Strategy, Corporate Development |
| Engineering | Frontend, Mobile, Backend, Full-Stack Engineering |
| Platform & Infrastructure | Platform Engineering, DevOps, Developer Experience, Release Engineering |
| Data & Analytics | Data Engineering, Analytics, Data Science, ML Engineering, Experimentation Platform |
| Security | Product Security, Offensive Security, Bug Bounty, Cloud Security, IAM, SOC, GRC, Privacy Engineering |
| Quality & Performance | Quality Assurance, Performance Engineering |
| Design & Research | UX Design, UX Research, Content Design |
| Customer & Support | Customer Support, Support Engineering, Solutions Engineering |
| Business Operations | Legal, Marketing, Revenue Operations |

---

## Governance & Training

### HR & Talent Management
- **[Agent Skill Requirements](AGENT_SKILL_REQUIREMENTS.md)**: Formal skill requirements, competencies, and qualifications for each agent role

### Change Management & Governance
- **[Change Management Policy](CHANGE_MANAGEMENT.md)**: Formal change control procedures, approval workflows, and deployment guidelines

### Compliance
- **[Compliance Framework Mapping](COMPLIANCE_MAPPING.md)**: SOC 2, ISO 27001, NIST CSF, and GDPR compliance mappings

### Training & Certification
- **[Operator Certification Program](OPERATOR_CERTIFICATION.md)**: Three-level certification path for system operators


