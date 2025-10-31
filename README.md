# Recon-automation-Bug-bounty-stack

Local recon toolchain and automation for authorized security testing.

- install script: `install.sh`
- run pipeline: `python3 run_pipeline.py`
- Cursor autostart: `.cursor.yml`
- Do not run against targets you do not own.

This repo contains my automated recon lab for offensive security research and bug bounty methodology testing.

## 🛠 Local Tool Installation

This project does **not** store recon binaries in Git.

To install tools locally, run:

\`\`\`bash
./install.sh
# or
make install
\`\`\`

Tools install into \`tools/bin/\` and are ignored by Git.

## Multi-Agent Orchestration

- Roles and mappings: see `AGENTS.md`
- Quick usage:

```bash
python3 scripts/agent_orchestrator.py --list
python3 scripts/agent_orchestrator.py --role Strategist --task plan
python3 scripts/agent_orchestrator.py --role Executor --task full-run
```
