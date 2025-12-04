<!--
PROPRIETARY AND CONFIDENTIAL

Copyright © 2025 Khallid H Nurse. All Rights Reserved.

This software and its documentation contain trade secrets and proprietary information
belonging to Khallid H Nurse. Unauthorized copying, distribution, or use of this file,
via any medium, is strictly prohibited. Use of this software is governed by the terms
and conditions set forth in the LICENSE file.

For licensing inquiries, contact: [Your Contact Information]
-->

# Recon-automation-Bug-bounty-stack

**PROPRIETARY SOFTWARE - UNAUTHORIZED USE PROHIBITED**

Local recon toolchain and automation for authorized security testing. This software is the intellectual property of Khallid H Nurse and is protected by copyright and other intellectual property laws.

## LEGAL NOTICE

This software is licensed, not sold. By using this software, you agree to be bound by the terms of the End User License Agreement (EULA) contained in the LICENSE file. Unauthorized copying, modification, distribution, public display, or public performance of this software is strictly prohibited and may result in severe civil and criminal penalties.

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
