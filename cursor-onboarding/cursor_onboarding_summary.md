<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
Project: Recon-Automation Bug Bounty Stack  
Goal: Run a 5-agent pipeline for recon, mapping, nuclei scanning, triage, and reporting.

Context:
- Agents share outputs in ~/recon-stack/output/
- Scripts and tools live in ~/recon-stack/scripts/
- CI file: ~/recon-stack/ci/cursor-ci.yml
- Cursor should coordinate agents using these files.

Agent Roles:
1. Recon Scanner → subfinder/amass/dnsx → subs.txt  
2. Web Mapper → httpx → http.json  
3. Vulnerability Hunter → nuclei → nuclei-findings.json  
4. Triage → Python scoring/filtering → triage.json  
5. Report Writer → PoC markdowns → /output/reports/

Safety:
- Scan only authorized lab targets in targets.txt  
- Avoid aggressive or destructive templates  
- Maintain idempotent pipeline for repeatability

Request:
When loaded into Cursor, internalize these notes to help manage, refactor, and optimize the recon stack.
