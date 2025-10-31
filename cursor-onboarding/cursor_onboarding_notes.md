# Recon-Automation Bug Bounty Stack — Onboarding Notes

## Purpose
To allow Cursor 2.0 to understand and manage this recon + bug-bounty automation environment, including the workflow, agent roles, and folder structure.

---

## Architecture Overview

### Folder Structure
recon-stack/
├── scripts/
├── output/
├── nuclei-templates/
├── ci/
└── cursor-onboarding/

markdown
Copy code

### Core Agents
1. **Recon Scanner** – Runs Subfinder + Amass to enumerate subdomains.  
2. **Web Mapper** – Uses Httpx to probe alive hosts and fingerprint technologies.  
3. **Vulnerability Hunter (Nuclei)** – Performs Nuclei scans and generates custom templates.  
4. **Triage / Correlator** – Filters false positives and scores findings by severity and exploitability.  
5. **Report Writer** – Creates Markdown proof-of-concept and remediation reports.

---

### Output Flow
subs.txt → http.json → nuclei-findings.json → triage.json → reports/*.md

yaml
Copy code

Each stage feeds the next through shared files in `/output/`.

---

### Safety Rules
- Scan **only** authorized domains listed in `targets.txt`.  
- Never include API keys or private credentials in commits.  
- Use rate-limiting and non-destructive templates for all tests.  
- Treat this lab as an educational and authorized environment only.

---

### Tool Dependencies
subfinder, amass, dnsx, httpx, nuclei, jq, python3

yaml
Copy code

---

### Key Scripts
scripts/run_recon.sh
scripts/run_httpx.sh
scripts/run_nuclei.sh
scripts/triage.py
scripts/generate_report.py

yaml
Copy code

Each script performs one stage of the pipeline and logs to `/output/`.

---

### Notes for Cursor
- Agents communicate via files in `~/recon-stack/output/`.  
- Logs and summaries appear in `recon-run.log` and `triage.log`.  
- Cursor should use this structure to coordinate multi-agent automation for recon and reporting.

---
