# Recon Automation – Bug Bounty Stack

## Overview
This repository kick-starts a high-impact bug bounty reconnaissance workflow. It combines:
- A playbook (`docs/enumeration_plan.md`) outlining how to enumerate assets efficiently for medium/high-severity findings.
- A configurable enumeration runner (`scripts/run_enumeration.py`) that orchestrates common tooling, captures results, and falls back to safe defaults when dependencies are missing.
- Scope scaffolding (`scope/targets.yaml`) and data directories to keep runs organized over time.

## Directory Layout
- `docs/` – strategic guidance and runbooks.
- `scope/` – in-scope targets you control; edit before each engagement.
- `scripts/` – automation entry points.
- `data/` – run outputs (timestamped); safe to clean between engagements.

## Prerequisites
1. Python 3.9+.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Install external reconnaissance tools for richer coverage:
   - `subfinder`, `amass`, `assetfinder`
   - `dnsx`, `httpx`
   - `masscan`, `nmap`
   - `katana`, `gospider`, `ffuf`, `nuclei`, etc. (hook in manually or via custom scripts)

> The runner checks for these tools automatically and will gracefully fall back to built-in alternatives when they are absent.

## Usage
1. Edit `scope/targets.yaml` with your asset inventory (domains, IP ranges, ASNs).
2. Kick off enumeration:
   ```bash
   python scripts/run_enumeration.py \
     --scope scope/targets.yaml \
     --output-dir data/runs \
     --http-timeout 10 \
     --run-masscan \
     --masscan-rate 8000 \
     --masscan-top-ports 200 \
     --nmap-top-ports 200
   ```
   - Omit `--run-masscan` if you do not want fast port sweeps or lack permission.
   - Add `--skip-nmap` for passive-only runs.

3. Review outputs under `data/runs/<timestamp>/`:
   - `subdomains/` – per-domain tool outputs and `live.txt` live host list.
   - `http/probe.jsonl` – HTTP response metadata for live hosts.
   - `ports/masscan.json|masscan_open.txt` – fast port sweep results (if enabled).
   - `ports/nmap.xml` – detailed service fingerprints.
   - `summary.json` – run metadata (counts, live hosts, optional masscan stats).

## Extending the Pipeline
- Leverage `docs/enumeration_plan.md` to design additional modules (JS endpoint extraction, storage exposure hunting, auth surface tracking).
- Integrate new tools by mirroring the helper pattern in `run_enumeration.py` (check availability, write outputs under a dedicated subfolder, update the summary).
- Schedule the script via cron or CI and diff successive `summary.json` files to detect new assets quickly.

## Next Steps for Medium/High Severity Focus
- Build playbooks for SSRF, auth bypass, deserialization, and data exposure targeting the technologies surfaced in `http/probe.jsonl`.
- Prioritize assets tagged as high criticality in your scope file; re-run enumeration after product releases.
- Feed high-signal findings into your bug bounty triage workflow with reproducible evidence (request logs, screenshots, payloads).

For deeper strategic context, consult `docs/enumeration_plan.md`. Contributions and new integrations are welcome—open issues or PRs with ideas that increase signal-to-noise for serious vulnerabilities.