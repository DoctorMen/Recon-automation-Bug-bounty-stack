# Same‑Day AppSec Signal — Idempotent Operations Runbook

Purpose: Make every engagement repeatable, auditable, and safe to re‑run.

## 0) Definitions
- Engagement ID: `YYYYMMDD-CLIENTCODE` (e.g., `20251102-ACME`)
- Consent ID: UUID attached to form and headers: `X-Consent-ID`.

## 1) Preflight (must pass)
- Consent & Scope PDF received (Apps Script auto‑email)
- Window + timezone confirmed, rate‑limit set (Conservative/Standard/Aggressive)
- Fixed egress IP verified/allowlisted (if needed)
- Create workspace: `./output/engagements/<ENGAGEMENT_ID>/`
  - subdirs: `evidence/`, `logs/`, `reports/`, `artifacts/`
  - copy `docs/config.js` snapshot to `artifacts/config.snapshot.js`

## 2) Idempotent run steps
- Discovery (safe): subdomain/asset discovery, HTTP fingerprint, TLS/cert review
- Scanning (safe): nuclei (non‑intrusive templates only), crypto‑aware checks
- Manual verifications (safe only)
- All commands run with headers `User-Agent: SameDayAppSec` and `X-Consent-ID: <UUID>`; rate‑limited; stop on instability
- Save artifacts to `evidence/` and hash files for integrity

## 3) Reporting
- Generate `reports/summary.md` with: scope, findings table, SLA hit/miss
- Export evidence bundle: `reports/evidence.zip`
- Optional: `reports/executive_summary.md`

## 4) Acceptance & refund logic
- Accept when summary + evidence delivered within window
- If SLA missed and prerequisites met, trigger refund per Terms

## 5) Re‑runs (idempotent)
- Re‑running only appends to `logs/` and `evidence/` with timestamped filenames
- Reports show run metadata (tool versions, start/end time, commit hashes)

## 6) Command snippets (example)
```bash
# create engagement skeleton
bash scripts/new_engagement.sh 20251102 ACME 5f0e9a7c-1b9d-4e3f-9f0a-aaaabbbbcccc

# staging dry‑run (no network impact)
bash scripts/run_staging.sh

# snapshot current env
bash scripts/snapshot_env.sh

# restore from a snapshot
bash scripts/restore_snapshot.sh snapshots/2025XXXX-XXXXXX
```

## 7) Delivery checklist
- [ ] Summary report
- [ ] Ticket‑ready issues (severity + repro)
- [ ] Evidence zip
- [ ] Executive summary (if requested)
- [ ] Retest letter (if requested)

Notes:
- Only non‑intrusive, read‑only activities are permitted.
- Stop immediately on instability; notify client.

## 8) IP protection controls
- Do not ship internal templates, scripts, or raw tool configs with Deliverables.
- Avoid listing precise tool versions/hashes in public‑facing reports; store them in `artifacts/` only.
- Watermark reports as proprietary; include a lightweight integrity hash.
- Keep proprietary checks server‑side; Deliverables contain results and recommendations only.

