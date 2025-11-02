## Session Playbook: Recon Automation (Portable + Secure)

This playbook lets you quickly follow, recreate, and redeploy the recon workflow, and securely back up/restore your session anywhere (Windows, Linux/WSL).

### 1) Prerequisites
- Windows PowerShell 5.1+ or PowerShell 7+
- Optional for strong encryption: gpg, 7-Zip, or openssl in PATH
- Python 3.8+ (for `run_pipeline.py` and utilities)

### 2) Common Tasks (Orchestrator)
- List available roles/tasks:
  - `python3 scripts/agent_orchestrator.py --list`
- Full run via Strategist/Executor flow:
  - `python3 scripts/agent_orchestrator.py --role Strategist --task plan`
  - `python3 scripts/agent_orchestrator.py --role Executor --task full-run`
- Direct stages (examples):
  - `./scripts/run_recon.sh`
  - `./scripts/run_httpx.sh`
  - `./scripts/run_nuclei.sh`

### 3) Windows Quick Start
1. Open PowerShell in the repo root.
2. Run the pipeline:
   - `python3 run_pipeline.py`  or  `./scripts/run_pipeline.sh`
3. After results are produced under `output/`, create an encrypted backup:
   - `powershell -ExecutionPolicy Bypass -File scripts/backup_and_encrypt.ps1 -OutputDir backups`

### 4) Linux/WSL Quick Start
1. In repo root:
   - `python3 run_pipeline.py`  or  `bash scripts/run_pipeline.sh`
2. Encrypted backup:
   - `bash scripts/backup_and_encrypt.sh backups`

### 5) What Gets Saved
The backup includes, if present:
- `output/`, `targets.txt`, `agents.json`, key `README*.md`, `SCAN_SUMMARY.md`
- `scripts/`, `ci/`, `workflows/`, `run_pipeline.py`, orchestrator helpers, `docs/`
- `session_meta/` with system info, recent git status/log/diff, file manifest

### 6) Restore From Backup
- Windows PowerShell:
  - `powershell -ExecutionPolicy Bypass -File scripts/restore_from_backup.ps1 -BackupPath backups\yourfile.zip.gpg -Destination .`
- Linux/WSL:
  - `bash scripts/restore_from_backup.sh backups/yourfile.zip.gpg .`

Notes:
- Supported encrypted formats: `.zip.gpg`, `.zip.7z`, `.zip.enc`, `.zip.dpapi` (Windows-only)
- You will need the passphrase used at backup time.

### 7) Security Notes
- gpg/7z/openssl use strong AES-based encryption; the passphrase is not stored.
- If none are available on Windows, DPAPI binds the backup to your user on that machine (not portable, safer than plaintext).
- Keep your passphrase in a password manager; rotate regularly.

### 8) Rapid Redeploy Checklist
- [ ] Restore latest backup to the machine
- [ ] Verify `targets.txt` and `output/` exist
- [ ] Run full pipeline or target stage(s)
- [ ] Generate or review `SCAN_SUMMARY.md`
- [ ] Create a fresh encrypted backup before moving machines



