# Staging Environment

Purpose: safe, idempotent dry‑runs with sanitized targets.

- Targets file: `env/staging/targets.txt`
- Output root: `env/staging/output/`
- Run: `bash scripts/run_staging.sh`
- Snapshot/restore: `bash scripts/snapshot_env.sh` and `bash scripts/restore_snapshot.sh <SNAPSHOT_DIR>`

This does not hit production customers. Replace with your own lab domains if needed.

