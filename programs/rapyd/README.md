# Rapyd Bug Bounty - Quick Start Script

## 🎯 Usage

This script sets up Rapyd bug bounty testing in your recon automation stack.

### Quick Start
```bash
cd "C:\Users\Doc Lab\.cursor\worktrees\Recon-automation-Bug-bounty-stack\bi6DL"
python3 run_pipeline.py --targets programs/rapyd/targets.txt --output output/rapyd
```

### Manual Steps
```bash
# 1. Run reconnaissance
./scripts/run_recon.sh programs/rapyd/targets.txt output/rapyd

# 2. Map live URLs
./scripts/run_httpx.sh output/rapyd/subdomains.txt output/rapyd

# 3. Passive vulnerability scanning (safe for bug bounties)
./scripts/run_nuclei.sh output/rapyd/live_urls.txt output/rapyd

# 4. Generate report
python3 scripts/generate_report.py --input output/rapyd --output programs/rapyd/reports/recon_report.md
```

## 📁 Directory Structure

```
programs/rapyd/
├── targets.txt          # Rapyd domains to test
├── config.yaml          # Scan configuration
├── permission.txt       # Program authorization
├── TESTING_CHECKLIST.md # Testing checklist
├── recon/              # Reconnaissance results
├── findings/           # Bug findings log
│   └── FINDINGS_LOG.md
├── reports/            # Generated reports
└── screenshots/        # Evidence screenshots
```

## 🔥 URGENT: Promotion Ends November 29, 2025

**Bonus Rewards:**
- +$500 for high-impact logic flaws
- +$1,000 for critical bypasses

**Focus:** API endpoints (sandboxapi.rapyd.net/v1)

## ⚠️ Critical Requirements

1. **Account:** DoctorMen@bugcrowdninja.com ✅
2. **Header:** X-Bugcrowd: Bugcrowd-DoctorMen
3. **Environment:** Sandbox API only
4. **Testing:** Manual only (no form automation)

## 📚 Reference Files

- `RAPYD_TESTING_GUIDE.md` - Complete testing methodology
- `QUICK_REFERENCE.md` - Daily quick access
- `bug_bounty_program_tracker.md` - Full program details

