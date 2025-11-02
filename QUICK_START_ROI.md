# Immediate ROI Bug Bounty Hunter - Quick Reference

## 🚀 One-Command Start

```bash
# Linux/WSL/Mac
chmod +x scripts/quick_start_roi.sh
./scripts/quick_start_roi.sh

# Or directly
./scripts/immediate_roi_hunter.sh
```

```powershell
# Windows PowerShell
.\scripts\immediate_roi_hunter.ps1
```

## 📋 What It Does

1. **Reconnaissance** → Find subdomains
2. **HTTP Probing** → Find alive endpoints  
3. **High-ROI Scan** → Critical/High vulnerabilities
4. **Secrets Scan** → Exposed credentials/keys
5. **API Discovery** → API endpoints & vulnerabilities
6. **Report Generation** → Submission-ready reports

## 📁 Results Location

```
output/immediate_roi/
├── ROI_SUMMARY.md              ← Start here!
├── submission_reports/         ← Individual reports
└── *.json                      ← Raw findings
```

## ⚡ Quick Commands

```bash
# Full run
./scripts/immediate_roi_hunter.sh

# Resume (skip completed stages)
./scripts/immediate_roi_hunter.sh --resume

# Run specific stage
./scripts/immediate_roi_hunter.sh --stage 3

# Force re-run
./scripts/immediate_roi_hunter.sh --force
```

## 🎯 High-ROI Targets

- **Critical**: Secrets, Auth Bypass, RCE, SSRF
- **High**: IDOR, SQLi, XXE, Privilege Escalation  
- **Medium**: API Issues, XSS, CORS, Open Redirects

## ✅ Idempotent

- Safe to run multiple times
- Resumes from checkpoints
- No duplicate findings
- Smart caching

## 📊 Expected Time

- **Full Scan**: 1-3 hours
- **Resume**: Seconds (skips completed)
- **Per Stage**: 10-30 minutes

## 🎓 Next Steps

1. Check `output/immediate_roi/ROI_SUMMARY.md`
2. Review individual reports
3. Verify findings manually
4. Submit to bug bounty platform

---

**Ready?** Run: `./scripts/quick_start_roi.sh`

