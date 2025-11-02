# Immediate ROI Bug Bounty System - README

## 🎯 Mission

**Immediate ROI Bug Bounty Hunter** is an idempotent, high-value vulnerability automation system designed to find and report bugs **tonight** for maximum profit.

## 🚀 Quick Start (Tonight!)

### 1. Prerequisites Check

```bash
# Install tools (if not already installed)
./install.sh

# Or manually:
# - nuclei
# - httpx  
# - python3
# - subfinder/amass (optional)
```

### 2. Configure Targets

Edit `targets.txt` with your authorized bug bounty targets:

```
example.com
target-app.com
authorized-domain.org
```

### 3. Run

```bash
# Linux/WSL/Mac
chmod +x scripts/immediate_roi_hunter.sh
./scripts/immediate_roi_hunter.sh

# Windows PowerShell
.\scripts\immediate_roi_hunter.ps1

# Or Python directly (cross-platform)
python3 scripts/immediate_roi_hunter.py
```

### 4. Check Results

```bash
# View summary
cat output/immediate_roi/ROI_SUMMARY.md

# View individual reports
ls output/immediate_roi/submission_reports/
```

## 📊 What You Get

### Immediate Outputs

1. **ROI_SUMMARY.md** - Executive summary with top findings
2. **submission_reports/** - Individual submission-ready reports
3. **Raw JSON** - High-ROI findings, secrets, API vulnerabilities

### High-Value Vulnerabilities Targeted

- **Critical**: Secrets exposure, Auth bypass, RCE, SSRF
- **High**: IDOR, SQLi, XXE, Privilege escalation
- **Medium**: API issues, XSS, CORS, Open redirects

## ✅ Idempotent Features

- **Safe to run multiple times** - No duplicate work
- **Resume capability** - Skip completed stages
- **Smart caching** - Reuses existing results
- **Checkpoint system** - Track progress

```bash
# Resume from last checkpoint
./scripts/immediate_roi_hunter.sh --resume

# Force re-run specific stage
./scripts/immediate_roi_hunter.sh --stage 3 --force
```

## 📋 Pipeline Stages

| Stage | Description | Output |
|-------|-------------|--------|
| 1 | Quick Reconnaissance | `output/subs.txt` |
| 2 | HTTP Probing | `output/http.json` |
| 3 | High-ROI Vulnerability Scan | `output/immediate_roi/high_roi_findings.json` |
| 4 | Secrets & Credentials Scan | `output/immediate_roi/secrets_found.json` |
| 5 | API Discovery & Testing | `output/immediate_roi/api_vulnerabilities.json` |
| 6 | Report Generation | `output/immediate_roi/submission_reports/` |

## 🎯 Usage Examples

### Full Pipeline (First Run)
```bash
./scripts/immediate_roi_hunter.sh
```

### Resume (Skip Completed Stages)
```bash
./scripts/immediate_roi_hunter.sh --resume
```

### Run Specific Stage Only
```bash
# Secrets scan only
./scripts/immediate_roi_hunter.sh --stage 4

# API discovery only
./scripts/immediate_roi_hunter.sh --stage 5

# Generate reports from existing findings
./scripts/immediate_roi_hunter.sh --stage 6
```

### Force Re-run
```bash
# Clear checkpoints and re-run everything
./scripts/immediate_roi_hunter.sh --force

# Re-run specific stage
./scripts/immediate_roi_hunter.sh --stage 3 --force
```

## 📁 File Structure

```
Recon-automation-Bug-bounty-stack/
├── scripts/
│   ├── immediate_roi_hunter.py      # Main Python script (cross-platform)
│   ├── immediate_roi_hunter.sh     # Bash wrapper
│   ├── immediate_roi_hunter.ps1    # PowerShell wrapper
│   └── quick_start_roi.sh           # Quick start script
├── output/
│   └── immediate_roi/
│       ├── ROI_SUMMARY.md           # Executive summary
│       ├── submission_reports/      # Individual reports
│       ├── high_roi_findings.json   # High-value vulnerabilities
│       ├── secrets_found.json       # Exposed secrets
│       ├── api_vulnerabilities.json # API security issues
│       ├── .status                  # Checkpoint file
│       └── roi_hunter.log           # Execution log
├── targets.txt                      # Your authorized targets
├── IMMEDIATE_ROI_GUIDE.md          # Detailed guide
└── QUICK_START_ROI.md              # Quick reference
```

## 🎓 Integration with Existing Pipeline

This system works alongside the existing recon stack:

- **Uses existing outputs**: Reads from `output/http.json`, `output/subs.txt`
- **Compatible**: Doesn't interfere with `run_pipeline.py`
- **Complementary**: Focuses on high-ROI while full pipeline does comprehensive scan

### Workflow Options

**Option 1: Standalone (Recommended for Tonight)**
```bash
# Just run ROI hunter
./scripts/immediate_roi_hunter.sh
```

**Option 2: After Full Pipeline**
```bash
# Run full pipeline first
python3 run_pipeline.py

# Then ROI hunter (uses existing outputs)
./scripts/immediate_roi_hunter.sh --resume
```

**Option 3: Hybrid**
```bash
# Run ROI hunter first (fast results)
./scripts/immediate_roi_hunter.sh

# Then full pipeline for comprehensive coverage
python3 run_pipeline.py
```

## 🔧 Troubleshooting

### Missing Tools
```bash
# Install all tools
./install.sh

# Or individually
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Python Issues
```bash
# Check version (need 3.7+)
python3 --version

# Use python instead of python3 if needed
python scripts/immediate_roi_hunter.py
```

### Windows Issues
```powershell
# If PowerShell script fails, use Python directly
python scripts/immediate_roi_hunter.py

# Or run in WSL
wsl bash scripts/immediate_roi_hunter.sh
```

### Check Logs
```bash
# View execution log
tail -f output/immediate_roi/roi_hunter.log

# Check status
cat output/immediate_roi/.status
```

## 📈 Expected Results

Based on typical bug bounty programs:

- **Time**: 1-3 hours (full scan)
- **Findings**: 5-50+ vulnerabilities
- **High-Value**: 1-10 critical/high findings
- **ROI**: Immediate submission-ready reports

## 🎯 Submission Workflow

1. **Run Hunter**: `./scripts/immediate_roi_hunter.sh`
2. **Review Summary**: `output/immediate_roi/ROI_SUMMARY.md`
3. **Verify Findings**: Manually test critical findings
4. **Enhance Reports**: Add screenshots/POCs to reports
5. **Submit**: Use reports to submit to bug bounty platform

## 🚨 Legal & Ethical

- ✅ Only scan authorized targets
- ✅ Follow responsible disclosure
- ✅ Respect rate limits
- ✅ Don't cause damage (no DoS, etc.)
- ✅ Follow bug bounty program rules

## 📚 Documentation

- **Detailed Guide**: `IMMEDIATE_ROI_GUIDE.md`
- **Quick Reference**: `QUICK_START_ROI.md`
- **This README**: Overview and integration

## 🎯 Key Features

✅ **Idempotent** - Safe to run multiple times  
✅ **High-ROI Focus** - Targets most valuable bugs  
✅ **Submission-Ready** - Pre-formatted reports  
✅ **Cross-Platform** - Windows, Linux, Mac  
✅ **Resume Capability** - Skip completed stages  
✅ **Smart Caching** - Reuses existing results  
✅ **Comprehensive** - 6-stage pipeline  

## 💡 Tips for Maximum ROI

1. **Start Early**: Run overnight for fresh results
2. **Focus on Secrets**: Exposed keys = quick wins
3. **API Endpoints**: Often overlooked, high value
4. **Verify Before Submit**: Manual verification increases acceptance
5. **Document Impact**: Clear impact = higher payout

## 🔗 Related Scripts

- `run_pipeline.py` - Full comprehensive pipeline
- `scripts/run_nuclei.sh` - Individual Nuclei scan
- `scripts/triage.py` - Vulnerability triage
- `scripts/generate_report.py` - Report generation

---

**Ready to hunt?** 

```bash
./scripts/immediate_roi_hunter.sh
```

Check `output/immediate_roi/ROI_SUMMARY.md` for your findings!

Good luck! 🎯💰

