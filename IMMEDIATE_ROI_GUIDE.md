# Immediate ROI Bug Bounty Hunter - Quick Start Guide

## 🎯 Overview

This is an **idempotent, high-ROI bug bounty automation** system designed to find and report vulnerabilities **tonight** for maximum profit. It focuses on the most valuable bug types that yield the highest returns.

## 🚀 Quick Start

### Prerequisites

1. **Install required tools**:
```bash
./install.sh
```

Required tools:
- `nuclei` - Vulnerability scanner
- `httpx` - HTTP probing
- `subfinder` / `amass` - Subdomain enumeration (optional but recommended)
- `python3` - Python 3.7+

### Basic Usage

#### Linux/WSL/Mac:
```bash
# Make executable
chmod +x scripts/immediate_roi_hunter.sh

# Run full pipeline
./scripts/immediate_roi_hunter.sh

# Resume from last checkpoint (idempotent)
./scripts/immediate_roi_hunter.sh --resume

# Run specific stage
./scripts/immediate_roi_hunter.sh --stage 3

# Force re-run (ignore checkpoints)
./scripts/immediate_roi_hunter.sh --force
```

#### Windows PowerShell:
```powershell
# Run full pipeline
.\scripts\immediate_roi_hunter.ps1

# Resume from last checkpoint
.\scripts\immediate_roi_hunter.ps1 -Resume

# Run specific stage
.\scripts\immediate_roi_hunter.ps1 -Stage 3

# Force re-run
.\scripts\immediate_roi_hunter.ps1 -Force
```

#### Direct Python:
```bash
python3 scripts/immediate_roi_hunter.py
python3 scripts/immediate_roi_hunter.py --resume
python3 scripts/immediate_roi_hunter.py --stage 3
python3 scripts/immediate_roi_hunter.py --force
```

## 📋 Pipeline Stages

The system runs **6 stages** in sequence:

1. **Stage 1: Quick Reconnaissance**
   - Subdomain enumeration (subfinder/amass)
   - Output: `output/subs.txt`

2. **Stage 2: HTTP Probing**
   - Find alive endpoints
   - Technology fingerprinting
   - Output: `output/http.json`

3. **Stage 3: High-ROI Vulnerability Scan**
   - Focuses on critical/high/medium severity
   - Targets: auth, IDOR, SQLi, SSRF, RCE, XSS, CORS
   - Output: `output/immediate_roi/high_roi_findings.json`

4. **Stage 4: Secrets & Credentials Scan**
   - Exposed API keys, tokens, credentials
   - Output: `output/immediate_roi/secrets_found.json`

5. **Stage 5: API Discovery & Testing**
   - Discovers API endpoints
   - Tests GraphQL, Swagger, OpenAPI
   - API security vulnerabilities
   - Output: `output/immediate_roi/api_vulnerabilities.json`

6. **Stage 6: Report Generation**
   - Generates submission-ready reports
   - Individual reports + summary
   - Output: `output/immediate_roi/submission_reports/`

## 🎯 High-ROI Vulnerability Focus

### Critical Priority (Highest Value)
- **Exposed Secrets**: API keys, credentials, tokens
- **Authentication Bypass**: Login bypass, session hijacking
- **RCE**: Remote code execution
- **SSRF**: Server-side request forgery
- **Subdomain Takeover**: DNS misconfigurations

### High Priority
- **IDOR**: Insecure direct object reference
- **SQL Injection**: Database injection attacks
- **XXE**: XML external entity
- **LFI**: Local file inclusion
- **Privilege Escalation**: Unauthorized access escalation

### Medium Priority
- **API Security**: Auth bypass, mass assignment
- **XSS**: Cross-site scripting
- **CORS**: CORS misconfiguration
- **Open Redirects**: Redirect vulnerabilities
- **Information Disclosure**: Sensitive data exposure

## 📁 Output Files

All results are saved in `output/immediate_roi/`:

```
output/immediate_roi/
├── ROI_SUMMARY.md                    # Executive summary
├── submission_reports/                # Individual submission-ready reports
│   ├── 001_critical_example.com_auth_bypass.md
│   ├── 002_high_example.com_idor.md
│   └── ...
├── high_roi_findings.json            # High-value vulnerabilities
├── secrets_found.json                # Exposed secrets
├── api_vulnerabilities.json          # API security issues
├── .status                           # Checkpoint file (idempotency)
└── roi_hunter.log                    # Execution log
```

## ✅ Idempotency Features

The system is **fully idempotent** - you can run it multiple times safely:

- **Checkpoint System**: Each stage marks completion in `.status`
- **Resume Capability**: Use `--resume` to skip completed stages
- **Smart Caching**: Reuses existing files when available
- **No Duplication**: Findings are deduplicated automatically

### Example Idempotent Workflow:

```bash
# First run - completes all stages
./scripts/immediate_roi_hunter.sh

# Second run - skips completed stages, only runs new scans
./scripts/immediate_roi_hunter.sh --resume

# Force re-run stage 3 only
./scripts/immediate_roi_hunter.sh --stage 3 --force

# Full reset (clear checkpoints)
./scripts/immediate_roi_hunter.sh --force
```

## 📊 Understanding Results

### ROI Summary Report

Check `output/immediate_roi/ROI_SUMMARY.md` for:
- Total findings count
- Severity breakdown
- Top 20 prioritized findings
- Next steps for submission

### Individual Reports

Each finding has a detailed report in `submission_reports/` with:
- Description
- Proof of concept
- Impact assessment
- Remediation recommendations
- References

### Submission Readiness

Reports are formatted for:
- Bugcrowd
- HackerOne
- Other bug bounty platforms

**Before submitting:**
1. ✅ Verify findings manually
2. ✅ Test exploitability
3. ✅ Document impact clearly
4. ✅ Follow responsible disclosure

## 🎯 Target Configuration

Edit `targets.txt` to add your authorized targets:

```
example.com
target-app.com
authorized-domain.org
```

**Important**: Only scan targets you are authorized to test!

## ⚡ Performance Tips

1. **Parallel Execution**: The system uses parallel processing where possible
2. **Rate Limiting**: Built-in rate limits prevent overwhelming targets
3. **Timeout Protection**: Stages have timeouts to prevent hanging
4. **Selective Scanning**: Focus on specific stages if needed

### Customize Scanning:

```bash
# Focus on secrets only
./scripts/immediate_roi_hunter.sh --stage 4

# Re-run API discovery
./scripts/immediate_roi_hunter.sh --stage 5 --force

# Generate reports from existing findings
./scripts/immediate_roi_hunter.sh --stage 6
```

## 🔧 Troubleshooting

### Missing Tools

```bash
# Install all tools
./install.sh

# Or install individually
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Python Issues

```bash
# Check Python version (need 3.7+)
python3 --version

# Install dependencies if needed
pip3 install -r requirements.txt  # if exists
```

### Windows Issues

If PowerShell script fails:
1. Use Python directly: `python scripts/immediate_roi_hunter.py`
2. Ensure Python is in PATH
3. Run PowerShell as Administrator if needed

### Stage Failures

- Check logs: `output/immediate_roi/roi_hunter.log`
- Verify tool installation
- Check network connectivity
- Ensure targets are reachable

## 📈 Expected Results

Based on typical bug bounty programs:

- **Time**: 1-3 hours for full scan (depending on target size)
- **Findings**: 5-50+ vulnerabilities (varies by target)
- **High-Value**: 1-10 critical/high findings (focus of this tool)
- **ROI**: Immediate submission-ready reports

## 🎓 Best Practices

1. **Start Small**: Test on authorized targets first
2. **Verify Findings**: Always manually verify before submission
3. **Document Impact**: Clear impact statements increase payout
4. **Follow Scope**: Respect program scope and rules
5. **Be Professional**: Professional reports get better responses

## 🚨 Legal & Ethical

- ✅ Only scan authorized targets
- ✅ Follow responsible disclosure
- ✅ Respect rate limits
- ✅ Don't cause damage (no DoS, etc.)
- ✅ Follow bug bounty program rules

## 📚 References

This system incorporates techniques from:
- Bug bounty methodology (Jason Haddix, etc.)
- OWASP Top 10
- API security best practices
- Common vulnerability patterns

## 🎯 Next Steps After Running

1. **Review Summary**: Check `ROI_SUMMARY.md`
2. **Verify Findings**: Manually test critical findings
3. **Prepare Reports**: Enhance reports with screenshots/POCs
4. **Submit**: Submit to bug bounty platform
5. **Track**: Monitor submission status

---

**Ready to hunt?** Run the script and check `output/immediate_roi/ROI_SUMMARY.md` for your findings!

Good luck! 🎯💰

