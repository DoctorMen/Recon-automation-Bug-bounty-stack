# Bug Bounty Scan - Medium+ Severity Focus

## ✅ Completed Setup

### 1. Helper Script Created ✓
**File**: `scripts/find_bug_bounty_programs.py`

This script identifies popular bug bounty programs from:
- **HackerOne**: 14 programs (Shopify, Starbucks, Uber, GitHub, etc.)
- **Bugcrowd**: 6 programs (Apple, Microsoft, Atlassian, etc.)
- **Public Programs**: 8 programs (Google, Facebook, LinkedIn, etc.)

**Usage**:
```bash
python3 scripts/find_bug_bounty_programs.py
```

This will:
- Generate/update `targets.txt` with popular bug bounty programs
- Export a JSON list to `bug_bounty_programs.json`
- Show available programs organized by platform

### 2. Targets Added ✓
**File**: `targets.txt`

Added **18 popular bug bounty program domains** including:
- HackerOne programs: shopify.com, starbucks.com, uber.com, github.com, mozilla.org, etc.
- Bugcrowd programs: apple.com, microsoft.com, atlassian.com
- Public programs: google.com, facebook.com, linkedin.com, oracle.com

⚠️ **IMPORTANT**: Review and uncomment only domains you are **authorized** to scan!

### 3. Configuration Updated ✓

#### `run_nuclei.py`
- **Default severity**: `medium,high,critical` (excludes info/low)
- Configurable via `NUCLEI_SEVERITY` environment variable
- Enhanced logging to highlight medium+ findings

#### `scripts/triage.py`
- **Default minimum severity**: `medium`
- Configurable via `TRIAGE_MIN_SEVERITY` environment variable
- Added summary statistics for bug bounty priorities

### 4. Scanning Started ✓

**Script**: `start_scan.py`

The scan pipeline is configured to:
1. ✅ Run recon scanner (if needed)
2. ✅ Run HTTP mapper with httpx (if needed)
3. 🔄 Run Nuclei with **medium+ severity only**
4. 🔄 Run triage filtering
5. 🔄 Generate reports

## 🚀 Running Scans

### Quick Start
```bash
python3 start_scan.py
```

Or use the shell script:
```bash
bash start_medium_high_scan.sh
```

### Full Pipeline
```bash
python3 run_pipeline.py
```

### Individual Steps
```bash
# Step 1: Recon (subdomain discovery)
python3 run_recon.py

# Step 2: HTTP Mapping (probe alive hosts)
python3 run_httpx.py

# Step 3: Vulnerability Scanning (medium+ only)
python3 run_nuclei.py

# Step 4: Triage & Filter
python3 scripts/triage.py

# Step 5: Generate Reports
python3 scripts/generate_report.py
```

## 📊 Expected Output

### Files Generated
- `output/nuclei-findings.json` - All medium+ severity findings
- `output/triage.json` - Filtered and scored findings
- `output/reports/summary.md` - Executive summary
- `output/reports/*.md` - Individual finding reports

### Focus Areas
The scan focuses on **medium to high severity** vulnerabilities:
- **Critical**: RCE, SSRF, authentication bypass
- **High**: SQL Injection, XXE, path traversal, IDOR
- **Medium**: XSS, CORS misconfig, API issues, information disclosure

## ⚙️ Configuration

### Environment Variables

```bash
# Nuclei severity filter (default: medium,high,critical)
export NUCLEI_SEVERITY="medium,high,critical"

# Triage minimum severity (default: medium)
export TRIAGE_MIN_SEVERITY="medium"

# Rate limiting
export NUCLEI_RATE_LIMIT=50
export HTTPX_RATE_LIMIT=100

# Timeouts
export NUCLEI_SCAN_TIMEOUT=7200  # 2 hours
export RECON_TIMEOUT=1800  # 30 minutes
```

## 📝 Notes

1. **Authorization Required**: Only scan domains you are authorized to test
2. **Scope Verification**: Always verify scope with each bug bounty program
3. **Rate Limiting**: Default settings are conservative to avoid overwhelming targets
4. **Focus**: All scans are configured for medium+ severity bug bounty priorities

## 🔍 Viewing Results

```bash
# View triaged findings
cat output/triage.json | jq '.[] | {severity: .info.severity, name: .info.name, url: .matched-at}'

# View summary
cat output/reports/summary.md

# Count findings by severity
cat output/triage.json | jq '[.[].info.severity] | group_by(.) | map({severity: .[0], count: length})'
```

## 📚 Resources

- **HackerOne Programs**: https://hackerone.com/programs
- **Bugcrowd Programs**: https://bugcrowd.com/programs
- **Bug Bounty Programs List**: `bug_bounty_programs.json`

---

**Status**: Scan is currently running in the background. Check `output/recon-run.log` for progress.

