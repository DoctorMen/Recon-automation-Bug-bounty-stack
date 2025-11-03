# Quick Commands to Check Scan Results

## 🚀 Instant Status Check

Run this command to see what's been found:

```bash
cd ~/Recon-automation-Bug-bounty-stack
python3 scripts/check_scan_status.py
```

## 📊 Manual Checks

### Check Subdomains Found (Stage 1)
```bash
# Count subdomains
wc -l output/subs.txt

# View first 20
head -20 output/subs.txt

# View all
cat output/subs.txt
```

### Check Alive Endpoints (Stage 2)
```bash
# Count URLs (if jq installed)
cat output/http.json | jq -r '.url' 2>/dev/null | wc -l

# View first 10 URLs
cat output/http.json | jq -r '.url' 2>/dev/null | head -10

# View all (without jq)
cat output/http.json | head -50
```

### Check Vulnerabilities Found (Stage 3)
```bash
# Count findings
cat output/immediate_roi/high_roi_findings.json 2>/dev/null | wc -l

# View vulnerability names
cat output/immediate_roi/high_roi_findings.json 2>/dev/null | jq -r '.info.name' | head -20

# View critical/high only
cat output/immediate_roi/high_roi_findings.json 2>/dev/null | jq 'select(.info.severity == "critical" or .info.severity == "high")'
```

### Check Reports Generated (Stage 6)
```bash
# List reports
ls -lh output/immediate_roi/submission_reports/ 2>/dev/null

# View summary
cat output/immediate_roi/ROI_SUMMARY.md 2>/dev/null || echo "Not generated yet"
```

## ⚡ Fast Status Check

```bash
cd ~/Recon-automation-Bug-bounty-stack && python3 scripts/check_scan_status.py
```

This shows:
- ✅ Subdomains found
- ✅ Alive endpoints
- ✅ Vulnerabilities discovered
- ✅ Reports generated
- ⏳ What's still running

---

**Run it now to see what's been found!** 🚀

