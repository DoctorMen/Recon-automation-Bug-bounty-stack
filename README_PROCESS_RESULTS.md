<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Processing Your 772 Nuclei Results

Found your scan results! You have **772 findings** from a 1-hour nuclei scan stored in:
```
~/nuclei-templates/results_web_scan.txt
```

## Quick Process

Run this to convert your text results to JSON and generate reports:

```bash
cd ~/recon-stack
bash scripts/process_nuclei_results.sh ~/nuclei-templates/results_web_scan.txt
```

Or if the file is in the default location:

```bash
bash scripts/process_nuclei_results.sh
```

## What This Does

1. **Parses** your nuclei text output (`results_web_scan.txt`) → `nuclei-findings.json`
2. **Triages** findings with improved scoring → `triage.json`
3. **Generates** markdown reports → `output/reports/`

## Manual Steps

If you prefer to run steps individually:

```bash
# Step 1: Parse text to JSON
python3 scripts/parse_nuclei_text_results.py ~/nuclei-templates/results_web_scan.txt

# Step 2: Triage findings
python3 scripts/triage.py

# Step 3: Generate reports
python3 scripts/generate_report.py
```

## Expected Results

Based on your scan, you should see:
- **~772 findings** parsed from text output
- Mostly **info/low severity** findings (DNS fingerprints, SSL info, CAA records, etc.)
- Breakdown by type:
  - `caa-fingerprint` - CAA record detections
  - `dns-saas-service-detection` - SaaS service detections
  - `ssl-issuer` - SSL certificate issuer info
  - `ssl-dns-names` - SSL certificate DNS names
  - And more...

## Output Files

After processing, you'll have:
- `output/nuclei-findings.json` - All findings in JSON format
- `output/triage.json` - Scored and filtered findings
- `output/reports/summary.md` - Executive summary
- `output/reports/*.md` - Individual finding reports

## View Results

```bash
# View summary
cat output/reports/summary.md

# Count findings
jq 'length' output/triage.json

# View severity breakdown
jq 'group_by(.info.severity) | map({severity: .[0].info.severity, count: length})' output/triage.json
```

---

**Note**: Your results show mostly informational findings (DNS/SSL fingerprinting), which is expected for a comprehensive recon scan. The triage script will score and prioritize these appropriately.

