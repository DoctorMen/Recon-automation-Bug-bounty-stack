<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# ⚡ QUICK REFERENCE CARD

## 🚀 One-Command Start

```bash
cd ~/Recon-automation-Bug-bounty-stack/programs/paypal
./advanced_paypal_hunter.sh
```

---

## 🛠️ Individual Tools

### Analyze Subdomains
```bash
python3 tools/smart_subdomain_analyzer.py --input recon/shadowstep_paypal_live.txt
```

### Targeted Scan
```bash
nuclei -l recon/high_priority_targets.txt -tags exposure,config,idor -severity high,critical -rate-limit 15 -o findings/scan.txt
```

### Analyze Results
```bash
python3 tools/intelligent_result_analyzer.py --scan-results findings/scan.txt
```

### API Fuzzing
```bash
python3 tools/advanced_api_fuzzer.py --target https://api.sandbox.paypal.com --endpoints recon/api_endpoints.txt --rate-limit 2
```

### Safe Testing
```bash
python3 tools/safe_testing_framework.py --target api.sandbox.paypal.com --mode gentle
```

---

## 📂 Key Files

| File | Purpose |
|------|---------|
| `recon/shadowstep_paypal_live.txt` | All 306 live hosts |
| `recon/high_priority_targets.txt` | Top 50 valuable targets |
| `findings/verified_findings_*.json` | Filtered real bugs |
| `findings/manual_verification_checklist_*.txt` | What to verify |

---

## 🎯 Workflow

1. **Analyze** → Identify high-value targets
2. **Scan** → Test focused target list
3. **Filter** → Remove false positives
4. **Fuzz** → Test business logic
5. **Verify** → Manual confirmation
6. **Report** → Submit to HackerOne

---

## 💡 Pro Tips

- Start with `gentle` mode (2 req/sec)
- Focus on staging/test environments
- Always manually verify critical findings
- Document proof of concept
- One $10k bug > 100 empty hunts

---

## ⚠️ Safety

- Rate limit: 2-15 req/sec max
- Watch for 429 responses
- Stop on repeated errors
- Test sandbox before production

---

## 📊 Expected Results

**Per hunt:**
- Time: 30-60 minutes
- Findings: 2-10 vulnerabilities
- Value: $1,000-$15,000

**Success rate:** 40-60% (vs 5-10% with basic tools)
