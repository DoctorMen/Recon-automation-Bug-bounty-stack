<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Complete Usage Examples for AI Agents

## Example 1: First Bug Bounty Scan (Complete Workflow)

### User Request
"I want to start bug bounty hunting on example.com"

### AI Response Flow
```bash
# Step 1: Verify tools are installed
python3 setup_tools.py

# Step 2: Check OPSEC (VPN, privacy settings)
bash scripts/opsec_check_all.sh

# Step 3: Create targets file
echo "example.com" > targets.txt

# Step 4: Execute full pipeline
python3 run_pipeline.py

# Expected output structure:
# output/
# ├── subs.txt (e.g., 247 subdomains)
# ├── http.json (e.g., 189 live endpoints)
# ├── nuclei-findings.json (e.g., 23 findings)
# ├── triage.json (e.g., 15 unique issues)
# └── reports/
#     ├── summary.md
#     ├── findings_by_severity.md
#     └── findings_by_target.md

# Step 5: Present results to user
cat output/reports/summary.md
```

**AI Communication:**
```
✅ Running bug bounty scan on example.com...

[OPSEC Check] VPN: Active ✓ | DNS: Protected ✓
[Recon] Discovered 247 subdomains (30m 15s)
[HTTP Mapping] Found 189 live endpoints (4m 32s)
[Nuclei Scan] Detected 23 potential vulnerabilities (22m 08s)
[Triage] Identified 15 unique issues (12s)
[Reports] Generated 3 reports (8s)

📊 Summary:
- Critical: 2 findings
- High: 5 findings
- Medium: 8 findings

🎯 Priority Findings:
1. [CRITICAL] SQL Injection at https://api.example.com/search
2. [CRITICAL] Authentication Bypass at https://admin.example.com/login
3. [HIGH] XSS in https://example.com/profile?name=

Full report: output/reports/summary.md
```

---

## Example 2: Resume Interrupted Scan

### User Request
"The scan was interrupted, continue where it left off"

### AI Response Flow
```bash
# Check what was completed
cat output/.pipeline_status
# Shows: recon\nhttpx\n

# Resume from nuclei stage
RESUME=true python3 run_pipeline.py
```

**AI Communication:**
```
♻️  Resuming scan...

[Status Check] Previously completed:
✓ Recon (247 subdomains)
✓ HTTP Mapping (189 endpoints)

[Resuming] Starting from Nuclei scan...
[Nuclei Scan] Scanning 189 endpoints...
[Progress] 45/189 (23%) - 8 findings so far...
```

---

## Example 3: Fast Scan (Time-Critical)

### User Request
"Quick security check on urgent-target.com, I need results in 20 minutes"

### AI Response Flow
```bash
echo "urgent-target.com" > targets.txt

# Aggressive settings for speed
RECON_TIMEOUT=600 \
SUBFINDER_THREADS=100 \
AMASS_MAX_DNS=5000 \
NUCLEI_RATE_LIMIT=300 \
NUCLEI_THREADS=100 \
NUCLEI_SEVERITY=high,critical \
python3 run_pipeline.py
```

**AI Communication:**
```
⚡ Running FAST SCAN on urgent-target.com
⚠️  Speed mode: May miss some findings

[Settings] High concurrency | Critical/High severity only | 10-minute timeout
[Recon] Found 89 subdomains (10m 12s)
[HTTP] Mapped 67 endpoints (2m 45s)
[Nuclei] Scanned for critical issues (6m 33s)

✅ Completed in 19 minutes 30 seconds

🚨 High Priority Issues Found:
- [CRITICAL] Remote Code Execution at https://api.urgent-target.com/exec
- [HIGH] Exposed Admin Panel at https://admin.urgent-target.com

Recommendation: Run thorough scan when time permits
```

---

## Example 4: Deep Comprehensive Scan

### User Request
"Do a thorough, comprehensive security assessment of acme.org - accuracy is more important than speed"

### AI Response Flow
```bash
echo "acme.org" > targets.txt

# Thorough settings for accuracy
RECON_TIMEOUT=3600 \
AMASS_MAX_DNS=20000 \
DNSX_THREADS=150 \
NUCLEI_RATE_LIMIT=50 \
NUCLEI_THREADS=25 \
NUCLEI_SEVERITY=low,medium,high,critical \
NUCLEI_RETRIES=5 \
python3 run_pipeline.py
```

**AI Communication:**
```
🔬 Running DEEP SCAN on acme.org
📊 Comprehensive mode: All severity levels | Maximum coverage | 60-minute recon

[Recon] Using Subfinder + Amass + DNSx validation...
[Recon] Discovered 1,847 subdomains (58m 23s)
[HTTP] Mapping 1,847 endpoints with full tech detection...
[HTTP] Found 1,203 live services (18m 45s)
[Nuclei] Comprehensive scan with 5 retries per template...
[Nuclei] Testing 1,203 endpoints against 3,500+ templates...
[Progress] 25% complete - 47 findings so far...
[Progress] 50% complete - 89 findings so far...
[Progress] 75% complete - 124 findings so far...
[Nuclei] Completed: 156 total findings (97m 12s)
[Triage] Deduplicating and prioritizing...
[Triage] 89 unique vulnerabilities identified

✅ Deep scan completed in 2h 54m

📊 Comprehensive Results:
- Critical: 3
- High: 12
- Medium: 34
- Low: 28
- Info: 12

Most Critical Finding:
[CRITICAL] Unauthenticated Database Access
Location: https://db.acme.org:5432
Impact: Full database compromise possible
```

---

## Example 5: Multi-Target Campaign

### User Request
"Scan all these domains: example.com, test.com, demo.org, and sample.net"

### AI Response Flow
```bash
# Create multi-target file
cat > targets.txt << EOF
example.com
test.com
demo.org
sample.net
EOF

# Run pipeline
python3 run_pipeline.py
```

**AI Communication:**
```
🎯 Running multi-target campaign
Targets: 4 domains

[Recon] Enumerating all targets in parallel...
- example.com: 247 subdomains
- test.com: 156 subdomains
- demo.org: 89 subdomains
- sample.net: 312 subdomains
[Total] 804 unique subdomains across 4 targets

[HTTP] Mapping 804 subdomains...
[Total] 567 live HTTP endpoints

[Nuclei] Scanning 567 endpoints...
[Progress] Example.com: 12 findings
[Progress] Test.com: 8 findings
[Progress] Demo.org: 5 findings
[Progress] Sample.net: 19 findings
[Total] 44 vulnerabilities detected

📊 Per-Target Summary:
1. sample.net - 19 findings (3 critical)
2. example.com - 12 findings (1 critical)
3. test.com - 8 findings (0 critical)
4. demo.org - 5 findings (1 high)
```

---

## Example 6: Agent-Based Orchestration

### User Request
"Use the strategist to plan the workflow, then have the executor run it"

### AI Response Flow
```bash
# Step 1: Strategist planning
python3 scripts/agent_orchestrator.py --role Strategist --task plan

# Step 2: Executor execution
python3 scripts/agent_orchestrator.py --role Executor --task full-run

# Step 3: Composer 3 reporting
python3 scripts/agent_orchestrator.py --role "Composer 3 — Documentation & Reporting" --task reports
```

**AI Communication:**
```
🤖 Multi-Agent Workflow Initiated

[Strategist Agent] Planning workflow...
✓ Validated targets.txt (example.com)
✓ Verified tool availability
✓ Optimized resource allocation
✓ Planned execution sequence: recon → httpx → nuclei → triage → report

[Executor Agent] Executing planned workflow...
✓ Stage 1: Recon (completed in 28m)
✓ Stage 2: HTTP Mapping (completed in 5m)
✓ Stage 3: Nuclei Scan (completed in 24m)
✓ Stage 4: Triage (completed in 15s)

[Composer 3 Agent] Generating documentation...
✓ Created summary.md
✓ Created findings_by_severity.md
✓ Created findings_by_target.md

🎯 Workflow Complete - All agents executed successfully
```

---

## Example 7: Filtering and Analysis

### User Request
"Show me only the XSS vulnerabilities"

### AI Response Flow
```python
import json

with open('output/triage.json', 'r') as f:
    findings = json.load(f)

xss_findings = [
    f for f in findings 
    if 'xss' in f.get('name', '').lower() 
    or 'xss' in str(f.get('info', {}).get('tags', [])).lower()
]

print(f"Found {len(xss_findings)} XSS vulnerabilities:\n")
for i, finding in enumerate(xss_findings, 1):
    print(f"{i}. {finding['name']}")
    print(f"   Location: {finding['matched-at']}")
    print(f"   Severity: {finding['info']['severity']}")
    print()
```

**AI Communication:**
```
🔍 Filtering for XSS vulnerabilities...

Found 7 XSS vulnerabilities:

1. Reflected XSS in Search Parameter
   Location: https://example.com/search?q=<script>
   Severity: medium
   
2. DOM-based XSS in Profile Page
   Location: https://example.com/profile?name=<img>
   Severity: high
   
3. Stored XSS in Comments
   Location: https://example.com/api/comments
   Severity: high

... (4 more findings)

Export command:
python3 -c "import json; data=json.load(open('output/triage.json')); xss=[f for f in data if 'xss' in f.get('name','').lower()]; json.dump(xss, open('xss_only.json','w'), indent=2)"
```

---

## Example 8: OPSEC Verification Workflow

### User Request
"Make sure everything is secure before I scan"

### AI Response Flow
```bash
# Comprehensive OPSEC check
bash scripts/opsec_check_all.sh

# If issues found, run fixes
bash scripts/opsec_check_vpn.sh
bash scripts/opsec_system_harden.sh
bash scripts/opsec_secrets_manager.sh
```

**AI Communication:**
```
🔒 Running OPSEC verification...

[VPN Check]
✓ VPN connection: Active (Server: US-East-1)
✓ IP leak protection: Enabled
✓ DNS leak protection: Enabled

[Privacy Check]
✓ No DNS leaks detected
✓ WebRTC disabled
✓ Real IP hidden

[Secrets Check]
✓ No API keys in code
✓ No credentials in files
✓ Environment variables secured

[System Hardening]
✓ Firewall: Active
✓ Secure DNS: Configured
✓ Process isolation: Enabled

[Log Sanitization]
✓ Sensitive data removed from logs
✓ Temporary files cleaned

🎯 OPSEC Score: 98/100

⚠️  Recommendation: Update VPN server location closer to target for better performance

✅ System secure - Safe to proceed with scanning
```

---

## Example 9: Comparing Scans (Delta Analysis)

### User Request
"What's different compared to last week's scan?"

### AI Response Flow
```bash
# Archive current findings
cp output/triage.json output/triage_$(date +%Y%m%d).json

# Run new scan
python3 run_pipeline.py

# Compare results
python3 -c "
import json
from datetime import datetime

old = json.load(open('output/triage_20251028.json'))
new = json.load(open('output/triage.json'))

old_urls = {f['matched-at'] for f in old}
new_urls = {f['matched-at'] for f in new}

new_findings = [f for f in new if f['matched-at'] not in old_urls]
fixed_findings = [f for f in old if f['matched-at'] not in new_urls]

print(f'NEW vulnerabilities: {len(new_findings)}')
print(f'FIXED vulnerabilities: {len(fixed_findings)}')
"
```

**AI Communication:**
```
📊 Comparing with scan from 2025-10-28...

Previous Scan (Oct 28):
- Total findings: 23
- Critical: 2
- High: 7

Current Scan (Nov 4):
- Total findings: 19
- Critical: 1
- High: 6

📈 Delta Analysis:
✅ FIXED (5 vulnerabilities):
1. [CRITICAL] SQL Injection at /api/search (PATCHED)
2. [HIGH] XSS at /profile (FIXED)
3. [MEDIUM] CORS misconfiguration (RESOLVED)
4. [MEDIUM] Information disclosure (FIXED)
5. [LOW] Missing security headers (ADDED)

🚨 NEW (1 vulnerability):
1. [HIGH] Authentication bypass at /admin/debug (NEW ENDPOINT)

💡 Insights:
- Security improved by 21% (5 fixed, 1 new)
- New endpoint /admin/debug introduced this week
- Recommendation: Investigate new admin debug endpoint immediately
```

---

## Example 10: Export for Submission

### User Request
"Prepare findings for HackerOne submission"

### AI Response Flow
```bash
# Create submission package
mkdir -p submission_package

# Generate all reports
python3 scripts/generate_report.py

# Sanitize outputs (remove sensitive data)
bash scripts/opsec_secrets_manager.sh

# Copy reports
cp output/reports/summary.md submission_package/
cp output/reports/findings_by_severity.md submission_package/
cp output/triage.json submission_package/

# Create submission template
cat > submission_package/SUBMISSION_TEMPLATE.md << 'EOF'
# Vulnerability Report

## Summary
[Brief description]

## Affected Asset
**Domain:** example.com
**Endpoint:** [specific URL]

## Vulnerability Details
**Type:** [SQL Injection/XSS/etc]
**Severity:** [Critical/High/Medium/Low]
**CVSS Score:** [if applicable]

## Steps to Reproduce
1. Navigate to [URL]
2. [Step 2]
3. [Step 3]

## Proof of Concept
```
[PoC code or curl command]
```

## Impact
[Describe the potential impact]

## Recommended Fix
[Suggested remediation]

## Supporting Evidence
- See attached screenshots
- See nuclei-findings.json for technical details
EOF

echo "✅ Submission package created in submission_package/"
ls -la submission_package/
```

**AI Communication:**
```
📦 Preparing bug bounty submission package...

[Sanitizing] Removing sensitive data...
✓ API keys removed
✓ Internal IPs sanitized
✓ Personal information redacted

[Packaging] Creating submission files...
✓ summary.md - Executive summary
✓ findings_by_severity.md - Detailed findings
✓ triage.json - Technical data
✓ SUBMISSION_TEMPLATE.md - Report template

📋 Submission Checklist:
☐ Fill out SUBMISSION_TEMPLATE.md
☐ Add proof-of-concept screenshots
☐ Include curl commands for reproduction
☐ Verify impact assessment
☐ Check severity rating
☐ Review for sensitive data

📂 Package location: submission_package/

🎯 Ready for HackerOne submission!

💡 Tip: Focus on the 2 critical findings first - they have highest payout potential
```

---

## Example 11: Continuous Monitoring Setup

### User Request
"Monitor example.com automatically every night"

### AI Response Flow
```bash
# Create monitoring script
cat > monitor_nightly.sh << 'EOF'
#!/bin/bash
cd /path/to/Recon-automation-Bug-bounty-stack
RESUME=true python3 run_pipeline.py

# Send notification if new critical findings
if [ -f output/triage.json ]; then
  CRITICAL_COUNT=$(python3 -c "import json; print(len([f for f in json.load(open('output/triage.json')) if f.get('info',{}).get('severity')=='critical']))")
  if [ "$CRITICAL_COUNT" -gt 0 ]; then
    # Send Discord notification
    curl -X POST $DISCORD_WEBHOOK \
      -H "Content-Type: application/json" \
      -d "{\"content\":\"🚨 Found $CRITICAL_COUNT critical vulnerabilities in example.com!\"}"
  fi
fi
EOF

chmod +x monitor_nightly.sh

# Add to crontab (runs at 2 AM daily)
(crontab -l 2>/dev/null; echo "0 2 * * * /path/to/monitor_nightly.sh") | crontab -
```

**AI Communication:**
```
⏰ Setting up continuous monitoring for example.com...

[Schedule] Daily at 2:00 AM
[Mode] Resume-enabled (only scans changes)
[Notifications] Discord alerts for critical findings

✓ Created monitoring script: monitor_nightly.sh
✓ Added to cron: 0 2 * * *
✓ Configured Discord webhook

📊 Monitoring Configuration:
- Target: example.com
- Frequency: Daily
- Scan type: Incremental (RESUME=true)
- Alert threshold: Critical findings
- Notification channel: Discord

🔔 You'll receive notifications when:
- New critical vulnerabilities found
- Scan errors occur
- Significant changes detected

✅ Continuous monitoring active!

Next scan: Tonight at 2:00 AM
```

---

## Pro Tips for AI Agents

### Context Detection
```python
# Always check for existing state
if os.path.exists('output/.pipeline_status'):
    # Scan in progress or completed
    suggest_resume = True

if os.path.exists('targets.txt'):
    # Previous targets exist
    ask_if_same_target = True
```

### Smart Defaults
- Fast scan: When user mentions "quick" or time pressure
- Thorough scan: When user mentions "comprehensive" or "complete"
- Resume: When output directory has partial results
- OPSEC check: Always before starting ANY scan

### Error Recovery
- Tool missing → Run setup_tools.py
- VPN down → Alert and suggest opsec_check_vpn.sh
- Out of memory → Suggest lower concurrency settings
- Scan stuck → Offer to kill and resume

### User Communication
- Always show progress for long-running operations
- Highlight critical findings immediately
- Provide actionable next steps
- Estimate completion times when possible

---

**Generated:** 2025-11-04  
**Purpose:** Comprehensive usage examples for AI agent training  
**System:** Recon Automation Bug Bounty Stack v1.0
