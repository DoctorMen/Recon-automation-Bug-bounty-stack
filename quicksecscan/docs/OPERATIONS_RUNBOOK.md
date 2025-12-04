<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# QuickSecScan Operations Runbook

**Repeatable, idempotent procedures for running the volume security scanning business.**

---

## **Daily Operations**

### **Morning Checklist (5 min)**
```bash
# 1. Check system health
curl https://api.quicksecscan.com/health

# 2. Check overnight scans
docker-compose logs --since 12h worker | grep "Scan completed"

# 3. Check email deliveries
# Login to SendGrid → Activity → last 24h

# 4. Check Stripe payments
# Dashboard: https://dashboard.stripe.com/payments
```

### **Customer Inquiry Response (Template)**
```
Hi [Name],

Thanks for your interest in QuickSecScan!

Quick answers:
- Scan time: 6–24 hours (typically 4–6h)
- Safe for production: Yes, non-intrusive only
- What you get: PDF report with severity breakdown + findings
- Refund: 50% if scan fails

Ready to start? [Payment Link]

Questions? Just reply.

—
QuickSecScan
support@quicksecscan.com
```

---

## **Customer Journey (Idempotent)**

### **Step 1: Payment Received**
**Trigger:** Stripe webhook `checkout.session.completed`

**Actions (Auto):**
1. Validate domain (DNS check)
2. Queue scan job
3. Log to monitoring inbox

**Manual Check:**
- Verify webhook fired: `docker-compose logs api | grep "Queueing scan"`

### **Step 2: Scan Execution**
**Duration:** 30 min–2 hours (depends on subdomain count)

**Actions (Auto):**
1. Subfinder → enumerate subdomains
2. HTTPx → probe live hosts
3. Nuclei → scan vulnerabilities
4. Save snapshot to S3

**Manual Check:**
- Watch progress: `docker-compose logs -f worker`
- If stuck > 2h: restart worker `docker-compose restart worker`

### **Step 3: Report Generation**
**Actions (Auto):**
1. Parse findings JSON
2. Render PDF from template
3. Upload to S3 (presigned URL, 30-day expiry)

**Manual Check:**
- Verify PDF exists: `aws s3 ls s3://quicksecscan-reports/reports/`

### **Step 4: Delivery**
**Actions (Auto):**
1. Email PDF link to customer
2. CC monitoring inbox
3. Mark job complete

**Manual Check:**
- Verify email sent: check doctormen131@outlook.com inbox
- If no email: check SendGrid Activity feed

---

## **Failure Scenarios (Idempotent Recovery)**

### **Scenario 1: Domain Not Resolvable**
**Symptoms:** Scan fails immediately, customer gets 50% refund email

**Actions:**
1. Verify: `dig customer-domain.com`
2. If DNS issue: email customer, offer re-run when fixed
3. If typo: manual refund + re-run with correct domain

**Idempotent Recovery:**
```bash
# Re-queue scan manually (if domain is now valid)
docker-compose exec api python -c "
from celery_app import scan_task
scan_task.delay(domain='customer-domain.com', customer_email='customer@example.com', session_id='manual_retry', tier='basic')
"
```

### **Scenario 2: Worker Crash Mid-Scan**
**Symptoms:** Job stuck in "in progress" state, no logs

**Actions:**
1. Check worker status: `docker ps | grep worker`
2. Restart worker: `docker-compose restart worker`
3. Re-queue job (idempotent — won't duplicate)

**Idempotent Recovery:**
```bash
# Find failed jobs
docker-compose exec redis redis-cli KEYS "*scan_task*"

# Re-queue (Celery will deduplicate)
docker-compose restart worker
```

### **Scenario 3: Zero Findings (Clean Scan)**
**Symptoms:** PDF shows "No issues found"

**Actions:**
1. Verify it's not a false negative (check raw Nuclei output in logs)
2. Send clean bill of health email (template in `celery_app.py`)
3. No refund needed (scan succeeded)

---

## **Refund Process (Idempotent)**

### **When to Refund:**
- Scan failed due to our error (not customer domain issue)
- Delivery > 24h (Basic) or > 12h (Pro) or > 6h (Team)
- Zero findings AND customer disputes (rare)

### **How to Refund (50%):**
```bash
# Via Stripe Dashboard
1. Go to payment: https://dashboard.stripe.com/payments/<session_id>
2. Click "Refund"
3. Enter 50% of amount
4. Reason: "Scan issue" or "Delivery SLA missed"
5. Click "Refund payment"
```

**Email Customer:**
```
Hi [Name],

We've processed a 50% refund for your QuickSecScan order.

Reason: [Scan failed / Delivery SLA missed]

Refund: $[amount] → original payment method (5–10 business days)

We apologize for the inconvenience. If you'd like to retry, reply and we'll prioritize your scan.

—
QuickSecScan
support@quicksecscan.com
```

---

## **Weekly Maintenance (30 min)**

### **Sunday Night Routine**
```bash
# 1. Update Nuclei templates
docker-compose exec worker nuclei -update-templates
docker-compose restart worker

# 2. Run snapshot analysis
docker-compose exec worker python snapshot_analyzer.py

# 3. Review tuning recommendations
cat tuning_recommendations_$(date +%Y%m%d).json

# 4. Backup snapshots
aws s3 sync s3://quicksecscan-reports/snapshots/ ~/backups/snapshots/

# 5. Check disk usage
docker system df
# If > 80%: docker system prune -af

# 6. Review week's metrics
# - Total scans: check Stripe Dashboard
# - Avg scan time: check logs
# - Failure rate: count "Scan failed" in logs
```

---

## **Scaling Operations**

### **At 50 scans/month (Current)**
- **Manual time:** ~1 hour/week
- **Worker config:** 2 concurrent jobs
- **Compute:** 1 server (2 vCPU, 4GB RAM)

### **At 100 scans/month**
- **Manual time:** ~2 hours/week
- **Worker config:** 4 concurrent jobs
- **Compute:** 1 server (4 vCPU, 8GB RAM)

### **At 200 scans/month**
- **Manual time:** ~4 hours/week (consider hire)
- **Worker config:** 8 concurrent jobs (2 servers)
- **Compute:** 2 servers or auto-scaling (Railway/Render)

---

## **Monitoring & Alerts (TODO)**

### **Setup Sentry (Errors)**
```python
# Add to webhook_handler.py
import sentry_sdk
sentry_sdk.init(dsn="https://...")
```

### **Setup Uptime Monitoring**
- Use UptimeRobot (free): https://uptimerobot.com
- Monitor: https://api.quicksecscan.com/health
- Alert: email if down > 5 min

### **Setup Revenue Alerts**
- Stripe → Settings → Notifications
- Enable: "Successful payments" → email

---

## **Command Reference (Idempotent)**

### **Restart All Services**
```bash
cd quicksecscan
docker-compose down
docker-compose up -d
```

### **View Live Logs**
```bash
docker-compose logs -f api worker
```

### **Manual Scan Trigger**
```bash
docker-compose exec api python -c "
from celery_app import scan_task
scan_task.delay(domain='example.com', customer_email='test@example.com', session_id='manual_test', tier='basic')
"
```

### **Check Queue Status**
```bash
docker-compose exec redis redis-cli
> LLEN celery  # Number of pending jobs
> KEYS *scan_task*  # List job IDs
```

### **Purge Failed Jobs**
```bash
docker-compose exec api celery -A celery_app purge
```

### **Update Code (Zero Downtime)**
```bash
cd quicksecscan
git pull
docker-compose build
docker-compose up -d  # Recreates containers
```

---

## **Incident Response**

### **P0: API Down**
1. Check health: `curl https://api.quicksecscan.com/health`
2. Check Docker: `docker ps`
3. Restart: `docker-compose restart api`
4. If still down: check logs, escalate to hosting provider

### **P1: No Scans Completing**
1. Check worker: `docker ps | grep worker`
2. Check logs: `docker-compose logs worker | tail -100`
3. Restart: `docker-compose restart worker`
4. If still failing: check Redis, reboot server

### **P2: Customer Complaint**
1. Find scan: `docker-compose logs worker | grep <customer-domain>`
2. Check S3 for report: `aws s3 ls s3://quicksecscan-reports/reports/<domain>/`
3. Re-send email manually if report exists
4. Re-run scan if report missing

---

## **Financial Tracking**

### **Monthly Revenue (Automated)**
- Stripe Dashboard → Balance → Payouts
- Export CSV for accounting

### **Monthly Costs (Manual)**
- Compute: Render/Railway invoice
- Storage: AWS S3 bill
- Email: SendGrid invoice
- **Total COGS:** ~$50–200/month (scales with volume)

### **Profit Margin**
- Revenue: scans × avg price ($300)
- COGS: $0.61/scan + fixed costs
- **Net margin: ~95%+**

---

## **Customer Success**

### **Upsell Opportunities**
- Basic → Pro: "Need faster delivery? Upgrade to 12h for $397"
- One-time → Monthly: "Scan weekly for $597/mo (4 scans)"
- Add-on: "Add 5 more domains for +$250"

### **Retention**
- Email 7 days after scan: "Found issues? We can rescan after fixes"
- Email 30 days after: "Time for a re-scan? Use code RESCAN20 for 20% off"

---

## **Legal & Compliance**

### **Terms Enforcement**
- Scope must be customer-owned (checked in consent)
- Non-intrusive only (no exploitation)
- Refund policy: 50% if we fail (not customer error)

### **Data Retention**
- Reports: 30 days (S3 presigned URL expiry)
- Snapshots: 90 days (for analysis)
- Logs: 7 days (Docker logs rotation)

---

## **Disaster Recovery**

### **Backup Strategy**
- **Code:** Git (GitHub)
- **Config:** `.env` backed up securely (1Password/Vault)
- **Data:** S3 versioning enabled
- **Snapshots:** Weekly sync to local backup

### **Recovery Time Objective (RTO)**
- **Target:** < 1 hour
- **Procedure:**
  1. Provision new server
  2. Clone repo: `git clone https://github.com/doctormen/quicksecscan`
  3. Restore `.env` from backup
  4. Run: `./deploy_idempotent.sh`
  5. Verify: `curl http://localhost:8000/health`

---

## **Contact**

- **Monitoring Email:** doctormen131@outlook.com
- **Customer Support:** support@quicksecscan.com
- **Emergency:** (Use monitoring email for now)

---

**Last Updated:** 2025-01-03  
**Version:** 1.0  
**Owner:** doctormen131@outlook.com

