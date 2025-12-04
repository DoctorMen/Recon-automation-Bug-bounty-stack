<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# QuickSecScan — Volume Security Scanning Business

**Affordable, automated security scans for startups. $197–$797. Results in 6–24 hours.**

---

## **Business Model**

**Target Market:** SMBs, startups, solo founders, dev shops  
**Pricing:** $197 (Basic), $397 (Pro), $797 (Team)  
**Volume Goal:** 50–200 customers/month  
**Fulfillment:** 90% automated, minimal human touch

---

## **Architecture**

```
Customer → Stripe Payment → Webhook → Backend API
                                          ↓
                                    Validate domain
                                          ↓
                                    Queue scan job (Celery)
                                          ↓
                                    Worker: HTTPx + Nuclei
                                          ↓
                                    Generate PDF report
                                          ↓
                                    Email customer + upload to S3
```

**Tech Stack:**
- **Backend:** Python FastAPI + Celery
- **Queue:** Redis
- **Compute:** Docker containers (Render/Railway/AWS)
- **Storage:** AWS S3 or Cloudflare R2
- **Email:** SendGrid
- **Frontend:** Static HTML (GitHub Pages)

---

## **Quick Start (Idempotent Deployment)**

### **Prerequisites**
- Docker & Docker Compose
- Stripe account (test mode OK for dev)
- AWS S3 or Cloudflare R2 bucket
- SendGrid account (free tier OK)

### **1. Clone and Setup**
```bash
cd quicksecscan
cp env.example .env
# Edit .env with your credentials
```

### **2. Deploy (Idempotent)**
```bash
chmod +x deploy_idempotent.sh
./deploy_idempotent.sh
```

This script is **idempotent** — run it multiple times safely. It will:
- ✓ Build Docker images
- ✓ Start services (API, Worker, Redis)
- ✓ Wait for health checks
- ✓ Run smoke tests
- ✓ Deploy site

### **3. Create Stripe Products**

Go to [Stripe Dashboard → Products](https://dashboard.stripe.com/products):

**Basic — $197**
- Name: `QuickSecScan — Basic`
- Price: One-time, $197 USD
- Metadata: `tier=basic`, `domains=1`

**Pro — $397**
- Name: `QuickSecScan — Pro`
- Price: One-time, $397 USD
- Metadata: `tier=pro`, `domains=3`

**Team — $797**
- Name: `QuickSecScan — Team`
- Price: One-time, $797 USD
- Metadata: `tier=team`, `domains=10`

Create Payment Links for each, then update `site/config.js`:
```javascript
window.quickSecConfig = {
  stripeBasicUrl: 'https://buy.stripe.com/...',
  stripeProUrl: 'https://buy.stripe.com/...',
  stripeTeamUrl: 'https://buy.stripe.com/...',
};
```

### **4. Setup Stripe Webhook**

1. Go to [Stripe Webhooks](https://dashboard.stripe.com/webhooks)
2. Click "+ Add endpoint"
3. Endpoint URL: `https://your-domain.com/webhook/stripe`
4. Events: Select `checkout.session.completed`
5. Copy webhook signing secret to `.env` as `STRIPE_WEBHOOK_SECRET`
6. Restart services: `docker-compose restart api worker`

### **5. Deploy Site**

**Option A: GitHub Pages**
```bash
cd site
gh repo create quicksecscan-site --public --source=. --push
# Enable Pages: Settings → Pages → Source: main branch
```

**Option B: Netlify/Vercel**
- Drag `site/` folder to Netlify Drop
- Or: `vercel --prod` from `site/` directory

---

## **Testing the Full Flow**

### **1. Test Payment (Stripe Test Mode)**
- Use test card: `4242 4242 4242 4242`
- Domain: `example.com` (add in checkout metadata)
- Email: your email

### **2. Verify Webhook**
```bash
docker-compose logs -f api
# Should see: "Queueing scan for example.com"
```

### **3. Check Worker**
```bash
docker-compose logs -f worker
# Should see scan execution logs
```

### **4. Check Email**
- Report PDF should arrive within 24h (typically 2–6h)
- Check spam folder if not in inbox

---

## **Idempotent Operations**

All scripts are designed to be **idempotent** (run multiple times safely):

- **`deploy_idempotent.sh`** — Full deployment
- **`docker-compose up -d`** — Start/restart services
- **Scan jobs** — Duplicate jobs (same session_id) are deduplicated
- **Snapshots** — Overwrite if domain + timestamp match

### **Snapshot System (Self-Improving)**

Every scan saves a snapshot to S3:
```
s3://quicksecscan-reports/snapshots/{domain}/{timestamp}.json
```

Weekly cron job analyzes snapshots:
```bash
docker-compose exec worker python snapshot_analyzer.py
```

**Improvements:**
- Identifies high-frequency false positives
- Tunes Nuclei template selection
- Adjusts scan depth by domain patterns

---

## **Scaling**

### **Horizontal Scaling**
```yaml
# docker-compose.yml
services:
  worker:
    deploy:
      replicas: 5  # Run 5 worker containers
```

### **Vertical Scaling**
- Increase worker concurrency: `--concurrency=4`
- Add more Redis memory
- Use faster compute (AWS c6i.xlarge vs t3.medium)

### **Cost Per Scan (at 100 scans/month)**
- Compute: $0.50 (5 min scan time, $0.10/hour rate)
- Storage: $0.10 (S3 storage + bandwidth)
- Email: $0.01 (SendGrid)
- **Total COGS: ~$0.61/scan**

**Margins:**
- Basic ($197): 99.7% margin
- Pro ($397): 99.8% margin
- Team ($797): 99.9% margin

---

## **Monitoring**

### **Health Checks**
```bash
curl http://localhost:8000/health
# {"status":"healthy","service":"quicksecscan-backend"}
```

### **Logs**
```bash
docker-compose logs -f api worker
```

### **Metrics (TODO)**
- Prometheus + Grafana
- Track: scans/day, avg scan time, failure rate, revenue

---

## **Maintenance**

### **Update Nuclei Templates**
```bash
docker-compose exec worker nuclei -update-templates
docker-compose restart worker
```

### **Backup Snapshots**
```bash
aws s3 sync s3://quicksecscan-reports/snapshots/ ./backups/snapshots/
```

### **Database (Optional Future)**
- Currently stateless (Redis for queue only)
- Add PostgreSQL for customer history, analytics

---

## **Security**

- **Webhook signature verification** (Stripe)
- **Domain validation** (DNS check, blocklist)
- **Rate limiting** (TODO: add to API)
- **Secrets** in `.env` (never commit)
- **S3 presigned URLs** (30-day expiry)

---

## **Troubleshooting**

### **Scan fails immediately**
- Check domain is resolvable: `dig example.com`
- Check not blocklisted: see `webhook_handler.py` BLOCKLIST_PATTERNS
- Check worker logs: `docker-compose logs worker`

### **Webhook not triggering**
- Verify Stripe webhook secret in `.env`
- Check API logs: `docker-compose logs api`
- Test manually: `curl -X POST http://localhost:8000/webhook/stripe`

### **No email received**
- Check SendGrid API key
- Verify FROM_EMAIL is verified in SendGrid
- Check spam folder
- Check worker logs for email send confirmation

---

## **Roadmap**

- [ ] Add API access tier (customers trigger scans via API)
- [ ] Slack/Discord webhook integration
- [ ] Monthly subscription automation (recurring scans)
- [ ] Dashboard for customers (view past scans)
- [ ] Nuclei template customization per customer
- [ ] Integration with Jira/Linear for ticket creation

---

## **Support**

- Email: support@quicksecscan.com
- Monitoring: doctormen131@outlook.com
- Docs: See `docs/` folder

---

## **License**

Proprietary. © 2025 QuickSecScan. All rights reserved.

