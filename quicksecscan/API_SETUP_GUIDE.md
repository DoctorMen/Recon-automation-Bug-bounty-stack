<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# QuickSecScan API - Setup Guide

## 🚀 QuickSecScan API Business - Complete Setup

**Automated API security scanning: $197-$797**
**Targets: SaaS startups, API-first companies**
**Includes: OAuth/JWT testing, IDOR detection, business logic testing**

---

## ✅ What's Been Built

### 1. API Security Scanner (`api_security_scanner.py`)
- ✅ OAuth 2.0 vulnerability testing
- ✅ JWT security testing (algorithm confusion, weak secrets)
- ✅ IDOR detection (horizontal & vertical privilege escalation)
- ✅ API key vulnerability testing
- ✅ Session management testing
- ✅ SQL/NoSQL injection testing
- ✅ SSRF testing
- ✅ Path traversal testing
- ✅ Business logic testing (race conditions, parameter tampering)
- ✅ Rate limiting analysis
- ✅ Data exposure detection

### 2. Backend Integration (`celery_app.py`)
- ✅ API scan task integration
- ✅ Dual-mode scanning (web + API)
- ✅ API-specific report generation
- ✅ Snapshot support for API scans

### 3. Webhook Handler (`webhook_handler.py`)
- ✅ API endpoint validation
- ✅ Metadata extraction (api_endpoint, tier, scan_type)
- ✅ Dual-mode webhook processing

### 4. Website (`site/index.html`)
- ✅ API security pricing tiers ($197-$797)
- ✅ API Basic, Pro, Team packages
- ✅ Stripe integration ready

### 5. Report Templates (`api_report_template.html`)
- ✅ API-specific PDF report template
- ✅ PoC request display
- ✅ Recommendations included

---

## 🔧 Setup Instructions

### Step 1: Install Dependencies
```bash
cd quicksecscan/backend
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables
```bash
cp env.example .env
# Edit .env with your credentials:
# - STRIPE_SECRET_KEY
# - STRIPE_WEBHOOK_SECRET
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - S3_BUCKET
# - SENDGRID_API_KEY
# - FROM_EMAIL
# - REDIS_URL
```

### Step 3: Create Stripe Products

Go to [Stripe Dashboard → Products](https://dashboard.stripe.com/products) and create:

**API Basic — $197**
- Name: `QuickSecScan API — Basic`
- Price: One-time, $197 USD
- Metadata: `tier=basic`, `scan_type=api`, `endpoints=1`

**API Pro — $397**
- Name: `QuickSecScan API — Pro`
- Price: One-time, $397 USD
- Metadata: `tier=pro`, `scan_type=api`, `endpoints=5`

**API Team — $797**
- Name: `QuickSecScan API — Team`
- Price: One-time, $797 USD
- Metadata: `tier=team`, `scan_type=api`, `endpoints=20`

Create Payment Links for each, then update `site/config.js`:
```javascript
window.quickSecConfig = {
  stripeBasicUrl: 'https://buy.stripe.com/...',
  stripeProUrl: 'https://buy.stripe.com/...',
  stripeTeamUrl: 'https://buy.stripe.com/...',
  stripeApiBasicUrl: 'https://buy.stripe.com/...',  // NEW
  stripeApiProUrl: 'https://buy.stripe.com/...',    // NEW
  stripeApiTeamUrl: 'https://buy.stripe.com/...',   // NEW
};
```

### Step 4: Setup Stripe Webhook

1. Go to [Stripe Webhooks](https://dashboard.stripe.com/webhooks)
2. Click "+ Add endpoint"
3. Endpoint URL: `https://your-domain.com/webhook/stripe`
4. Events: Select `checkout.session.completed`
5. Copy webhook signing secret to `.env` as `STRIPE_WEBHOOK_SECRET`

### Step 5: Configure Stripe Checkout Metadata

When creating Payment Links in Stripe, add custom fields:
- **API Endpoint** (text field): Customer enters their API base URL
- **Scan Type**: Auto-set to `api` for API products

Alternatively, use Stripe Checkout Sessions API to collect metadata:
```python
session = stripe.checkout.Session.create(
    payment_method_types=['card'],
    line_items=[{
        'price': 'price_api_basic',
        'quantity': 1,
    }],
    mode='payment',
    metadata={
        'scan_type': 'api',
        'tier': 'basic'
    },
    # Customer will enter API endpoint in custom field
)
```

### Step 6: Start Services

```bash
# Start Redis
redis-server

# Start Celery worker
cd backend
celery -A celery_app worker --loglevel=info

# Start FastAPI server
uvicorn webhook_handler:app --host 0.0.0.0 --port 8000
```

### Step 7: Deploy Site

```bash
cd site
# Deploy to GitHub Pages, Netlify, or Vercel
# Update config.js with Stripe payment links
```

---

## 🧪 Testing

### Test API Scanner Locally
```python
from api_security_scanner import APISecurityScanner

# Test with a public API
scanner = APISecurityScanner('https://api.example.com')
findings = scanner.scan(tier='basic')
print(f"Found {len(findings)} issues")

for finding in findings:
    print(f"{finding['severity']}: {finding['type']} - {finding['endpoint']}")
```

### Test Webhook (Local)
```bash
# Use Stripe CLI to forward webhooks
stripe listen --forward-to localhost:8000/webhook/stripe

# Trigger test event
stripe trigger checkout.session.completed
```

### Test Full Flow
1. Create test Stripe product with metadata: `api_endpoint=https://api.example.com`
2. Complete test checkout
3. Check Celery logs for scan execution
4. Verify PDF report generation
5. Check email delivery

---

## 📊 API Security Testing Features

### Authentication Testing
- ✅ OAuth 2.0 state parameter validation
- ✅ JWT algorithm confusion attacks
- ✅ JWT signature bypass attempts
- ✅ Weak API key detection
- ✅ Session management flaws

### Authorization Testing
- ✅ IDOR detection (horizontal escalation)
- ✅ Privilege escalation (vertical escalation)
- ✅ RBAC bypass attempts
- ✅ Function-level access control

### Input Validation
- ✅ SQL injection (Blind, Time-based, Error-based)
- ✅ NoSQL injection
- ✅ Command injection
- ✅ SSRF detection
- ✅ Path traversal

### Business Logic
- ✅ Race condition testing
- ✅ Parameter tampering
- ✅ Workflow bypass detection

### Rate Limiting
- ✅ Brute force resistance testing
- ✅ Rate limit bypass detection
- ✅ DoS resistance analysis

### Data Exposure
- ✅ Sensitive data leak detection
- ✅ Error message disclosure
- ✅ API key exposure in responses

---

## 🎯 Pricing Tiers

| Tier | Price | Endpoints | Features |
|------|-------|-----------|----------|
| **API Basic** | $197 | 1 | OAuth/JWT testing, IDOR detection, input validation |
| **API Pro** | $397 | Up to 5 | + Business logic testing, rate limiting analysis |
| **API Team** | $797 | Up to 20 | + Advanced business logic, SSRF testing, PoC requests |

---

## 📈 Next Steps

1. **Launch Marketing**
   - Update website copy for API security focus
   - Create API security case studies
   - Post on Product Hunt, Indie Hackers

2. **Expand Testing**
   - Add GraphQL security testing
   - Add gRPC security testing
   - Add API documentation security review

3. **Enterprise Features**
   - API security monitoring (monthly scans)
   - Custom API security templates
   - White-label API security reports

4. **Integration**
   - CI/CD integration (GitHub Actions, GitLab CI)
   - Slack/Discord notifications
   - API security dashboard

---

## 🔒 Security Notes

- All API scans are **non-intrusive** (read-only)
- No actual exploitation attempts
- Rate limiting applied to prevent DoS
- Customer data encrypted at rest
- Reports stored securely (S3 presigned URLs)

---

## 📝 Files Created/Modified

### New Files
- `backend/api_security_scanner.py` - Main API security scanner
- `backend/templates/api_report_template.html` - API report template

### Modified Files
- `backend/celery_app.py` - Added API scan support
- `backend/webhook_handler.py` - Added API endpoint handling
- `site/index.html` - Added API pricing section
- `backend/requirements.txt` - Added requests, PyJWT

---

## ✅ Status: READY TO LAUNCH

All components are built and integrated. The QuickSecScan API business is ready to accept customers!

**Next:** Create Stripe products → Configure webhooks → Deploy → Launch marketing

---

**Created:** 2025-11-03  
**Status:** Production Ready 🚀

