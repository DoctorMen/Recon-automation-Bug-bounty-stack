<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# QuickSecScan — 15-Minute Quickstart

**Get your volume security scanning business live in 15 minutes.**

---

## **What You're Building**

A **$197–$797 automated security scanning service** that:
- Takes Stripe payments automatically
- Scans customer domains with HTTPx + Nuclei
- Generates PDF reports and emails them
- Runs 50–200 scans/month with 95%+ margins

---

## **Prerequisites (5 min)**

1. **Docker installed:** `docker --version`
2. **Stripe account:** [dashboard.stripe.com](https://dashboard.stripe.com)
3. **AWS S3 bucket:** [console.aws.amazon.com/s3](https://console.aws.amazon.com/s3) (or Cloudflare R2)
4. **SendGrid account:** [sendgrid.com](https://sendgrid.com) (free tier OK)

---

## **Step 1: Deploy Backend (5 min)**

```bash
# Clone the repo
cd ~/Recon-automation-Bug-bounty-stack/quicksecscan

# Copy and edit environment
cp env.example .env
nano .env  # Fill in your API keys

# Deploy (idempotent)
chmod +x deploy_idempotent.sh
./deploy_idempotent.sh
```

**Verify:**
```bash
curl http://localhost:8000/health
# Should return: {"status":"healthy","service":"quicksecscan-backend"}
```

---

## **Step 2: Create Stripe Products (3 min)**

Go to [Stripe Dashboard → Products](https://dashboard.stripe.com/products):

**Basic ($197):**
- Name: `QuickSecScan — Basic`
- Price: One-time, $197 USD
- Create Payment Link
- Copy URL: `https://buy.stripe.com/...`

**Pro ($397):**
- Name: `QuickSecScan — Pro`
- Price: One-time, $397 USD
- Create Payment Link
- Copy URL

**Team ($797):**
- Name: `QuickSecScan — Team`
- Price: One-time, $797 USD
- Create Payment Link
- Copy URL

---

## **Step 3: Wire Payment Links (1 min)**

Edit `site/config.js`:
```javascript
window.quickSecConfig = {
  stripeBasicUrl: 'https://buy.stripe.com/YOUR_BASIC_LINK',
  stripeProUrl: 'https://buy.stripe.com/YOUR_PRO_LINK',
  stripeTeamUrl: 'https://buy.stripe.com/YOUR_TEAM_LINK',
};
```

---

## **Step 4: Setup Stripe Webhook (2 min)**

1. Go to [Stripe Webhooks](https://dashboard.stripe.com/webhooks)
2. Click "+ Add endpoint"
3. **Endpoint URL:** `https://your-domain.com/webhook/stripe`
   - For local testing: use [ngrok](https://ngrok.com): `ngrok http 8000`
   - Use the ngrok URL: `https://abc123.ngrok.io/webhook/stripe`
4. **Events:** Select `checkout.session.completed`
5. **Copy webhook signing secret** (starts with `whsec_...`)
6. Add to `.env`: `STRIPE_WEBHOOK_SECRET=whsec_...`
7. Restart: `docker-compose restart api worker`

---

## **Step 5: Deploy Site (2 min)**

**Option A: GitHub Pages**
```bash
cd site
gh repo create quicksecscan-site --public --source=. --push
# Enable Pages: repo Settings → Pages → Source: main
```

**Option B: Local test**
```bash
cd site
python3 -m http.server 8080
# Open: http://localhost:8080
```

---

## **Step 6: Test End-to-End (2 min)**

1. **Pay with test card:**
   - Open your site: `http://localhost:8080` or GitHub Pages URL
   - Click "Buy Basic"
   - Use test card: `4242 4242 4242 4242`
   - Enter domain in Stripe metadata: `example.com`

2. **Check webhook fired:**
   ```bash
   docker-compose logs api | grep "Queueing scan"
   # Should see: "Queueing scan for example.com"
   ```

3. **Watch scan progress:**
   ```bash
   docker-compose logs -f worker
   # Should see: subfinder → httpx → nuclei → PDF generation
   ```

4. **Check email:**
   - Report PDF should arrive at your email
   - Check spam folder if not in inbox

---

## **You're Live! 🎉**

**Next Steps:**

1. **Replace test Stripe with live mode:**
   - Stripe Dashboard → toggle "Test mode" OFF
   - Create new live Payment Links
   - Update `site/config.js`
   - Update webhook endpoint (use production domain)

2. **Deploy to production:**
   - Host backend: [Render.com](https://render.com), [Railway.app](https://railway.app), or AWS
   - Host site: GitHub Pages, Netlify, or custom domain

3. **Marketing:**
   - Post on Reddit (r/startups, r/SaaS)
   - Launch on Product Hunt
   - Create Upwork catalog listing (like ScopeLock)
   - Twitter thread with launch offer

4. **Monitor:**
   - Check `docker-compose logs` daily
   - Review Stripe Dashboard for payments
   - Check SendGrid Activity for email delivery

---

## **Troubleshooting**

### **Webhook not firing?**
- Check Stripe Dashboard → Webhooks → Recent deliveries
- Verify endpoint URL is correct
- Test with Stripe CLI: `stripe listen --forward-to localhost:8000/webhook/stripe`

### **Scan stuck?**
- Restart worker: `docker-compose restart worker`
- Check logs: `docker-compose logs worker`

### **No email?**
- Check SendGrid API key in `.env`
- Verify FROM_EMAIL is verified sender in SendGrid
- Check spam folder

---

## **Support**

- **Email:** doctormen131@outlook.com
- **Docs:** See `README.md` and `docs/OPERATIONS_RUNBOOK.md`

---

**Estimated Time to First Dollar:** < 24 hours after launching marketing  
**Estimated Monthly Revenue (at 50 scans/month):** $15,000+  
**Estimated Monthly Costs:** < $200 (compute + storage + email)  
**Net Profit Margin:** 95%+

**Now go make money.** 🚀

