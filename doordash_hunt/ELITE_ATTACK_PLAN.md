# DoorDash Elite Attack Plan

**Hunter:** shadowstep_131  
**Email:** doctormen131@outlook.com  
**Header:** `X-Bug-Bounty: shadowstep_131`

---

## 🎯 Target Analysis

### Tech Stack (from their engineering blog)
- **Legacy:** Python/Django monolith
- **Current:** Microservices (Kotlin, Go, Java)
- **Frontend:** React.js
- **Mobile:** iOS (Swift), Android (Kotlin)

### Business Logic Understanding
- **Consumer:** Orders food, pays, tracks delivery
- **Dasher:** Accepts orders, delivers, receives payout
- **Merchant:** Manages menu, receives orders, gets paid

**KEY INSIGHT:** The money flows from Consumer → DoorDash → Merchant/Dasher. Any bug that touches this flow = CRITICAL.

---

## 💰 Bounty Maximization Strategy

### Tier 1: Critical ($5,000-$12,000)

| Attack Vector | Target | Why It's Critical |
|---------------|--------|-------------------|
| **SSRF → AWS Metadata** | API endpoints | IMDSv1 → creds → RCE |
| **GraphQL Injection** | `/graphql` | Mass data exfil |
| **OAuth Flow Hijack** | Social login | Full ATO |
| **Payment Bypass** | Checkout flow | Free food = fraud |
| **Mass IDOR** | Order/User APIs | PII at scale |

### Tier 2: High ($1,000-$5,000)

| Attack Vector | Target | Impact |
|---------------|--------|--------|
| **Stored XSS** | Merchant dashboard | Admin takeover |
| **IDOR in Payout** | Dasher endpoints | Financial data |
| **Race Condition** | Promo codes | Money manipulation |
| **JWT Confusion** | Auth tokens | Role escalation |

---

## 🔥 Elite Attack Playbook

### Phase 1: Reconnaissance (Day 1)

```
1. Map all API endpoints via:
   - Burp crawl on www.doordash.com
   - Mobile app traffic (iOS + Android)
   - JS file analysis for hidden APIs
   
2. Identify GraphQL:
   - /graphql introspection
   - Schema extraction
   - Mutation enumeration

3. Auth flow analysis:
   - Session token structure (JWT?)
   - OAuth providers (Google, Apple, Facebook)
   - Password reset flow
   - 2FA implementation
```

### Phase 2: SSRF Hunting (Day 2-3)

**Why SSRF?** DoorDash uses AWS. SSRF → metadata = instant critical.

```
Target Parameters:
- url, uri, path, dest, redirect
- webhook, callback, return_url
- image, avatar, logo
- pdf, export, download

Payloads:
- http://169.254.169.254/latest/meta-data/
- http://[::ffff:169.254.169.254]/
- http://169.254.169.254.xip.io/
- file:///etc/passwd
- gopher://localhost:6379/_INFO

Focus Areas:
- Merchant logo upload
- Receipt PDF generation
- Webhook configurations
- Image proxy endpoints
```

### Phase 3: IDOR/Authorization (Day 4-5)

**Horizontal Escalation:**
```
1. Create 2 test accounts (consumer)
2. Capture order_id, user_id, address_id
3. Swap IDs between accounts
4. Check access to:
   - Other users' orders
   - Other users' addresses
   - Other users' payment methods
   - Other users' order history
```

**Vertical Escalation:**
```
1. Consumer → Merchant access
2. Consumer → Dasher access
3. Dasher → Merchant access
4. Any role → Admin access

Parameters to manipulate:
- role, user_type, account_type
- is_admin, is_merchant, is_dasher
- permissions[], scopes[]
```

### Phase 4: Payment/Business Logic (Day 6-7)

**Race Conditions:**
```python
# Promo code double-spend
import threading
import requests

def apply_promo():
    requests.post(
        "https://api.doordash.com/v2/promo/apply",
        headers={"X-Bug-Bounty": "shadowstep_131"},
        json={"code": "DISCOUNT50", "order_id": "xxx"}
    )

threads = [threading.Thread(target=apply_promo) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

**Price Manipulation:**
```
1. Add items to cart
2. Intercept checkout request
3. Modify: item_price, subtotal, tip_amount, delivery_fee
4. Check if backend validates
```

**Refund Abuse:**
```
1. Complete order
2. Request refund
3. Check if order marked as refunded but food still delivered
4. Check double refund possibility
```

### Phase 5: XSS Hunting (Day 8-9)

**High-Value Targets:**
```
- Merchant menu item names/descriptions
- Restaurant reviews
- Dasher notes
- Promo code names (admin views)
- Support ticket content
```

**Payloads for WAF bypass:**
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

---

## 🛠️ Tool Configuration

### Burp Suite Extensions
- Autorize (auth testing)
- Param Miner (hidden params)
- GraphQL Raider (GraphQL testing)
- JSON Web Token Attacker
- Active Scan++

### Custom Headers (ALL REQUESTS)
```
X-Bug-Bounty: shadowstep_131
User-Agent: Mozilla/5.0 (shadowstep_131 Security Research)
```

---

## 📝 Triager's Perspective

**What makes a WINNING report:**

1. **Clear Impact Statement**
   - "This allows attacker to..."
   - Include $ value if financial impact

2. **Clean PoC**
   - Step-by-step reproduction
   - cURL commands
   - Screenshots with timestamps

3. **Business Context**
   - "Affects X million users"
   - "Could result in $X fraud"

4. **No Fluff**
   - Technical, concise
   - Skip the "dear security team" intro

---

## 🚫 Avoid These (Waste of Time)

- Missing security headers alone
- Rate limiting issues
- Self-XSS
- CSRF on non-sensitive actions
- Leaked creds from third-party breaches
- Open redirect without chain

---

## 📊 Success Metrics

| Metric | Target |
|--------|--------|
| Reports Submitted | 5-10 quality reports |
| Expected Hit Rate | 30-40% |
| Expected Bounty | $2,000-$5,000 total |
| Time Investment | 2 weeks focused |

---

## 🎯 Day-by-Day Schedule

| Day | Focus | Goal |
|-----|-------|------|
| 1 | Recon & Mapping | Full API inventory |
| 2-3 | SSRF Hunting | Find AWS metadata access |
| 4-5 | IDOR/AuthZ | Cross-account access |
| 6-7 | Payment Logic | Race conditions, price manipulation |
| 8-9 | XSS/Injection | Stored XSS in merchant/admin |
| 10 | Report Writing | Submit best findings |

---

## ⚡ Quick Wins Checklist

- [ ] GraphQL introspection enabled?
- [ ] IDOR in order_id parameter?
- [ ] JWT none algorithm accepted?
- [ ] Password reset token predictable?
- [ ] Promo code race condition?
- [ ] SSRF in image upload?
- [ ] Subdomain takeover on *.doordash.com?
- [ ] Debug endpoints exposed?
- [ ] API versioning issues (v1 vs v2)?
- [ ] Mobile app hardcoded secrets?

---

*"The best hunters don't find bugs. They understand the business, then find where the business logic breaks."*
