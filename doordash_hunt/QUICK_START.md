# DoorDash Hunt - Quick Start Guide

## Hunter Profile

| Field | Value |
|-------|-------|
| **Username** | shadowstep_131 |
| **Email** | doctormen131@outlook.com |
| **Header** | `X-Bug-Bounty: shadowstep_131` |

---

## Step 1: Create Test Account

1. Go to https://www.doordash.com/
2. Click "Sign Up"
3. Use email: `shadowstep_131@wearehackerone.com`
4. For multiple accounts: `shadowstep_131+1@wearehackerone.com`

---

## Step 2: Configure Burp Suite

Add to Project Options > Sessions > Session Handling Rules:

```
X-Bug-Bounty: shadowstep_131
```

---

## Step 3: Run Automated Hunter

```bash
cd ~/Recon-automation-Bug-bounty-stack/doordash_hunt
python3 doordash_hunter.py
```

---

## Step 4: Manual Testing Priority

### Day 1-2: SSRF (Critical - $5k-$12k)

Test these endpoints for SSRF:
- Image upload (merchant logos)
- PDF export/receipt generation
- Webhook configurations
- URL preview features

Payloads:
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Day 3-4: IDOR (High - $1k-$5k)

Test ID parameters:
- `/api/v1/orders/{order_id}`
- `/api/v1/users/{user_id}`
- `/api/v1/addresses/{address_id}`
- `/api/v1/payments/{payment_id}`

### Day 5-6: Payment Logic (High - $1k-$5k)

Test race conditions:
- Promo code application
- Referral credits
- Refund requests
- Double-spending scenarios

### Day 7: XSS (Medium-High - $500-$5k)

Test input fields:
- Restaurant reviews
- Delivery instructions
- Merchant menu items
- Support ticket submissions

---

## Reporting Template

```markdown
## Summary
[One sentence describing the vulnerability]

## Severity
[Critical/High/Medium/Low] - [Estimated bounty range]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
[What an attacker could achieve]

## Proof of Concept
[cURL commands, screenshots]

## Remediation
[How to fix]
```

---

## Quick Commands

```bash
# Check if endpoints are alive
curl -I -H "X-Bug-Bounty: shadowstep_131" https://www.doordash.com

# Test GraphQL introspection
curl -X POST https://www.doordash.com/graphql \
  -H "Content-Type: application/json" \
  -H "X-Bug-Bounty: shadowstep_131" \
  -d '{"query":"{ __schema { types { name } } }"}'

# Test SSRF
curl "https://www.doordash.com/api/v1/image?url=http://169.254.169.254/" \
  -H "X-Bug-Bounty: shadowstep_131"
```

---

## Files Created

| File | Purpose |
|------|---------|
| `ELITE_ATTACK_PLAN.md` | Full 10-day attack strategy |
| `doordash_hunter.py` | Automated vulnerability scanner |
| `findings/` | Directory for discovered bugs |

---

## Expected Results

| Metric | Target |
|--------|--------|
| **Time Investment** | 10-14 days |
| **Reports Submitted** | 5-10 quality reports |
| **Hit Rate** | 30-40% |
| **Expected Bounty** | $2,000-$5,000 |

---

## ⚠️ Rules Reminder

- ❌ No automated scanners
- ❌ No DoS/brute force
- ❌ No pivoting after discovery
- ❌ No public disclosure
- ✅ Add `X-Bug-Bounty: shadowstep_131` to ALL requests
- ✅ Use @wearehackerone.com email for accounts

---

*Hunt smart. Report clean. Get paid.* 🎯
