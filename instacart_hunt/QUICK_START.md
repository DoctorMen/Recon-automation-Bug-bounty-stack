# Instacart Hunt - Quick Start

## Hunter Profile

| Field | Value |
|-------|-------|
| **Username** | shadowstep_131 |
| **Email** | doctormen131@outlook.com |
| **Header** | `X-Bug-Bounty: shadowstep_131` |

---

## Step 1: Get Auth Tokens

### Customer Account
1. Go to https://www.instacart.com/
2. Sign up with `shadowstep_131@wearehackerone.com`
3. Complete onboarding
4. Use Burp Suite to capture: `Authorization: Bearer eyJ...`

### Shopper Account  
1. Apply as shopper: `shadowstep_131+1@wearehackerone.com`
2. Complete registration
3. Capture shopper token from API calls

### Merchant Account
1. Register retailer: `shadowstep_131+2@wearehackerone.com`
2. Access merchant dashboard
3. Capture merchant token

*See AUTH_TOKEN_GUIDE.md for detailed instructions*

---

## Step 2: Configure Hunter

```python
# Edit instacart_hunter.py or set tokens directly
hunter = InstacartHunter()
hunter.set_auth_tokens(
    customer="Bearer YOUR_CUSTOMER_TOKEN",
    shopper="Bearer YOUR_SHOPPER_TOKEN", 
    merchant="Bearer YOUR_MERCHANT_TOKEN"
)
```

---

## Step 3: Run Hunt

```bash
cd ~/Recon-automation-Bug-bounty-stack/instacart_hunt

# Run automated hunter
python3 instacart_hunter.py

# View findings
cat findings/*.md
```

---

## Priority Targets

| Attack | Bounty | Focus |
|--------|--------|-------|
| **Tip Race Condition** | $2,000-$6,000 | Modify tips concurrently |
| **Promo Stacking** | $1,000-$3,000 | Apply multiple promos |
| **Cross-Role IDOR** | $500-$2,000 | Customer → Shopper data |
| **GraphQL Auth Bypass** | $1,000-$3,000 | Query unauthorized data |

---

## Expected Timeline

| Day | Activity | Goal |
|-----|----------|-------|
| **1** | Account setup + tokens | 3 role tokens |
| **2-3** | IDOR testing | Cross-role access |
| **4-5** | Race conditions | Tip/promo abuse |
| **6-7** | GraphQL testing | Auth bypass |
| **8-10** | Report writing | Submit findings |

---

## Quick Commands

```bash
# Test tokens manually
curl -H "Authorization: Bearer TOKEN" \
     -H "X-Bug-Bounty: shadowstep_131" \
     https://api.instacart.com/v1/user

# GraphQL introspection
curl -X POST https://api.instacart.com/graphql \
     -H "Authorization: Bearer TOKEN" \
     -H "X-Bug-Bounty: shadowstep_131" \
     -d '{"query":"{ __schema { queryType { name } } }"}'
```

---

## Files Created

| File | Purpose |
|------|---------|
| `INSTACART_ELITE_ATTACK_PLAN.md` | 10-day attack strategy |
| `instacart_hunter.py` | Automated scanner |
| `AUTH_TOKEN_GUIDE.md` | Token acquisition guide |
| `findings/` | Store discovered bugs |

---

## Expected Bounty

| Finding Type | Count | Bounty Range | Total |
|--------------|-------|--------------|-------|
| IDOR | 2-3 | $500-$2,000 | $3,000 |
| Race Conditions | 1-2 | $2,000-$6,000 | $6,000 |
| GraphQL | 1 | $1,000-$3,000 | $2,000 |
| **Expected Total** | | | **$11,000** |

---

## ⚠️ Rules Reminder

- ✅ Use `X-Bug-Bounty: shadowstep_131` header
- ✅ Use @wearehackerone.com email
- ✅ Only test within scope
- ❌ No production disruption
- ❌ No automated scanners

---

*Ready to hunt? Get those tokens first.* 🎯
