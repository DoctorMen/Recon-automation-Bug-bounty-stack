<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🎯 MANUAL TESTING PLAYBOOK
## Step-by-Step Guide for Finding HIGH/CRITICAL Bugs

**Time per target:** 8-12 hours  
**Success rate:** 10-30% find MEDIUM+  
**Expected payout:** $5K-$50K when successful

---

## 📋 PRE-HUNT CHECKLIST

Before starting ANY hunt:

- [ ] Target has active bug bounty program (confirmed)
- [ ] Bounty pool > $25,000
- [ ] You have 10+ hours available
- [ ] Authorization file created (`authorizations/target.json`)
- [ ] Burp Suite open and configured
- [ ] Notebook ready for documentation
- [ ] Tools tested and working

---

## ⏰ HOUR-BY-HOUR WORKFLOW

### **HOUR 1: Initial Reconnaissance**

#### **1.1 Technology Stack Identification (15 min)**

```bash
# Identify technologies
whatweb https://target.com -a 3

# Check headers
curl -I https://target.com

# Framework detection
# Look at page source, check for:
# - React/Vue/Angular (client-side frameworks)
# - Next.js/Nuxt (SSR frameworks)
# - GraphQL endpoints
# - API documentation links
```

**Document:**
- Frontend framework
- Backend technology (if visible)
- API type (REST, GraphQL, both)
- Authentication method (JWT, session, OAuth)

#### **1.2 Subdomain/Path Discovery (20 min)**

```bash
# Find subdomains
subfinder -d target.com -silent | httpx -silent

# Discover paths
katana -u https://target.com -d 3 -jc -silent

# Common API paths
curl https://target.com/api
curl https://target.com/swagger.json
curl https://target.com/openapi.json
curl https://target.com/.well-known/
```

**Document:**
- All live subdomains
- All discovered paths
- API documentation URLs
- Interesting endpoints

#### **1.3 Authentication Flow Mapping (25 min)**

**Critical - This is where auth bypass bugs hide!**

1. **Create test account**
   - Register new user
   - Note all fields required
   - Check email verification process

2. **Capture login flow in Burp**
   - Login with test account
   - Inspect all requests/responses
   - Note authentication token type
   - Check token format (JWT, session ID, custom)

3. **Test token behavior**
   - Copy token value
   - Where is it stored? (localStorage, cookie, header)
   - How long does it last?
   - Can you decode it? (JWT.io for JWTs)

**Document:**
- Registration endpoint
- Login endpoint
- Token type and format
- Token expiration
- Where token is sent (header, cookie, etc.)

---

### **HOUR 2: API Endpoint Mapping**

#### **2.1 Find ALL API Endpoints (30 min)**

**Method 1: Browse the app with Burp running**
- Click every button
- Navigate every page
- Fill out every form
- Watch Burp HTTP history

**Method 2: Check for API documentation**
```bash
# Swagger/OpenAPI
curl https://target.com/swagger.json | jq '.'
curl https://target.com/api-docs | jq '.'

# GraphQL
curl https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

**Method 3: Path fuzzing**
```bash
# Use ffuf or similar
ffuf -w /path/to/api-wordlist.txt \
  -u https://target.com/api/FUZZ \
  -mc 200,201,401,403
```

#### **2.2 Categorize Endpoints (30 min)**

**Create a spreadsheet or document with:**

| Endpoint | Method | Auth Required? | Purpose | Parameters |
|----------|--------|----------------|---------|------------|
| /api/v1/user/{id} | GET | Yes | Get user data | id (numeric) |
| /api/v1/swap | POST | Yes | Token swap | amount, token_in, token_out |
| /api/v1/rewards/claim | POST | Yes | Claim rewards | None |

**Prioritize:**
1. **Financial endpoints** (swap, transfer, withdraw)
2. **User data endpoints** (profile, settings, KYC)
3. **Admin endpoints** (/admin, /internal, /debug)
4. **Sensitive operations** (password reset, 2FA, email change)

---

### **HOUR 3-4: Authentication & Authorization Testing**

#### **3.1 Test EVERY Protected Endpoint (60 min)**

**For EACH endpoint in your list, test:**

**Test 1: No Authentication**
```bash
# Remove auth token, send request
# Should return 401 Unauthorized
curl https://target.com/api/v1/user/profile
```
❌ If it returns 200 with data → **AUTH BYPASS BUG!**

**Test 2: Expired/Invalid Token**
```bash
# Use old expired token or random string
curl https://target.com/api/v1/user/profile \
  -H "Authorization: Bearer invalid_token_here"
```
❌ If it returns 200 with data → **TOKEN VALIDATION BUG!**

**Test 3: Different User's Token**
```bash
# Login as user A, get token
# Try to access user B's data with user A's token
curl https://target.com/api/v1/user/999/profile \
  -H "Authorization: Bearer user_a_token"
```
❌ If it returns user 999's data → **IDOR BUG!** (This is CRITICAL, $5K-$30K)

**Test 4: Role/Permission Escalation**
```bash
# If JWT token, decode it
# Check for "role", "admin", "permissions" fields
# Try manipulating these in the token
```

#### **3.2 IDOR Testing - THE MONEY MAKER (60 min)**

**IDOR = Insecure Direct Object Reference**  
**This is where most $10K-$50K bugs are found**

**Step-by-step IDOR test:**

1. **Create two test accounts** (user A and user B)

2. **Login as user A**, perform actions:
   - View profile → Note the request
   - View transactions → Note the request
   - View wallet/balance → Note the request

3. **Identify the user identifier:**
   - URL: `/api/v1/user/123` → ID is 123
   - Parameter: `?user_id=456` → ID is 456
   - Body: `{"user_id": 789}` → ID is 789

4. **Login as user B**, get user B's ID

5. **Use user A's session, try to access user B's data:**
   ```bash
   # User A's token
   TOKEN_A="eyJhbGc..."
   
   # User B's ID
   USER_B_ID="456"
   
   # Try to access user B's data with user A's token
   curl https://target.com/api/v1/user/${USER_B_ID} \
     -H "Authorization: Bearer ${TOKEN_A}"
   ```

6. **If you get user B's data → CRITICAL IDOR BUG!**

**Test on EVERY user-specific endpoint:**
- Profile
- Transactions
- Wallet/Balance
- Orders
- Settings
- KYC documents
- API keys
- 2FA settings

---

### **HOUR 5-6: Business Logic Testing**

#### **5.1 Parameter Tampering (60 min)**

**Test manipulation of critical parameters:**

**Financial Parameters:**
```bash
# Normal swap
POST /api/v1/swap
{"amount_in": 100, "amount_out": 95, "fee": 5}

# Try zero fee
{"amount_in": 100, "amount_out": 100, "fee": 0}

# Try negative fee (get paid to swap!)
{"amount_in": 100, "amount_out": 105, "fee": -5}

# Try huge amount
{"amount_in": 999999999, "amount_out": 1, "fee": 0}
```

**Boolean Flags:**
```bash
# Normal transfer
POST /api/v1/transfer
{"to": "0x123...", "amount": 100}

# Add bypass flags
{"to": "0x123...", "amount": 100, "skip_fee": true}
{"to": "0x123...", "amount": 100, "admin": true}
{"to": "0x123...", "amount": 100, "bypass_limits": true}
```

**Array Manipulation:**
```bash
# If expecting array
POST /api/v1/batch_transfer
{"transfers": [{"to": "0x1", "amount": 10}]}

# Try empty
{"transfers": []}

# Try huge array
{"transfers": [... 10000 items ...]}
```

#### **5.2 Race Conditions (30 min)**

**Test for race conditions in financial operations:**

**Scenario: Can you claim rewards twice?**

1. **Capture the claim request in Burp**
   ```
   POST /api/v1/rewards/claim
   Authorization: Bearer token
   ```

2. **Send to Burp Repeater**

3. **Send 10 identical requests simultaneously**
   - Right-click → Send to Intruder
   - Set attack type: "Pitchfork" or "Sniper"
   - Set threads: 10
   - Start attack

4. **If multiple succeed → RACE CONDITION BUG!**

**Test on:**
- Claiming rewards
- Withdrawing funds
- Voting (can you vote multiple times?)
- Redeeming coupons
- Using referral codes

#### **5.3 DeFi-Specific Logic (30 min)**

**Price Manipulation:**
```bash
# Can you submit your own price?
POST /api/v1/oracle/update
{"token": "ETH", "price": 1}  # Set ETH to $1!

# Can you manipulate slippage?
POST /api/v1/swap
{"slippage": 100}  # 100% slippage = anything goes
```

**Liquidity Pool Attacks:**
```bash
# Can you add liquidity with worthless tokens?
POST /api/v1/pool/add_liquidity
{"token_a": "SCAM_TOKEN", "amount_a": 999999}

# Can you remove more than you added?
POST /api/v1/pool/remove_liquidity
{"lp_tokens": 100, "expected_a": 999999}
```

---

### **HOUR 7-8: Advanced Testing**

#### **7.1 GraphQL Exploitation (if applicable) (45 min)**

**Test 1: Introspection**
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```
✅ If this works → Huge information disclosure  
Submit as MEDIUM/HIGH finding

**Test 2: Batch Queries (IDOR via GraphQL)**
```graphql
query {
  user1: getUser(id: 1) { email balance }
  user2: getUser(id: 2) { email balance }
  user3: getUser(id: 3) { email balance }
  # ... repeat 100x
}
```
✅ If this returns other users' data → CRITICAL IDOR

**Test 3: Nested Queries (DoS)**
```graphql
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              # ... nest 20 levels deep
            }
          }
        }
      }
    }
  }
}
```
✅ If server crashes or times out → DoS vulnerability

#### **7.2 Input Validation (45 min)**

**Test EVERY input field:**

**SQL Injection:**
```bash
# In any text field
username: admin' OR '1'='1
email: test@test.com' OR '1'='1
```

**XSS (if bounty includes it):**
```bash
username: <script>alert(1)</script>
bio: <img src=x onerror=alert(1)>
```

**Command Injection:**
```bash
# If app processes files or system commands
filename: test.txt; ls -la
filename: test.txt | cat /etc/passwd
```

**Path Traversal:**
```bash
# In file upload/download
filename: ../../etc/passwd
filename: ..\..\windows\system32\config\sam
```

#### **7.3 Rate Limiting & Brute Force (30 min)**

**Test rate limits:**
```bash
# Send 100 requests to sensitive endpoint
for i in {1..100}; do
  curl https://target.com/api/v1/login \
    -d '{"email":"test@test.com","password":"wrong"}'
done
```

**Check if:**
- Account gets locked after X attempts?
- IP gets blocked?
- Rate limit error (429)?
- Nothing happens? → **NO RATE LIMITING = MEDIUM BUG**

---

### **HOUR 9-10: Verification & PoC Development**

#### **9.1 Verify All Findings (60 min)**

**For each potential bug:**

1. **Can you reproduce it consistently?**
   - Test 3-5 times
   - Same result every time?

2. **Is it actually a security issue?**
   - Does it expose sensitive data?
   - Can attacker gain unauthorized access?
   - Can it cause financial loss?

3. **What's the real-world impact?**
   - Who is affected?
   - How bad is it?
   - Can it be automated?

#### **9.2 Create Proof of Concept (60 min)**

**For each confirmed bug, create PoC:**

**Example PoC for IDOR:**
```python
import requests

# User A credentials
token_a = "eyJhbGciOiJ..."

# User B's ID (discovered via enumeration)
user_b_id = "456"

# Attempt to access User B's data with User A's token
response = requests.get(
    f"https://target.com/api/v1/user/{user_b_id}",
    headers={"Authorization": f"Bearer {token_a}"}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")

# If status = 200 and contains User B's data → IDOR confirmed
```

**PoC Requirements:**
- Shows the vulnerability clearly
- Reproduces the issue
- Demonstrates impact
- Includes expected vs actual behavior

---

### **HOUR 11-12: Report Writing & Submission**

#### **11.1 Write Professional Reports (75 min)**

**Use this template for EACH bug:**

```markdown
# [Vulnerability Type] in [Component]

## Summary
[2-3 sentences describing the vulnerability and impact]

## Severity
CRITICAL / HIGH / MEDIUM

## Vulnerability Details
- **CWE:** CWE-XXX
- **CVSS Score:** X.X
- **Affected Endpoint:** https://target.com/api/v1/example
- **Attack Vector:** [How attacker exploits this]

## Steps to Reproduce
1. [Detailed step 1]
2. [Detailed step 2]
3. [Detailed step 3]
...

## Proof of Concept
[Include code, screenshots, or curl commands]

## Impact
- [Business impact]
- [User impact]
- [Financial impact]
- [Compliance impact]

## Remediation
1. [Specific fix recommendation]
2. [Additional hardening measures]

## References
- [Relevant CWE/OWASP links]
- [Similar disclosed vulnerabilities]
```

#### **11.2 Submit Reports (15 min)**

**Before submitting:**
- [ ] Spell-checked and grammar-checked
- [ ] All screenshots clear and labeled
- [ ] PoC tested one final time
- [ ] Impact clearly explained
- [ ] Remediation provided

**Submit to:**
- HackerOne
- HackenProof
- Bugcrowd
- Direct program email

**Track in spreadsheet:**
- Report ID
- Date submitted
- Expected response time
- Status updates

---

## 🎯 CRITICAL SUCCESS FACTORS

### **What Separates $0 from $50K:**

**Winners:**
- ✅ Test EVERY endpoint for IDOR
- ✅ Manually verify automation findings
- ✅ Create clear, reproducible PoCs
- ✅ Explain business impact clearly
- ✅ Professional, detailed reports
- ✅ Submit within 24 hours of discovery

**Losers:**
- ❌ Only run automated scanners
- ❌ Submit LOW severity junk
- ❌ Poor report quality
- ❌ Can't reproduce the bug
- ❌ No understanding of impact
- ❌ Wait weeks to submit

---

## 💰 REALISTIC EXPECTATIONS

### **Per 10-hour hunt:**

**Best case (20% of hunts):**
- Find 2-5 MEDIUM/HIGH bugs
- Acceptance rate: 60%
- Payout: $5K-$30K

**Average case (30% of hunts):**
- Find 1-2 MEDIUM bugs
- Acceptance rate: 40%
- Payout: $1K-$5K

**Worst case (50% of hunts):**
- Find 0 MEDIUM+ bugs
- Only LOW severity
- Payout: $0-$500

**The math:**
- 10 hunts = 100 hours
- Expected: 3-8 accepted bugs
- Expected payout: $10K-$50K
- Hourly rate: $100-$500/hour

**This beats most jobs when successful!**

---

## ✅ POST-HUNT CHECKLIST

After each hunt:
- [ ] All findings documented
- [ ] Reports submitted
- [ ] Tracking spreadsheet updated
- [ ] Learned something new
- [ ] Notes for next hunt

**Continuous improvement:**
- What worked well?
- What bugs did I miss?
- What tools should I add?
- What can I do faster next time?

---

**Remember: Manual testing finds 80% of HIGH/CRITICAL bugs. Automated scanning finds 20%.**

**Master this playbook = $50K-$200K/year potential.**
