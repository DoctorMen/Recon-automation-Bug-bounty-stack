# Advanced Burp Suite Configuration & API Testing Workflow for Rapyd

**Account:** DoctorMen@bugcrowdninja.com  
**Required Header:** X-Bugcrowd: Bugcrowd-DoctorMen  
**Last Updated:** November 1, 2025

---

## 🔧 **BURP SUITE CONFIGURATION**

### **Step 1: Download Burp Configuration**

1. Navigate to: `https://bugcrowd.com/engagements/rapyd`
2. Go to **Attachments** section
3. Download: `rapyd-burp-configuration.json`

### **Step 2: Import Scope Configuration**

1. Open Burp Suite Professional
2. Go to **Target** → **Scope**
3. Click **Import** → Select `rapyd-burp-configuration.json`
4. Verify scope includes:
   - `https://sandboxapi.rapyd.net`
   - `https://dashboard.rapyd.net`
   - `https://verify.rapyd.net`
   - `https://checkout.rapyd.net`
   - `https://api.rapyd.net`

### **Step 3: Configure X-Bugcrowd Header (CRITICAL)**

#### **Method 1: Session Handling Rule (Recommended)**

1. Go to **Project options** → **Sessions** → **Session Handling Rules**
2. Click **Add** → Name it "Rapyd Bugcrowd Header"
3. **Rule Actions** → **Add** → **Run a macro**
4. **Match Conditions** → **Add** → **URL is in target scope**
5. **Add** → **Header name matches** → `X-Bugcrowd`
6. **Add Header Rule**:
   ```
   Header name: X-Bugcrowd
   Header value: Bugcrowd-DoctorMen
   ```
7. Enable **Add if header is missing**

#### **Method 2: Match and Replace (Alternative)**

1. Go to **Project options** → **Match and Replace**
2. Click **Add**:
   - **Type**: Request header
   - **Match**: `^X-Bugcrowd:.*`
   - **Replace**: `X-Bugcrowd: Bugcrowd-DoctorMen`
   - **Enable**: ✅

#### **Method 3: Extension (Advanced)**

Use **Burp Extension** to automatically add header:
```python
# Custom Burp Extension (if needed)
from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            # Add X-Bugcrowd header if missing
            if b"X-Bugcrowd:" not in request:
                messageInfo.setRequest(addHeader(request, "X-Bugcrowd", "Bugcrowd-DoctorMen"))
```

### **Step 4: Configure Proxy Settings**

1. **Proxy** → **Options** → **Proxy Listeners**
2. Ensure listener is running on `127.0.0.1:8080`
3. **Intercept** → **Intercept Client Requests**:
   - ✅ `^https?://sandboxapi\.rapyd\.net/.*`
   - ✅ `^https?://dashboard\.rapyd\.net/.*`
   - ✅ `^https?://verify\.rapyd\.net/.*`
   - ✅ `^https?://checkout\.rapyd\.net/.*`

### **Step 5: Configure Browser**

1. Install Burp CA certificate (if not already installed)
2. Configure browser proxy:
   - HTTP Proxy: `127.0.0.1:8080`
   - HTTPS Proxy: `127.0.0.1:8080`
3. Verify connection: Visit `http://burpsuite` → Should see Burp page

---

## 🔍 **ADVANCED API QUERY TECHNIQUES**

### **Technique 1: Progressive Parameter Discovery**

Advanced hunters systematically discover all API parameters:

#### **Step 1: Base Request Capture**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 100,
  "currency": "USD",
  "payment_method": "bank_transfer"
}
```

#### **Step 2: Parameter Enumeration**
Use Burp **Intruder** to test each parameter:

**Payload Set 1: Amount Manipulation**
```json
{
  "amount": §-100§,      // Negative
  "amount": §0§,          // Zero
  "amount": §999999999§,  // Overflow
  "amount": §0.01§,       // Minimum
  "amount": §"100"§,      // String type
  "amount": §null§,       // Null
}
```

**Payload Set 2: Currency Manipulation**
```json
{
  "currency": §"INVALID"§,
  "currency": §"USD"§,      // Normal
  "currency": §null§,
  "currency": §"USD" + " " + "USD"§, // Concatenation
}
```

**Payload Set 3: Payment Method**
```json
{
  "payment_method": §"invalid_method"§,
  "payment_method": §null§,
  "payment_method": §"bank_transfer" AND "1"="1"§, // SQL injection attempt
}
```

#### **Step 3: Response Analysis**
After each request, analyze:
- Status codes (200, 400, 401, 403, 500)
- Error messages (information disclosure)
- Response time (timing attacks)
- Operation ID presence (for reporting)

### **Technique 2: GraphQL Query Testing (if applicable)**

If Rapyd uses GraphQL:

```graphql
# Test 1: Introspection Query
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

# Test 2: Query Depth Limit
query {
  payments {
    customer {
      payments {
        customer {
          payments {
            id
          }
        }
      }
    }
  }
}

# Test 3: Query Cost Analysis Bypass
query {
  payments {
    id
    amount
    currency
    # ... repeat 1000 times
  }
}
```

### **Technique 3: Authentication Bypass Testing**

#### **Test Sequence:**
1. **No Authentication**
   ```http
   POST /v1/payments/create HTTP/1.1
   Host: sandboxapi.rapyd.net
   X-Bugcrowd: Bugcrowd-DoctorMen
   ```
   Expected: 401 Unauthorized

2. **Invalid Token**
   ```http
   Authorization: Bearer invalid_token_here
   ```
   Expected: 401 Unauthorized

3. **Expired Token**
   ```http
   Authorization: Bearer <expired_token>
   ```
   Expected: 401 Unauthorized (but check for token reuse)

4. **Wrong Token Format**
   ```http
   Authorization: Bearer
   Authorization: Bearer<no_space>token
   Authorization: Basic base64_encoded
   ```

5. **Token from Another User**
   ```http
   Authorization: Bearer <stolen_token_from_other_account>
   ```
   Expected: 403 Forbidden (but check for IDOR)

6. **Missing Signature**
   ```http
   POST /v1/payments/create HTTP/1.1
   Host: sandboxapi.rapyd.net
   Authorization: Bearer YOUR_TOKEN
   X-Bugcrowd: Bugcrowd-DoctorMen
   # Missing: Signature header (if required)
   ```

### **Technique 4: Business Logic Testing**

#### **Payment Amount Manipulation**

**Test 1: Negative Amount**
```json
{
  "amount": -100,
  "currency": "USD"
}
```
**Expected:** Should reject negative amounts  
**If accepted:** Critical vulnerability - can create negative balance

**Test 2: Currency Mismatch**
```json
{
  "amount": 100,
  "currency": "USD",
  "wallet_id": "wallet_that_uses_EUR"
}
```
**Expected:** Should convert or reject  
**If accepted incorrectly:** Business logic flaw

**Test 3: Refund More Than Original**
```json
{
  "payment_id": "pay_123",
  "amount": 200,  // Original was 100
  "refund_reason": "test"
}
```
**Expected:** Should reject refund > original  
**If accepted:** Critical financial vulnerability

#### **Race Condition Testing**

**Test: Concurrent Payments**
```bash
# Send 10 simultaneous requests
for i in {1..10}; do
  curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
    -d '{"amount":100,"currency":"USD"}' &
done
```

**Expected:** Should handle race conditions properly  
**If double-charged:** Race condition vulnerability

### **Technique 5: IDOR (Insecure Direct Object Reference) Testing**

#### **Test Sequence:**

1. **List Own Resources**
   ```http
   GET /v1/customers?limit=10 HTTP/1.1
   ```
   Note: Your customer IDs

2. **Access Another User's Resource**
   ```http
   GET /v1/customers/cust_OTHER_USER_ID HTTP/1.1
   ```
   Expected: 403 Forbidden  
   If 200 OK: IDOR vulnerability

3. **Modify Another User's Resource**
   ```http
   PUT /v1/customers/cust_OTHER_USER_ID HTTP/1.1
   {
     "email": "hacked@example.com"
   }
   ```

4. **Access Another User's Payment**
   ```http
   GET /v1/payments/pay_OTHER_USER_PAYMENT_ID HTTP/1.1
   ```

### **Technique 6: Parameter Pollution**

```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 100,
  "amount": 200,  // Duplicate parameter
  "currency": "USD",
  "currency": "EUR"  // Duplicate parameter
}
```

**Expected:** Should reject or use last value  
**If both processed:** Parameter pollution vulnerability

---

## 🎯 **SYSTEMATIC TESTING WORKFLOW**

### **Phase 1: Reconnaissance (Day 1)**

1. ✅ Run automated recon: `python3 run_pipeline.py --targets programs/rapyd/targets.txt`
2. ✅ Review API documentation: `https://docs.rapyd.net`
3. ✅ Map all endpoints:
   - Payment endpoints
   - Wallet endpoints
   - Customer endpoints
   - Authentication endpoints
4. ✅ Document all parameters for each endpoint

### **Phase 2: Authentication Testing (Day 2)**

#### **Morning: Basic Auth Tests**
- [ ] Missing authentication
- [ ] Invalid tokens
- [ ] Expired tokens
- [ ] Wrong token format
- [ ] Token reuse after expiration

#### **Afternoon: Authorization Tests**
- [ ] IDOR on customer endpoints
- [ ] IDOR on payment endpoints
- [ ] IDOR on wallet endpoints
- [ ] Privilege escalation
- [ ] Horizontal privilege escalation

### **Phase 3: Business Logic Testing (Day 3-4)**

#### **Payment Logic**
- [ ] Negative amounts
- [ ] Zero amounts
- [ ] Overflow amounts
- [ ] Currency manipulation
- [ ] Refund logic flaws
- [ ] Double refunds

#### **Wallet Logic**
- [ ] Balance manipulation
- [ ] Negative balance creation
- [ ] Transfer amount limits
- [ ] Transfer to invalid wallet
- [ ] Race conditions

### **Phase 4: Input Validation (Day 5)**

- [ ] SQL injection (all parameters)
- [ ] XSS (if applicable)
- [ ] Command injection
- [ ] XXE (if XML used)
- [ ] Path traversal

### **Phase 5: Advanced Testing (Day 6)**

- [ ] Race conditions (concurrent requests)
- [ ] GraphQL vulnerabilities (if applicable)
- [ ] Rate limiting bypass
- [ ] Timing attacks
- [ ] SSRF (if applicable)

### **Phase 6: Documentation & Submission (Day 7)**

- [ ] Document all findings
- [ ] Capture screenshots
- [ ] Include operation IDs
- [ ] Write clear reproduction steps
- [ ] Submit reports

---

## 📊 **HOW TO CONTINUE TESTING**

### **After Finding #1: Don't Stop!**

1. **Document immediately**:
   - Screenshot request/response
   - Note operation ID
   - Write brief description

2. **Continue testing**:
   - Don't submit yet - find more issues
   - Similar endpoints might have same flaw
   - Related functionality might be vulnerable

3. **Depth over breadth**:
   - Fully explore each endpoint
   - Test edge cases
   - Look for bypasses

### **Query Pattern: Systematic Enumeration**

```
For each endpoint:
  ├─ Test authentication
  ├─ Test authorization (IDOR)
  ├─ Test each parameter:
  │   ├─ Type validation
  │   ├─ Range validation
  │   ├─ Format validation
  │   └─ Business logic validation
  ├─ Test race conditions
  ├─ Test error handling
  └─ Test edge cases
```

### **Progressive Testing Strategy**

#### **Level 1: Happy Path**
```json
{
  "amount": 100,
  "currency": "USD"
}
```
✅ Verify it works

#### **Level 2: Boundary Testing**
```json
{
  "amount": 0,
  "amount": 999999999,
  "amount": -1
}
```
✅ Test limits

#### **Level 3: Type Confusion**
```json
{
  "amount": "100",  // String instead of number
  "amount": null,
  "amount": [],
  "amount": {}
}
```
✅ Test type validation

#### **Level 4: Business Logic**
```json
{
  "amount": 100,
  "currency": "USD",
  "refund_amount": 200  // More than original
}
```
✅ Test business rules

#### **Level 5: Advanced Attacks**
```json
{
  "amount": 100,
  "amount": 200,  // Parameter pollution
  "description": "<script>alert(1)</script>",  // XSS
  "id": "1' OR '1'='1"  // SQL injection
}
```
✅ Test security controls

---

## 🔥 **PRO TIPS FOR ADVANCED HUNTERS**

### **1. Operation ID Tracking**
- Always capture operation IDs from responses
- Use them in reports for easy verification
- Track which operations led to findings

### **2. Request/Response Correlation**
- Save every request/response pair
- Use Burp **Logger** extension
- Export to JSON for later analysis

### **3. Error Message Analysis**
- Deep dive into error messages
- Often reveal information disclosure
- Can lead to other vulnerabilities

### **4. State Machine Testing**
- Understand payment flow states
- Test invalid state transitions
- Look for state bypass vulnerabilities

### **5. Rate Limiting Bypass**
- Test with different IPs
- Test with different API keys
- Test header manipulation
- Test endpoint-specific limits

### **6. Documentation Mining**
- Read API docs thoroughly
- Look for deprecated endpoints
- Check changelog for recent changes
- Find undocumented endpoints

---

## 📝 **TESTING TEMPLATE**

### **For Each Endpoint:**

```markdown
## Endpoint: POST /v1/payments/create

### Authentication Tests
- [ ] Missing auth → 401 ✅
- [ ] Invalid token → 401 ✅
- [ ] Expired token → 401 ✅

### Authorization Tests
- [ ] Access other user's payment → 403 ✅
- [ ] Modify other user's payment → 403 ✅

### Parameter Tests
- [ ] Negative amount → Rejected ✅
- [ ] Zero amount → Accepted (expected)
- [ ] Overflow amount → Rejected ✅
- [ ] Invalid currency → Rejected ✅

### Business Logic Tests
- [ ] Refund > original → Rejected ✅
- [ ] Double refund → Rejected ✅
- [ ] Race condition → Handled ✅

### Findings
- [ ] Finding #1: [Description]
- [ ] Finding #2: [Description]
```

---

## 🚀 **QUICK START COMMANDS**

### **Test Authentication Bypass**
```bash
curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"currency":"USD"}'
```

### **Test Amount Manipulation**
```bash
curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json" \
  -d '{"amount":-100,"currency":"USD"}'
```

### **Test Race Condition**
```bash
for i in {1..10}; do
  curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
    -d '{"amount":100,"currency":"USD"}' &
done
```

---

**Remember:** Quality over quantity. One high-impact finding is worth more than ten low-impact reports! 🎯

