# Rapyd API Testing - Ready-to-Use Templates

**Account:** DoctorMen@bugcrowdninja.com  
**Required Header:** X-Bugcrowd: Bugcrowd-DoctorMen  
**Status:** Ready for immediate testing

---

## 🎯 **BURP REPEATER TEMPLATES**

### **Template 1: Test Authentication Bypass**

**Request:**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 100,
  "currency": "USD",
  "payment_method": "bank_transfer"
}
```

**Test Variations:**
1. **No Authorization header** - Remove `Authorization: Bearer` line
2. **Invalid token** - Change token to `invalid_token`
3. **Expired token** - Use old/expired token
4. **Wrong token format** - Remove `Bearer` prefix
5. **Another user's token** - Use token from different account

---

### **Template 2: Test Amount Manipulation**

**Request:**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": -100,
  "currency": "USD"
}
```

**Test Variations:**
- `"amount": -100` - Negative amount
- `"amount": 0` - Zero amount
- `"amount": 999999999999` - Overflow
- `"amount": 0.01` - Minimum amount
- `"amount": "100"` - String instead of number
- `"amount": null` - Null value

---

### **Template 3: Test Currency Manipulation**

**Request:**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 100,
  "currency": "INVALID"
}
```

**Test Variations:**
- `"currency": "INVALID"` - Invalid currency
- `"currency": null` - Null currency
- `"currency": "USD" + " " + "USD"` - Concatenation attempt
- Remove currency field entirely

---

### **Template 4: Test IDOR (Insecure Direct Object Reference)**

**Request:**
```http
GET /v1/customers/CUSTOMER_ID_HERE HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
```

**Test Steps:**
1. **Get your own customer ID:**
   ```http
   GET /v1/customers?limit=10 HTTP/1.1
   ```
   Note your customer ID from response

2. **Test IDOR:**
   - Replace `CUSTOMER_ID_HERE` with another user's ID
   - Try accessing other users' data
   - Check if you can modify other users' resources

---

### **Template 5: Test Refund Logic**

**Request:**
```http
POST /v1/payments/PAYMENT_ID/refund HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 200
}
```

**Test Variations:**
- `"amount": 200` - More than original (original was 100)
- `"amount": 0` - Zero refund
- `"amount": -50` - Negative refund
- Try double refund (same payment ID twice)
- Try refund to different account

---

### **Template 6: Test Wallet Operations**

**Request:**
```http
POST /v1/wallets/WALLET_ID/transfer HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 1000,
  "currency": "USD",
  "destination_wallet": "WALLET_ID_HERE"
}
```

**Test Variations:**
- `"amount": 1000` - More than balance
- `"amount": -100` - Negative transfer
- `"amount": 0` - Zero transfer
- `"destination_wallet": "invalid_wallet"` - Invalid wallet
- Try transferring to your own wallet (self-transfer)

---

### **Template 7: Test Parameter Pollution**

**Request:**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 100,
  "amount": 200,
  "currency": "USD",
  "currency": "EUR"
}
```

**Test:** Duplicate parameters to see which one is processed

---

### **Template 8: Test SQL Injection**

**Request:**
```http
POST /v1/customers HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "email": "test@example.com' OR '1'='1",
  "name": "Test User"
}
```

**Test Variations:**
- `"email": "test' OR '1'='1"` - SQL injection attempt
- `"name": "Test' OR '1'='1"` - SQL injection in name
- Try in all input fields

---

## 🚀 **POSTMAN CONFIGURATION**

### **Environment Variables**

Create Postman environment with:

```json
{
  "rapyd_api_key": "YOUR_API_KEY_HERE",
  "rapyd_secret_key": "YOUR_SECRET_KEY_HERE",
  "rapyd_base_url": "https://sandboxapi.rapyd.net",
  "bugcrowd_header": "Bugcrowd-DoctorMen"
}
```

### **Pre-request Script**

Add to Postman collection:

```javascript
// Add X-Bugcrowd header to all requests
pm.request.headers.add({
    key: 'X-Bugcrowd',
    value: pm.environment.get('bugcrowd_header')
});

// Generate signature if needed (Rapyd requires signature)
// This is a placeholder - use Rapyd's signature algorithm
```

### **Collection Setup**

1. **Create Collection:** "Rapyd Bug Bounty Testing"
2. **Add Header Globally:**
   - Collection → Headers
   - Add: `X-Bugcrowd: Bugcrowd-DoctorMen`
3. **Import Rapyd API Collection:**
   - Download from: https://docs.rapyd.net
   - Import into Postman
   - Add X-Bugcrowd header to collection

---

## 📝 **TESTING WORKFLOW**

### **Phase 1: Authentication Testing (Start Here)**

1. **Test without token:**
   ```http
   POST /v1/payments/create HTTP/1.1
   Host: sandboxapi.rapyd.net
   X-Bugcrowd: Bugcrowd-DoctorMen
   ```
   Expected: 401 Unauthorized  
   If 200 OK: **CRITICAL FINDING!**

2. **Test with invalid token:**
   ```http
   Authorization: Bearer invalid_token_here
   ```
   Expected: 401 Unauthorized  
   If 200 OK: **CRITICAL FINDING!**

3. **Test with expired token:**
   - Use old token
   - Check if still accepted

### **Phase 2: Business Logic Testing**

1. **Amount Manipulation:**
   - Test negative amounts
   - Test zero amounts
   - Test overflow amounts

2. **Refund Logic:**
   - Test refund > original payment
   - Test double refund
   - Test refund to different account

3. **Wallet Operations:**
   - Test transfer > balance
   - Test negative transfers
   - Test race conditions

### **Phase 3: IDOR Testing**

1. **List your resources:**
   ```http
   GET /v1/customers?limit=10
   GET /v1/payments?limit=10
   GET /v1/wallets?limit=10
   ```

2. **Access other users' resources:**
   - Replace IDs with other users' IDs
   - Check if you can access/modify

---

## 🎯 **HIGH-PRIORITY TEST CASES**

### **Test Case 1: Authentication Bypass**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 100,
  "currency": "USD"
}
```
**Remove Authorization header** - If payment creates, **CRITICAL FINDING!**

### **Test Case 2: Negative Amount Payment**
```http
POST /v1/payments/create HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": -100,
  "currency": "USD"
}
```
**If accepted:** Can create negative balance - **HIGH FINDING!**

### **Test Case 3: Refund More Than Original**
```http
POST /v1/payments/PAYMENT_ID/refund HTTP/1.1
Host: sandboxapi.rapyd.net
Authorization: Bearer YOUR_TOKEN
X-Bugcrowd: Bugcrowd-DoctorMen
Content-Type: application/json

{
  "amount": 200
}
```
**If original was 100 and refund of 200 is accepted:** **CRITICAL FINDING!**

---

## 📊 **TRACKING TEMPLATE**

For each test, document:

```markdown
### Test #001 - Authentication Bypass
- **Date:** YYYY-MM-DD
- **Endpoint:** POST /v1/payments/create
- **Test:** Remove Authorization header
- **Expected:** 401 Unauthorized
- **Actual:** [Response code]
- **Result:** [Pass/Fail - Finding or Not]
- **Request:** [Full request]
- **Response:** [Full response]
- **Operation ID:** [If present]
- **Screenshot:** [If applicable]
```

---

## ⚡ **QUICK START COMMANDS**

### **Using curl:**
```bash
# Test authentication bypass
curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"currency":"USD"}'

# Test with token
curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json" \
  -d '{"amount":-100,"currency":"USD"}'
```

---

## 🎯 **PRIORITY ORDER**

1. **Authentication bypass** (Highest reward potential)
2. **Amount manipulation** (Business logic flaws)
3. **IDOR** (Authorization issues)
4. **Refund logic** (Financial vulnerabilities)
5. **Race conditions** (Concurrency issues)

---

**Ready to test! Just add your API keys and start!** 🚀

