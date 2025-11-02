# IDOR Vulnerability Retesting Guide

**Date:** $(date +%Y-%m-%d)  
**Target:** dashboard.rapyd.net  
**Vulnerability:** IDOR - Unauthorized Access to Payment/Customer Data

---

## 🎯 **PRE-TESTING CHECKLIST**

Before starting, ensure you have:
- [ ] Access to dashboard.rapyd.net
- [ ] Burp Suite installed and configured
- [ ] Browser configured to use Burp proxy
- [ ] Screenshot tool ready (Windows Snipping Tool or similar)
- [ ] Text editor ready to save requests/responses

---

## 📋 **STEP 1: SETUP BURP SUITE**

1. **Open Burp Suite**
2. **Configure Proxy:**
   - Proxy → Options → Proxy Listeners
   - Ensure proxy is listening on `127.0.0.1:8080`
3. **Set Up Match/Replace Rule:**
   - Proxy → Options → Match and Replace Rules
   - Add rule: Add `X-Bugcrowd: Bugcrowd-DoctorMen` header to all requests
4. **Configure Browser:**
   - Chrome/Edge: Settings → Advanced → System → Open proxy settings
   - Set HTTP proxy: `127.0.0.1:8080`
   - Set HTTPS proxy: `127.0.0.1:8080`
   - Install Burp CA certificate: http://burpsuite/cert

---

## 🔍 **STEP 2: IDENTIFY VULNERABLE ENDPOINT**

### **Option A: Dashboard API Testing (Recommended)**

1. **Log in to dashboard.rapyd.net:**
   ```
   URL: https://dashboard.rapyd.net
   Username: DoctorMen@bugcrowdninja.com
   ```

2. **Navigate to Payments/Customers section:**
   - Go to Payments or Customers page
   - Open Burp Proxy → HTTP History
   - Look for API calls like:
     - `/api/v1/payments/{payment_id}`
     - `/api/v1/customers/{customer_id}`
     - `/api/v1/transactions/{transaction_id}`

3. **Identify Object IDs:**
   - Note the ID format (e.g., `pay_1234567890abcdef`, `cus_abc123def456`)
   - Note which endpoint shows your own data

### **Option B: Browser Network Tab**

1. Open browser DevTools (F12)
2. Go to Network tab
3. Navigate to dashboard.rapyd.net and log in
4. Click on a payment/customer to view details
5. Look for requests containing IDs in URL or parameters

---

## 🧪 **STEP 3: TEST IDOR VULNERABILITY**

### **Test Scenario 1: Access Another User's Payment**

1. **Get Your Own Payment ID:**
   ```
   GET https://dashboard.rapyd.net/api/v1/payments?limit=1
   ```
   - Copy your payment ID from response (e.g., `pay_abc123def456`)

2. **Test IDOR:**
   ```
   GET https://dashboard.rapyd.net/api/v1/payments/pay_abc123def456
   ```
   - Note: This should return YOUR payment data

3. **Modify ID (Try different values):**
   ```
   GET https://dashboard.rapyd.net/api/v1/payments/pay_xyz789ghi012
   ```
   - Try incrementing/decrementing IDs
   - Try random IDs
   - **If you get data:** 🚨 **IDOR CONFIRMED!**

### **Test Scenario 2: Access Another User's Customer Data**

1. **Get Your Customer ID:**
   ```
   GET https://dashboard.rapyd.net/api/v1/customers?limit=1
   ```
   - Copy your customer ID

2. **Test IDOR:**
   ```
   GET https://dashboard.rapyd.net/api/v1/customers/cus_abc123def456
   ```
   - Modify ID to another user's ID
   - Check if you can access their data

---

## 📸 **STEP 4: CAPTURE EVIDENCE**

### **A. Screenshots**

Take screenshots of:
1. **Before:** Your own payment/customer data (with your ID)
2. **After:** Another user's data (with modified ID)
3. **Browser URL bar:** Showing the modified ID
4. **Burp Request:** Showing the request with modified ID
5. **Burp Response:** Showing unauthorized data access

**Screenshot Naming:**
- `01_my_payment_id.png` - Your own data
- `02_modified_id_url.png` - URL with modified ID
- `03_unauthorized_data.png` - Another user's data accessed
- `04_burp_request.png` - Burp request
- `05_burp_response.png` - Burp response

### **B. HTTP Request/Response**

**From Burp Suite:**
1. Right-click on request → **Copy as cURL**
2. Save to: `programs/rapyd/findings/request_001.txt`
3. Right-click on response → **Copy response**
4. Save to: `programs/rapyd/findings/response_001.txt`

**Format:**
```http
=== REQUEST ===
GET /api/v1/payments/pay_MODIFIED_ID HTTP/1.1
Host: dashboard.rapyd.net
Authorization: Bearer YOUR_TOKEN
X-Bugcrowd: Bugcrowd-DoctorMen
Cookie: session=YOUR_SESSION
...

=== RESPONSE ===
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "id": "pay_MODIFIED_ID",
    "amount": 100,
    "customer": "OTHER_USER_DATA",
    ...
  }
}
```

---

## 🎯 **STEP 5: DOCUMENT FINDING**

Update `programs/rapyd/findings/FINDINGS_LOG.md` with:

```markdown
### Finding #001 - IDOR in Dashboard Payment Endpoint
- **Date**: 2025-11-XX
- **Severity**: High (P2)
- **Status**: Verified
- **Target**: dashboard.rapyd.net
- **Endpoint**: GET /api/v1/payments/{payment_id}
- **Description**: Can access other users' payment data by modifying payment ID
- **Impact**: Unauthorized access to payment and customer data
- **Evidence**: 
  - Screenshots: screenshots/001_*.png
  - Request: findings/request_001.txt
  - Response: findings/response_001.txt
- **Operation ID**: [from response if present]
```

---

## ✅ **VERIFICATION CHECKLIST**

Before submitting, ensure you have:
- [ ] Actual vulnerable endpoint URL
- [ ] Full HTTP request (with X-Bugcrowd header)
- [ ] Full HTTP response (showing unauthorized data)
- [ ] Screenshots showing the vulnerability
- [ ] Operation ID (if present in Rapyd API responses)
- [ ] Clear steps to reproduce

---

## 🚨 **WHAT TO LOOK FOR**

**Successful IDOR Test:**
- ✅ Can access resources with modified IDs
- ✅ Response contains data belonging to other users
- ✅ No authorization error (should be 403 Forbidden if protected)
- ✅ Response is 200 OK with unauthorized data

**Example Successful Response:**
```json
{
  "status": {
    "status": "SUCCESS"
  },
  "data": {
    "id": "pay_OTHER_USER_ID",
    "amount": 500,
    "currency": "USD",
    "customer": {
      "id": "cus_OTHER_USER",
      "email": "other.user@example.com",
      "name": "Other User"
    }
  }
}
```

---

## 📝 **NEXT STEPS**

1. Complete the retest
2. Capture all evidence
3. Update Bugcrowd submission with real data
4. Submit report

---

**Remember:** Always test in sandbox environment and only access your own test data!

