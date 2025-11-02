# IDOR Vulnerability - Evidence Capture Template

**Date:** $(date +%Y-%m-%d)  
**Researcher:** DoctorMen@bugcrowdninja.com  
**Target:** dashboard.rapyd.net

---

## 📋 **STEP-BY-STEP TESTING**

### **STEP 1: Access Dashboard**
1. Open browser → Navigate to https://dashboard.rapyd.net
2. Log in with: DoctorMen@bugcrowdninja.com
3. Enable browser DevTools (F12)
4. Go to **Network** tab

### **STEP 2: Find Vulnerable Endpoint**
1. Navigate to **Payments** or **Customers** section
2. Click on a payment/customer to view details
3. In Network tab, find API calls containing IDs:
   - Look for: `/api/v1/payments/{id}`
   - Or: `/api/v1/customers/{id}`
   - Or: `/api/v1/transactions/{id}`

### **STEP 3: Capture Your Request**
1. Click on the API request in Network tab
2. Copy the **Request URL** (full URL with your ID)
3. Copy the **Request Headers** (all headers)
4. Copy the **Response** (full JSON response)

**Example format to save:**
```
=== REQUEST ===
GET https://dashboard.rapyd.net/api/v1/payments/pay_YOUR_ID_HERE HTTP/1.1
Host: dashboard.rapyd.net
Authorization: Bearer YOUR_TOKEN_HERE
X-Bugcrowd: Bugcrowd-DoctorMen
Cookie: session=YOUR_SESSION_HERE
...

=== RESPONSE ===
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "id": "pay_YOUR_ID_HERE",
    ...
  }
}
```

### **STEP 4: Test IDOR**
1. **Modify the ID** in the URL:
   - Change `pay_YOUR_ID` to `pay_DIFFERENT_ID`
   - Try incrementing: `pay_abc123` → `pay_abc124`
   - Try random IDs
2. **Send the modified request**:
   - Right-click request → Copy as cURL
   - Modify the ID in cURL command
   - Execute in terminal OR use Burp Repeater
3. **Check response**:
   - If you get data → **IDOR CONFIRMED!**
   - If you get 403/401 → Authorization working (no IDOR)

### **STEP 5: Document Evidence**

**Screenshots needed:**
1. **Before:** Your own data (with your ID visible)
2. **URL Bar:** Showing modified ID
3. **After:** Another user's data displayed
4. **Network Tab:** Request/response details
5. **Burp/DevTools:** Showing full request/response

**Files to save:**
- `findings/requests/001_request.txt` - Full HTTP request
- `findings/responses/001_response.txt` - Full HTTP response
- `screenshots/001_before.png` - Your data
- `screenshots/001_after.png` - Unauthorized data

---

## 🎯 **QUICK TEST COMMANDS**

### **Using Browser DevTools:**
1. Open DevTools (F12)
2. Network tab → Find API request
3. Right-click → Copy → Copy as cURL
4. Modify ID in the copied command
5. Run in terminal

### **Using Burp Suite:**
1. Intercept request in Proxy
2. Forward to Repeater
3. Modify ID in URL/parameters
4. Send request
5. Copy request/response

---

## ✅ **WHAT TO LOOK FOR**

**Successful IDOR:**
- ✅ Response 200 OK (not 403 Forbidden)
- ✅ Response contains data belonging to another user
- ✅ Different customer ID, email, or payment details
- ✅ No authorization error

**Example Successful Response:**
```json
{
  "status": { "status": "SUCCESS" },
  "data": {
    "id": "pay_OTHER_USER_ID",
    "amount": 500,
    "customer": {
      "id": "cus_OTHER_USER",
      "email": "other.user@example.com"
    }
  }
}
```

---

## 📝 **FILL IN THESE DETAILS**

**Vulnerable Endpoint:**
```
[Copy actual endpoint URL here]
```

**Your ID:**
```
[Your payment/customer ID]
```

**Modified ID Used:**
```
[ID you used to access other user's data]
```

**Request:**
```
[Full HTTP request with headers]
```

**Response:**
```
[Full HTTP response showing unauthorized data]
```

**Operation ID (if present):**
```
[From response headers]
```

---

**Ready to test! Follow the steps above and capture all evidence!** 🚀

