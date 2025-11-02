# IDOR Vulnerability - Quick Testing Checklist

**Target:** dashboard.rapyd.net  
**Account:** DoctorMen@bugcrowdninja.com  
**Required Header:** X-Bugcrowd: Bugcrowd-DoctorMen

---

## ⚡ **QUICK STEPS TO RETEST**

### **Step 1: Log In & Navigate**
1. ✅ Log in to https://dashboard.rapyd.net
2. ✅ Navigate to **Payments** or **Customers** section
3. ✅ Open browser DevTools (F12) → **Network** tab
4. ✅ Click on one payment/customer to view details

### **Step 2: Find the API Call**
1. ✅ In Network tab, look for API requests like:
   - `/api/v1/payments/{id}`
   - `/api/v1/customers/{id}`
   - `/api/v1/transactions/{id}`
2. ✅ Click on the request → Check **Headers** tab
3. ✅ Check **Payload** or **Request URL** tab for the ID
4. ✅ **Copy the full request URL** (e.g., `https://dashboard.rapyd.net/api/v1/payments/pay_abc123`)

### **Step 3: Test IDOR**
1. ✅ Note your own ID (e.g., `pay_abc123`)
2. ✅ Modify ID in URL (e.g., change to `pay_xyz789` or `pay_abc124`)
3. ✅ Open modified URL in new tab or use Burp Repeater
4. ✅ Check if you can access another user's data

### **Step 4: Capture Evidence**

**Take Screenshots:**
- [ ] Screenshot 1: Your own payment/customer data (with your ID in URL)
- [ ] Screenshot 2: Modified URL in browser bar
- [ ] Screenshot 3: Another user's data displayed (IDOR successful)
- [ ] Screenshot 4: Network tab showing the request
- [ ] Screenshot 5: Response showing unauthorized data

**Save HTTP Request/Response:**
- [ ] Copy full HTTP request from Network tab or Burp
- [ ] Copy full HTTP response from Network tab or Burp
- [ ] Note Operation ID if present in response headers

---

## 📝 **WHAT TO FILL IN BUGGROWD FORM**

### **URL/Location:**
```
https://dashboard.rapyd.net/api/v1/payments/{payment_id}
```
(Replace with actual endpoint you found)

### **HTTP Request:**
```
GET /api/v1/payments/pay_MODIFIED_ID HTTP/1.1
Host: dashboard.rapyd.net
Authorization: Bearer YOUR_TOKEN
X-Bugcrowd: Bugcrowd-DoctorMen
Cookie: session=YOUR_SESSION
...
```

### **HTTP Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "id": "pay_MODIFIED_ID",
    "amount": 100,
    "customer": {
      "id": "cus_OTHER_USER",
      "email": "other.user@example.com"
    }
  }
}
```

---

## ✅ **SUBMISSION CHECKLIST**

Before submitting to Bugcrowd:
- [ ] ✅ Title filled
- [ ] ✅ Target selected (dashboard.rapyd.net)
- [ ] ✅ VRT Category selected (P2 IDOR)
- [ ] ✅ Description filled with actual endpoint
- [ ] ✅ Actual HTTP request (with X-Bugcrowd header)
- [ ] ✅ Actual HTTP response (showing unauthorized data)
- [ ] ✅ Screenshots attached (5+ screenshots)
- [ ] ✅ Operation ID noted (if present)
- [ ] ✅ Clear reproduction steps

---

## 🚨 **IF YOU CAN'T FIND THE VULNERABILITY**

If IDOR doesn't work, try testing:
1. **Authentication bypass** (remove Authorization header)
2. **Amount manipulation** (negative amounts)
3. **Refund logic** (refund more than original)
4. **Other endpoints** (wallets, transactions, etc.)

See: `programs/rapyd/TESTING_TEMPLATES.md` for more test cases

---

**Good luck!** 🎯

