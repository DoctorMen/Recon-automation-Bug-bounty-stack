# IDOR Vulnerability - Exact Endpoint Path

**Based on Bug Bounty Report Description:**  
"Modify the parameter to a different value" in the URL bar

**Target:** dashboard.rapyd.net

---

## 🎯 **MOST LIKELY ENDPOINT PATTERNS**

Based on the network requests captured (`/v1/merchants-portal/list/payments`), the IDOR vulnerability endpoint is likely:

### **Option 1: Frontend Route (Most Likely)**
```
https://dashboard.rapyd.net/collect/payments/{payment_id}
```
OR
```
https://dashboard.rapyd.net/collect/payments/details/{payment_id}
```

### **Option 2: API Endpoint**
```
GET https://dashboard.rapyd.net/v1/merchants-portal/payments/{payment_id}
```
OR
```
GET https://dashboard.rapyd.net/v1/merchants-portal/payments/{payment_id}/details
```

---

## 🔍 **HOW TO FIND THE EXACT PATH**

### **Step 1: Log in and Navigate to Payments**
1. Log in to https://dashboard.rapyd.net
2. Navigate to **Collect → Payments**

### **Step 2: Find a Payment ID**
1. Open DevTools (F12) → Network tab
2. Look for the response from `/v1/merchants-portal/list/payments`
3. Check the response JSON for payment IDs (format: `pay_xxxxx` or similar)

### **Step 3: Click on a Payment**
1. Click on any payment in the list
2. **Watch the URL bar** - this will show the exact endpoint path
3. Look for patterns like:
   - `/collect/payments/pay_abc123`
   - `/collect/payments/details/pay_abc123`
   - `/collect/payments?id=pay_abc123`

### **Step 4: Check Network Tab**
1. When you click on a payment, check Network tab
2. Look for API calls like:
   - `/v1/merchants-portal/payments/{id}`
   - `/v1/merchants-portal/payments/{id}/details`
   - `/v1/merchants-portal/payments/details/{id}`

---

## 📝 **TESTING THE IDOR**

Once you find the exact path:

1. **Get your own payment ID:**
   - Note the ID from your payment list response

2. **Modify the URL:**
   - Change `{payment_id}` to a different ID
   - Example: `pay_abc123` → `pay_xyz789`
   - Or increment: `pay_abc123` → `pay_abc124`

3. **Access the modified URL:**
   - If you get another user's payment data → **IDOR CONFIRMED!**
   - If you get 403/401 → Authorization working (no IDOR)

---

## ✅ **WHAT TO CAPTURE**

1. **Exact URL Path:** Copy the full URL showing the payment ID
2. **Modified URL:** Copy the URL with modified ID
3. **HTTP Request:** Full request headers (include X-Bugcrowd)
4. **HTTP Response:** Full response showing unauthorized data
5. **Screenshots:** Before/after showing the vulnerability

---

## 🚨 **MOST COMMON IDOR PATTERNS**

Based on typical dashboard implementations:

1. **Frontend Route:**
   ```
   /collect/payments/{payment_id}
   /collect/payments/details/{payment_id}
   /payments/{payment_id}
   ```

2. **API Endpoint:**
   ```
   GET /v1/merchants-portal/payments/{payment_id}
   GET /v1/merchants-portal/payments/{payment_id}/details
   GET /api/v1/payments/{payment_id}
   ```

---

**Next Step:** Log in, navigate to payments, click on a payment, and check the URL bar to find the exact endpoint path!

