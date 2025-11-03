# IDOR Testing - Network Requests Found

**Date:** 2025-01-31  
**Status:** ✅ Logged in successfully  
**Current Page:** `/collect/payments`

---

## 🔍 **API ENDPOINTS DISCOVERED**

### **Payments API:**
- **List Payments:** `POST https://dashboard.rapyd.net/v1/merchants-portal/list/payments`
  - Status: 200 OK
  - Method: POST
  - This endpoint lists all payments

### **Next Steps to Find IDOR:**

1. **Get Payment ID:**
   - Check the response from `/v1/merchants-portal/list/payments`
   - Look for payment IDs in the response (format: `pay_xxxxx` or similar)

2. **Test Individual Payment Endpoint:**
   - Try: `GET https://dashboard.rapyd.net/v1/merchants-portal/payments/{payment_id}`
   - Or: `GET https://dashboard.rapyd.net/v1/merchants-portal/payments/{payment_id}/details`
   - Replace `{payment_id}` with actual ID from response

3. **Test IDOR:**
   - Once you have a payment ID, modify it to test if you can access other users' payments
   - Try incrementing/decrementing IDs
   - Try random IDs

---

## 📝 **TESTING COMMANDS**

### **Using Browser DevTools:**
1. Open DevTools (F12) → Network tab
2. Find the `/v1/merchants-portal/list/payments` request
3. Click on it → Check Response tab
4. Copy any payment ID found
5. Try accessing: `GET /v1/merchants-portal/payments/{payment_id}`

### **Using Burp Suite:**
1. Intercept the payments list request
2. Forward to Repeater
3. Modify the request to access individual payment
4. Test IDOR by changing payment IDs

---

## ✅ **READY TO TEST**

You're now logged in and have access to the dashboard. The next step is to:
1. Check if there are any existing payments
2. If not, create a test payment first
3. Then test IDOR vulnerability

**Note:** Since this is a new account, you may need to create test data first before testing IDOR.



