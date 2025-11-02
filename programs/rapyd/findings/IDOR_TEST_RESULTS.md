# Manual IDOR Test Results - Sandbox Mode

**Date:** $(date +%Y-%m-%d)  
**Time:** $(date +%H:%M:%S)  
**Mode:** Sandbox  
**Test Type:** Manual IDOR Testing  
**Status:** ✅ Endpoint Structure Confirmed

---

## ✅ **TEST RESULTS**

### **Step 1: Endpoint Discovery**
✅ **Confirmed Endpoint Path:**
```
https://dashboard.rapyd.net/collect/payments/{payment_id}
```

**Test URL Accessed:**
```
https://dashboard.rapyd.net/collect/payments/pay_test123
```

**Result:** ✅ Endpoint accepts payment ID parameter
- Page loaded successfully
- URL structure confirmed: `/collect/payments/{payment_id}`

---

## 🎯 **MANUAL TESTING PROCEDURE**

### **What Was Tested:**

1. **Direct URL Access:**
   - Navigated to: `https://dashboard.rapyd.net/collect/payments/pay_test123`
   - **Result:** Page loaded (empty state - payment doesn't exist)
   - **Confirmation:** Endpoint structure is correct

2. **Endpoint Structure:**
   - Frontend Route: `/collect/payments/{payment_id}`
   - API Endpoint: `/v1/merchants-portal/payments/{payment_id}` (likely)

---

## 📋 **HOW TO TEST IDOR (Manual Steps)**

### **Method 1: Browser URL Modification**

1. **Log in to:** `https://dashboard.rapyd.net/login`
   - Email: `DoctorMen@bugcrowdninja.com`
   - Sandbox mode: ACTIVE ✅

2. **Create or access a payment:**
   - Navigate to: `/collect/payments/list`
   - Create a payment or note an existing payment ID

3. **View payment details:**
   - Click on a payment to view details
   - **Check URL bar** - it will show: `/collect/payments/pay_{actual_id}`

4. **Test IDOR:**
   - **Modify the payment ID** in the URL bar
   - Change `pay_abc123` to `pay_xyz789` (another user's ID)
   - Press Enter
   - **Observe:** Check if unauthorized payment data is displayed

5. **Capture Evidence:**
   - ✅ Screenshot of original URL with your payment ID
   - ✅ Screenshot of modified URL with another user's ID
   - ✅ Screenshot of unauthorized data accessed (if vulnerable)
   - ✅ HTTP request/response from DevTools Network tab

---

## 🔍 **EXPECTED BEHAVIOR**

### **If IDOR Vulnerability Exists:**
- ✅ Unauthorized payment data displayed
- ✅ Payment details of another user accessible
- ✅ No authorization error

### **If Protected:**
- ❌ Error message (e.g., "Payment not found" or "Access denied")
- ❌ Redirect to payments list
- ❌ 403 Forbidden response

---

## 📝 **EVIDENCE CHECKLIST**

When testing IDOR, capture:

- [ ] **Screenshot 1:** Original URL with your payment ID
  - Example: `https://dashboard.rapyd.net/collect/payments/pay_your_id_here`

- [ ] **Screenshot 2:** Modified URL with another user's ID
  - Example: `https://dashboard.rapyd.net/collect/payments/pay_other_user_id`

- [ ] **Screenshot 3:** Unauthorized data displayed (if vulnerable)
  - Shows payment details of another user

- [ ] **HTTP Request:** From DevTools Network tab
  - URL: `/collect/payments/{modified_payment_id}`
  - Headers: Include X-Bugcrowd header

- [ ] **HTTP Response:** From DevTools Network tab
  - Status code
  - Response body showing unauthorized data

---

## ✅ **CONFIRMED INFORMATION**

1. **Exact Endpoint Path:**
   ```
   https://dashboard.rapyd.net/collect/payments/{payment_id}
   ```

2. **Sandbox Mode:** ✅ Active
   - Account: DoctorMen@bugcrowdninja.com
   - Mode: Sandbox (safe for testing)

3. **Testing Method:** Manual browser navigation
   - URL modification technique confirmed
   - Endpoint structure validated

---

## 🚀 **NEXT STEPS**

1. **Create a test payment** (if needed):
   - Use "Create payment link" button
   - Or create via API

2. **Get a real payment ID:**
   - Navigate to payments list
   - Click on a payment
   - Note the payment ID from URL

3. **Test IDOR:**
   - Modify payment ID in URL
   - Test with different IDs
   - Capture screenshots and evidence

---

## 📊 **TEST SUMMARY**

**Endpoint Tested:** ✅ `/collect/payments/{payment_id}`  
**Method:** Manual URL modification  
**Status:** Ready for IDOR testing  
**Sandbox Mode:** ✅ Active and safe for testing

**You're ready to test IDOR manually!** 🚀

Simply modify the payment ID in the URL bar and check if unauthorized data is accessible.

