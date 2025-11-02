# IDOR Testing - Complete Setup Guide

**Date:** $(date +%Y-%m-%d)  
**Status:** ✅ Secret Key Configured | Ready to Test

---

## ✅ **SETUP COMPLETE**

### **1. Credentials Configured:**
- ✅ Secret Key: `rsk_0171288550b537ece3ee6cd7b27b534278970e09b1b8d50e512f7ead43ba7b14545647cabe9e30dd`
- ✅ Configuration file: `programs/rapyd/credentials.sh`
- ✅ Testing script: `programs/rapyd/findings/test_idor_with_credentials.sh`

---

## 🎯 **TWO WAYS TO TEST IDOR**

### **Option 1: Dashboard Testing (Find Exact Path)**

**Steps:**
1. **Log in to Dashboard:**
   ```bash
   # Navigate to: https://dashboard.rapyd.net/login
   # Email: DoctorMen@bugcrowdninja.com
   ```

2. **Navigate to Payments:**
   - Go to: `/collect/payments/list`
   - Click on a payment to view details
   - **Check the URL bar** - this is your exact endpoint path!

3. **Common Endpoint Patterns:**
   - `/collect/payments/{payment_id}`
   - `/collect/payments/details/{payment_id}`
   - `/collect/payments/{payment_id}/details`
   - `/api/v1/merchants-portal/payments/{payment_id}`

4. **Test IDOR:**
   - Modify the `{payment_id}` in the URL
   - Check if you can access another user's payment data
   - **Screenshot the URL** (this is your proof!)

---

### **Option 2: API Testing (Direct)**

**Using the secret key we just configured:**

```bash
# 1. Load credentials
cd programs/rapyd
source credentials.sh

# 2. Run IDOR test script
cd findings
./test_idor_with_credentials.sh
```

**Or test manually:**

```bash
# Get your payment ID
curl -X POST "https://sandboxapi.rapyd.net/v1/payments" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Authorization: Bearer $RAPYD_SECRET_KEY" \
  -H "Content-Type: application/json"

# Test IDOR by modifying payment ID
curl -X GET "https://sandboxapi.rapyd.net/v1/payments/{MODIFIED_PAYMENT_ID}" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Authorization: Bearer $RAPYD_SECRET_KEY" \
  -H "Content-Type: application/json"
```

---

## 📋 **EVIDENCE CAPTURE CHECKLIST**

When testing IDOR, capture:

- [ ] **Screenshot of URL bar** showing the vulnerable endpoint
- [ ] **Screenshot of unauthorized data** accessed
- [ ] **HTTP Request** (from browser DevTools or Burp)
- [ ] **HTTP Response** (showing unauthorized data)
- [ ] **Original Payment ID** (your own)
- [ ] **Modified Payment ID** (that you accessed)

---

## 🔍 **FINDING THE EXACT PATH**

The bug bounty report mentioned:
> "In the URL bar, modify the parameter to a different value"

This means:
1. **Log in** → Navigate to payments
2. **Click on a payment** → Check URL bar
3. **The URL path you see** = Exact endpoint path
4. **Modify the ID** in that URL = IDOR test

---

## 🚀 **NEXT STEPS**

**RIGHT NOW:**
1. Log in to dashboard.rapyd.net
2. Navigate to `/collect/payments/list`
3. Click on a payment
4. **Check URL bar** - that's your exact path!
5. Modify the payment ID
6. Capture screenshots and evidence

---

## 📝 **SAVE EVIDENCE**

Once you find the exact path, save:

```bash
# Save URL path
echo "Vulnerable Endpoint: /collect/payments/{payment_id}" > evidence/endpoint_path.txt

# Save request/response
# Copy from browser DevTools → Network tab
```

---

**You're ready to test!** 🚀

