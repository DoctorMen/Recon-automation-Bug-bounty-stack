<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Immediate Testing Guide - Start Testing NOW!

**Status:** ✅ Burp Suite configured | ⚠️ Need API keys to test

---

## 🚀 **IMMEDIATE TESTING OPTIONS**

### **Option 1: Test WITHOUT API Keys (Authentication Bypass)**

You can test authentication bypass **RIGHT NOW** without API keys!

#### **Burp Repeater:**
1. Open Burp Suite → **Repeater** tab
2. Enter URL: `https://sandboxapi.rapyd.net/v1/payments/create`
3. Method: **POST**
4. **Headers:**
   ```
   X-Bugcrowd: Bugcrowd-DoctorMen
   Content-Type: application/json
   ```
   **DO NOT add Authorization header!**

5. **Body:**
   ```json
   {
     "amount": 100,
     "currency": "USD"
   }
   ```

6. Click **Send**
7. **If you get 200 OK:** 🚨 **CRITICAL FINDING!** Authentication bypass!
8. **If you get 401:** Expected - authentication is working

---

### **Option 2: Test WITH API Keys (Full Testing)**

Once you have API keys, use these ready-to-use templates:

#### **Quick Test Commands:**

**Test Authentication Bypass:**
```bash
curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json" \
  -d '{"amount":100,"currency":"USD"}'
```

**Test Negative Amount:**
```bash
curl -X POST https://sandboxapi.rapyd.net/v1/payments/create \
  -H "Authorization: Bearer $YOUR_TOKEN" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json" \
  -d '{"amount":-100,"currency":"USD"}'
```

---

## 📋 **READY-TO-USE TEMPLATES**

### **Burp Repeater Templates:**

See: `programs/rapyd/TESTING_TEMPLATES.md`

### **Postman Collection:**

Import: `programs/rapyd/rapyd_bug_bounty_postman_collection.json`

### **Testing Script:**

Run: `bash scripts/rapyd_api_testing.sh`

---

## 🎯 **START TESTING NOW**

### **Step 1: Test Authentication (No API Keys Needed!)**

1. Open Burp Suite → **Repeater**
2. URL: `https://sandboxapi.rapyd.net/v1/payments/create`
3. Method: **POST**
4. Headers:
   - `X-Bugcrowd: Bugcrowd-DoctorMen`
   - `Content-Type: application/json`
5. Body: `{"amount":100,"currency":"USD"}`
6. **Remove Authorization header** (if present)
7. Click **Send**
8. **Document result!**

### **Step 2: Test Other Endpoints**

Try these endpoints without auth:
- `GET /v1/customers`
- `GET /v1/payments`
- `GET /v1/wallets`
- `POST /v1/wallets/create`

### **Step 3: Document Findings**

Update: `programs/rapyd/findings/FINDINGS_LOG.md`

---

## 📊 **WHAT TO LOOK FOR**

### **Critical Findings:**
- ✅ 200 OK without Authorization header
- ✅ Can create payments without auth
- ✅ Can access data without auth

### **High Findings:**
- ✅ Negative amounts accepted
- ✅ Refund > original payment
- ✅ IDOR (access other users' data)

### **Medium Findings:**
- ✅ Information disclosure in errors
- ✅ Missing rate limiting
- ✅ Verbose error messages

---

## 🎯 **TESTING CHECKLIST**

- [ ] Test authentication bypass (no API keys needed!)
- [ ] Test negative amounts (need API keys)
- [ ] Test IDOR (need API keys)
- [ ] Test refund logic (need API keys)
- [ ] Document all findings

---

**Start with authentication bypass testing - no API keys needed!** 🚀

