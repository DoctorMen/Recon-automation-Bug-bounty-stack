# Browser Snapshot - Current State

**Date:** $(date +%Y-%m-%d)  
**Time:** $(date +%H:%M:%S)  
**Browser State:** Captured

---

## 📸 **CURRENT BROWSER STATE**

### **URL:** 
```
https://dashboard.rapyd.net/login
```

### **Page Title:** 
```
Sign in - Rapyd Client Portal
```

### **Status:** 
- ❌ Not logged in (session expired)
- Need to log in again

---

## 🔍 **ENDPOINT PATTERNS DISCOVERED**

From network requests analysis:

### **Payments API:**
- **List Payments:** `POST /v1/merchants-portal/list/payments`
- **Individual Payment:** `GET /v1/merchants-portal/payments/{payment_id}` (likely)

### **Frontend Routes:**
- **Payments List:** `/collect/payments/list`
- **Payment Details:** `/collect/payments/{payment_id}` (likely)

---

## 🎯 **IDOR TESTING APPROACH (Idempotent)**

### **Step 1: Login**
```bash
# Navigate to dashboard
https://dashboard.rapyd.net/login
```

### **Step 2: Get Payment ID**
```bash
# Navigate to payments
https://dashboard.rapyd.net/collect/payments/list

# Check Network tab for:
POST /v1/merchants-portal/list/payments
# Extract payment ID from response
```

### **Step 3: Find Exact Endpoint**
```bash
# Click on a payment
# Watch URL bar for exact path:
# Example: /collect/payments/pay_abc123
# Or: /collect/payments/details/pay_abc123
```

### **Step 4: Test IDOR**
```bash
# Modify ID in URL:
# Your ID: pay_abc123
# Test ID: pay_xyz789 (or increment)
# Navigate to modified URL
```

---

## ✅ **IDEMPOTENT TEST CHECKLIST**

- [ ] State file created (`results/idor_test_state.json`)
- [ ] Endpoint path identified
- [ ] Payment ID captured
- [ ] Test ID generated
- [ ] IDOR test executed
- [ ] Results documented
- [ ] Evidence saved

---

## 📝 **STATE MANAGEMENT**

The idempotent script (`test_idor_idempotent.sh`) maintains state in:
- `results/idor_test_state.json` - Tracks progress
- `evidence/` - Stores test evidence
- `results/` - Stores test results

**Run multiple times safely** - script checks state and resumes from last checkpoint.

---

## 🚀 **QUICK START**

```bash
cd programs/rapyd/findings
chmod +x test_idor_idempotent.sh
./test_idor_idempotent.sh
```

The script will:
1. Check existing state
2. Prompt for missing information
3. Execute IDOR test
4. Save evidence
5. Update state for next run

---

**Status:** Ready for idempotent testing! 🎯

