# Manual IDOR Test - Sandbox Mode

**Date:** $(date +%Y-%m-%d)  
**Mode:** Sandbox  
**Test Type:** Manual IDOR Testing

---

## 📋 **MANUAL TESTING STEPS**

### **Step 1: Navigate to Payments List**
✅ Already on: `https://dashboard.rapyd.net/collect/payments/list`

### **Step 2: Test IDOR Directly**

Since there are no payments yet, we'll test the IDOR vulnerability by:

1. **Direct URL Access Test:**
   - Try accessing payment endpoints with test IDs
   - Test common ID patterns: `pay_123`, `pay_abc123`, etc.

2. **Check API Response:**
   - Open browser DevTools (F12)
   - Navigate to Network tab
   - Try accessing modified payment IDs
   - Check responses for unauthorized data access

### **Step 3: Test Payment ID Pattern**

Let's test the endpoint structure by navigating to:
```
https://dashboard.rapyd.net/collect/payments/pay_test123
```

This will reveal:
- The exact endpoint structure
- Error messages (which reveal ID format)
- Whether the endpoint exists

---

## 🎯 **MANUAL TEST COMMANDS**

### **Browser Navigation:**
1. Open DevTools (F12) → Network tab
2. Navigate to payment detail URL pattern
3. Modify payment ID in URL
4. Observe response

### **Expected Behavior:**
- **If IDOR exists:** Unauthorized payment data displayed
- **If Protected:** Error message or redirect
- **If Invalid ID:** Error message (reveals ID format)

---

## 📝 **EVIDENCE CAPTURE**

When testing, capture:
- ✅ Screenshot of URL bar with modified ID
- ✅ Screenshot of response/error
- ✅ Network request/response from DevTools
- ✅ Original vs Modified ID comparison

---

**Ready to test manually in browser!** 🚀

