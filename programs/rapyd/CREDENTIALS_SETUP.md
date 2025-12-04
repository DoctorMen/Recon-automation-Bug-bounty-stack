<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# API Credentials Setup Complete

**Date:** $(date +%Y-%m-%d)  
**Status:** ✅ Secret Key Configured

---

## 🔐 **CREDENTIALS CONFIGURED**

### **Secret Key (Private Key):**
```
rsk_0171288550b537ece3ee6cd7b27b534278970e09b1b8d50e512f7ead43ba7b14545647cabe9e30dd
```

### **Configuration Files:**
- `programs/rapyd/credentials.sh` - Credentials file (DO NOT COMMIT)
- `programs/rapyd/findings/test_idor_with_credentials.sh` - IDOR testing script

---

## 🚀 **QUICK START**

### **1. Load Credentials:**
```bash
cd programs/rapyd
source credentials.sh
```

### **2. Run IDOR Test:**
```bash
cd findings
chmod +x test_idor_with_credentials.sh
./test_idor_with_credentials.sh
```

---

## 📝 **NEXT STEPS**

### **For Dashboard IDOR Testing:**

1. **Log in to Dashboard:**
   ```bash
   # Navigate to: https://dashboard.rapyd.net/login
   ```

2. **Find Payment Endpoint:**
   - Go to: `/collect/payments/list`
   - Click on a payment
   - **Check URL bar** for exact endpoint path
   - Common patterns:
     - `/collect/payments/{payment_id}`
     - `/collect/payments/details/{payment_id}`

3. **Test IDOR:**
   - Modify payment ID in URL
   - Check if unauthorized data is accessible
   - Capture screenshots and HTTP requests

### **For API IDOR Testing:**

The script `test_idor_with_credentials.sh` will:
- Use your secret key for authentication
- Fetch payment list
- Extract payment IDs
- Test IDOR by modifying IDs
- Save evidence

---

## ⚠️ **SECURITY NOTES**

- ✅ Credentials file is in `.gitignore`
- ✅ Never commit credentials to git
- ✅ Use environment variables for testing
- ✅ Rotate keys if exposed

---

## 🎯 **READY TO TEST**

You now have:
- ✅ Secret key configured
- ✅ Testing scripts ready
- ✅ IDOR testing script available

**Next:** Run the IDOR test script or manually test in dashboard!





