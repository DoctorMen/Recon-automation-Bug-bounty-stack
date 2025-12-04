<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# CA Certificate Installation - Complete Guide

**Prerequisites:** Burp Suite must be running with proxy listener active on port 8080

---

## ✅ **STEP 1: Download CA Certificate**

### **Method 1: Via Browser (Easiest)**

1. **Ensure Burp Suite is running** with proxy listener on port 8080
2. **Open your browser** (Chrome, Edge, or Firefox)
3. **Navigate to:** `http://burpsuite` (or `http://127.0.0.1:8080`)
4. **You should see:** Burp Suite welcome page
5. **Click:** **CA Certificate** link
6. **Download:** `cacert.der` file (save to Desktop or Downloads)

### **Method 2: Direct Download (If Method 1 doesn't work)**

If `http://burpsuite` doesn't work:
1. **Check Burp Suite:**
   - Proxy → Options → Proxy Listeners
   - Ensure listener is running on `127.0.0.1:8080`

2. **Try direct URL:** `http://127.0.0.1:8080`
3. **Or download from:** Burp Suite → Project options → Network → TLS → CA Certificate → Export

---

## ✅ **STEP 2: Install CA Certificate**

### **For Chrome/Edge:**

1. **Open Chrome/Edge Settings:**
   - Click three dots menu → Settings
   - Or: `chrome://settings/` or `edge://settings/`

2. **Navigate to Certificates:**
   - Privacy and Security → Security
   - Scroll down → Click **"Manage certificates"**

3. **Import Certificate:**
   - Click **"Import"** button
   - Browse to where you saved `cacert.der`
   - Select the file → Click **"Open"**

4. **Certificate Store:**
   - Select **"Place all certificates in the following store"**
   - Click **"Browse"**
   - Select **"Trusted Root Certification Authorities"**
   - Click **"OK"**

5. **Complete Import:**
   - Click **"Next"**
   - Click **"Finish"**
   - Click **"Yes"** on security warning

6. **Verify:**
   - You should see "PortSwigger CA" in the certificate list

### **For Firefox:**

1. **Open Firefox Settings:**
   - Click hamburger menu → Settings
   - Or: `about:preferences`

2. **Navigate to Certificates:**
   - Privacy & Security → Scroll to **"Certificates"**
   - Click **"View Certificates"**

3. **Import Certificate:**
   - Click **"Authorities"** tab
   - Click **"Import"** button
   - Browse to `cacert.der`
   - Select file → Click **"Open"**

4. **Trust Settings:**
   - Check **"Trust this CA to identify websites"**
   - Click **"OK"**

5. **Verify:**
   - You should see "PortSwigger CA" in the list

---

## ✅ **STEP 3: Verify Installation**

### **Test Certificate:**

1. **Enable Burp Intercept:**
   - Burp Suite → Proxy → Intercept → **Intercept is on**

2. **Visit HTTPS Site:**
   - Navigate to `https://dashboard.rapyd.net` in browser
   - **If certificate is installed correctly:**
     - Site loads without SSL errors
     - Request appears in Burp Intercept tab
   - **If certificate is NOT installed:**
     - You'll see "Your connection is not private" error
     - Need to retry installation

3. **Check Burp:**
   - Request should appear in **Proxy → HTTP history**
   - No SSL/TLS errors in Burp

---

## 🔧 **TROUBLESHOOTING**

### **Issue: "http://burpsuite" doesn't work**

**Solutions:**
- Ensure Burp Suite is running
- Check proxy listener is active (Proxy → Options → Proxy Listeners)
- Try `http://127.0.0.1:8080` instead
- Check browser proxy settings

### **Issue: "Your connection is not private" error**

**Solutions:**
- Certificate not installed correctly
- Re-download and re-install certificate
- Ensure certificate is in "Trusted Root Certification Authorities"
- Clear browser cache and restart browser

### **Issue: Certificate import fails**

**Solutions:**
- Try running browser as Administrator
- Check file permissions on `cacert.der`
- Ensure certificate format is correct (.der file)

---

## ✅ **CHECKLIST**

- [ ] Burp Suite running
- [ ] Proxy listener active on port 8080
- [ ] Navigated to `http://burpsuite`
- [ ] Downloaded `cacert.der`
- [ ] Certificate imported into browser
- [ ] Certificate in Trusted Root store
- [ ] Tested with HTTPS site
- [ ] No SSL errors

---

## 🎯 **AFTER INSTALLATION**

Once certificate is installed:

1. **Configure Browser Proxy** (next step)
2. **Test Interception** - Visit any HTTPS site
3. **Verify Header** - Check X-Bugcrowd header is added

---

**Next:** Configure browser proxy settings!

