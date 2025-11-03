# Browser Proxy Configuration - Complete Guide

**Burp Suite Proxy:** `127.0.0.1:8080`  
**Status:** Ready to configure

---

## 🌐 **CHROME/EDGE PROXY CONFIGURATION**

### **Method 1: FoxyProxy Extension (RECOMMENDED - Easiest)**

1. **Install FoxyProxy:**
   - Chrome: https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogbbifdlmhjg
   - Edge: https://microsoftedge.microsoft.com/addons/detail/foxyproxy-standard/dpplabbmogjaaglojkjodldadajbeekf

2. **Configure FoxyProxy:**
   - Click FoxyProxy icon → **Options**
   - Click **Add New Proxy**
   - **General Tab:**
     - Title: `Burp Suite - Rapyd`
     - Proxy IP: `127.0.0.1`
     - Port: `8080`
     - Type: `HTTP`
   - **URL Patterns Tab:**
     - Click **Add New Pattern**
     - Pattern: `*rapyd.net*`
     - Pattern Type: `Wildcard`
     - Click **Save**
   - Click **Save** on proxy settings

3. **Enable Proxy:**
   - Click FoxyProxy icon → Select **"Burp Suite - Rapyd"**
   - Icon should turn blue/active

### **Method 2: Manual Proxy Settings**

1. **Open Proxy Settings:**
   - Chrome: Settings → System → Open proxy settings
   - Edge: Settings → System → Open proxy settings
   - Or: Windows Settings → Network & Internet → Proxy

2. **Configure Manual Proxy:**
   - Turn **ON** "Use a proxy server"
   - Address: `127.0.0.1`
   - Port: `8080`
   - Click **Save**

3. **Note:** This routes ALL traffic through Burp. Use FoxyProxy for selective routing.

---

## 🦊 **FIREFOX PROXY CONFIGURATION**

### **Method 1: FoxyProxy Extension (RECOMMENDED)**

1. **Install FoxyProxy:**
   - https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/

2. **Configure:**
   - Same as Chrome/Edge instructions above

### **Method 2: Manual Proxy Settings**

1. **Open Settings:**
   - Click hamburger menu → Settings
   - Or: `about:preferences`

2. **Network Settings:**
   - Scroll to **"Network Settings"**
   - Click **"Settings"**

3. **Configure Manual Proxy:**
   - Select **"Manual proxy configuration"**
   - HTTP Proxy: `127.0.0.1`, Port: `8080`
   - HTTPS Proxy: `127.0.0.1`, Port: `8080`
   - Check **"Also use this proxy for HTTPS"**
   - No proxy for: `localhost,127.0.0.1`
   - Click **"OK"**

---

## ✅ **VERIFY PROXY CONFIGURATION**

### **Test 1: Check Burp Suite**

1. **Enable Interception:**
   - Burp Suite → Proxy → Intercept → **Intercept is on**

2. **Visit Any Website:**
   - Navigate to `https://dashboard.rapyd.net` in browser
   - Request should appear in Burp **Intercept** tab

3. **If Request Appears:**
   - ✅ Proxy is working!
   - Click **Forward** to send request

### **Test 2: Check Burp HTTP History**

1. **Visit:** `https://dashboard.rapyd.net`
2. **Check:** Proxy → HTTP history
3. **Should see:** Request to `dashboard.rapyd.net`

### **Test 3: Verify X-Bugcrowd Header**

1. **In Burp Suite:**
   - Proxy → HTTP history
   - Click on request to `dashboard.rapyd.net`
   - Check **Request** tab
   - Look for header: `X-Bugcrowd: Bugcrowd-DoctorMen`

---

## 🔧 **TROUBLESHOOTING**

### **Issue: Requests not appearing in Burp**

**Solutions:**
- Check Burp proxy listener is running (Proxy → Options → Proxy Listeners)
- Verify browser proxy settings are correct (`127.0.0.1:8080`)
- Check Burp Intercept is enabled (Proxy → Intercept → Intercept is on)
- Try disabling firewall temporarily
- Restart browser

### **Issue: SSL/Certificate Errors**

**Solutions:**
- CA certificate not installed correctly
- Re-install certificate (see `CA_CERTIFICATE_INSTALLATION.md`)
- Ensure certificate is in "Trusted Root Certification Authorities"
- Clear browser cache and restart

### **Issue: All sites redirect through proxy**

**Solutions:**
- Use FoxyProxy extension for selective routing
- Configure URL patterns to only proxy `*rapyd.net*`
- Or use manual proxy with exceptions list

---

## 📋 **QUICK SETUP CHECKLIST**

### **Burp Suite:**
- [ ] Proxy listener running on `127.0.0.1:8080`
- [ ] Scope configured (5 Rapyd domains)
- [ ] X-Bugcrowd header configured
- [ ] Intercept enabled

### **Browser:**
- [ ] CA certificate installed
- [ ] Proxy configured (`127.0.0.1:8080`)
- [ ] FoxyProxy installed (recommended)
- [ ] URL patterns set to `*rapyd.net*`

### **Verification:**
- [ ] Can visit `https://dashboard.rapyd.net` without SSL errors
- [ ] Requests appear in Burp Suite
- [ ] X-Bugcrowd header present in requests

---

## 🎯 **AFTER PROXY IS CONFIGURED**

Once proxy is working:

1. **Test Interception:**
   - Visit `https://dashboard.rapyd.net`
   - Request should appear in Burp

2. **Verify Header:**
   - Check X-Bugcrowd header is added

3. **Next Steps:**
   - Complete account verification
   - Generate API keys
   - Start testing!

---

**Configuration File:** `programs/rapyd/BURP_CONFIGURATION_COMPLETE.md`

