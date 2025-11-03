# Burp Suite Configuration - Step-by-Step Guide

**Account:** DoctorMen@bugcrowdninja.com  
**Header:** X-Bugcrowd: Bugcrowd-DoctorMen

---

## ✅ **STEP 1: First Launch Setup**

1. **Launch Burp Suite Community Edition**
2. **Welcome Screen:**
   - Click "Next"
   - Accept license agreement
   - Choose **"Temporary project"** (or save project if you want to keep it)
   - Click "Start Burp"

---

## ✅ **STEP 2: Configure Proxy Listener**

1. Go to **Proxy** → **Options** → **Proxy Listeners**
2. Verify listener is running on `127.0.0.1:8080`
3. If not running:
   - Click **Add**
   - Bind to port: `8080`
   - Bind to address: `127.0.0.1`
   - Click **OK**

---

## ✅ **STEP 3: Import Scope Configuration**

### **Option A: Manual Scope Setup (Recommended)**

1. Go to **Target** → **Scope**
2. Click **Add** (in the Include section)
3. Add these domains one by one:
   ```
   https://sandboxapi.rapyd.net
   https://api.rapyd.net
   https://dashboard.rapyd.net
   https://verify.rapyd.net
   https://checkout.rapyd.net
   ```
4. Click **OK** for each

### **Option B: Import from JSON (Alternative)**

1. Go to **Target** → **Scope**
2. Click **Load** (if available)
3. Navigate to: `programs/rapyd/burp_config/rapyd-burp-configuration.json`
4. Note: Burp may not directly import JSON scope - manual setup is more reliable

---

## ✅ **STEP 4: Configure X-Bugcrowd Header**

### **Method 1: Match and Replace (Easiest)**

1. Go to **Project options** → **Match and Replace**
2. Click **Add**:
   - **Type:** Request header
   - **Match:** `^X-Bugcrowd:.*`
   - **Replace:** `X-Bugcrowd: Bugcrowd-DoctorMen`
   - **Enable:** ✅ Checked
3. Click **Add** again (for missing header):
   - **Type:** Request header
   - **Match:** `^$` (empty - matches requests without X-Bugcrowd)
   - **Replace:** `X-Bugcrowd: Bugcrowd-DoctorMen`
   - **Enable:** ✅ Checked
   - **Note:** This may not work perfectly - use Method 2 instead

### **Method 2: Session Handling Rules (Better)**

1. Go to **Project options** → **Sessions** → **Session Handling Rules**
2. Click **Add**
3. **Rule name:** `Rapyd X-Bugcrowd Header`
4. **Rule actions:**
   - Click **Add** → **Run a macro**
   - Actually, skip macro - use **Add header** instead:
   - Click **Add** → **Add a custom header**
   - **Header name:** `X-Bugcrowd`
   - **Header value:** `Bugcrowd-DoctorMen`
5. **Rule conditions:**
   - Click **Add** → **URL is in target scope**
6. Click **OK**
7. **Enable:** ✅ Checked

### **Method 3: Manual Header Addition (For Testing)**

When testing manually in Repeater:
- Just add header manually: `X-Bugcrowd: Bugcrowd-DoctorMen`

---

## ✅ **STEP 5: Install CA Certificate**

1. **Open browser** and navigate to: `http://burpsuite`
2. Click **CA Certificate** link
3. Download `cacert.der`
4. **Install certificate:**

   **Chrome/Edge:**
   - Settings → Privacy and Security → Security → Manage certificates
   - Import → Select `cacert.der`
   - Trust for: "Trust this certificate for identifying websites"
   - Click OK

   **Firefox:**
   - Settings → Privacy & Security → Certificates → View Certificates
   - Authorities → Import → Select `cacert.der`
   - Trust for: "Trust this CA to identify websites"
   - Click OK

---

## ✅ **STEP 6: Configure Browser Proxy**

### **Chrome/Edge (Using FoxyProxy Extension - Recommended)**

1. Install **FoxyProxy** extension
2. Click FoxyProxy icon → Options
3. **Add New Proxy:**
   - Title: `Burp Suite`
   - Proxy IP: `127.0.0.1`
   - Port: `8080`
   - Type: HTTP
   - **URL Patterns:** Add `*rapyd.net*`
4. Save and enable

### **Chrome/Edge (Manual Proxy)**

1. Settings → System → Open proxy settings
2. Manual proxy:
   - HTTP Proxy: `127.0.0.1:8080`
   - HTTPS Proxy: `127.0.0.1:8080`
   - Use proxy for: `rapyd.net,*.rapyd.net` (or all traffic)

### **Firefox (Manual Proxy)**

1. Settings → Network Settings → Manual proxy
2. HTTP Proxy: `127.0.0.1`, Port: `8080`
3. HTTPS Proxy: `127.0.0.1`, Port: `8080`
4. Check "Also use this proxy for HTTPS"
5. No proxy for: `localhost,127.0.0.1`

---

## ✅ **STEP 7: Verify Configuration**

### **Test 1: Proxy Connection**
```bash
# In terminal, test proxy
curl -x http://127.0.0.1:8080 https://sandboxapi.rapyd.net/v1/payments/list \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen"
```

### **Test 2: Burp Interception**
1. Enable **Proxy** → **Intercept** → **Intercept is on**
2. Visit `https://dashboard.rapyd.net` in browser
3. Request should appear in Burp **Intercept** tab
4. Verify `X-Bugcrowd: Bugcrowd-DoctorMen` header is present
5. Click **Forward** to send request

### **Test 3: Scope Verification**
1. Visit `https://dashboard.rapyd.net` in browser
2. Check **Target** → **Site map**
3. Should see `dashboard.rapyd.net` in the tree
4. Verify it's marked as "in scope" (green checkmark)

---

## ✅ **STEP 8: Configure Advanced Settings**

### **Proxy Interception Rules**
1. Go to **Proxy** → **Options** → **Intercept Client Requests**
2. Add rules:
   - ✅ `^https?://sandboxapi\.rapyd\.net/.*`
   - ✅ `^https?://dashboard\.rapyd\.net/.*`
   - ✅ `^https?://verify\.rapyd\.net/.*`
   - ✅ `^https?://checkout\.rapyd\.net/.*`

### **Disable Interception for Static Files (Optional)**
- Uncheck: `^.*\.(css|js|png|jpg|gif|ico|svg|woff|woff2|ttf|eot)$`

---

## ✅ **CHECKLIST**

- [ ] Burp Suite launched
- [ ] Proxy listener running on 8080
- [ ] Scope configured (5 Rapyd domains)
- [ ] X-Bugcrowd header configured
- [ ] CA certificate installed in browser
- [ ] Browser proxy configured
- [ ] Interception tested
- [ ] Header verified in requests

---

## 🎯 **NEXT STEPS**

Once Burp Suite is configured:

1. **Complete Account Verification:**
   - Finish Iceland onboarding form
   - Upload address verification document

2. **Generate API Keys:**
   - Navigate to dashboard.rapyd.net/developers/api-keys
   - Generate sandbox API keys

3. **Start Testing:**
   - Review `programs/rapyd/BURP_ADVANCED_TESTING.md`
   - Begin manual API testing
   - Document findings in `programs/rapyd/findings/FINDINGS_LOG.md`

---

## 📚 **REFERENCE FILES**

- **Advanced Testing:** `programs/rapyd/BURP_ADVANCED_TESTING.md`
- **Testing Checklist:** `programs/rapyd/TESTING_CHECKLIST.md`
- **Config Files:** `programs/rapyd/burp_config/`

---

**Ready to start testing once API keys are generated!** 🚀

