<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Burp Suite Configuration - Quick Reference

**Current Status:** ✅ Scope configured (5 domains added)

---

## ✅ **STEP 1: Configure X-Bugcrowd Header**

### **Method: Match and Replace**

1. Go to **Project options** → **Match and Replace**
2. Click **Add**:
   - **Type:** Request header
   - **Match:** `^X-Bugcrowd:.*`
   - **Replace:** `X-Bugcrowd: Bugcrowd-DoctorMen`
   - **Enable:** ✅ Checked
3. Click **OK**

**Note:** This will replace any existing X-Bugcrowd header. If you want to add it when missing, we'll need Session Handling Rules (more complex).

---

## ✅ **STEP 2: Install CA Certificate**

1. **Open browser** → Navigate to: `http://burpsuite`
2. Click **CA Certificate** link
3. Download `cacert.der`
4. **Install:**

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

## ✅ **STEP 3: Configure Browser Proxy**

### **Option A: FoxyProxy Extension (Recommended)**

1. Install **FoxyProxy** extension (Chrome/Edge/Firefox)
2. Click FoxyProxy icon → Options
3. **Add New Proxy:**
   - Title: `Burp Suite`
   - Proxy IP: `127.0.0.1`
   - Port: `8080`
   - Type: HTTP
   - **URL Patterns:** Add `*rapyd.net*`
4. Save and enable

### **Option B: Manual Proxy Settings**

**Chrome/Edge:**
- Settings → System → Open proxy settings
- Manual proxy:
  - HTTP Proxy: `127.0.0.1:8080`
  - HTTPS Proxy: `127.0.0.1:8080`

**Firefox:**
- Settings → Network Settings → Manual proxy
- HTTP Proxy: `127.0.0.1`, Port: `8080`
- HTTPS Proxy: `127.0.0.1`, Port: `8080`
- Check "Also use this proxy for HTTPS"
- No proxy for: `localhost,127.0.0.1`

---

## ✅ **STEP 4: Verify Setup**

1. **Enable Interception:**
   - Go to **Proxy** → **Intercept** → **Intercept is on**

2. **Test in Browser:**
   - Visit `https://dashboard.rapyd.net`
   - Request should appear in Burp **Intercept** tab

3. **Check Header:**
   - Look for `X-Bugcrowd: Bugcrowd-DoctorMen` in the request
   - If missing, we'll add it manually in Repeater

4. **Forward Request:**
   - Click **Forward** to send request
   - Check **Target** → **Site map** to see traffic

---

## ✅ **BURP SUITE SETUP COMPLETE!**

Once verified, you're ready to:
1. Complete account verification
2. Generate API keys
3. Start testing!

---

**Next:** Complete account verification → Generate API keys → Start testing!

