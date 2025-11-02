# Burp Suite Download Guide for Rapyd Bug Bounty

**Last Updated:** November 1, 2025

---

## 🎯 **DOWNLOAD OPTIONS**

### **Option 1: Burp Suite Community Edition (FREE)**
- ✅ Free forever
- ✅ Perfect for bug bounty testing
- ✅ All core features included
- ❌ No advanced scanner (but manual testing works great!)

### **Option 2: Burp Suite Professional (PAID)**
- ✅ Advanced automated scanner
- ✅ Requires license (~$399/year)
- ✅ Not required for Rapyd testing (manual is preferred)

**Recommendation:** Start with **Community Edition** - it's free and perfect for manual bug bounty testing!

---

## 📥 **DOWNLOAD INSTRUCTIONS**

### **Windows (Your System)**

1. **Visit Download Page:**
   ```
   https://portswigger.net/burp/communitydownload
   ```

2. **Download:**
   - Click "Download now" button
   - Choose Windows installer (.exe)
   - File will be: `burpsuite_community_windows-x64_v2024.x.x.exe`

3. **Install:**
   - Run the downloaded `.exe` file
   - Follow installation wizard
   - Launch Burp Suite Community Edition

### **WSL/Linux (If Using WSL)**

```bash
# Navigate to programs/rapyd directory
cd "C:\Users\Doc Lab\.cursor\worktrees\Recon-automation-Bug-bounty-stack\bi6DL\programs\rapyd"

# Create download directory
mkdir -p burp_download

# Download Burp Suite Community Edition (Linux)
cd burp_download
wget https://portswigger.net/burp/releases/download?product=community&version=2024.11.1&type=jar -O burpsuite_community.jar

# Make executable
chmod +x burpsuite_community.jar

# Run Burp Suite
java -jar burpsuite_community.jar
```

**Note:** Requires Java installed:
```bash
# Check if Java is installed
java -version

# Install Java if needed (Ubuntu/Debian)
sudo apt update
sudo apt install default-jre -y
```

---

## 🚀 **QUICK START AFTER INSTALLATION**

### **Step 1: First Launch**
1. Launch Burp Suite Community Edition
2. Click "Next" on welcome screen
3. Accept license agreement
4. Choose "Temporary project" or "Save project"
5. Click "Start Burp"

### **Step 2: Configure Proxy**
1. Go to **Proxy** → **Options** → **Proxy Listeners**
2. Verify listener is running on `127.0.0.1:8080`
3. If not, click **Add** → Default bind to port `8080`

### **Step 3: Install CA Certificate**
1. Open browser and navigate to `http://burpsuite`
2. Click **CA Certificate** link
3. Download `cacert.der`
4. Install certificate:
   - **Chrome/Edge:** Settings → Privacy → Security → Manage certificates → Import → Select `cacert.der`
   - **Firefox:** Options → Privacy & Security → Certificates → View Certificates → Import → Select `cacert.der`

### **Step 4: Configure Browser Proxy**
1. **Chrome/Edge:** Install FoxyProxy extension or:
   - Settings → System → Open proxy settings
   - Manual proxy: `127.0.0.1:8080` for HTTP and HTTPS
2. **Firefox:** 
   - Settings → Network Settings → Manual proxy
   - HTTP Proxy: `127.0.0.1`, Port: `8080`
   - HTTPS Proxy: `127.0.0.1`, Port: `8080`

### **Step 5: Import Rapyd Configuration**
1. Open Burp Suite
2. Go to **Target** → **Scope**
3. Click **Load** → Select `programs/rapyd/burp_config/rapyd-burp-configuration.json`
4. Verify scope includes all Rapyd domains

### **Step 6: Configure X-Bugcrowd Header**
See `BURP_ADVANCED_TESTING.md` for detailed instructions.

---

## 🔧 **VERIFICATION**

### **Test Proxy Connection**
```bash
# In terminal, test proxy
curl -x http://127.0.0.1:8080 https://sandboxapi.rapyd.net/v1/payments/list \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen"
```

### **Check Burp Interception**
1. Enable **Proxy** → **Intercept** → **Intercept is on**
2. Visit any website in browser
3. Request should appear in Burp **Intercept** tab
4. Click **Forward** to send request

---

## 📚 **ADDITIONAL RESOURCES**

### **Burp Suite Documentation**
- User Manual: https://portswigger.net/burp/documentation
- Video Tutorials: https://portswigger.net/burp/documentation/desktop/getting-started/video-tutorials

### **Bug Bounty Testing with Burp**
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Burp Suite Extensions: https://portswigger.net/bappstore

### **Rapyd-Specific Configuration**
- See: `programs/rapyd/BURP_ADVANCED_TESTING.md`
- Config files: `programs/rapyd/burp_config/`

---

## ⚠️ **TROUBLESHOOTING**

### **Issue: Proxy not intercepting**
- Check browser proxy settings
- Verify Burp listener is running
- Check firewall isn't blocking port 8080

### **Issue: Certificate errors**
- Re-download and install CA certificate
- Clear browser cache
- Verify certificate is trusted

### **Issue: Can't connect to proxy**
- Check Burp listener port (default: 8080)
- Verify `127.0.0.1:8080` is correct
- Try different port if 8080 is in use

---

## ✅ **CHECKLIST**

- [ ] Burp Suite Community Edition downloaded
- [ ] Burp Suite installed
- [ ] CA certificate installed in browser
- [ ] Browser proxy configured (127.0.0.1:8080)
- [ ] Proxy interception tested
- [ ] Rapyd scope imported
- [ ] X-Bugcrowd header configured
- [ ] Ready to start testing!

---

**Next Steps:** Once Burp Suite is installed, proceed to `BURP_ADVANCED_TESTING.md` for configuration details!

