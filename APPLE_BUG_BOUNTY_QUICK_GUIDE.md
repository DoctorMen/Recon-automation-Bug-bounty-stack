<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Apple Bug Bounty - Quick Reference Guide

## ✅ You Have an Account - What's Next?

### Step 1: Verify Scope
**Go to:** https://security.apple.com/bounty/guidelines/

**Check if these are in scope:**
- Web/CDN endpoints
- CDN subdomains (2b4a6b31ca2273bb.apple.com)
- API endpoints

**⚠️ Important:** Apple's program focuses on iOS/macOS/iCloud, NOT web CDN endpoints.

---

### Step 2: Understand Apple's Program

**Apple Security Bounty focuses on:**
- ✅ iOS vulnerabilities
- ✅ macOS vulnerabilities  
- ✅ Safari security
- ✅ iCloud security
- ✅ Apple ID authentication
- ✅ Hardware security

**Typically OUT OF SCOPE:**
- ❌ CDN endpoints (like yours)
- ❌ Third-party services
- ❌ Denial of service
- ❌ Social engineering

---

### Step 3: Test Safely (If In Scope)

**Safe testing rules:**
1. ✅ Single requests only (no automation)
2. ✅ No rate limiting abuse
3. ✅ No data exfiltration
4. ✅ Document everything
5. ✅ Stop if you get 403/401 (protected)

**Test commands:**
```bash
# Basic connectivity
curl -v http://2b4a6b31ca2273bb.apple.com/api/checkout

# Check headers
curl -I http://2b4a6b31ca2273bb.apple.com/api/checkout

# Follow redirects
curl -L http://2b4a6b31ca2273bb.apple.com/api/checkout
```

---

### Step 4: Document Findings

**Required for submission:**
1. **Clear title:** "Vulnerability Type in Component"
2. **Description:** What, where, how
3. **Steps to reproduce:** Numbered, exact steps
4. **Proof of concept:** Screenshots, HTTP requests/responses
5. **Impact:** What can attacker do? Who's affected?

---

### Step 5: Submit Your Finding

**Submission process:**
1. Go to: https://security.apple.com/bounty/
2. Sign in with Apple ID
3. Click "Submit a Report"
4. Fill out form:
   - Title
   - Description
   - Steps to reproduce
   - Impact
   - Attach screenshots/files
5. Submit

**⚠️ Important:**
- Be honest about scope
- If out of scope, they'll reject it
- But you won't get in trouble if honest

---

### Step 6: Alternative - Focus on Rapyd Instead

**💡 Recommendation:** Instead of Apple CDN endpoints, focus on Rapyd

**Why Rapyd:**
- ✅ Confirmed in scope
- ✅ Full safe harbor protection
- ✅ You already have API keys
- ✅ High rewards ($1,500-$4,500)
- ✅ Bonus rewards until Nov 29

**Rapyd endpoints:**
- sandboxapi.rapyd.net/v1
- dashboard.rapyd.net
- verify.rapyd.net
- checkout.rapyd.net

**Rapyd program:** https://bugcrowd.com/engagements/rapyd

---

## Quick Links

- **Apple Security Bounty:** https://security.apple.com/bounty/
- **Apple Guidelines:** https://security.apple.com/bounty/guidelines/
- **Rapyd Program:** https://bugcrowd.com/engagements/rapyd

---

## Next Steps

1. ✅ Verify scope at Apple's guidelines page
2. ✅ If in scope: Test safely, document, submit
3. ✅ If out of scope: Focus on Rapyd instead (safer, higher ROI)

**Good luck! 🎯**








