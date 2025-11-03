# ACTION PLAN - TODAY (15 Minutes)

**Date:** November 1, 2025  
**Priority:** 🔥 URGENT - Rapyd Promotion Ends November 29!

---

## ⚡ **YOUR NEXT 15 MINUTES**

### **Step 1: Account Setup (5 minutes)**

1. **Go to:** https://dashboard.rapyd.net
2. **Sign up with:**
   - Email: `DoctorMen@bugcrowdninja.com` ✅ (Already created!)
   - Country: **Iceland** ✅ (Already selected!)
3. **Complete verification:**
   - Finish Iceland onboarding form
   - Upload address verification document
   - Verify email

### **Step 2: Generate API Keys (5 minutes)**

1. **Navigate to:** https://dashboard.rapyd.net/developers/api-keys
2. **Generate:**
   - Sandbox API keys
   - Production API keys (optional)
3. **Save securely:**
   - Store in secure password manager
   - **DO NOT commit to git!**
   - Export to environment variables for testing

### **Step 3: Download & Configure Tools (5 minutes)**

1. **Burp Suite:**
   - ✅ Download link opened in browser
   - Install Burp Suite Community Edition
   - Import config: `programs/rapyd/burp_config/rapyd-burp-configuration.json`
   - Configure X-Bugcrowd header (see `BURP_ADVANCED_TESTING.md`)

2. **Postman (Optional):**
   - Download Postman
   - Import Rapyd API collection from docs.rapyd.net

---

## ✅ **CHECKLIST**

- [ ] Rapyd account created ✅
- [ ] Country set to Iceland ✅
- [ ] Account verification completed
- [ ] API keys generated
- [ ] Burp Suite downloaded
- [ ] Burp Suite installed
- [ ] Burp config imported
- [ ] X-Bugcrowd header configured
- [ ] Ready to start testing!

---

## 🎯 **AFTER COMPLETION**

Once all items are checked:

1. **Run Reconnaissance:**
   ```bash
   cd "C:\Users\Doc Lab\.cursor\worktrees\Recon-automation-Bug-bounty-stack\bi6DL"
   python3 run_pipeline.py --targets programs/rapyd/targets.txt --output output/rapyd
   ```

2. **Start Manual Testing:**
   - Review `programs/rapyd/BURP_ADVANCED_TESTING.md`
   - Follow `programs/rapyd/TESTING_CHECKLIST.md`
   - Document findings in `programs/rapyd/findings/FINDINGS_LOG.md`

---

## 📚 **QUICK REFERENCE**

- **Testing Guide:** `RAPYD_TESTING_GUIDE.md`
- **Burp Setup:** `programs/rapyd/BURP_ADVANCED_TESTING.md`
- **Quick Reference:** `QUICK_REFERENCE.md`
- **Program Details:** `bug_bounty_program_tracker.md`

---

**🔥 REMINDER: Promotion ends November 29, 2025 - 28 days remaining!**

