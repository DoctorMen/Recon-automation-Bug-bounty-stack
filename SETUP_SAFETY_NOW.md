<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🛡️ SETUP SAFETY SYSTEM - DO THIS NOW

**Created:** November 4, 2025  
**Priority:** CRITICAL - Do before ANY scanning  
**Time Required:** 5 minutes

---

## ⚡ QUICK SETUP (5 Minutes)

### **STEP 1: Add Your First Scope (2 minutes)**

Let's add Shopify as a practice target (safe to scan):

```bash
cd ~/Recon-automation-Bug-bounty-stack

# Add Shopify scope
python3 MASTER_SAFETY_SYSTEM.py add-scope
```

**When prompted, enter:**
```
Program name: Shopify Bug Bounty
In-scope domains: *.shopify.com,shopify.dev,myshopify.com
Out-of-scope domains: admin.shopify.com,payments.shopify.com
```

---

### **STEP 2: Test the Safety System (1 minute)**

```bash
# Test if Shopify is safe to scan
python3 MASTER_SAFETY_SYSTEM.py test shopify.com

# Should output: ✅ Target is SAFE to scan
```

---

### **STEP 3: Add Authorization (2 minutes)**

```bash
# Add authorization for Shopify
python3 authorization_checker.py add
```

**When prompted, enter:**
```
Target domain/system: shopify.com
Authorization Type: 2 (Bug Bounty Program)
Client/Program Name: Shopify Bug Bounty
Contract/Reference Number: HackerOne-Shopify-Public
Scope: web_scan,api_test,subdomain_enum
Expiry Date: 2025-12-31
Contact Email: security@shopify.com
Notes: Public bug bounty program on HackerOne
```

---

## ✅ YOU'RE NOW PROTECTED

Your system now has **3 layers of protection**:

1. **Authorization Check** - Verifies you have permission
2. **Scope Check** - Ensures target is in defined scope
3. **Rate Limiting** - Prevents accidental DoS
4. **Dangerous Target Block** - Blocks .gov, .mil, etc.
5. **Format Validation** - Checks target is valid
6. **Destructive Operation Block** - Prevents harmful actions

---

## 🎯 HOW TO USE IN YOUR SCANS

### **Method 1: Automatic (Recommended)**

Your pipeline automatically uses safety system:

```bash
# Just run normally - safety checks happen automatically
python3 run_pipeline.py
```

---

### **Method 2: Manual Check (Testing)**

Test a target before scanning:

```bash
# Check if target is safe
python3 MASTER_SAFETY_SYSTEM.py test example.com

# If ✅ - proceed
# If ❌ - blocked (see reason)
```

---

## 🚨 EMERGENCY COMMANDS

### **Stop ALL Operations:**
```bash
python3 MASTER_SAFETY_SYSTEM.py emergency-stop
```

### **Resume Operations:**
```bash
python3 MASTER_SAFETY_SYSTEM.py resume
```

### **Block a Specific Target:**
```bash
python3 MASTER_SAFETY_SYSTEM.py block malicious.com "Dangerous target"
```

---

## 📋 ADD MORE PROGRAMS

### **Example: Add GitHub:**

```bash
python3 MASTER_SAFETY_SYSTEM.py add-scope
```

**Enter:**
```
Program name: GitHub Bug Bounty
In-scope domains: *.github.com,github.io,githubusercontent.com
Out-of-scope domains: enterprise.github.com
```

---

### **Example: Add Client Project:**

```bash
python3 MASTER_SAFETY_SYSTEM.py add-scope
```

**Enter:**
```
Program name: Client - Acme Corp
In-scope domains: acmecorp.com,*.acmecorp.com
Out-of-scope domains: admin.acmecorp.com,internal.acmecorp.com
```

---

## ⚠️ WHAT GETS AUTOMATICALLY BLOCKED

**The system automatically blocks:**

### **1. Government/Military:**
- ❌ `.gov` domains
- ❌ `.mil` domains
- ❌ FBI, CIA, NSA, Pentagon
- ❌ Defense.gov, whitehouse.gov

### **2. Critical Infrastructure:**
- ❌ Power plants
- ❌ Nuclear facilities
- ❌ Hospitals
- ❌ Emergency services

### **3. Educational:**
- ❌ `.edu` domains (unless authorized)

### **4. Rate Limits:**
- ❌ More than 20 requests/minute per target
- ❌ More than 100 requests/minute globally

### **5. Invalid Targets:**
- ❌ localhost, 127.0.0.1
- ❌ Invalid domain formats

---

## 🎯 EXAMPLE WORKFLOW

### **Safe Bug Bounty Hunting:**

```bash
# 1. Add program scope
python3 MASTER_SAFETY_SYSTEM.py add-scope
# Enter: Shopify, *.shopify.com, etc.

# 2. Add authorization
python3 authorization_checker.py add
# Enter: Shopify details

# 3. Test it's safe
python3 MASTER_SAFETY_SYSTEM.py test shopify.com
# Should show: ✅ SAFE

# 4. Run your scan
python3 run_pipeline.py
# Safety checks happen automatically
```

---

## 📊 CHECK YOUR PROTECTION STATUS

```bash
# List all authorized targets
python3 authorization_checker.py list

# View all scopes
cat .protection/scope_definitions.json

# View blocked targets
cat .protection/blocked_targets.json

# View safety logs
cat .protection/safe_operations.log
```

---

## ✅ VERIFICATION CHECKLIST

Before scanning ANY target, verify:

- [ ] Target is added to scope
- [ ] Authorization is documented
- [ ] Safety test passes
- [ ] Not a .gov/.mil domain
- [ ] Within rate limits
- [ ] Have written permission (if not public bug bounty)

---

## 🛡️ LEGAL PROTECTION

**This system protects you from:**

1. ✅ Accidentally scanning unauthorized targets
2. ✅ Going outside client/program scope
3. ✅ Causing accidental denial of service
4. ✅ Scanning government systems
5. ✅ Legal violations
6. ✅ Reputation damage

**You STILL need:**
- Written authorization for client work
- Bug bounty program enrollment
- Professional liability insurance
- Documentation of all activities

---

## 🎯 NEXT STEPS

1. **Add 3-5 bug bounty programs to your scope**
2. **Test each one**: `python3 MASTER_SAFETY_SYSTEM.py test <target>`
3. **Run a safe scan** on authorized target
4. **Check logs** to verify safety system worked

---

**YOU ARE NOW PROTECTED** ✅

All your scans will:
- Check authorization first
- Verify scope
- Enforce rate limits
- Block dangerous targets
- Log all activities

**Start scanning safely!**
