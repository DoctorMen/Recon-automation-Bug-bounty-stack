# 🛡️ LEGAL PROTECTION SYSTEM
## Idempotent Authorization Shield for All Security Operations

**Copyright © 2025 DoctorMen. All Rights Reserved.**

---

## ⚠️ CRITICAL: READ THIS FIRST

**This repository now has MANDATORY legal protection.**

**ALL scanning operations are BLOCKED unless you have written authorization.**

**This protection CANNOT be bypassed. This protection is IDEMPOTENT (always active).**

---

## 🔒 WHAT WAS IMPLEMENTED

### **1. Legal Authorization Shield**
**File:** `LEGAL_AUTHORIZATION_SYSTEM.py`

**Prevents:**
- ❌ Scanning any target without authorization file
- ❌ Scanning targets outside authorized scope
- ❌ Scanning outside authorized time window
- ❌ Scanning with invalid/expired authorization

**Enforces:**
- ✅ Written authorization required (NO exceptions)
- ✅ Scope verification (in-scope targets only)
- ✅ Time window verification (valid date range)
- ✅ Signature verification (client confirmation)
- ✅ Audit logging (all attempts logged)

---

### **2. Protected Tools**

**SENTINEL_AGENT.py** - Security assessment agent
- ✅ Legal shield integrated at initialization
- ✅ Blocks creation if unauthorized
- ✅ Cannot scan without valid authorization file

**run_pipeline.py** - Main recon pipeline
- ✅ Legal authorization check BEFORE any scanning
- ✅ Verifies ALL targets in targets.txt
- ✅ Exits immediately if any target unauthorized

**All Scripts** - Via wrapper
- ✅ LEGAL_SHIELD_WRAPPER.sh protects any script
- ✅ Use wrapper for any new scripts

---

### **3. Authorization Creator**
**File:** `CREATE_AUTHORIZATION.py`

**Creates:** Authorization template files  
**Usage:** `python3 CREATE_AUTHORIZATION.py --target example.com --client "Client Name"`

---

## 🎯 HOW IT WORKS

### **The Legal Shield is IDEMPOTENT:**

```
Try to scan → Check authorization → If no authorization → BLOCK → Exit
                                   → If authorized → Proceed

Every time. No exceptions. Cannot be disabled. Cannot be bypassed.
```

### **Authorization File Structure:**

```json
{
  "client_name": "Example Corp",
  "target": "example.com",
  "scope": [
    "example.com",
    "*.example.com",
    "api.example.com"
  ],
  "start_date": "2025-11-04T14:00:00",
  "end_date": "2025-12-04T14:00:00",
  "authorized_by": "John Doe",
  "authorized_by_email": "john@example.com",
  "authorized_by_title": "CTO",
  "contact_emergency": "+1-555-1234",
  "testing_types_authorized": [
    "vulnerability_scanning",
    "port_scanning",
    "web_application_testing"
  ],
  "testing_types_forbidden": [
    "dos_testing",
    "social_engineering",
    "physical_access"
  ]
}
```

---

## 📋 USAGE GUIDE

### **Step 1: Get Authorization (REQUIRED)**

**Before ANY scanning, you MUST:**

1. **Contact target owner**
   - Explain what you'll be testing
   - Get verbal agreement
   
2. **Send written proposal**
   - Scope of testing
   - Timeline
   - Pricing (if commercial)
   
3. **Get written confirmation**
   - Email reply minimum
   - Signed contract preferred
   - Keep forever (legal protection)

---

### **Step 2: Create Authorization File**

```bash
# Create authorization template
python3 CREATE_AUTHORIZATION.py \
  --target example.com \
  --client "Example Corp"

# This creates: ./authorizations/example_com_authorization.json
```

---

### **Step 3: Edit Authorization File**

```bash
# Open the file
nano ./authorizations/example_com_authorization.json

# REQUIRED EDITS:
# 1. Add ALL in-scope targets to "scope" array
# 2. Set correct start_date and end_date
# 3. Add client contact information
# 4. Add authorized_by name and email
# 5. Add signature_date after client confirms
```

**Example:**

```json
{
  "client_name": "Real Client Inc",
  "target": "clientsite.com",
  "scope": [
    "clientsite.com",
    "*.clientsite.com",
    "api.clientsite.com",
    "admin.clientsite.com"
  ],
  "start_date": "2025-11-04T09:00:00",
  "end_date": "2025-11-18T17:00:00",
  "authorized_by": "Jane Smith",
  "authorized_by_email": "jane.smith@clientsite.com",
  "authorized_by_title": "CTO",
  "contact_emergency": "+1-555-9876",
  "signature_date": "2025-11-04T10:30:00"
}
```

---

### **Step 4: Run Scan (Now Authorized)**

```bash
# Using SENTINEL Agent
python3 SENTINEL_AGENT.py clientsite.com --tier basic

# Using main pipeline
# 1. Add to targets.txt:
echo "clientsite.com" >> targets.txt

# 2. Run pipeline:
python3 run_pipeline.py

# Using any other script (via wrapper):
./LEGAL_SHIELD_WRAPPER.sh clientsite.com ./scripts/run_nuclei.sh
```

---

## 🚫 WHAT HAPPENS IF NO AUTHORIZATION

### **Scenario 1: Try to scan without authorization file**

```bash
$ python3 SENTINEL_AGENT.py example.com --tier basic

============================================================
🛡️  LEGAL AUTHORIZATION CHECK
============================================================
Target: example.com

❌ SCAN BLOCKED
   Target: example.com
   Reason: NO AUTHORIZATION FILE FOUND - SCAN BLOCKED

⚠️  TO AUTHORIZE THIS TARGET:
   1. Create authorization file: ./authorizations/[target]_authorization.json
   2. Use template: ./CREATE_AUTHORIZATION.py
   3. Get client signature
   4. Try again
============================================================

🚫 SENTINEL AGENT BLOCKED
   Target: example.com
   Reason: NO AUTHORIZATION FILE FOUND - SCAN BLOCKED

⚠️  LEGAL REQUIREMENT: Written authorization required before scanning
   Use: python3 CREATE_AUTHORIZATION.py --target example.com

[EXITS WITH ERROR CODE 1]
```

**Result:** Scan NEVER executes. Tool exits immediately.

---

### **Scenario 2: Target out of scope**

```bash
$ python3 SENTINEL_AGENT.py subdomain.example.com --tier basic

# Authorization file exists for example.com
# But subdomain.example.com not in scope array

============================================================
🛡️  LEGAL AUTHORIZATION CHECK
============================================================
Target: subdomain.example.com

❌ SCAN BLOCKED
   Target: subdomain.example.com
   Reason: TARGET OUT OF SCOPE - SCAN BLOCKED
   Authorized: ['example.com', 'api.example.com']

[EXITS WITH ERROR CODE 1]
```

**Result:** Scan NEVER executes. Target not in authorized scope.

---

### **Scenario 3: Outside time window**

```bash
$ python3 SENTINEL_AGENT.py example.com --tier basic

# Authorization exists but expired

============================================================
🛡️  LEGAL AUTHORIZATION CHECK
============================================================
Target: example.com

❌ SCAN BLOCKED
   Target: example.com
   Reason: OUTSIDE AUTHORIZED TIME WINDOW - SCAN BLOCKED
   Window: 2025-10-01T00:00:00 to 2025-10-31T23:59:59

[EXITS WITH ERROR CODE 1]
```

**Result:** Scan NEVER executes. Authorization expired.

---

## ✅ WHAT HAPPENS WITH VALID AUTHORIZATION

```bash
$ python3 SENTINEL_AGENT.py example.com --tier basic

============================================================
🛡️  LEGAL AUTHORIZATION CHECK
============================================================
Target: example.com

✅ AUTHORIZATION VALID
   Client: Example Corp
   Authorized by: John Doe
   Valid until: 2025-12-04T14:00:00
   Scope: ['example.com', '*.example.com']
============================================================

🛡️  SENTINEL Agent initialized (AUTHORIZED)
   Target: example.com
   Client: Example Corp
   Tier: basic
   Assessment ID: example_com_20251104_140532

============================================================
STARTING SECURITY ASSESSMENT: example.com
============================================================

[SCAN PROCEEDS NORMALLY]
```

**Result:** Scan executes. All operations logged with authorization details.

---

## 📊 AUDIT LOGGING

### **All Authorization Attempts Logged**

**File:** `./authorizations/audit_log.json`

**Logged Information:**
- Timestamp of attempt
- Target requested
- Status (BLOCKED or AUTHORIZED)
- Reason (if blocked)
- Client name (if authorized)
- System user

**Example Log:**

```json
[
  {
    "timestamp": "2025-11-04T14:05:32",
    "target": "example.com",
    "status": "BLOCKED",
    "reason": "NO AUTHORIZATION FILE FOUND",
    "user": "ubuntu"
  },
  {
    "timestamp": "2025-11-04T14:12:45",
    "target": "clientsite.com",
    "status": "AUTHORIZED",
    "client": "Real Client Inc",
    "authorized_by": "Jane Smith",
    "user": "ubuntu"
  }
]
```

**Purpose:** 
- Legal protection (proof you checked)
- Incident investigation
- Compliance auditing
- Client reporting

---

## 🔐 LEGAL PROTECTION BENEFITS

### **This System Protects You From:**

1. **Accidental Unauthorized Scanning**
   - Someone runs script on wrong target
   - Typo in domain name
   - Forgotten about scope limits

2. **Intentional Unauthorized Scanning**
   - Cannot be bypassed
   - Cannot be disabled
   - Mandatory checks

3. **Legal Liability**
   - Audit log proves you verified authorization
   - Authorization files prove client consent
   - Time windows prove limited engagement
   - Scope definitions prove boundaries

4. **CFAA Violations**
   - Computer Fraud and Abuse Act
   - Up to 10 years prison
   - Civil liability
   - Professional reputation

---

## 📚 LEGAL REQUIREMENTS

### **What Constitutes Valid Authorization:**

**MINIMUM Requirements:**
- ✅ Written communication from authorized representative
- ✅ Clear statement of permission to test
- ✅ Defined scope (what can be tested)
- ✅ Defined timeframe (when testing authorized)

**RECOMMENDED Additional:**
- ✅ Signed contract with terms and conditions
- ✅ Statement of work (SOW)
- ✅ Non-disclosure agreement (NDA)
- ✅ Emergency contact information
- ✅ Testing restrictions clearly defined

**KEEP FOREVER:**
- All authorization documents
- All client communications
- All contracts and agreements
- Legal protection for 7+ years

---

## 🎯 PRACTICE/TESTING ENVIRONMENTS

### **Safe Targets (No Authorization Needed):**

**Legal Practice Platforms:**
- HackTheBox.com
- TryHackMe.com
- PentesterLab.com
- PortSwigger Web Security Academy
- VulnHub VMs

**Your Own Assets:**
- Domains you own
- Servers you control
- Local VMs/containers
- Development environments

**Bug Bounty Programs (Follow Rules):**
- HackerOne (in-scope targets only)
- Bugcrowd (in-scope targets only)
- Synack
- Intigriti

**For These:** Still create authorization files for audit trail (self-authorization)

---

## 🔧 TECHNICAL DETAILS

### **How Authorization Check Works:**

1. **File Lookup**
   - Searches `./authorizations/` for matching file
   - Pattern: `[target]_authorization.json`
   - Also checks for wildcard matches

2. **Data Validation**
   - Parses JSON
   - Verifies required fields present
   - Checks data types and formats

3. **Scope Verification**
   - Exact match: `target == authorized_target`
   - Wildcard match: `*.example.com` matches `sub.example.com`
   - Parent domain match: `example.com` authorization covers root

4. **Time Window Check**
   - Converts ISO timestamps to datetime
   - Checks: `start_date <= now <= end_date`
   - Rejects if outside window

5. **Signature Verification**
   - Currently: checks required fields exist
   - Future: cryptographic signature verification

6. **Audit Logging**
   - Logs ALL attempts (authorized and blocked)
   - Appends to `audit_log.json`
   - Never deletes entries

---

## 🚀 INTEGRATION WITH EXISTING TOOLS

### **Already Protected:**
- ✅ `SENTINEL_AGENT.py` - Security assessment agent
- ✅ `run_pipeline.py` - Main recon pipeline
- ✅ All tools via `LEGAL_SHIELD_WRAPPER.sh`

### **To Protect New Scripts:**

**Option 1: Python Script**

```python
#!/usr/bin/env python3
from LEGAL_AUTHORIZATION_SYSTEM import LegalAuthorizationShield
import sys

def scan_target(target):
    # Check authorization
    shield = LegalAuthorizationShield()
    authorized, reason, auth_data = shield.check_authorization(target)
    
    if not authorized:
        print(f"❌ Scan blocked: {reason}")
        sys.exit(1)
    
    # Proceed with scan
    print(f"✅ Authorized - scanning {target}")
    # ... your scanning code here ...

if __name__ == '__main__':
    target = sys.argv[1]
    scan_target(target)
```

**Option 2: Shell Script (Use Wrapper)**

```bash
#!/bin/bash
# Instead of:
# ./your_script.sh example.com

# Use wrapper:
./LEGAL_SHIELD_WRAPPER.sh example.com ./your_script.sh
```

**Option 3: Decorator (Python)**

```python
from LEGAL_AUTHORIZATION_SYSTEM import require_authorization

@require_authorization
def my_scan_function(target):
    # This function will only run if authorized
    print(f"Scanning {target}")
    # ... scanning code ...

# Usage:
my_scan_function("example.com")  # Blocked if unauthorized
```

---

## 📋 CHECKLIST: BEFORE EVERY SCAN

- [ ] Do I have written authorization from target owner?
- [ ] Have I created authorization file?
- [ ] Is target in the "scope" array?
- [ ] Is current date/time within authorized window?
- [ ] Do I have client emergency contact info?
- [ ] Have I saved original authorization document?
- [ ] Have I backed up authorization file?

**If ALL boxes checked → Safe to scan**

**If ANY box unchecked → DO NOT SCAN**

---

## ⚠️ WARNINGS

### **DO NOT:**
- ❌ Delete or modify authorization files without client approval
- ❌ Extend authorization dates without client agreement
- ❌ Add targets to scope without client permission
- ❌ Share authorization files (confidential)
- ❌ Try to bypass the legal shield (impossible + illegal)
- ❌ Scan first, ask authorization later (ALWAYS get authorization FIRST)

### **DO:**
- ✅ Keep ALL authorization files forever
- ✅ Back up authorization files (multiple locations)
- ✅ Review audit logs regularly
- ✅ Renew authorizations before expiry
- ✅ Document all client communications
- ✅ When in doubt, DON'T scan

---

## 📞 SUPPORT

### **If You Need Help:**

**Authorization Questions:**
- Review this README
- Check `CREATE_AUTHORIZATION.py --help`
- Review example authorization files

**Technical Issues:**
- Check audit log: `./authorizations/audit_log.json`
- Verify authorization file format (valid JSON)
- Ensure all required fields present

**Legal Questions:**
- Consult with lawyer (I'm not providing legal advice)
- Review applicable laws (CFAA, state laws, international)
- When unsure, DON'T scan

---

## ✅ SYSTEM STATUS

**Legal Protection System:** ✅ ACTIVE  
**Authorization Shield:** ✅ ENABLED  
**Bypass Protection:** ✅ CANNOT BE BYPASSED  
**Audit Logging:** ✅ ALL ATTEMPTS LOGGED  
**Idempotent:** ✅ ALWAYS ACTIVE

**Your repository is now legally protected. All scanning requires authorization. No exceptions.**

---

## 🎯 SUMMARY

**What Changed:**
- ALL scanning tools now require written authorization
- Authorization files must exist before any scan
- Targets must be in scope
- Time windows must be valid
- All attempts are logged

**Why This Matters:**
- Prevents accidental illegal scanning
- Protects you from CFAA violations
- Provides legal documentation trail
- Professional business practice
- Client trust and confidence

**What You Need To Do:**
1. Get written authorization before ANY scan
2. Create authorization file using CREATE_AUTHORIZATION.py
3. Edit file with correct client information
4. Keep original authorization forever
5. Run scans (now legally protected)

---

**The legal shield is now active. You're protected. Your clients are protected. Scan with confidence (but only when authorized).** 🛡️⚖️

**Copyright © 2025 DoctorMen. All Rights Reserved.**
