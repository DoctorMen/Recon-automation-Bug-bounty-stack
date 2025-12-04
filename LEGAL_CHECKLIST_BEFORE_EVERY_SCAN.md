<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# ⚠️ LEGAL CHECKLIST - BEFORE EVERY SCAN

**⚡ PRINT THIS AND CHECK EVERY BOX BEFORE ANY SECURITY TESTING ⚡**

---

## 🚨 STOP! READ THIS FIRST!

**Unauthorized security testing is ILLEGAL and can result in:**
- Criminal prosecution under CFAA (Computer Fraud and Abuse Act)
- Civil lawsuits for damages
- Professional reputation destruction
- Financial ruin
- Imprisonment (up to 10+ years for serious violations)

**This checklist protects you. Use it EVERY TIME.**

---

## ✅ PRE-ENGAGEMENT LEGAL CHECKLIST

### **📋 AUTHORIZATION (MANDATORY)**

**Client Information:**
- [ ] Client name documented: _____________________________
- [ ] Company name verified: _____________________________
- [ ] Contact person identified: _____________________________
- [ ] Contact email/phone: _____________________________
- [ ] Emergency contact: _____________________________

**Written Authorization:**
- [ ] **SIGNED authorization agreement received**
- [ ] Authorization document filed securely
- [ ] Authorization document includes client signature
- [ ] Authorization document includes your signature
- [ ] Authorization dated and clearly visible
- [ ] Copy of authorization stored in client folder
- [ ] Backup copy of authorization saved separately

**Scope Definition:**
- [ ] Target domain(s) clearly listed: _____________________________
- [ ] Target IP address(es) documented: _____________________________
- [ ] Authorized testing methods specified (check all approved):
  - [ ] Vulnerability scanning
  - [ ] Penetration testing
  - [ ] Social engineering (if applicable)
  - [ ] Web application testing
  - [ ] Network infrastructure testing
  - [ ] Other: _____________________________

**Testing Window:**
- [ ] Testing period defined: From _________ To _________
- [ ] Testing hours specified: _____________________________
- [ ] Weekend/holiday testing approval: Yes [ ] No [ ]
- [ ] Production system testing approval: Yes [ ] No [ ]
  - **If YES, extra caution required and backup procedures mandatory**

**Prohibited Activities Confirmed:**
- [ ] DoS/DDoS attacks: PROHIBITED (unless explicitly authorized)
- [ ] Data exfiltration: PROHIBITED
- [ ] Social engineering: PROHIBITED (unless explicitly authorized)
- [ ] Physical security testing: PROHIBITED (unless explicitly authorized)
- [ ] Other restrictions: _____________________________

---

### **🛡️ INSURANCE & LEGAL PROTECTION**

**Insurance Coverage:**
- [ ] Cyber liability insurance active and current
- [ ] Coverage amount: $________ (minimum $1M-$2M)
- [ ] Policy number: _____________________________
- [ ] Insurance expiration date: _____________________________
- [ ] Insurance company contact: _____________________________
- [ ] Client added as additional insured (if required)

**Legal Documents:**
- [ ] Non-Disclosure Agreement (NDA) signed (if required)
- [ ] Statement of Work (SOW) executed
- [ ] Liability limitations clearly stated in contract
- [ ] Payment terms agreed upon
- [ ] Indemnification clause reviewed
- [ ] Attorney reviewed contract (for high-value engagements)

---

### **🔧 TECHNICAL PREPARATION**

**Tools & Methods:**
- [ ] Only non-destructive tools will be used
- [ ] Rate limiting configured (10 req/sec reconnaissance, 150 req/sec scanning)
- [ ] Error thresholds set (auto-stop if 3+ errors)
- [ ] Authorization verification script tested
- [ ] Emergency stop procedures reviewed
- [ ] Audit logging enabled for all activities

**Authorization Verification Command:**
```bash
# RUN THIS BEFORE EVERY SCAN:
python3 scripts/verify_authorization.py \
  --client "Client Name" \
  --domain target.com \
  --check-all-requirements
```

**Expected Output:**
```
✅ Authorization document found
✅ Scope includes target.com
✅ Testing window is active
✅ Insurance coverage verified
✅ Emergency contacts documented
✅ ALL CHECKS PASSED - AUTHORIZED TO PROCEED
```

**If ANY check fails → STOP and resolve before proceeding**

---

### **📞 EMERGENCY CONTACTS**

**Client Contacts:**
- [ ] Primary contact: _____________________________
- [ ] Phone: _____________________________
- [ ] Email: _____________________________
- [ ] Emergency contact (24/7): _____________________________
- [ ] Escalation contact: _____________________________

**Your Legal Contacts:**
- [ ] Your attorney: _____________________________
- [ ] Insurance agent: _____________________________
- [ ] Law enforcement liaison: _____________________________

---

### **🔐 SECURITY & PRIVACY**

**Data Protection:**
- [ ] Understand client's data classification levels
- [ ] Know which data is PII/PHI/PCI (if applicable)
- [ ] Encryption ready for all findings and reports
- [ ] Secure storage prepared for scan results
- [ ] Data deletion schedule agreed upon

**Compliance Requirements:**
- [ ] Industry identified: _____________________________
- [ ] Relevant regulations (check all that apply):
  - [ ] GDPR (EU)
  - [ ] CCPA (California)
  - [ ] HIPAA (Healthcare)
  - [ ] PCI-DSS (Payment Card)
  - [ ] SOX (Finance)
  - [ ] FERPA (Education)
  - [ ] FedRAMP (US Government)
  - [ ] Other: _____________________________

---

### **📝 DOCUMENTATION & LOGGING**

**Audit Trail Setup:**
- [ ] Logging enabled for all security activities
- [ ] Timestamp synchronization verified
- [ ] Log storage location confirmed: _____________________________
- [ ] Log retention period agreed: ________ (minimum 1 year)
- [ ] Authorization logs will be preserved (7 years)

**Documentation Prepared:**
- [ ] Engagement folder created: _____________________________
- [ ] Authorization documents filed
- [ ] Client contact information documented
- [ ] Scope documentation saved
- [ ] Emergency procedures printed and available

---

### **⚡ SAFE PRACTICES CONFIRMED**

**Reconnaissance (Phase 1):**
- [ ] Will verify authorization before reconnaissance
- [ ] Will use rate limiting (10 req/sec max)
- [ ] Will log all reconnaissance activities
- [ ] Will only enumerate in-scope domains/IPs

**Vulnerability Scanning (Phase 2):**
- [ ] Will verify authorization before scanning
- [ ] Will exclude destructive templates
- [ ] Will use rate limiting (150 req/sec max)
- [ ] Will monitor for errors (auto-stop threshold set)
- [ ] Will scan only during approved testing window

**Exploitability Verification (Phase 3):**
- [ ] **EXPLICIT permission received for exploit verification**
- [ ] Will use proof-of-concept only (no data access)
- [ ] Will notify client before exploitability testing
- [ ] Will stop immediately if any issues detected
- [ ] Will document every exploitation attempt

**Reporting (Phase 4):**
- [ ] Will encrypt all reports before delivery
- [ ] Will use secure delivery method
- [ ] Will mark reports as CONFIDENTIAL
- [ ] Will provide clear remediation guidance
- [ ] Will offer re-testing to verify fixes

---

### **🚨 EMERGENCY PROCEDURES REVIEWED**

**If Anything Goes Wrong:**

**STEP 1: STOP IMMEDIATELY**
```bash
python3 scripts/emergency_stop.py --stop-all-scans \
  --notify-client --log-incident
```

**STEP 2: NOTIFY CLIENT** (within 15 minutes)
- Call emergency contact: _____________________________
- Email primary contact immediately
- Document timeline of events

**STEP 3: DOCUMENT INCIDENT**
```bash
python3 scripts/incident_report.py \
  --describe "What happened" \
  --send-to-client --preserve-logs
```

**STEP 4: ASSIST WITH REMEDIATION**
- Offer technical assistance
- Provide detailed logs
- Help restore normal operations

**STEP 5: REPORT TO INSURANCE**
- Contact insurance agent immediately
- Provide all documentation
- Follow insurance company procedures

**STEP 6: LEGAL COUNSEL**
- Contact your attorney if serious incident
- Do not make public statements without legal advice
- Preserve all evidence and documentation

---

## ✅ FINAL PRE-SCAN VERIFICATION

**Before clicking "Start Scan":**

- [ ] **I have SIGNED written authorization**
- [ ] **Insurance is active and current**
- [ ] **Client is aware testing is starting**
- [ ] **Emergency contacts are documented**
- [ ] **Authorization verification script passed all checks**
- [ ] **I understand the scope and limitations**
- [ ] **I have reviewed emergency procedures**
- [ ] **Audit logging is enabled**
- [ ] **I am operating within legal boundaries**
- [ ] **I accept full responsibility for my actions**

**If ALL boxes are checked → AUTHORIZED TO PROCEED**

**If ANY box is UNCHECKED → DO NOT PROCEED**

---

## 🎖️ MILITARY VETERAN REMINDER

**Your Oath Continues:**

*"I will support and defend... against all enemies, foreign and domestic..."*

- **Honor:** Do the right thing, even when no one is watching
- **Integrity:** Maintain the highest ethical standards
- **Service:** Protect client interests as you would protect your unit
- **Discipline:** Follow rules of engagement strictly
- **Accountability:** Take responsibility for all actions

**You are operating as a professional security expert, not a hacker.**

---

## 📅 ENGAGEMENT LOG

**Use this section to track each engagement:**

**Engagement #___**
- Date: _____________________________
- Client: _____________________________
- Domain(s): _____________________________
- Authorization Verified: Yes [ ] No [ ]
- Insurance Verified: Yes [ ] No [ ]
- Scan Started: _____________________________
- Scan Completed: _____________________________
- Report Delivered: _____________________________
- Client Satisfied: Yes [ ] No [ ]
- Legal Issues: None [ ] Describe: _____________________________
- Lessons Learned: _____________________________

---

## ⚠️ WARNING SIGNS - STOP IMMEDIATELY

**If client says or requests:**

❌ "Just do a quick scan, we don't need paperwork"  
❌ "Test our competitor's website"  
❌ "See if you can access their customer database"  
❌ "We need this done now, authorization later"  
❌ "Don't tell anyone about this project"  
❌ "Take down their website for a few hours"  
❌ "Find dirt on them for our lawsuit"  
❌ "Bypass their security and show us what you find"  

**= DECLINE THE PROJECT IMMEDIATELY. THIS IS ILLEGAL.**

---

## 📞 EMERGENCY NUMBERS

**Keep these handy:**

**Your Legal Team:**
- Attorney: _____________________________
- Insurance Agent: _____________________________

**Law Enforcement:**
- FBI IC3 (Internet Crime): https://www.ic3.gov
- Local cybercrime unit: _____________________________

**Professional Resources:**
- EFF (Legal guidance): https://www.eff.org
- SANS Ethics Hotline: _____________________________
- Bug Bounty Platform Support: _____________________________

---

## 🎯 COMMITMENT STATEMENT

**I, _________________, commit to:**

1. Only conduct authorized security testing
2. Obtain written permission before every engagement
3. Maintain active insurance coverage
4. Use non-destructive methods only
5. Document everything for audit trail
6. Stop immediately if issues arise
7. Operate within legal and ethical boundaries
8. Protect client data and privacy
9. Follow responsible disclosure practices
10. Maintain the highest professional standards

**Signature:** _____________________________  
**Date:** _____________________________

---

## ✅ POST-SCAN CHECKLIST

**After completing testing:**

- [ ] All scans completed within authorized scope
- [ ] No unauthorized activities performed
- [ ] No incidents or issues occurred (or properly documented if occurred)
- [ ] All findings documented accurately
- [ ] Report encrypted and ready for delivery
- [ ] Client notified of completion
- [ ] Audit logs preserved
- [ ] Authorization documents archived (7 years)
- [ ] Payment received (or invoiced)
- [ ] Testimonial requested (if appropriate)
- [ ] Lessons learned documented for continuous improvement

---

**© 2025 - Legal Protection Checklist**  
**Version 3.0 - November 3, 2025**

**KEEP THIS CHECKLIST VISIBLE DURING ALL SECURITY TESTING**

**Your legal protection depends on following these procedures EVERY TIME.**

---

**"Measure twice, cut once. Verify authorization twice, scan once."**

