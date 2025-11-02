# Rapyd Bug Bounty Testing Guide

**Created:** November 1, 2025  
**Account:** DoctorMen@bugcrowdninja.com  
**Status:** Account Created ✅ | API Keys: Pending Verification

---

## 🎯 **CRITICAL PROMOTION INFO**

### **API Testing Promotion (October 29 - November 29, 2025)**

**🔥 BONUS REWARDS:**
- **+$500 Bonus** – High-Impact Logic Flaw: For validated issues causing unintended API states, misconfigurations, or logic inconsistencies
- **+$1,000 Bonus** – Critical Bypass / Transaction Integrity: For confirmed vulnerabilities compromising financial transactions, authentication, or sensitive data protection
- **Exclusive Swag** – Limited-edition Rapyd researcher gear for top submissions

**⚠️ DEADLINE:** November 29, 2025 (28 days remaining!)

---

## 💰 **REWARD STRUCTURE**

### **Tier 3 Premium (API Testing - PRIMARY FOCUS)**
- **P1 (Critical):** $5,000 - $7,500
- **P2 (High):** $1,500 - $4,500
- **P3 (Medium):** $600 - $1,400
- **P4 (Low):** $100 - $500

### **Tier 2 (Dashboard)**
- **P1:** $2,800 - $5,500
- **P2:** $1,300 - $2,500
- **P3:** $400 - $1,200
- **P4:** $100 - $400

### **PCI-Related Findings**
- Minimum bonus: **$500** (plus base reward)
- Increased rewards based on impact

---

## 📋 **REQUIREMENTS & SETUP**

### **✅ Account Setup (COMPLETED)**
- **Email:** DoctorMen@bugcrowdninja.com ✅
- **Country:** Iceland (selected for production mode) ✅
- **Account Status:** Created, verification pending ⚠️
- **API Keys:** Need to generate after verification

### **⚠️ CRITICAL HEADERS**
Every API request MUST include:
```
X-Bugcrowd: Bugcrowd-DoctorMen
```

**Burp Configuration:** Download from Bugcrowd program page attachments:
- `rapyd-burp-configuration.json`

### **🔐 API Keys Location**
API keys will be available at:
- **Dashboard:** `https://dashboard.rapyd.net/developers/api-keys`
- **Note:** May require account verification first

---

## 🎯 **TESTING TARGETS**

### **Priority 1: API Endpoints (sandboxapi.rapyd.net/v1)**
**Tier 3 Premium rewards - HIGHEST PRIORITY**

**Focus Areas:**
1. **Authentication & Authorization**
   - Unauthorized access
   - Privilege escalation
   - Access control bypass

2. **Transaction & Business Logic**
   - Amount manipulation
   - Currency manipulation
   - Payment outcome manipulation
   - Race conditions in refunds/transfers
   - Wallet balance manipulation

3. **Data Security & Integrity**
   - Merchant data exposure
   - Customer data exposure
   - Sensitive information alteration

4. **Input Validation & Injection**
   - SQL injection
   - XSS
   - Command injection
   - Other injection flaws

### **Priority 2: Dashboard (dashboard.rapyd.net)**
**Two Testing Modes:**
- **Sandbox Mode:** All users are admins
- **Production Mode:** Users and permissions can be tested (Iceland required ✅)

**Focus Areas:**
- IDOR (Insecure Direct Object References)
- CSRF on authenticated forms
- XSS in input fields
- Business logic flaws
- Session management issues

### **Priority 3: Hosted Pages**
- **verify.rapyd.net** - Identity verification bypass
- **checkout.rapyd.net** - Payment flow manipulation

---

## 🔍 **TOP SUBMITTED VULNERABILITIES**

Based on Bugcrowd program data, focus on:
1. **Email template injections** - Sanitization issues
2. **Race conditions** - Multiple refunds/transactions
3. **Business logic flaws** - Wallet balance manipulation with incorrect amounts

---

## 📝 **TESTING METHODOLOGY**

### **Phase 1: API Reconnaissance**
1. **Review API Documentation**
   - Visit: `https://docs.rapyd.net`
   - Identify all endpoints
   - Understand authentication mechanism
   - Map out transaction flows

2. **Generate API Keys**
   - Complete account verification
   - Navigate to Developers → API Keys
   - Generate sandbox keys
   - Test signature generation

3. **Initial API Testing**
   - Use Postman collection from docs
   - Configure Burp with X-Bugcrowd header
   - Test basic authentication
   - Verify signature works

### **Phase 2: Authentication Testing**
- [ ] API key exposure in responses
- [ ] Weak signature validation
- [ ] Token reuse issues
- [ ] Privilege escalation
- [ ] Authorization bypass

### **Phase 3: Transaction Logic Testing**
- [ ] Negative amount manipulation
- [ ] Currency conversion flaws
- [ ] Wallet balance manipulation
- [ ] Refund logic bypass
- [ ] Transfer amount manipulation
- [ ] Race conditions (multiple concurrent requests)

### **Phase 4: Business Logic Testing**
- [ ] Payment flow bypasses
- [ ] Status manipulation
- [ ] Duplicate transaction prevention
- [ ] Limit bypasses
- [ ] State machine manipulation

### **Phase 5: Input Validation Testing**
- [ ] SQL injection in all input fields
- [ ] XSS in response data
- [ ] Command injection
- [ ] XXE (if XML used)
- [ ] Path traversal (if file operations)

### **Phase 6: Dashboard Testing**
- [ ] IDOR in URLs/API calls
- [ ] CSRF on sensitive actions
- [ ] XSS in form inputs
- [ ] Business logic flaws
- [ ] Permission bypasses

---

## 🛠️ **TOOLS & SETUP**

### **Required Tools**
1. **Burp Suite Professional**
   - Load `rapyd-burp-configuration.json`
   - Configure proxy
   - Add X-Bugcrowd header globally

2. **Postman**
   - Import Rapyd API collection
   - Test signature generation
   - Send test requests

3. **API Documentation**
   - Bookmark: `https://docs.rapyd.net`
   - Understand request/response formats
   - Learn signature algorithm

### **Burp Configuration**
```json
{
  "target": {
    "scope": {
      "include": [
        {
          "protocol": "https",
          "host": "sandboxapi.rapyd.net"
        },
        {
          "protocol": "https",
          "host": "dashboard.rapyd.net"
        }
      ]
    }
  },
  "headers": [
    {
      "name": "X-Bugcrowd",
      "value": "Bugcrowd-DoctorMen"
    }
  ]
}
```

---

## 📊 **REPORTING REQUIREMENTS**

### **Required Information**
- [ ] Clear title describing vulnerability
- [ ] Severity assessment (P1/P2/P3/P4)
- [ ] Step-by-step reproduction
- [ ] **HTTP request and response** (mandatory)
- [ ] **Operation ID** (if present in response)
- [ ] Screenshots/screen recording
- [ ] Impact description
- [ ] Suggested remediation

### **Report Template**
```markdown
# Title: [Severity] [Vulnerability Type] in [Endpoint/Feature]

## Summary
Brief description of the vulnerability

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Request
```
[Full HTTP request with headers]
```

## Response
```
[Full HTTP response]
```

## Operation ID
[If present]

## Impact
Explain the security impact

## Remediation
Suggest how to fix
```

---

## ⚠️ **OUT-OF-SCOPE**

**DO NOT TEST:**
- DNS attacks
- UDP flood attacks
- Social engineering
- Automated form submissions
- Rate limiting on non-auth endpoints
- Clickjacking on non-sensitive pages
- CSRF on unauthenticated forms
- Missing CSP headers
- Missing HttpOnly/Secure flags
- Rate limit issues

---

## 🚨 **CRITICAL RULES**

1. **ONLY use sandbox environment** for API testing
2. **ONLY test your own account** - do not access others' data
3. **STOP immediately** if you gain access to non-public apps/credentials
4. **Include operation ID** in reports when available
5. **NO automation** against form submissions
6. **Manual testing only** - no automated scans
7. **Secure deletion** - delete any downloaded data after testing

---

## 📅 **TIMELINE & GOALS**

### **Week 1: Setup & API Testing**
- **Day 1:** Complete verification, get API keys, setup tools
- **Day 2-3:** API authentication & authorization testing
- **Day 4-5:** Transaction logic & business logic testing
- **Day 6:** Input validation & injection testing
- **Day 7:** Document findings, submit reports

### **Week 2: Dashboard & Hosted Pages**
- **Day 1-2:** Dashboard testing (IDOR, CSRF, XSS)
- **Day 3:** verify.rapyd.net testing
- **Day 4:** checkout.rapyd.net testing
- **Day 5-7:** Additional testing, report submission

---

## 📚 **RESOURCES**

- **Program Page:** https://bugcrowd.com/engagements/rapyd
- **API Docs:** https://docs.rapyd.net
- **Dashboard:** https://dashboard.rapyd.net
- **Burp Config:** Download from program attachments
- **Support:** https://bugcrowd-support.freshdesk.com

---

## ✅ **CHECKLIST**

### **Setup**
- [x] Account created with DoctorMen@bugcrowdninja.com
- [x] Country set to Iceland
- [ ] Account verification completed
- [ ] API keys generated
- [ ] Burp Suite configured with X-Bugcrowd header
- [ ] Postman collection imported

### **Testing**
- [ ] API authentication tested
- [ ] Transaction logic tested
- [ ] Business logic tested
- [ ] Input validation tested
- [ ] Dashboard tested
- [ ] Hosted pages tested

### **Documentation**
- [ ] All findings documented
- [ ] Screenshots captured
- [ ] Operation IDs recorded
- [ ] Reports submitted

---

## 🎯 **SUCCESS METRICS**

- **Target:** 3-5 valid findings
- **Focus:** High-impact logic flaws for bonuses
- **Priority:** API endpoints (Tier 3 Premium)
- **Deadline:** November 29, 2025

---

**Last Updated:** November 1, 2025  
**Next Action:** Complete account verification → Generate API keys → Begin API testing

