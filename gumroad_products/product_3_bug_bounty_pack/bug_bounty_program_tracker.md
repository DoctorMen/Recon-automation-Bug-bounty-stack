<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Bug Bounty Program Tracker
**Focus**: Fintech/Payment/SaaS/API Programs with High Severity ≥ $1,000  
**Methodology**: Manual testing (single requests, screenshots, documentation)  
**Last Updated**: November 1, 2025

---

## 🎯 Top Priority Programs (Meeting All Criteria)

### 1. Mastercard Public Bug Bounty ✅ FOUND!
- **Platform**: Bugcrowd (Public)
- **Program URL**: `https://bugcrowd.com/engagements/mastercard`
- **Reward Structure** (Fixed Payouts):
  - **P1 (Critical)**: $5,000
  - **P2 (High)**: $2,000 ✅ **MEETS CRITERIA**
  - **P3 (Medium)**: $1,000
  - **P4 (Low)**: $250
- **Actual Reward Range**: $50 - $5,000 (display), $250 - $5,000 (actual)
- **Average Payout**: $109.73 (last 3 months)
- **Vulnerabilities Rewarded**: 1,027 total
- **Category**: Finance/Payment Processing
- **Scope URLs** (Main Targets):
  - `www.mastercard.us` (US site)
  - `www.mastercard.ch` (Switzerland - German & French)
  - `www.mastercard.nl` (Netherlands)
  - `www.mastercard.com.au` (Australia)
  - `developer.mastercard.com` (Developer Portal) 🎯
  - `donate.mastercard.com`
  - `demo.priceless.com` & `priceless.com/golf/`
  - `performancemarketing.mastercard.com/portal/`
  - `src.mastercard.com` (Secure Remote Commerce)
  - `masterpassteststore.com` (Test checkout - SRC only)
  - **Finicity APIs** (Data Services, Connect, Decisioning) 🎯
  - `www.finicity.com`
- **Test Accounts**: ✅ **masterpassteststore.com** available for SRC checkout testing
- **Authentication Allowed**: ✅ **YES** - Finicity APIs available for testing
- **Automation Restrictions**: ⚠️ Review program rules - likely no aggressive scanning
- **Safe Harbor**: Partial safe harbor
- **Validation Time**: 12 days (75% within this time)
- **Status**: ✅ **CONFIRMED & ACCESSIBLE** - Public program, no invitation needed
- **Notes**: 
  - **Excellent program with clear scope and fixed rewards**
  - Started Aug 01, 2016 - mature, established program
  - 20 announcements - active communication
  - Uses Bugcrowd Vulnerability Rating Taxonomy
  - Multiple domains = diverse attack surface
  - **Developer portal and Finicity APIs are high-value targets**
  - Focus areas: Payment processing, API security, authentication, business logic

---

### 2. Rapyd Bug Bounty Program 🔥 ACTIVE PROMOTION!
- **Platform**: Bugcrowd (Public)
- **Program URL**: `https://bugcrowd.com/engagements/rapyd`
- **Reward Structure**:
  - **Tier 2 (Dashboard/Verify/Checkout):**
    - P1 (Critical): $2,800 - $5,500
    - P2 (High): $1,300 - $2,500 ✅ **MEETS CRITERIA**
    - P3 (Medium): $400 - $1,200
    - P4 (Low): $100 - $400
  - **Tier 3 (Premium - API):** 🎯
    - P1 (Critical): $5,000 - $7,500
    - P2 (High): $1,500 - $4,500 ✅ **MEETS CRITERIA**
    - P3 (Medium): $600 - $1,400
    - P4 (Low): $100 - $500
- **🎁 BONUS REWARDS (Oct 29 - Nov 29, 2025):**
  - **$500 Bonus**: High-impact logic flaws
  - **$1,000 Bonus**: Critical bypass / transaction integrity issues
  - **Exclusive Swag**: For top submissions
- **Average Payout**: $220 (last 3 months)
- **Vulnerabilities Rewarded**: 74 total
- **Validation Time**: 5 days (75% within this time)
- **Category**: Fintech/Payment API
- **Scope URLs**:
  - **Tier 3 (Premium):**
    - `sandboxapi.rapyd.net/v1` (Sandbox API) 🎯
    - `api.rapyd.net/v1` (Production API - sandbox only for testing)
  - **Tier 2:**
    - `dashboard.rapyd.net` (Client Portal Dashboard)
    - `verify.rapyd.net` (Identity verification)
    - `checkout.rapyd.net` (Payment checkout pages)
- **Documentation**: 
  - API Docs: `https://docs.rapyd.net/`
  - Client Portal: `https://docs.rapyd.net/client-portal/docs/client-portal-overview`
  - Postman Collection available
- **Test Accounts**: ✅ **REQUIRED** 
  - **MUST use**: `[username]@bugcrowdninja.com` email to sign up
  - Sign up at `dashboard.rapyd.net`
  - **Sandbox mode**: All users are admins
  - **Production mode**: Only available if you select **Iceland** as country during signup
  - Get API keys from Client Portal
- **Authentication Allowed**: ✅ **YES** - API keys provided, full testing allowed
- **Special Requirements**:
  - ✅ **MUST add X-Bugcrowd header** with your username: `Bugcrowd-<Username>`
  - ✅ Burp config file provided for scope setup
  - ✅ Must include operation ID in reports (provided in API responses)
- **Automation Restrictions**: 
  - ❌ **NO automation/scripts against support forms** - can lead to ban
  - ❌ **NO rate limit abuse** - they enforce limits
  - ✅ Manual API testing with single requests is allowed
- **Safe Harbor**: Full safe harbor
- **Status**: ✅ **HIGHEST PRIORITY** - Active promotion with bonuses, clear testing procedures
- **Priority Focus Areas** (from program):
  1. **Authentication & Authorization**: Bypass, privilege escalation, access control issues
  2. **Transaction & Business Logic**: Amount manipulation, currency bypass, payment outcome flaws
  3. **Data Security & Integrity**: Exposure/alteration of sensitive data
  4. **Input Validation & Injection**: SQL injection, XSS, command injection
- **Top Submitted Vulns** (avoid duplicates):
  - Email template injections (sanitization issues)
  - Race conditions in business logic (multiple refunds)
  - Business logic flaws (wallet balance manipulation)
- **Notes**: 
  - **BEST CANDIDATE - Active promotion until Nov 29!**
  - Excellent documentation and testing setup
  - Clear bonus structure for quality findings
  - Fast validation (5 days average)
  - Signature mechanism required for API calls (use Postman collection)

---

### 3. Bybit Bug Bounty Program
- **Platform**: Bugcrowd (Public)
- **Reward Range**: $5,000 - $20,000 (Critical)
- **Reward for High Severity**: ~$2,500 - $10,000 (estimated)
- **Category**: Fintech/Cryptocurrency Exchange
- **Scope URLs**:
  - `bybit.com` (primary target)
- **In-Scope Assets**: Full website and associated APIs
- **Test Accounts**: ⚠️ Not specified - requires review of program brief
- **Authentication Allowed**: ⚠️ Requires verification
- **Automation Restrictions**: ⚠️ Requires verification
- **Status**: 🔍 **HIGH PRIORITY** - Excellent rewards, needs scope confirmation
- **Notes**: 
  - Highest reward potential in list
  - Cryptocurrency exchange = high-value targets
  - Focus areas: Trading logic, wallet security, 2FA bypass, fund manipulation
  - Review program rules before testing

---

## 💰 Secondary Priority Programs

### 4. Chime Managed Bug Bounty
- **Platform**: Bugcrowd (Public)
- **Program URL**: `https://bugcrowd.com/engagements/chime`
- **Reward Range**: $50 - $20,000
- **Reward for High Severity**: ~$2,000 - $8,000 (estimated)
- **Category**: Fintech/Banking
- **Scope**: Financial services platform
- **Status**: 🔍 **REVIEW REQUIRED**
- **Notes**: Very high max payout, but need to confirm High severity meets $1k threshold

### 5. AAX Bug Bounty Program
- **Platform**: HackenProof
- **Reward Range**: 
  - Critical: $1,000 - $1,500
  - High: $500 - $900
- **Reward for High Severity**: $500 - $900
- **Category**: Fintech/Cryptocurrency
- **Scope URLs**: Website, API, iOS app, Android app
- **Test Accounts**: ⚠️ Not specified
- **Status**: ⚠️ **DOES NOT MEET CRITERIA** - High severity < $1,000
- **Notes**: Below $1k threshold for High, but Critical meets criteria

### 6. Razorpay Bug Bounty Program
- **Platform**: Public Program
- **Reward Range**: $1,000 - $3,000 (Critical)
- **Reward for High Severity**: ~$500 - $1,500 (estimated)
- **Category**: Fintech/Payment Gateway
- **Scope URLs**: Dashboard, API, Checkout, Invoice domains
- **Status**: 🔍 **BORDERLINE** - Verify High severity rewards
- **Notes**: Indian payment gateway, strong API focus

### 7. Bitso Managed Bug Bounty
- **Platform**: Bugcrowd (Public)
- **Reward Range**: $500 - $15,000
- **Reward for High Severity**: ~$2,000 - $6,000 (estimated)
- **Category**: Fintech/Cryptocurrency (Latin America)
- **Status**: ✅ **APPROVED** - Meets criteria
- **Notes**: Latin America's leading crypto financial services

### 8. Immutable Bug Bounty
- **Platform**: Bugcrowd (Public)
- **Reward Range**: $50 - $25,000
- **Reward for High Severity**: ~$1,500 - $8,000 (estimated)
- **Category**: Blockchain/Gaming SaaS
- **Status**: 🔍 **HIGH POTENTIAL** - Review scope and rewards

---

## 📋 Programs from Bugcrowd Search (Fintech/Payment Focus)

### Programs Found (Below $1k for High - Reference Only)
- **Okta**: $100 - $75,000 (Cloud Identity SaaS) - *Verify High severity threshold*
- **Nubank Brasil**: $50 - $4,000 (Banking) - *Review reward structure*
- **Bolt Technology OÜ**: $150 - $6,500 (Ride-hailing payments)
- **Octopus Deploy**: $200 - $6,000 (DevOps SaaS)

---

## ✅ Recommended Top 3 for Manual Testing

Based on criteria analysis and verified program details, here are your best candidates:

### 🥇 #1 Priority: Rapyd 🔥 **START HERE**
- **Why**: 
  - **Active promotion until Nov 29** with bonus rewards ($500-$1,000 extra!)
  - Clear scope, excellent documentation, fast validation (5 days)
  - Test accounts available with specific setup instructions
  - API-focused with sandbox environment
  - High rewards: $1,500-$4,500 for High severity (API tier)
- **Estimated Time Investment**: 15-20 hours for thorough testing
- **Test Plan**:
  1. **Setup** (1-2 hours):
     - Sign up at `dashboard.rapyd.net` using `[yourusername]@bugcrowdninja.com`
     - Select Iceland as country for production mode access
     - Generate API keys in Client Portal (sandbox and production)
     - Download Burp config file from program page
     - Configure X-Bugcrowd header with your username
     - Import Rapyd Postman collection
  2. **Reconnaissance** (2-3 hours):
     - Review API documentation at `docs.rapyd.net`
     - Map all API endpoints (payments, wallets, transactions)
     - Document request/response patterns
     - Note required authentication flows
  3. **Testing - API (6-8 hours)**:
     - Authentication & Authorization: API key bypass, privilege escalation
     - Transaction Logic: Amount manipulation, currency bypass, negative amounts
     - Business Logic: Wallet balance manipulation, duplicate transactions
     - Input Validation: SQL injection in API parameters, XSS in responses
     - Rate Limiting: Check enforcement, bypass attempts (within limits!)
  4. **Testing - Hosted Pages** (3-4 hours):
     - XSS on checkout.rapyd.net (stored, reflected, DOM-based)
     - CSRF on dashboard.rapyd.net state-changing actions
     - Payment flow manipulation on hosted checkout
     - Identity verification bypass on verify.rapyd.net
  5. **Documentation** (2-3 hours):
     - Capture HTTP requests/responses with operation IDs
     - Screenshot all PoCs
     - Write clear reproduction steps
     - Document impact and remediation

### 🥈 #2 Priority: Mastercard
- **Why**: 
  - Established program (since 2016), 1,027 bugs rewarded
  - Fixed rewards - clear expectations ($2,000 for High)
  - Multiple domains and APIs in scope
  - Test store available (masterpassteststore.com)
  - Developer portal and Finicity APIs = high-value targets
- **Estimated Time Investment**: 12-15 hours per domain (start with 1-2 domains)
- **Test Plan**:
  1. **Target Selection** (1 hour):
     - Priority 1: `developer.mastercard.com` (API portal)
     - Priority 2: Finicity APIs (Data Services, Connect, Decisioning)
     - Priority 3: `src.mastercard.com` (Secure Remote Commerce)
  2. **Developer Portal Testing** (4-5 hours):
     - Account takeover via password reset, OAuth flaws
     - API key exposure or theft
     - Injection attacks in API documentation/sandbox
     - IDOR in project/application management
  3. **Finicity API Testing** (5-6 hours):
     - Authentication bypass (API keys, tokens)
     - Data exposure (customer financial data)
     - Business logic (account linking, data aggregation)
     - Authorization flaws (access other accounts' data)
  4. **SRC Testing** (3-4 hours):
     - Use `masterpassteststore.com` for checkout testing
     - Payment amount manipulation
     - Checkout flow bypass
     - Stored credential theft

### 🥉 #3 Priority: Bybit
- **Why**: Highest reward potential ($2,500-$10,000 for High severity)
- **Note**: Need to verify test account policy before starting
- **Test Plan** (if test accounts allowed):
  1. Review program brief for scope and restrictions
  2. Create test account with minimal funding
  3. Test trading logic (order manipulation, price manipulation)
  4. Test wallet security (withdrawal bypass, 2FA bypass)
  5. Document all findings with transaction IDs and screenshots

---

## 📝 Next Steps / Action Items

### Immediate Actions:
1. ✅ **Confirm Mastercard program access**
   - Check Bugcrowd dashboard for program invitation
   - If not available, request access or skip
   - Get direct link to program brief

2. ✅ **Review Rapyd program brief**
   - Visit: `https://bugcrowd.com/engagements/rapyd`
   - Read full scope, out-of-scope items, and rules
   - Note any rate limiting or testing restrictions
   - Register for test API keys

3. ✅ **Review Bybit program brief**
   - Verify test account policy
   - Check if sandbox environment exists
   - Review out-of-scope items carefully

### Testing Preparation:
4. **Set up testing environment**
   - Burp Suite for request interception
   - Screenshot tool ready (Snagit, Greenshot, etc.)
   - Note-taking template for findings
   - Proxy configured for manual request inspection

5. **Create testing checklist per program**
   - Authentication tests
   - Authorization tests
   - Business logic tests
   - Input validation tests
   - API-specific tests (rate limiting, parameter tampering, etc.)

6. **Familiarize with reporting format**
   - Review Bugcrowd submission guidelines
   - Prepare template: Title, Severity, Steps to Reproduce, Impact, Proof of Concept, Remediation

---

## 🔍 Research Questions to Resolve

### For Mastercard:
- [ ] Do I have access to this program on Bugcrowd?
- [ ] What is the exact link to the program brief?
- [ ] What are the specific High severity reward amounts?
- [ ] Are test accounts provided or allowed?
- [ ] What authentication methods are in scope?

### For Rapyd:
- [ ] What is the typical response time for submissions?
- [ ] Are there any rate limits on sandbox API testing?
- [ ] Can I test both sandbox and production with different API keys?
- [ ] What types of vulnerabilities have been rewarded previously?

### For Bybit:
- [ ] Is there a sandbox/testnet environment?
- [ ] Can I create multiple test accounts for testing?
- [ ] What is considered "aggressive testing" that's prohibited?
- [ ] Are there specific areas prioritized (e.g., wallet vs trading)?

---

## 📊 Program Comparison Matrix

| Program | High Severity $ | Critical $ | Test Accts | API Scope | Validation Time | Status |
|---------|----------------|-----------|------------|-----------|-----------------|---------|
| **Rapyd** 🔥 | **$1,500-$4,500** | **$5,000-$7,500** | ✅ **Yes (+bonuses!)** | ✅ **Full API** | **5 days** | ✅ **START NOW** |
| **Mastercard** | **$2,000 (fixed)** | **$5,000 (fixed)** | ✅ **Test store** | ✅ **Finicity APIs** | **12 days** | ✅ **Confirmed** |
| Bybit | $2,500-$10,000 | $5,000-$20,000 | ❓ TBD | ❓ TBD | ❓ TBD | 🔍 Verify |
| Bitso | ~$2,000-$6,000 | ~$8,000-$15,000 | ❓ TBD | ❓ TBD | ❓ TBD | 🔍 Backup |
| Chime | ~$2,000-$8,000 | ~$10,000-$20,000 | ❓ TBD | ❓ TBD | ❓ TBD | 🔍 Backup |

### Key Insights:
- **Rapyd**: Best overall - active promotion, fast payouts, clear setup
- **Mastercard**: Best for consistency - fixed rewards, mature program
- **Bybit**: Highest potential - but needs verification before starting

---

## 🎯 Success Metrics
- [ ] Confirm access to top 3 programs
- [ ] Obtain test credentials for at least 2 programs
- [ ] Complete manual reconnaissance for each program
- [ ] Identify at least 3-5 test cases per program
- [ ] Submit at least 1 valid finding per program

---

## 📌 Important Reminders
- **Manual testing only** - No automated scanners
- **Single requests** - One at a time, document everything
- **Screenshots required** - Capture every step
- **Respect scope** - Stay within defined boundaries
- **No DOS/DDOS** - Avoid high-volume requests
- **Report responsibly** - Follow disclosure timeline


