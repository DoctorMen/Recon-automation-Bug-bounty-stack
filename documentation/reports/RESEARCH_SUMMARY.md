<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Bug Bounty Program Research Summary
**Date**: November 1, 2025  
**Research Goal**: Find fintech/payment/SaaS/API programs with High severity rewards ≥ $1,000  
**Method**: Manual browser research + web search on Bugcrowd platform

---

## ✅ Mission Accomplished!

I successfully identified and verified **2 excellent programs** that meet ALL your criteria, with a 3rd high-potential option pending verification.

---

## 🎯 Confirmed Programs

### 1. ⭐ Rapyd Bug Bounty (HIGHEST PRIORITY) 🔥

**Program Link**: https://bugcrowd.com/engagements/rapyd

**Why This is #1:**
- **ACTIVE PROMOTION** running Oct 29 - Nov 29, 2025
- **BONUS REWARDS**: +$500 for high-impact logic flaws, +$1,000 for critical bypasses
- **FASTEST VALIDATION**: 5 days average (vs 12 days for Mastercard)
- **EXCELLENT DOCUMENTATION**: Full API docs, Postman collection, Burp config provided
- **CLEAR SETUP PROCESS**: Step-by-step instructions for test accounts

**Rewards:**
- **API Testing (Tier 3 - Premium):**
  - Critical (P1): $5,000 - $7,500 (+bonuses)
  - **High (P2): $1,500 - $4,500** ✅ **MEETS CRITERIA**
  - Medium (P3): $600 - $1,400
  - Low (P4): $100 - $500

- **Dashboard/Hosted Pages (Tier 2):**
  - Critical (P1): $2,800 - $5,500
  - **High (P2): $1,300 - $2,500** ✅ **MEETS CRITERIA**
  - Medium (P3): $400 - $1,200
  - Low (P4): $100 - $400

**Scope:**
- `sandboxapi.rapyd.net/v1` (Sandbox API) 🎯 PRIMARY TARGET
- `api.rapyd.net/v1` (Production API - use sandbox for testing)
- `dashboard.rapyd.net` (Client Portal)
- `verify.rapyd.net` (Identity verification)
- `checkout.rapyd.net` (Payment checkout)

**Test Account Setup:**
1. **MUST** use `[yourusername]@bugcrowdninja.com` email format
2. Sign up at `dashboard.rapyd.net`
3. Select **Iceland** as country for full production mode testing
4. Generate API keys in Client Portal
5. **MUST** add `X-Bugcrowd: Bugcrowd-[YourUsername]` header to all requests

**Priority Testing Areas (from program brief):**
1. Authentication & Authorization bypass
2. Transaction/Business Logic manipulation
3. Data Security & Integrity issues
4. Input Validation & Injection attacks

**Statistics:**
- 74 vulnerabilities rewarded
- $220 average payout (last 3 months)
- Full safe harbor protection

**Screenshot**: See `rapyd-program-overview.png`

---

### 2. ⭐ Mastercard Public Bug Bounty

**Program Link**: https://bugcrowd.com/engagements/mastercard

**Why This is Great:**
- **FIXED REWARDS** - No negotiation, clear expectations
- **MATURE PROGRAM** - Running since Aug 2016, 1,027 bugs rewarded
- **MULTIPLE HIGH-VALUE TARGETS** - Developer portal, APIs, test stores
- **ESTABLISHED BRAND** - Strong reputation, reliable payouts
- **BROAD SCOPE** - 17+ domains/applications in scope

**Rewards (Fixed):**
- Critical (P1): **$5,000**
- **High (P2): $2,000** ✅ **MEETS CRITERIA**
- **Medium (P3): $1,000** ✅ **ALSO MEETS!**
- Low (P4): $250

**High-Priority Targets:**
1. **`developer.mastercard.com`** (Developer Portal) 🎯
   - API key management
   - Developer accounts
   - API sandbox/testing tools

2. **Finicity APIs** 🎯
   - Finicity Connect (account aggregation)
   - Finicity Data Services (financial data)
   - Finicity Decisioning (credit decisions)
   - Note: These handle sensitive financial data

3. **`src.mastercard.com`** (Secure Remote Commerce)
   - Payment card storage
   - Checkout integration
   - Test store: `masterpassteststore.com`

4. **Regional Mastercard Sites**
   - `www.mastercard.us`
   - `www.mastercard.ch` (Swiss - German & French)
   - `www.mastercard.nl` (Netherlands)
   - `www.mastercard.com.au` (Australia)

5. **Other Targets**
   - `demo.priceless.com` & `priceless.com/golf/`
   - `donate.mastercard.com`
   - `performancemarketing.mastercard.com/portal/`

**Testing Allowances:**
- ✅ Test store available: `masterpassteststore.com` (SRC checkout only)
- ✅ API testing allowed on Finicity APIs
- ✅ Account creation allowed on developer portal
- ⚠️ Partial safe harbor (review restrictions carefully)

**Statistics:**
- 1,027 vulnerabilities rewarded (very active program)
- $109.73 average payout (last 3 months)
- 12-day average validation time

**Eligibility Restrictions:**
- ❌ Cannot be resident of sanctioned countries (Russia, Iran, North Korea, Syria)
- ❌ Cannot be Mastercard employee or immediate family
- ⚠️ Must be 14+ years old (with parent permission if minor)

**Screenshot**: See `mastercard-program-overview.png`

---

### 3. 🔍 Bybit Bug Bounty (Pending Verification)

**Estimated Rewards:**
- Critical: $5,000 - $20,000
- High: $2,500 - $10,000 ✅ **HIGHEST POTENTIAL**

**Status**: Public program on Bugcrowd, but needs verification of:
- Test account policy
- Sandbox/testnet availability
- Testing restrictions

**Why Consider It:**
- Cryptocurrency exchange = high-value targets
- Highest potential payout for High severity
- Focus on trading logic, wallet security, financial transactions

**Action Required**: Review full program brief before testing

---

## 📋 Program Comparison

| Factor | Rapyd 🔥 | Mastercard | Bybit |
|--------|---------|------------|-------|
| **High Severity Reward** | $1,500-$4,500 | $2,000 (fixed) | $2,500-$10,000 |
| **Critical Reward** | $5,000-$7,500 | $5,000 (fixed) | $5,000-$20,000 |
| **Bonus Opportunities** | ✅ Yes (+$500-$1,000) | ❌ No | ❌ No |
| **Test Accounts** | ✅ Yes (clear process) | ✅ Yes (test store) | ❓ TBD |
| **API Testing** | ✅ Full sandbox | ✅ Finicity APIs | ❓ TBD |
| **Validation Speed** | ⚡ 5 days | 12 days | ❓ TBD |
| **Documentation** | ⭐⭐⭐⭐⭐ Excellent | ⭐⭐⭐⭐ Good | ❓ TBD |
| **Active Promotion** | ✅ Until Nov 29 | ❌ No | ❌ No |
| **Program Maturity** | 3 years (74 bugs) | 9 years (1,027 bugs) | ❓ TBD |
| **Readiness** | ✅ Start Today | ✅ Start Today | 🔍 Review First |

---

## 🎯 Recommended Action Plan

### Week 1: Rapyd (Priority 1) 🔥
**Time Investment**: 15-20 hours

**Day 1-2: Setup & Reconnaissance**
- [ ] Create account with `@bugcrowdninja.com` email
- [ ] Set up Iceland country profile for production mode
- [ ] Generate API keys (sandbox + production)
- [ ] Download and configure Burp scope file
- [ ] Import Rapyd Postman collection
- [ ] Review full API documentation
- [ ] Map all API endpoints

**Day 3-4: API Testing**
- [ ] Test authentication/authorization flows
- [ ] Test transaction manipulation (amounts, currencies)
- [ ] Test business logic (wallets, refunds, transfers)
- [ ] Test input validation (injection attacks)
- [ ] Document findings with operation IDs

**Day 5-6: Hosted Pages Testing**
- [ ] Test XSS on checkout.rapyd.net
- [ ] Test CSRF on dashboard.rapyd.net
- [ ] Test payment flow bypasses
- [ ] Test identity verification on verify.rapyd.net

**Day 7: Documentation & Submission**
- [ ] Compile all findings
- [ ] Create detailed reproduction steps
- [ ] Capture screenshots for each finding
- [ ] Submit reports with HTTP requests/responses

### Week 2: Mastercard (Priority 2)
**Time Investment**: 12-15 hours (focus on 1-2 domains)

**Target Priority:**
1. **Start with**: `developer.mastercard.com` (4-5 hours)
   - Test account security, API key management, OAuth flows
   
2. **Then**: Finicity APIs (5-6 hours)
   - Test authentication, data exposure, authorization
   
3. **If time**: `src.mastercard.com` + test store (3-4 hours)
   - Test payment flows, checkout manipulation

### Week 3+: Additional Programs
- Review Bybit program brief and start if suitable
- Explore Bitso or Chime as alternatives
- Return to Rapyd/Mastercard for deeper testing

---

## ⚠️ Critical Reminders

### For Rapyd:
- ✅ **MUST** use `X-Bugcrowd` header with your username
- ✅ **MUST** include operation ID in all reports
- ❌ **NO** automation against support forms (instant ban)
- ❌ **NO** rate limit abuse
- ✅ Only test sandbox API, not production
- ⏰ Promotion ends Nov 29, 2025

### For Mastercard:
- ✅ SRC testing ONLY on `masterpassteststore.com`
- ⚠️ Partial safe harbor - review restrictions
- ✅ Finicity APIs are in scope for testing
- ⚠️ Check eligibility (no sanctioned countries)

### For All Programs:
- 📸 Screenshot EVERYTHING
- 📝 Document every request/response
- 🎯 Focus on HIGH impact findings
- ⚡ Submit as you find (don't batch)
- 📧 Follow disclosure guidelines
- 🚫 Never test outside scope
- 🚫 Never use automation tools
- 🚫 Never access real user data

---

## 📊 Success Metrics

**Short-term (1 month):**
- [ ] Complete Rapyd testing (target: 3-5 valid findings)
- [ ] Complete Mastercard developer portal testing (target: 2-3 findings)
- [ ] Submit at least 5 total reports
- [ ] Receive at least 1 bounty payment

**Medium-term (3 months):**
- [ ] Test all 3 top programs thoroughly
- [ ] Build reputation with fast responses
- [ ] Earn $2,000+ total in bounties
- [ ] Get invited to private programs

---

## 🔗 Quick Links

### Rapyd
- Program: https://bugcrowd.com/engagements/rapyd
- Dashboard: https://dashboard.rapyd.net
- API Docs: https://docs.rapyd.net
- Client Portal Docs: https://docs.rapyd.net/client-portal/docs/client-portal-overview

### Mastercard
- Program: https://bugcrowd.com/engagements/mastercard
- Developer Portal: https://developer.mastercard.com
- Test Store: https://masterpassteststore.com
- SRC: https://src.mastercard.com
- Finicity: https://www.finicity.com

### Resources
- Bugcrowd Taxonomy: https://bugcrowd.com/vulnerability-rating-taxonomy
- Bugcrowdninja Email: https://docs.bugcrowd.com/researchers/participating-in-program/your-bugcrowdninja-email-address/

---

## 📁 Files Created

1. `bug_bounty_program_tracker.md` - Comprehensive program tracker with 10+ programs
2. `RESEARCH_SUMMARY.md` - This summary document
3. `rapyd-program-overview.png` - Screenshot of Rapyd program page
4. `mastercard-program-overview.png` - Screenshot of Mastercard program page

---

## ✨ Key Takeaways

1. **You have 2 confirmed programs** ready for immediate testing
2. **Rapyd has active bonuses** - prioritize this until Nov 29
3. **Both programs meet your $1k+ criteria** for High severity
4. **Test accounts are available** for both programs
5. **Clear documentation exists** - no guesswork needed
6. **Your manual methodology is perfect** for both programs
7. **Time-sensitive opportunity** with Rapyd promotion

---

**Next Step**: Start with Rapyd account creation TODAY to take advantage of the active promotion! 🚀

