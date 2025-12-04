# Safe Bug Bounty Testing Guide - Non-Critical Targets Only

**Owner:** Khallid Hakeem Nurse  
**Rule:** Only test non-critical infrastructure  
**Principle:** Better to miss a bounty than cause real damage  

---

## 🎯 Your Safety Rule Applied

**Before EVERY test:**
```
1. Is this target explicitly in scope? (Authorization)
2. Is this target non-critical? (Safety)
3. Can I test without affecting real users? (Ethics)

ALL THREE must be YES to proceed.
```

---

## ✅ GREEN LIGHT Targets (Safe to Test)

### **Category 1: Test Environments**
```
demo.hackerone.com          ✅ Designed for testing
staging.shopify.com         ✅ Non-production
test-api.github.com         ✅ Test infrastructure
sandbox.stripe.com          ✅ Sandbox mode
```

**Why safe:**
- Isolated from production
- No real user data
- Breaking them = expected
- Low business impact

### **Category 2: Public Marketing**
```
blog.example.com            ✅ Static content
www.example.com             ✅ Public website
marketing.example.com       ✅ Marketing pages
careers.example.com         ✅ Job listings
```

**Why safe:**
- No sensitive data
- No user accounts
- Public-facing only
- Easy to restore

### **Category 3: CTF/Training**
```
ctf.hacker101.com          ✅ Intentionally vulnerable
h1-702.hackerone.com       ✅ Test program
playground.bugcrowd.com    ✅ Practice environment
```

**Why safe:**
- Designed to be broken
- Zero real users
- Educational purpose
- No consequences

---

## 🚫 RED LIGHT Targets (DO NOT TEST)

### **Category 1: Payment Systems**
```
pay.example.com             ❌ CRITICAL
payment.example.com         ❌ CRITICAL
billing.example.com         ❌ CRITICAL
checkout.example.com        ❌ CRITICAL
```

**Why critical:**
- Real money transactions
- Financial data
- PCI-DSS regulated
- High legal risk

### **Category 2: Authentication**
```
auth.example.com            ❌ CRITICAL
login.example.com           ❌ CRITICAL
sso.example.com             ❌ CRITICAL
oauth.example.com           ❌ CRITICAL
```

**Why critical:**
- User account security
- Identity management
- Widespread impact
- High severity if broken

### **Category 3: Production Data**
```
api.example.com             ❌ CRITICAL (if real data)
data.example.com            ❌ CRITICAL
database.example.com        ❌ CRITICAL
user-accounts.example.com   ❌ CRITICAL
```

**Why critical:**
- Real user information
- Privacy violations possible
- Data loss risk
- GDPR/privacy laws

### **Category 4: Infrastructure**
```
admin.example.com           ❌ CRITICAL
internal.example.com        ❌ CRITICAL
ops.example.com             ❌ CRITICAL
production.example.com      ❌ CRITICAL
```

**Why critical:**
- Business operations
- Internal tools
- Production systems
- Company-wide impact

---

## 🎯 Real-World Examples

### **Example 1: Shopify**

**SAFE Targets:**
```
✅ Your own test store: yourstore.myshopify.com
✅ Shopify partners sandbox
✅ Public marketing: www.shopify.com
✅ Developer docs: shopify.dev
```

**AVOID:**
```
❌ Other merchants' stores
❌ admin.shopify.com (production admin)
❌ Shopify Payments (payment processing)
❌ Real customer data
```

**How to test safely:**
1. Create your own test store (free)
2. Only test YOUR store
3. Use test payment methods
4. Never access other merchants' data

---

### **Example 2: GitHub**

**SAFE Targets:**
```
✅ Your own public repos
✅ Your own test repos
✅ github.com public features
✅ gist.github.com
```

**AVOID:**
```
❌ Other users' private repos
❌ Organization admin panels (not yours)
❌ api.github.com with real user tokens
❌ Private data access
```

**How to test safely:**
1. Create test repos
2. Only test public features
3. Use test accounts
4. Never access others' private data

---

### **Example 3: Stripe**

**SAFE Targets:**
```
✅ Test mode API keys
✅ stripe.com/docs
✅ dashboard.stripe.com (test mode)
✅ Your test account
```

**AVOID:**
```
❌ Live mode API keys
❌ Real payment processing
❌ Customer payment data
❌ Production webhooks
```

**How to test safely:**
1. Use ONLY test mode
2. Never use live keys
3. Test with $0.00 amounts
4. Use test card numbers only

---

## 📋 Pre-Test Safety Checklist

**Before starting ANY test:**

```
[ ] Read program policy completely
[ ] Identify out-of-scope targets
[ ] Check for critical infrastructure warnings
[ ] Confirm target is non-critical
[ ] Verify you have authorization file
[ ] Create test accounts (never use real accounts)
[ ] Set up test environment (not production)
[ ] Plan minimal impact testing
[ ] Have rollback plan if something breaks
[ ] Know emergency contact for program

If ANY checkbox is unchecked → DO NOT PROCEED
```

---

## 🚨 Risk Assessment Framework

### **Low Risk (Safe to Test):**
```
✓ Test environments explicitly marked
✓ Public marketing pages
✓ CTF/training platforms
✓ Your own test accounts
✓ Sandbox environments
✓ Documentation sites

Impact if broken: Minimal, easy to restore
Users affected: Zero or very few
Data at risk: None or test data only
Business impact: Negligible

→ PROCEED with testing
```

### **Medium Risk (Test Cautiously):**
```
⚠ Public APIs (read-only)
⚠ Community forums
⚠ Public search features
⚠ Developer portals

Impact if broken: Temporary service disruption
Users affected: Some public users
Data at risk: Public data only
Business impact: Low

→ PROCEED with minimal impact testing
→ Use test accounts
→ Limit request rates
→ Test during off-peak hours
```

### **High Risk (AVOID):**
```
✕ Production databases
✕ Payment systems
✕ Authentication services
✕ Admin panels
✕ User data storage
✕ Critical business operations

Impact if broken: Severe service disruption
Users affected: Many or all users
Data at risk: Sensitive user/business data
Business impact: High financial/reputation cost

→ DO NOT TEST without explicit written approval
→ If in scope, ask program team first
→ Consider if finding is worth the risk
→ Have very clear authorization
```

---

## 💡 Practical Decision Tree

```
Found potential target?
    ↓
Is it in program scope?
    ↓ NO → Don't test
    ↓ YES
    ↓
Is it marked as critical infrastructure?
    ↓ YES → Don't test
    ↓ NO
    ↓
Does it handle real user data?
    ↓ YES → Ask program team first
    ↓ NO
    ↓
Is there a test/staging version?
    ↓ YES → Test that instead
    ↓ NO
    ↓
Can you test without affecting real users?
    ↓ NO → Don't test
    ↓ YES
    ↓
✅ Safe to proceed with minimal impact testing
```

---

## 🎯 Your GHOST IDE Configuration

**Set safe default target:**
```javascript
// In GHOST IDE, always start with safe targets
Default target: demo.hackerone.com  ✅
Backup targets: 
  - Your own test store
  - CTF platforms
  - Sandbox environments
```

**Before clicking "Run Scan":**
1. Verify target is non-critical
2. Check SAFE_TARGETS_CONFIG.json
3. Confirm authorization exists
4. Proceed only if all green lights

---

## 📊 Safe Testing Statistics

**Focus on these programs (lowest risk):**

```
Hacker101 CTF:
- Risk Level: ZERO (designed to break)
- Bounty: Learning & reputation
- Your focus: 20% of time

Test Programs (H1-702, etc):
- Risk Level: VERY LOW (test infrastructure)
- Bounty: $0-$5k (practice)
- Your focus: 30% of time

Safe Production Targets (marketing, docs):
- Risk Level: LOW (non-critical)
- Bounty: $500-$5k (real but low)
- Your focus: 30% of time

Test Stores/Sandboxes (your own):
- Risk Level: ZERO (you own it)
- Bounty: Real program bounties
- Your focus: 20% of time
```

**Result: 100% safe testing, zero risk of critical impact**

---

## 🚀 Recommended Starting Path

### **Week 1: Zero-Risk Practice**
```
Targets:
✅ ctf.hacker101.com
✅ hackerone.com/h1-702-2018
✅ Your own test applications

Goal: Learn Divergent modes risk-free
```

### **Week 2-3: Low-Risk Testing**
```
Targets:
✅ Public marketing sites (in scope)
✅ Documentation platforms
✅ Your own test stores

Goal: First real findings, zero critical impact
```

### **Week 4+: Carefully Selected Production**
```
Targets:
✅ Non-critical production (marketing, public APIs)
✅ Test/staging when available
✅ Your own authenticated test accounts

Goal: Real bounties, maintained safety
```

---

## ✅ Your Safety Commitment

**Memorize this:**

> "I will ONLY test targets that are:
> 1. Explicitly in scope (legal)
> 2. Non-critical infrastructure (safe)
> 3. Can be tested without affecting real users (ethical)
>
> When in doubt, I will ask first or skip the target.
> Better to miss a bounty than cause real damage."

---

## 🎯 Update Your GHOST IDE Workflow

**New workflow with safety check:**

```
1. Open GHOST IDE
2. See potential target
3. Check: Is it in SAFE_TARGETS_CONFIG.json?
   → YES: Proceed
   → NO: Evaluate risk level
4. If low risk: Verify authorization → Test
5. If medium risk: Use test account → Minimal impact
6. If high risk: Skip or ask program team first
```

---

## 📞 When to Contact Program Team

**Ask BEFORE testing if:**
- Target seems critical but is in scope
- Unclear if test environment exists
- Potential for high impact
- Program policy is ambiguous
- You're unsure about criticality

**Template message:**
```
Hi [Program] Team,

I'm interested in testing [specific target/feature]. 

Before proceeding, I want to confirm:
1. Is this target considered critical infrastructure?
2. Is there a test/staging version I should use instead?
3. Any specific testing guidelines for this area?

I want to ensure minimal impact while doing thorough testing.

Thanks,
[Your Handle]
```

---

## 🏆 Success Metrics (Safe Testing)

**Track in GHOST IDE:**
```
✓ Targets tested: Only non-critical
✓ Critical systems affected: 0
✓ Real users impacted: 0
✓ Authorization violations: 0
✓ Findings discovered: [Your count]
✓ Bounties earned: [Your amount]

Goal: High findings, zero critical impact
```

---

**Remember: A missed bounty is better than a lawsuit or causing real harm. Stay safe, stay legal, stay ethical.**

**Owner:** Khallid Hakeem Nurse  
**Copyright:** © 2025 Khallid Hakeem Nurse - All Rights Reserved  
**System ID:** DIVERGENT_THINKING_20251105  
