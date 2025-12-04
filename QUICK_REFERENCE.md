<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Quick Reference Card - Bug Bounty Testing

## 🎯 Your Top 2 Programs (Confirmed & Ready)

---

## 1. RAPYD 🔥 (START HERE)

### URLs
- Program: `https://bugcrowd.com/engagements/rapyd`
- Dashboard: `https://dashboard.rapyd.net`
- API Docs: `https://docs.rapyd.net`

### Rewards (High Severity)
- **API (Tier 3):** $1,500 - $4,500
- **Dashboard (Tier 2):** $1,300 - $2,500
- **BONUSES:** +$500 or +$1,000 (until Nov 29, 2025)

### Account Setup
```
Email: [yourusername]@bugcrowdninja.com
Country: Iceland (for production mode)
Get API keys from: Client Portal
```

### Required Headers
```
X-Bugcrowd: Bugcrowd-[YourUsername]
```

### Scope
```
✅ sandboxapi.rapyd.net/v1 (API - PRIORITY)
✅ dashboard.rapyd.net (Portal)
✅ verify.rapyd.net (Verification)
✅ checkout.rapyd.net (Checkout)
```

### Testing Focus
- [ ] API authentication bypass
- [ ] Transaction amount manipulation
- [ ] Wallet balance manipulation
- [ ] Business logic flaws (refunds, transfers)
- [ ] XSS on hosted pages
- [ ] CSRF on dashboard

### Rules
- ✅ Manual testing OK
- ✅ Sandbox API testing
- ❌ NO automation on forms
- ❌ NO rate limit abuse
- ⏰ Promotion ends Nov 29

---

## 2. MASTERCARD

### URLs
- Program: `https://bugcrowd.com/engagements/mastercard`
- Developer Portal: `https://developer.mastercard.com`
- Test Store: `https://masterpassteststore.com`

### Rewards (Fixed)
- **High (P2):** $2,000
- **Medium (P3):** $1,000
- **Critical (P1):** $5,000

### Priority Targets
```
1. developer.mastercard.com (Developer Portal)
2. Finicity APIs (Connect, Data Services, Decisioning)
3. src.mastercard.com (Secure Remote Commerce)
4. masterpassteststore.com (Test Store)
```

### Testing Focus
- [ ] Developer portal account security
- [ ] API key theft/exposure
- [ ] Finicity API authorization flaws
- [ ] SRC checkout manipulation
- [ ] Payment flow bypasses

### Rules
- ✅ Test store available
- ✅ API testing allowed
- ⚠️ Partial safe harbor - review restrictions
- ⚠️ Check eligibility (no sanctioned countries)

---

## 📝 Report Checklist

### Before Submitting
- [ ] Clear title describing the vulnerability
- [ ] Severity assessment (P1/P2/P3/P4)
- [ ] Step-by-step reproduction
- [ ] HTTP request/response (Rapyd: include operation ID)
- [ ] Screenshots/screen recording
- [ ] Impact description
- [ ] Suggested remediation
- [ ] No real user data accessed

### Quality Tips
- Use clear, concise language
- Number your reproduction steps
- Show before/after states
- Explain "why this matters"
- Suggest how to fix it

---

## ⏱️ Time Estimates

### Rapyd (Total: 15-20 hours)
- Setup: 1-2 hours
- Recon: 2-3 hours
- API Testing: 6-8 hours
- Hosted Pages: 3-4 hours
- Documentation: 2-3 hours

### Mastercard (Per Domain: 4-6 hours)
- Developer Portal: 4-5 hours
- Finicity APIs: 5-6 hours
- SRC Testing: 3-4 hours

---

## 🚀 Quick Start (Today)

### Step 1: Rapyd Account (15 min)
1. Go to `https://dashboard.rapyd.net`
2. Sign up with `[username]@bugcrowdninja.com`
3. Select **Iceland** as country
4. Verify email
5. Generate sandbox API keys

### Step 2: Download Tools (15 min)
1. Burp config: Rapyd program page → Attachments
2. Postman collection: Rapyd docs
3. Configure Burp proxy
4. Add X-Bugcrowd header to Burp

### Step 3: First Test (30 min)
1. Review Rapyd API docs
2. Send first API request via Postman
3. Verify signature works
4. Try simple manipulation (e.g., negative amount)
5. Document results

---

## 📊 Comparison At-a-Glance

| Factor | Rapyd | Mastercard |
|--------|-------|------------|
| **High $ Min** | $1,500 | $2,000 |
| **High $ Max** | $4,500 | $2,000 |
| **Bonuses** | ✅ Yes | ❌ No |
| **Validation** | 5 days | 12 days |
| **Setup Time** | 1 hour | 30 min |
| **Best For** | API testing | Web app testing |
| **Urgency** | 🔥 HIGH (promotion) | 📅 Normal |

---

## ⚠️ Don't Forget!

### Rapyd
- [ ] Use @bugcrowdninja.com email
- [ ] Add X-Bugcrowd header
- [ ] Include operation ID in reports
- [ ] Test sandbox only
- [ ] No automation on forms

### Mastercard
- [ ] Check eligibility first
- [ ] SRC testing only on test store
- [ ] Review partial safe harbor
- [ ] Focus on high-value targets first

---

## 📞 Support

### If You Get Stuck
1. **Rapyd**: Check announcements (17 posts) or submit clarification question
2. **Mastercard**: Review program brief (20 announcements)
3. **Bugcrowd**: https://bugcrowd-support.freshdesk.com

### Common Issues
- **Can't sign up**: Check email format (@bugcrowdninja.com)
- **API signature fails**: Use Postman collection
- **Unsure about scope**: Ask program team before testing
- **Duplicate finding**: Check CrowdStream for similar reports

---

## 🎯 Daily Goals

### Week 1 (Rapyd)
- **Day 1**: Setup + recon
- **Day 2**: API auth testing
- **Day 3**: Transaction logic testing
- **Day 4**: Business logic testing
- **Day 5**: Hosted pages testing
- **Day 6**: Dashboard testing
- **Day 7**: Document + submit

### Week 2 (Mastercard)
- **Day 1-2**: Developer portal
- **Day 3-4**: Finicity APIs
- **Day 5**: SRC testing
- **Day 6-7**: Additional domains

---

**Remember**: Quality over quantity. One high-impact finding is worth more than ten low-impact reports! 🎯

