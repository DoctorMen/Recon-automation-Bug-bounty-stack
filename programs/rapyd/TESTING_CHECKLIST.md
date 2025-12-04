<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Rapyd Testing Checklist

## 📋 Pre-Testing Setup
- [x] Account created with @bugcrowdninja.com email
- [x] Iceland selected as country
- [ ] Account verification completed
- [ ] API keys generated (sandbox + production)
- [ ] Burp Suite configured with X-Bugcrowd header
- [ ] Postman collection imported
- [ ] Reconnaissance completed
- [ ] High-priority targets identified

## 🔐 Authentication & Authorization Testing

### API Authentication
- [ ] Test with missing Bearer token
- [ ] Test with invalid/expired token
- [ ] Test with another user's token
- [ ] Test API key rotation/revocation
- [ ] Test signature verification bypass
- [ ] Test rate limiting per API key

### Dashboard Authentication
- [ ] Test password reset flow
- [ ] Test session management
- [ ] Test 2FA bypass (if enabled)
- [ ] Test account takeover vectors
- [ ] Test OAuth flow issues

### Authorization
- [ ] Test vertical privilege escalation (user → admin)
- [ ] Test horizontal privilege escalation (user A → user B)
- [ ] Test IDOR on customer endpoints
- [ ] Test IDOR on payment/transaction endpoints
- [ ] Test IDOR on wallet endpoints

## 💰 Transaction & Business Logic Testing

### Payment Creation
- [ ] Test negative amounts
- [ ] Test zero amounts
- [ ] Test excessive amounts (integer overflow)
- [ ] Test currency manipulation
- [ ] Test amount precision bypass
- [ ] Test recipient manipulation
- [ ] Test payment status manipulation

### Refunds & Reversals
- [ ] Test double refund
- [ ] Test refund amount > original payment
- [ ] Test refund to different account
- [ ] Test race condition on refunds
- [ ] Test partial refund bypass

### Wallet Operations
- [ ] Test wallet balance manipulation
- [ ] Test negative balance creation
- [ ] Test transfer to invalid wallet
- [ ] Test transfer amount limits
- [ ] Test simultaneous transfers (race condition)

### Business Logic Flaws
- [ ] Test transaction replay
- [ ] Test order of operations bypass
- [ ] Test state machine violations
- [ ] Test time-based logic flaws
- [ ] Test promotion/discount abuse

## 🛡️ Input Validation & Injection

### SQL Injection
- [ ] Test on API parameters
- [ ] Test on search functionality
- [ ] Test on filter parameters
- [ ] Test in JSON payloads
- [ ] Test in URL parameters

### XSS (Cross-Site Scripting)
- [ ] Test stored XSS on dashboard
- [ ] Test reflected XSS on checkout
- [ ] Test DOM-based XSS
- [ ] Test in transaction descriptions
- [ ] Test in customer name fields

### Command Injection
- [ ] Test in file upload names
- [ ] Test in webhook URLs
- [ ] Test in callback parameters

### JSON Injection
- [ ] Test parameter pollution
- [ ] Test JSON payload manipulation
- [ ] Test nested object injection

## 🌐 Web Application Testing

### CSRF (Cross-Site Request Forgery)
- [ ] Test on payment creation
- [ ] Test on wallet transfer
- [ ] Test on account settings
- [ ] Test on API key generation
- [ ] Test on user deletion

### CORS (Cross-Origin Resource Sharing)
- [ ] Test CORS policy on API
- [ ] Test credential exposure
- [ ] Test null origin bypass

### Clickjacking
- [ ] Test X-Frame-Options on dashboard
- [ ] Test on checkout pages
- [ ] Test on sensitive actions

### Open Redirect
- [ ] Test redirect parameters
- [ ] Test OAuth callback URLs
- [ ] Test post-login redirects

## 🔍 Information Disclosure

### Sensitive Data Exposure
- [ ] Test API responses for PII
- [ ] Test error messages for information leakage
- [ ] Test source code comments
- [ ] Test debugging endpoints
- [ ] Test API documentation leaks

### Debug Information
- [ ] Test verbose error messages
- [ ] Test stack traces in responses
- [ ] Test debug mode enabled
- [ ] Test internal IP disclosure

## 🎭 Advanced Testing

### Race Conditions
- [ ] Test concurrent payment creation
- [ ] Test simultaneous wallet operations
- [ ] Test parallel refund requests
- [ ] Test parallel balance updates

### GraphQL (if applicable)
- [ ] Test introspection enabled
- [ ] Test query depth limits
- [ ] Test batch queries
- [ ] Test query cost analysis bypass

### API Rate Limiting
- [ ] Test rate limit bypass techniques
- [ ] Test per-endpoint limits
- [ ] Test global limits
- [ ] Test rate limit headers

### File Upload (if applicable)
- [ ] Test unrestricted file upload
- [ ] Test file type validation
- [ ] Test file size limits
- [ ] Test malicious file execution

## 📱 Hosted Pages Testing

### checkout.rapyd.net
- [ ] Test payment amount manipulation
- [ ] Test checkout flow bypass
- [ ] Test XSS in form fields
- [ ] Test CSRF on payment submission

### verify.rapyd.net
- [ ] Test identity verification bypass
- [ ] Test document upload validation
- [ ] Test information disclosure

### dashboard.rapyd.net
- [ ] Test all OWASP Top 10 on dashboard
- [ ] Test admin panel access
- [ ] Test sensitive data exposure

## 📊 Testing Progress

| Category | Tests Complete | Findings | Severity |
|----------|----------------|----------|----------|
| Authentication | 0/12 | - | - |
| Business Logic | 0/15 | - | - |
| Injection | 0/12 | - | - |
| Web App | 0/10 | - | - |
| Info Disclosure | 0/6 | - | - |
| Advanced | 0/10 | - | - |
| Hosted Pages | 0/8 | - | - |

**Total Progress**: 0/73 tests

## ⚠️ Important Reminders

- **✅ DO**: Test one request at a time
- **✅ DO**: Screenshot every finding
- **✅ DO**: Include operation ID in reports
- **✅ DO**: Use X-Bugcrowd header
- **✅ DO**: Test sandbox API only
- **❌ DON'T**: Use automation on forms
- **❌ DON'T**: Test production API directly
- **❌ DON'T**: Abuse rate limits
- **❌ DON'T**: Access real customer data

## 🎯 Daily Goals

**Week 1**: Complete 50% of checklist
**Week 2**: Complete 100% of checklist  
**Week 3**: Re-test high-priority areas

