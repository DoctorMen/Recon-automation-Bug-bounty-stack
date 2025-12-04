<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Quick Start - High ROI Bug Hunting

## Goal: High to Medium Severity Bugs Ready for Submission Tonight

## Priority Order (Highest ROI First)

1. **IDOR (Insecure Direct Object Reference)** - HIGH SEVERITY
   - Use existing IDOR evidence capture workflow
   - Test payment endpoints
   - Test wallet endpoints
   - Already have evidence capture process

2. **Authentication Bypass** - HIGH SEVERITY
   - Test endpoints without auth
   - JWT manipulation
   - Session management

3. **Payment Manipulation** - HIGH SEVERITY
   - Amount manipulation
   - Status bypass
   - Refund issues

4. **Rate Limiting Bypass** - MEDIUM SEVERITY
   - Rapid requests
   - Bypass attempts

## Quick Execution



## Individual Tests



## Submission Ready

All bugs are formatted for Bugcrowd submission in:
- submissions/ directory

## Next Steps

1. Run IDOR tester with your actual account tokens
2. Use existing IDOR evidence capture workflow
3. Test authentication endpoints
4. Review submissions directory
5. Submit to Bugcrowd

## High ROI Targets

- Payment endpoints (highest value)
- Authentication endpoints
- User account endpoints
- Transaction endpoints
