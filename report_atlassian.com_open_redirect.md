## Summary
open-redirect vulnerability found on atlassian.com

## Vulnerability Details
**Type:** open-redirect
**Severity:** medium
**Asset:** https://atlassian.com/?url=https://evil.com

## Steps to Reproduce
1. Navigate to https://atlassian.com/?url=https://evil.com
2. Observe the vulnerability

## Proof of Concept
URL: https://atlassian.com/?url=https://evil.com
Evidence: Redirects to: https://www.atlassian.com/?url=https%3A%2F%2Fevil.com

## Impact
This vulnerability could allow attackers to [describe impact based on type]

## Recommended Fix
[Provide brief fix recommendation]

## Discovery Date
2025Y11-05

---
Submitted via: Recon Automation Bug Bounty Stack
Copyright © 2025 DoctorMen. All Rights Reserved.