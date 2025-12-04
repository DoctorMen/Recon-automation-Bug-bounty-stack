<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Bug Submission Template - Bugcrowd Format

## Title
[Brief description of vulnerability]

## Severity
[High/Medium/Low]

## CVSS Score
[If applicable]

## CWE
[Common Weakness Enumeration]

## Description
[Detailed description of the vulnerability]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Evidence
- Screenshots: [location]
- Network requests: [location]
- API responses: [location]

## Impact
[What can an attacker do?]

## Recommendation
[How to fix]

## Affected Endpoint
[URL/endpoint]

## Request/Response
[Include relevant HTTP requests/responses]

---

## Quick Fill Template

**Title:** IDOR in Payment Endpoint

**Severity:** High

**Description:** 
Account A can access Account B payment details without authorization by modifying the payment ID in the request.

**Steps to Reproduce:**
1. Login to Account A
2. Create a payment in Account B (note the payment ID)
3. While logged in as Account A, access: https://sandboxapi.rapyd.net/v1/payments/{account_b_payment_id}
4. Observe unauthorized access to Account B payment details

**Impact:** 
Unauthorized access to sensitive payment information, potential data breach.

**Recommendation:**
Implement proper authorization checks to verify the authenticated user owns the requested resource.
