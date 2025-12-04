<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Manual Submission Template for Bugcrowd

## Bug 1: Authentication Bypass - Admin Endpoint

**Title:** Authentication Bypass - merchant.bolt.com/admin

**Severity:** HIGH

**Description:**
The admin endpoint at https://merchant.bolt.com/admin is accessible without authentication. The endpoint returns a 200 OK response with substantial data (>500 bytes), indicating unauthorized access to administrative functions.

**Steps to Reproduce:**
1. Open browser (not logged in)
2. Navigate to: https://merchant.bolt.com/admin
3. Observe 200 OK response
4. Verify unauthorized access to admin functions

**Impact:**
Unauthorized users can access administrative functions without authentication, potentially allowing unauthorized access to sensitive merchant data and system configurations.

**Evidence:**
- Automated testing confirmed 200 OK response
- Endpoint accessible without authentication headers
- Response contains substantial data (not an error page)

---

## Bug 2: Authentication Bypass - Dashboard

**Title:** Authentication Bypass - merchant.bolt.com/dashboard

**Severity:** HIGH

**Description:**
The dashboard endpoint is accessible without authentication, allowing unauthorized access to merchant dashboard functionality.

**Steps to Reproduce:**
1. Navigate to: https://merchant.bolt.com/dashboard
2. Observe 200 OK response
3. Verify unauthorized access

**Impact:**
Unauthorized access to merchant dashboard functions.

---

## Bug 3: Authentication Bypass - Settings

**Title:** Authentication Bypass - merchant.bolt.com/settings

**Severity:** HIGH

**Description:**
Settings endpoint accessible without authentication.

**Steps to Reproduce:**
1. Navigate to: https://merchant.bolt.com/settings
2. Observe 200 OK response

**Impact:**
Unauthorized access to merchant settings.

---

## Bug 4: Authentication Bypass - API Admin

**Title:** Authentication Bypass - merchant.bolt.com/api/admin

**Severity:** HIGH

**Description:**
API admin endpoint accessible without authentication.

**Steps to Reproduce:**
1. Navigate to: https://merchant.bolt.com/api/admin
2. Observe 200 OK response

**Impact:**
Unauthorized access to admin API functions.

---

## Bug 5: Payment Manipulation - Negative Amount

**Title:** Payment Manipulation - Negative Amount Accepted

**Severity:** HIGH

**Description:**
The payment endpoint accepts negative amounts, allowing payment manipulation.

**Steps to Reproduce:**
1. POST to: https://merchant.bolt.com/api/v1/payments
2. Send payload: {
