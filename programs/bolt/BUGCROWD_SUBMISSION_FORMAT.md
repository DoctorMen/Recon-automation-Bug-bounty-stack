# Bugcrowd Submission Format - Bolt Technologies

## Submission Page URL:
https://bugcrowd.com/submit

---

## SUBMISSION 1/8: Authentication Bypass - Admin Endpoint

**Title:**
Authentication Bypass - Admin Endpoint Accessible Without Authentication

**Severity:**
High

**Description:**
The admin endpoint at https://merchant.bolt.com/admin is accessible without authentication. The endpoint returns HTTP 200 OK with substantial response data (>500 bytes), indicating unauthorized access to administrative functions.

**Steps to Reproduce:**
1. Open browser in incognito/private mode (not logged in)
2. Navigate to: https://merchant.bolt.com/admin
3. Observe HTTP 200 OK response
4. Verify that the endpoint returns administrative data without requiring authentication

**Proof of Concept:**
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/4725584/build/assets/favicon.ac07a2d4.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Merchant Dashboard Beta</title>
    <script src="https://pg.feroot.com/v1/bundle/6b2540e4-725f-4b65-9ffe-b601bf50ba24"></script>
    <script type="module" crossorigin src="/4725584/build/js/entry-app.js"></script>
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-edit-user-modal.308b462f.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-polyfills.86a59b21.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-context.834aeef2.js">
  </head>
  <body class="merchant-v2">
    <div id="root"></div>
    
  </body>
</html>

Response: HTTP 200 OK (should be 401/403)

**Impact:**
Unauthorized users can access administrative functions without authentication, potentially allowing:
- Access to sensitive merchant data
- System configuration manipulation
- Privilege escalation

**Affected Endpoint:**
https://merchant.bolt.com/admin

---

## SUBMISSION 2/8: Authentication Bypass - Dashboard

**Title:**
Authentication Bypass - Dashboard Accessible Without Authentication

**Severity:**
High

**Description:**
The dashboard endpoint at https://merchant.bolt.com/dashboard is accessible without authentication, allowing unauthorized access to merchant dashboard functionality.

**Steps to Reproduce:**
1. Navigate to: https://merchant.bolt.com/dashboard (without authentication)
2. Observe HTTP 200 OK response
3. Verify unauthorized access to dashboard functions

**Proof of Concept:**
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/4725584/build/assets/favicon.ac07a2d4.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Merchant Dashboard Beta</title>
    <script src="https://pg.feroot.com/v1/bundle/6b2540e4-725f-4b65-9ffe-b601bf50ba24"></script>
    <script type="module" crossorigin src="/4725584/build/js/entry-app.js"></script>
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-edit-user-modal.308b462f.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-polyfills.86a59b21.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-context.834aeef2.js">
  </head>
  <body class="merchant-v2">
    <div id="root"></div>
    
  </body>
</html>

Response: HTTP 200 OK

**Impact:**
Unauthorized access to merchant dashboard, allowing viewing of sensitive merchant data and operations.

**Affected Endpoint:**
https://merchant.bolt.com/dashboard

---

## SUBMISSION 3/8: Authentication Bypass - Settings

**Title:**
Authentication Bypass - Settings Endpoint Accessible Without Authentication

**Severity:**
High

**Description:**
The settings endpoint at https://merchant.bolt.com/settings is accessible without authentication.

**Steps to Reproduce:**
1. Navigate to: https://merchant.bolt.com/settings (without authentication)
2. Observe HTTP 200 OK response
3. Verify unauthorized access to settings

**Proof of Concept:**
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/4725584/build/assets/favicon.ac07a2d4.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Merchant Dashboard Beta</title>
    <script src="https://pg.feroot.com/v1/bundle/6b2540e4-725f-4b65-9ffe-b601bf50ba24"></script>
    <script type="module" crossorigin src="/4725584/build/js/entry-app.js"></script>
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-edit-user-modal.308b462f.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-polyfills.86a59b21.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-context.834aeef2.js">
  </head>
  <body class="merchant-v2">
    <div id="root"></div>
    
  </body>
</html>

Response: HTTP 200 OK

**Impact:**
Unauthorized access to merchant settings, potentially allowing configuration changes.

**Affected Endpoint:**
https://merchant.bolt.com/settings

---

## SUBMISSION 4/8: Authentication Bypass - API Admin

**Title:**
Authentication Bypass - API Admin Endpoint Accessible Without Authentication

**Severity:**
High

**Description:**
The API admin endpoint at https://merchant.bolt.com/api/admin is accessible without authentication.

**Steps to Reproduce:**
1. Navigate to: https://merchant.bolt.com/api/admin (without authentication)
2. Observe HTTP 200 OK response
3. Verify unauthorized access to admin API functions

**Proof of Concept:**
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/4725584/build/assets/favicon.ac07a2d4.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Merchant Dashboard Beta</title>
    <script src="https://pg.feroot.com/v1/bundle/6b2540e4-725f-4b65-9ffe-b601bf50ba24"></script>
    <script type="module" crossorigin src="/4725584/build/js/entry-app.js"></script>
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-edit-user-modal.308b462f.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-polyfills.86a59b21.js">
    <link rel="modulepreload" crossorigin href="/4725584/build/js/chunk-context.834aeef2.js">
  </head>
  <body class="merchant-v2">
    <div id="root"></div>
    
  </body>
</html>

Response: HTTP 200 OK

**Impact:**
Unauthorized access to administrative API functions.

**Affected Endpoint:**
https://merchant.bolt.com/api/admin

---

## SUBMISSION 5/8: Payment Manipulation - Negative Amount

**Title:**
Payment Manipulation - Negative Amount Accepted

**Severity:**
High

**Description:**
The payment endpoint at https://merchant.bolt.com/api/v1/payments accepts negative amounts, allowing payment manipulation that could result in refunds or payment reversals.

**Steps to Reproduce:**
1. Send POST request to: https://merchant.bolt.com/api/v1/payments
2. Include payload: {
