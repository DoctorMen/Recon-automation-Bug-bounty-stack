# IDOR Evidence Capture Process - Step-by-Step Guide

## Overview
This guide walks through capturing IDOR evidence for Rapyd bug bounty submission.

## Prerequisites
- Account A: DoctorMen@bugcrowdninja.com (password required)
- Account B: Need to create or use existing account
- Browser with DevTools enabled
- Evidence directory: programs/rapyd/findings/evidence/

---

## STEP 1: Account A Dashboard Capture (5 min)

### Actions:
1. Navigate to: https://dashboard.rapyd.net/login
2. Log in with: DoctorMen@bugcrowdninja.com
3. Wait for dashboard to load
4. Take screenshot showing Account A username/account context

### Screenshot Required:
- File: evidence/account_a_dashboard.png
- Must show: Username/email visible in dashboard UI

### Verification:
- [ ] Screenshot saved
- [ ] Account A username visible in screenshot
- [ ] Dashboard loaded successfully

---

## STEP 2: Account B Setup (5 min)

### Option A: Create New Account
1. Sign out from Account A
2. Navigate to: https://dashboard.rapyd.net/signup
3. Create account with different email
4. Complete signup process
5. Take screenshot of account creation

### Option B: Use Existing Account
1. Log in with existing Account B credentials
2. Take screenshot of account dashboard

### Screenshot Required:
- File: evidence/account_b_created.png
- Must show: Account B creation/login confirmation

### Verification:
- [ ] Account B created/logged in
- [ ] Screenshot saved

---

## STEP 3: Create Payment in Account B (10 min)

### Actions:
1. Logged in as Account B
2. Navigate to: Payments â†’ Create Payment
3. Use sandbox test card details:
   - Card Number: 4111111111111111
   - Expiry: 12/2025
   - CVV: 123
4. Complete payment creation
5. **Capture Payment ID from URL** (e.g., pay_abc123...)
   - URL format: https://dashboard.rapyd.net/collect/payments/{PAYMENT_ID}

### Screenshot Required:
- File: evidence/account_b_payment_created.png
- Must show: Payment creation confirmation with Payment ID

### Data to Capture:
- Payment ID (from URL)
- Payment amount
- Payment status
- Timestamp

### Verification:
- [ ] Payment created successfully
- [ ] Payment ID captured
- [ ] Screenshot saved

---

## STEP 4: Capture IDOR Access (15-20 min) - CRITICAL STEP

### Preparation:
1. **Log in as Account A** (DoctorMen@bugcrowdninja.com)
2. Open DevTools (F12)
3. Go to Network tab
4. Enable " Preserve log checkbox
