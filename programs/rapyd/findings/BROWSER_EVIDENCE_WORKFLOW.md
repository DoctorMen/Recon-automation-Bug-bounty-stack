# IDOR Evidence Capture - Browser-Based Idempotent Workflow

**Goal:** Capture all required evidence for IDOR submission using browser automation
**Status:** ✅ **READY - Run steps sequentially**

---

## 🎯 **WORKFLOW OVERVIEW**

This workflow is **idempotent** - you can run it multiple times safely. Each step saves progress, so you can resume from any point.

---

## 📋 **STEP 1: SETUP - Create Evidence Directory**

```bash
# Create evidence directory (idempotent - safe to run multiple times)
mkdir -p programs/rapyd/findings/evidence
cd programs/rapyd/findings
```

**Status File:** `evidence/.capture_state.json` (tracks progress)

---

## 📋 **STEP 2: LOGIN TO ACCOUNT A**

**Browser Actions:**
1. Navigate to: `https://dashboard.rapyd.net/login`
2. Log in with: `DoctorMen@bugcrowdninja.com`
3. Take screenshot: `evidence/account_a_dashboard.png`
4. Capture Account A username from dashboard header
5. Note login timestamp (UTC)

**Save to state:**
```json
{
  "account_a": {
    "email": "DoctorMen@bugcrowdninja.com",
    "username": "[captured from dashboard]",
    "login_timestamp": "[UTC timestamp]",
    "screenshot": "evidence/account_a_dashboard.png",
    "status": "complete"
  }
}
```

---

## 📋 **STEP 3: CREATE ACCOUNT B (OR USE EXISTING)**

**Option A: Create New Account B**
1. Open incognito/private window
2. Navigate to: `https://dashboard.rapyd.net/signup`
3. Create account with email: `test_account_b_[timestamp]@bugcrowdninja.com`
4. Complete registration
5. Take screenshot: `evidence/account_b_created.png`

**Option B: Use Existing Account**
1. Log out of Account A
2. Log in to Account B
3. Capture Account B email and username

**Save to state:**
```json
{
  "account_b": {
    "email": "[REDACTED in report]",
    "username": "[captured from dashboard]",
    "creation_timestamp": "[UTC timestamp]",
    "screenshot": "evidence/account_b_created.png",
    "status": "complete"
  }
}
```

---

## 📋 **STEP 4: CREATE PAYMENT IN ACCOUNT B**

**Browser Actions:**
1. Logged in as Account B, navigate to: `https://dashboard.rapyd.net/collect/payments/list`
2. Click "Create Payment" or "New Payment"
3. Use sandbox test card:
   - Card Number: `4111111111111111`
   - Expiry: `12/2025`
   - CVV: `123`
   - Amount: `100 USD`
4. Complete payment creation
5. **Capture Payment ID from URL or response**
   - URL format: `https://dashboard.rapyd.net/collect/payments/pay_abc123def456ghi789`
   - Payment ID: `pay_abc123def456ghi789`
6. Take screenshot: `evidence/account_b_payment_created.png`
7. Note creation timestamp (UTC)

**Save to state:**
```json
{
  "payment": {
    "payment_id": "pay_abc123def456ghi789",
    "account_b_email": "[REDACTED]",
    "creation_timestamp": "[UTC timestamp]",
    "amount": 100,
    "currency": "USD",
    "screenshot": "evidence/account_b_payment_created.png",
    "status": "complete"
  }
}
```

---

## 📋 **STEP 5: LOGIN TO ACCOUNT A AGAIN**

**Browser Actions:**
1. Log out of Account B (or use separate browser window)
2. Navigate to: `https://dashboard.rapyd.net/login`
3. Log in as Account A: `DoctorMen@bugcrowdninja.com`
4. Verify Account A dashboard loads
5. Open DevTools (F12)
6. Go to Network tab
7. Enable "Preserve log"
8. Take screenshot: `evidence/account_a_dashboard_with_devtools.png`

**Status:** Ready to capture IDOR access

---

## 📋 **STEP 6: CAPTURE IDOR ACCESS - THE CRITICAL STEP**

**Browser Actions:**

1. **In Account A session, navigate to Account B's payment URL:**
   ```
   https://dashboard.rapyd.net/collect/payments/pay_abc123def456ghi789
   ```
   (Replace with actual Account B payment ID)

2. **In DevTools Network tab:**
   - Find the API request to `/v1/merchants-portal/payments/{payment_id}`
   - The request should show 200 OK status
   - Click on the request to view details

3. **Capture Request (cURL):**
   - Right-click on the network request
   - Select "Copy" → "Copy as cURL"
   - Save to: `evidence/idor_request_curl.txt`
   - Or manually copy and save

4. **Capture Response (JSON):**
   - Click on the network request
   - Go to "Response" tab
   - Copy the full JSON response
   - Save to: `evidence/idor_response_raw.json`

5. **Capture Screenshots:**
   - Account A username visible in top-left: `evidence/idor_account_context.png`
   - Payment details page: `evidence/idor_payment_details.png`
   - URL bar showing payment ID: `evidence/idor_url_bar.png`
   - Full page: `evidence/idor_full_page.png`

6. **Capture Operation ID:**
   - From API response JSON, find `operation_id` field
   - Example: `"operation_id": "op_xyz789abc123"`
   - Save to state file

7. **Capture Timestamp:**
   - Note exact UTC timestamp of access
   - Format: `YYYY-MM-DD HH:MM:SS UTC`

**Save to state:**
```json
{
  "idor_access": {
    "timestamp": "[UTC timestamp]",
    "payment_id": "pay_abc123def456ghi789",
    "account_a_email": "DoctorMen@bugcrowdninja.com",
    "account_b_email": "[REDACTED]",
    "operation_id": "op_xyz789abc123",
    "status_code": 200,
    "screenshots": [
      "evidence/idor_account_context.png",
      "evidence/idor_payment_details.png",
      "evidence/idor_url_bar.png",
      "evidence/idor_full_page.png"
    ],
    "network_capture": "evidence/idor_request_curl.txt",
    "raw_response": "evidence/idor_response_raw.json",
    "status": "complete"
  }
}
```

---

## 📋 **STEP 7: REDACT SENSITIVE DATA**

**Automated Redaction Script:**

```bash
# Run redaction script (idempotent)
cd programs/rapyd/findings
python3 <<'EOF'
import json
import re
from datetime import datetime

# Load raw response
with open('evidence/idor_response_raw.json', 'r') as f:
    data = json.load(f)

# Fields to always redact
SENSITIVE_FIELDS = [
    'email', 'phone', 'phone_number', 'cvv', 'ssn', 
    'card_number', 'name', 'full_name', 'last_name', 'first_name',
    'last4', 'expiration_month', 'expiration_year',
    'billing_address', 'shipping_address', 'street', 'city', 'zip'
]

def redact_value(obj, path=''):
    """Recursively redact sensitive values"""
    if isinstance(obj, dict):
        return {k: redact_value(v, f"{path}.{k}" if path else k) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_value(item, path) for item in obj]
    elif isinstance(obj, str):
        # Redact emails
        if '@' in obj and '.' in obj:
            return '[REDACTED]'
        # Redact phone numbers
        if re.match(r'^\+?\d{10,15}$', obj.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')):
            return '[REDACTED]'
        # Redact card numbers (13-19 digits)
        if re.match(r'^\d{13,19}$', obj.replace(' ', '').replace('-', '')):
            return '[REDACTED]'
        return obj
    else:
        return obj

def deep_redact(obj, path=''):
    """Redact specific sensitive fields"""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            field_path = f"{path}.{k}" if path else k
            # Check if this field should be redacted
            if any(field in k.lower() for field in SENSITIVE_FIELDS):
                result[k] = '[REDACTED]'
            else:
                result[k] = deep_redact(v, field_path)
        return result
    elif isinstance(obj, list):
        return [deep_redact(item, path) for item in obj]
    else:
        return obj

# Apply redaction
redacted = deep_redact(redact_value(data))

# Save redacted version
with open('evidence/idor_response_redacted.json', 'w') as f:
    json.dump(redacted, f, indent=2)

print("✅ Redacted JSON saved to: evidence/idor_response_redacted.json")
EOF
```

**Manual Check:**
- Review `evidence/idor_response_redacted.json`
- Ensure all emails, card numbers, names are redacted
- Verify payment IDs, amounts, timestamps are preserved

---

## 📋 **STEP 8: RECORD VIDEO (OPTIONAL BUT RECOMMENDED)**

**Video Recording Steps:**

1. **Prepare:**
   - Account A logged in
   - Account B payment ID ready
   - Screen recording tool (OBS, QuickTime, or browser extension)

2. **Record (20-30 seconds):**
   - **0-5s:** Show Account A dashboard (username visible)
   - **5-10s:** Navigate to URL bar, type Account B's payment URL
   - **10-15s:** Show page loading
   - **15-25s:** Show payment details page with Account B's data
   - **25-30s:** Zoom in on URL bar showing payment ID

3. **Save:** `evidence/idor_proof_video.mp4` (max 50MB)

**Status:** Optional but highly persuasive

---

## 📋 **STEP 9: GENERATE FINAL REPORT**

**Automated Report Generation:**

```bash
# Generate final report with captured data
cd programs/rapyd/findings
python3 <<'EOF'
import json
from datetime import datetime

# Load state
with open('evidence/.capture_state.json', 'r') as f:
    state = json.load(f)

# Generate report
report = f"""# IDOR Evidence Capture - Complete Report

**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
**Status:** ✅ **EVIDENCE CAPTURED**

---

## Account Information

**Account A:**
- Email: {state['account_a']['email']}
- Username: {state['account_a'].get('username', 'Not captured')}
- Login Timestamp: {state['account_a']['login_timestamp']}

**Account B:**
- Email: [REDACTED]
- Username: {state['account_b'].get('username', 'Not captured')}
- Creation Timestamp: {state['account_b']['creation_timestamp']}

---

## Payment Information

- Payment ID: {state['payment']['payment_id']}
- Account B Email: [REDACTED]
- Creation Timestamp: {state['payment']['creation_timestamp']}
- Amount: {state['payment']['amount']} {state['payment']['currency']}

---

## IDOR Access Proof

- Access Timestamp: {state['idor_access']['timestamp']}
- Payment ID Accessed: {state['idor_access']['payment_id']}
- Operation ID: {state['idor_access']['operation_id']}
- Status Code: {state['idor_access']['status_code']}

---

## Evidence Files

### Screenshots:
{chr(10).join(f"- {s}" for s in state['idor_access']['screenshots'])}

### Network Capture:
- Request: {state['idor_access']['network_capture']}
- Raw Response: {state['idor_access']['raw_response']}
- Redacted Response: evidence/idor_response_redacted.json

### Video (Optional):
- Video Proof: evidence/idor_proof_video.mp4

---

## Next Steps

1. Review all evidence files
2. Verify redacted JSON is safe to share
3. Update SUBMISSION_READY_REPORT.md with actual values
4. Submit to Bugcrowd

**Status:** ✅ **READY FOR SUBMISSION**
"""

with open('evidence/CAPTURE_COMPLETE.md', 'w') as f:
    f.write(report)

print("✅ Report generated: evidence/CAPTURE_COMPLETE.md")
EOF
```

---

## ✅ **IDEMPOTENCY FEATURES**

1. **State Tracking:** All progress saved to `evidence/.capture_state.json`
2. **Resume Capability:** Can resume from any step
3. **Safe Re-runs:** Scripts check if files exist before overwriting
4. **Progress Indicators:** Each step shows completion status

---

## 🚀 **QUICK START COMMANDS**

```bash
# 1. Navigate to findings directory
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings

# 2. Create evidence directory (idempotent)
mkdir -p evidence

# 3. Follow browser steps above manually
# OR use browser automation (see below)

# 4. After capturing evidence, run redaction:
python3 -c "$(cat <<'PYEOF'
# Paste redaction script from Step 7 above
PYEOF
)"

# 5. Generate final report:
python3 -c "$(cat <<'PYEOF'
# Paste report generation script from Step 9 above
PYEOF
)"
```

---

## 📝 **BROWSER AUTOMATION OPTIONS**

**Option 1: Manual Browser + Scripts**
- Follow steps 1-9 manually in browser
- Use scripts for redaction and report generation
- Most flexible, full control

**Option 2: Browser DevTools Recording**
- Use browser's built-in recording
- Capture network requests automatically
- Export as HAR file

**Option 3: Burp Suite**
- Proxy browser through Burp
- Automatic request/response capture
- Professional security testing tool

---

**Status:** ✅ **READY TO USE**  
**Estimated Time:** 30-60 minutes for complete capture  
**Difficulty:** Medium (requires two accounts and manual browser work)



