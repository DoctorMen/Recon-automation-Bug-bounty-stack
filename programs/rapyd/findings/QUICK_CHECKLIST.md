# Quick Browser Evidence Capture Checklist

## ✅ **STEP-BY-STEP CHECKLIST**

### **Step 1: Account A** ✅
- [ ] Open browser → `https://dashboard.rapyd.net/login`
- [ ] Log in: `DoctorMen@bugcrowdninja.com`
- [ ] Screenshot: `evidence/account_a_dashboard.png`
- [ ] Note: Username from dashboard header
- [ ] Note: Login timestamp (UTC)

### **Step 2: Account B** ✅
- [ ] Open incognito window → `https://dashboard.rapyd.net/signup`
- [ ] Create Account B (or log in to existing)
- [ ] Screenshot: `evidence/account_b_created.png`
- [ ] Note: Account B email
- [ ] Note: Account B username

### **Step 3: Create Payment in Account B** ✅
- [ ] In Account B → `https://dashboard.rapyd.net/collect/payments/list`
- [ ] Create test payment (sandbox card: `4111111111111111`)
- [ ] Copy Payment ID from URL (e.g., `pay_abc123...`)
- [ ] Screenshot: `evidence/account_b_payment_created.png`
- [ ] Note: Payment creation timestamp (UTC)

### **Step 4: IDOR Access Capture** ✅ (CRITICAL)
- [ ] Switch to Account A session
- [ ] Open DevTools (F12) → Network tab
- [ ] Enable "Preserve log"
- [ ] Navigate to: `https://dashboard.rapyd.net/collect/payments/{Account_B_Payment_ID}`
- [ ] In Network tab, find API request to `/v1/merchants-portal/payments/{payment_id}`
- [ ] Right-click request → "Copy" → "Copy as cURL"
- [ ] Save to: `evidence/idor_request_curl.txt`
- [ ] Click request → "Response" tab → Copy JSON
- [ ] Save to: `evidence/idor_response_raw.json`
- [ ] Screenshot: Account A username + Account B payment → `evidence/idor_account_context.png`
- [ ] Screenshot: Payment details → `evidence/idor_payment_details.png`
- [ ] Screenshot: URL bar → `evidence/idor_url_bar.png`
- [ ] Note: Operation ID from JSON response
- [ ] Note: Access timestamp (UTC)

### **Step 5: Redact Sensitive Data** ✅
```bash
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings
python3 <<'EOF'
import json
import re

with open('evidence/idor_response_raw.json', 'r') as f:
    data = json.load(f)

SENSITIVE_FIELDS = ['email', 'phone', 'phone_number', 'cvv', 'ssn', 'card_number', 
                    'name', 'full_name', 'last_name', 'first_name', 'last4', 
                    'expiration_month', 'expiration_year']

def redact_value(obj, path=''):
    if isinstance(obj, dict):
        return {k: redact_value(v, f"{path}.{k}" if path else k) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_value(item, path) for item in obj]
    elif isinstance(obj, str):
        if '@' in obj and '.' in obj:
            return '[REDACTED]'
        if re.match(r'^\+?\d{10,15}$', obj.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')):
            return '[REDACTED]'
        if re.match(r'^\d{13,19}$', obj.replace(' ', '').replace('-', '')):
            return '[REDACTED]'
        return obj
    else:
        return obj

def deep_redact(obj, path=''):
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            field_path = f"{path}.{k}" if path else k
            if any(field in k.lower() for field in SENSITIVE_FIELDS):
                result[k] = '[REDACTED]'
            else:
                result[k] = deep_redact(v, field_path)
        return result
    elif isinstance(obj, list):
        return [deep_redact(item, path) for item in obj]
    else:
        return obj

redacted = deep_redact(redact_value(data))

with open('evidence/idor_response_redacted.json', 'w') as f:
    json.dump(redacted, f, indent=2)

print("✅ Redacted JSON saved")
EOF
```

### **Step 6: Verify Evidence** ✅
- [ ] All screenshots saved
- [ ] cURL request saved
- [ ] Raw JSON response saved
- [ ] Redacted JSON created
- [ ] Operation ID captured
- [ ] All timestamps documented (UTC)

---

## 🎯 **QUICK COMMANDS**

```bash
# Create evidence directory
mkdir -p ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings/evidence

# Navigate to findings
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings

# Check what's captured
ls -lh evidence/

# Run redaction (after capturing raw JSON)
python3 <<'EOF'
# Paste redaction script from Step 5 above
EOF
```

---

**Status:** Follow checklist above in your browser  
**Estimated Time:** 30-60 minutes  
**Critical Step:** Step 4 (IDOR Access Capture)

