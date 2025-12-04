# Instacart Auth Token Guide

## 🎯 Goal: Get 3 Role Tokens

| Role | Token Use | Why Critical |
|------|-----------|-------------|
| **Customer** | `customer_token` | Access orders, payments, tips |
| **Shopper** | `shopper_token` | Access earnings, assignments |
| **Merchant** | `merchant_token` | Access inventory, store data |

---

## 📱 Method 1: Mobile App (Easiest)

### Customer Token
```
1. Download Instacart app (iOS/Android)
2. Sign up with shadowstep_131@wearehackerone.com
3. Complete onboarding
4. Use Burp Suite to intercept traffic
5. Look for: Authorization: Bearer eyJhbGciOi...
```

### Shopper Token
```
1. Apply to be a shopper in app
2. Use different email: shadowstep_131+1@wearehackerone.com
3. Complete shopper registration
4. Capture shopper-specific API calls
5. Extract token from Authorization header
```

### Merchant Token
```
1. Go to instacart.com/retail
2. Register as retailer/business
3. Use shadowstep_131+2@wearehackerone.com
4. Access merchant dashboard
5. Capture merchant API traffic
```

---

## 💻 Method 2: Web + Burp Suite

### Setup
```bash
# Configure Burp
1. Proxy: 127.0.0.1:8080
2. Install CA certificate on device
3. Add header rule: X-Bug-Bounty: shadowstep_131
4. Enable HTTP history logging
```

### Capture Tokens
```javascript
// Browser console - check localStorage
console.log(localStorage.getItem('auth_token'))
console.log(localStorage.getItem('customer_token'))
console.log(localStorage.getItem('shopper_token'))

// Check cookies
document.cookie
```

---

## 🔍 Method 3: Network Inspection

### Chrome DevTools
```
1. Open Instacart website
2. F12 → Network tab
3. Filter: /api/
4. Look for POST /login or PUT /session
5. Check Request Headers for Authorization
```

### iOS Packet Capture
```bash
# Using rvictl (macOS)
rvictl -s <device_udid>
# Run Wireshark on rvi0 interface
# Filter: http and frame contains "Authorization"
```

---

## 📝 Token Format Examples

### Customer Token
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-Instacart-User-Type: customer
X-Instacart-User-ID: cust_12345678
```

### Shopper Token
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-Instacart-User-Type: shopper
X-Instacart-Shopper-ID: shopper_87654321
```

### Merchant Token
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-Instacart-User-Type: merchant
X-Instacart-Store-ID: store_11223344
```

---

## ⚡ Quick Test Script

```python
# test_tokens.py
import requests

tokens = {
    "customer": "Bearer eyJ...",
    "shopper": "Bearer eyJ...",
    "merchant": "Bearer eyJ..."
}

base_url = "https://api.instacart.com"

for role, token in tokens.items():
    headers = {
        "Authorization": token,
        "X-Bug-Bounty": "shadowstep_131"
    }
    
    # Test basic endpoint
    resp = requests.get(f"{base_url}/v1/user", headers=headers)
    print(f"{role}: {resp.status_code}")
    
    if resp.status_code == 200:
        print(f"  Token valid for {role}")
    else:
        print(f"  Token invalid or expired")
```

---

## 🔄 Token Refresh

Tokens expire. Need to:

1. **Monitor expiration** - Check 401 responses
2. **Auto-refresh** - Implement token refresh logic
3. **Backup tokens** - Save multiple tokens per role

```python
# Token refresh example
def refresh_token(refresh_token):
    resp = requests.post(
        "https://api.instacart.com/v1/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    return resp.json().get("access_token")
```

---

## 🎯 Once You Have Tokens

```python
# Update hunter with real tokens
hunter = InstacartHunter()
hunter.set_auth_tokens(
    customer="Bearer eyJ...",
    shopper="Bearer eyJ...",
    merchant="Bearer eyJ..."
)
hunter.run_full_hunt()
```

---

## ⚠️ Important Notes

1. **Use @wearehackerone.com email** - Required by program
2. **Don't abuse tokens** - Only for authorized testing
3. **Token rotation** - Get fresh tokens if expired
4. **Document everything** - Save token acquisition method

---

## 🏁 Success Criteria

- [ ] Customer token can access `/v1/orders`
- [ ] Shopper token can access `/v1/earnings`
- [ ] Merchant token can access `/v1/inventory`
- [ ] All tokens pass basic auth test
- [ ] Ready to run `instacart_hunter.py`

---

*Tokens are the keys. Get them right, the hunt begins.* 🔑
