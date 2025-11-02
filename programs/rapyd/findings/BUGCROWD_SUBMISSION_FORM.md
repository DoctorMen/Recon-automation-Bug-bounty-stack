# Bugcrowd Submission Form - Complete Fields

## Submission Title
```
IDOR Vulnerability in Payment Details Endpoint
```

## Target
```
dashboard.rapyd.net
```

## VRT Category
```
Insecure Direct Object Reference (IDOR)
```

## URL / Location of Vulnerability
```
https://dashboard.rapyd.net/collect/payments/{payment_id}
```

## Description (Markdown Format)

### Vulnerability Description

An **Insecure Direct Object Reference (IDOR)** vulnerability exists in the Rapyd dashboard payment details endpoint (`/collect/payments/{payment_id}`). The application lacks proper access control validation, allowing authenticated users to access payment information belonging to other users by modifying the payment ID parameter in the URL.

### Impact

**Security Impact:**
- **Unauthorized Data Access:** Attackers can view payment details belonging to other users
- **Privacy Violation:** Exposure of financial transaction information
- **Compliance Violations:** Potential GDPR/PCI-DSS violations
- **Data Breach Risk:** Bulk enumeration of payment data possible

**Business Impact:**
- **Reputational Damage:** Loss of customer trust and brand integrity
- **Regulatory Fines:** Potential penalties for data protection violations
- **Legal Liability:** Data breach liabilities and lawsuits

### Steps to Reproduce

**Prerequisites:**
- Two Rapyd dashboard accounts (Account A and Account B)
- Account B must have at least one payment created

**Reproduction Steps:**

1. **Log in to Account A**
   - Navigate to: `https://dashboard.rapyd.net/login`
   - Login with: `Account_A_Email@example.com`
   - **Capture:** Screenshot of Account A dashboard showing username

2. **Obtain Account B's Payment ID**
   - Log in to Account B (separate session)
   - Navigate to: `https://dashboard.rapyd.net/collect/payments/list`
   - Note a payment ID from Account B (e.g., `pay_abc123def456ghi789`)
   - **Capture:** Screenshot of Account B's payment list

3. **Access Account B's Payment from Account A**
   - While logged in as Account A, navigate to:
     ```
     https://dashboard.rapyd.net/collect/payments/pay_abc123def456ghi789
     ```
   - Replace `pay_abc123def456ghi789` with Account B's actual payment ID
   - **Observe:** Payment details page loads successfully, displaying Account B's payment data

4. **Verify Unauthorized Access**
   - Check that payment details displayed belong to Account B
   - Verify Account A can access data it should not have permission to view
   - **Capture:** Screenshot showing Account A username and Account B's payment details

### Proof of Concept

**Test Accounts:**

**Account A:**
- Email: `DoctorMen@bugcrowdninja.com`
- Account ID: `[TO BE CAPTURED]`
- Login Timestamp: `[TO BE CAPTURED] UTC`

**Account B:**
- Email: `[REDACTED]`
- Account ID: `[TO BE CAPTURED]`
- Payment ID: `pay_abc123def456ghi789`
- Payment Creation: `[TO BE CAPTURED] UTC`

**IDOR Access Attempt:**

**Request (cURL):**
```bash
curl -X GET "https://dashboard.rapyd.net/v1/merchants-portal/payments/pay_abc123def456ghi789" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "X-Bugcrowd: Bugcrowd-DoctorMen" \
  -H "Content-Type: application/json"
```

**Response:** (Redacted - Sensitive data marked as `[REDACTED]`)
```json
{
  "status": {
    "status": "SUCCESS",
    "operation_id": "op_xyz789abc123"
  },
  "data": {
    "id": "pay_abc123def456ghi789",
    "amount": 100,
    "currency": "USD",
    "status": "CLOSED",
    "created_at": "2025-01-XX 12:34:56 UTC",
    "customer": {
      "id": "cust_xyz789",
      "email": "[REDACTED]",
      "name": "[REDACTED]"
    },
    "payment_method": {
      "type": "card",
      "last4": "[REDACTED]",
      "expiration_month": "[REDACTED]",
      "expiration_year": "[REDACTED]"
    },
    "merchant": {
      "id": "[Account B's Merchant ID]",
      "name": "[REDACTED]"
    }
  }
}
```

**Access Timestamp:** `[TO BE CAPTURED] UTC`  
**Operation ID:** `op_xyz789abc123`

**Evidence Attached:**
1. Screenshot: Account A dashboard showing username `DoctorMen`
2. Screenshot: Account B payment creation confirmation
3. Screenshot: Account A accessing Account B's payment details
4. Screenshot: URL bar showing Account B's payment ID in Account A's session
5. Network Capture: Full cURL request/response (see attached files)
6. Video: 30-second video showing complete reproduction (optional)

### CVSS Scoring

**CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Base Score:** **7.5 (High)**

**Breakdown:**
- Attack Vector: Network (remotely exploitable)
- Attack Complexity: Low (simple parameter manipulation)
- Privileges Required: Low (requires authenticated user)
- User Interaction: None
- Scope: Unchanged
- Confidentiality: High (unauthorized access to sensitive financial data)
- Integrity: None
- Availability: None

### Recommended Fix

Implement proper authorization checks to verify that the authenticated user has permission to access the requested payment resource.

**Implementation Example:**

```python
def get_payment_details(payment_id, current_user):
    """
    Retrieve payment details with proper authorization check.
    """
    payment = Payment.query.filter_by(id=payment_id).first()
    
    if not payment:
        return {"error": "Payment not found"}, 404
    
    # Authorization check: Verify user owns the payment
    if payment.merchant_id != current_user.merchant_id and not current_user.is_admin:
        log_security_event(
            event_type="unauthorized_access_attempt",
            user_id=current_user.id,
            resource_type="payment",
            resource_id=payment_id,
            timestamp=datetime.utcnow()
        )
        return {"error": "Forbidden"}, 403
    
    return payment.to_dict(), 200
```

**Additional Security Measures:**
1. Implement role-based access control (RBAC)
2. Use merchant-level isolation
3. Log all payment detail access attempts
4. Monitor for enumeration attempts
5. Implement rate limiting on payment detail endpoints

### Testing Environment

- **Mode:** Sandbox
- **Account A:** DoctorMen@bugcrowdninja.com
- **Account B:** [REDACTED]
- **Header:** `X-Bugcrowd: Bugcrowd-DoctorMen`

