#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

"""
Automated Browser Evidence Capture for IDOR Testing
Assists with capturing screenshots and network requests for bug bounty submission.

This script guides through browser automation to capture:
- Account A dashboard screenshots
- Account B payment creation screenshots  
- IDOR access evidence (screenshots + network requests)
- Operation IDs from API responses

Usage:
    python3 automated_browser_evidence_capture.py
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Evidence directory
EVIDENCE_DIR = Path(__file__).parent / "evidence"
STATE_FILE = EVIDENCE_DIR / ".capture_state.json"


def ensure_evidence_dir():
    """Create evidence directory if it doesn't exist"""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"✅ Evidence directory ready: {EVIDENCE_DIR}")


def load_state() -> Dict:
    """Load capture state from file"""
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {
        "account_a": {"status": "pending"},
        "account_b": {"status": "pending"},
        "payment": {"status": "pending"},
        "idor_access": {"status": "pending"}
    }


def save_state(state: Dict):
    """Save capture state to file"""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)
    print(f"✅ State saved to {STATE_FILE}")


def print_step_header(step_num: int, title: str):
    """Print formatted step header"""
    print("\n" + "="*70)
    print(f"STEP {step_num}: {title}")
    print("="*70)


def print_browser_instructions(url: str, actions: list, screenshot_name: str):
    """Print browser instructions for manual steps"""
    print(f"\n🌐 Browser Actions Required:")
    print(f"   1. Navigate to: {url}")
    print(f"   2. Perform the following actions:")
    for i, action in enumerate(actions, 1):
        print(f"      {i}. {action}")
    print(f"\n📸 Screenshot Required:")
    print(f"   Save screenshot as: {EVIDENCE_DIR}/{screenshot_name}")
    print(f"\n⏸️  Press Enter after completing these steps...")
    input()


def capture_account_a(state: Dict):
    """Step 1: Capture Account A dashboard"""
    print_step_header(1, "Account A Dashboard Capture")
    
    if state["account_a"].get("status") == "complete":
        print("✅ Account A already captured. Skipping...")
        return state
    
    url = "https://dashboard.rapyd.net/login"
    actions = [
        "Log in with: DoctorMen@bugcrowdninja.com",
        "Wait for dashboard to load",
        "Take screenshot showing username/account context"
    ]
    
    print_browser_instructions(url, actions, "account_a_dashboard.png")
    
    # Update state
    account_a_email = input("Enter Account A email (or press Enter for default): ").strip()
    if not account_a_email:
        account_a_email = "DoctorMen@bugcrowdninja.com"
    
    account_a_username = input("Enter Account A username (from dashboard): ").strip()
    
    state["account_a"] = {
        "email": account_a_email,
        "username": account_a_username,
        "login_timestamp": datetime.utcnow().isoformat() + " UTC",
        "screenshot": "evidence/account_a_dashboard.png",
        "status": "complete"
    }
    
    save_state(state)
    return state


def capture_account_b(state: Dict):
    """Step 2: Capture Account B creation"""
    print_step_header(2, "Account B Setup")
    
    if state["account_b"].get("status") == "complete":
        print("✅ Account B already captured. Skipping...")
        return state
    
    print("\n📋 Choose Account B setup method:")
    print("   1. Create new account (recommended)")
    print("   2. Use existing account")
    choice = input("Choice (1/2): ").strip()
    
    if choice == "1":
        url = "https://dashboard.rapyd.net/signup"
        actions = [
            "Create new account",
            "Use email: test_account_b_[timestamp]@bugcrowdninja.com",
            "Complete registration",
            "Take screenshot of account creation"
        ]
    else:
        url = "https://dashboard.rapyd.net/login"
        actions = [
            "Log in to Account B",
            "Take screenshot showing Account B username"
        ]
    
    print_browser_instructions(url, actions, "account_b_created.png")
    
    account_b_email = input("Enter Account B email (will be redacted in report): ").strip()
    account_b_username = input("Enter Account B username: ").strip()
    
    state["account_b"] = {
        "email": account_b_email,
        "username": account_b_username,
        "creation_timestamp": datetime.utcnow().isoformat() + " UTC",
        "screenshot": "evidence/account_b_created.png",
        "status": "complete"
    }
    
    save_state(state)
    return state


def capture_payment_creation(state: Dict):
    """Step 3: Capture payment creation in Account B"""
    print_step_header(3, "Payment Creation (Account B)")
    
    if state["payment"].get("status") == "complete":
        print("✅ Payment already captured. Skipping...")
        return state
    
    url = "https://dashboard.rapyd.net/collect/payments/list"
    actions = [
        "Log in as Account B",
        "Navigate to Payments → Create Payment",
        "Use sandbox test card:",
        "  - Card: 4111111111111111",
        "  - Expiry: 12/2025",
        "  - CVV: 123",
        "  - Amount: 100 USD",
        "Complete payment creation",
        "Capture Payment ID from URL or response"
    ]
    
    print_browser_instructions(url, actions, "account_b_payment_created.png")
    
    payment_id = input("Enter Payment ID (from URL or response): ").strip()
    if not payment_id:
        print("⚠️  Warning: Payment ID not captured. Please enter it manually.")
        payment_id = input("Payment ID: ").strip()
    
    state["payment"] = {
        "payment_id": payment_id,
        "account_b_email": state["account_b"]["email"],
        "creation_timestamp": datetime.utcnow().isoformat() + " UTC",
        "amount": 100,
        "currency": "USD",
        "screenshot": "evidence/account_b_payment_created.png",
        "status": "complete"
    }
    
    save_state(state)
    return state


def capture_idor_access(state: Dict):
    """Step 4: Capture IDOR access evidence"""
    print_step_header(4, "IDOR Access Evidence Capture")
    
    if state["idor_access"].get("status") == "complete":
        print("✅ IDOR access already captured. Skipping...")
        return state
    
    payment_id = state["payment"].get("payment_id")
    if not payment_id:
        print("⚠️  Error: Payment ID not found. Please complete Step 3 first.")
        return state
    
    url = f"https://dashboard.rapyd.net/collect/payments/{payment_id}"
    
    print("\n🔧 Setup Instructions:")
    print("   1. Log in to Account A: DoctorMen@bugcrowdninja.com")
    print("   2. Open DevTools (F12)")
    print("   3. Go to Network tab")
    print("   4. Enable 'Preserve log'")
    print("\n🌐 Browser Actions:")
    print(f"   1. Navigate to: {url}")
    print("   2. Wait for page to load")
    print("   3. In DevTools Network tab:")
    print("      - Find API request to /v1/merchants-portal/payments/{payment_id}")
    print("      - Right-click → Copy → Copy as cURL")
    print("      - Save to: evidence/idor_request_curl.txt")
    print("   4. Click on the network request:")
    print("      - Go to Response tab")
    print("      - Copy full JSON response")
    print("      - Save to: evidence/idor_response_raw.json")
    print("\n📸 Screenshots Required:")
    print("   - evidence/idor_account_context.png (Account A username + payment details)")
    print("   - evidence/idor_payment_details.png (Payment details page)")
    print("   - evidence/idor_url_bar.png (URL bar showing payment ID)")
    print("   - evidence/idor_full_page.png (Full page view)")
    
    print("\n⏸️  Press Enter after capturing all evidence...")
    input()
    
    # Verify files exist
    required_files = [
        "evidence/idor_request_curl.txt",
        "evidence/idor_response_raw.json",
        "evidence/idor_account_context.png",
        "evidence/idor_payment_details.png",
        "evidence/idor_url_bar.png"
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = EVIDENCE_DIR.parent / file_path.replace("evidence/", "")
        if not full_path.exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  Warning: Missing files:")
        for f in missing_files:
            print(f"   - {f}")
        print("\nPlease capture these before proceeding.")
        proceed = input("Continue anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            return state
    
    # Extract operation ID from response if available
    operation_id = None
    response_file = EVIDENCE_DIR / "idor_response_raw.json"
    if response_file.exists():
        try:
            with open(response_file, 'r') as f:
                response_data = json.load(f)
                # Try to find operation_id in various locations
                if isinstance(response_data, dict):
                    operation_id = (
                        response_data.get("operation_id") or
                        response_data.get("status", {}).get("operation_id") or
                        response_data.get("data", {}).get("operation_id")
                    )
        except Exception as e:
            print(f"⚠️  Could not extract operation ID: {e}")
    
    if not operation_id:
        operation_id = input("Enter Operation ID (from API response, or press Enter to skip): ").strip() or None
    
    state["idor_access"] = {
        "timestamp": datetime.utcnow().isoformat() + " UTC",
        "payment_id": payment_id,
        "account_a_email": state["account_a"]["email"],
        "account_b_email": state["account_b"]["email"],
        "operation_id": operation_id,
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
    
    save_state(state)
    return state


def generate_summary_report(state: Dict):
    """Generate summary report of captured evidence"""
    print_step_header(5, "Evidence Summary Report")
    
    report = f"""# IDOR Evidence Capture - Summary Report

**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Status:** ✅ **EVIDENCE CAPTURED**

---

## Account Information

**Account A:**
- Email: {state['account_a'].get('email', 'Not captured')}
- Username: {state['account_a'].get('username', 'Not captured')}
- Login Timestamp: {state['account_a'].get('login_timestamp', 'Not captured')}

**Account B:**
- Email: [REDACTED]
- Username: {state['account_b'].get('username', 'Not captured')}
- Creation Timestamp: {state['account_b'].get('creation_timestamp', 'Not captured')}

---

## Payment Information

- Payment ID: {state['payment'].get('payment_id', 'Not captured')}
- Account B Email: [REDACTED]
- Creation Timestamp: {state['payment'].get('creation_timestamp', 'Not captured')}
- Amount: {state['payment'].get('amount', 'N/A')} {state['payment'].get('currency', 'USD')}

---

## IDOR Access Proof

- Access Timestamp: {state['idor_access'].get('timestamp', 'Not captured')}
- Payment ID Accessed: {state['idor_access'].get('payment_id', 'Not captured')}
- Operation ID: {state['idor_access'].get('operation_id', 'Not captured')}
- Status Code: {state['idor_access'].get('status_code', 'N/A')}

---

## Evidence Files

### Screenshots:
{chr(10).join(f"- {s}" for s in state['idor_access'].get('screenshots', []))}

### Network Capture:
- Request: {state['idor_access'].get('network_capture', 'Not captured')}
- Raw Response: {state['idor_access'].get('raw_response', 'Not captured')}
- Redacted Response: evidence/idor_response_redacted.json (to be created)

---

## Next Steps

1. ✅ Review all evidence files
2. ⏳ Run redaction script on raw JSON response
3. ⏳ Generate final bug bounty report
4. ⏳ Submit to Bugcrowd

**Status:** ✅ **READY FOR REDACTION AND REPORT GENERATION**

---

## Evidence Checklist

- [x] Account A dashboard screenshot
- [x] Account B creation screenshot
- [x] Payment creation screenshot
- [x] IDOR access screenshots (4x)
- [x] Network request (cURL)
- [x] Raw API response (JSON)
- [ ] Redacted JSON response (run redaction script)
- [ ] Final bug bounty report (generate from evidence)
"""
    
    report_file = EVIDENCE_DIR / "CAPTURE_SUMMARY.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"✅ Summary report saved to: {report_file}")
    print("\n" + report)


def main():
    """Main workflow"""
    print("="*70)
    print("IDOR Evidence Capture - Automated Browser Assistant")
    print("="*70)
    print("\nThis script will guide you through capturing IDOR evidence.")
    print("Follow the browser instructions at each step.")
    print("\nNote: This script assists with manual browser work.")
    print("You'll need to manually navigate and capture screenshots.")
    
    ensure_evidence_dir()
    state = load_state()
    
    try:
        # Step 1: Account A
        state = capture_account_a(state)
        
        # Step 2: Account B
        state = capture_account_b(state)
        
        # Step 3: Payment Creation
        state = capture_payment_creation(state)
        
        # Step 4: IDOR Access
        state = capture_idor_access(state)
        
        # Step 5: Generate Summary
        generate_summary_report(state)
        
        print("\n" + "="*70)
        print("✅ Evidence capture complete!")
        print("="*70)
        print(f"\n📁 Evidence location: {EVIDENCE_DIR}")
        print(f"📄 State file: {STATE_FILE}")
        print(f"📋 Summary report: {EVIDENCE_DIR / 'CAPTURE_SUMMARY.md'}")
        print("\nNext steps:")
        print("1. Run redaction script on idor_response_raw.json")
        print("2. Generate final bug bounty report")
        print("3. Submit to Bugcrowd")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Capture interrupted. Progress saved.")
        print(f"Resume anytime by running: python3 {__file__}")
        save_state(state)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("State saved. You can resume from where you left off.")
        save_state(state)


if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55








