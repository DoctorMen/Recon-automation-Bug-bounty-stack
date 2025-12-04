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
Verify Bolt Bug Findings
Tests each finding to confirm it's actually exploitable before submission
"""

import json
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

BOLT_BUGS_FILE = Path("programs/bolt/recon/output/confirmed_exploitable_bugs.json")
VERIFICATION_OUTPUT = Path("programs/bolt/recon/output/verified_bugs.json")
SUBMISSIONS_DIR = Path("programs/bolt/submissions")

def verify_auth_bypass(url: str) -> Dict[str, Any]:
    """Verify authentication bypass vulnerability"""
    result = {
        "url": url,
        "verified": False,
        "exploitable": False,
        "evidence": {}
    }
    
    try:
        # Test 1: Unauthenticated GET request
        resp = requests.get(url, timeout=10, allow_redirects=False)
        result["evidence"]["status_code"] = resp.status_code
        result["evidence"]["response_length"] = len(resp.text)
        result["evidence"]["headers"] = dict(resp.headers)
        
        # Check for indicators of successful access
        if resp.status_code == 200:
            # Check if it's not just a redirect or login page
            text_lower = resp.text.lower()
            login_indicators = ["login", "sign in", "authentication", "unauthorized", "403", "401"]
            is_login_page = any(indicator in text_lower[:500] for indicator in login_indicators)
            
            if not is_login_page and len(resp.text) > 1000:
                result["verified"] = True
                result["exploitable"] = True
                result["evidence"]["proof"] = "Unauthenticated access to protected endpoint"
            else:
                result["evidence"]["proof"] = "Returns login page or redirect"
        elif resp.status_code == 302 or resp.status_code == 301:
            result["evidence"]["redirect_location"] = resp.headers.get("Location", "Unknown")
            result["evidence"]["proof"] = "Redirects to login page"
        else:
            result["evidence"]["proof"] = f"Status code {resp.status_code} - not exploitable"
            
    except Exception as e:
        result["evidence"]["error"] = str(e)
        result["evidence"]["proof"] = f"Error during verification: {e}"
    
    return result

def verify_payment_manipulation(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Verify payment manipulation vulnerability"""
    result = {
        "url": url,
        "payload": payload,
        "verified": False,
        "exploitable": False,
        "evidence": {}
    }
    
    try:
        # Test payment manipulation
        resp = requests.post(url, json=payload, timeout=10, allow_redirects=False)
        result["evidence"]["status_code"] = resp.status_code
        result["evidence"]["response_length"] = len(resp.text)
        
        try:
            result["evidence"]["response_json"] = resp.json()
        except:
            result["evidence"]["response_text"] = resp.text[:500]
        
        # Check if payment was actually accepted
        if resp.status_code in [200, 201]:
            # Check response for successful payment indicators
            response_text = json.dumps(result["evidence"].get("response_json", {}))
            if not response_text:
                response_text = result["evidence"].get("response_text", "")
            
            # Indicators of successful payment creation
            success_indicators = ["payment", "transaction", "id", "created", "success"]
            error_indicators = ["error", "invalid", "unauthorized", "forbidden", "required"]
            
            has_success = any(ind in response_text.lower() for ind in success_indicators)
            has_error = any(ind in response_text.lower() for ind in error_indicators)
            
            if has_success and not has_error:
                result["verified"] = True
                result["exploitable"] = True
                result["evidence"]["proof"] = "Payment manipulation accepted by API"
            elif has_error:
                result["evidence"]["proof"] = "API rejected payment manipulation"
            else:
                result["evidence"]["proof"] = "Unclear response - needs manual verification"
        elif resp.status_code == 401:
            result["evidence"]["proof"] = "Authentication required - not exploitable without auth"
        elif resp.status_code == 400:
            result["evidence"]["proof"] = "Bad request - validation may be working"
        else:
            result["evidence"]["proof"] = f"Status code {resp.status_code} - needs manual review"
            
    except Exception as e:
        result["evidence"]["error"] = str(e)
        result["evidence"]["proof"] = f"Error during verification: {e}"
    
    return result

def main():
    """Main verification function"""
    print("=" * 70)
    print("BOLT BUG VERIFICATION")
    print("=" * 70)
    
    # Load findings
    if not BOLT_BUGS_FILE.exists():
        print(f"ERROR: Findings file not found: {BOLT_BUGS_FILE}")
        return
    
    with open(BOLT_BUGS_FILE, "r") as f:
        findings = json.load(f)
    
    verified_bugs = []
    verification_results = []
    
    for bug in findings.get("confirmed_bugs", []):
        bug_type = bug.get("type")
        url = bug.get("url")
        
        print(f"\n[VERIFY] Verifying: {bug_type} - {url}")
        
        if bug_type == "Authentication Bypass":
            result = verify_auth_bypass(url)
            if result["exploitable"]:
                verified_bugs.append(bug)
                print(f"  [OK] VERIFIED: Exploitable")
            else:
                print(f"  [FAIL] NOT VERIFIED: {result['evidence'].get('proof', 'Unknown')}")
        
        elif bug_type == "Payment Manipulation":
            payload = bug.get("payload", {})
            result = verify_payment_manipulation(url, payload)
            if result["exploitable"]:
                verified_bugs.append(bug)
                print(f"  [OK] VERIFIED: Exploitable")
            else:
                print(f"  [FAIL] NOT VERIFIED: {result['evidence'].get('proof', 'Unknown')}")
        
        verification_results.append({
            "bug": bug,
            "verification": result
        })
    
    # Save verification results
    verification_data = {
        "target": "bolt",
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings.get("confirmed_bugs", [])),
        "verified_exploitable": len(verified_bugs),
        "verification_results": verification_results,
        "verified_bugs": verified_bugs
    }
    
    VERIFICATION_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(VERIFICATION_OUTPUT, "w") as f:
        json.dump(verification_data, f, indent=2)
    
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total Findings: {len(findings.get('confirmed_bugs', []))}")
    print(f"Verified Exploitable: {len(verified_bugs)}")
    print(f"Results saved to: {VERIFICATION_OUTPUT}")
    
    if verified_bugs:
        print("\n[OK] The following bugs are verified exploitable:")
        for bug in verified_bugs:
            print(f"  - {bug['type']}: {bug['url']}")
    else:
        print("\n[WARN] No bugs verified as exploitable. Manual verification required.")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
