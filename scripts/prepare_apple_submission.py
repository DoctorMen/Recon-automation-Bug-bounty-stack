#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Prepare Apple CDN Submission
Create submission-ready report with disclosure
"""

import json
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"
OUTPUT_DIR = REPO_ROOT / "output" / "apple_submission"

def prepare_submission():
    """Prepare Apple CDN endpoint submission"""
    
    print("=" * 60)
    print("APPLE CDN ENDPOINT SUBMISSION PREPARATION")
    print("=" * 60)
    print()
    
    # Load test results
    results_file = ROI_OUTPUT_DIR / "apple_manual_test_results.json"
    
    if not results_file.exists():
        print("❌ Test results not found")
        print("Run: python3 scripts/test_apple_auto.py")
        return
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    if not results:
        print("❌ No test results found")
        return
    
    # Get first result
    test_result = results[0]
    endpoint = test_result.get("endpoint", "")
    status_code = test_result.get("status_code", "")
    server = test_result.get("headers", {}).get("Server", "")
    
    print(f"Endpoint: {endpoint}")
    print(f"Status Code: {status_code}")
    print(f"Server: {server}")
    print()
    
    # Create submission directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Prepare submission content
    submission = {
        "title": "Potential Security Issue in Apple CDN Endpoint - Scope Verification Requested",
        "endpoint": endpoint,
        "test_results": results,
        "submission_text": prepare_submission_text(endpoint, test_result),
        "timestamp": datetime.now().isoformat()
    }
    
    # Save submission
    submission_file = OUTPUT_DIR / "submission_report.txt"
    with open(submission_file, 'w') as f:
        f.write(submission["submission_text"])
    
    json_file = OUTPUT_DIR / "submission_data.json"
    with open(json_file, 'w') as f:
        json.dump(submission, f, indent=2)
    
    print("=" * 60)
    print("SUBMISSION PREPARED")
    print("=" * 60)
    print()
    print(f"📄 Submission text saved to: {submission_file}")
    print(f"📄 JSON data saved to: {json_file}")
    print()
    
    print("=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print()
    print("1. Go to: https://security.apple.com/bounty/")
    print("2. Sign in with your Apple ID")
    print("3. Click 'Submit a Report'")
    print("4. Copy and paste the submission text below:")
    print()
    print("-" * 60)
    print(submission["submission_text"])
    print("-" * 60)
    print()
    
    print("=" * 60)
    print("IMPORTANT REMINDERS")
    print("=" * 60)
    print()
    print("✅ Include this disclosure:")
    print("   'This endpoint appears to be a CDN subdomain.'")
    print("   'Please verify if it's in scope for the program.'")
    print()
    print("✅ Be honest about findings")
    print("✅ Include test results")
    print("✅ No legal risk - you're being transparent")
    print()
    
    return submission_file

def prepare_submission_text(endpoint: str, test_result: dict) -> str:
    """Prepare submission text"""
    
    status_code = test_result.get("status_code", "")
    server = test_result.get("headers", {}).get("Server", "")
    response_preview = test_result.get("response_preview", "")
    
    text = f"""Title: Potential Security Issue in Apple CDN Endpoint - Scope Verification Requested

IMPORTANT DISCLOSURE:
This endpoint appears to be a CDN subdomain (hash prefix: 2b4a6b31ca2273bb).
Please verify if CDN endpoints are within the scope of the Apple Security Bounty program.
If this is out of scope, please let me know and I will not pursue further testing.

DETAILED DESCRIPTION:

Endpoint: {endpoint}

During automated security testing, I discovered this endpoint that responds with:
- HTTP Status: {status_code}
- Server Header: {server}

BEHAVIOR OBSERVED:
The endpoint responds with a 301 redirect to HTTPS. The hash prefix in the subdomain 
suggests this is a Content Delivery Network (CDN) endpoint, which may be out of scope 
for the bug bounty program.

EXPECTED BEHAVIOR:
If this is an Apple-owned web server, proper authentication and authorization should 
be in place. However, since this appears to be a CDN endpoint, I wanted to verify 
scope before conducting further testing.

STEPS TO REPRODUCE:
1. Send GET request to: {endpoint}
2. Observe response headers and status code
3. Follow redirect if applicable

PROOF OF CONCEPT:
HTTP Request:
GET {endpoint} HTTP/1.1
Host: 2b4a6b31ca2273bb.apple.com

HTTP Response:
Status: {status_code}
Server: {server}

Response Preview:
{response_preview[:200] if response_preview else "N/A"}

IMPACT ASSESSMENT:
Since this appears to be a CDN endpoint, the security impact may be limited.
However, if this endpoint is in scope and contains vulnerabilities, it could 
potentially affect users accessing Apple services through the CDN.

SCOPE VERIFICATION REQUEST:
Please confirm:
1. Is this CDN endpoint in scope?
2. Should I conduct further security testing?
3. Are there specific testing guidelines for CDN endpoints?

Thank you for your time and consideration.

---
Researcher Information:
- Submitted through official Apple Security Bounty portal
- Following responsible disclosure practices
- Willing to provide additional information if needed
"""
    
    return text

if __name__ == "__main__":
    prepare_submission()








