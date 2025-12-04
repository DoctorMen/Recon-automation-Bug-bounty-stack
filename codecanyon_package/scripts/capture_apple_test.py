#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Capture Apple Test Results
Use this to record what you tested and what you found
"""

import json
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"
RESULTS_FILE = ROI_OUTPUT_DIR / "apple_manual_test_results.json"

def capture_result():
    """Interactively capture test results"""
    
    print("=" * 60)
    print("Capture Apple Endpoint Test Results")
    print("=" * 60)
    print()
    
    # Load existing results
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, 'r') as f:
            results = json.load(f)
    else:
        results = []
    
    # Get test details
    endpoint = input("Endpoint URL: ").strip()
    if not endpoint:
        print("❌ No endpoint provided")
        return
    
    test_type = input("Test type (IDOR/auth bypass/other): ").strip() or "other"
    
    print("\nResponse details:")
    status_code = input("Status code: ").strip()
    
    response_preview = input("Response preview (first 200 chars, or press Enter to skip): ").strip()
    
    finding = input("Finding (vulnerable/safe/other): ").strip() or "other"
    
    notes = input("Additional notes (optional): ").strip()
    
    # Create result entry
    result = {
        "timestamp": datetime.now().isoformat(),
        "endpoint": endpoint,
        "test_type": test_type,
        "status_code": status_code,
        "response_preview": response_preview,
        "finding": finding,
        "notes": notes
    }
    
    results.append(result)
    
    # Save
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    print()
    print(f"✅ Result saved!")
    print(f"   File: {RESULTS_FILE}")
    print()
    
    # Show summary
    print("=" * 60)
    print("Test Summary")
    print("=" * 60)
    print()
    
    vulnerable = sum(1 for r in results if r.get("finding") == "vulnerable")
    safe = sum(1 for r in results if r.get("finding") == "safe")
    
    print(f"Total tests: {len(results)}")
    print(f"Vulnerable: {vulnerable}")
    print(f"Safe: {safe}")
    print()
    
    if vulnerable > 0:
        print("⚠️  VULNERABILITIES FOUND!")
        print("   Review these endpoints:")
        for r in results:
            if r.get("finding") == "vulnerable":
                print(f"   - {r['endpoint']}")
        print()

if __name__ == "__main__":
    capture_result()






