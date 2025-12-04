#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Check Apple Endpoint Test Results
Looks for any test results, logs, or evidence of Apple endpoint testing
"""

import json
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
ROI_OUTPUT_DIR = OUTPUT_DIR / "immediate_roi"

def check_apple_test_results():
    """Check for Apple endpoint test results"""
    
    print("=" * 60)
    print("Checking for Apple Endpoint Test Results")
    print("=" * 60)
    print()
    
    # Check priority endpoints
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints_by_program.json"
    
    if priority_file.exists():
        with open(priority_file, 'r') as f:
            data = json.load(f)
        
        apple_endpoints = data.get("apple", [])
        
        if apple_endpoints:
            print(f"✅ Found {len(apple_endpoints)} Apple endpoints in priority list")
            print()
            print("Top Apple Endpoints:")
            for idx, ep in enumerate(apple_endpoints[:5], 1):
                url = ep.get("url", "")
                score = ep.get("score", 0)
                reasons = ep.get("reasons", [])
                print(f"{idx}. Score: {score}")
                print(f"   URL: {url}")
                print(f"   Reasons: {', '.join(reasons)}")
                print()
        else:
            print("❌ No Apple endpoints found")
    
    # Check for test results files
    print()
    print("=" * 60)
    print("Checking for Test Results")
    print("=" * 60)
    print()
    
    result_files = [
        ROI_OUTPUT_DIR / "apple_test_results.json",
        OUTPUT_DIR / "apple_test_results.json",
        ROI_OUTPUT_DIR / "test_results.json",
    ]
    
    found_results = False
    for result_file in result_files:
        if result_file.exists():
            print(f"✅ Found: {result_file}")
            try:
                with open(result_file, 'r') as f:
                    results = json.load(f)
                    print(f"   Results: {len(results) if isinstance(results, list) else 'dict'}")
                    found_results = True
            except:
                print("   (Could not parse)")
    
    if not found_results:
        print("⚠️  No test results files found")
        print()
        print("Did you:")
        print("1. Test manually in browser?")
        print("2. Run a script?")
        print("3. Use curl/Postman?")
        print()
        print("If you tested manually, please share:")
        print("- What endpoints you tested")
        print("- What responses you got")
        print("- Any errors or interesting findings")
    
    # Check log files
    print()
    print("=" * 60)
    print("Checking Log Files")
    print("=" * 60)
    print()
    
    log_file = ROI_OUTPUT_DIR / "roi_hunter.log"
    if log_file.exists():
        print(f"✅ Found log file: {log_file}")
        print("   Checking for Apple-related entries...")
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                apple_lines = [l for l in lines if 'apple' in l.lower()][-10:]
                if apple_lines:
                    print("   Recent Apple-related entries:")
                    for line in apple_lines:
                        print(f"   {line.strip()}")
                else:
                    print("   No Apple-related entries found")
        except:
            print("   (Could not read)")
    
    print()
    print("=" * 60)
    print("How to Share Test Results")
    print("=" * 60)
    print()
    print("If you tested Apple endpoints, please share:")
    print()
    print("1. Which endpoints you tested:")
    print("   Example: http://2b4a6b31ca2273bb.apple.com/api/checkout")
    print()
    print("2. What you tested:")
    print("   - IDOR?")
    print("   - Auth bypass?")
    print("   - Other?")
    print()
    print("3. Results:")
    print("   - HTTP status codes")
    print("   - Error messages")
    print("   - Any interesting responses")
    print()
    print("4. Where you saved results:")
    print("   - File path")
    print("   - Screenshots")
    print("   - Notes")
    print()
    print("=" * 60)

if __name__ == "__main__":
    check_apple_test_results()






