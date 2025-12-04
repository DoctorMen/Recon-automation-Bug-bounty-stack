#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Apple Endpoint Test Results Capture
Helps document what you tested and what you found
"""

import json
import sys
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

def capture_test_results():
    """Capture Apple endpoint test results"""
    
    print("=" * 60)
    print("Apple Endpoint Test Results Capture")
    print("=" * 60)
    print()
    
    # Load Apple endpoints
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints_by_program.json"
    
    if not priority_file.exists():
        print("❌ Priority endpoints file not found")
        print("Run: python3 scripts/prioritize_endpoints.py")
        return
    
    with open(priority_file, 'r') as f:
        data = json.load(f)
    
    apple_endpoints = data.get("apple", [])
    
    if not apple_endpoints:
        print("❌ No Apple endpoints found")
        return
    
    print(f"Found {len(apple_endpoints)} Apple endpoints")
    print()
    print("Please share what you tested:")
    print()
    
    # Show top endpoints
    print("Top Apple Endpoints Available:")
    for idx, ep in enumerate(apple_endpoints[:5], 1):
        print(f"{idx}. {ep['url']}")
    print()
    
    # Create results template
    results = {
        "timestamp": datetime.now().isoformat(),
        "tested_endpoints": [],
        "findings": []
    }
    
    print("=" * 60)
    print("Quick Test Results Form")
    print("=" * 60)
    print()
    
    # Ask what was tested
    print("Which endpoint did you test? (Enter URL or number)")
    print("Or press Enter to skip...")
    
    # In interactive mode, we'd read input, but for now create template
    print()
    print("Example format:")
    print("""
{
  "endpoint": "http://2b4a6b31ca2273bb.apple.com/api/checkout",
  "test_type": "IDOR / Auth Bypass / etc",
  "method": "GET / POST",
  "status_code": 200 / 403 / 404 / etc,
  "response": "Brief description",
  "vulnerability_found": true / false,
  "notes": "Any additional notes"
}
""")
    
    # Save template
    template_file = ROI_OUTPUT_DIR / "apple_test_results_template.json"
    with open(template_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[*] Created template: {template_file}")
    print()
    print("=" * 60)
    print("How to Share Your Results")
    print("=" * 60)
    print()
    print("Option 1: Tell me directly")
    print("  - Which endpoint you tested")
    print("  - What test you did (IDOR, auth bypass, etc.)")
    print("  - What response you got (status code, error, etc.)")
    print("  - Any findings or vulnerabilities")
    print()
    print("Option 2: Create results file")
    print("  - Edit: output/immediate_roi/apple_test_results.json")
    print("  - Add your test results")
    print()
    print("Option 3: Share terminal output")
    print("  - Copy/paste curl commands you ran")
    print("  - Share responses you got")
    print()
    print("=" * 60)

if __name__ == "__main__":
    capture_test_results()






