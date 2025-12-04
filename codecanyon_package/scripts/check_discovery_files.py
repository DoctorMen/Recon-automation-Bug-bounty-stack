#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Quick diagnostic - Check what discovery files exist
"""

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
ROI_OUTPUT_DIR = OUTPUT_DIR / "immediate_roi"

print("=" * 60)
print("Discovery Files Diagnostic")
print("=" * 60)
print()

# Check main output directory
print(f"[*] Checking: {OUTPUT_DIR}")
if OUTPUT_DIR.exists():
    files = list(OUTPUT_DIR.glob("*.json")) + list(OUTPUT_DIR.glob("*.txt"))
    if files:
        for f in files[:10]:
            size = f.stat().st_size
            print(f"  ✅ {f.name} ({size:,} bytes)")
    else:
        print("  ❌ No JSON/TXT files found")
else:
    print("  ❌ Directory doesn't exist")

print()

# Check immediate_roi directory
print(f"[*] Checking: {ROI_OUTPUT_DIR}")
if ROI_OUTPUT_DIR.exists():
    files = list(ROI_OUTPUT_DIR.glob("*.json")) + list(ROI_OUTPUT_DIR.glob("*.txt"))
    if files:
        for f in files[:10]:
            size = f.stat().st_size
            print(f"  ✅ {f.name} ({size:,} bytes)")
    else:
        print("  ❌ No JSON/TXT files found")
else:
    print("  ❌ Directory doesn't exist")

print()

# Check subdirectories
print(f"[*] Checking subdirectories in: {OUTPUT_DIR}")
if OUTPUT_DIR.exists():
    subdirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir()]
    for subdir in subdirs[:10]:
        files = list(subdir.glob("*.json")) + list(subdir.glob("discovered_endpoints.json"))
        if files:
            print(f"  ✅ {subdir.name}/")
            for f in files[:3]:
                print(f"     - {f.name}")

print()
print("=" * 60)
print("Recommendation:")
print("=" * 60)

if not OUTPUT_DIR.exists() or not any(OUTPUT_DIR.glob("*.json")):
    print("❌ No discovery files found!")
    print("")
    print("Run discovery scan first:")
    print("  python3 scripts/immediate_roi_hunter.py")
else:
    print("✅ Found discovery files!")
    print("")
    print("Now run priority selector:")
    print("  python3 scripts/prioritize_endpoints.py")






