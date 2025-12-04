#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Training Material Verification Tool
Validates that all AI training files are complete and properly structured
"""

import json
import os
from pathlib import Path

TRAINING_DIR = Path(__file__).parent
REQUIRED_FILES = [
    "README.md",
    "training-index.md",
    "openapi-spec.yaml",
    "api-schemas.json",
    "agent-training-manifest.json",
    "command-reference.md",
    "intent-patterns.json",
    "validation-rules.json",
    "usage-examples.md",
    "integration-patterns.md",
    "ai-assistant-guide.md",
    "DEPLOYMENT_SUMMARY.md",
    "advanced-ai-capabilities.json",
    "context-awareness-engine.json",
    "performance-optimization-ml.json",
    "real-time-collaboration.json",
    "bleeding-edge-features.json",
    "POWER_LEVEL_UPGRADE.md"
]

def verify_file_exists(filename):
    """Check if required file exists"""
    filepath = TRAINING_DIR / filename
    if not filepath.exists():
        print(f"[X] Missing: {filename}")
        return False
    print(f"[OK] Found: {filename}")
    return True

def verify_json_valid(filename):
    """Verify JSON file is valid"""
    try:
        filepath = TRAINING_DIR / filename
        with open(filepath, 'r') as f:
            json.load(f)
        print(f"[OK] Valid JSON: {filename}")
        return True
    except json.JSONDecodeError as e:
        print(f"[X] Invalid JSON in {filename}: {e}")
        return False

def verify_yaml_valid(filename):
    """Verify YAML file exists and has content"""
    try:
        filepath = TRAINING_DIR / filename
        with open(filepath, 'r') as f:
            content = f.read()
        if len(content) > 100:  # Basic check that file has content
            print(f"[OK] YAML file has content: {filename}")
            return True
        else:
            print(f"[X] YAML file too small: {filename}")
            return False
    except Exception as e:
        print(f"[X] Error reading {filename}: {e}")
        return False

def verify_manifest_structure():
    """Verify training manifest has required keys"""
    required_keys = [
        "manifest_version",
        "repository",
        "training_files",
        "core_concepts",
        "entry_points",
        "environment_variables"
    ]
    
    filepath = TRAINING_DIR / "agent-training-manifest.json"
    with open(filepath, 'r') as f:
        manifest = json.load(f)
    
    for key in required_keys:
        if key not in manifest:
            print(f"[X] Missing key in manifest: {key}")
            return False
    
    print("[OK] Manifest structure valid")
    return True

def verify_intent_patterns():
    """Verify intent patterns are properly structured"""
    filepath = TRAINING_DIR / "intent-patterns.json"
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    if "intent_patterns" not in data:
        print("[X] No intent_patterns key found")
        return False
    
    patterns = data["intent_patterns"]
    if len(patterns) < 10:
        print(f"[!] Only {len(patterns)} intent patterns defined (expected 10+)")
    else:
        print(f"[OK] Found {len(patterns)} intent patterns")
    
    return True

def verify_validation_rules():
    """Verify validation rules are defined"""
    filepath = TRAINING_DIR / "validation-rules.json"
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    required_sections = ["command_validation", "input_validation", "safety_checks"]
    for section in required_sections:
        if section not in data.get("validation_rules", {}):
            print(f"[X] Missing validation section: {section}")
            return False
    
    print("[OK] Validation rules complete")
    return True

def main():
    print("=" * 60)
    print("AI Training Material Verification")
    print("=" * 60)
    print()
    
    all_passed = True
    
    # Check file existence
    print("Checking required files...")
    for filename in REQUIRED_FILES:
        if not verify_file_exists(filename):
            all_passed = False
    print()
    
    # Verify JSON files
    print("Validating JSON files...")
    json_files = ["api-schemas.json", "agent-training-manifest.json", 
                  "intent-patterns.json", "validation-rules.json"]
    for filename in json_files:
        if not verify_json_valid(filename):
            all_passed = False
    print()
    
    # Verify YAML files
    print("Validating YAML files...")
    if not verify_yaml_valid("openapi-spec.yaml"):
        all_passed = False
    print()
    
    # Verify structure
    print("Verifying structure...")
    if not verify_manifest_structure():
        all_passed = False
    if not verify_intent_patterns():
        all_passed = False
    if not verify_validation_rules():
        all_passed = False
    print()
    
    # Final report
    print("=" * 60)
    if all_passed:
        print("[SUCCESS] ALL CHECKS PASSED")
        print("Training materials are complete and valid")
    else:
        print("[FAILED] SOME CHECKS FAILED")
        print("Please review errors above")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    exit(main())
