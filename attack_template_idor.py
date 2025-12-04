#!/usr/bin/env python3
"""
IDOR/BOLA Attack Template Generator
Generates IDOR test cases from recon output.

ETHICAL COMPLIANCE:
- Only generates test cases for authorized targets
- All payloads are non-destructive
- No actual exploitation, only test case generation
"""

import json
import sys
from pathlib import Path

# Import policy compliance guard
try:
    from POLICY_COMPLIANCE_GUARD import COMPLIANCE_GUARD, check_target_compliance, check_action_compliance, validate_payload_safety
    COMPLIANCE_ENABLED = True
except ImportError:
    print("[!] WARNING: POLICY_COMPLIANCE_GUARD not found - running without compliance checks")
    COMPLIANCE_ENABLED = False

def load_recon(path):
    """Load recon output from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Recon file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] JSON decode error in {path}: {e}")
        sys.exit(1)

def extract_idor_targets(recon):
    """
    Identify likely IDOR/BOLA endpoints from recon output.
    Look for:
    - Endpoints with IDs in path (e.g., /api/users/{id})
    - Query parameters that look like IDs
    - Authenticated resources with roles/organizations
    """
    targets = []
    for asset in recon.get("assets", []):
        host = asset.get("host")
        for endpoint in asset.get("endpoints", []):
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            auth_required = endpoint.get("auth_required", False)
            # Simple heuristic: path contains 'id' or numeric param
            if "{id}" in path or "id=" in path or "/\\d+" in path:
                targets.append({
                    "host": host,
                    "method": method,
                    "path": path,
                    "auth_required": auth_required,
                    "notes": endpoint.get("notes", "")
                })
            # Also look for org/team/project patterns
            if any(k in path.lower() for k in ["org", "team", "project", "account"]):
                targets.append({
                    "host": host,
                    "method": method,
                    "path": path,
                    "auth_required": auth_required,
                    "notes": endpoint.get("notes", "")
                })
    return targets

def generate_idor_tests(targets):
    """
    For each target, generate concrete test cases.
    Include:
    - Increment/decrement IDs
    - Switch to another user's known ID
    - Try with different auth tokens (if available)
    """
    tests = []
    for t in targets:
        # Check compliance before generating tests
        if COMPLIANCE_ENABLED:
            allowed, reason = check_target_compliance(t["host"])
            if not allowed:
                print(f"[!] BLOCKED: IDOR tests for {t['host']} - {reason}")
                continue
        
        base_url = f"https://{t['host']}{t['path']}"
        # Assume {id} placeholder; if not, we'll add generic ID param tests
        if "{id}" in t["path"]:
            # Generate a few ID variations
            for delta in [-5, -1, 0, 1, 5, 9999]:
                test_id = f"REPLACE_WITH_KNOWN_ID_{delta}" if delta == 0 else f"REPLACE_WITH_KNOWN_ID_{delta}"
                test_path = t["path"].replace("{id}", test_id)
                
                # Validate payload safety
                payload = f"ID={test_id}"
                if COMPLIANCE_ENABLED:
                    payload_safe, payload_reason = validate_payload_safety(payload)
                    if not payload_safe:
                        print(f"[!] BLOCKED: Unsafe IDOR payload for {t['host']} - {payload_reason}")
                        continue
                
                tests.append({
                    "host": t["host"],
                    "method": t["method"],
                    "path": test_path,
                    "auth_required": t["auth_required"],
                    "description": f"IDOR test: {delta} offset from known ID",
                    "what_to_watch": [
                        "Access to another user's data",
                        "Unexpected role/permissions",
                        "Error messages revealing internal IDs"
                    ]
                })
        else:
            # Generic parameter tampering
            tests.append({
                "host": t["host"],
                "method": t["method"],
                "path": t["path"],
                "auth_required": t["auth_required"],
                "description": "Generic ID parameter tampering (add ?id=...)",
                "what_to_watch": [
                    "Data leakage via ID parameter",
                    "Inconsistent access control",
                    "Error messages exposing IDs"
                ]
            })
    return tests

def save_tests(tests, path):
    """Save generated tests to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tests, f, indent=2)
    print(f"[+] Saved IDOR test plan to: {path}")

def print_summary(tests):
    """Print a quick summary of generated tests."""
    print("\n--- IDOR Test Plan Summary ---")
    print(f"Generated {len(tests)} test cases.")
    for i, t in enumerate(tests[:10], 1):
        print(f"{i:2d}. {t['method']} {t['host']}{t['path']}")
        print(f"    Auth required: {t['auth_required']}")
        print(f"    Description: {t['description']}")
        print()
    if len(tests) > 10:
        print(f"... and {len(tests) - 10} more tests. See idor_tests.json for full list.")

def main():
    recon_file = Path("recon.json")
    tests_file = Path("idor_tests.json")
    if not recon_file.is_file():
        print("[!] Creating stub recon.json – please edit with real recon data.")
        stub = {
            "assets": [
                {
                    "host": "app.example.com",
                    "type": "web_app",
                    "auth_required": True,
                    "endpoints": [
                        {"method": "GET", "path": "/api/v1/users/{id}", "auth_required": True, "notes": "User profile"},
                        {"method": "GET", "path": "/api/v1/organizations/{org_id}/members", "auth_required": True, "notes": "Org members"},
                        {"method": "PATCH", "path": "/api/v1/projects/{project_id}", "auth_required": True, "notes": "Update project"},
                        {"method": "GET", "path": "/api/v1/teams", "auth_required": True, "notes": "List teams (no ID in path)"}
                    ]
                }
            ]
        }
        with open(recon_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub created at: {recon_file}")
        print("[!] Edit recon.json with real recon data and re-run.")
        return

    recon = load_recon(recon_file)
    targets = extract_idor_targets(recon)
    tests = generate_idor_tests(targets)
    save_tests(tests, tests_file)
    print_summary(tests)

if __name__ == "__main__":
    main()
