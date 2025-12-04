#!/usr/bin/env python3
"""
IDOR Workflow Helper
Generates test commands to verify IDORs between two users.
"""

import argparse
import sys

def generate_commands(endpoint, method, cookies_a, cookies_b, id_a, id_b):
    """Generates curl commands to cross-test IDs."""
    
    print("\n[+] IDOR Test Plan Generated")
    print("============================")
    print(f"Target: {endpoint}")
    print(f"Method: {method}")
    print("Goal: Access User A's Resource (ID: {id_a}) using User B's Session")
    print("----------------------------")
    
    # Replace placeholder in URL
    target_url = endpoint.replace("{id}", id_a)
    
    cmd = f"curl -X {method} '{target_url}' \\\n"
    cmd += f"  -H 'Cookie: {cookies_b}' \\\n"
    cmd += "  -v"
    
    print("\n[1] Run this command (Attacker Request):")
    print(cmd)
    
    print("\n[2] Expected Result:")
    print("    - 401/403 Forbidden: Secure")
    print("    - 200 OK + Data: VULNERABLE (IDOR)")
    print("============================")

if __name__ == "__main__":
    print("--- IDOR Workflow Helper ---")
    if len(sys.argv) < 2:
        print("Usage: Enter details interactively when prompted.")
        endpoint = input("Enter Endpoint URL (use {id} as placeholder): ")
        method = input("HTTP Method (GET/POST/PUT): ").upper()
        cookies_b = input("Enter User B (Attacker) Cookies/Auth Header: ")
        id_a = input("Enter User A (Victim) Resource ID: ")
        
        generate_commands(endpoint, method, "COOKIE_A_PLACEHOLDER", cookies_b, id_a, "ID_B_PLACEHOLDER")
    else:
        print("Please run without arguments for interactive mode.")
