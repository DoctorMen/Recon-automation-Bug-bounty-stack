#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GHOST Security Services Pricing
Copyright (c) 2025 Khallid Hakeem Nurse - All Rights Reserved
"""
import sys
import io

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

SERVICES = {
    "basic_scan": {
        "price": 199,
        "delivery": "2 hours",
        "features": [
            "Full website vulnerability scan",
            "50+ security checks",
            "PDF report with findings",
            "30-minute consultation"
        ]
    },
    "premium_scan": {
        "price": 499,
        "delivery": "4 hours",
        "features": [
            "Advanced penetration test",
            "100+ security checks",
            "Live demo of findings",
            "7-day support"
        ]
    },
    "enterprise": {
        "price": 1999,
        "delivery": "24-48 hours",
        "features": [
            "Full security audit",
            "200+ security checks",
            "Executive summary + technical report",
            "30-day support",
            "Remediation assistance"
        ]
    }
}

def list_services():
    """Display available services in a nice format"""
    print("\n[GHOST SECURITY SERVICES]")
    print("=" * 50)
    for service, details in SERVICES.items():
        print(f"\n[+] {service.upper()} (${details['price']}) - Ready in {details['delivery']}")
        for feature in details['features']:
            print(f"   - {feature}")
    print("\n[!] Tip: Use these in your Upwork proposals!")

def get_service(service_name):
    """Get service details by name"""
    return SERVICES.get(service_name.lower(), None)

if __name__ == "__main__":
    list_services()
