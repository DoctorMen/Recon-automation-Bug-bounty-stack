#!/usr/bin/env python3
"""
Verify VetraFi authorization and run full security assessment
"""

from LEGAL_AUTHORIZATION_SYSTEM import LegalAuthorizationShield

def verify_and_run():
    shield = LegalAuthorizationShield()
    authorized, reason, auth_data = shield.check_authorization('app.vetrafi.com')
    
    print(f"Authorized: {authorized}")
    print(f"Reason: {reason}")
    
    if authorized:
        print(f"Scope: {auth_data['scope']}")
        print(f"Ends: {auth_data['end_date']}")
        print(f"Testing types: {auth_data['testing_types_authorized']}")
        return True
    else:
        return False

if __name__ == "__main__":
    verify_and_run()
