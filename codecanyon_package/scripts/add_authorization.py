#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
📝 AUTHORIZATION MANAGEMENT SYSTEM
Add, update, and manage client authorizations

LEGAL REQUIREMENT: All security testing requires written authorization
This tool helps you document and track authorizations properly
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

class AuthorizationManager:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.safety_db = self.project_root / "data" / "safety"
        self.safety_db.mkdir(parents=True, exist_ok=True)
        self.auth_db = self.safety_db / "authorizations.json"
        
        if not self.auth_db.exists():
            self._init_db()
    
    def _init_db(self):
        """Initialize authorization database"""
        initial_data = {
            "authorizations": [],
            "templates": {}
        }
        with open(self.auth_db, 'w') as f:
            json.dump(initial_data, f, indent=2)
    
    def add_authorization(self,
                         client_name: str,
                         company: str,
                         contact_email: str,
                         domains: List[str],
                         ips: List[str],
                         activities: List[str],
                         testing_days: int = 30,
                         emergency_contact: str = "") -> Dict:
        """
        Add a new client authorization
        
        Args:
            client_name: Client's full name
            company: Company name
            contact_email: Client's email
            domains: List of authorized domains
            ips: List of authorized IP addresses
            activities: List of authorized activities
            testing_days: Number of days authorization is valid (default 30)
            emergency_contact: Emergency contact info
        """
        
        # Load existing authorizations
        with open(self.auth_db, 'r') as f:
            data = json.load(f)
        
        # Create authorization record
        now = datetime.now()
        end_date = now + timedelta(days=testing_days)
        
        # Generate hash for this authorization
        auth_string = f"{client_name}{company}{','.join(domains)}{now.isoformat()}"
        auth_hash = hashlib.sha256(auth_string.encode()).hexdigest()[:16]
        
        authorization = {
            "client_name": client_name,
            "company": company,
            "contact_email": contact_email,
            "contact_phone": "",
            "authorized_domains": domains,
            "authorized_ips": ips,
            "testing_period_start": now.isoformat(),
            "testing_period_end": end_date.isoformat(),
            "authorized_activities": activities,
            "prohibited_activities": [
                "dos_attacks",
                "ddos_attacks",
                "data_exfiltration",
                "physical_destruction",
                "unauthorized_social_engineering"
            ],
            "emergency_contact": emergency_contact or contact_email,
            "signed_date": now.isoformat(),
            "authorization_hash": auth_hash,
            "status": "active",
            "created_by": "AuthorizationManager",
            "notes": ""
        }
        
        data["authorizations"].append(authorization)
        
        # Save updated database
        with open(self.auth_db, 'w') as f:
            json.dump(data, f, indent=2)
        
        print("✅ Authorization added successfully!")
        print(f"\nAuthorization Hash: {auth_hash}")
        print(f"Client: {client_name} ({company})")
        print(f"Valid from: {now.strftime('%Y-%m-%d')}")
        print(f"Valid until: {end_date.strftime('%Y-%m-%d')}")
        print(f"Authorized domains: {', '.join(domains)}")
        print(f"Authorized activities: {', '.join(activities)}")
        
        return authorization
    
    def list_authorizations(self):
        """List all current authorizations"""
        with open(self.auth_db, 'r') as f:
            data = json.load(f)
        
        authorizations = data.get("authorizations", [])
        
        if not authorizations:
            print("No authorizations found.")
            print("\nAdd authorization with:")
            print("python3 scripts/add_authorization.py --client 'Client Name' --domain example.com")
            return
        
        print(f"\n{'='*80}")
        print(f"📋 ACTIVE AUTHORIZATIONS ({len(authorizations)} total)")
        print(f"{'='*80}\n")
        
        for i, auth in enumerate(authorizations, 1):
            status = self._check_authorization_status(auth)
            status_symbol = "✅" if status == "active" else "⚠️" if status == "expiring" else "❌"
            
            print(f"{status_symbol} Authorization #{i}")
            print(f"   Client: {auth['client_name']} ({auth['company']})")
            print(f"   Hash: {auth['authorization_hash']}")
            print(f"   Valid until: {auth['testing_period_end'][:10]}")
            print(f"   Domains: {', '.join(auth['authorized_domains'])}")
            print(f"   Status: {status.upper()}")
            print()
    
    def _check_authorization_status(self, auth: Dict) -> str:
        """Check if authorization is active, expiring, or expired"""
        try:
            end_date = datetime.fromisoformat(auth['testing_period_end'])
            now = datetime.now()
            days_remaining = (end_date - now).days
            
            if days_remaining < 0:
                return "expired"
            elif days_remaining < 7:
                return "expiring"
            else:
                return "active"
        except:
            return "error"
    
    def remove_authorization(self, auth_hash: str):
        """Remove an authorization by hash"""
        with open(self.auth_db, 'r') as f:
            data = json.load(f)
        
        original_count = len(data["authorizations"])
        data["authorizations"] = [
            auth for auth in data["authorizations"]
            if auth.get("authorization_hash") != auth_hash
        ]
        
        if len(data["authorizations"]) < original_count:
            with open(self.auth_db, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"✅ Authorization {auth_hash} removed")
        else:
            print(f"❌ Authorization {auth_hash} not found")
    
    def generate_authorization_template(self, client_name: str, output_file: Optional[str] = None):
        """Generate a client authorization template document"""
        template = f"""
SECURITY TESTING AUTHORIZATION AGREEMENT

Date: {datetime.now().strftime('%B %d, %Y')}

I, [CLIENT NAME], hereby authorize [YOUR NAME/COMPANY] to perform 
security testing on the following assets:

CLIENT INFORMATION:
Name: {client_name}
Company: [COMPANY NAME]
Email: [EMAIL]
Phone: [PHONE]

AUTHORIZED SCOPE:
Domain(s): [LIST DOMAINS]
IP Address(es): [LIST IPs]
Application(s): [LIST APPLICATIONS]
Testing Period: From [START DATE] To [END DATE]

AUTHORIZED ACTIVITIES:
☐ Reconnaissance (subdomain enumeration, asset discovery)
☐ Vulnerability Scanning (automated security checks)
☐ Penetration Testing (exploitability verification)
☐ Web Application Testing
☐ Network Infrastructure Testing
☐ API Security Testing
☐ Other: _____________________________________

PROHIBITED ACTIVITIES:
☐ Denial of Service (DoS/DDoS) attacks
☐ Data exfiltration or copying
☐ Physical destruction or modification
☐ Social engineering of employees
☐ Testing outside specified scope
☐ Other: _____________________________________

RULES OF ENGAGEMENT:
Testing hours: [SPECIFY HOURS]
Emergency contact: [NAME AND PHONE]
Notification protocol: [DESCRIBE PROCESS]
Reporting timeline: [SPECIFY DEADLINE]

DATA PROTECTION:
All findings will be:
☐ Encrypted during transmission
☐ Stored securely
☐ Shared only with authorized personnel
☐ Deleted after [RETENTION PERIOD]

LEGAL ACKNOWLEDGMENT:
The client acknowledges that security testing may:
- Temporarily impact system performance
- Reveal sensitive security vulnerabilities
- Require coordination with IT staff
- Need to be paused if issues arise

SIGNATURES:
Client Signature: ______________________________
Printed Name: _________________________________
Date: __________________________________________

Tester Signature: ______________________________
Printed Name: _________________________________
Date: __________________________________________

AUTHORIZATION HASH: [WILL BE GENERATED UPON ENTRY INTO SYSTEM]
"""
        
        if output_file:
            output_path = Path(output_file)
            output_path.write_text(template)
            print(f"✅ Authorization template saved to: {output_file}")
        else:
            print(template)
        
        return template


def main():
    parser = argparse.ArgumentParser(description="Manage client authorizations")
    parser.add_argument("--client", help="Client name")
    parser.add_argument("--company", help="Company name", default="")
    parser.add_argument("--email", help="Contact email", default="")
    parser.add_argument("--domain", help="Authorized domain (can be used multiple times)", action="append")
    parser.add_argument("--ip", help="Authorized IP (can be used multiple times)", action="append")
    parser.add_argument("--activity", help="Authorized activity (can be used multiple times)", action="append")
    parser.add_argument("--days", type=int, default=30, help="Days authorization is valid (default: 30)")
    parser.add_argument("--list", action="store_true", help="List all authorizations")
    parser.add_argument("--remove", help="Remove authorization by hash")
    parser.add_argument("--template", help="Generate authorization template for client")
    parser.add_argument("--quick", action="store_true", help="Quick add with minimal info")
    
    args = parser.parse_args()
    
    manager = AuthorizationManager()
    
    if args.list:
        manager.list_authorizations()
        return
    
    if args.remove:
        manager.remove_authorization(args.remove)
        return
    
    if args.template:
        manager.generate_authorization_template(args.template, f"{args.template}_authorization.txt")
        return
    
    if args.client and args.domain:
        # Default activities if none specified
        activities = args.activity or [
            "reconnaissance",
            "vulnerability_scan",
            "exploit_verification",
            "web_application_testing"
        ]
        
        domains = args.domain
        ips = args.ip or []
        
        company = args.company or args.client
        email = args.email or f"contact@{domains[0]}" if domains else ""
        
        manager.add_authorization(
            client_name=args.client,
            company=company,
            contact_email=email,
            domains=domains,
            ips=ips,
            activities=activities,
            testing_days=args.days
        )
    else:
        print("Usage examples:")
        print("\n1. Add authorization:")
        print("   python3 scripts/add_authorization.py --client 'Acme Corp' --domain acme.com --days 30")
        print("\n2. List authorizations:")
        print("   python3 scripts/add_authorization.py --list")
        print("\n3. Generate template:")
        print("   python3 scripts/add_authorization.py --template 'Acme Corp'")
        print("\n4. Remove authorization:")
        print("   python3 scripts/add_authorization.py --remove <hash>")


if __name__ == "__main__":
    main()

