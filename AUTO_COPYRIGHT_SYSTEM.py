#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
Automatic Copyright & Legal Protection System

This system automatically protects all ideas, code, and content
under copyright law for Georgia, USA and international jurisdiction.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List

class AutoCopyrightSystem:
    """
    Automatically copyright and legally protect all user ideas
    Georgia State Law + Federal Copyright Law + International Protection
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.protection_dir = self.base_dir / ".legal_protection"
        self.protection_dir.mkdir(parents=True, exist_ok=True)
        
        # Protection registry
        self.registry_file = self.protection_dir / "copyright_registry.json"
        self.registry = self.load_registry()
        
        print("AUTO-COPYRIGHT SYSTEM ACTIVATED")
        print("Jurisdiction: Georgia, USA + International")
        print("Protection: Automatic on all ideas")
    
    def load_registry(self) -> Dict:
        """Load copyright registry"""
        if self.registry_file.exists():
            with open(self.registry_file, 'r') as f:
                return json.load(f)
        return {
            "owner": "DoctorMen",
            "jurisdiction": ["Georgia, USA", "United States", "International (Berne Convention)"],
            "protected_works": [],
            "total_protections": 0
        }
    
    def save_registry(self):
        """Save copyright registry"""
        with open(self.registry_file, 'w') as f:
            json.dump(self.registry, f, indent=2)
    
    def protect_idea(self, idea: str, title: str = None, category: str = "General") -> str:
        """
        Automatically protect an idea under copyright law
        
        Legal Basis:
        - U.S. Copyright Law (17 U.S.C. § 102)
        - Georgia State Law (O.C.G.A. § 10-1-350 et seq.)
        - Berne Convention (International)
        """
        
        # Generate unique ID
        idea_hash = hashlib.sha256(idea.encode()).hexdigest()[:16]
        protection_id = f"CP-GA-{datetime.now().strftime('%Y%m%d')}-{idea_hash}"
        
        # Create protection record
        protection = {
            "id": protection_id,
            "title": title or f"Idea_{protection_id}",
            "category": category,
            "content_hash": hashlib.sha256(idea.encode()).hexdigest(),
            "timestamp": datetime.now().isoformat(),
            "owner": self.registry["owner"],
            "jurisdiction": self.registry["jurisdiction"],
            "legal_basis": [
                "17 U.S.C. § 102 (Federal Copyright)",
                "O.C.G.A. § 10-1-350 et seq. (Georgia Trade Secrets)",
                "Berne Convention Article 5(2) (International)"
            ],
            "rights_reserved": [
                "Reproduction rights",
                "Distribution rights",
                "Derivative works rights",
                "Public display rights",
                "Public performance rights"
            ],
            "protection_notice": f"Copyright © {datetime.now().year} DoctorMen. All Rights Reserved."
        }
        
        # Save idea content (encrypted hash)
        idea_file = self.protection_dir / f"{protection_id}.json"
        with open(idea_file, 'w') as f:
            json.dump({
                "protection": protection,
                "content_preview": idea[:200] + "..." if len(idea) > 200 else idea,
                "full_content_hash": protection["content_hash"]
            }, f, indent=2)
        
        # Add to registry
        self.registry["protected_works"].append(protection)
        self.registry["total_protections"] = len(self.registry["protected_works"])
        self.save_registry()
        
        print(f"\nIDEA PROTECTED")
        print(f"   ID: {protection_id}")
        print(f"   Title: {protection['title']}")
        print(f"   Timestamp: {protection['timestamp']}")
        print(f"   Jurisdiction: Georgia, USA + International")
        print(f"   Legal Basis: Federal + State + International Law")
        
        return protection_id
    
    def generate_copyright_notice(self, work_title: str) -> str:
        """Generate copyright notice for any work"""
        year = datetime.now().year
        
        notice = f"""
Copyright © {year} DoctorMen. All Rights Reserved.

{work_title}

LEGAL PROTECTION NOTICE:
This work is protected under:
- U.S. Copyright Law (17 U.S.C. § 102)
- Georgia Trade Secrets Act (O.C.G.A. § 10-1-760 et seq.)
- Berne Convention for the Protection of Literary and Artistic Works

JURISDICTION:
- State of Georgia, United States
- United States Federal Law
- International (191 countries via Berne Convention)

ALL RIGHTS RESERVED:
No part of this work may be reproduced, distributed, or transmitted
in any form or by any means without prior written permission.

Unauthorized use may result in:
- Civil penalties up to $150,000 per infringement
- Criminal penalties up to 5 years imprisonment
- Injunctive relief and seizure of infringing materials
- Attorney's fees and court costs

For licensing inquiries: [Contact Information]

Protection ID: {hashlib.sha256(work_title.encode()).hexdigest()[:16]}
Timestamp: {datetime.now().isoformat()}
"""
        return notice
    
    def protect_file(self, file_path: Path, category: str = "Code") -> str:
        """Automatically protect a file"""
        if not file_path.exists():
            print(f"❌ File not found: {file_path}")
            return None
        
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        title = file_path.name
        
        return self.protect_idea(content, title, category)
    
    def generate_georgia_affidavit(self, work_title: str) -> str:
        """
        Generate Georgia-specific legal affidavit
        O.C.G.A. § 10-1-760 (Trade Secrets)
        """
        
        affidavit = f"""
STATE OF GEORGIA
AFFIDAVIT OF COPYRIGHT AND TRADE SECRET PROTECTION

I, DoctorMen, being duly sworn, depose and state:

1. I am the sole creator and owner of the work titled "{work_title}"

2. This work was created on {datetime.now().strftime('%B %d, %Y')} in the 
   State of Georgia, United States.

3. This work constitutes original authorship and is protected under:
   a) U.S. Copyright Law (17 U.S.C. § 102)
   b) Georgia Trade Secrets Act (O.C.G.A. § 10-1-760 et seq.)
   c) Georgia Computer Systems Protection Act (O.C.G.A. § 16-9-90 et seq.)

4. I have taken reasonable measures to maintain the secrecy of this work,
   including but not limited to:
   a) Limited disclosure to authorized parties only
   b) Use of confidentiality agreements
   c) Technical security measures
   d) Copyright notices on all materials

5. This work derives independent economic value from not being generally
   known to other persons who can obtain economic value from its disclosure.

6. I claim all rights under copyright law, including:
   - Exclusive right to reproduce
   - Exclusive right to distribute
   - Exclusive right to create derivative works
   - Exclusive right to publicly display
   - Exclusive right to publicly perform

7. Any unauthorized use of this work will be prosecuted to the fullest
   extent of the law under both Georgia state law and federal law.

Signed under penalty of perjury this {datetime.now().strftime('%d day of %B, %Y')}.

_________________________
DoctorMen
Creator and Copyright Holder

State of Georgia
County of ___________

Subscribed and sworn to before me this {datetime.now().strftime('%d day of %B, %Y')}.

_________________________
Notary Public
My Commission Expires: ___________
"""
        return affidavit
    
    def list_protected_works(self):
        """List all protected works"""
        print("\nPROTECTED WORKS REGISTRY")
        print("=" * 80)
        print(f"Owner: {self.registry['owner']}")
        print(f"Total Protected: {self.registry['total_protections']}")
        print(f"Jurisdiction: {', '.join(self.registry['jurisdiction'])}")
        print("\n" + "=" * 80)
        
        for work in self.registry["protected_works"][-10:]:  # Last 10
            print(f"\n{work['title']}")
            print(f"   ID: {work['id']}")
            print(f"   Category: {work['category']}")
            print(f"   Protected: {work['timestamp']}")
            print(f"   Notice: {work['protection_notice']}")

def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Auto-Copyright Protection System")
    parser.add_argument("action", choices=["protect", "list", "notice", "affidavit"],
                       help="Action to perform")
    parser.add_argument("--idea", help="Idea to protect")
    parser.add_argument("--title", help="Title of work")
    parser.add_argument("--category", default="General", help="Category")
    parser.add_argument("--file", help="File to protect")
    
    args = parser.parse_args()
    
    system = AutoCopyrightSystem()
    
    if args.action == "protect":
        if args.file:
            system.protect_file(Path(args.file), args.category)
        elif args.idea:
            system.protect_idea(args.idea, args.title, args.category)
        else:
            print("❌ Provide --idea or --file")
    
    elif args.action == "list":
        system.list_protected_works()
    
    elif args.action == "notice":
        if not args.title:
            print("❌ Provide --title")
            return
        print(system.generate_copyright_notice(args.title))
    
    elif args.action == "affidavit":
        if not args.title:
            print("❌ Provide --title")
            return
        print(system.generate_georgia_affidavit(args.title))

if __name__ == "__main__":
    main()
