#!/usr/bin/env python3
"""
GDPR Compliance Verification Tool
Validates authorization files and DPIAs for European operations

Copyright © 2025 DoctorMen. All Rights Reserved.
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
try:
    init(autoreset=True)
except:
    # Fallback if colorama not installed
    class Fore:
        GREEN = RED = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

def print_header(text):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
    print(f"{text}")
    print(f"{'='*70}{Style.RESET_ALL}\n")

def print_success(text):
    print(f"{Fore.GREEN}✅ {text}{Style.RESET_ALL}")

def print_error(text):
    print(f"{Fore.RED}❌ {text}{Style.RESET_ALL}")

def print_warning(text):
    print(f"{Fore.YELLOW}⚠️  {text}{Style.RESET_ALL}")

def print_info(text):
    print(f"{Fore.BLUE}ℹ️  {text}{Style.RESET_ALL}")

def verify_authorization_file(auth_file):
    """Verify GDPR authorization file"""
    
    print_header("GDPR AUTHORIZATION FILE VERIFICATION")
    
    if not Path(auth_file).exists():
        print_error(f"Authorization file not found: {auth_file}")
        return False
    
    print_info(f"Checking: {auth_file}")
    
    try:
        with open(auth_file, 'r', encoding='utf-8') as f:
            auth_data = json.load(f)
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON format: {str(e)}")
        return False
    except Exception as e:
        print_error(f"Cannot read file: {str(e)}")
        return False
    
    print_success("File format valid (JSON)")
    
    # Check required fields
    required_fields = [
        "client_name", "target", "scope", "start_date", "end_date",
        "authorized_by", "authorized_by_email", "gdpr_lawful_basis",
        "gdpr_consent_date", "gdpr_data_controller", "gdpr_dpo_contact",
        "gdpr_data_categories", "gdpr_retention_period",
        "gdpr_subject_rights_acknowledged", "gdpr_cross_border_transfer"
    ]
    
    missing_fields = []
    for field in required_fields:
        if field not in auth_data:
            missing_fields.append(field)
    
    if missing_fields:
        print_error(f"Missing required fields: {', '.join(missing_fields)}")
        return False
    
    print_success("All required fields present")
    
    # Validate lawful basis
    valid_bases = ["consent", "contract", "legal_obligation", "vital_interests", 
                   "public_task", "legitimate_interests"]
    if auth_data["gdpr_lawful_basis"] not in valid_bases:
        print_error(f"Invalid lawful basis: {auth_data['gdpr_lawful_basis']}")
        print_info(f"Valid options: {', '.join(valid_bases)}")
        return False
    
    print_success(f"Lawful basis valid: {auth_data['gdpr_lawful_basis']}")
    
    # Validate consent date
    try:
        consent_date = datetime.fromisoformat(auth_data["gdpr_consent_date"])
        age_days = (datetime.now() - consent_date).days
        
        if age_days < 0:
            print_error("Consent date is in the future")
            return False
        
        if age_days > 730:
            print_warning(f"Consent is {age_days} days old (>2 years) - consider renewal")
        else:
            print_success(f"Consent date valid ({age_days} days old)")
    except:
        print_error("Invalid consent date format (must be ISO 8601)")
        return False
    
    # Validate time window
    try:
        start = datetime.fromisoformat(auth_data["start_date"])
        end = datetime.fromisoformat(auth_data["end_date"])
        now = datetime.now()
        
        if start > end:
            print_error("Start date is after end date")
            return False
        
        if now < start:
            print_warning("Authorization not yet active")
        elif now > end:
            print_error("Authorization has expired")
            return False
        else:
            days_remaining = (end - now).days
            print_success(f"Time window valid ({days_remaining} days remaining)")
    except:
        print_error("Invalid date format for start_date or end_date")
        return False
    
    # Validate DPO contact
    dpo = auth_data.get("gdpr_dpo_contact", {})
    if not isinstance(dpo, dict):
        print_error("DPO contact must be an object")
        return False
    
    if not dpo.get("name") or not dpo.get("email"):
        print_error("DPO contact incomplete (needs name and email)")
        return False
    
    print_success(f"DPO contact valid: {dpo.get('name')}")
    
    # Validate data categories
    if not auth_data.get("gdpr_data_categories") or len(auth_data["gdpr_data_categories"]) == 0:
        print_error("No data categories declared")
        return False
    
    print_success(f"{len(auth_data['gdpr_data_categories'])} data categories declared")
    
    # Validate retention period
    retention_days = auth_data.get("gdpr_retention_period", 0)
    if retention_days <= 0:
        print_error("Invalid retention period (must be > 0)")
        return False
    
    if retention_days > 2555:
        print_error(f"Retention period too long ({retention_days} days > 7 years)")
        return False
    
    print_success(f"Retention period valid: {retention_days} days")
    
    # Check cross-border transfers
    cross_border = auth_data.get("gdpr_cross_border_transfer", {})
    if cross_border.get("transfers_data_outside_eea"):
        if not cross_border.get("adequacy_decision") and not cross_border.get("safeguards"):
            print_error("Cross-border transfer without adequate safeguards")
            return False
        print_warning("Cross-border data transfer declared - ensure safeguards in place")
    
    # Check DPIA requirement
    if auth_data.get("requires_dpia", True):
        dpia_ref = auth_data.get("gdpr_dpia_reference")
        if not dpia_ref:
            print_error("DPIA required but no reference provided")
            return False
        
        dpia_completed = auth_data.get("gdpr_dpia_completed", False)
        if not dpia_completed:
            print_warning(f"DPIA referenced ({dpia_ref}) but not marked as completed")
            return False
        
        print_success(f"DPIA reference valid: {dpia_ref}")
    
    # Check signature
    if not auth_data.get("signature_date"):
        print_warning("No signature date - authorization not finalized")
        return False
    
    print_success("Signature date present")
    
    print_header("AUTHORIZATION FILE: VALID ✅")
    return True

def verify_dpia_file(dpia_file):
    """Verify DPIA completeness"""
    
    print_header("DPIA VERIFICATION")
    
    if not Path(dpia_file).exists():
        print_error(f"DPIA file not found: {dpia_file}")
        return False
    
    print_info(f"Checking: {dpia_file}")
    
    try:
        with open(dpia_file, 'r', encoding='utf-8') as f:
            dpia_data = json.load(f)
    except Exception as e:
        print_error(f"Cannot read DPIA: {str(e)}")
        return False
    
    print_success("DPIA file readable")
    
    # Check required sections
    required_sections = [
        "processing_operations",
        "necessity_proportionality",
        "risk_assessment",
        "risk_mitigation_measures",
        "security_measures",
        "dpo_consultation",
        "conclusion"
    ]
    
    missing_sections = []
    for section in required_sections:
        if section not in dpia_data:
            missing_sections.append(section)
    
    if missing_sections:
        print_error(f"Missing DPIA sections: {', '.join(missing_sections)}")
        return False
    
    print_success("All required DPIA sections present")
    
    # Check DPO consultation
    dpo_consulted = dpia_data.get("dpo_consultation", {}).get("dpo_consulted", False)
    if not dpo_consulted:
        print_warning("DPO not yet consulted")
        return False
    
    print_success("DPO consultation completed")
    
    # Check approval
    approved = dpia_data.get("approval", {}).get("approved", False)
    if not approved:
        print_warning("DPIA not yet approved")
        return False
    
    print_success("DPIA approved")
    
    # Check if complete
    complete = dpia_data.get("conclusion", {}).get("dpia_complete", False)
    if not complete:
        print_error("DPIA marked as incomplete")
        return False
    
    print_success("DPIA marked as complete")
    
    # Check if processing may proceed
    may_proceed = dpia_data.get("conclusion", {}).get("processing_may_proceed", False)
    if not may_proceed:
        print_error("DPIA conclusion: Processing may NOT proceed")
        return False
    
    print_success("DPIA conclusion: Processing may proceed")
    
    # Check validity
    try:
        valid_until = datetime.fromisoformat(dpia_data.get("conclusion", {}).get("dpia_valid_until", ""))
        if datetime.now() > valid_until:
            print_error(f"DPIA expired (valid until {valid_until.date()})")
            return False
        
        days_remaining = (valid_until - datetime.now()).days
        print_success(f"DPIA valid ({days_remaining} days remaining)")
    except:
        print_warning("Cannot verify DPIA validity date")
    
    print_header("DPIA: VALID ✅")
    return True

def verify_complete_compliance(auth_file):
    """Verify complete GDPR compliance (authorization + DPIA)"""
    
    print_header("🇪🇺 COMPLETE GDPR COMPLIANCE CHECK")
    
    # Verify authorization file
    auth_valid = verify_authorization_file(auth_file)
    if not auth_valid:
        print_error("Authorization file validation FAILED")
        return False
    
    # Check if DPIA is required
    try:
        with open(auth_file, 'r') as f:
            auth_data = json.load(f)
        
        if auth_data.get("requires_dpia", True):
            dpia_ref = auth_data.get("gdpr_dpia_reference")
            dpia_dir = Path("./authorizations/dpia_assessments")
            dpia_file = dpia_dir / f"{dpia_ref}.json"
            
            dpia_valid = verify_dpia_file(dpia_file)
            if not dpia_valid:
                print_error("DPIA validation FAILED")
                return False
        else:
            print_info("DPIA not required for this processing")
    except Exception as e:
        print_error(f"Cannot verify DPIA requirement: {str(e)}")
        return False
    
    # All checks passed
    print_header("🎉 GDPR COMPLIANCE: VERIFIED ✅")
    print_success("Authorization file: VALID")
    print_success("DPIA (if required): VALID")
    print_success("All GDPR requirements: MET")
    print()
    print_info("You may now proceed with authorized security testing")
    print_info("Ensure compliance is maintained throughout the engagement")
    print()
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Verify GDPR compliance of authorization and DPIA files",
        epilog="Example: python3 VERIFY_GDPR_COMPLIANCE.py ./authorizations/example_com_gdpr_authorization.json"
    )
    
    parser.add_argument("auth_file", help="Path to GDPR authorization file")
    parser.add_argument("--dpia-only", help="Verify only DPIA file (provide DPIA path)", metavar="DPIA_FILE")
    
    args = parser.parse_args()
    
    try:
        if args.dpia_only:
            # Verify DPIA only
            success = verify_dpia_file(args.dpia_only)
        else:
            # Verify complete compliance
            success = verify_complete_compliance(args.auth_file)
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Verification cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
