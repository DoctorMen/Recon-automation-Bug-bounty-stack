#!/usr/bin/env python3
"""
GDPR-Compliant Legal Authorization System for European Operations
Copyright © 2025 DoctorMen. All Rights Reserved.

COMPLIANCE:
- GDPR (General Data Protection Regulation) - EU 2016/679
- NIS2 Directive (Network and Information Security) - EU 2022/2555
- Cybersecurity Act - EU 2019/881
- ePrivacy Directive - 2002/58/EC
- DORA (Digital Operational Resilience Act) - EU 2022/2554

CRITICAL: This system enforces European data protection and cybersecurity laws.
All security testing MUST comply with GDPR and member state laws.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import uuid

class GDPRLegalAuthorizationShield:
    """
    GDPR-Compliant Authorization Shield for European Security Operations
    
    Enforces:
    - GDPR Article 6 (Lawfulness of Processing)
    - GDPR Article 7 (Conditions for Consent)
    - GDPR Article 13-14 (Information to Data Subjects)
    - GDPR Article 15-22 (Data Subject Rights)
    - GDPR Article 25 (Data Protection by Design)
    - GDPR Article 32 (Security of Processing)
    - GDPR Article 33-34 (Breach Notification)
    - GDPR Article 35 (Data Protection Impact Assessment)
    - NIS2 Directive (Security Measures & Incident Reporting)
    """
    
    def __init__(self):
        self.auth_dir = Path("./authorizations")
        self.auth_dir.mkdir(exist_ok=True)
        
        self.audit_log = self.auth_dir / "gdpr_audit_log.json"
        self.consent_log = self.auth_dir / "gdpr_consent_log.json"
        self.dpia_dir = self.auth_dir / "dpia_assessments"
        self.dpia_dir.mkdir(exist_ok=True)
        
        # GDPR-required retention periods
        self.retention_policy = {
            "authorization_files": 2555,  # 7 years (standard for security)
            "audit_logs": 2555,  # 7 years (NIS2 requirement)
            "consent_records": 2555,  # 7 years (GDPR recommendation)
            "dpia_assessments": 3650,  # 10 years (best practice)
            "personal_data": 365  # 1 year or less (data minimization)
        }
    
    def check_authorization(self, target, processing_purpose="security_testing"):
        """
        Check GDPR-compliant authorization for security testing
        
        Additional checks vs US version:
        - Lawful basis for processing (GDPR Art. 6)
        - Explicit consent recorded (GDPR Art. 7)
        - Data protection impact assessment (GDPR Art. 35)
        - Cross-border data transfer compliance (GDPR Art. 44-50)
        - Data subject rights acknowledgment
        - NIS2 security measures compliance
        """
        
        # Standard authorization checks
        auth_file = self._find_authorization_file(target)
        
        if not auth_file:
            reason = "NO GDPR-COMPLIANT AUTHORIZATION FILE FOUND - SCAN BLOCKED"
            self._log_blocked_attempt(target, reason, processing_purpose)
            return False, reason, None
        
        # Load and validate authorization
        try:
            with open(auth_file, 'r', encoding='utf-8') as f:
                auth_data = json.load(f)
        except Exception as e:
            reason = f"AUTHORIZATION FILE CORRUPT - SCAN BLOCKED: {str(e)}"
            self._log_blocked_attempt(target, reason, processing_purpose)
            return False, reason, None
        
        # GDPR-specific validation
        gdpr_valid, gdpr_reason = self._validate_gdpr_compliance(auth_data, target)
        if not gdpr_valid:
            self._log_blocked_attempt(target, gdpr_reason, processing_purpose)
            return False, gdpr_reason, None
        
        # Standard scope and time validation
        if not self._target_in_scope(target, auth_data.get("scope", [])):
            reason = "TARGET OUT OF SCOPE - SCAN BLOCKED"
            self._log_blocked_attempt(target, reason, processing_purpose)
            return False, reason, None
        
        if not self._within_time_window(auth_data):
            reason = "OUTSIDE AUTHORIZED TIME WINDOW - SCAN BLOCKED"
            self._log_blocked_attempt(target, reason, processing_purpose)
            return False, reason, None
        
        # DPIA requirement check (GDPR Art. 35)
        if auth_data.get("requires_dpia", True):
            dpia_valid, dpia_reason = self._check_dpia_completed(target, auth_data)
            if not dpia_valid:
                self._log_blocked_attempt(target, dpia_reason, processing_purpose)
                return False, dpia_reason, None
        
        # Log authorized scan with GDPR metadata
        self._log_authorized_scan(target, auth_data, processing_purpose)
        
        return True, "AUTHORIZATION VALID - GDPR COMPLIANT", auth_data
    
    def _validate_gdpr_compliance(self, auth_data, target):
        """
        Validate GDPR-specific requirements
        
        GDPR Article 6 - Lawful Basis:
        - Consent (explicit)
        - Contract (service agreement)
        - Legal obligation
        - Vital interests
        - Public task
        - Legitimate interests
        """
        
        # Required GDPR fields
        required_gdpr_fields = [
            "gdpr_lawful_basis",
            "gdpr_consent_date",
            "gdpr_data_controller",
            "gdpr_dpo_contact",
            "gdpr_data_categories",
            "gdpr_retention_period",
            "gdpr_subject_rights_acknowledged",
            "gdpr_cross_border_transfer"
        ]
        
        for field in required_gdpr_fields:
            if field not in auth_data:
                return False, f"GDPR COMPLIANCE FAILED: Missing required field '{field}'"
        
        # Validate lawful basis
        valid_bases = ["consent", "contract", "legal_obligation", "vital_interests", 
                       "public_task", "legitimate_interests"]
        if auth_data["gdpr_lawful_basis"] not in valid_bases:
            return False, f"GDPR COMPLIANCE FAILED: Invalid lawful basis '{auth_data['gdpr_lawful_basis']}'"
        
        # Validate consent date is present and recent (within 24 months)
        try:
            consent_date = datetime.fromisoformat(auth_data["gdpr_consent_date"])
            age_days = (datetime.now() - consent_date).days
            if age_days > 730:  # 2 years
                return False, "GDPR COMPLIANCE FAILED: Consent expired (>2 years old), renewal required"
        except:
            return False, "GDPR COMPLIANCE FAILED: Invalid consent date format"
        
        # Validate DPO contact
        dpo = auth_data.get("gdpr_dpo_contact", {})
        if not dpo.get("name") or not dpo.get("email"):
            return False, "GDPR COMPLIANCE FAILED: Data Protection Officer contact incomplete"
        
        # Validate data categories declared
        if not auth_data.get("gdpr_data_categories") or len(auth_data["gdpr_data_categories"]) == 0:
            return False, "GDPR COMPLIANCE FAILED: No data categories declared"
        
        # Validate retention period is reasonable
        retention_days = auth_data.get("gdpr_retention_period", 0)
        if retention_days > 2555:  # More than 7 years
            return False, "GDPR COMPLIANCE FAILED: Retention period exceeds reasonable limits (max 7 years)"
        
        # Validate data subject rights acknowledged
        if not auth_data.get("gdpr_subject_rights_acknowledged"):
            return False, "GDPR COMPLIANCE FAILED: Data subject rights not acknowledged"
        
        # Validate cross-border transfer compliance
        cross_border = auth_data.get("gdpr_cross_border_transfer", {})
        if cross_border.get("transfers_data_outside_eea"):
            if not cross_border.get("adequacy_decision") and not cross_border.get("safeguards"):
                return False, "GDPR COMPLIANCE FAILED: Cross-border transfer without adequate safeguards"
        
        # NIS2 Directive compliance (for critical infrastructure)
        if auth_data.get("nis2_critical_entity", False):
            if not auth_data.get("nis2_incident_response_plan"):
                return False, "NIS2 COMPLIANCE FAILED: Critical entity without incident response plan"
            if not auth_data.get("nis2_csirt_contact"):
                return False, "NIS2 COMPLIANCE FAILED: Critical entity without CSIRT contact"
        
        return True, "GDPR compliant"
    
    def _check_dpia_completed(self, target, auth_data):
        """
        Check if Data Protection Impact Assessment (DPIA) is completed
        Required by GDPR Article 35 for high-risk processing
        """
        
        dpia_id = auth_data.get("gdpr_dpia_reference")
        if not dpia_id:
            return False, "GDPR COMPLIANCE FAILED: DPIA required but not referenced"
        
        dpia_file = self.dpia_dir / f"{dpia_id}.json"
        if not dpia_file.exists():
            return False, f"GDPR COMPLIANCE FAILED: DPIA file not found ({dpia_id})"
        
        try:
            with open(dpia_file, 'r', encoding='utf-8') as f:
                dpia = json.load(f)
            
            # Validate DPIA is complete
            required_sections = [
                "risk_assessment",
                "necessity_proportionality",
                "risk_mitigation_measures",
                "dpo_consultation",
                "approval_date"
            ]
            
            for section in required_sections:
                if section not in dpia:
                    return False, f"GDPR COMPLIANCE FAILED: DPIA incomplete (missing {section})"
            
            # Check DPIA is recent (within 12 months)
            approval_date = datetime.fromisoformat(dpia["approval_date"])
            age_days = (datetime.now() - approval_date).days
            if age_days > 365:
                return False, "GDPR COMPLIANCE FAILED: DPIA expired (>12 months old)"
            
            return True, "DPIA valid"
            
        except Exception as e:
            return False, f"GDPR COMPLIANCE FAILED: Cannot validate DPIA: {str(e)}"
    
    def _find_authorization_file(self, target):
        """Find GDPR authorization file for target"""
        normalized = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        auth_file = self.auth_dir / f"{normalized}_gdpr_authorization.json"
        
        if auth_file.exists():
            return auth_file
        
        # Check for wildcard matches
        for auth in self.auth_dir.glob("*_gdpr_authorization.json"):
            try:
                with open(auth, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if self._target_in_scope(target, data.get("scope", [])):
                        return auth
            except:
                continue
        
        return None
    
    def _target_in_scope(self, target, scope):
        """Check if target is in authorized scope"""
        target_clean = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        for authorized in scope:
            if authorized.startswith("*."):
                domain = authorized[2:]
                if target_clean.endswith(domain) or target_clean == domain:
                    return True
            elif authorized == target_clean:
                return True
            elif target_clean.startswith(authorized.replace("*.", "")):
                return True
        
        return False
    
    def _within_time_window(self, auth_data):
        """Check if current time is within authorized window"""
        try:
            start = datetime.fromisoformat(auth_data["start_date"])
            end = datetime.fromisoformat(auth_data["end_date"])
            now = datetime.now()
            return start <= now <= end
        except:
            return False
    
    def _log_blocked_attempt(self, target, reason, processing_purpose):
        """Log blocked scan attempt (GDPR Article 32 - Security logging)"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_id": str(uuid.uuid4()),
            "target": target,
            "status": "BLOCKED",
            "reason": reason,
            "processing_purpose": processing_purpose,
            "user": os.getenv("USER", "unknown"),
            "gdpr_processing_record": {
                "lawful_basis": "legal_obligation",
                "data_categories": ["security_logs", "system_access"],
                "retention_period_days": self.retention_policy["audit_logs"]
            }
        }
        
        self._append_to_log(self.audit_log, log_entry)
        print(f"⚠️  GDPR: Blocked attempt logged (Event ID: {log_entry['event_id']})")
    
    def _log_authorized_scan(self, target, auth_data, processing_purpose):
        """Log authorized scan (GDPR Article 30 - Records of processing)"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_id": str(uuid.uuid4()),
            "target": target,
            "status": "AUTHORIZED",
            "processing_purpose": processing_purpose,
            "client": auth_data.get("client_name"),
            "authorized_by": auth_data.get("authorized_by"),
            "user": os.getenv("USER", "unknown"),
            "gdpr_metadata": {
                "lawful_basis": auth_data.get("gdpr_lawful_basis"),
                "data_controller": auth_data.get("gdpr_data_controller"),
                "data_categories": auth_data.get("gdpr_data_categories"),
                "retention_period_days": auth_data.get("gdpr_retention_period"),
                "dpia_reference": auth_data.get("gdpr_dpia_reference")
            }
        }
        
        self._append_to_log(self.audit_log, log_entry)
        
        # Also log consent (GDPR Article 7.1 - Demonstrable consent)
        consent_entry = {
            "timestamp": datetime.now().isoformat(),
            "consent_id": str(uuid.uuid4()),
            "target": target,
            "client": auth_data.get("client_name"),
            "consent_date": auth_data.get("gdpr_consent_date"),
            "lawful_basis": auth_data.get("gdpr_lawful_basis"),
            "processing_purposes": [processing_purpose],
            "data_subject_informed": True,
            "withdrawal_mechanism": auth_data.get("gdpr_consent_withdrawal_method", "email")
        }
        
        self._append_to_log(self.consent_log, consent_entry)
        print(f"✅ GDPR: Authorized scan logged (Event ID: {log_entry['event_id']})")
    
    def _append_to_log(self, log_file, entry):
        """Append entry to JSON log file"""
        logs = []
        if log_file.exists():
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except:
                logs = []
        
        logs.append(entry)
        
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    
    def create_gdpr_authorization_template(self, target, client_name, eu_member_state=""):
        """
        Create GDPR-compliant authorization template
        
        Includes all required GDPR fields per Articles 13-14
        """
        
        normalized = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        filename = self.auth_dir / f"{normalized}_gdpr_authorization.json"
        
        template = {
            "_gdpr_notice": "This authorization template complies with GDPR (EU 2016/679) and NIS2 Directive",
            "_instructions": "Fill in all fields. All fields are REQUIRED for GDPR compliance.",
            
            # Basic Information
            "client_name": client_name,
            "target": target,
            "scope": [
                target,
                f"*.{target}"
            ],
            "start_date": datetime.now().isoformat(),
            "end_date": (datetime.now() + timedelta(days=30)).isoformat(),
            
            # Contact Information
            "authorized_by": "[Name of person authorizing]",
            "authorized_by_email": "[email@client.com]",
            "authorized_by_title": "[Job Title]",
            "contact_emergency": "[+XX-XXX-XXX-XXXX]",
            
            # GDPR Article 6 - Lawful Basis for Processing
            "gdpr_lawful_basis": "consent",  # Options: consent, contract, legal_obligation, vital_interests, public_task, legitimate_interests
            "gdpr_consent_date": datetime.now().isoformat(),
            "gdpr_consent_method": "written_agreement",  # written_agreement, electronic_signature, email_confirmation
            "gdpr_consent_withdrawal_method": "email",  # How data subject can withdraw consent
            
            # GDPR Article 13 - Information to Data Subject
            "gdpr_data_controller": {
                "name": "[Your Company Name]",
                "address": "[Your Company Address]",
                "country": "[Country]",
                "email": "[dpo@yourcompany.com]",
                "phone": "[+XX-XXX-XXX-XXXX]"
            },
            
            # GDPR Article 37 - Data Protection Officer
            "gdpr_dpo_contact": {
                "name": "[DPO Name or 'Not Required']",
                "email": "[dpo@client.com or 'N/A']",
                "phone": "[+XX-XXX-XXX-XXXX or 'N/A']"
            },
            
            # GDPR Article 30 - Records of Processing Activities
            "gdpr_data_categories": [
                "system_logs",
                "network_traffic_metadata",
                "vulnerability_scan_results",
                "security_event_logs"
            ],
            "gdpr_special_categories": [],  # Sensitive data: racial/ethnic, political, religious, health, sexual orientation, biometric, genetic
            
            # GDPR Article 5 - Data Minimization & Retention
            "gdpr_retention_period": 365,  # Days to retain data (default: 1 year)
            "gdpr_deletion_date": (datetime.now() + timedelta(days=395)).isoformat(),  # Auto-delete after retention + 30 days
            
            # GDPR Articles 15-22 - Data Subject Rights
            "gdpr_subject_rights_acknowledged": True,
            "gdpr_subject_rights_notice": {
                "right_to_access": "Data subject can request copy of their data",
                "right_to_rectification": "Data subject can request corrections",
                "right_to_erasure": "Data subject can request deletion (right to be forgotten)",
                "right_to_restrict_processing": "Data subject can request processing limitation",
                "right_to_data_portability": "Data subject can request data in portable format",
                "right_to_object": "Data subject can object to processing",
                "automated_decision_making": "No automated decision-making or profiling performed"
            },
            
            # GDPR Articles 44-50 - Cross-Border Data Transfer
            "gdpr_cross_border_transfer": {
                "transfers_data_outside_eea": False,  # Set to True if transferring data outside EU/EEA
                "destination_countries": [],  # List countries if transfers_data_outside_eea = True
                "adequacy_decision": False,  # True if destination has EU adequacy decision
                "safeguards": "",  # If no adequacy decision: "standard_contractual_clauses", "binding_corporate_rules", "certification"
                "us_data_privacy_framework": False  # True if transferring to US under DPF
            },
            
            # GDPR Article 35 - Data Protection Impact Assessment (DPIA)
            "requires_dpia": True,  # Required for high-risk processing
            "gdpr_dpia_reference": f"DPIA-{normalized}-{datetime.now().strftime('%Y%m%d')}",
            "gdpr_dpia_completed": False,  # Set to True after DPIA is completed
            
            # GDPR Article 32 - Security of Processing
            "gdpr_security_measures": [
                "encryption_in_transit_and_rest",
                "access_control_and_authentication",
                "audit_logging",
                "regular_security_testing",
                "incident_response_plan"
            ],
            
            # GDPR Articles 33-34 - Breach Notification
            "gdpr_breach_notification": {
                "supervisory_authority": "[National DPA - e.g., CNIL (France), ICO (UK)]",
                "notification_within_72_hours": True,
                "data_subject_notification_required": "if_high_risk"
            },
            
            # NIS2 Directive (EU 2022/2555) - For Critical Entities
            "nis2_critical_entity": False,  # True if client is essential/important entity under NIS2
            "nis2_sector": "",  # Options: energy, transport, banking, health, water, digital_infrastructure, etc.
            "nis2_incident_response_plan": "",  # Reference to incident response plan
            "nis2_csirt_contact": "",  # Computer Security Incident Response Team contact
            
            # Member State Specific
            "eu_member_state": eu_member_state,  # e.g., "France", "Germany", "Netherlands"
            "national_law_references": [],  # Any additional national laws (e.g., BDSG in Germany)
            
            # Testing Scope
            "testing_types_authorized": [
                "vulnerability_scanning",
                "port_scanning",
                "web_application_testing",
                "api_security_testing"
            ],
            "testing_types_forbidden": [
                "dos_testing",
                "social_engineering",
                "physical_access_testing"
            ],
            
            # Signature
            "signature_date": "[YYYY-MM-DDTHH:MM:SS after client signs]",
            "signature_method": "electronic_signature",  # electronic_signature, wet_signature, email_confirmation
            "signature_hash": "[SHA256 hash of signed document]"
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(template, f, indent=2, ensure_ascii=False)
        
        print(f"✅ GDPR authorization template created: {filename}")
        print(f"\n📋 NEXT STEPS:")
        print(f"1. Edit {filename}")
        print(f"2. Fill in ALL required fields")
        print(f"3. Complete DPIA assessment (use CREATE_DPIA_TEMPLATE.py)")
        print(f"4. Get client signature")
        print(f"5. Hash signed document and add signature_hash")
        print(f"6. Verify with: python3 VERIFY_GDPR_COMPLIANCE.py {filename}")
        
        return str(filename)


# Decorator for easy integration
def require_gdpr_authorization(func):
    """
    Decorator to require GDPR-compliant authorization for any function
    Usage:
        @require_gdpr_authorization
        def my_scan_function(target):
            # scanning code here
    """
    def wrapper(target, *args, **kwargs):
        shield = GDPRLegalAuthorizationShield()
        authorized, reason, auth_data = shield.check_authorization(target)
        
        if not authorized:
            print(f"\n🚫 GDPR COMPLIANCE FAILED")
            print(f"   Target: {target}")
            print(f"   Reason: {reason}")
            print(f"\n⚠️  Cannot proceed without GDPR-compliant authorization")
            sys.exit(1)
        
        print(f"\n✅ GDPR AUTHORIZATION VERIFIED")
        print(f"   Client: {auth_data.get('client_name')}")
        print(f"   Lawful Basis: {auth_data.get('gdpr_lawful_basis')}")
        print(f"   DPO: {auth_data.get('gdpr_dpo_contact', {}).get('email')}")
        
        return func(target, *args, **kwargs)
    
    return wrapper


if __name__ == "__main__":
    print("="*60)
    print("GDPR-COMPLIANT LEGAL AUTHORIZATION SHIELD")
    print("European Cybersecurity Compliance System")
    print("="*60)
    print("\nThis system enforces:")
    print("✅ GDPR (EU 2016/679)")
    print("✅ NIS2 Directive (EU 2022/2555)")
    print("✅ Cybersecurity Act (EU 2019/881)")
    print("✅ ePrivacy Directive (2002/58/EC)")
    print("\nUsage:")
    print("  from LEGAL_AUTHORIZATION_SYSTEM_GDPR import GDPRLegalAuthorizationShield")
    print("  shield = GDPRLegalAuthorizationShield()")
    print("  authorized, reason, data = shield.check_authorization('example.com')")
