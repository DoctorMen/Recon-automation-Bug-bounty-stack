#!/usr/bin/env python3
"""
DPIA Template Creator - GDPR Article 35 Compliance
Data Protection Impact Assessment for Security Testing Operations

Copyright © 2025 DoctorMen. All Rights Reserved.

GDPR Article 35: DPIA Required When Processing is Likely to Result in High Risk
- Systematic and extensive evaluation (including profiling)
- Large scale processing of special category data
- Systematic monitoring of publicly accessible areas
- Security testing of systems containing personal data
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
import uuid

def create_dpia_template(target, client_name, dpia_id=None):
    """
    Create GDPR Article 35 compliant DPIA template
    
    Required elements per Article 35(7):
    - Description of processing operations and purposes
    - Assessment of necessity and proportionality
    - Assessment of risks to rights and freedoms
    - Measures to address risks (including safeguards)
    """
    
    if not dpia_id:
        normalized = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        dpia_id = f"DPIA-{normalized}-{datetime.now().strftime('%Y%m%d')}"
    
    dpia_dir = Path("./authorizations/dpia_assessments")
    dpia_dir.mkdir(parents=True, exist_ok=True)
    
    filename = dpia_dir / f"{dpia_id}.json"
    
    template = {
        "_notice": "GDPR Article 35 - Data Protection Impact Assessment",
        "_version": "1.0",
        "_created": datetime.now().isoformat(),
        "_instructions": "Complete all sections. Consult DPO before finalizing.",
        
        # Identification
        "dpia_id": dpia_id,
        "client_name": client_name,
        "target": target,
        "assessment_date": datetime.now().isoformat(),
        "assessor": "[Your Name]",
        "assessor_role": "[Your Role/Title]",
        
        # Article 35(7)(a) - Description of Processing Operations
        "processing_operations": {
            "description": "Security testing and vulnerability assessment of client systems",
            "purposes": [
                "Identify security vulnerabilities",
                "Assess security posture",
                "Provide remediation recommendations",
                "Compliance verification (if applicable)"
            ],
            "lawful_basis": "contract",  # or "consent", "legitimate_interests"
            "legitimate_interests": "Ensuring security and integrity of client systems",
            
            "data_categories_processed": [
                "System logs (access logs, error logs)",
                "Network traffic metadata (IP addresses, ports, protocols)",
                "Security event data (vulnerability findings)",
                "System configuration data",
                "User account metadata (usernames, roles - NO passwords)"
            ],
            
            "special_category_data": False,  # True if processing sensitive personal data
            "special_category_justification": "",
            
            "data_subjects": [
                "System administrators",
                "End users (indirect - only metadata)",
                "Client employees"
            ],
            
            "recipients": [
                "Client security team",
                "Client management",
                "Security assessment provider (your company)"
            ],
            
            "third_country_transfers": False,
            "third_country_details": "",
            
            "retention_period": "12 months (365 days)",
            "deletion_procedure": "Automated deletion after retention period + secure erasure"
        },
        
        # Article 35(7)(b) - Necessity and Proportionality
        "necessity_proportionality": {
            "necessity_assessment": {
                "is_processing_necessary": True,
                "justification": "Security testing requires access to system data to identify vulnerabilities. Data minimization is applied - only technical data necessary for security assessment is collected.",
                "alternative_methods_considered": [
                    "Manual code review only - insufficient for runtime vulnerabilities",
                    "Black-box testing only - insufficient for comprehensive assessment",
                    "Automated scanning only - requires human verification"
                ],
                "why_alternatives_insufficient": "Comprehensive security assessment requires combination of automated and manual testing with access to system metadata."
            },
            
            "proportionality_assessment": {
                "is_processing_proportional": True,
                "data_minimization_applied": True,
                "data_minimization_measures": [
                    "Only technical/metadata collected - no personal content",
                    "Passwords and credentials never collected",
                    "Payment information never accessed",
                    "Personal communications never intercepted",
                    "IP addresses pseudonymized in reports",
                    "Limited retention period (12 months maximum)"
                ],
                "purpose_limitation_applied": True,
                "purpose_limitation_measures": [
                    "Data used ONLY for security assessment",
                    "No secondary use of data",
                    "No data sharing with third parties",
                    "No profiling or automated decision-making"
                ]
            }
        },
        
        # Article 35(7)(c) - Risk Assessment
        "risk_assessment": {
            "methodology": "ISO 27005 risk assessment methodology",
            
            "identified_risks": [
                {
                    "risk_id": "RISK-001",
                    "risk_category": "Confidentiality",
                    "description": "Unauthorized access to scan data containing system vulnerabilities",
                    "likelihood": "Low",  # Low, Medium, High
                    "impact": "High",  # Low, Medium, High
                    "risk_level": "Medium",  # Low, Medium, High
                    "affected_rights": [
                        "Right to security of personal data (Article 32)"
                    ]
                },
                {
                    "risk_id": "RISK-002",
                    "risk_category": "Integrity",
                    "description": "Accidental modification of production systems during testing",
                    "likelihood": "Low",
                    "impact": "High",
                    "risk_level": "Medium",
                    "affected_rights": [
                        "Right to data integrity"
                    ]
                },
                {
                    "risk_id": "RISK-003",
                    "risk_category": "Availability",
                    "description": "Service disruption due to intensive scanning",
                    "likelihood": "Low",
                    "impact": "Medium",
                    "risk_level": "Low",
                    "affected_rights": [
                        "Right to availability of services"
                    ]
                },
                {
                    "risk_id": "RISK-004",
                    "risk_category": "Transparency",
                    "description": "Data subjects not informed about security testing",
                    "likelihood": "Medium",
                    "impact": "Low",
                    "risk_level": "Low",
                    "affected_rights": [
                        "Right to be informed (Articles 13-14)"
                    ]
                }
            ],
            
            "residual_risk_acceptable": True,
            "residual_risk_justification": "After mitigation measures, residual risks are low and acceptable for security testing purposes"
        },
        
        # Article 35(7)(d) - Risk Mitigation Measures
        "risk_mitigation_measures": [
            {
                "risk_id": "RISK-001",
                "mitigation_measures": [
                    "End-to-end encryption of scan data in transit and at rest",
                    "Access control - only authorized personnel",
                    "Multi-factor authentication required",
                    "Encrypted backups stored in EU jurisdiction",
                    "Regular security audits of storage systems",
                    "Incident response plan in place"
                ],
                "responsibility": "Security Assessment Provider",
                "implementation_status": "Implemented",
                "verification_method": "Annual security audit"
            },
            {
                "risk_id": "RISK-002",
                "mitigation_measures": [
                    "Testing in staging environment first (when available)",
                    "Read-only scanning by default",
                    "Explicit authorization required for active testing",
                    "Rate limiting to prevent service impact",
                    "Rollback procedures documented",
                    "Testing during off-peak hours"
                ],
                "responsibility": "Security Assessment Provider",
                "implementation_status": "Implemented",
                "verification_method": "Testing logs and client confirmation"
            },
            {
                "risk_id": "RISK-003",
                "mitigation_measures": [
                    "Rate limiting on all scans",
                    "Testing schedule coordinated with client",
                    "Monitoring for service impact",
                    "Immediate stop if issues detected",
                    "Emergency contact available 24/7"
                ],
                "responsibility": "Security Assessment Provider",
                "implementation_status": "Implemented",
                "verification_method": "Service monitoring logs"
            },
            {
                "risk_id": "RISK-004",
                "mitigation_measures": [
                    "Client provides privacy notice to data subjects",
                    "Testing disclosed in privacy policy",
                    "Data subjects informed of their rights",
                    "Mechanism for data subject requests"
                ],
                "responsibility": "Client (Data Controller)",
                "implementation_status": "To be implemented by client",
                "verification_method": "Review of client privacy policy"
            }
        ],
        
        # Technical and Organizational Measures (Article 32)
        "security_measures": {
            "technical_measures": [
                "AES-256 encryption for data at rest",
                "TLS 1.3 for data in transit",
                "Multi-factor authentication (MFA)",
                "Role-based access control (RBAC)",
                "Automated vulnerability scanning of own systems",
                "Intrusion detection systems (IDS)",
                "Security information and event management (SIEM)",
                "Regular penetration testing of own infrastructure"
            ],
            
            "organizational_measures": [
                "ISO 27001 certified processes",
                "Regular staff security training",
                "Background checks for all personnel",
                "Non-disclosure agreements (NDAs)",
                "Incident response plan tested quarterly",
                "Data breach notification procedures (72-hour)",
                "DPO consultation on all high-risk processing",
                "Regular DPIA reviews (annual minimum)"
            ],
            
            "data_minimization": [
                "Collect only necessary technical data",
                "Pseudonymization of IP addresses in reports",
                "Aggregation of statistics where possible",
                "No collection of special category data",
                "No collection of passwords or credentials"
            ],
            
            "data_subject_rights": [
                "Right to access - provided within 30 days",
                "Right to rectification - corrections within 14 days",
                "Right to erasure - immediate upon request (if no legal obligation)",
                "Right to restrict processing - honored immediately",
                "Right to data portability - provided in machine-readable format",
                "Right to object - processing stopped immediately"
            ]
        },
        
        # Article 35(4) - DPO Consultation
        "dpo_consultation": {
            "dpo_consulted": False,  # Set to True after consultation
            "dpo_name": "[DPO Name or 'Not Required']",
            "dpo_email": "[dpo@company.com or 'N/A']",
            "consultation_date": "[YYYY-MM-DDTHH:MM:SS]",
            "dpo_advice": "[DPO recommendations]",
            "dpo_advice_followed": True,
            "reasons_if_not_followed": ""
        },
        
        # Article 35(4) - Data Subject Consultation (if appropriate)
        "data_subject_consultation": {
            "consultation_appropriate": False,
            "consultation_performed": False,
            "consultation_method": "",
            "consultation_date": "",
            "feedback_received": [],
            "feedback_addressed": True
        },
        
        # Supervisory Authority (if high residual risk)
        "supervisory_authority_consultation": {
            "required": False,  # True if high residual risk remains
            "authority_name": "[National DPA]",
            "consultation_date": "",
            "authority_advice": "",
            "compliance_confirmed": False
        },
        
        # Approval and Review
        "approval": {
            "approved": False,  # Set to True after approval
            "approved_by": "[Name of person approving]",
            "approved_by_role": "[Role/Title]",
            "approval_date": "[YYYY-MM-DDTHH:MM:SS]",
            "approval_signature": "[Signature or hash]"
        },
        
        "review_schedule": {
            "next_review_date": (datetime.fromisoformat(datetime.now().isoformat()).replace(year=datetime.now().year + 1)).isoformat(),
            "review_frequency": "Annual or when processing changes significantly",
            "review_triggers": [
                "Change in processing operations",
                "New types of data processed",
                "Change in third-party providers",
                "Data breach incident",
                "Change in applicable law",
                "DPO recommendation"
            ]
        },
        
        # Conclusion
        "conclusion": {
            "overall_risk_level": "Low to Medium",
            "processing_may_proceed": False,  # Set to True after all measures implemented
            "conditions": [
                "All mitigation measures implemented",
                "DPO consulted and advice followed",
                "Client informed and authorization obtained",
                "Regular monitoring and review performed"
            ],
            "dpia_complete": False,  # Set to True when all sections completed
            "dpia_valid_until": (datetime.fromisoformat(datetime.now().isoformat()).replace(year=datetime.now().year + 1)).isoformat()
        }
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    
    return str(filename)


def main():
    parser = argparse.ArgumentParser(
        description="Create DPIA (Data Protection Impact Assessment) template for GDPR compliance",
        epilog="Example: python3 CREATE_DPIA_TEMPLATE.py --target example.com --client 'Client Corp'"
    )
    
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--client", required=True, help="Client company name")
    parser.add_argument("--dpia-id", required=False, help="Custom DPIA ID (optional)")
    
    args = parser.parse_args()
    
    print("="*70)
    print("📋 DPIA TEMPLATE CREATOR - GDPR Article 35")
    print("="*70)
    print(f"\nTarget: {args.target}")
    print(f"Client: {args.client}")
    print()
    
    filename = create_dpia_template(
        target=args.target,
        client_name=args.client,
        dpia_id=args.dpia_id
    )
    
    print("✅ DPIA template created:", filename)
    print("\n" + "="*70)
    print("⚠️  NEXT STEPS TO COMPLETE DPIA")
    print("="*70)
    
    print("\n1️⃣  EDIT DPIA FILE")
    print(f"   nano {filename}")
    print("   Complete all sections:")
    print("   - Review and customize processing operations")
    print("   - Assess necessity and proportionality")
    print("   - Identify additional risks (if any)")
    print("   - Document mitigation measures")
    print("   - Verify security measures are in place")
    
    print("\n2️⃣  CONSULT DATA PROTECTION OFFICER (DPO)")
    print("   - Share DPIA with DPO (if you have one)")
    print("   - Document DPO advice")
    print("   - Update DPIA based on recommendations")
    print("   - Set dpo_consulted = True")
    
    print("\n3️⃣  OBTAIN APPROVAL")
    print("   - Get management/legal approval")
    print("   - Add approval details to DPIA")
    print("   - Set approved = True")
    print("   - Set dpia_complete = True")
    
    print("\n4️⃣  LINK TO AUTHORIZATION")
    print("   - Open authorization file")
    print("   - Set gdpr_dpia_reference to this DPIA ID")
    print("   - Set gdpr_dpia_completed = True")
    
    print("\n5️⃣  REVIEW ANNUALLY")
    print("   - Schedule review for:", datetime.now().year + 1)
    print("   - Review when processing changes")
    print("   - Update as needed")
    
    print("\n" + "="*70)
    print("📚 DPIA RESOURCES")
    print("="*70)
    print("\n🇪🇺 GDPR Article 35 Guidelines:")
    print("   https://gdpr.eu/article-35-impact-assessment/")
    print("\n📋 WP29 DPIA Guidelines:")
    print("   https://ec.europa.eu/newsroom/article29/items/611236")
    print("\n🛠️  ICO DPIA Template (UK):")
    print("   https://ico.org.uk/for-organisations/guide-to-data-protection/")
    print("\n⚖️  CNIL DPIA Tools (France):")
    print("   https://www.cnil.fr/en/PIA-privacy-impact-assessment")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
