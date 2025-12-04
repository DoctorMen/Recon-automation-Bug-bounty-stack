#!/usr/bin/env python3

from RESPONSIBLE_DISCLOSURE_VALIDATOR import ResponsibleDisclosureValidator

def validate_oppo_targets():
    """Validate OPPO targets responsibly before any disclosure"""
    
    validator = ResponsibleDisclosureValidator()
    
    # OPPO targets to validate
    oppo_targets = [
        "https://gcsm.oppoit.com",
        "https://www.oppo.com", 
        "https://id.heytap.com"
    ]
    
    print("🔒 RESPONSIBLE VALIDATION STARTED")
    print("⚠️  NO DISCLOSURE WITHOUT VALIDATION")
    print("📋 Testing OPPO targets for actual vulnerabilities...\n")
    
    validated_findings = []
    
    for target in oppo_targets:
        print(f"🔍 TESTING: {target}")
        
        claimed_finding = {
            "title": "Missing Security Headers",
            "remediation": "Implement security headers",
            "impact_assessment": "Medium risk",
            "reproduction_steps": f"Use curl -I {target} to check headers"
        }
        
        is_valid, validation_report = validator.validate_finding_before_disclosure(
            target, "missing_security_headers", claimed_finding
        )
        
        if is_valid:
            print(f"✅ VALIDATED: {target}")
            validated_findings.append(validation_report)
        else:
            print(f"❌ NOT VALIDATED: {target}")
            print(f"   Errors: {validation_report['errors']}")
        
        print()
    
    # Generate responsible report only for validated findings
    if validated_findings:
        print("📋 GENERATING RESPONSIBLE DISCLOSURE REPORT")
        print("✅ Only validated findings will be included")
        
        for i, finding in enumerate(validated_findings, 1):
            print(f"\n--- VALIDATED FINDING #{i} ---")
            report = validator.generate_responsible_report(finding)
            print(report[:500] + "..." if len(report) > 500 else report)
    else:
        print("❌ NO VALIDATED FINDINGS - No disclosure recommended")
    
    return validated_findings

if __name__ == "__main__":
    validate_oppo_targets()
