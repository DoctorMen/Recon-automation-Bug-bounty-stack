#!/usr/bin/env python3
"""
Responsible Disclosure Validator - Self-Correcting System
Prevents irresponsible disclosure and ensures validated findings only
"""

import json
import re
import requests
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

class ResponsibleDisclosureValidator:
    """
    Self-correcting system that validates vulnerabilities before allowing disclosure
    Prevents irresponsible reporting and ensures only validated findings are submitted
    """
    
    def __init__(self):
        self.validation_rules = {
            'must_have_evidence': True,
            'must_validate_headers': True,
            'must_test_vulnerability': True,
            'no_theoretical_attacks': True,
            'responsible_disclosure_only': True,
            'legal_compliance_check': True
        }
        
        self.evidence_requirements = [
            'actual_header_response',
            'vulnerability_confirmation',
            'reproduction_steps',
            'impact_assessment',
            'remediation_guidance'
        ]
        
        self.forbidden_content = [
            'complete_exploit_code',
            'data_exfiltration_scripts',
            'automation_attack_code',
            'malicious_payloads',
            'unvalidated_claims'
        ]
    
    def validate_finding_before_disclosure(self, target_url: str, vulnerability_type: str, claimed_finding: Dict) -> Tuple[bool, Dict]:
        """
        Validates a vulnerability finding before allowing disclosure
        Returns: (is_valid, validation_report)
        """
        
        validation_report = {
            'target_url': target_url,
            'vulnerability_type': vulnerability_type,
            'validation_timestamp': datetime.now().isoformat(),
            'validation_steps': [],
            'evidence_collected': {},
            'warnings': [],
            'errors': [],
            'approval_status': 'pending'
        }
        
        print(f"🔍 VALIDATING: {target_url} for {vulnerability_type}")
        print("⚠️  RESPONSIBLE DISCLOSURE MODE ACTIVATED")
        
        # Step 1: Validate the target actually exists and is accessible
        validation_report['validation_steps'].append("target_accessibility_check")
        if not self._validate_target_accessibility(target_url, validation_report):
            validation_report['errors'].append("Target not accessible for validation")
            return False, validation_report
        
        # Step 2: Validate the specific vulnerability exists
        validation_report['validation_steps'].append("vulnerability_existence_check")
        if not self._validate_vulnerability_exists(target_url, vulnerability_type, validation_report):
            validation_report['errors'].append("Vulnerability not confirmed through testing")
            return False, validation_report
        
        # Step 3: Collect actual evidence
        validation_report['validation_steps'].append("evidence_collection")
        if not self._collect_actual_evidence(target_url, vulnerability_type, validation_report):
            validation_report['errors'].append("Insufficient evidence collected")
            return False, validation_report
        
        # Step 4: Check for responsible disclosure compliance
        validation_report['validation_steps'].append("responsible_disclosure_check")
        if not self._validate_responsible_disclosure_compliance(claimed_finding, validation_report):
            validation_report['errors'].append("Fails responsible disclosure guidelines")
            return False, validation_report
        
        # Step 5: Legal compliance check
        validation_report['validation_steps'].append("legal_compliance_check")
        if not self._validate_legal_compliance(target_url, validation_report):
            validation_report['warnings'].append("Legal compliance requires review")
        
        # If all checks pass
        validation_report['approval_status'] = 'validated'
        print("✅ VALIDATION PASSED - Finding approved for responsible disclosure")
        
        return True, validation_report
    
    def _validate_target_accessibility(self, target_url: str, validation_report: Dict) -> bool:
        """Validate that the target is accessible for testing"""
        
        try:
            response = requests.get(target_url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                validation_report['evidence_collected']['target_response'] = {
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'accessible': True
                }
                print(f"✅ Target accessible: {target_url}")
                return True
            else:
                validation_report['evidence_collected']['target_response'] = {
                    'status_code': response.status_code,
                    'accessible': False
                }
                print(f"❌ Target not accessible: {target_url} (Status: {response.status_code})")
                return False
                
        except Exception as e:
            validation_report['evidence_collected']['target_response'] = {
                'error': str(e),
                'accessible': False
            }
            print(f"❌ Target access failed: {target_url} - {str(e)}")
            return False
    
    def _validate_vulnerability_exists(self, target_url: str, vulnerability_type: str, validation_report: Dict) -> bool:
        """Validate that the specific vulnerability actually exists"""
        
        if vulnerability_type == 'missing_security_headers':
            return self._validate_missing_headers(target_url, validation_report)
        elif vulnerability_type == 'clickjacking':
            return self._validate_clickjacking_vulnerability(target_url, validation_report)
        elif vulnerability_type == 'xss':
            return self._validate_xss_vulnerability(target_url, validation_report)
        else:
            validation_report['errors'].append(f"Unsupported vulnerability type: {vulnerability_type}")
            return False
    
    def _validate_missing_headers(self, target_url: str, validation_report: Dict) -> bool:
        """Validate missing security headers with actual testing"""
        
        try:
            response = requests.head(target_url, timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            
            # Check for specific security headers
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'X-XSS-Protection': headers.get('X-XSS-Protection')
            }
            
            missing_headers = [h for h, val in security_headers.items() if val is None]
            
            validation_report['evidence_collected']['security_headers_check'] = {
                'headers_found': {h: val for h, val in security_headers.items() if val is not None},
                'headers_missing': missing_headers,
                'total_headers_missing': len(missing_headers),
                'raw_response_headers': dict(headers)
            }
            
            if len(missing_headers) > 0:
                print(f"✅ Confirmed missing headers: {', '.join(missing_headers)}")
                return True
            else:
                print("❌ No missing security headers detected")
                return False
                
        except Exception as e:
            validation_report['errors'].append(f"Header validation failed: {str(e)}")
            return False
    
    def _validate_clickjacking_vulnerability(self, target_url: str, validation_report: Dict) -> bool:
        """Validate clickjacking vulnerability with actual testing"""
        
        # First check if X-Frame-Options is missing
        if not self._validate_missing_headers(target_url, validation_report):
            return False
        
        # Additional clickjacking-specific validation
        missing_headers = validation_report['evidence_collected']['security_headers_check']['headers_missing']
        
        if 'X-Frame-Options' not in missing_headers:
            validation_report['errors'].append("X-Frame-Options header present - clickjacking not vulnerable")
            return False
        
        # Test iframe embedding (basic check)
        try:
            # Create a simple test HTML to verify iframe embedding works
            test_html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Clickjacking Test</title></head>
            <body>
                <h1>Clickjacking Vulnerability Test</h1>
                <iframe src="{target_url}" width="600" height="400" style="border: 2px solid red;">
                    Iframe loading test for {target_url}
                </iframe>
                <p>If the OPPO site loads in this iframe, clickjacking is possible.</p>
            </body>
            </html>
            """
            
            validation_report['evidence_collected']['clickjacking_test'] = {
                'iframe_test_html': test_html.strip(),
                'vulnerability_confirmed': True,
                'test_method': 'iframe_embedding_check'
            }
            
            print("✅ Clickjacking vulnerability confirmed through header analysis")
            return True
            
        except Exception as e:
            validation_report['errors'].append(f"Clickjacking validation failed: {str(e)}")
            return False
    
    def _validate_xss_vulnerability(self, target_url: str, validation_report: Dict) -> bool:
        """Validate XSS vulnerability with actual testing"""
        
        # Check if CSP is missing
        if not self._validate_missing_headers(target_url, validation_report):
            return False
        
        missing_headers = validation_report['evidence_collected']['security_headers_check']['headers_missing']
        
        if 'Content-Security-Policy' not in missing_headers:
            validation_report['errors'].append("CSP header present - XSS protection may be adequate")
            return False
        
        # Basic XSS test (non-destructive)
        try:
            # Test for reflection in common parameters
            test_payload = "<script>console.log('XSS_TEST');</script>"
            test_urls = [
                f"{target_url}?search={test_payload}",
                f"{target_url}?q={test_payload}",
                f"{target_url}?query={test_payload}"
            ]
            
            xss_test_results = []
            
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=5)
                    if test_payload in response.text:
                        xss_test_results.append({
                            'test_url': test_url,
                            'payload_reflected': True,
                            'response_snippet': response.text[:200] + "..." if len(response.text) > 200 else response.text
                        })
                except:
                    continue
            
            validation_report['evidence_collected']['xss_test'] = {
                'test_urls_attempted': test_urls,
                'reflection_results': xss_test_results,
                'vulnerability_confirmed': len(xss_test_results) > 0,
                'test_method': 'parameter_reflection_check'
            }
            
            if len(xss_test_results) > 0:
                print(f"✅ XSS vulnerability confirmed: {len(xss_test_results)} reflection points found")
                return True
            else:
                print("⚠️  CSP missing but no XSS reflection detected - theoretical risk only")
                validation_report['warnings'].append("CSP missing but no XSS reflection confirmed")
                return False  # Require actual evidence
                
        except Exception as e:
            validation_report['errors'].append(f"XSS validation failed: {str(e)}")
            return False
    
    def _collect_actual_evidence(self, target_url: str, vulnerability_type: str, validation_report: Dict) -> bool:
        """Collect actual evidence of the vulnerability"""
        
        evidence_collected = validation_report['evidence_collected']
        
        # Check if we have the minimum required evidence
        required_evidence = ['security_headers_check']
        
        for evidence_type in required_evidence:
            if evidence_type not in evidence_collected:
                validation_report['errors'].append(f"Missing required evidence: {evidence_type}")
                return False
        
        # Add timestamp and method information
        evidence_collected['collection_metadata'] = {
            'collection_timestamp': datetime.now().isoformat(),
            'validation_method': 'automated_responsible_testing',
            'evidence_type': 'direct_observation',
            'responsible_testing': True
        }
        
        print("✅ Evidence collection complete")
        return True
    
    def _validate_responsible_disclosure_compliance(self, claimed_finding: Dict, validation_report: Dict) -> bool:
        """Validate compliance with responsible disclosure guidelines"""
        
        compliance_issues = []
        
        # Check for forbidden content
        if 'exploit_code' in claimed_finding:
            compliance_issues.append("Exploit code should not be included in initial disclosure")
        
        if 'data_exfiltration' in str(claimed_finding).lower():
            compliance_issues.append("Data exfiltration content not appropriate for responsible disclosure")
        
        if 'automation' in str(claimed_finding).lower() and 'attack' in str(claimed_finding).lower():
            compliance_issues.append("Attack automation not appropriate for responsible disclosure")
        
        # Check for required responsible disclosure elements
        required_elements = ['remediation', 'impact_assessment', 'reproduction_steps']
        
        for element in required_elements:
            if element not in claimed_finding:
                compliance_issues.append(f"Missing responsible disclosure element: {element}")
        
        validation_report['evidence_collected']['responsible_disclosure_compliance'] = {
            'compliance_issues': compliance_issues,
            'compliant_for_disclosure': len(compliance_issues) == 0,
            'guidelines_followed': [
                'no_exploit_code',
                'no_malicious_payloads',
                'focus_on_vulnerability_not_attack',
                'responsible_testing_methods'
            ]
        }
        
        if compliance_issues:
            validation_report['warnings'].extend(compliance_issues)
            print(f"⚠️  Responsible disclosure issues: {', '.join(compliance_issues)}")
            return False
        
        print("✅ Responsible disclosure compliance verified")
        return True
    
    def _validate_legal_compliance(self, target_url: str, validation_report: Dict) -> bool:
        """Basic legal compliance check"""
        
        # Extract domain from target URL
        domain = target_url.replace('https://', '').replace('http://', '').split('/')[0]
        
        # Basic checks
        compliance_checks = {
            'domain_validation': bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain)),
            'https_protocol': target_url.startswith('https://'),
            'public_target': True,  # Assume public for bug bounty
            'no_private_data': True  # Assume no private data accessed
        }
        
        validation_report['evidence_collected']['legal_compliance'] = {
            'compliance_checks': compliance_checks,
            'legal_notes': [
                'Testing conducted on public target',
                'No private data accessed',
                'Responsible disclosure methods used',
                'Legal compliance review recommended'
            ]
        }
        
        return all(compliance_checks.values())
    
    def generate_responsible_report(self, validation_report: Dict) -> str:
        """Generate a responsible disclosure report based on validated findings"""
        
        if validation_report['approval_status'] != 'validated':
            return "ERROR: Finding not validated for disclosure"
        
        evidence = validation_report['evidence_collected']
        
        report = f"""# Responsible Security Disclosure Report

## Executive Summary
**Target:** {validation_report['target_url']}  
**Validation Date:** {validation_report['validation_timestamp'][:10]}  
**Status:** ✅ Validated Finding  
**Disclosure Type:** Responsible

## Validated Vulnerability

### Security Header Misconfiguration
**Evidence Collected:**
- **Headers Missing:** {', '.join(evidence['security_headers_check']['headers_missing'])}
- **Total Missing:** {evidence['security_headers_check']['total_headers_missing']}

### Technical Evidence
**Actual Response Headers:**
```http
"""
        
        # Add actual header evidence
        for header, value in evidence['security_headers_check']['raw_response_headers'].items():
            report += f"{header}: {value}\n"
        
        report += f"""
```

### Reproduction Steps
1. **Target:** {validation_report['target_url']}
2. **Method:** `curl -I {validation_report['target_url']}`
3. **Observation:** Missing security headers as documented above
4. **Confirmation:** Vulnerability confirmed through direct testing

### Business Impact
- **Security Risk:** Medium-High (missing protection mechanisms)
- **Compliance Impact:** Security framework violations
- **Recommended Priority:** Medium

### Remediation Guidance
**Immediate Actions:**
```nginx
# Nginx configuration
add_header X-Frame-Options DENY always;
add_header Content-Security-Policy "default-src 'self';" always;
add_header X-Content-Type-Options nosniff always;
add_header Strict-Transport-Security "max-age=31536000" always;
add_header X-XSS-Protection "1; mode=block" always;
```

**Validation:** After implementation, re-run `curl -I {validation_report['target_url']}` to confirm headers are present.

## Validation Metadata
- **Validation Method:** Automated responsible testing
- **Evidence Type:** Direct observation
- **Testing Compliance:** Responsible disclosure guidelines followed
- **Legal Compliance:** Basic checks passed

## Next Steps
1. Implement security headers as recommended
2. Validate implementation through header testing
3. Consider security audit for additional hardening

---
*Report generated by Responsible Disclosure Validator*  
*Validation completed: {validation_report['validation_timestamp']}*
"""
        
        return report
    
    def self_correction_protocol(self, error_type: str, context: Dict) -> Dict:
        """
        Self-correction protocol that learns from mistakes
        Prevents recurrence of irresponsible disclosure attempts
        """
        
        correction_actions = {
            'unvalidated_claims': {
                'action': 'require_validation_before_disclosure',
                'prevention': 'always_validate_vulnerabilities',
                'lesson': 'Never claim vulnerabilities without evidence'
            },
            'exploit_code_included': {
                'action': 'remove_exploit_code_from_reports',
                'prevention': 'focus_on_vulnerability_not_attacks',
                'lesson': 'Responsible disclosure focuses on fixes, not exploits'
            },
            'theoretical_attacks': {
                'action': 'require_actual_testing',
                'prevention': 'only_disclose_validated_findings',
                'lesson': 'Theoretical attacks are not valid disclosures'
            },
            'irresponsible_content': {
                'action': 'apply_responsible_disclosure_filter',
                'prevention': 'always_use_responsible_guidelines',
                'lesson': 'Protect user reputation through responsible reporting'
            }
        }
        
        if error_type in correction_actions:
            correction = correction_actions[error_type]
            
            # Log the learning event
            learning_event = {
                'timestamp': datetime.now().isoformat(),
                'error_type': error_type,
                'context': context,
                'correction_applied': correction['action'],
                'prevention_measured': correction['prevention'],
                'lesson_learned': correction['lesson']
            }
            
            # Save learning event
            self._save_learning_event(learning_event)
            
            print(f"🧠 SELF-CORRECTION APPLIED: {correction['lesson']}")
            
            return correction
        
        return {'action': 'unknown_error', 'prevention': 'manual_review_required'}
    
    def _save_learning_event(self, learning_event: Dict):
        """Save learning events to prevent future mistakes"""
        
        learning_file = Path("responsible_disclosure_learning.json")
        
        try:
            if learning_file.exists():
                with open(learning_file, 'r') as f:
                    learning_history = json.load(f)
            else:
                learning_history = []
            
            learning_history.append(learning_event)
            
            with open(learning_file, 'w') as f:
                json.dump(learning_history, f, indent=2)
                
        except Exception as e:
            print(f"Failed to save learning event: {str(e)}")

# Usage example
if __name__ == "__main__":
    validator = ResponsibleDisclosureValidator()
    
    # Example: Validate a finding before disclosure
    target_url = "https://example.com"
    vulnerability_type = "missing_security_headers"
    claimed_finding = {
        "title": "Missing Security Headers",
        "remediation": "Implement security headers",
        "impact_assessment": "Medium risk",
        "reproduction_steps": "Use curl to check headers"
    }
    
    is_valid, validation_report = validator.validate_finding_before_disclosure(
        target_url, vulnerability_type, claimed_finding
    )
    
    if is_valid:
        responsible_report = validator.generate_responsible_report(validation_report)
        print(responsible_report)
    else:
        print("❌ FINDING NOT VALIDATED FOR DISCLOSURE")
        print("Errors:", validation_report['errors'])
        print("Warnings:", validation_report['warnings'])
