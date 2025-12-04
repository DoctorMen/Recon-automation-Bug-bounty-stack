#!/usr/bin/env python3
"""
Professional Vulnerability Disclosure Template
Industry-standard bug bounty submission format with validated evidence
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

class ProfessionalDisclosureTemplate:
    """
    Creates professional vulnerability disclosure reports
    Following industry standards for responsible disclosure
    """
    
    def __init__(self):
        self.template_structure = {
            'report_metadata': {},
            'vulnerability_summary': {},
            'detailed_findings': {},
            'proof_of_vulnerability': {},
            'reproduction_steps': [],
            'business_impact': {},
            'remediation_guidance': {},
            'compliance_impact': {},
            'researcher_info': {}
        }
    
    def create_disclosure_report(self, validation_result: Dict, researcher_info: Dict = None) -> Dict:
        """
        Create professional disclosure report from validation results
        
        Args:
            validation_result: Results from VulnerabilityValidator
            researcher_info: Optional researcher information
            
        Returns:
            Complete professional disclosure report
        """
        
        report = self.template_structure.copy()
        
        # Report metadata
        report['report_metadata'] = {
            'report_id': f"VULN-{validation_result['session_id'].upper()}",
            'target_url': validation_result['target_url'],
            'vulnerability_type': validation_result['vulnerability_type'],
            'severity': validation_result.get('proof_of_vulnerability', {}).get('severity', 'medium'),
            'discovery_date': validation_result['validation_timestamp'],
            'report_date': datetime.now().isoformat(),
            'status': 'new'
        }
        
        # Vulnerability summary
        report['vulnerability_summary'] = {
            'title': self._generate_title(validation_result),
            'description': validation_result.get('proof_of_vulnerability', {}).get('impact_description', ''),
            'affected_endpoint': validation_result['endpoint_tested'],
            'cvss_score': self._calculate_cvss(validation_result),
            'cwe_id': self._get_cwe_id(validation_result['vulnerability_type']),
            'owasp_category': self._get_owasp_category(validation_result['vulnerability_type'])
        }
        
        # Detailed findings
        report['detailed_findings'] = {
            'validation_status': validation_result['validation_status'],
            'technical_analysis': validation_result['evidence'],
            'root_cause': self._identify_root_cause(validation_result),
            'attack_vector': self._describe_attack_vector(validation_result),
            'conditions_required': self._list_conditions(validation_result)
        }
        
        # Proof of vulnerability
        report['proof_of_vulnerability'] = {
            'evidence_type': 'automated_validation',
            'validation_method': 'VulnerabilityValidator Framework',
            'test_results': validation_result['evidence'],
            'screenshots': [],  # Would be populated with actual screenshots
            'network_logs': [],  # Would be populated with actual logs
            'console_output': [],  # Would be populated with actual output
            'validation_confidence': 'high'
        }
        
        # Reproduction steps
        report['reproduction_steps'] = validation_result['reproduction_steps']
        
        # Business impact
        report['business_impact'] = {
            'technical_impact': validation_result.get('proof_of_vulnerability', {}).get('exploit_scenario', ''),
            'business_risk': validation_result.get('proof_of_vulnerability', {}).get('business_impact', ''),
            'affected_assets': self._identify_affected_assets(validation_result),
            'potential_damage': self._assess_potential_damage(validation_result),
            'compliance_risk': validation_result['responsible_disclosure'].get('compliance_impact', [])
        }
        
        # Remediation guidance
        report['remediation_guidance'] = {
            'immediate_actions': self._get_immediate_actions(validation_result),
            'long_term_fixes': self._get_long_term_fixes(validation_result),
            'code_examples': self._provide_code_examples(validation_result),
            'testing_procedures': self._suggest_testing_procedures(validation_result),
            'deployment_considerations': self._list_deployment_considerations(validation_result)
        }
        
        # Compliance impact
        report['compliance_impact'] = {
            'affected_standards': validation_result['responsible_disclosure'].get('compliance_impact', []),
            'regulatory_implications': self._assess_regulatory_implications(validation_result),
            'audit_failures': self._identify_audit_failures(validation_result),
            'legal_exposure': self._assess_legal_exposure(validation_result)
        }
        
        # Researcher information
        report['researcher_info'] = researcher_info or {
            'name': 'Security Researcher',
            'contact_method': 'Platform messaging',
            'preferred_communication': 'Platform messaging',
            'availability_for_questions': 'Yes'
        }
        
        return report
    
    def _generate_title(self, validation_result: Dict) -> str:
        """Generate professional vulnerability title"""
        
        vuln_type = validation_result['vulnerability_type'].title()
        endpoint = validation_result['endpoint_tested']
        
        titles = {
            'clickjacking': f'Clickjacking Vulnerability in {endpoint}',
            'xss': f'Cross-Site Scripting (XSS) in {endpoint}',
            'missing_csp': f'Missing Content Security Policy in {endpoint}',
            'missing_hsts': f'Missing HSTS Header in {endpoint}',
            'csrf': f'Cross-Site Request Forgery (CSRF) in {endpoint}',
            'idor': f'Insecure Direct Object Reference (IDOR) in {endpoint}',
            'ssrf': f'Server-Side Request Forgery (SSRF) in {endpoint}'
        }
        
        return titles.get(validation_result['vulnerability_type'].lower(), f'{vuln_type} in {endpoint}')
    
    def _calculate_cvss(self, validation_result: Dict) -> Dict:
        """Calculate CVSS score based on vulnerability"""
        
        severity = validation_result.get('proof_of_vulnerability', {}).get('severity', 'medium')
        
        cvss_scores = {
            'critical': {'base_score': 9.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'},
            'high': {'base_score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'},
            'medium': {'base_score': 5.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'},
            'low': {'base_score': 3.0, 'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L'}
        }
        
        return cvss_scores.get(severity, cvss_scores['medium'])
    
    def _get_cwe_id(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        
        cwe_mapping = {
            'clickjacking': 'CWE-451',
            'xss': 'CWE-79',
            'missing_csp': 'CWE-693',
            'missing_hsts': 'CWE-319',
            'csrf': 'CWE-352',
            'idor': 'CWE-639',
            'ssrf': 'CWE-918'
        }
        
        return cwe_mapping.get(vuln_type.lower(), 'CWE-16')
    
    def _get_owasp_category(self, vuln_type: str) -> str:
        """Get OWASP Top 10 category"""
        
        owasp_mapping = {
            'clickjacking': 'A05:2021 - Security Misconfiguration',
            'xss': 'A03:2021 - Injection',
            'missing_csp': 'A05:2021 - Security Misconfiguration',
            'missing_hsts': 'A02:2021 - Cryptographic Failures',
            'csrf': 'A01:2021 - Broken Access Control',
            'idor': 'A01:2021 - Broken Access Control',
            'ssrf': 'A10:2021 - Server-Side Request Forgery'
        }
        
        return owasp_mapping.get(vuln_type.lower(), 'A00:2021 - Unknown')
    
    def _identify_root_cause(self, validation_result: Dict) -> str:
        """Identify root cause of vulnerability"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        root_causes = {
            'clickjacking': 'Missing X-Frame-Options header and/or CSP frame-ancestors directive',
            'xss': 'Lack of input validation and output encoding, missing CSP protection',
            'missing_csp': 'No Content Security Policy header implemented',
            'missing_hsts': 'No Strict-Transport-Security header configured',
            'csrf': 'Missing anti-CSRF tokens and inadequate SameSite cookie protection',
            'idor': 'Insufficient access control validation on object references',
            'ssrf': 'Insufficient URL validation allows internal network access'
        }
        
        return root_causes.get(vuln_type, 'Security control weakness')
    
    def _describe_attack_vector(self, validation_result: Dict) -> str:
        """Describe attack vector"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        vectors = {
            'clickjacking': 'Attacker creates malicious page with invisible iframe containing target, overlays deceptive UI elements to hijack user clicks',
            'xss': 'Attacker injects malicious scripts through input parameters that execute in victim\'s browser',
            'missing_csp': 'Attacker can inject and execute scripts due to lack of CSP restrictions',
            'missing_hsts': 'Attacker can perform SSL stripping attacks to downgrade HTTPS to HTTP',
            'csrf': 'Attacker crafts malicious requests that execute with victim\'s authentication context',
            'idor': 'Attacker modifies object identifiers to access unauthorized data',
            'ssrf': 'Attacker manipulates server to make requests to internal network resources'
        }
        
        return vectors.get(vuln_type, 'Security weakness exploitation')
    
    def _list_conditions(self, validation_result: Dict) -> List[str]:
        """List conditions required for exploitation"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        conditions = {
            'clickjacking': [
                'User visits malicious website',
                'User is logged into target application',
                'User clicks on deceptive UI elements'
            ],
            'xss': [
                'User visits vulnerable page with injected payload',
                'Payload executes in browser context',
                'No CSP restrictions block execution'
            ],
            'missing_csp': [
                'Attacker can inject scripts through any input vector',
                'Scripts execute without CSP restrictions',
                'Browser allows script execution'
            ],
            'missing_hsts': [
                'User connects over HTTP initially',
                'Attacker can perform MITM attack',
                'SSL stripping successful'
            ],
            'csrf': [
                'User is authenticated to target application',
                'User visits malicious website',
                'Malicious request triggers action'
            ],
            'idor': [
                'Attacker guesses or enumerates object IDs',
                'No proper access control validation',
                'Server returns unauthorized data'
            ],
            'ssrf': [
                'Application accepts URLs as input',
                'Server makes requests to provided URLs',
                'Insufficient URL validation'
            ]
        }
        
        return conditions.get(vuln_type, ['Security control weakness'])
    
    def _identify_affected_assets(self, validation_result: Dict) -> List[str]:
        """Identify affected assets"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        assets = {
            'clickjacking': ['User interface', 'Authentication flows', 'Administrative functions'],
            'xss': ['User sessions', 'Browser data', 'Application functionality'],
            'missing_csp': ['Application security', 'User data', 'System integrity'],
            'missing_hsts': ['Data in transit', 'User credentials', 'Session tokens'],
            'csrf': ['User accounts', 'Application state', 'Business operations'],
            'idor': ['User data', 'Sensitive information', 'System resources'],
            'ssrf': ['Internal network', 'Cloud infrastructure', 'System files']
        }
        
        return assets.get(vuln_type, ['Application security'])
    
    def _assess_potential_damage(self, validation_result: Dict) -> Dict:
        """Assess potential damage"""
        
        severity = validation_result.get('proof_of_vulnerability', {}).get('severity', 'medium')
        
        damage_levels = {
            'critical': {
                'data_exposure': 'Complete system compromise possible',
                'financial_impact': '$100K - $1M+',
                'reputation_impact': 'Severe',
                'operational_impact': 'Service disruption'
            },
            'high': {
                'data_exposure': 'Sensitive data exposure',
                'financial_impact': '$10K - $100K',
                'reputation_impact': 'High',
                'operational_impact': 'Partial service impact'
            },
            'medium': {
                'data_exposure': 'Limited data exposure',
                'financial_impact': '$1K - $10K',
                'reputation_impact': 'Moderate',
                'operational_impact': 'Minimal impact'
            },
            'low': {
                'data_exposure': 'Minimal data exposure',
                'financial_impact': '$0 - $1K',
                'reputation_impact': 'Low',
                'operational_impact': 'No impact'
            }
        }
        
        return damage_levels.get(severity, damage_levels['medium'])
    
    def _get_immediate_actions(self, validation_result: Dict) -> List[str]:
        """Get immediate remediation actions"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        immediate_actions = {
            'clickjacking': [
                'Add X-Frame-Options: DENY or SAMEORIGIN header',
                'Implement CSP frame-ancestors directive',
                'Review iframe usage in application'
            ],
            'xss': [
                'Implement input validation and output encoding',
                'Add Content Security Policy header',
                'Review all user input handling'
            ],
            'missing_csp': [
                'Implement comprehensive Content Security Policy',
                'Start with restrictive policy and whitelist needed sources',
                'Test policy thoroughly before deployment'
            ],
            'missing_hsts': [
                'Add Strict-Transport-Security header',
                'Set appropriate max-age (minimum 6 months)',
                'Consider includeSubDomains and preload'
            ],
            'csrf': [
                'Implement anti-CSRF tokens in all forms',
                'Set SameSite cookie attributes',
                'Verify state-changing requests'
            ],
            'idor': [
                'Implement proper access control checks',
                'Validate user permissions for all object access',
                'Use indirect references to sensitive resources'
            ],
            'ssrf': [
                'Implement URL validation and allowlisting',
                'Block internal network ranges',
                'Use dedicated HTTP client with restrictions'
            ]
        }
        
        return immediate_actions.get(vuln_type, ['Review and implement appropriate security controls'])
    
    def _get_long_term_fixes(self, validation_result: Dict) -> List[str]:
        """Get long-term fixes"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        long_term_fixes = {
            'clickjacking': [
                'Implement comprehensive clickjacking protection framework',
                'Regular security header audits',
                'Security awareness training for developers'
            ],
            'xss': [
                'Implement secure coding practices',
                'Regular code reviews for injection vulnerabilities',
                'Automated security testing in CI/CD'
            ],
            'missing_csp': [
                'Develop CSP deployment strategy',
                'Regular CSP policy reviews',
                'Content Security Policy monitoring'
            ],
            'missing_hsts': [
                'Implement HTTPS everywhere strategy',
                'HSTS preloading submission',
                'Regular TLS configuration audits'
            ],
            'csrf': [
                'Implement comprehensive CSRF protection framework',
                'Session management improvements',
                'Regular access control testing'
            ],
            'idor': [
                'Implement role-based access control (RBAC)',
                'Regular authorization testing',
                'Secure API design patterns'
            ],
            'ssrf': [
                'Implement network segmentation',
                'Regular network security assessments',
                'Secure third-party integration practices'
            ]
        }
        
        return long_term_fixes.get(vuln_type, ['Implement comprehensive security framework'])
    
    def _provide_code_examples(self, validation_result: Dict) -> Dict:
        """Provide code examples for remediation"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        code_examples = {
            'clickjacking': {
                'nginx': 'add_header X-Frame-Options DENY;',
                'apache': 'Header always set X-Frame-Options DENY',
                'csp': "Content-Security-Policy: frame-ancestors 'none';"
            },
            'xss': {
                'python': 'html.escape(user_input)',
                'javascript': 'textContent instead of innerHTML',
                'csp': "Content-Security-Policy: script-src 'self';"
            },
            'missing_hsts': {
                'nginx': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                'apache': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
            },
            'csrf': {
                'django': '{% csrf_token %}',
                'express': 'app.use(csrf({ cookie: { sameSite: \'strict\' } }));',
                'same_site': 'Set-Cookie: session=...; SameSite=Strict'
            }
        }
        
        return code_examples.get(vuln_type, {'general': 'Implement appropriate security controls for the vulnerability type'})
    
    def _suggest_testing_procedures(self, validation_result: Dict) -> List[str]:
        """Suggest testing procedures"""
        
        return [
            'Deploy fix to staging environment',
            'Run automated vulnerability scans',
            'Perform manual testing with reproduction steps',
            'Verify fix does not break functionality',
            'Monitor for regression in production'
        ]
    
    def _list_deployment_considerations(self, validation_result: Dict) -> List[str]:
        """List deployment considerations"""
        
        return [
            'Test in non-production environment first',
            'Consider impact on existing functionality',
            'Plan rollback procedure if issues arise',
            'Monitor application performance after deployment',
            'Document changes for security audit'
        ]
    
    def _assess_regulatory_implications(self, validation_result: Dict) -> Dict:
        """Assess regulatory implications"""
        
        compliance = validation_result['responsible_disclosure'].get('compliance_impact', [])
        
        implications = {
            'GDPR': 'Potential violation if personal data exposed',
            'PCI-DSS': 'Non-compliance if payment data affected',
            'HIPAA': 'Potential violation if health data exposed',
            'SOC 2': 'Security control deficiency identified',
            'NIST CSF': 'Control gap in security framework'
        }
        
        return {standard: implications.get(standard, 'Compliance impact identified') for standard in compliance}
    
    def _identify_audit_failures(self, validation_result: Dict) -> List[str]:
        """Identify potential audit failures"""
        
        vuln_type = validation_result['vulnerability_type'].lower()
        
        audit_failures = {
            'xss': ['Input validation controls', 'Output encoding controls', 'Web application security'],
            'csrf': ['Access control testing', 'Session management', 'Request validation'],
            'idor': ['Authorization testing', 'Access control matrix', 'Data classification'],
            'ssrf': ['Network security', 'Input validation', 'System integration']
        }
        
        return audit_failures.get(vuln_type, ['Security control deficiency'])
    
    def _assess_legal_exposure(self, validation_result: Dict) -> Dict:
        """Assess legal exposure"""
        
        severity = validation_result.get('proof_of_vulnerability', {}).get('severity', 'medium')
        
        exposure_levels = {
            'critical': {
                'data_breach_laws': 'High probability of triggering breach notification requirements',
                'negligence_claims': 'Potential negligence claims for inadequate security',
                'regulatory_fines': 'Potential for significant regulatory penalties'
            },
            'high': {
                'data_breach_laws': 'Possible breach notification requirements',
                'negligence_claims': 'Moderate risk of negligence claims',
                'regulatory_fines': 'Potential for moderate penalties'
            },
            'medium': {
                'data_breach_laws': 'Low probability of breach notification',
                'negligence_claims': 'Low risk of negligence claims',
                'regulatory_fines': 'Minimal regulatory risk'
            },
            'low': {
                'data_breach_laws': 'Unlikely to trigger breach laws',
                'negligence_claims': 'Very low risk',
                'regulatory_fines': 'Minimal to no risk'
            }
        }
        
        return exposure_levels.get(severity, exposure_levels['medium'])
    
    def format_for_platform(self, report: Dict, platform: str) -> str:
        """Format report for specific bug bounty platform"""
        
        if platform.lower() == 'hackerone':
            return self._format_hackerone(report)
        elif platform.lower() == 'bugcrowd':
            return self._format_bugcrowd(report)
        elif platform.lower() == 'intigriti':
            return self._format_intigriti(report)
        else:
            return self._format_generic(report)
    
    def _format_hackerone(self, report: Dict) -> str:
        """Format for HackerOne platform"""
        
        formatted = f"""
# {report['vulnerability_summary']['title']}

## Vulnerability Type
{report['vulnerability_summary']['description']}

## Severity
{report['report_metadata']['severity'].upper()}

## Affected URL
{report['report_metadata']['target_url']}

## CVSS Score
{report['vulnerability_summary']['cvss_score']['base_score']} - {report['vulnerability_summary']['cvss_score']['vector']}

## CWE ID
{report['vulnerability_summary']['cwe_id']}

## OWASP Category
{report['vulnerability_summary']['owasp_category']}

## Detailed Description
{report['detailed_findings']['root_cause']}

## Proof of Concept
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(report['reproduction_steps']))}

## Business Impact
{report['business_impact']['business_risk']}

## Remediation
{chr(10).join(f"- {action}" for action in report['remediation_guidance']['immediate_actions'])}

## Timeline
- **Discovery**: {report['report_metadata']['discovery_date']}
- **Report**: {report['report_metadata']['report_date']}
        """
        
        return formatted.strip()
    
    def _format_bugcrowd(self, report: Dict) -> str:
        """Format for Bugcrowd platform"""
        
        formatted = f"""
**Vulnerability Summary:**
{report['vulnerability_summary']['title']}

**Description:**
{report['vulnerability_summary']['description']}

**Severity:** {report['report_metadata']['severity'].upper()}
**CVSS:** {report['vulnerability_summary']['cvss_score']['base_score']}

**Affected Endpoint:** {report['vulnerability_summary']['affected_endpoint']}

**Steps to Reproduce:**
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(report['reproduction_steps']))}

**Evidence:**
Validation confirmed through automated testing framework.

**Business Impact:**
{report['business_impact']['business_risk']}

**Recommendations:**
{chr(10).join(f"• {action}" for action in report['remediation_guidance']['immediate_actions'])}
        """
        
        return formatted.strip()
    
    def _format_intigriti(self, report: Dict) -> str:
        """Format for Intigriti platform"""
        
        formatted = f"""
**Vulnerability Details**

**Type:** {report['vulnerability_summary']['title']}
**Severity:** {report['report_metadata']['severity'].upper()}
**CWE:** {report['vulnerability_summary']['cwe_id']}

**Description:**
{report['vulnerability_summary']['description']}

**Affected URL:** {report['report_metadata']['target_url']}

**Proof of Concept:**
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(report['reproduction_steps']))}

**Impact Analysis:**
{report['business_impact']['business_risk']}

**Remediation Advice:**
{chr(10).join(f"- {action}" for action in report['remediation_guidance']['immediate_actions'])}
        """
        
        return formatted.strip()
    
    def _format_generic(self, report: Dict) -> str:
        """Generic format for any platform"""
        
        return json.dumps(report, indent=2, default=str)

# Usage example
if __name__ == "__main__":
    # Create disclosure template
    template = ProfessionalDisclosureTemplate()
    
    # Sample validation result
    validation_result = {
        'session_id': 'abc123',
        'target_url': 'https://example.com',
        'vulnerability_type': 'xss',
        'endpoint_tested': 'https://example.com/search',
        'validation_timestamp': '2025-01-01T12:00:00',
        'validation_status': 'vulnerable',
        'evidence': {'test': 'data'},
        'reproduction_steps': ['Step 1', 'Step 2', 'Step 3'],
        'proof_of_vulnerability': {
            'severity': 'high',
            'impact_description': 'XSS vulnerability allows script injection',
            'exploit_scenario': 'Session hijacking through script injection',
            'business_impact': 'Account takeover and data theft'
        },
        'responsible_disclosure': {
            'compliance_impact': ['OWASP Top 10', 'PCI-DSS', 'GDPR']
        }
    }
    
    # Create disclosure report
    report = template.create_disclosure_report(validation_result)
    
    # Format for HackerOne
    hackerone_report = template.format_for_platform(report, 'hackerone')
    print("HackerOne Report:")
    print(hackerone_report)
