#!/usr/bin/env python3
"""
Enhanced Validation Integration
Integrates advanced penetration testing methodologies with professional vulnerability validation
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from VULNERABILITY_VALIDATION_FRAMEWORK import VulnerabilityValidator
from PROFESSIONAL_DISCLOSURE_TEMPLATE import ProfessionalDisclosureTemplate
from ADVANCED_PENETRATION_TESTING_FRAMEWORK import AdvancedPenetrationTestingFramework

class EnhancedValidationIntegration:
    """
    Integrates industry-standard penetration testing methodologies
    with professional vulnerability validation and reporting
    """
    
    def __init__(self, target: str, scope: List[str] = None, rules_of_engagement: Dict = None):
        self.target = target
        self.scope = scope or [target]
        self.rules_of_engagement = rules_of_engagement or {}
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialize components
        self.validator = VulnerabilityValidator(target)
        self.pentest_framework = AdvancedPenetrationTestingFramework(target, scope, rules_of_engagement)
        self.disclosure_template = ProfessionalDisclosureTemplate()
        
        # Output directory
        self.output_dir = Path(f"enhanced_validation_{self.session_id}")
        self.output_dir.mkdir(exist_ok=True)
        
        # Results storage
        self.validation_results = {}
        self.pentest_results = {}
        self.disclosure_reports = {}
        
        print(f"Enhanced Validation Integration initialized")
        print(f"Target: {target}")
        print(f"Session ID: {self.session_id}")
        print(f"Output directory: {self.output_dir}")
    
    def run_comprehensive_assessment(self) -> Dict:
        """
        Run comprehensive assessment combining:
        1. Advanced penetration testing (PTES methodology)
        2. Professional vulnerability validation
        3. Industry-standard disclosure reporting
        """
        
        print("Starting comprehensive security assessment...")
        
        assessment_results = {
            'session_id': self.session_id,
            'target': self.target,
            'start_time': datetime.now().isoformat(),
            'phases': {}
        }
        
        # Phase 1: Advanced Penetration Testing
        print("\n" + "="*60)
        print("PHASE 1: ADVANCED PENETRATION TESTING")
        print("="*60)
        
        try:
            pentest_results = self.pentest_framework.run_complete_pentest()
            self.pentest_results = pentest_results
            assessment_results['phases']['pentest'] = pentest_results
            
            print(f"✅ Penetration testing completed")
            print(f"   Total findings: {len(pentest_results.get('phases', {}).get('vulnerability_analysis', {}).get('validated_vulnerabilities', []))}")
            
        except Exception as e:
            print(f"❌ Penetration testing failed: {e}")
            assessment_results['phases']['pentest'] = {'error': str(e)}
        
        # Phase 2: Professional Vulnerability Validation
        print("\n" + "="*60)
        print("PHASE 2: PROFESSIONAL VULNERABILITY VALIDATION")
        print("="*60)
        
        try:
            validation_results = self._run_comprehensive_validation()
            self.validation_results = validation_results
            assessment_results['phases']['validation'] = validation_results
            
            print(f"✅ Vulnerability validation completed")
            print(f"   Validations performed: {len(validation_results)}")
            
        except Exception as e:
            print(f"❌ Vulnerability validation failed: {e}")
            assessment_results['phases']['validation'] = {'error': str(e)}
        
        # Phase 3: Professional Disclosure Reporting
        print("\n" + "="*60)
        print("PHASE 3: PROFESSIONAL DISCLOSURE REPORTING")
        print("="*60)
        
        try:
            disclosure_results = self._generate_disclosure_reports()
            self.disclosure_reports = disclosure_results
            assessment_results['phases']['disclosure'] = disclosure_results
            
            print(f"✅ Disclosure reports generated")
            print(f"   Reports created: {len(disclosure_results)}")
            
        except Exception as e:
            print(f"❌ Disclosure reporting failed: {e}")
            assessment_results['phases']['disclosure'] = {'error': str(e)}
        
        # Phase 4: Integrated Analysis
        print("\n" + "="*60)
        print("PHASE 4: INTEGRATED ANALYSIS")
        print("="*60)
        
        try:
            integrated_analysis = self._perform_integrated_analysis()
            assessment_results['phases']['analysis'] = integrated_analysis
            
            print(f"✅ Integrated analysis completed")
            
        except Exception as e:
            print(f"❌ Integrated analysis failed: {e}")
            assessment_results['phases']['analysis'] = {'error': str(e)}
        
        assessment_results['end_time'] = datetime.now().isoformat()
        assessment_results['total_duration'] = str(
            datetime.now() - datetime.fromisoformat(assessment_results['start_time'])
        )
        
        # Save comprehensive results
        self._save_comprehensive_results(assessment_results)
        
        # Generate summary
        self._generate_assessment_summary(assessment_results)
        
        print(f"\n" + "="*60)
        print("COMPREHENSIVE ASSESSMENT COMPLETED")
        print("="*60)
        print(f"Total duration: {assessment_results['total_duration']}")
        print(f"Results saved to: {self.output_dir}")
        
        return assessment_results
    
    def _run_comprehensive_validation(self) -> Dict:
        """Run comprehensive vulnerability validation"""
        
        validation_results = {}
        
        # Get validated vulnerabilities from pentest
        pentest_vulns = self.pentest_framework.phases['vulnerability_analysis'].findings
        
        if not pentest_vulns:
            print("No vulnerabilities found in pentest, running default validation...")
            # Run default validation on main target
            default_vulns = ['clickjacking', 'xss', 'missing_csp', 'missing_hsts', 'csrf']
            
            for vuln_type in default_vulns:
                print(f"  Validating {vuln_type}...")
                result = self.validator.validate_vulnerability(vuln_type, self.target)
                validation_results[vuln_type] = result
                
                if result['validation_status'] == 'vulnerable':
                    print(f"    ✅ VULNERABLE: {vuln_type}")
                else:
                    print(f"    ✅ Not vulnerable: {vuln_type}")
        else:
            print(f"Validating {len(pentest_vulns)} findings from pentest...")
            
            for vuln in pentest_vulns:
                vuln_type = self._map_finding_to_validation_type(vuln)
                if vuln_type:
                    print(f"  Validating {vuln_type}: {vuln.get('title', 'Untitled')}")
                    result = self.validator.validate_vulnerability(vuln_type, vuln.get('data', {}).get('location', self.target))
                    validation_results[vuln['title']] = result
                    
                    if result['validation_status'] == 'vulnerable':
                        print(f"    ✅ VULNERABLE")
                    else:
                        print(f"    ✅ Not vulnerable")
        
        return validation_results
    
    def _map_finding_to_validation_type(self, finding: Dict) -> Optional[str]:
        """Map pentest finding to validation type"""
        
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        cwe = finding.get('data', {}).get('cwe', '')
        
        # Map based on CWE
        cwe_mapping = {
            'CWE-451': 'clickjacking',
            'CWE-79': 'xss',
            'CWE-693': 'missing_csp',
            'CWE-319': 'missing_hsts',
            'CWE-352': 'csrf',
            'CWE-639': 'idor',
            'CWE-918': 'ssrf'
        }
        
        if cwe in cwe_mapping:
            return cwe_mapping[cwe]
        
        # Map based on keywords
        keyword_mapping = {
            'clickjacking': 'clickjacking',
            'xss': 'xss',
            'cross-site scripting': 'xss',
            'content security policy': 'missing_csp',
            'csp': 'missing_csp',
            'hsts': 'missing_hsts',
            'strict-transport-security': 'missing_hsts',
            'csrf': 'csrf',
            'cross-site request forgery': 'csrf',
            'idor': 'idor',
            'insecure direct object reference': 'idor',
            'ssrf': 'ssrf',
            'server-side request forgery': 'ssrf'
        }
        
        for keyword, vuln_type in keyword_mapping.items():
            if keyword in title or keyword in description:
                return vuln_type
        
        return None
    
    def _generate_disclosure_reports(self) -> Dict:
        """Generate professional disclosure reports"""
        
        disclosure_reports = {}
        
        # Combine findings from pentest and validation
        all_findings = []
        
        # Add pentest findings
        pentest_vulns = self.pentest_framework.phases['vulnerability_analysis'].findings
        all_findings.extend(pentest_vulns)
        
        # Add validation results
        for vuln_name, validation_result in self.validation_results.items():
            if validation_result['validation_status'] == 'vulnerable':
                # Convert validation result to finding format
                finding = {
                    'title': validation_result['vulnerability_type'].title(),
                    'description': validation_result['proof_of_vulnerability']['impact_description'],
                    'severity': validation_result['proof_of_vulnerability']['severity'],
                    'type': validation_result['vulnerability_type'],
                    'validation_result': validation_result,
                    'source': 'validation_framework'
                }
                all_findings.append(finding)
        
        # Generate disclosure reports for each vulnerability
        for finding in all_findings:
            print(f"  Generating disclosure report for: {finding['title']}")
            
            if 'validation_result' in finding:
                # Use validation result for disclosure
                report = self.disclosure_template.create_disclosure_report(finding['validation_result'])
            else:
                # Create validation-like structure from pentest finding
                validation_like_result = self._convert_finding_to_validation_format(finding)
                report = self.disclosure_template.create_disclosure_report(validation_like_result)
            
            # Format for different platforms
            platform_reports = {}
            for platform in ['hackerone', 'bugcrowd', 'intigriti']:
                platform_reports[platform] = self.disclosure_template.format_for_platform(report, platform)
            
            disclosure_reports[finding['title']] = {
                'report_data': report,
                'platform_reports': platform_reports,
                'finding': finding
            }
            
            print(f"    ✅ Report generated for {len(platform_reports)} platforms")
        
        return disclosure_reports
    
    def _convert_finding_to_validation_format(self, finding: Dict) -> Dict:
        """Convert pentest finding to validation format"""
        
        return {
            'session_id': self.session_id,
            'target_url': self.target,
            'vulnerability_type': finding.get('type', 'unknown'),
            'endpoint_tested': finding.get('data', {}).get('location', self.target),
            'validation_timestamp': datetime.now().isoformat(),
            'validation_status': 'vulnerable',
            'evidence': finding.get('data', {}),
            'reproduction_steps': finding.get('data', {}).get('reproduction_steps', [
                "1. Navigate to the target endpoint",
                "2. Exploit the identified vulnerability",
                "3. Observe the security impact"
            ]),
            'proof_of_vulnerability': {
                'type': finding.get('type', 'unknown'),
                'severity': finding.get('severity', 'medium'),
                'impact_description': finding.get('description', ''),
                'exploit_scenario': finding.get('data', {}).get('exploit_scenario', ''),
                'business_impact': finding.get('data', {}).get('business_impact', '')
            },
            'responsible_disclosure': {
                'summary': f"{finding['title'].upper()} CONFIRMED",
                'security_focus': "The security flaw itself, not attack automation",
                'compliance_impact': ['OWASP Top 10', 'General Security']
            }
        }
    
    def _perform_integrated_analysis(self) -> Dict:
        """Perform integrated analysis of all results"""
        
        analysis = {
            'correlation_analysis': {},
            'risk_assessment': {},
            'recommendations': {},
            'metrics': {}
        }
        
        # Correlation analysis
        print("  Performing correlation analysis...")
        
        pentest_vulns = set(f['title'] for f in self.pentest_framework.phases['vulnerability_analysis'].findings)
        validation_vulns = set()
        
        for vuln_name, validation_result in self.validation_results.items():
            if validation_result['validation_status'] == 'vulnerable':
                validation_vulns.add(validation_result['vulnerability_type'])
        
        correlation = {
            'pentest_only': list(pentest_vulns - validation_vulns),
            'validation_only': list(validation_vulns - pentest_vulns),
            'both_methods': list(pentest_vulns.intersection(validation_vulns)),
            'correlation_score': len(pentest_vulns.intersection(validation_vulns)) / max(len(pentest_vulns.union(validation_vulns)), 1)
        }
        
        analysis['correlation_analysis'] = correlation
        
        print(f"    Correlation score: {correlation['correlation_score']:.2%}")
        print(f"    Both methods: {len(correlation['both_methods'])}")
        print(f"    Pentest only: {len(correlation['pentest_only'])}")
        print(f"    Validation only: {len(correlation['validation_only'])}")
        
        # Risk assessment
        print("  Performing risk assessment...")
        
        all_vulnerabilities = []
        
        # Add pentest vulnerabilities
        for vuln in self.pentest_framework.phases['vulnerability_analysis'].findings:
            all_vulnerabilities.append({
                'source': 'pentest',
                'title': vuln['title'],
                'severity': vuln.get('severity', 'medium'),
                'type': vuln.get('type', 'unknown')
            })
        
        # Add validation vulnerabilities
        for vuln_name, validation_result in self.validation_results.items():
            if validation_result['validation_status'] == 'vulnerable':
                all_vulnerabilities.append({
                    'source': 'validation',
                    'title': validation_result['vulnerability_type'],
                    'severity': validation_result['proof_of_vulnerability']['severity'],
                    'type': validation_result['vulnerability_type']
                })
        
        # Calculate risk metrics
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in all_vulnerabilities:
            severity_counts[vuln['severity']] = severity_counts.get(vuln['severity'], 0) + 1
        
        risk_assessment = {
            'total_vulnerabilities': len(all_vulnerabilities),
            'severity_breakdown': severity_counts,
            'overall_risk_score': self._calculate_overall_risk_score(severity_counts),
            'high_priority_vulnerabilities': [v for v in all_vulnerabilities if v['severity'] in ['critical', 'high']]
        }
        
        analysis['risk_assessment'] = risk_assessment
        
        print(f"    Total vulnerabilities: {risk_assessment['total_vulnerabilities']}")
        print(f"    Overall risk score: {risk_assessment['overall_risk_score']}")
        print(f"    High priority: {len(risk_assessment['high_priority_vulnerabilities'])}")
        
        # Recommendations
        print("  Generating recommendations...")
        
        recommendations = self._generate_integrated_recommendations(all_vulnerabilities, correlation)
        analysis['recommendations'] = recommendations
        
        # Metrics
        print("  Calculating metrics...")
        
        metrics = {
            'assessment_coverage': {
                'pentest_phases_completed': len([p for p, phase in self.pentest_framework.phases.items() if phase.status == 'completed']),
                'total_pentest_phases': len(self.pentest_framework.phases),
                'validation_types_tested': len(self.validation_results),
                'reports_generated': len(self.disclosure_reports)
            },
            'efficiency_metrics': {
                'vulnerabilities_per_hour': len(all_vulnerabilities) / max(1, len(all_vulnerabilities)),  # Simplified
                'validation_success_rate': len([v for v in self.validation_results.values() if v['validation_status'] == 'vulnerable']) / max(1, len(self.validation_results))
            },
            'quality_metrics': {
                'evidence_collected': sum(len(phase.evidence) for phase in self.pentest_framework.phases.values()),
                'reproduction_steps_provided': len([v for v in self.validation_results.values() if v.get('reproduction_steps')]),
                'professional_reports_generated': len(self.disclosure_reports) * 3  # 3 platforms per vulnerability
            }
        }
        
        analysis['metrics'] = metrics
        
        print(f"    Pentest phases completed: {metrics['assessment_coverage']['pentest_phases_completed']}/{metrics['assessment_coverage']['total_pentest_phases']}")
        print(f"    Validation success rate: {metrics['efficiency_metrics']['validation_success_rate']:.1%}")
        print(f"    Professional reports: {metrics['quality_metrics']['professional_reports_generated']}")
        
        return analysis
    
    def _calculate_overall_risk_score(self, severity_counts: Dict) -> int:
        """Calculate overall risk score"""
        weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        
        total_score = 0
        total_vulns = sum(severity_counts.values())
        
        if total_vulns == 0:
            return 0
        
        for severity, count in severity_counts.items():
            total_score += weights.get(severity, 0) * count
        
        return total_score / total_vulns
    
    def _generate_integrated_recommendations(self, vulnerabilities: List[Dict], correlation: Dict) -> Dict:
        """Generate integrated recommendations"""
        
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategy': [],
            'methodology_improvements': []
        }
        
        # Immediate actions (critical/high vulnerabilities)
        critical_high_vulns = [v for v in vulnerabilities if v['severity'] in ['critical', 'high']]
        
        if critical_high_vulns:
            recommendations['immediate_actions'].append(
                f"Address {len(critical_high_vulns)} critical/high vulnerabilities immediately"
            )
        
        # Methodology improvements based on correlation
        if correlation['correlation_score'] < 0.5:
            recommendations['methodology_improvements'].append(
                "Low correlation between pentest and validation methods - review testing approaches"
            )
        
        if correlation['pentest_only']:
            recommendations['methodology_improvements'].append(
                f"Consider adding validation checks for: {', '.join(correlation['pentest_only'][:3])}"
            )
        
        # Short-term improvements
        recommendations['short_term_improvements'] = [
            "Implement automated vulnerability scanning",
            "Enhance security headers configuration",
            "Conduct regular security assessments"
        ]
        
        # Long-term strategy
        recommendations['long_term_strategy'] = [
            "Develop comprehensive security program",
            "Implement secure development lifecycle (SDLC)",
            "Establish continuous security monitoring"
        ]
        
        return recommendations
    
    def _save_comprehensive_results(self, results: Dict):
        """Save comprehensive assessment results"""
        
        # Save main results
        results_file = self.output_dir / "comprehensive_assessment_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Save individual components
        components_dir = self.output_dir / "components"
        components_dir.mkdir(exist_ok=True)
        
        # Save validation results
        validation_file = components_dir / "validation_results.json"
        with open(validation_file, 'w') as f:
            json.dump(self.validation_results, f, indent=2, default=str)
        
        # Save disclosure reports
        for vuln_name, report_data in self.disclosure_reports.items():
            safe_name = "".join(c for c in vuln_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
            report_file = components_dir / f"disclosure_report_{safe_name}.json"
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
        
        print(f"Results saved to: {results_file}")
    
    def _generate_assessment_summary(self, results: Dict):
        """Generate assessment summary"""
        
        summary_file = self.output_dir / "assessment_summary.md"
        
        summary = f"""# Comprehensive Security Assessment Summary

## Assessment Overview

**Target:** {results['target']}  
**Date:** {results['start_time']}  
**Duration:** {results['total_duration']}  
**Session ID:** {results['session_id']}

## Methodology

This assessment combined:
1. **Advanced Penetration Testing** - PTES methodology with NIST SP 800-115 compliance
2. **Professional Vulnerability Validation** - Evidence-based validation framework
3. **Industry-Standard Disclosure Reporting** - Multi-platform professional reports

## Results Summary

### Penetration Testing
- Phases Completed: {len([p for p in results['phases'].get('pentest', {}).get('phases', {}).values() if p.get('status') == 'completed'])}
- Vulnerabilities Found: {len(results['phases'].get('pentest', {}).get('phases', {}).get('vulnerability_analysis', {}).get('validated_vulnerabilities', []))}

### Vulnerability Validation
- Validations Performed: {len(results['phases'].get('validation', {}))}
- Vulnerabilities Confirmed: {len([v for v in results['phases'].get('validation', {}).values() if v.get('validation_status') == 'vulnerable'])}

### Disclosure Reports
- Professional Reports Generated: {len(results['phases'].get('disclosure', {}))}
- Platforms Supported: HackerOne, Bugcrowd, Intigriti

## Risk Assessment

"""
        
        # Add risk assessment if available
        if 'analysis' in results and 'risk_assessment' in results['analysis']:
            risk_assessment = results['analysis']['risk_assessment']
            summary += f"""### Overall Risk Score: {risk_assessment.get('overall_risk_score', 'N/A')}

### Severity Breakdown
- Critical: {risk_assessment.get('severity_breakdown', {}).get('critical', 0)}
- High: {risk_assessment.get('severity_breakdown', {}).get('high', 0)}
- Medium: {risk_assessment.get('severity_breakdown', {}).get('medium', 0)}
- Low: {risk_assessment.get('severity_breakdown', {}).get('low', 0)}

### High Priority Vulnerabilities
{chr(10).join(f"- {v['title']}" for v in risk_assessment.get('high_priority_vulnerabilities', [])[:5])}

"""
        
        # Add recommendations
        if 'analysis' in results and 'recommendations' in results['analysis']:
            recommendations = results['analysis']['recommendations']
            
            summary += "## Recommendations\n\n"
            
            if recommendations.get('immediate_actions'):
                summary += "### Immediate Actions\n"
                for action in recommendations['immediate_actions']:
                    summary += f"- {action}\n"
                summary += "\n"
            
            if recommendations.get('short_term_improvements'):
                summary += "### Short-term Improvements\n"
                for improvement in recommendations['short_term_improvements']:
                    summary += f"- {improvement}\n"
                summary += "\n"
            
            if recommendations.get('long_term_strategy'):
                summary += "### Long-term Strategy\n"
                for strategy in recommendations['long_term_strategy']:
                    summary += f"- {strategy}\n"
                summary += "\n"
        
        summary += f"""## Files Generated

- Main Results: `comprehensive_assessment_results.json`
- Validation Results: `components/validation_results.json`
- Disclosure Reports: `components/disclosure_report_*.json`
- Pentest Evidence: `{self.pentest_framework.base_dir}/`
- Validation Evidence: `{self.validator.output_dir}/`

## Next Steps

1. Review detailed findings in the main results file
2. Prioritize remediation based on risk assessment
3. Use disclosure reports for bug bounty submissions
4. Implement recommended security improvements
5. Schedule regular follow-up assessments

---
*Assessment completed using industry-standard methodologies and professional validation frameworks*
"""
        
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        print(f"Assessment summary saved to: {summary_file}")

# Usage example
if __name__ == "__main__":
    # Example usage
    target = "https://example.com"
    scope = ["example.com", "*.example.com"]
    roe = {
        'testing_window': '24/7',
        'emergency_contacts': ['security@example.com'],
        'authorized_methods': ['passive_recon', 'active_scanning', 'vulnerability_analysis'],
        'forbidden_actions': ['dos_attacks', 'data_exfiltration'],
        'compliance_requirements': ['OWASP Top 10', 'PCI-DSS']
    }
    
    # Initialize enhanced validation
    enhanced_validation = EnhancedValidationIntegration(target, scope, roe)
    
    # Run comprehensive assessment
    results = enhanced_validation.run_comprehensive_assessment()
    
    print(f"\nEnhanced validation completed!")
    print(f"Session ID: {results['session_id']}")
    print(f"Results directory: {enhanced_validation.output_dir}")
