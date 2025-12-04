#!/usr/bin/env python3
"""
John Deere Bug Bounty Program Scope Analysis
Analyzes the John Deere vulnerability disclosure program scope and requirements
"""

import json
import csv
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class JohnDeereScopeAnalyzer:
    """
    Analyzes John Deere bug bounty program scope and provides optimization recommendations
    """
    
    def __init__(self, scope_file: str = None):
        self.scope_file = scope_file
        self.scope_data = []
        self.program_analysis = {}
        self.optimization_recommendations = []
        
        # Program characteristics
        self.program_info = {
            'name': 'John Deere Vulnerability Disclosure Program',
            'bounty_program': False,  # No bounty, disclosure only
            'response_efficiency': 0.90,  # Above 90%
            'avg_first_response': '3 hours',
            'avg_triage_time': '3 days, 6 hours',
            'avg_resolution': '2 weeks, 15 hours',
            'safe_harbor': True,
            'user_agent_required': 'hackerone-{username}'
        }
        
        # Scope exclusions and inclusions
        self.in_scope = [
            'Any John Deere digital application, product or service',
            'Web applications and services',
            'API endpoints',
            'Mobile applications'
        ]
        
        self.out_of_scope = [
            'John Deere machines, equipment or hardware',
            'Software, firmware or components of equipment',
            'Core Ineligible Findings',
            'Exposed Okta Client_ID/Secret',
            'Clickjacking on pages with no sensitive actions',
            'Unauthenticated/logout/login CSRF',
            'MITM or physical access attacks',
            'Previously known vulnerable libraries without PoC',
            'CSV injection without vulnerability demonstration',
            'Missing SSL/TLS best practices',
            'Rate limiting vulnerabilities',
            'Content spoofing without attack vector',
            'Social engineering attacks',
            'Self/Client/Reflective XSS (except Stored XSS)',
            'Session cookie reuse',
            'Open redirect vulnerabilities',
            'Open ports without vulnerability',
            'Automated tool reports without PoC',
            'Physical penetration testing',
            'DoS attacks',
            'Autocomplete attributes',
            'Cache poisoning vulnerabilities',
            'Dangling IP without demonstrated impact'
        ]
        
        # Special considerations
        self.special_rules = {
            'dangling_ip': 'Only in scope with clear security impact (subdomain takeover, malicious content serving)',
            'role_based_vulnerabilities': 'Low severity if user is invited and actions limited to entity',
            'account_registration': 'Use @wearehackerone.com email',
            'breached_credentials': 'Currently out of scope',
            'user_agent': 'Required: hackerone-{username}'
        }
        
        if scope_file:
            self.load_scope_data(scope_file)
    
    def load_scope_data(self, scope_file: str):
        """Load scope data from CSV file"""
        
        try:
            with open(scope_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.scope_data = [row for row in reader]
            
            logger.info(f"Loaded {len(self.scope_data)} scope entries from {scope_file}")
            self.analyze_scope_data()
        
        except Exception as e:
            logger.error(f"Error loading scope data: {e}")
    
    def analyze_scope_data(self):
        """Analyze loaded scope data"""
        
        if not self.scope_data:
            return
        
        analysis = {
            'total_assets': len(self.scope_data),
            'asset_types': {},
            'bounty_eligible': 0,
            'submission_eligible': 0,
            'severity_levels': {},
            'requirements': {
                'availability': {},
                'confidentiality': {},
                'integrity': {}
            },
            'domains': [],
            'subdomains': []
        }
        
        for entry in self.scope_data:
            # Asset types
            asset_type = entry.get('asset_type', 'unknown')
            analysis['asset_types'][asset_type] = analysis['asset_types'].get(asset_type, 0) + 1
            
            # Bounty and submission eligibility
            if entry.get('eligible_for_bounty', '').lower() == 'true':
                analysis['bounty_eligible'] += 1
            
            if entry.get('eligible_for_submission', '').lower() == 'true':
                analysis['submission_eligible'] += 1
            
            # Severity levels
            severity = entry.get('max_severity', 'unknown')
            analysis['severity_levels'][severity] = analysis['severity_levels'].get(severity, 0) + 1
            
            # Requirements analysis
            for req_type in ['availability_requirement', 'confidentiality_requirement', 'integrity_requirement']:
                req_level = entry.get(req_type, '').lower()
                if req_level:
                    req_category = req_type.replace('_requirement', '')
                    analysis['requirements'][req_category][req_level] = analysis['requirements'][req_category].get(req_level, 0) + 1
            
            # Domain analysis
            identifier = entry.get('identifier', '')
            if identifier and '.' in identifier:
                if identifier.startswith('www.'):
                    domain = identifier[4:]
                    analysis['domains'].append(domain)
                else:
                    analysis['domains'].append(identifier)
                
                # Extract subdomains
                parts = identifier.split('.')
                if len(parts) > 2:
                    analysis['subdomains'].append(identifier)
        
        self.program_analysis = analysis
    
    def get_target_prioritization(self) -> List[Dict]:
        """Get prioritized targets for testing"""
        
        prioritized_targets = []
        
        if not self.scope_data:
            return prioritized_targets
        
        # Prioritization criteria
        high_value_indicators = [
            'deere.com', 'johndeerecloud.com', 'john-deere.com',
            'api', 'admin', 'portal', 'system', 'service'
        ]
        
        for entry in self.scope_data:
            identifier = entry.get('identifier', '')
            score = 0
            reasons = []
            
            # Check for high-value indicators
            for indicator in high_value_indicators:
                if indicator in identifier.lower():
                    score += 10
                    reasons.append(f"Contains high-value indicator: {indicator}")
            
            # Check submission eligibility
            if entry.get('eligible_for_submission', '').lower() == 'true':
                score += 5
                reasons.append("Eligible for submission")
            
            # Check severity level
            if entry.get('max_severity', '').lower() == 'critical':
                score += 8
                reasons.append("Accepts critical severity")
            
            # Check requirements (higher requirements = higher value)
            for req_type in ['availability', 'confidentiality', 'integrity']:
                req_level = entry.get(f'{req_type}_requirement', '').lower()
                if req_level == 'high':
                    score += 3
                    reasons.append(f"High {req_type} requirement")
                elif req_level == 'medium':
                    score += 2
                    reasons.append(f"Medium {req_type} requirement")
            
            # Domain analysis
            if 'deere.com' in identifier:
                score += 15
                reasons.append("Primary deere.com domain")
            elif 'johndeerecloud.com' in identifier:
                score += 12
                reasons.append("Cloud infrastructure")
            
            prioritized_targets.append({
                'identifier': identifier,
                'score': score,
                'reasons': reasons,
                'asset_type': entry.get('asset_type', ''),
                'eligible_for_submission': entry.get('eligible_for_submission', ''),
                'max_severity': entry.get('max_severity', ''),
                'availability_requirement': entry.get('availability_requirement', ''),
                'confidentiality_requirement': entry.get('confidentiality_requirement', ''),
                'integrity_requirement': entry.get('integrity_requirement', '')
            })
        
        # Sort by score (highest first)
        prioritized_targets.sort(key=lambda x: x['score'], reverse=True)
        
        return prioritized_targets
    
    def get_vulnerability_prioritization(self) -> Dict:
        """Get vulnerability type prioritization for John Deere"""
        
        vulnerability_priorities = {
            'high_priority': {
                'vulnerabilities': [
                    'Stored XSS',
                    'SQL Injection',
                    'Remote Code Execution',
                    'Authentication bypass',
                    'Privilege escalation',
                    'Sensitive data exposure',
                    'Business logic flaws',
                    'API endpoint vulnerabilities'
                ],
                'reasoning': 'High impact on critical infrastructure and data',
                'estimated_value': 'High recognition and impact'
            },
            'medium_priority': {
                'vulnerabilities': [
                    'CSRF (with sensitive actions)',
                    'Information disclosure',
                    'Security misconfiguration',
                    'Broken authentication',
                    'Insecure direct object references'
                ],
                'reasoning': 'Moderate impact with clear exploitability',
                'estimated_value': 'Good recognition potential'
            },
            'low_priority': {
                'vulnerabilities': [
                    'Missing security headers',
                    'Clickjacking (with sensitive actions)',
                    'Weak password policies',
                    'Informational findings'
                ],
                'reasoning': 'Lower impact but still valid findings',
                'estimated_value': 'Limited recognition'
            },
            'out_of_scope': {
                'vulnerabilities': self.out_of_scope,
                'reasoning': 'Explicitly excluded by program policy',
                'estimated_value': 'No recognition - will be rejected'
            }
        }
        
        return vulnerability_priorities
    
    def generate_testing_strategy(self) -> Dict:
        """Generate comprehensive testing strategy"""
        
        prioritized_targets = self.get_target_prioritization()
        vuln_priorities = self.get_vulnerability_prioritization()
        
        strategy = {
            'program_overview': self.program_info,
            'target_strategy': {
                'primary_targets': prioritized_targets[:10],  # Top 10 targets
                'secondary_targets': prioritized_targets[10:25],  # Next 15 targets
                'testing_approach': {
                    'reconnaissance': 'Identify subdomains, technologies, and attack surface',
                    'enumeration': 'Map endpoints, parameters, and functionality',
                    'vulnerability_assessment': 'Systematic testing for high-priority vulnerabilities',
                    'exploitation': 'Develop proof-of-concept exploits for valid findings'
                }
            },
            'vulnerability_focus': vuln_priorities,
            'methodology': {
                'phase_1_recon': {
                    'duration': '1-2 days',
                    'activities': [
                        'Subdomain enumeration',
                        'Technology fingerprinting',
                        'Endpoint discovery',
                        'Asset correlation'
                    ],
                    'tools': ['subfinder', 'amass', 'nmap', 'httpx', 'nuclei']
                },
                'phase_2_assessment': {
                    'duration': '3-5 days',
                    'activities': [
                        'Authentication testing',
                        'Authorization testing',
                        'Input validation',
                        'Business logic testing',
                        'API security testing'
                    ],
                    'tools': ['burp suite', 'owasp zap', 'sqlmap', 'custom scripts']
                },
                'phase_3_exploitation': {
                    'duration': '2-3 days',
                    'activities': [
                        'Proof-of-concept development',
                        'Impact assessment',
                        'Exploit chain analysis',
                        'Documentation preparation'
                    ],
                    'tools': ['metasploit', 'custom exploits', 'documentation tools']
                }
            },
            'compliance_requirements': {
                'user_agent': self.special_rules['user_agent'],
                'reporting_format': 'Detailed report with reproducible steps and screenshots',
                'safe_harbor': 'Comply with John Deere and HackerOne policies',
                'data_handling': 'Immediately purge any personal data encountered',
                'disclosure': 'No disclosure without John Deere approval'
            },
            'success_metrics': {
                'high_value_findings': 'Target 3-5 high/medium severity findings',
                'acceptance_rate': 'Aim for >80% report acceptance',
                'response_time': 'Leverage 3-hour first response time',
                'quality_focus': 'Detailed PoCs and clear impact assessment'
            }
        }
        
        return strategy
    
    def create_optimization_report(self) -> Dict:
        """Create comprehensive optimization report"""
        
        strategy = self.generate_testing_strategy()
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'program': 'John Deere Vulnerability Disclosure Program',
                'report_type': 'Scope Analysis and Testing Strategy',
                'version': '1.0'
            },
            'executive_summary': {
                'program_status': 'Active disclosure program (no bounty)',
                'response_efficiency': 'Excellent (>90%)',
                'scope_size': len(self.scope_data) if self.scope_data else 0,
                'key_opportunities': [
                    'High-value targets in deere.com domain',
                    'Cloud infrastructure testing opportunities',
                    'API security assessment potential',
                    'Business logic vulnerability discovery'
                ],
                'primary_challenges': [
                    'No monetary compensation',
                    'Strict out-of-scope policy',
                    'High bar for vulnerability acceptance',
                    'Complex infrastructure requiring deep analysis'
                ]
            },
            'scope_analysis': self.program_analysis,
            'target_prioritization': strategy['target_strategy'],
            'vulnerability_prioritization': strategy['vulnerability_focus'],
            'testing_methodology': strategy['methodology'],
            'compliance_guidelines': strategy['compliance_requirements'],
            'success_metrics': strategy['success_metrics'],
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate specific recommendations"""
        
        recommendations = [
            {
                'category': 'Target Selection',
                'priority': 'High',
                'recommendation': 'Focus on primary deere.com domains and cloud infrastructure',
                'reasoning': 'Higher likelihood of finding significant vulnerabilities',
                'action_items': [
                    'Prioritize www.deere.com and johndeerecloud.com',
                    'Map API endpoints and services',
                    'Analyze authentication and authorization mechanisms'
                ]
            },
            {
                'category': 'Vulnerability Focus',
                'priority': 'High',
                'recommendation': 'Concentrate on stored XSS and business logic vulnerabilities',
                'reasoning': 'High impact and within scope acceptance criteria',
                'action_items': [
                    'Test for stored XSS in user-generated content areas',
                    'Analyze business workflows for logic flaws',
                    'Focus on authentication bypass opportunities'
                ]
            },
            {
                'category': 'Testing Approach',
                'priority': 'Medium',
                'recommendation': 'Use systematic methodology with detailed documentation',
                'reasoning': 'Program requires detailed reports with reproducible steps',
                'action_items': [
                    'Document all steps with screenshots',
                    'Develop clear proof-of-concept exploits',
                    'Provide detailed impact analysis'
                ]
            },
            {
                'category': 'Compliance',
                'priority': 'Critical',
                'recommendation': 'Strictly follow all program requirements and exclusions',
                'reasoning': 'Safe harbor protection depends on policy compliance',
                'action_items': [
                    'Always include required User-Agent header',
                    'Use @wearehackerone.com for account registration',
                    'Avoid all out-of-scope vulnerability types',
                    'Immediately report any personal data exposure'
                ]
            },
            {
                'category': 'Quality Over Quantity',
                'priority': 'High',
                'recommendation': 'Focus on high-quality, high-impact findings',
                'reasoning': 'No bounty program - recognition comes from impact and quality',
                'action_items': [
                    'Target critical and high severity findings',
                    'Develop comprehensive exploit chains',
                    'Provide detailed remediation guidance'
                ]
            }
        ]
        
        return recommendations
    
    def save_report(self, output_file: str = None):
        """Save optimization report to file"""
        
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"john_deere_scope_analysis_{timestamp}.json"
        
        report = self.create_optimization_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"John Deere scope analysis report saved to: {output_file}")
        return output_file
    
    def print_summary(self):
        """Print analysis summary"""
        
        print("\n" + "="*80)
        print("🚜 JOHN DEERE VULNERABILITY DISCLOSURE PROGRAM ANALYSIS")
        print("="*80)
        
        print(f"\n📊 Program Overview:")
        print(f"   Program Type: Vulnerability Disclosure (No Bounty)")
        print(f"   Response Efficiency: {self.program_info['response_efficiency']:.0%}")
        print(f"   First Response: {self.program_info['avg_first_response']}")
        print(f"   Triage Time: {self.program_info['avg_triage_time']}")
        print(f"   Resolution Time: {self.program_info['avg_resolution']}")
        print(f"   Safe Harbor: {'Yes' if self.program_info['safe_harbor'] else 'No'}")
        
        if self.program_analysis:
            print(f"\n📈 Scope Analysis:")
            print(f"   Total Assets: {self.program_analysis['total_assets']}")
            print(f"   Submission Eligible: {self.program_analysis['submission_eligible']}")
            print(f"   Asset Types: {list(self.program_analysis['asset_types'].keys())}")
            print(f"   Severity Levels: {list(self.program_analysis['severity_levels'].keys())}")
        
        print(f"\n🎯 Top Priority Targets:")
        prioritized_targets = self.get_target_prioritization()
        for i, target in enumerate(prioritized_targets[:5], 1):
            print(f"   {i}. {target['identifier']} (Score: {target['score']})")
            for reason in target['reasons'][:2]:
                print(f"      - {reason}")
        
        print(f"\n🔍 Vulnerability Priorities:")
        vuln_priorities = self.get_vulnerability_prioritization()
        print(f"   High Priority: {', '.join(vuln_priorities['high_priority']['vulnerabilities'][:3])}")
        print(f"   Medium Priority: {', '.join(vuln_priorities['medium_priority']['vulnerabilities'][:3])}")
        print(f"   Out of Scope: {len(vuln_priorities['out_of_scope']['vulnerabilities'])} vulnerability types")
        
        print(f"\n⚠️ Critical Requirements:")
        print(f"   User-Agent: {self.special_rules['user_agent']}")
        print(f"   Account Registration: Use @wearehackerone.com email")
        print(f"   Data Handling: Immediately purge personal data exposure")
        print(f"   Disclosure: No disclosure without approval")
        
        print(f"\n📋 Key Recommendations:")
        recommendations = self._generate_recommendations()
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. {rec['recommendation']}")
        
        print("\n" + "="*80)

# Main execution
if __name__ == "__main__":
    print("🚜 John Deere Bug Bounty Program Scope Analysis")
    print("="*80)
    
    # Initialize analyzer
    analyzer = JohnDeereScopeAnalyzer()
    
    # Print summary
    analyzer.print_summary()
    
    # Generate and save report
    report_file = analyzer.save_report()
    print(f"\n📄 Detailed report saved to: {report_file}")
    
    print("\n✅ John Deere scope analysis complete!")
    print("🎯 Use this analysis to optimize your vulnerability research strategy")
