#!/usr/bin/env python3
"""
Submission Readiness Analyzer - Analyzes all existing bugs for submission viability
Determines which findings are ready for submission and which need work
"""

import json
import re
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class SubmissionStatus:
    """Submission readiness status"""
    file_path: str
    target_company: str
    vulnerability_type: str
    severity: str
    is_ready: bool
    missing_elements: List[str]
    submission_score: float
    estimated_bounty: str
    recommendations: List[str]
    submission_priority: str

class SubmissionReadinessAnalyzer:
    """
    Analyzes all bug findings for submission readiness
    - Checks completeness of evidence and documentation
    - Validates technical accuracy
    - Estimates bounty potential
    - Prioritizes submissions
    """
    
    def __init__(self):
        self.required_elements = {
            'evidence': ['Evidence:', 'Proof of Concept', 'curl ', 'http', 'screenshot'],
            'technical_details': ['Technical Details:', 'Vulnerability Type:', 'CWE-', 'CVSS'],
            'impact_analysis': ['Business Impact:', 'Financial Impact:', 'Risk Assessment:'],
            'remediation': ['Remediation:', 'Fix:', 'Recommendations:', 'Solution:'],
            'scope_verification': ['Scope:', 'Authorized:', 'In Scope:', 'Target:']
        }
        
        self.severity_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'informational': 1.0
        }
        
        self.bounty_estimates = {
            'critical': {'min': 5000, 'max': 25000},
            'high': {'min': 1000, 'max': 10000},
            'medium': {'min': 500, 'max': 3000},
            'low': {'min': 100, 'max': 1000},
            'informational': {'min': 0, 'max': 500}
        }
    
    def analyze_all_findings(self) -> List[SubmissionStatus]:
        """Analyze all bug findings for submission readiness"""
        
        print("🔍 SUBMISSION READINESS ANALYZER")
        print("📋 ASSESSING ALL BUG FINDINGS")
        print("💰 ESTIMATING BOUNTY POTENTIAL")
        print()
        
        submission_statuses = []
        
        # Find all bug report files
        bug_files = self._find_bug_files()
        
        print(f"📁 Found {len(bug_files)} bug report files")
        print()
        
        for bug_file in bug_files:
            print(f"📋 ANALYZING: {bug_file}")
            
            # Analyze submission readiness
            status = self._analyze_submission_readiness(bug_file)
            
            if status:
                submission_statuses.append(status)
                
                # Display analysis
                readiness_icon = "✅" if status.is_ready else "❌"
                print(f"   {readiness_icon} {status.target_company} - {status.vulnerability_type}")
                print(f"   📊 Score: {status.submission_score:.1f}/10 | 💰 {status.estimated_bounty}")
                print(f"   🎯 Priority: {status.submission_priority}")
                
                if status.missing_elements:
                    print(f"   ⚠️  Missing: {', '.join(status.missing_elements[:3])}")
                print()
        
        # Sort by submission priority and score
        submission_statuses.sort(key=lambda x: (
            {'high': 3, 'medium': 2, 'low': 1}[x.submission_priority],
            -x.submission_score
        ))
        
        print(f"📊 ANALYSIS COMPLETE")
        print(f"✅ Ready for submission: {len([s for s in submission_statuses if s.is_ready])}")
        print(f"❌ Need work: {len([s for s in submission_statuses if not s.is_ready])}")
        print(f"💰 Total estimated value: ${self._calculate_total_value(submission_statuses):,}")
        
        return submission_statuses
    
    def _find_bug_files(self) -> List[str]:
        """Find all bug report files"""
        
        bug_files = []
        
        # Search patterns for bug reports
        bug_patterns = [
            "*REPORT*.md",
            "*report*.md",
            "*VULNERABILITY*.md",
            "*vulnerability*.md",
            "*BUG*.md",
            "*bug*.md",
            "*finding*.md",
            "*FINDING*.md"
        ]
        
        from pathlib import Path
        base_path = Path(".")
        
        for pattern in bug_patterns:
            for file_path in base_path.rglob(pattern):
                if file_path.is_file() and file_path.suffix == '.md':
                    # Skip template files and system reports
                    if not any(skip in str(file_path).lower() for skip in ['template', 'readme', 'summary']):
                        bug_files.append(str(file_path))
        
        # Remove duplicates and sort
        bug_files = sorted(list(set(bug_files)))
        
        return bug_files
    
    def _analyze_submission_readiness(self, bug_file: str) -> Optional[SubmissionStatus]:
        """Analyze individual bug file for submission readiness"""
        
        try:
            with open(bug_file, 'r', encoding='utf-8') as f:
                content = f.read().lower()
        except:
            return None
        
        # Extract key information
        target_company = self._extract_target_company(content, bug_file)
        vulnerability_type = self._extract_vulnerability_type(content)
        severity = self._extract_severity(content)
        
        if not target_company or not vulnerability_type:
            return None
        
        # Check required elements
        missing_elements = []
        element_scores = []
        
        for element, keywords in self.required_elements.items():
            has_element = any(keyword in content for keyword in keywords)
            if not has_element:
                missing_elements.append(element)
                element_scores.append(0)
            else:
                element_scores.append(2.0)  # Full points for having the element
        
        # Calculate submission score
        base_score = sum(element_scores)
        
        # Bonus points for quality indicators
        quality_bonus = 0
        
        # Has working exploit code
        if '```' in content and ('curl' in content or 'python' in content or 'javascript' in content):
            quality_bonus += 1.0
        
        # Has screenshots/evidence
        if 'screenshot' in content or 'image' in content or 'png' in content:
            quality_bonus += 0.5
        
        # Has detailed impact analysis
        if any(impact in content for impact in ['financial impact', 'business impact', 'risk assessment']):
            quality_bonus += 0.5
        
        # Has proper remediation
        if any(remediation in content for remediation in ['remediation', 'fix recommendation', 'solution']):
            quality_bonus += 0.5
        
        # Severity bonus
        severity_bonus = self.severity_scores.get(severity.lower(), 3.0) / 3.0
        
        submission_score = min(10.0, base_score + quality_bonus + severity_bonus)
        
        # Determine if ready for submission
        is_ready = len(missing_elements) == 0 and submission_score >= 7.0
        
        # Estimate bounty
        estimated_bounty = self._estimate_bounty(severity, target_company, submission_score)
        
        # Determine priority
        submission_priority = self._determine_priority(severity, submission_score, target_company)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(missing_elements, submission_score, content)
        
        return SubmissionStatus(
            file_path=bug_file,
            target_company=target_company,
            vulnerability_type=vulnerability_type,
            severity=severity,
            is_ready=is_ready,
            missing_elements=missing_elements,
            submission_score=submission_score,
            estimated_bounty=estimated_bounty,
            recommendations=recommendations,
            submission_priority=submission_priority
        )
    
    def _extract_target_company(self, content: str, filename: str) -> Optional[str]:
        """Extract target company from content or filename"""
        
        # Company patterns
        company_patterns = [
            r'target[:\s]+([a-z]+)',
            r'company[:\s]+([a-z]+)',
            r'domain[:\s]+([a-z]+\.[a-z]+)',
            r'https?://([a-z]+\.[a-z]+)'
        ]
        
        for pattern in company_patterns:
            match = re.search(pattern, content)
            if match:
                company = match.group(1)
                # Clean up and normalize
                if '.' in company:
                    company = company.split('.')[0]
                return company.lower()
        
        # Try filename extraction
        filename_companies = ['paypal', 'stripe', 'apple', 'google', 'microsoft', 'amazon', 
                             'netflix', 'twitter', 'shopify', 'slack', 'twilio', 'zoom',
                             'vectra', 'oppo', 'rapyd']
        
        filename_lower = filename.lower()
        for company in filename_companies:
            if company in filename_lower:
                return company
        
        return None
    
    def _extract_vulnerability_type(self, content: str) -> Optional[str]:
        """Extract vulnerability type from content"""
        
        vuln_patterns = [
            r'(missing security headers)',
            r'(idor|insecure direct object reference)',
            r'(clickjacking)',
            r'(cross.site.scripting|xss)',
            r'(sql injection)',
            r'(authentication bypass)',
            r'(privilege escalation)',
            r'(business logic flaw)',
            r'(csrf)',
            r'(ssrf)',
            r'(information disclosure)',
            r'(security misconfiguration)'
        ]
        
        for pattern in vuln_patterns:
            match = re.search(pattern, content)
            if match:
                vuln_type = match.group(1)
                # Normalize
                return vuln_type.replace(' ', '_').title()
        
        return "Unknown"
    
    def _extract_severity(self, content: str) -> str:
        """Extract severity from content"""
        
        severity_patterns = [
            r'severity[:\s]+(critical|high|medium|low|informational)',
            r'risk[:\s]+(critical|high|medium|low|informational)',
            r'classification[:\s]+(critical|high|medium|low|informational)',
            r'cvss[:\s]+([0-9\.]+)'
        ]
        
        for pattern in severity_patterns:
            match = re.search(pattern, content)
            if match:
                severity = match.group(1).lower()
                if severity in self.severity_scores:
                    return severity
                elif severity.replace('.', '').isdigit():
                    # CVSS score
                    cvss = float(severity)
                    if cvss >= 9.0:
                        return 'critical'
                    elif cvss >= 7.0:
                        return 'high'
                    elif cvss >= 4.0:
                        return 'medium'
                    else:
                        return 'low'
        
        # Default to medium if not found
        return 'medium'
    
    def _estimate_bounty(self, severity: str, target_company: str, submission_score: float) -> str:
        """Estimate bounty range"""
        
        base_range = self.bounty_estimates.get(severity.lower(), {'min': 100, 'max': 1000})
        
        # Company multipliers
        company_multipliers = {
            'paypal': 2.0, 'stripe': 2.0, 'apple': 1.8, 'google': 1.5,
            'microsoft': 1.5, 'amazon': 1.5, 'netflix': 1.3, 'twitter': 1.2,
            'shopify': 1.3, 'slack': 1.2, 'twilio': 1.1, 'zoom': 1.1
        }
        
        multiplier = company_multipliers.get(target_company.lower(), 1.0)
        
        # Quality multiplier based on submission score
        quality_multiplier = submission_score / 10.0
        
        min_bounty = int(base_range['min'] * multiplier * quality_multiplier)
        max_bounty = int(base_range['max'] * multiplier * quality_multiplier)
        
        return f"${min_bounty:,}-${max_bounty:,}"
    
    def _determine_priority(self, severity: str, submission_score: float, target_company: str) -> str:
        """Determine submission priority"""
        
        # High-value companies
        high_value_companies = ['paypal', 'stripe', 'apple', 'google', 'microsoft', 'amazon']
        
        if severity.lower() in ['critical', 'high'] and submission_score >= 8.0:
            if target_company.lower() in high_value_companies:
                return 'high'
            else:
                return 'medium'
        elif submission_score >= 7.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, missing_elements: List[str], score: float, content: str) -> List[str]:
        """Generate recommendations for improving submission"""
        
        recommendations = []
        
        # Missing elements recommendations
        element_recommendations = {
            'evidence': 'Add concrete evidence (curl commands, screenshots, HTTP requests)',
            'technical_details': 'Include technical details (CWE, CVSS, vulnerability parameters)',
            'impact_analysis': 'Add business impact analysis (financial, compliance, reputation)',
            'remediation': 'Provide clear remediation steps and code examples',
            'scope_verification': 'Verify and document that the target is in scope'
        }
        
        for element in missing_elements:
            if element in element_recommendations:
                recommendations.append(element_recommendations[element])
        
        # Quality improvements
        if score < 8.0:
            recommendations.append('Add working exploit code or proof of concept')
            recommendations.append('Include screenshots demonstrating the vulnerability')
            recommendations.append('Enhance business impact analysis with financial estimates')
        
        if 'curl' not in content and '```' not in content:
            recommendations.append('Add curl commands or code examples for reproduction')
        
        if 'financial' not in content and 'business' not in content:
            recommendations.append('Quantify business impact and potential financial loss')
        
        return recommendations
    
    def _calculate_total_value(self, submission_statuses: List[SubmissionStatus]) -> int:
        """Calculate total estimated value of all submissions"""
        
        total_value = 0
        
        for status in submission_statuses:
            if status.is_ready:
                # Take midpoint of estimated range
                bounty_range = status.estimated_bounty.replace('$', '').replace(',', '')
                if '-' in bounty_range:
                    min_val, max_val = bounty_range.split('-')
                    avg_value = (int(min_val) + int(max_val)) // 2
                    total_value += avg_value
        
        return total_value
    
    def generate_submission_report(self, submission_statuses: List[SubmissionStatus]) -> str:
        """Generate comprehensive submission readiness report"""
        
        ready_submissions = [s for s in submission_statuses if s.is_ready]
        need_work = [s for s in submission_statuses if not s.is_ready]
        
        report = f"""# Submission Readiness Analysis Report

## Executive Summary
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d')}  
**Total Findings Analyzed:** {len(submission_statuses)}  
**Ready for Submission:** {len(ready_submissions)}  
**Need Work:** {len(need_work)}  
**Total Estimated Value:** ${self._calculate_total_value(submission_statuses):,}

## Submission Status Overview

### Ready for Submission ({len(ready_submissions)})
"""
        
        for status in ready_submissions:
            report += f"- **{status.target_company}** - {status.vulnerability_type} ({status.submission_score:.1f}/10) - {status.estimated_bounty}\n"
        
        report += f"""

### Need Work ({len(need_work)})
"""
        
        for status in need_work:
            report += f"- **{status.target_company}** - {status.vulnerability_type} ({status.submission_score:.1f}/10) - Missing: {', '.join(status.missing_elements[:2])}\n"
        
        report += f"""

## High Priority Submissions (Ready Now)
"""
        
        high_priority = [s for s in ready_submissions if s.submission_priority == 'high']
        for status in high_priority[:5]:  # Top 5
            report += f"""
### {status.target_company} - {status.vulnerability_type}
- **File:** {status.file_path}
- **Severity:** {status.severity}
- **Score:** {status.submission_score:.1f}/10
- **Estimated Bounty:** {status.estimated_bounty}
- **Priority:** {status.submission_priority.upper()}

**Submit immediately** - High value, complete documentation
"""
        
        report += f"""

## Immediate Actions Required

### For Ready Submissions
1. **Submit High Priority Findings** - Focus on {len(high_priority)} high-priority submissions
2. **Prepare Submission Packages** - Create platform-specific submissions
3. **Follow Program Guidelines** - Adhere to each company's submission requirements

### For Findings Needing Work
1. **Add Missing Evidence** - {len([s for s in need_work if 'evidence' in s.missing_elements])} findings need evidence
2. **Enhance Technical Details** - {len([s for s in need_work if 'technical_details' in s.missing_elements])} findings need technical details
3. **Add Impact Analysis** - {len([s for s in need_work if 'impact_analysis' in s.missing_elements])} findings need impact analysis

## Quality Improvements Needed

### Common Missing Elements
"""
        
        # Count missing elements
        missing_counts = {}
        for status in need_work:
            for missing in status.missing_elements:
                missing_counts[missing] = missing_counts.get(missing, 0) + 1
        
        for element, count in sorted(missing_counts.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{element}:** {count} findings\n"
        
        report += f"""

### Recommended Actions
1. **Standardize Report Format** - Ensure all reports have required sections
2. **Add Working Exploits** - Include curl commands or code examples
3. **Quantify Business Impact** - Add financial impact assessments
4. **Include Screenshots** - Add visual evidence for all findings
5. **Verify Scope** - Confirm all targets are in authorized scope

## Submission Strategy

### Phase 1: Immediate (This Week)
- Submit {len(high_priority)} high-priority, ready findings
- Estimated value: ${sum([int(s.estimated_bounty.split('-')[1].replace('$', '').replace(',', '')) for s in high_priority if '-' in s.estimated_bounty]):,}

### Phase 2: Short Term (Next 2 Weeks)
- Complete {len(need_work)} findings that need work
- Submit medium-priority findings
- Estimated additional value: ${sum([int(s.estimated_bounty.split('-')[1].replace('$', '').replace(',', '')) for s in ready_submissions if s.submission_priority == 'medium' and '-' in s.estimated_bounty]):,}

### Phase 3: Long Term (Next Month)
- Enhance remaining findings
- Develop new exploits based on gaps identified
- Focus on high-value targets

## Platform Recommendations

### HackerOne
- Best for: Technical findings with strong evidence
- Format: Detailed technical reports with reproduction steps
- Timeline: 7-14 days for triage

### Bugcrowd
- Best for: Business impact focused findings
- Format: Executive summary with technical details
- Timeline: 5-10 days for triage

### Direct VDP
- Best for: High-severity findings on major platforms
- Format: Formal security disclosure
- Timeline: Varies by program

## Conclusion

{len(ready_submissions)} findings are ready for immediate submission with an estimated total value of ${self._calculate_total_value(submission_statuses):,}. Focus on high-priority submissions first while completing the remaining {len(need_work)} findings that need additional work.

**Key Recommendation:** Submit the {len(high_priority)} high-priority findings this week to maximize bounty potential.

---
*Report generated by Submission Readiness Analyzer*  
*Analysis completed: {datetime.now().isoformat()}*
"""
        
        return report
    
    def save_submission_report(self, submission_statuses: List[SubmissionStatus]):
        """Save submission readiness report"""
        
        # Generate report
        report = self.generate_submission_report(submission_statuses)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"submission_readiness_report_{timestamp}.md"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"📋 SUBMISSION READINESS REPORT SAVED: {report_filename}")
        
        # Save analysis data
        analysis_data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_findings': len(submission_statuses),
            'ready_submissions': len([s for s in submission_statuses if s.is_ready]),
            'need_work': len([s for s in submission_statuses if not s.is_ready]),
            'total_estimated_value': self._calculate_total_value(submission_statuses),
            'submission_statuses': [
                {
                    'file_path': status.file_path,
                    'target_company': status.target_company,
                    'vulnerability_type': status.vulnerability_type,
                    'severity': status.severity,
                    'is_ready': status.is_ready,
                    'missing_elements': status.missing_elements,
                    'submission_score': status.submission_score,
                    'estimated_bounty': status.estimated_bounty,
                    'recommendations': status.recommendations,
                    'submission_priority': status.submission_priority
                }
                for status in submission_statuses
            ]
        }
        
        # Save JSON data
        json_filename = f"submission_analysis_data_{timestamp}.json"
        
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=2)
        
        print(f"💾 ANALYSIS DATA SAVED: {json_filename}")
        
        return report_filename, json_filename

# Usage example
if __name__ == "__main__":
    analyzer = SubmissionReadinessAnalyzer()
    
    print("🔍 SUBMISSION READINESS ANALYZER")
    print("📋 ASSESSING ALL BUG FINDINGS")
    print("💰 ESTIMATING BOUNTY POTENTIAL")
    print()
    
    # Analyze all findings
    submission_statuses = analyzer.analyze_all_findings()
    
    print()
    
    # Save report
    report_file, data_file = analyzer.save_submission_report(submission_statuses)
    
    print(f"✅ SUBMISSION ANALYSIS COMPLETE")
    print(f"📊 {len(submission_statuses)} findings analyzed")
    print(f"✅ {len([s for s in submission_statuses if s.is_ready])} ready for submission")
    print(f"💰 Total estimated value: ${analyzer._calculate_total_value(submission_statuses):,}")
