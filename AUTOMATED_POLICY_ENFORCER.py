#!/usr/bin/env python3
"""
Automated Policy Enforcer - Real-time Policy Compliance for All Exploits
Automatically validates all exploitation activities against company policies
"""

import json
import re
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class PolicyViolation:
    """Policy violation with details"""
    severity: str
    violation_type: str
    description: str
    required_action: str
    legal_references: List[str]

@dataclass
class ExploitValidation:
    """Exploit validation result"""
    exploit_file: str
    target_company: str
    vulnerability_type: str
    is_compliant: bool
    violations: List[PolicyViolation]
    approved_actions: List[str]
    blocked_actions: List[str]
    recommendations: List[str]

class AutomatedPolicyEnforcer:
    """
    Automated policy enforcement system
    - Real-time compliance checking for all exploitation
    - Automatic blocking of non-compliant activities
    - Integration with all exploitation tools
    - Comprehensive policy validation
    """
    
    def __init__(self):
        self.compliance_system = None  # Will import after creating the file
        self.policy_cache = {}
        self.violation_log = []
        self.blocked_actions = set()
        
        # Import compliance system
        try:
            from POLICY_COMPLIANCE_SYSTEM import PolicyComplianceSystem
            self.compliance_system = PolicyComplianceSystem()
        except ImportError:
            print("⚠️ Policy Compliance System not found. Please ensure POLICY_COMPLIANCE_SYSTEM.py exists.")
            sys.exit(1)
        
        # Initialize policy enforcement
        self._initialize_enforcement()
    
    def _initialize_enforcement(self):
        """Initialize policy enforcement mechanisms"""
        
        print("🛡️ AUTOMATED POLICY ENFORCER INITIALIZED")
        print("⚖️ REAL-TIME COMPLIANCE MONITORING ACTIVE")
        print("🚫 NON-COMPLIANT ACTIVITIES WILL BE BLOCKED")
        print()
        
        # Create enforcement directories
        self.enforcement_dir = Path("policy_enforcement")
        self.enforcement_dir.mkdir(exist_ok=True)
        
        # Create violation log
        self.violation_log_file = self.enforcement_dir / "violation_log.json"
        if self.violation_log_file.exists():
            with open(self.violation_log_file, 'r') as f:
                self.violation_log = json.load(f)
        
        # Create blocked actions registry
        self.blocked_actions_file = self.enforcement_dir / "blocked_actions.json"
        if self.blocked_actions_file.exists():
            with open(self.blocked_actions_file, 'r') as f:
                self.blocked_actions = set(json.load(f))
    
    def validate_exploit_before_execution(self, exploit_file: str, target_company: str, 
                                        vulnerability_type: str, proposed_actions: List[str]) -> bool:
        """
        Validate exploit before execution
        Returns True if compliant, False if blocked
        """
        
        print(f"🔍 VALIDATING EXPLOIT: {exploit_file}")
        print(f"🎯 TARGET: {target_company}")
        print(f"🐛 VULNERABILITY: {vulnerability_type}")
        print(f"⚡ ACTIONS: {len(proposed_actions)} proposed")
        
        # Perform compliance check
        compliance_check = self.compliance_system.check_compliance(
            target_company, vulnerability_type, proposed_actions
        )
        
        # Analyze violations
        violations = []
        blocked_actions = []
        approved_actions = []
        
        for violation in compliance_check.violations:
            if "Universally forbidden" in violation:
                violations.append(PolicyViolation(
                    severity="CRITICAL",
                    violation_type="UNIVERSAL_VIOLATION",
                    description=violation,
                    required_action="IMMEDIATELY STOP - This action is illegal and unethical",
                    legal_references=["CFAA", "Computer Fraud and Abuse Act", "State Laws"]
                ))
            elif "Company policy violation" in violation:
                violations.append(PolicyViolation(
                    severity="HIGH",
                    violation_type="POLICY_VIOLATION",
                    description=violation,
                    required_action="STOP - This violates company's bug bounty policy",
                    legal_references=["Company Bug Bounty Policy", "Terms of Service"]
                ))
            elif "Out-of-scope" in violation:
                violations.append(PolicyViolation(
                    severity="MEDIUM",
                    violation_type="SCOPE_VIOLATION",
                    description=violation,
                    required_action="MODIFY - Stay within authorized scope",
                    legal_references=["Authorization Requirements", "Scope Limitations"]
                ))
        
        # Determine which actions to block
        for action in proposed_actions:
            action_blocked = False
            
            # Check against violations
            for violation in violations:
                if violation.severity in ["CRITICAL", "HIGH"]:
                    blocked_actions.append(action)
                    action_blocked = True
                    break
            
            # Check against universal restrictions
            if not action_blocked and self._is_universally_forbidden(action):
                blocked_actions.append(action)
                action_blocked = True
            
            # Add to approved if not blocked
            if not action_blocked:
                approved_actions.append(action)
        
        # Create validation result
        validation = ExploitValidation(
            exploit_file=exploit_file,
            target_company=target_company,
            vulnerability_type=vulnerability_type,
            is_compliant=len(violations) == 0,
            violations=violations,
            approved_actions=approved_actions,
            blocked_actions=blocked_actions,
            recommendations=compliance_check.recommendations
        )
        
        # Log validation
        self._log_validation(validation)
        
        # Display results
        if validation.is_compliant:
            print(f"✅ EXPLOIT COMPLIANT - {len(approved_actions)} actions approved")
            for action in approved_actions:
                print(f"   ✅ {action}")
            return True
        else:
            print(f"🚫 EXPLOIT NON-COMPLIANT - {len(blocked_actions)} actions blocked")
            for violation in violations:
                print(f"   ❌ {violation.severity}: {violation.description}")
            for action in blocked_actions:
                print(f"   🚫 BLOCKED: {action}")
            
            # Critical violations - immediate block
            if any(v.severity == "CRITICAL" for v in violations):
                print("🚨 CRITICAL VIOLATIONS DETECTED - EXPLOIT EXECUTION BLOCKED")
                print("⚖️ LEGAL RISK: These actions may violate federal law")
                print("📋 REQUIRED ACTION: Do NOT proceed with exploit execution")
                return False
            else:
                print("⚠️ MODERATE VIOLATIONS - Modify exploit before proceeding")
                return False
    
    def _is_universally_forbidden(self, action: str) -> bool:
        """Check if action is universally forbidden"""
        
        forbidden_patterns = [
            r'ddos|denial of service|dos',
            r'social.engineering|phishing',
            r'physical.security|on.site',
            r'data.exfiltration|data.theft',
            r'ransomware|malware|malicious',
            r'identity.theft|impersonation',
            r'wiretap|communication.intercept',
            r'destroy.data|damage.system',
            r'payment.fraud|financial.theft',
            r'unauthorized.access|illegal.access'
        ]
        
        for pattern in forbidden_patterns:
            if re.search(pattern, action, re.IGNORECASE):
                return True
        
        return False
    
    def _log_validation(self, validation: ExploitValidation):
        """Log validation result"""
        
        # Add to violation log
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'exploit_file': validation.exploit_file,
            'target_company': validation.target_company,
            'vulnerability_type': validation.vulnerability_type,
            'is_compliant': validation.is_compliant,
            'violations': [
                {
                    'severity': v.severity,
                    'violation_type': v.violation_type,
                    'description': v.description,
                    'required_action': v.required_action,
                    'legal_references': v.legal_references
                }
                for v in validation.violations
            ],
            'approved_actions': validation.approved_actions,
            'blocked_actions': validation.blocked_actions,
            'recommendations': validation.recommendations
        }
        
        self.violation_log.append(log_entry)
        
        # Update blocked actions registry
        for action in validation.blocked_actions:
            self.blocked_actions.add(action)
        
        # Save logs
        self._save_logs()
    
    def _save_logs(self):
        """Save enforcement logs"""
        
        # Save violation log
        with open(self.violation_log_file, 'w') as f:
            json.dump(self.violation_log, f, indent=2)
        
        # Save blocked actions
        with open(self.blocked_actions_file, 'w') as f:
            json.dump(list(self.blocked_actions), f, indent=2)
    
    def validate_all_existing_exploits(self) -> List[ExploitValidation]:
        """Validate all existing exploit files"""
        
        print("🔍 SCANNING ALL EXISTING EXPLOIT FILES")
        print("⚖️ COMPREHENSIVE POLICY COMPLIANCE CHECK")
        print()
        
        validations = []
        
        # Find all exploit-related files
        exploit_files = self._find_exploit_files()
        
        for exploit_file in exploit_files:
            print(f"📁 ANALYZING: {exploit_file}")
            
            # Extract exploit details
            exploit_details = self._extract_exploit_details(exploit_file)
            
            if exploit_details:
                # Validate exploit
                is_valid = self.validate_exploit_before_execution(
                    exploit_file,
                    exploit_details['target_company'],
                    exploit_details['vulnerability_type'],
                    exploit_details['proposed_actions']
                )
                
                # Create validation object
                validation = ExploitValidation(
                    exploit_file=exploit_file,
                    target_company=exploit_details['target_company'],
                    vulnerability_type=exploit_details['vulnerability_type'],
                    is_compliant=is_valid,
                    violations=[],  # Already logged in validation method
                    approved_actions=[],
                    blocked_actions=[],
                    recommendations=[]
                )
                
                validations.append(validation)
        
        print(f"\n📊 EXPLOIT VALIDATION COMPLETE")
        print(f"📁 {len(exploit_files)} exploit files analyzed")
        print(f"✅ {len([v for v in validations if v.is_compliant])} compliant exploits")
        print(f"🚫 {len([v for v in validations if not v.is_compliant])} non-compliant exploits")
        
        return validations
    
    def _find_exploit_files(self) -> List[str]:
        """Find all exploit-related files"""
        
        exploit_files = []
        
        # Search patterns for exploit files
        exploit_patterns = [
            "*EXPLOIT*.py",
            "*exploit*.py",
            "*ATTACK*.py",
            "*attack*.py",
            "*VULNERABILITY*.py",
            "*vulnerability*.py",
            "*ENHANCEMENT*.py",
            "*enhancement*.py",
            "*CHAIN*.py",
            "*chain*.py"
        ]
        
        from pathlib import Path
        base_path = Path(".")
        
        for pattern in exploit_patterns:
            for file_path in base_path.rglob(pattern):
                if file_path.is_file() and file_path.suffix == '.py':
                    exploit_files.append(str(file_path))
        
        # Remove duplicates and sort
        exploit_files = sorted(list(set(exploit_files)))
        
        return exploit_files
    
    def _extract_exploit_details(self, exploit_file: str) -> Optional[Dict]:
        """Extract exploit details from file"""
        
        try:
            with open(exploit_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            return None
        
        # Extract target company
        target_company = self._extract_target_company(content, exploit_file)
        
        # Extract vulnerability type
        vulnerability_type = self._extract_vulnerability_type(content)
        
        # Extract proposed actions
        proposed_actions = self._extract_proposed_actions(content)
        
        if not target_company or not vulnerability_type:
            return None
        
        return {
            'target_company': target_company,
            'vulnerability_type': vulnerability_type,
            'proposed_actions': proposed_actions
        }
    
    def _extract_target_company(self, content: str, filename: str) -> Optional[str]:
        """Extract target company from content or filename"""
        
        # Try to extract from content first
        company_patterns = [
            r'target[:\s]+([a-z]+)',
            r'company[:\s]+([a-z]+)',
            r'paypal|stripe|apple|google|microsoft|amazon|netflix|twitter|shopify|slack|twilio|zoom'
        ]
        
        for pattern in company_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                if pattern == r'target[:\s]+([a-z]+)' or pattern == r'company[:\s]+([a-z]+)':
                    return match.group(1).lower()
                else:
                    return match.group(0).lower()
        
        # Try to extract from filename
        filename_companies = ['paypal', 'stripe', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'twitter', 'shopify', 'slack', 'twilio', 'zoom']
        for company in filename_companies:
            if company in filename.lower():
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
            r'(ssrf)'
        ]
        
        for pattern in vuln_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1).lower()
        
        return None
    
    def _extract_proposed_actions(self, content: str) -> List[str]:
        """Extract proposed actions from content"""
        
        actions = []
        
        # Look for action keywords
        action_patterns = [
            r'(security header analysis)',
            r'(xss testing)',
            r'(csrf testing)',
            r'(authentication testing)',
            r'(api testing)',
            r'(automated scanning)',
            r'(social engineering)',
            r'(denial of service)',
            r'(data exfiltration)',
            r'(privilege escalation)',
            r'(account takeover)',
            r'(session hijacking)',
            r'(credential theft)'
        ]
        
        for pattern in action_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            actions.extend(matches)
        
        # Remove duplicates and return
        return list(set(actions))
    
    def generate_enforcement_report(self, validations: List[ExploitValidation]) -> str:
        """Generate comprehensive enforcement report"""
        
        report = f"""# Automated Policy Enforcement Report

## Executive Summary
**Enforcement Date:** {datetime.now().strftime('%Y-%m-%d')}  
**Total Exploits Analyzed:** {len(validations)}  
**Compliant Exploits:** {len([v for v in validations if v.is_compliant])}  
**Non-Compliant Exploits:** {len([v for v in validations if not v.is_compliant])}  
**Blocked Actions:** {len(self.blocked_actions)}

## Enforcement Statistics

### Compliance Status
- **Fully Compliant:** {len([v for v in validations if v.is_compliant])} exploits ({len([v for v in validations if v.is_compliant])/len(validations)*100:.1f}%)
- **Non-Compliant:** {len([v for v in validations if not v.is_compliant])} exploits ({len([v for v in validations if not v.is_compliant])/len(validations)*100:.1f}%)

### Blocked Actions Registry
"""
        
        for action in sorted(self.blocked_actions):
            report += f"- 🚫 {action}\n"
        
        report += f"""

### Violation Log Summary
"""
        
        # Analyze violation log
        violation_types = {}
        for log_entry in self.violation_log:
            for violation in log_entry['violations']:
                violation_types[violation['violation_type']] = violation_types.get(violation['violation_type'], 0) + 1
        
        for violation_type, count in sorted(violation_types.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{violation_type}:** {count} occurrences\n"
        
        report += f"""

## Detailed Exploit Validations

"""
        
        for i, validation in enumerate(validations, 1):
            report += f"""### Exploit #{i}: {validation.exploit_file}

**Target Company:** {validation.target_company}  
**Vulnerability Type:** {validation.vulnerability_type}  
**Compliance Status:** {'✅ COMPLIANT' if validation.is_compliant else '🚫 NON-COMPLIANT'}

"""
            if not validation.is_compliant:
                report += f"**Status:** This exploit requires modification before execution.\n\n"
            
            report += "---\n\n"
        
        report += f"""## Policy Enforcement Actions

### Immediate Actions Required
1. **Modify Non-Compliant Exploits** - Update exploits to remove blocked actions
2. **Implement Rate Limiting** - Ensure all automated scanning includes rate limits
3. **Review Company Policies** - Verify authorization for all target companies
4. **Update Exploit Documentation** - Clearly document scope limitations

### Ongoing Enforcement
1. **Real-time Validation** - All new exploits must pass compliance checks
2. **Regular Policy Reviews** - Update enforcement rules as policies change
3. **Violation Monitoring** - Track and analyze violation patterns
4. **Compliance Training** - Ensure understanding of policy requirements

### Legal Compliance
1. **CFAA Compliance** - All activities must comply with federal law
2. **Authorization Requirements** - Explicit authorization required for all testing
3. **Scope Adherence** - Strict compliance with defined scope limitations
4. **Responsible Disclosure** - Follow proper disclosure procedures

## Enforcement System Status

### Active Monitoring
- ✅ Real-time exploit validation
- ✅ Automatic violation detection
- ✅ Blocked actions registry
- ✅ Comprehensive logging
- ✅ Policy compliance checking

### System Configuration
- **Total Blocked Actions:** {len(self.blocked_actions)}
- **Violation Log Entries:** {len(self.violation_log)}
- **Enforcement Directory:** {self.enforcement_dir}
- **Last Update:** {datetime.now().isoformat()}

## Conclusion

The automated policy enforcement system has analyzed {len(validations)} exploits and identified {len([v for v in validations if not v.is_compliant])} that require modification. All non-compliant activities will be automatically blocked to ensure legal and policy compliance.

**Critical Reminders:**
- Always validate exploits before execution
- Stay within authorized scope
- Follow company-specific policies
- Comply with all applicable laws
- Report violations immediately

---
*Report generated by Automated Policy Enforcer*  
*Enforcement completed: {datetime.now().isoformat()}*
"""
        
        return report
    
    def save_enforcement_report(self, validations: List[ExploitValidation]):
        """Save enforcement report"""
        
        # Generate report
        report = self.generate_enforcement_report(validations)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = self.enforcement_dir / f"policy_enforcement_report_{timestamp}.md"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"📋 POLICY ENFORCEMENT REPORT SAVED: {report_filename}")
        
        return report_filename

# Policy enforcement decorator for functions
def enforce_policy_compliance(target_company: str, vulnerability_type: str):
    """Decorator to enforce policy compliance on functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create enforcer
            enforcer = AutomatedPolicyEnforcer()
            
            # Extract proposed actions from function
            proposed_actions = [func.__name__]
            
            # Validate before execution
            is_compliant = enforcer.validate_exploit_before_execution(
                func.__module__ + ".py",
                target_company,
                vulnerability_type,
                proposed_actions
            )
            
            if not is_compliant:
                print("🚫 FUNCTION EXECUTION BLOCKED - POLICY VIOLATION")
                return None
            
            # Execute function if compliant
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage example
if __name__ == "__main__":
    enforcer = AutomatedPolicyEnforcer()
    
    print("🛡️ AUTOMATED POLICY ENFORCER")
    print("⚖️ REAL-TIME COMPLIANCE MONITORING")
    print("🚫 NON-COMPLIANT ACTIVITIES BLOCKED")
    print()
    
    # Validate all existing exploits
    validations = enforcer.validate_all_existing_exploits()
    
    print()
    
    # Save enforcement report
    report_file = enforcer.save_enforcement_report(validations)
    
    print(f"✅ POLICY ENFORCEMENT COMPLETE")
    print(f"📊 {len(validations)} exploits validated")
    print(f"🚫 {len(enforcer.blocked_actions)} actions blocked")
    print(f"📋 Enforcement report saved")
