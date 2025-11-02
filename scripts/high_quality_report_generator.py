#!/usr/bin/env python3
"""
High-Quality Report Generator
Generates submission-ready reports with POC, impact, and remediation
"""

import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import re

class HighQualityReportGenerator:
    """
    Generates high-quality, submission-ready reports
    Includes clear description, POC, impact assessment, remediation
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.reports_dir = output_dir / "submission_reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, finding: Dict[str, Any], program_info: Dict[str, Any] = None) -> str:
        """
        Generate high-quality submission-ready report
        """
        endpoint = finding.get("endpoint", "")
        test_type = finding.get("test_case", "")
        proof = finding.get("proof", {})
        verification = finding.get("verification", {})
        value = finding.get("value", 0)
        
        # Extract components
        parsed = urlparse(endpoint)
        domain = parsed.netloc
        path = parsed.path
        
        # Determine severity
        impact = verification.get("impact", "low")
        confidence = verification.get("confidence", 0)
        
        if impact == "high" or value >= 3000:
            severity = "High"
        elif impact == "medium" or value >= 1000:
            severity = "Medium"
        else:
            severity = "Low"
        
        # Generate report
        report = f"""# {severity} Severity: {test_type.replace('_', ' ').title()}

## Summary

**Target**: {domain}
**Endpoint**: `{endpoint}`
**Vulnerability Type**: {test_type.replace('_', ' ').title()}
**Severity**: {severity}
**Confidence**: {confidence}%
**Estimated Value**: ${value:,}

---

## Description

This report describes a {test_type.replace('_', ' ').title()} vulnerability found on {domain}.

**Affected Endpoint**: `{endpoint}`

**Vulnerability Details**:
"""
        
        # Add specific details based on test type
        if "auth_bypass" in test_type:
            report += f"""
The endpoint `{endpoint}` is accessible without proper authentication.

**Proof**:
- Status Code: {proof.get('status_code', 'N/A')}
- Response Length: {proof.get('response_length', 'N/A')} bytes
- Authentication Required: No
- Sensitive Data Exposed: {verification.get('impact', 'Unknown')}

**Impact**: Unauthorized access to potentially sensitive endpoints or data.
"""
        elif "idor" in test_type:
            report += f"""
The endpoint `{endpoint}` is vulnerable to Insecure Direct Object Reference (IDOR).

**Proof**:
- Original ID: {proof.get('original_id', 'N/A')}
- Test ID: {proof.get('test_id', 'N/A')}
- Status Code: {proof.get('status_code', 'N/A')}
- Response Length: {proof.get('response_length', 'N/A')} bytes

**Impact**: Unauthorized access to other users' resources or data.
"""
        elif "information_disclosure" in test_type or "generic" in test_type:
            report += f"""
The endpoint `{endpoint}` exposes sensitive information or API documentation.

**Proof**:
- Status Code: {proof.get('status_code', 'N/A')}
- Response Length: {proof.get('response_length', 'N/A')} bytes
- Endpoint Type: {test_type.replace('_', ' ').title()}

**Impact**: Information disclosure may aid attackers in understanding the API structure or finding additional vulnerabilities.
"""
        
        # Add proof of concept
        report += f"""
---

## Proof of Concept

### Step 1: Discovery
The endpoint was discovered during automated security testing.

### Step 2: Verification
"""
        
        if "auth_bypass" in test_type:
            report += f"""
**Request**:
```http
GET {endpoint} HTTP/1.1
Host: {domain}
```

**Response**:
```http
HTTP/1.1 {proof.get('status_code', '200')} OK
Content-Length: {proof.get('response_length', 'N/A')}
...
```

**Analysis**: The endpoint responds with status code {proof.get('status_code', '200')} without requiring authentication.
"""
        elif "idor" in test_type:
            report += f"""
**Original Request**:
```http
GET {endpoint} HTTP/1.1
Host: {domain}
```

**Modified Request** (IDOR):
```http
GET {endpoint.replace(proof.get('original_id', ''), proof.get('test_id', ''))} HTTP/1.1
Host: {domain}
```

**Response**:
```http
HTTP/1.1 {proof.get('status_code', '200')} OK
Content-Length: {proof.get('response_length', 'N/A')}
...
```

**Analysis**: The endpoint allows access to different resources by modifying the ID parameter.
"""
        else:
            report += f"""
**Request**:
```http
GET {endpoint} HTTP/1.1
Host: {domain}
```

**Response**:
```http
HTTP/1.1 {proof.get('status_code', '200')} OK
Content-Length: {proof.get('response_length', 'N/A')}
...
```

**Analysis**: The endpoint exposes sensitive information or API documentation.
"""
        
        # Add impact assessment
        report += f"""
---

## Impact Assessment

**Severity**: {severity}
**Confidence**: {confidence}%
**Exploitability**: {"Yes" if verification.get('exploitable', False) else "Needs Manual Verification"}

**Potential Impact**:
"""
        
        if impact == "high":
            report += """
- Unauthorized access to sensitive data or functionality
- Potential for privilege escalation
- Possible data breach or system compromise
- Significant security risk
"""
        elif impact == "medium":
            report += """
- Unauthorized access to some functionality
- Potential information disclosure
- Moderate security risk
"""
        else:
            report += """
- Information disclosure
- May aid attackers in reconnaissance
- Low to moderate security risk
"""
        
        # Add remediation
        report += f"""
---

## Remediation Recommendations

### For Authentication Bypass:
1. Implement proper authentication checks on all sensitive endpoints
2. Require valid authentication tokens or session cookies
3. Validate user permissions before allowing access
4. Implement rate limiting to prevent brute force attacks

### For IDOR:
1. Implement proper authorization checks
2. Verify user has permission to access requested resource
3. Use random, unpredictable resource IDs
4. Implement access control lists (ACLs)

### For Information Disclosure:
1. Remove or restrict access to debug/documentation endpoints
2. Implement proper access controls
3. Review what information is exposed in error messages
4. Follow principle of least information disclosure

### General Recommendations:
1. Implement proper authentication and authorization
2. Validate all user inputs
3. Follow secure coding practices
4. Regular security audits and penetration testing

---

## Additional Information

**Discovery Method**: Automated security testing
**Testing Methodology**: Based on industry-standard bug bounty methodologies
**Verification Status**: {"Verified" if verification.get('verified', False) else "Needs Manual Verification"}
**Confidence Level**: {confidence}%

**Report Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**System ID**: Automated Bug Bounty System
"""
        
        return report
    
    def generate_all_reports(self, findings: List[Dict[str, Any]], program_info: Dict[str, Any] = None):
        """Generate reports for all findings"""
        reports_generated = 0
        
        for idx, finding in enumerate(findings, 1):
            # Generate report
            report_content = self.generate_report(finding, program_info)
            
            # Save report
            endpoint = finding.get("endpoint", "")
            parsed = urlparse(endpoint)
            domain = parsed.netloc.replace(".", "_")
            test_type = finding.get("test_case", "unknown").replace("_", "-")
            
            filename = f"{domain}_{test_type}_{idx}.md"
            report_file = self.reports_dir / filename
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            reports_generated += 1
        
        return reports_generated

