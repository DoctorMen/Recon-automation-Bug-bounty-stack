# SecureStack CLI - Proof of Concept

**Copyright © 2025 DoctorMen. All Rights Reserved.**

## Overview

SecureStack CLI is an automated reconnaissance and vulnerability assessment platform that demonstrates:

- **Passive Reconnaissance**: Endpoint discovery and mapping
- **Neural Risk Scoring**: ML-based vulnerability detection
- **Legal Authorization**: CFAA compliance verification
- **Automated Reporting**: Professional assessment reports

## Quick Start

### Prerequisites

- Python 3.7 or higher
- No additional dependencies required for basic operation

### Installation

1. Navigate to the secure-stack-pro directory:
```bash
cd secure-stack-pro
```

2. Make the script executable (if not already):
```bash
chmod +x securestack_cli.py
```

### Usage

#### Basic Demo (Default Target)
```bash
python3 securestack_cli.py
```

This will run a demonstration assessment against the default target:
- **Target**: `*.staging-api.corp-target.com`
- **Engagement ID**: `AUTH-882-XJ9`

#### Custom Target Assessment
```bash
python3 securestack_cli.py "*.yourdomain.com" "ENG-123-ABC"
```

Arguments:
1. **Target Scope**: The domain or IP range to assess
2. **Engagement ID**: Your authorization tracking identifier

### Example Output

```
 _____                            _____ _             _     
 / ____|                          / ____| |           | |    
 | (___   ___  ___ _   _ _ __ ___| (___ | |_ __ _  ___| | __ 
  \___ \ / _ \/ __| | | | '__/ _ \\___ \| __/ _` |/ __| |/ / 
  ____) |  __/ (__| |_| | | |  __/____) | || (_| | (__|   <  
 |_____/ \___|\___|\____|_|  \___|_____/ \__\__,_|\___|_|\_\ 
  :: Automated Recon & Vulnerability Assessment Platform :: v2.1
----------------------------------------------------------------------
[*] TARGET SCOPE:  *.staging-api.corp-target.com
[*] ENGAGEMENT ID: AUTH-882-XJ9
[LEGAL] Verifying CFAA Authorization Token... VERIFIED
[LEGAL] Checking Exclusion List (RoE)...      CLEARED
----------------------------------------------------------------------
[+] PHASE 1: PASSIVE RECONNAISSANCE
    > Discovered endpoint: api.v1.login (Status: 200 OK)
    > Discovered endpoint: admin.dashboard (Status: 200 OK)
    > Discovered endpoint: dev.upload (Status: 200 OK)
    > Discovered endpoint: internal.metrics (Status: 200 OK)
    > Discovered endpoint: auth.sso (Status: 200 OK)

[+] PHASE 2: NEURAL RISK SCORING (ML-Based)
    > Analyzing traffic patterns...
    > Detecting IDOR signatures...
    > Heuristic Scan: SUSPICIOUS ACTIVITY DETECTED

[!] CRITICAL VULNERABILITY IDENTIFIED
    TYPE:       BOLA / IDOR (Broken Object Level Authorization)
    ENDPOINT:   /api/v1/user/profile?id=1002
    PAYLOAD:    User ID enumeration (No Auth Enforcement)
    SEVERITY:   CVSS 9.1 (Critical)
----------------------------------------------------------------------
[SUCCESS] ASSESSMENT COMPLETE. REPORT GENERATED.
Output: ./reports/SecureStack_Scan_2025-12-07.pdf
Time Elapsed: 0m 3s (5x faster than manual baseline)
```

## Features Demonstrated

### 1. Legal Authorization Verification
- **CFAA Token Verification**: Ensures legal authorization exists
- **Rules of Engagement (RoE) Check**: Validates target is not excluded
- **Engagement ID Tracking**: Maintains audit trail

### 2. Passive Reconnaissance
- Endpoint discovery and enumeration
- Service identification
- Status code analysis
- Risk categorization

### 3. Neural Risk Scoring
- ML-based pattern detection
- IDOR signature recognition
- Heuristic vulnerability scanning
- Confidence scoring

### 4. Vulnerability Detection
The POC demonstrates detection of:
- **BOLA/IDOR** (Broken Object Level Authorization)
- User enumeration vulnerabilities
- Missing authorization checks
- API security issues

### 5. Automated Reporting
- Timestamped assessment reports
- JSON data export for integrations
- PDF-style summary reports
- Performance metrics

## Output Files

The assessment generates reports in the `./reports` directory:

- **SecureStack_Scan_YYYY-MM-DD.pdf**: Human-readable assessment report
- **SecureStack_Scan_YYYY-MM-DD.json**: Machine-readable data export

### JSON Report Structure

```json
{
  "version": "2.1",
  "timestamp": "2025-12-07T23:04:18.123456",
  "target_scope": "*.staging-api.corp-target.com",
  "engagement_id": "AUTH-882-XJ9",
  "duration_seconds": 3,
  "endpoints_discovered": 5,
  "vulnerabilities_found": 1,
  "vulnerabilities": [
    {
      "type": "BOLA / IDOR (Broken Object Level Authorization)",
      "endpoint": "/api/v1/user/profile?id=1002",
      "payload": "User ID enumeration (No Auth Enforcement)",
      "severity": "CVSS 9.1 (Critical)",
      "confidence": 0.95,
      "description": "Endpoint allows unauthorized access to user profiles by manipulating ID parameter",
      "impact": "Attackers can enumerate and access all user profiles without authentication",
      "recommendation": "Implement proper authorization checks before returning user data"
    }
  ]
}
```

## Architecture

### Design Principles

1. **Idempotent Operations**: Same input always produces same output
2. **Snapshot Methodology**: Each assessment creates an immutable state record
3. **Zero-Trust Security**: All operations require explicit authorization
4. **ML-Enhanced Detection**: Heuristic analysis for emerging vulnerabilities

### Technology Stack

- **Language**: Python 3.7+
- **Core Libraries**: Standard library only (no external dependencies for POC)
- **Future Enhancements**: 
  - Integration with Nuclei, Subfinder, httpx
  - OpenAI/LangChain for AI insights
  - PostgreSQL for state persistence
  - Redis for job queuing

## Proof of Concept Status

✅ **Working Features:**
- ASCII banner and branding
- Target scope validation
- Legal authorization verification
- Passive reconnaissance simulation
- Neural risk scoring demonstration
- Vulnerability detection (IDOR example)
- Report generation
- Timing and performance metrics

🔜 **Production Enhancements:**
- Real passive recon using external tools
- Actual ML model for risk scoring
- Integration with authorization APIs
- True PDF report generation
- Database persistence
- Web API interface
- Real-time scanning

## Moving to Separate Repository

This tool is designed to be self-contained and can be easily moved to a separate repository:

### Files to Include:
```
secure-stack-pro/
├── securestack_cli.py          # Main CLI tool
├── SECURESTACK_CLI_README.md   # This documentation
├── requirements.txt            # Python dependencies (empty for POC)
├── LICENSE                     # License file
└── reports/                    # Output directory (created on first run)
```

### Steps to Extract:
1. Create new repository: `SecureStack-CLI`
2. Copy the above files
3. Initialize git and create first commit
4. Add appropriate license and copyright notices
5. Update documentation with new repository URLs

## Legal Notice

This proof-of-concept tool is provided for demonstration purposes only. 

**IMPORTANT**: Only use this tool against systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

## Support

For questions, issues, or feature requests, contact the repository owner.

---

**Version**: 2.1  
**Last Updated**: December 2025  
**Status**: ✅ Proof of Concept - Working
