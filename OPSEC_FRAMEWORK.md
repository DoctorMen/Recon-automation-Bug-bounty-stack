# OPERATIONAL SECURITY (OPSEC) FRAMEWORK
## Bug Bounty & Reconnaissance Automation Protection System

```
Copyright © 2025 Security Research Operations
All Rights Reserved.

PROPRIETARY AND CONFIDENTIAL

This OPSEC framework is proprietary information and may not be
disclosed, copied, or reproduced without written permission.
Unauthorized access, use, or distribution may result in severe
civil and criminal penalties.
```

---

## TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Threat Model](#threat-model)
3. [Data Classification](#data-classification)
4. [Identity Protection](#identity-protection)
5. [Network Security](#network-security)
6. [Credential Management](#credential-management)
7. [Data Sanitization](#data-sanitization)
8. [Communication Security](#communication-security)
9. [Backup & Recovery](#backup--recovery)
10. [Incident Response](#incident-response)
11. [Automated Protection](#automated-protection)
12. [Compliance Requirements](#compliance-requirements)

---

## EXECUTIVE SUMMARY

This OPSEC framework protects bug bounty researchers from:
- **Identity exposure** during reconnaissance activities
- **Legal liability** from unauthorized scanning
- **Data breaches** exposing targets and findings
- **Operational disruption** from security incidents
- **Financial loss** from credential compromise

### Protection Layers
```
┌─────────────────────────────────────────┐
│   Layer 1: Identity Protection          │
├─────────────────────────────────────────┤
│   Layer 2: Network Isolation            │
├─────────────────────────────────────────┤
│   Layer 3: Data Sanitization            │
├─────────────────────────────────────────┤
│   Layer 4: Credential Security          │
├─────────────────────────────────────────┤
│   Layer 5: Backup & Recovery            │
└─────────────────────────────────────────┘
```

---

## THREAT MODEL

### Primary Threats

1. **Identity Deanonymization**
   - Risk: High
   - Impact: Legal action, retaliation, privacy violation
   - Mitigation: VPN/Tor, separate identities, burner infrastructure

2. **Legal Exposure**
   - Risk: High
   - Impact: Civil/criminal prosecution
   - Mitigation: Authorization verification, scope validation, audit trails

3. **Data Exfiltration**
   - Risk: Medium
   - Impact: Target disclosure, competitive intelligence loss
   - Mitigation: Encryption, access control, secure deletion

4. **Credential Compromise**
   - Risk: Medium
   - Impact: Account takeover, financial loss, reputation damage
   - Mitigation: Secrets management, 2FA, key rotation

5. **Operational Detection**
   - Risk: Medium
   - Impact: IP bans, WAF blocks, blacklisting
   - Mitigation: Rate limiting, residential proxies, user-agent rotation

---

## DATA CLASSIFICATION

### TOP SECRET
- **API Keys** (HackerOne, Bugcrowd, OpenAI, etc.)
- **Authentication Tokens** (session cookies, JWT)
- **Private Keys** (SSH, GPG, SSL certificates)
- **Personal Identity Information** (real name, address, SSN)

**Handling:**
- Never commit to git
- Store in encrypted vaults only (Bitwarden, 1Password, KeePass)
- Rotate every 90 days minimum
- Use environment variables only

### SECRET
- **Target Lists** (domains, IPs, subdomains)
- **Vulnerability Findings** (before disclosure)
- **Financial Information** (bounty earnings, tax data)
- **Communication Records** (emails with programs)

**Handling:**
- Encrypt at rest (GPG, VeraCrypt)
- Sanitize before sharing
- Delete after 30 days of disclosure
- Use secure file transfer only

### CONFIDENTIAL
- **Scan Results** (raw output from tools)
- **Reconnaissance Data** (OSINT, metadata)
- **Tool Configurations** (wordlists, custom templates)

**Handling:**
- Local storage only (no cloud)
- Sanitize metadata before archiving
- Use `.gitignore` protections

### PUBLIC
- **Code** (sanitized scripts)
- **Documentation** (generic guides)
- **Training Materials** (OPSEC procedures)

**Handling:**
- Review before publication
- Remove all identifying information
- Use copyright notices

---

## IDENTITY PROTECTION

### Separation of Identities

```
REAL IDENTITY ──┐
                ├─── NEVER LINK ───┐
RESEARCH IDENTITY ──┘               │
                                    ▼
                            Professional Alias
                            Separate Email/Phone
                            Different Payment Methods
                            Isolated Social Media
```

### Implementation Checklist

- [ ] **Create Research Persona**
  - Unique username (not linked to real identity)
  - Separate email (ProtonMail, Tutanota)
  - Burner phone number (Google Voice, Burner app)
  - PO Box for physical mail

- [ ] **Digital Footprint Isolation**
  - Separate browser profiles (Firefox containers, Chrome profiles)
  - Never sign in to personal accounts on research systems
  - Use different passwords for each identity
  - Disable browser sync and telemetry

- [ ] **Financial Separation**
  - Separate bank account for bounty payments
  - Privacy.com virtual cards for tool subscriptions
  - Crypto wallets for anonymous payments
  - Never link PayPal to personal accounts

---

## NETWORK SECURITY

### Layered Network Protection

```
┌─────────────────────────────────────────────────────┐
│ Layer 1: VPN (NordVPN, Mullvad, ProtonVPN)          │
│   - No logs policy                                   │
│   - Kill switch enabled                              │
│   - Multi-hop if available                           │
├─────────────────────────────────────────────────────┤
│ Layer 2: Tor (for high-risk reconnaissance)         │
│   - Use Tor Browser or proxychains                   │
│   - Never over VPN (use VPN over Tor)                │
│   - Rotate circuits frequently                       │
├─────────────────────────────────────────────────────┤
│ Layer 3: Residential Proxies (optional)             │
│   - For scanning that needs clean IPs                │
│   - Rotate per request                               │
│   - Monitor for bans                                 │
└─────────────────────────────────────────────────────┘
```

### Network Rules

1. **NEVER** scan without VPN active
2. **ALWAYS** verify VPN connection before starting tools
3. **USE** different VPN locations for different targets
4. **ROTATE** exit nodes every 24 hours minimum
5. **MONITOR** for DNS leaks (dnsleaktest.com)

### VPN Kill Switch Script
```bash
# Automatically added to your system in scripts/vpn_killswitch.sh
```

---

## CREDENTIAL MANAGEMENT

### Secrets Hierarchy

```
HIGH SECURITY VAULT (Bitwarden/1Password)
├── Platform Credentials
│   ├── HackerOne API Key
│   ├── Bugcrowd Token
│   └── Intigriti OAuth
├── Cloud Services
│   ├── AWS Access Keys
│   ├── OpenAI API Key
│   └── Discord Webhook URLs
└── Financial
    ├── Banking Credentials
    ├── Crypto Private Keys
    └── Payment Processor Tokens

LOCAL ENCRYPTED FILE (.env.gpg)
├── Tool Configuration
│   ├── Subfinder API Keys
│   ├── Amass Config
│   └── Nuclei Discord Alerts
└── Infrastructure
    ├── VPS SSH Keys
    ├── Database Credentials
    └── Internal API Tokens
```

### Environment Variable Management

**NEVER include in code:**
```bash
# ❌ WRONG - EXPOSED IN GIT
API_KEY="abc123"
```

**ALWAYS use .env files:**
```bash
# ✅ CORRECT - GITIGNORED
source .env.local  # Contains: export API_KEY="abc123"
```

### Automated Key Rotation
- Scan for exposed secrets: `scripts/opsec_scan_secrets.sh`
- Rotate keys quarterly: `scripts/opsec_rotate_keys.sh`
- Audit access logs: `scripts/opsec_audit_keys.sh`

---

## DATA SANITIZATION

### Before Sharing Code/Results

```bash
# Run sanitization suite
./scripts/opsec_sanitize_all.sh
```

### What Gets Sanitized

1. **Target Information**
   - Domain names → `example.com`, `target.com`
   - IP addresses → `192.0.2.1` (RFC 5737 addresses)
   - Subdomains → `subdomain.example.com`

2. **Personal Information**
   - Usernames → `researcher`
   - Email addresses → `researcher@example.com`
   - File paths → `/home/user/` → `/home/researcher/`

3. **API Keys & Tokens**
   - Any string matching key patterns
   - Base64 encoded credentials
   - JWT tokens
   - OAuth tokens

4. **Proprietary Information**
   - Internal IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Company-specific terminology
   - Custom vulnerability details

### Sanitization Patterns

```regex
# Automatically applied by sanitization scripts
IP_PATTERN='\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
EMAIL_PATTERN='[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
API_KEY_PATTERN='[A-Za-z0-9_-]{20,}={0,2}'
DOMAIN_PATTERN='[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+'
```

---

## COMMUNICATION SECURITY

### Secure Communication Channels

| Platform | Use Case | Security Level | Notes |
|----------|----------|----------------|-------|
| **Signal** | Sensitive discussions | ★★★★★ | End-to-end encrypted |
| **ProtonMail** | Research email | ★★★★☆ | Zero-knowledge encryption |
| **Keybase** | File sharing | ★★★★☆ | Encrypted file storage |
| **PGP Email** | Program communication | ★★★★☆ | Requires key management |
| **Slack/Discord** | Non-sensitive | ★★☆☆☆ | Assume monitored |

### Email Security

```
┌─────────────────────────────────────────┐
│ 1. Use ProtonMail/Tutanota              │
│ 2. Enable PGP encryption                │
│ 3. Never include sensitive data inline  │
│ 4. Use pastebin for large payloads      │
│ 5. Set self-destruct timers             │
└─────────────────────────────────────────┘
```

### Report Submission OPSEC

1. **Before Submitting:**
   - Run sanitization scripts
   - Remove internal tools/scripts from proof-of-concept
   - Sanitize HTTP requests (remove custom headers)
   - Strip EXIF data from screenshots

2. **During Submission:**
   - Use VPN
   - Use research identity email
   - Never reveal personal information
   - Use platform's built-in encryption

3. **After Submission:**
   - Archive encrypted copy locally
   - Delete from cloud storage
   - Document in encrypted journal

---

## BACKUP & RECOVERY

### Backup Strategy

```
PRIMARY SYSTEM (WSL/Linux)
    ├── Daily: Encrypted local backup
    │   └── Location: /mnt/external/backups/
    │
    ├── Weekly: Cloud encrypted backup
    │   └── Location: Encrypted cloud (Tresorit, SpiderOak)
    │
    └── Monthly: Offline cold storage
        └── Location: Encrypted USB drive (offline)
```

### Backup Automation

```bash
# Automated daily backups
0 2 * * * /home/ubuntu/recon-stack/scripts/opsec_backup.sh

# Weekly encrypted cloud sync
0 3 * * 0 /home/ubuntu/recon-stack/scripts/opsec_cloud_backup.sh

# Monthly verification
0 4 1 * * /home/ubuntu/recon-stack/scripts/opsec_verify_backups.sh
```

### What Gets Backed Up

**INCLUDE:**
- [ ] Tool configurations
- [ ] Custom scripts
- [ ] Documentation
- [ ] Encrypted findings archive
- [ ] Credentials vault backup

**EXCLUDE:**
- [ ] Raw scan results (sanitize first)
- [ ] Temporary files
- [ ] Cache directories
- [ ] Virtual environments
- [ ] Node modules

### Recovery Procedure

1. **Verify backup integrity**: `./scripts/opsec_verify_backup.sh`
2. **Decrypt backup**: `gpg -d backup.tar.gz.gpg | tar -xzf -`
3. **Restore configurations**: `./scripts/opsec_restore_config.sh`
4. **Reinstall tools**: `./install.sh`
5. **Verify environment**: `./scripts/opsec_audit.sh`

---

## INCIDENT RESPONSE

### Security Incident Classifications

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| **P0 - Critical** | Identity exposure | Immediate | Real name leaked in report |
| **P1 - High** | Credential compromise | < 1 hour | API key in public repo |
| **P2 - Medium** | Data leak | < 4 hours | Target list exposed |
| **P3 - Low** | OPSEC violation | < 24 hours | VPN disconnected during scan |

### Incident Response Playbook

#### P0: Identity Exposure
```bash
1. IMMEDIATELY cease all operations
2. Delete exposed information (contact platform)
3. Change all associated credentials
4. Consult legal counsel
5. Document incident
6. Review and update OPSEC procedures
```

#### P1: Credential Compromise
```bash
1. Revoke compromised credentials immediately
2. Generate new keys/tokens
3. Audit access logs for unauthorized use
4. Enable additional security (2FA, IP whitelisting)
5. Notify affected parties if required
6. Run: ./scripts/opsec_incident_p1.sh
```

#### P2: Data Leak
```bash
1. Identify scope of leak
2. Remove leaked data (DMCA if needed)
3. Notify affected bug bounty programs
4. Sanitize remaining data
5. Review backup procedures
6. Run: ./scripts/opsec_incident_p2.sh
```

#### P3: OPSEC Violation
```bash
1. Stop current operation
2. Assess exposure risk
3. Review logs for compromise
4. Implement corrective measures
5. Update procedures
6. Run: ./scripts/opsec_incident_p3.sh
```

### Emergency Contact List
```
┌──────────────────────────────────────────┐
│ VPN Provider: [REDACTED]                 │
│ Password Manager: [REDACTED]             │
│ Legal Counsel: [REDACTED]                │
│ Bug Bounty Platform: security@platform   │
└──────────────────────────────────────────┘
```

---

## AUTOMATED PROTECTION

### Pre-Commit Hooks

Automatically installed git hooks prevent sensitive data commits:

```bash
.git/hooks/pre-commit
├── Check for API keys
├── Check for email addresses
├── Check for IP addresses
├── Check for file size (prevent large binary commits)
├── Verify no credentials in code
└── Scan with custom patterns
```

### Continuous Monitoring

```bash
# Scan for exposed secrets
./scripts/opsec_scan_secrets.sh

# Verify VPN connection
./scripts/opsec_check_vpn.sh

# Audit file permissions
./scripts/opsec_audit_permissions.sh

# Check for data leaks
./scripts/opsec_check_leaks.sh
```

### Automated Sanitization Pipeline

```
┌─────────────────────────────────────────┐
│ 1. Pre-commit: Scan for secrets         │
├─────────────────────────────────────────┤
│ 2. Pre-push: Verify sanitization        │
├─────────────────────────────────────────┤
│ 3. Daily: Audit repositories            │
├─────────────────────────────────────────┤
│ 4. Weekly: Review access logs           │
├─────────────────────────────────────────┤
│ 5. Monthly: Security assessment         │
└─────────────────────────────────────────┘
```

---

## COMPLIANCE REQUIREMENTS

### Legal Prerequisites

Before ANY scanning activity:

- [ ] **Written Authorization** on file
  - Platform terms of service acceptance
  - Scope document if private program
  - Screenshot of program page

- [ ] **Scope Verification**
  - Target in scope list: `config/allowed_targets.txt`
  - No prohibited activities (DOS, social engineering, physical)
  - Respect rate limits

- [ ] **Audit Trail**
  - All scans logged: `output/audit.log`
  - Authorization documents: `programs/[target]/permission.txt`
  - Communication records archived

### Bug Bounty Platform Compliance

| Platform | Requirements | OPSEC Notes |
|----------|--------------|-------------|
| **HackerOne** | Real identity for payment | Use separate payment email |
| **Bugcrowd** | W-9/W-8BEN for US tax | PO Box for mailing |
| **Intigriti** | EU compliance | GDPR aware |
| **YesWeHack** | European focus | Check local laws |

### Data Retention Policy

```
┌────────────────────────────────────────────────┐
│ Active Research: Encrypted local storage       │
│ Retention: Until 30 days after disclosure      │
├────────────────────────────────────────────────┤
│ Disclosed Findings: Sanitized archive          │
│ Retention: 7 years for tax records             │
├────────────────────────────────────────────────┤
│ Rejected Findings: Delete immediately          │
│ Retention: 0 days                              │
├────────────────────────────────────────────────┤
│ Scan Results: Local encrypted backup           │
│ Retention: 30 days, then secure deletion       │
└────────────────────────────────────────────────┘
```

---

## OPSEC CHECKLIST

### Daily
- [ ] Verify VPN connection
- [ ] Check for exposed credentials in code
- [ ] Review firewall rules
- [ ] Backup critical findings

### Weekly
- [ ] Rotate VPN exit nodes
- [ ] Audit access logs
- [ ] Review incident reports
- [ ] Test backup restoration

### Monthly
- [ ] Rotate API keys
- [ ] Update tools and dependencies
- [ ] Security assessment
- [ ] Review and update documentation

### Quarterly
- [ ] Full security audit
- [ ] Penetration test own infrastructure
- [ ] Update threat model
- [ ] Review insurance coverage

---

## QUICK REFERENCE COMMANDS

```bash
# Verify OPSEC posture
./scripts/opsec_check_all.sh

# Sanitize before sharing
./scripts/opsec_sanitize_all.sh

# Emergency credential rotation
./scripts/opsec_emergency_rotate.sh

# Verify no leaks
./scripts/opsec_scan_secrets.sh

# Check VPN status
./scripts/opsec_check_vpn.sh

# Backup now
./scripts/opsec_backup.sh

# Audit current state
./scripts/opsec_audit.sh
```

---

## SUPPORT & UPDATES

This OPSEC framework is a living document and will be updated regularly.

**Last Updated:** November 3, 2025  
**Version:** 1.0.0  
**Next Review:** February 3, 2026

**Maintained by:** Security Research Operations  
**License:** Proprietary - All Rights Reserved

---

## LEGAL DISCLAIMER

```
This OPSEC framework is provided for educational and authorized
security research purposes only. Unauthorized access to computer
systems is illegal. Always obtain proper authorization before
conducting security testing. The authors assume no liability for
misuse of this information.

Consult with legal counsel in your jurisdiction before conducting
any security research activities.
```

---

**END OF DOCUMENT**

