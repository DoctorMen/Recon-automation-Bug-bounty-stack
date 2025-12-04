<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Bug Bounty Attack Categories

This document outlines the comprehensive attack surface coverage in the recon stack pipeline.

## Core Vulnerability Scanning

### Nuclei Comprehensive Scan

The main Nuclei scan (`run_nuclei.sh`) now performs **comprehensive bug bounty scanning** across all vulnerability categories, excluding only truly problematic categories:

**Excluded Categories:**
- `dos` - Denial of Service (too aggressive)
- `fuzzing` - Fuzzing templates (can be resource-intensive)
- `malware` - Malware-related (not applicable)
- `intrusive` - Intrusive tests (may cause harm)
- `network` - Network-level scans (out of scope)

**Included Categories (Automatic):**
All other Nuclei templates are included, covering:

1. **Authentication & Authorization**
   - Login bypass attempts
   - Broken authentication
   - Session management issues
   - Privilege escalation
   - OAuth vulnerabilities
   - JWT/token issues

2. **Injection Attacks**
   - SQL Injection (SQLi)
   - NoSQL Injection
   - Command Injection
   - LDAP Injection
   - XPath Injection
   - Template Injection

3. **API Security**
   - REST API vulnerabilities
   - GraphQL vulnerabilities
   - API key exposure
   - OpenAPI/Swagger exposure
   - API authentication bypass

4. **Server-Side Vulnerabilities**
   - Server-Side Request Forgery (SSRF)
   - XML External Entity (XXE)
   - Remote Code Execution (RCE)
   - Path Traversal
   - File Upload vulnerabilities
   - Local File Inclusion (LFI)
   - Remote File Inclusion (RFI)

5. **Client-Side Vulnerabilities**
   - Cross-Site Scripting (XSS)
   - Cross-Site Request Forgery (CSRF)
   - Open Redirects
   - Clickjacking

6. **Security Headers & Configuration**
   - Missing security headers
   - CORS misconfigurations
   - SSL/TLS issues
   - Information disclosure
   - Exposed sensitive files

7. **Cloud & Infrastructure**
   - AWS/S3 bucket misconfigurations
   - Azure misconfigurations
   - GCP misconfigurations
   - Kubernetes vulnerabilities
   - Docker vulnerabilities
   - CI/CD misconfigurations

8. **Technology-Specific**
   - WordPress vulnerabilities
   - CMS vulnerabilities
   - Framework-specific issues
   - Database exposures (Redis, MongoDB, etc.)

9. **Credential & Secret Exposure**
   - Default credentials
   - Exposed credentials
   - API key leaks
   - Token exposure
   - Backup file exposure

10. **Information Disclosure**
    - Directory listings
    - Source code disclosure
    - Error messages with sensitive data
    - Version disclosure

## Specialized Attack Vectors

### 1. Subdomain Takeover Scanner (`run_subdomain_takeover.sh`)

**Purpose:** Identifies subdomains vulnerable to takeover attacks.

**What it checks:**
- DNS misconfigurations
- Abandoned subdomains pointing to external services
- GitHub Pages takeover opportunities
- Azure App Service takeover
- AWS S3 bucket takeover
- Cloudflare Pages takeover
- Shopify takeover
- And many more...

**Output:** `output/subdomain-takeover.json`

### 2. Secrets & Credentials Scanner (`run_secrets_scan.sh`)

**Purpose:** Discovers exposed secrets, API keys, and credentials.

**What it checks:**
- API key exposure (AWS, Azure, GCP, GitHub, etc.)
- Credential disclosure in responses
- Token exposure (JWT, OAuth, etc.)
- Secret leaks in endpoints
- Credentials in error messages
- Backup files containing secrets

**Output:** `output/secrets-found.json`

### 3. Cloud Misconfiguration Scanner (`run_cloud_scan.sh`)

**Purpose:** Identifies cloud service misconfigurations.

**What it checks:**
- **AWS:**
  - S3 bucket public access
  - Exposed EC2 instances
  - CloudFront misconfigurations
  - AWS metadata exposure
  
- **Azure:**
  - Blob storage exposure
  - App Service misconfigurations
  - Azure Functions exposure
  
- **GCP:**
  - Google Cloud Storage buckets
  - Cloud Functions exposure
  - GCP metadata exposure
  
- **Kubernetes:**
  - API server exposure
  - Dashboard exposure
  - ConfigMap/Secret exposure
  
- **Docker:**
  - Registry exposure
  - Container misconfigurations

**Output:** `output/cloud-misconfigs.json`

### 4. API Endpoint Discovery (`run_api_discovery.sh`)

**Purpose:** Discovers and catalogs API endpoints for deeper testing.

**What it discovers:**
- REST API endpoints (`/api`, `/api/v1`, etc.)
- GraphQL endpoints (`/graphql`, `/graphiql`)
- OpenAPI/Swagger documentation
- API documentation endpoints
- Versioned API paths

**Additional Testing:**
- GraphQL introspection vulnerabilities
- Swagger/OpenAPI exposure
- API authentication bypass
- REST API misconfigurations

**Output:** `output/api-endpoints.json`

## Enhanced HTTP Probing

The `httpx` scanner now captures more attack surface information:

**Additional Features:**
- Favicon fingerprinting
- Hash-based fingerprinting
- Server headers analysis
- Response headers analysis
- HTTP method enumeration
- ASN (Autonomous System Number) information
- CDN detection
- Certificate chain analysis
- JARM fingerprinting (TLS fingerprinting)

This enhanced fingerprinting helps identify:
- Technology stacks
- Framework versions
- Security configurations
- Potential attack vectors

## Configuration Options

### Focused Scanning

You can focus on specific vulnerability categories:

```bash
# Focus only on high-value categories
export NUCLEI_FOCUS_TAGS="auth,api,ssrf,rce,xss,sqli"
./scripts/run_nuclei.sh
```

### Excluding Categories

Customize exclusions:

```bash
# Exclude additional categories
export NUCLEI_EXCLUDE_TAGS="dos,fuzzing,malware,intrusive,network,wordpress"
./scripts/run_nuclei.sh
```

### Skipping Specialized Scans

If you want faster scans without specialized checks:

```bash
SKIP_SPECIALIZED_SCANS=true ./scripts/run_pipeline.sh
```

## Attack Surface Coverage Summary

| Category | Coverage | Tools |
|----------|----------|-------|
| Injection Attacks | ✅ Comprehensive | Nuclei |
| Authentication Issues | ✅ Comprehensive | Nuclei |
| Authorization Issues | ✅ Comprehensive | Nuclei |
| API Security | ✅ Comprehensive | Nuclei, API Discovery |
| SSRF/XXE | ✅ Comprehensive | Nuclei |
| Path Traversal | ✅ Comprehensive | Nuclei |
| File Upload | ✅ Comprehensive | Nuclei |
| XSS/CSRF | ✅ Comprehensive | Nuclei |
| CORS Issues | ✅ Comprehensive | Nuclei |
| Open Redirects | ✅ Comprehensive | Nuclei |
| Subdomain Takeover | ✅ Dedicated Scanner | Subdomain Takeover Scanner |
| Secrets Exposure | ✅ Dedicated Scanner | Secrets Scanner |
| Cloud Misconfigs | ✅ Dedicated Scanner | Cloud Scanner |
| GraphQL | ✅ Dedicated Scanner | API Discovery |
| SSL/TLS Issues | ✅ Comprehensive | Nuclei, httpx |
| Information Disclosure | ✅ Comprehensive | Nuclei |
| Cloud Services | ✅ Comprehensive | Cloud Scanner, Nuclei |
| Technology Stacks | ✅ Comprehensive | httpx, Nuclei |

## High-Priority Bug Bounty Targets

Based on the attack surface, these are high-priority findings:

1. **Critical:**
   - RCE vulnerabilities
   - SSRF leading to internal network access
   - Subdomain takeover
   - Exposed credentials/secrets
   - Cloud misconfigurations (public S3 buckets, etc.)

2. **High:**
   - SQL Injection
   - Authentication bypass
   - Authorization flaws (IDOR, privilege escalation)
   - XXE vulnerabilities
   - Path traversal to sensitive files

3. **Medium:**
   - XSS vulnerabilities
   - CORS misconfigurations
   - API security issues
   - Information disclosure
   - Open redirects

4. **Low/Info:**
   - Version disclosure
   - Missing security headers
   - SSL/TLS issues
   - Technology fingerprinting

## Best Practices

1. **Always get authorization** before scanning
2. **Start with rate limits** to avoid overwhelming targets
3. **Review specialized scan results** - they often find unique issues
4. **Focus on authenticated endpoints** when available
5. **Combine findings** - API discovery + Nuclei often finds chain exploits
6. **Check cloud scans** - cloud misconfigurations are frequently overlooked
7. **Verify subdomain takeovers** - these can be quick wins

## Output Files Reference

- `output/nuclei-findings.json` - Comprehensive vulnerability scan results
- `output/api-endpoints.json` - Discovered API endpoints
- `output/subdomain-takeover.json` - Subdomain takeover vulnerabilities
- `output/secrets-found.json` - Exposed secrets and credentials
- `output/cloud-misconfigs.json` - Cloud misconfiguration findings
- `output/triage.json` - Scored and filtered findings (all scans combined in triage)
- `output/reports/*.md` - Individual finding reports

---

**Remember:** This is a comprehensive scanning suite. Always ensure you have proper authorization and follow responsible disclosure practices.

