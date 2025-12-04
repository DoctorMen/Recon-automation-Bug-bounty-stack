# Henkel Bug Bounty Hunt Plan

## Target Vulnerabilities (Priority Order)

| Priority | Vulnerability | Bounty Impact |
|----------|---------------|---------------|
| 🔴 P0 | **RCE** | Critical |
| 🔴 P0 | **SQLi** | Critical |
| 🟡 P1 | **Personal Data Leakage** | High |
| 🟡 P1 | **Privilege Escalation** | High |

---

## Phase 1: Reconnaissance

### Subdomain Enumeration
```bash
# Target wildcards with highest potential
*.henkel-consumer-brands.cn
*.schwarzkopfclub.com.cn
*.wechat-henkel-adhesives.cn
*.loctite.com
*.schwarzkopf.de
```

### Technology Stack Detection
- Identify CMS (WordPress, AEM, etc.)
- Find API endpoints
- Detect WAF presence

---

## Phase 2: SQLi Hunting

### High-Value Targets
1. Login forms
2. Search functionality
3. Product catalogs
4. User registration
5. API endpoints with parameters

### Test Payloads
```
' OR '1'='1
" OR "1"="1
1' AND '1'='1
1 UNION SELECT NULL--
1' ORDER BY 1--
```

### Chinese Domains (Priority - often less protected)
- smartshelf.henkel.cn
- smc-analyzer.henkel-consumer-brands.cn
- auth.eshop-henkel-adhesives.cn

---

## Phase 3: RCE Hunting

### Attack Vectors
1. **File Upload** - Look for image/document upload forms
2. **Deserialization** - Java/.NET applications
3. **Template Injection** - SSTI in email templates
4. **Command Injection** - URL parameters, file operations
5. **Log4j** - Check for vulnerable Java apps

### Target Endpoints
- Image processing
- PDF generation
- Export functionality
- Admin panels

---

## Phase 4: Personal Data Leakage

### IDOR Targets
- User profile APIs
- Order history
- Invoice downloads
- Account settings

### Information Disclosure
- Debug endpoints
- Error messages with stack traces
- Backup files (.bak, .old, .sql)
- Git repositories (.git/)
- Environment files (.env)

### API Enumeration
- GraphQL introspection
- Swagger/OpenAPI docs
- API versioning (v1, v2)

---

## Phase 5: Privilege Escalation

### Horizontal Escalation
- Change user ID in requests
- Modify email/phone in session
- Access other users' resources

### Vertical Escalation
- Role parameter manipulation
- Admin functionality access
- Hidden admin endpoints

---

## Tools Required

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| httpx | Alive host detection |
| nuclei | Automated vuln scanning |
| sqlmap | SQL injection |
| ffuf | Directory fuzzing |
| Burp Suite | Manual testing |

---

## Testing Headers

As required by program:
```
X-HackerOne-Research: [your_h1_username]
```

---

## Out of Scope Reminder

- *.ru domains
- DoS/DDoS
- Social engineering
- Rate limiting issues
- Missing headers only
