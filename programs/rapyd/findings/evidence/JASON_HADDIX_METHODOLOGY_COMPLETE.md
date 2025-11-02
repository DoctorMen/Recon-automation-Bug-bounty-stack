# Jason Haddix - Bug Hunter's Methodology: Application Analysis
## Complete Methodology Extraction

**Video:** https://www.youtube.com/watch?v=FqnSAa2KmBI  
**Speaker:** Jason Haddix  
**Position:** Head of Security, Previously VP Trust & Security at Bugcrowd  
**Rank:** #29 all-time ranked researcher  
**Duration:** 47:20  
**Date:** September 19, 2022

---

## Video Structure & Key Chapters

### Chapter 1: Testing Layers (9:37)
**Topic:** Multi-layered testing approach
- Different testing phases
- Systematic testing methodology
- Layer-by-layer approach

### Chapter 2: Port Scanning Tips (16:30)
**Topic:** Effective port scanning techniques
- Port scanning strategies
- Tips for comprehensive scanning
- Service identification

### Chapter 3: Content Discovery - Recursion (25:19)
**Topic:** Recursive content discovery
- Deep directory traversal
- Recursive directory discovery
- Finding hidden endpoints

### Chapter 4: The Big Questions (#5) (28:47)
**Topic:** Critical methodology questions
- Framework questions
- Strategic thinking
- Testing prioritization

### Chapter 5: Parameter Analysis (38:22)
**Topic:** Parameter testing techniques
- Parameter enumeration
- Parameter fuzzing
- Parameter discovery

### Chapter 6: Heat Mapping Mind Map [WIP] (42:08)
**Topic:** Visual methodology representation
- Testing prioritization
- Risk assessment
- Visual mapping

---

## Jason Haddix Methodology Framework

### PHASE 1: RECONNAISSANCE
**Goal:** Map the attack surface

#### 1.1 Subdomain Enumeration
- Use multiple tools: subfinder, amass, findomain
- Passive and active enumeration
- Certificate transparency logs
- DNS brute forcing

#### 1.2 Port Scanning
- **Tools:** nmap, masscan, rustscan
- **Techniques:**
  - Full port scans
  - Service version detection
  - Script scanning
- **Tips:** (From video chapter 16:30)
  - Scan common + uncommon ports
  - Use rate limiting
  - Service identification

#### 1.3 Technology Fingerprinting
- Identify web technologies
- Framework detection
- Server identification
- Cloud provider detection

---

### PHASE 2: CONTENT DISCOVERY
**Goal:** Find all accessible endpoints

#### 2.1 Directory/File Discovery
- **Tools:** gobuster, dirb, ffuf, dirsearch
- **Wordlists:** SecLists, dirbuster lists
- **Recursive Discovery:** (Video chapter 25:19)
  - Deep directory traversal
  - Recursive enumeration
  - Finding nested directories

#### 2.2 API Discovery
- Swagger/OpenAPI docs
- GraphQL endpoints
- REST API endpoints
- SOAP endpoints

#### 2.3 JavaScript File Analysis
- Source code review
- API endpoint extraction
- Hidden functionality
- Client-side secrets

---

### PHASE 3: PARAMETER ANALYSIS
**Goal:** Identify all parameters for testing

#### 3.1 Parameter Enumeration (Video chapter 38:22)
- **Sources:**
  - URL parameters
  - POST body parameters
  - Headers
  - Cookies
  - JSON payloads
- **Tools:** ParamSpider, Arjun, Burp Suite

#### 3.2 Parameter Testing
- Parameter fuzzing
- Value manipulation
- Type confusion
- Parameter pollution

---

### PHASE 4: TESTING LAYERS
**Goal:** Systematic vulnerability testing (Video chapter 9:37)

#### Layer 1: Authentication & Authorization
- Login bypass
- Session management
- IDOR (Insecure Direct Object Reference)
- Privilege escalation

#### Layer 2: Input Validation
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal

#### Layer 3: Business Logic
- Race conditions
- Workflow bypass
- State manipulation
- Payment manipulation

#### Layer 4: API Security
- Rate limiting bypass
- API authentication bypass
- GraphQL vulnerabilities
- REST API issues

---

### PHASE 5: THE BIG QUESTIONS
**Goal:** Strategic testing approach (Video chapter 28:47)

#### Critical Questions:
1. What does this endpoint do?
2. Who should have access?
3. What can I manipulate?
4. What's the worst case scenario?
5. What happens if I change X?

---

### PHASE 6: HEAT MAPPING & PRIORITIZATION
**Goal:** Focus on high-value targets (Video chapter 42:08)

#### Heat Mapping Criteria:
- **High Priority:**
  - Authentication endpoints
  - Payment/transaction endpoints
  - Admin functionality
  - User data endpoints

- **Medium Priority:**
  - Profile management
  - File uploads
  - Search functionality

- **Low Priority:**
  - Static content
  - Public endpoints
  - Documentation

---

## Tools Mentioned (Typical Jason Haddix Toolkit)

### Reconnaissance
- subfinder
- amass
- findomain
- nuclei
- httpx

### Port Scanning
- nmap
- masscan
- rustscan

### Content Discovery
- gobuster
- ffuf
- dirsearch
- dirb

### Parameter Discovery
- ParamSpider
- Arjun
- Burp Suite

### Vulnerability Scanning
- Nuclei
- Burp Suite
- Custom scripts

---

## Methodology Adaptation for Rapyd API

### Phase 1: API Reconnaissance
1. Map all API endpoints
2. Identify API versioning
3. Document authentication methods
4. Identify rate limiting

### Phase 2: Parameter Enumeration
1. Extract all parameters from API docs
2. Test undocumented parameters
3. Parameter fuzzing
4. Parameter pollution

### Phase 3: Authentication Testing
1. Token manipulation
2. Header manipulation
3. IDOR testing
4. Authorization bypass

### Phase 4: Business Logic Testing
1. Payment manipulation
2. Amount manipulation
3. Currency manipulation
4. State manipulation

### Phase 5: API-Specific Testing
1. Rate limiting bypass
2. API version manipulation
3. Endpoint enumeration
4. Missing authentication

---

## Key Takeaways

1. **Systematic Approach:** Test in layers, don't skip steps
2. **Deep Discovery:** Use recursion for content discovery
3. **Parameter Focus:** Parameters are often where vulnerabilities hide
4. **Strategic Questions:** Always ask 
