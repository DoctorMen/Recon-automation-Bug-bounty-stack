#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
QuickSecScan API Security Scanner
OAuth/JWT testing, IDOR detection, business logic testing
"""
import requests
import json
import re
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)

class APISecurityScanner:
    """Comprehensive API security scanner"""
    
    def __init__(self, api_base_url: str, auth_token: Optional[str] = None):
        self.api_base_url = api_base_url.rstrip('/')
        self.auth_token = auth_token
        self.session = requests.Session()
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        self.findings = []
        self.endpoints = []
        
    def scan(self, tier: str = 'basic') -> List[Dict]:
        """
        Run comprehensive API security scan
        tier: 'basic', 'pro', 'team' - determines scan depth
        """
        logger.info(f"Starting API security scan for {self.api_base_url}, tier: {tier}")
        
        # Phase 1: API Discovery
        self.discover_endpoints()
        
        # Phase 2: Authentication Testing
        if tier in ['pro', 'team']:
            self.test_authentication()
        
        # Phase 3: Authorization Testing
        self.test_authorization()
        
        # Phase 4: Input Validation
        self.test_input_validation()
        
        # Phase 5: Business Logic Testing
        if tier == 'team':
            self.test_business_logic()
        
        # Phase 6: Rate Limiting
        if tier in ['pro', 'team']:
            self.test_rate_limiting()
        
        # Phase 7: Data Exposure
        self.test_data_exposure()
        
        logger.info(f"API security scan completed. Found {len(self.findings)} issues.")
        return self.findings
    
    def discover_endpoints(self):
        """Discover API endpoints via OpenAPI/Swagger, enumeration, common paths"""
        logger.info("Phase 1: Discovering API endpoints")
        
        # Try OpenAPI/Swagger discovery
        self.discover_openapi()
        
        # Common API endpoint enumeration
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2',
            '/graphql', '/graphiql', '/api/graphql',
            '/rest', '/restapi', '/api/rest',
            '/swagger', '/swagger.json', '/swagger.yaml',
            '/openapi', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/docs', '/documentation'
        ]
        
        for path in common_paths:
            try:
                url = urljoin(self.api_base_url, path)
                resp = self.session.get(url, timeout=10)
                if resp.status_code < 400:
                    self.endpoints.append({
                        'url': url,
                        'method': 'GET',
                        'status': resp.status_code,
                        'content_type': resp.headers.get('Content-Type', '')
                    })
            except Exception as e:
                logger.debug(f"Failed to probe {path}: {e}")
    
    def discover_openapi(self):
        """Discover and parse OpenAPI/Swagger specifications"""
        swagger_paths = [
            '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/openapi.yaml',
            '/api-docs', '/docs/swagger.json'
        ]
        
        for path in swagger_paths:
            try:
                url = urljoin(self.api_base_url, path)
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    if 'json' in content_type or path.endswith('.json'):
                        spec = resp.json()
                        self.parse_openapi_spec(spec)
                    elif 'yaml' in content_type or path.endswith('.yaml'):
                        # Would need yaml library for full parsing
                        logger.info(f"Found OpenAPI spec at {url} (YAML)")
            except Exception as e:
                logger.debug(f"Failed to fetch OpenAPI spec at {path}: {e}")
    
    def parse_openapi_spec(self, spec: dict):
        """Parse OpenAPI specification and extract endpoints"""
        paths = spec.get('paths', {})
        base_path = spec.get('servers', [{}])[0].get('url', '')
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    endpoint_url = urljoin(self.api_base_url, base_path + path)
                    self.endpoints.append({
                        'url': endpoint_url,
                        'method': method.upper(),
                        'operation_id': details.get('operationId', ''),
                        'parameters': details.get('parameters', []),
                        'security': details.get('security', [])
                    })
    
    def test_authentication(self):
        """Test OAuth 2.0, JWT, and API key authentication"""
        logger.info("Phase 2: Testing authentication mechanisms")
        
        # Test JWT vulnerabilities
        self.test_jwt_vulnerabilities()
        
        # Test OAuth 2.0 vulnerabilities
        self.test_oauth_vulnerabilities()
        
        # Test API key vulnerabilities
        self.test_api_key_vulnerabilities()
        
        # Test session management
        self.test_session_management()
    
    def test_jwt_vulnerabilities(self):
        """Test JWT token vulnerabilities"""
        if not self.auth_token:
            return
        
        # Try algorithm confusion (none algorithm)
        try:
            import jwt
            # Decode without verification to check structure
            try:
                decoded = jwt.decode(self.auth_token, options={"verify_signature": False})
                self.findings.append({
                    'severity': 'MEDIUM',
                    'type': 'JWT Structure Analysis',
                    'description': 'JWT token structure analyzed',
                    'endpoint': 'Authentication',
                    'poc': f'Token payload: {json.dumps(decoded, indent=2)}'
                })
                
                # Check for weak algorithm
                header = jwt.get_unverified_header(self.auth_token)
                alg = header.get('alg', '')
                if alg in ['HS256', 'none']:
                    self.findings.append({
                        'severity': 'HIGH',
                        'type': 'Weak JWT Algorithm',
                        'description': f'JWT uses potentially weak algorithm: {alg}',
                        'endpoint': 'Authentication',
                        'recommendation': 'Use RS256 or stronger algorithm'
                    })
            except Exception:
                pass
        except ImportError:
            logger.warning("PyJWT not installed, skipping JWT analysis")
        
        # Test JWT without signature
        test_token = self.auth_token.rsplit('.', 1)[0] + '.unsigned'
        test_headers = {'Authorization': f'Bearer {test_token}'}
        for endpoint in self.endpoints[:5]:  # Test first 5 endpoints
            try:
                resp = self.session.request(
                    endpoint['method'],
                    endpoint['url'],
                    headers=test_headers,
                    timeout=10
                )
                if resp.status_code == 200:
                    self.findings.append({
                        'severity': 'CRITICAL',
                        'type': 'JWT Signature Bypass',
                        'description': 'API accepts unsigned JWT tokens',
                        'endpoint': endpoint['url'],
                        'poc': f'Use token: {test_token}'
                    })
            except Exception:
                pass
    
    def test_oauth_vulnerabilities(self):
        """Test OAuth 2.0 vulnerabilities"""
        oauth_endpoints = [
            '/oauth/authorize',
            '/oauth/token',
            '/oauth/callback',
            '/oauth/v2/authorize',
            '/oauth/v2/token'
        ]
        
        for path in oauth_endpoints:
            url = urljoin(self.api_base_url, path)
            try:
                # Test for missing state parameter
                resp = self.session.get(url, params={'response_type': 'code', 'client_id': 'test'}, timeout=10)
                if resp.status_code < 400:
                    content = resp.text.lower()
                    if 'state' not in content and 'state' not in resp.url:
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'type': 'OAuth Missing State Parameter',
                            'description': 'OAuth endpoint may not require state parameter for CSRF protection',
                            'endpoint': url,
                            'recommendation': 'Always require state parameter in OAuth flows'
                        })
            except Exception:
                pass
    
    def test_api_key_vulnerabilities(self):
        """Test API key vulnerabilities"""
        # Test for predictable API keys
        test_keys = ['test', 'demo', '123456', 'api_key', 'secret']
        for key in test_keys:
            test_headers = {'X-API-Key': key, 'API-Key': key, 'Authorization': f'Bearer {key}'}
            for endpoint in self.endpoints[:3]:
                try:
                    resp = self.session.request(
                        endpoint['method'],
                        endpoint['url'],
                        headers=test_headers,
                        timeout=10
                    )
                    if resp.status_code == 200:
                        self.findings.append({
                            'severity': 'HIGH',
                            'type': 'Weak API Key',
                            'description': f'API accepts weak/default API key: {key}',
                            'endpoint': endpoint['url'],
                            'recommendation': 'Use strong, randomly generated API keys'
                        })
                except Exception:
                    pass
    
    def test_session_management(self):
        """Test session management vulnerabilities"""
        # Test for session fixation
        session1 = requests.Session()
        session2 = requests.Session()
        
        try:
            resp1 = session1.get(self.api_base_url, timeout=10)
            resp2 = session2.get(self.api_base_url, timeout=10)
            
            # Check if session IDs are predictable
            cookies1 = session1.cookies.get_dict()
            cookies2 = session2.cookies.get_dict()
            
            for cookie_name in cookies1:
                if cookie_name in cookies2:
                    val1 = cookies1[cookie_name]
                    val2 = cookies2[cookie_name]
                    if val1 == val2:
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'type': 'Session Management Issue',
                            'description': f'Session cookie {cookie_name} appears to be predictable',
                            'endpoint': self.api_base_url,
                            'recommendation': 'Use cryptographically secure session IDs'
                        })
        except Exception:
            pass
    
    def test_authorization(self):
        """Test authorization vulnerabilities (IDOR, privilege escalation)"""
        logger.info("Phase 3: Testing authorization")
        
        # IDOR testing - try accessing resources with different IDs
        self.test_idor()
        
        # Privilege escalation testing
        self.test_privilege_escalation()
    
    def test_idor(self):
        """Test for Insecure Direct Object Reference (IDOR) vulnerabilities"""
        # Test common IDOR patterns
        test_ids = ['1', '2', '100', '999', 'admin', 'test']
        
        for endpoint in self.endpoints:
            if endpoint['method'] in ['GET', 'POST', 'PUT', 'DELETE']:
                # Try with different IDs in URL
                url = endpoint['url']
                for test_id in test_ids:
                    # Replace ID patterns in URL
                    test_url = re.sub(r'/(\d+)', f'/{test_id}', url)
                    test_url = re.sub(r'/([a-z]+)', f'/{test_id}', test_url)
                    
                    if test_url != url:
                        try:
                            resp = self.session.request(
                                endpoint['method'],
                                test_url,
                                timeout=10
                            )
                            if resp.status_code == 200:
                                # Check if response contains sensitive data
                                content = resp.text.lower()
                                sensitive_keywords = ['password', 'token', 'secret', 'key', 'private']
                                if any(keyword in content for keyword in sensitive_keywords):
                                    self.findings.append({
                                        'severity': 'HIGH',
                                        'type': 'IDOR Vulnerability',
                                        'description': f'Possible IDOR: Accessing resource with ID {test_id} returned data',
                                        'endpoint': test_url,
                                        'poc': f'{endpoint["method"]} {test_url}',
                                        'recommendation': 'Implement proper authorization checks for all resources'
                                    })
                        except Exception:
                            pass
    
    def test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities"""
        # Test admin endpoints
        admin_paths = ['/admin', '/api/admin', '/admin/users', '/api/users']
        
        for path in admin_paths:
            url = urljoin(self.api_base_url, path)
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    self.findings.append({
                        'severity': 'HIGH',
                        'type': 'Privilege Escalation Risk',
                        'description': f'Admin endpoint accessible without proper authorization: {url}',
                        'endpoint': url,
                        'recommendation': 'Implement role-based access control (RBAC)'
                    })
            except Exception:
                pass
    
    def test_input_validation(self):
        """Test input validation vulnerabilities"""
        logger.info("Phase 4: Testing input validation")
        
        # SQL Injection testing
        self.test_sql_injection()
        
        # NoSQL Injection testing
        self.test_nosql_injection()
        
        # SSRF testing
        self.test_ssrf()
        
        # Path traversal testing
        self.test_path_traversal()
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1' OR '1'='1'--"
        ]
        
        for endpoint in self.endpoints:
            if endpoint['method'] in ['GET', 'POST']:
                for payload in sql_payloads:
                    try:
                        if endpoint['method'] == 'GET':
                            resp = self.session.get(
                                endpoint['url'],
                                params={'id': payload, 'q': payload},
                                timeout=10
                            )
                        else:
                            resp = self.session.post(
                                endpoint['url'],
                                json={'id': payload, 'query': payload},
                                timeout=10
                            )
                        
                        # Check for SQL error messages
                        error_patterns = [
                            'sql syntax', 'mysql_fetch', 'postgresql',
                            'ora-', 'sqlite', 'sql error'
                        ]
                        content_lower = resp.text.lower()
                        if any(pattern in content_lower for pattern in error_patterns):
                            self.findings.append({
                                'severity': 'CRITICAL',
                                'type': 'SQL Injection',
                                'description': 'Possible SQL injection vulnerability detected',
                                'endpoint': endpoint['url'],
                                'poc': f'{endpoint["method"]} {endpoint["url"]} with payload: {payload}',
                                'recommendation': 'Use parameterized queries and input validation'
                            })
                    except Exception:
                        pass
    
    def test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        nosql_payloads = [
            {'$ne': None},
            {'$gt': ''},
            {'$regex': '.*'},
            {'$where': '1==1'}
        ]
        
        for endpoint in self.endpoints:
            if endpoint['method'] in ['POST', 'PUT']:
                for payload in nosql_payloads:
                    try:
                        resp = self.session.post(
                            endpoint['url'],
                            json=payload,
                            timeout=10
                        )
                        if resp.status_code == 200:
                            self.findings.append({
                                'severity': 'HIGH',
                                'type': 'NoSQL Injection Risk',
                                'description': 'API accepts MongoDB operators in input',
                                'endpoint': endpoint['url'],
                                'poc': f'POST {endpoint["url"]} with payload: {json.dumps(payload)}',
                                'recommendation': 'Validate and sanitize all input before database queries'
                            })
                    except Exception:
                        pass
    
    def test_ssrf(self):
        """Test for Server-Side Request Forgery (SSRF) vulnerabilities"""
        ssrf_urls = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254',  # AWS metadata
            'file:///etc/passwd'
        ]
        
        for endpoint in self.endpoints:
            if endpoint['method'] in ['GET', 'POST']:
                for test_url in ssrf_urls:
                    try:
                        if endpoint['method'] == 'GET':
                            resp = self.session.get(
                                endpoint['url'],
                                params={'url': test_url, 'endpoint': test_url},
                                timeout=5
                            )
                        else:
                            resp = self.session.post(
                                endpoint['url'],
                                json={'url': test_url, 'endpoint': test_url},
                                timeout=5
                            )
                        
                        # Check if internal resources were accessed
                        if 'localhost' in resp.text or '127.0.0.1' in resp.text:
                            self.findings.append({
                                'severity': 'HIGH',
                                'type': 'SSRF Vulnerability',
                                'description': 'API may be vulnerable to SSRF attacks',
                                'endpoint': endpoint['url'],
                                'poc': f'{endpoint["method"]} {endpoint["url"]} with url={test_url}',
                                'recommendation': 'Validate and whitelist allowed URLs, block internal IPs'
                            })
                    except Exception:
                        pass
    
    def test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd'
        ]
        
        for endpoint in self.endpoints:
            if 'file' in endpoint['url'].lower() or 'path' in endpoint['url'].lower():
                for payload in traversal_payloads:
                    try:
                        test_url = endpoint['url'] + '/' + payload
                        resp = self.session.get(test_url, timeout=10)
                        if resp.status_code == 200:
                            # Check for sensitive file contents
                            if 'root:' in resp.text or '[boot loader]' in resp.text:
                                self.findings.append({
                                    'severity': 'CRITICAL',
                                    'type': 'Path Traversal',
                                    'description': 'Path traversal vulnerability detected',
                                    'endpoint': test_url,
                                    'poc': f'GET {test_url}',
                                    'recommendation': 'Validate and sanitize file paths, use whitelist'
                                })
                    except Exception:
                        pass
    
    def test_business_logic(self):
        """Test business logic vulnerabilities"""
        logger.info("Phase 5: Testing business logic")
        
        # Race condition testing
        self.test_race_conditions()
        
        # Parameter tampering
        self.test_parameter_tampering()
        
        # Workflow bypass
        self.test_workflow_bypass()
    
    def test_race_conditions(self):
        """Test for race condition vulnerabilities"""
        # This would require concurrent requests - simplified version
        for endpoint in self.endpoints:
            if endpoint['method'] in ['POST', 'PUT']:
                # Check if endpoint handles concurrent requests properly
                self.findings.append({
                    'severity': 'MEDIUM',
                    'type': 'Race Condition Testing Recommended',
                    'description': 'Manual race condition testing recommended for concurrent operations',
                    'endpoint': endpoint['url'],
                    'recommendation': 'Use database transactions and locking mechanisms'
                })
    
    def test_parameter_tampering(self):
        """Test for parameter tampering vulnerabilities"""
        tampering_tests = [
            {'price': -1},
            {'quantity': 999999},
            {'amount': 0.01},
            {'discount': 100}
        ]
        
        for endpoint in self.endpoints:
            if endpoint['method'] in ['POST', 'PUT']:
                for test_data in tampering_tests:
                    try:
                        resp = self.session.post(endpoint['url'], json=test_data, timeout=10)
                        if resp.status_code == 200:
                            self.findings.append({
                                'severity': 'HIGH',
                                'type': 'Parameter Tampering Risk',
                                'description': 'API accepts potentially tampered parameters',
                                'endpoint': endpoint['url'],
                                'poc': f'POST {endpoint["url"]} with {json.dumps(test_data)}',
                                'recommendation': 'Validate all parameters server-side, never trust client input'
                            })
                    except Exception:
                        pass
    
    def test_workflow_bypass(self):
        """Test for workflow bypass vulnerabilities"""
        # Test skipping steps in multi-step processes
        # This is domain-specific and would need custom logic per API
        pass
    
    def test_rate_limiting(self):
        """Test rate limiting and DoS resistance"""
        logger.info("Phase 6: Testing rate limiting")
        
        for endpoint in self.endpoints[:3]:  # Test first 3 endpoints
            try:
                # Send rapid requests
                requests_sent = 0
                for i in range(100):
                    resp = self.session.request(
                        endpoint['method'],
                        endpoint['url'],
                        timeout=5
                    )
                    requests_sent += 1
                    if resp.status_code == 429:  # Too Many Requests
                        break
                    time.sleep(0.1)
                
                if requests_sent >= 100 and resp.status_code != 429:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'type': 'Missing Rate Limiting',
                        'description': f'Endpoint appears to lack rate limiting ({requests_sent} requests accepted)',
                        'endpoint': endpoint['url'],
                        'recommendation': 'Implement rate limiting to prevent brute force and DoS attacks'
                    })
            except Exception:
                pass
    
    def test_data_exposure(self):
        """Test for data exposure vulnerabilities"""
        logger.info("Phase 7: Testing data exposure")
        
        for endpoint in self.endpoints:
            try:
                resp = self.session.request(
                    endpoint['method'],
                    endpoint['url'],
                    timeout=10
                )
                
                # Check for sensitive data in responses
                sensitive_patterns = [
                    r'password["\s]*[:=]["\s]*([^",\s]+)',
                    r'api[_-]?key["\s]*[:=]["\s]*([^",\s]+)',
                    r'secret["\s]*[:=]["\s]*([^",\s]+)',
                    r'bearer\s+([a-zA-Z0-9_-]+)',
                    r'[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}'  # Credit card pattern
                ]
                
                content = resp.text
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.findings.append({
                            'severity': 'HIGH',
                            'type': 'Sensitive Data Exposure',
                            'description': f'Possible sensitive data exposed in response: {pattern}',
                            'endpoint': endpoint['url'],
                            'recommendation': 'Remove sensitive data from API responses, use data masking'
                        })
                
                # Check for detailed error messages
                error_keywords = ['stack trace', 'exception', 'error at', 'line', 'file']
                if any(keyword in content.lower() for keyword in error_keywords):
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'type': 'Information Disclosure',
                        'description': 'Detailed error messages may expose system information',
                        'endpoint': endpoint['url'],
                        'recommendation': 'Return generic error messages to clients, log details server-side'
                    })
            except Exception:
                pass
    
    def generate_poc_requests(self) -> List[Dict]:
        """Generate Proof of Concept requests for findings"""
        poc_requests = []
        
        for finding in self.findings:
            if 'poc' in finding:
                poc_requests.append({
                    'finding': finding['type'],
                    'curl_command': f"curl -X {finding.get('method', 'GET')} '{finding.get('endpoint', '')}'",
                    'description': finding.get('description', '')
                })
        
        return poc_requests

