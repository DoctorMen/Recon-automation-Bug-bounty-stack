import json
import os
import sys
from datetime import datetime

def load_rl_knowledge():
    """Load learned patterns from DVWA"""
    try:
        with open('reinforcement_learning_data/dvwa_knowledge.json', 'r') as f:
            return json.load(f)
    except:
        return None

def map_dvwa_to_real_world(vuln_type, target_domain):
    """Map DVWA vulnerability patterns to real-world endpoints"""
    
    # Real-world endpoint patterns based on vulnerability type
    endpoint_mappings = {
        'xss': [
            f"/search",
            f"/query", 
            f"/api/search",
            f"/v1/search",
            f"/find",
            f"/lookup",
            f"/explore",
            f"/suggestions",
            f"/autocomplete",
            f"/redirect"
        ],
        'sqli': [
            f"/api/users",
            f"/v1/users",
            f"/api/data",
            f"/v1/data",
            f"/api/records",
            f"/api/items",
            f"/api/products",
            f"/api/transactions",
            f"/api/history",
            f"/reports"
        ],
        'command_injection': [
            f"/api/ping",
            f"/api/health",
            f"/api/status",
            f"/api/trace",
            f"/api/debug",
            f"/admin/ping",
            f"/utils/ping",
            f"/tools/lookup",
            f"/api/resolve",
            f"/api/check"
        ],
        'lfi': [
            f"/file",
            f"/download",
            f"/view",
            f"/document",
            f"/template",
            f"/static",
            f"/assets",
            f"/uploads",
            f"/media",
            f"/reports"
        ],
        'idor': [
            f"/api/profile",
            f"/api/account",
            f"/api/user",
            f"/profile",
            f"/account",
            f"/settings",
            f"/dashboard",
            f"/api/wallet",
            f"/portfolio",
            f"/transactions"
        ]
    }
    
    return endpoint_mappings.get(vuln_type, [f"/{vuln_type}"])

def get_realistic_parameters(vuln_type):
    """Get realistic parameter names for real applications"""
    params = {
        'xss': ['q', 'query', 'search', 'term', 'keyword', 'input', 'message', 'comment', 'name', 'redirect'],
        'sqli': ['id', 'user_id', 'uid', 'account', 'token', 'key', 'category', 'type', 'filter', 'limit'],
        'command_injection': ['ip', 'host', 'domain', 'url', 'address', 'target', 'server', 'endpoint', 'cmd', 'exec'],
        'lfi': ['file', 'path', 'document', 'template', 'page', 'view', 'download', 'filename', 'asset', 'resource'],
        'idor': ['user_id', 'account_id', 'profile_id', 'wallet_id', 'transaction_id', 'id', 'uid', 'address', 'hash']
    }
    return params.get(vuln_type, ['id', 'param'])

def realistic_assessment(target_url):
    """Run realistic assessment adapted from DVWA patterns"""
    print(f"🌐 REAL-WORLD ASSESSMENT: {target_url}")
    print("=" * 60)
    
    # Extract domain
    if target_url.startswith('https://'):
        domain = target_url[8:].split('/')[0]
    elif target_url.startswith('http://'):
        domain = target_url[7:].split('/')[0]
    else:
        domain = target_url
    
    # Load RL knowledge
    knowledge = load_rl_knowledge()
    if not knowledge:
        print("❌ No RL knowledge. Run: python3 QUICK_RL_INTEGRATION.py")
        return
    
    # Create realistic assessment
    assessment = {
        'target': target_url,
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'predictions': [],
        'total_confidence': 0.0
    }
    
    total_conf = 0
    vuln_count = 0
    
    print(f"🧠 Based on DVWA laboratory learning")
    print(f"🎯 Domain: {domain}")
    print("\nREALISTIC VULNERABILITY PREDICTIONS:")
    
    for vuln_type, payloads in knowledge['vulnerability_patterns'].items():
        if knowledge['success_rates'][vuln_type] > 0.5:
            # Get real-world endpoints
            endpoints = map_dvwa_to_real_world(vuln_type, domain)
            parameters = get_realistic_parameters(vuln_type)
            
            prediction = {
                'type': vuln_type.upper(),
                'confidence': knowledge['success_rates'][vuln_type],
                'endpoints_to_test': endpoints[:5],  # Top 5 endpoints
                'parameters': parameters[:5],  # Top 5 parameters
                'sample_payloads': payloads[:3],  # Top 3 payloads from DVWA
                'test_urls': []
            }
            
            # Create test URLs
            for endpoint in endpoints[:3]:
                for param in parameters[:2]:
                    test_url = f"{target_url}{endpoint}?{param}={{payload}}"
                    prediction['test_urls'].append(test_url)
            
            assessment['predictions'].append(prediction)
            total_conf += knowledge['success_rates'][vuln_type]
            vuln_count += 1
            
            # Display
            print(f"\n  {vuln_type.upper()}")
            print(f"    Confidence: {knowledge['success_rates'][vuln_type]:.1%}")
            print(f"    Endpoints to test:")
            for ep in endpoints[:3]:
                print(f"      - {ep}")
            print(f"    Parameters: {', '.join(parameters[:3])}")
            print(f"    Sample tests:")
            for url in prediction['test_urls'][:2]:
                print(f"      - {url}")
    
    if vuln_count > 0:
        assessment['total_confidence'] = total_conf / vuln_count
    
    # Save assessment
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"realistic_assessment_{domain}_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(assessment, f, indent=2)
    
    print(f"\n✅ Realistic assessment saved: {filename}")
    print(f"📊 Overall confidence: {assessment['total_confidence']:.1%}")
    print(f"💡 These are realistic test cases based on DVWA patterns")
    
    return assessment

# Usage
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        realistic_assessment(target)
    else:
        print("Usage: python3 REAL_WORLD_RL_ASSESSMENT.py <target_url>")
        print("Example: python3 REAL_WORLD_RL_ASSESSMENT.py https://uniswap.org")
