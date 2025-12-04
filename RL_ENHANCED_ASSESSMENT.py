import json
import os
import sys
from datetime import datetime

# Load RL knowledge
def load_rl_knowledge():
    """Load learned patterns from DVWA"""
    try:
        with open('reinforcement_learning_data/dvwa_knowledge.json', 'r') as f:
            return json.load(f)
    except:
        return None

def enhance_assessment_with_rl(target_url, base_assessment):
    """Enhance any assessment with RL predictions"""
    knowledge = load_rl_knowledge()
    if not knowledge:
        print("⚠️ No RL knowledge found. Run QUICK_RL_INTEGRATION.py first")
        return base_assessment
    
    # Add RL predictions to assessment
    enhanced = base_assessment.copy()
    enhanced['rl_predictions'] = []
    enhanced['rl_confidence'] = 0.0
    
    total_confidence = 0
    vuln_count = 0
    
    for vuln_type, payloads in knowledge['vulnerability_patterns'].items():
        if knowledge['success_rates'][vuln_type] > 0.5:  # Only use high-confidence patterns
            prediction = {
                'type': vuln_type,
                'confidence': knowledge['success_rates'][vuln_type],
                'recommended_payloads': payloads[:3],  # Top 3 payloads
                'test_url': f"{target_url}/vulnerabilities/{vuln_type.replace('_', '/')}/",
                'parameter_hint': get_parameter_hint(vuln_type)
            }
            enhanced['rl_predictions'].append(prediction)
            total_confidence += knowledge['success_rates'][vuln_type]
            vuln_count += 1
    
    if vuln_count > 0:
        enhanced['rl_confidence'] = total_confidence / vuln_count
    
    return enhanced

def get_parameter_hint(vuln_type):
    """Get common parameter names for vulnerability type"""
    hints = {
        'xss': ['name', 'search', 'query', 'input', 'message'],
        'sqli': ['id', 'user_id', 'category', 'product_id'],
        'command_injection': ['ip', 'host', 'cmd', 'exec'],
        'lfi': ['file', 'page', 'document', 'template'],
        'idor': ['user_id', 'account', 'profile', 'id']
    }
    return hints.get(vuln_type, ['id', 'param'])

def quick_enhanced_assessment(target_url):
    """Run quick assessment enhanced with RL"""
    print(f"🚀 ENHANCED ASSESSMENT: {target_url}")
    print("=" * 50)
    
    # Load RL knowledge
    knowledge = load_rl_knowledge()
    if not knowledge:
        print("❌ No RL knowledge. Run: python3 QUICK_RL_INTEGRATION.py")
        return
    
    # Create base assessment
    base_assessment = {
        'target': target_url,
        'timestamp': datetime.now().isoformat(),
        'findings': []
    }
    
    # Enhance with RL
    enhanced = enhance_assessment_with_rl(target_url, base_assessment)
    
    # Display predictions
    print(f"🧠 RL Confidence: {enhanced['rl_confidence']:.1%}")
    print(f"🎯 Predictions: {len(enhanced['rl_predictions'])}")
    print("\nPREDICTED VULNERABILITIES:")
    
    for pred in enhanced['rl_predictions']:
        print(f"\n  {pred['type'].upper()}")
        print(f"    Confidence: {pred['confidence']:.1%}")
        print(f"    Test URL: {pred['test_url']}")
        print(f"    Parameters: {', '.join(pred['parameter_hint'])}")
        print(f"    Payloads to try:")
        for payload in pred['recommended_payloads']:
            print(f"      - {payload[:60]}...")
    
    # Save enhanced assessment
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"enhanced_assessment_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(enhanced, f, indent=2)
    
    print(f"\n✅ Enhanced assessment saved: {filename}")
    print("💡 Use these predictions to guide your testing!")
    
    return enhanced

# Usage examples
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        quick_enhanced_assessment(target)
    else:
        print("Usage: python3 RL_ENHANCED_ASSESSMENT.py <target_url>")
        print("Example: python3 RL_ENHANCED_ASSESSMENT.py https://example.com")
