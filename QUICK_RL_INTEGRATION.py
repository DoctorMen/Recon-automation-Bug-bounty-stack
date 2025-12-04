import json
import os
from datetime import datetime

def quick_rl_integration():
    """
    Ultra-efficient RL integration - 30 seconds setup
    """
    
    # 1. Load latest DVWA results
    dvwa_files = [f for f in os.listdir('.') if f.startswith('dvwa_assessment_') and f.endswith('.json')]
    if not dvwa_files:
        print("❌ No DVWA results found. Run: python3 simulated_dvwa_assessment.py")
        return
    
    latest_file = sorted(dvwa_files)[-1]
    
    with open(latest_file, 'r') as f:
        results = json.load(f)
    
    # 2. Extract key patterns (optimized)
    patterns = {
        'xss': [f['payload'] for f in results['findings'] if f['type'] == 'xss'],
        'sqli': [f['payload'] for f in results['findings'] if f['type'] == 'sqli'],
        'command_injection': [f['payload'] for f in results['findings'] if f['type'] == 'command_injection'],
        'lfi': [f['payload'] for f in results['findings'] if f['type'] == 'lfi'],
        'idor': [f['payload'] for f in results['findings'] if f['type'] == 'idor']
    }
    
    # 3. Create RL knowledge base (single file)
    rl_knowledge = {
        'lab_target': results['target'],
        'vulnerability_patterns': patterns,
        'success_rates': {
            vuln_type: min(len(payloads) * 0.8, 1.0) 
            for vuln_type, payloads in patterns.items()
        },
        'learned_date': datetime.now().isoformat(),
        'total_findings': len(results['findings'])
    }
    
    # 4. Save to existing RL data directory
    os.makedirs('reinforcement_learning_data', exist_ok=True)
    knowledge_file = 'reinforcement_learning_data/dvwa_knowledge.json'
    
    with open(knowledge_file, 'w') as f:
        json.dump(rl_knowledge, f, indent=2)
    
    # 5. Quick summary
    print("⚡ QUICK RL INTEGRATION COMPLETE")
    print("=" * 50)
    print(f"📊 Processed: {len(results['findings'])} vulnerabilities")
    print(f"🎯 Target: {results['target']}")
    print(f"📚 Knowledge saved: {knowledge_file}")
    print("\nLEARNED PATTERNS:")
    for vuln_type, payloads in patterns.items():
        if payloads:
            print(f"  {vuln_type.upper()}: {len(payloads)} payloads")
            print(f"    Sample: {payloads[0][:50]}...")
    
    # 6. Create prediction helper
    prediction_helper = '''
# PREDICTION HELPER - Use in future assessments
def predict_vulnerabilities(target_url):
    """Predict vulnerabilities based on DVWA learning"""
    with open('reinforcement_learning_data/dvwa_knowledge.json', 'r') as f:
        knowledge = json.load(f)
    
    predictions = []
    for vuln_type, payloads in knowledge['vulnerability_patterns'].items():
        if knowledge['success_rates'][vuln_type] > 0.5:
            predictions.append({
                'type': vuln_type,
                'confidence': knowledge['success_rates'][vuln_type],
                'test_payloads': payloads[:3]  # Top 3 payloads
            })
    
    return predictions
'''
    
    with open('reinforcement_learning_data/prediction_helper.py', 'w') as f:
        f.write(prediction_helper)
    
    print("\n✅ Ready for real-world assessments!")
    print("💡 The system will now predict vulnerabilities based on DVWA patterns")
    
    return rl_knowledge

# Run it
if __name__ == "__main__":
    quick_rl_integration()
