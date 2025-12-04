
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
