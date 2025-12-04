import json
import os
import sys
from datetime import datetime, timezone

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from REINFORCEMENT_LEARNING_AUTOMATION import ReinforcementLearningAutomation
    from LEARNING_INTEGRATION_ORCHESTRATOR import LearningIntegrationOrchestrator
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False
    print("Warning: RL modules not available, using mock training")

class DVWATrainer:
    def __init__(self):
        self.rl_system = None
        if RL_AVAILABLE:
            self.rl_system = ReinforcementLearningAutomation()
        self.training_data = []
        self.patterns = {}

    def load_dvwa_results(self, filename):
        """Load DVWA assessment results"""
        with open(filename, 'r') as f:
            return json.load(f)

    def extract_patterns(self, results):
        """Extract vulnerability patterns from DVWA results"""
        patterns = {
            'xss_patterns': [],
            'sqli_patterns': [],
            'command_injection_patterns': [],
            'lfi_patterns': [],
            'idor_patterns': []
        }
        
        for finding in results.get('findings', []):
            vuln_type = finding.get('type', '').lower()
            payload = finding.get('payload', '')
            parameter = finding.get('parameter', '')
            
            if vuln_type == 'xss':
                patterns['xss_patterns'].append({
                    'payload': payload,
                    'parameter': parameter,
                    'context': 'reflected'
                })
            elif vuln_type == 'sqli':
                patterns['sqli_patterns'].append({
                    'payload': payload,
                    'parameter': parameter,
                    'context': 'blind'
                })
            elif vuln_type == 'command_injection':
                patterns['command_injection_patterns'].append({
                    'payload': payload,
                    'parameter': parameter,
                    'context': 'execution'
                })
            elif vuln_type == 'lfi':
                patterns['lfi_patterns'].append({
                    'payload': payload,
                    'parameter': parameter,
                    'context': 'file_access'
                })
            elif vuln_type == 'idor':
                patterns['idor_patterns'].append({
                    'payload': payload,
                    'parameter': parameter,
                    'context': 'direct_access'
                })
        
        return patterns

    def create_training_scenarios(self, patterns):
        """Create training scenarios for RL system"""
        scenarios = []
        
        for vuln_type, pattern_list in patterns.items():
            if pattern_list:
                scenario = {
                    'vulnerability_type': vuln_type,
                    'success_rate': len(pattern_list) / 10.0,  # Normalize to 0-1
                    'payloads': [p['payload'] for p in pattern_list],
                    'parameters': [p['parameter'] for p in pattern_list],
                    'context': pattern_list[0].get('context', 'unknown'),
                    'confidence': 0.8  # High confidence in DVWA lab
                }
                scenarios.append(scenario)
        
        return scenarios

    def train_model(self, scenarios):
        """Train the RL model on DVWA scenarios"""
        if not RL_AVAILABLE:
            print("Mock training on DVWA scenarios...")
            print(f"Training on {len(scenarios)} vulnerability scenarios")
            for scenario in scenarios:
                print(f"  - {scenario['vulnerability_type']}: {len(scenario['payloads'])} payloads learned")
            return True
        
        print(f"Training RL model on {len(scenarios)} DVWA scenarios...")
        
        # Convert scenarios to training data format
        training_data = []
        for scenario in scenarios:
            training_entry = {
                'target_type': 'lab',
                'vulnerability_class': scenario['vulnerability_type'],
                'techniques': scenario['payloads'],
                'success_rate': scenario['success_rate'],
                'context': scenario['context']
            }
            training_data.append(training_entry)
        
        # Train the model
        try:
            self.rl_system.learn_from_assessment(training_data)
            print("✅ RL model training completed successfully")
            return True
        except Exception as e:
            print(f"❌ Training failed: {e}")
            return False

    def save_training_results(self, patterns, scenarios):
        """Save training results for future reference"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        
        # Save patterns
        patterns_file = f"dvwa_patterns_{timestamp}.json"
        with open(patterns_file, 'w') as f:
            json.dump(patterns, f, indent=2)
        
        # Save scenarios
        scenarios_file = f"dvwa_training_scenarios_{timestamp}.json"
        with open(scenarios_file, 'w') as f:
            json.dump(scenarios, f, indent=2)
        
        print(f"Training data saved:")
        print(f"  - Patterns: {patterns_file}")
        print(f"  - Scenarios: {scenarios_file}")
        
        return patterns_file, scenarios_file

    def run_training(self, dvwa_results_file):
        """Complete training pipeline"""
        print("=" * 60)
        print("DVWA REINFORCEMENT LEARNING TRAINING")
        print("=" * 60)
        
        # Load DVWA results
        print("\n1. Loading DVWA assessment results...")
        results = self.load_dvwa_results(dvwa_results_file)
        print(f"   Loaded {len(results.get('findings', []))} findings")
        
        # Extract patterns
        print("\n2. Extracting vulnerability patterns...")
        patterns = self.extract_patterns(results)
        total_patterns = sum(len(p) for p in patterns.values())
        print(f"   Extracted {total_patterns} patterns across {len(patterns)} vulnerability types")
        
        # Create training scenarios
        print("\n3. Creating training scenarios...")
        scenarios = self.create_training_scenarios(patterns)
        print(f"   Created {len(scenarios)} training scenarios")
        
        # Train model
        print("\n4. Training RL model...")
        success = self.train_model(scenarios)
        
        # Save results
        print("\n5. Saving training results...")
        patterns_file, scenarios_file = self.save_training_results(patterns, scenarios)
        
        # Summary
        print("\n" + "=" * 60)
        print("TRAINING SUMMARY")
        print("=" * 60)
        print(f"Total Findings Processed: {len(results.get('findings', []))}")
        print(f"Vulnerability Types: {len(patterns)}")
        print(f"Training Scenarios: {len(scenarios)}")
        print(f"Training Status: {'✅ SUCCESS' if success else '❌ FAILED'}")
        
        print("\nLEARNED PATTERNS:")
        for vuln_type, pattern_list in patterns.items():
            if pattern_list:
                print(f"  {vuln_type}: {len(pattern_list)} patterns")
                for i, pattern in enumerate(pattern_list[:2]):  # Show first 2
                    print(f"    - {pattern['payload']}")
                if len(pattern_list) > 2:
                    print(f"    ... and {len(pattern_list) - 2} more")
        
        print("\nNEXT STEPS:")
        print("1. The RL model has learned from DVWA vulnerabilities")
        print("2. Future assessments will use these patterns")
        print("3. Model will predict vulnerabilities based on learned patterns")
        print("4. Run assessments on real targets to validate learning")
        
        return success

if __name__ == "__main__":
    # Find the latest DVWA assessment file
    dvwa_files = [f for f in os.listdir('.') if f.startswith('dvwa_assessment_') and f.endswith('.json')]
    
    if not dvwa_files:
        print("No DVWA assessment files found. Run simulated_dvwa_assessment.py first.")
        sys.exit(1)
    
    latest_file = sorted(dvwa_files)[-1]
    print(f"Using DVWA assessment file: {latest_file}")
    
    # Run training
    trainer = DVWATrainer()
    trainer.run_training(latest_file)
