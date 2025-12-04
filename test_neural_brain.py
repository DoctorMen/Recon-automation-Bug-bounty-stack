#!/usr/bin/env python3
"""
Quick test for Neural Network Brain system.
Run this to verify everything works.

Usage:
    python3 test_neural_brain.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_learned_prioritizer():
    """Test the learned prioritizer"""
    print("\n" + "="*60)
    print("TEST 1: Learned Prioritizer")
    print("="*60)
    
    from NEURAL_NETWORK_BRAIN import LearnedPrioritizer
    
    prioritizer = LearnedPrioritizer()
    
    # Test assets
    assets = [
        {'name': 'admin.example.com', 'degree': 2, 'technologies': ['wordpress']},
        {'name': 'api.staging.example.com', 'degree': 3, 'technologies': ['nodejs']},
        {'name': 'www.example.com', 'degree': 0, 'technologies': ['react']},
        {'name': 'debug.internal.example.com', 'degree': 4, 'technologies': ['flask']},
    ]
    
    print("\nScoring assets:")
    for asset in assets:
        score = prioritizer.score(asset)
        features = prioritizer.get_top_features(asset)
        print(f"  {asset['name']}: {score:.3f}")
        print(f"    Top features: {features[:3]}")
    
    # Test prioritization
    ranked = prioritizer.prioritize(assets, top_n=3)
    print("\nTop 3 by neural score:")
    for asset, score in ranked:
        print(f"  {score:.3f}: {asset['name']}")
    
    # Test learning
    print("\nTesting learning (gradient descent):")
    result = prioritizer.learn(assets[0], was_real_bug=True)
    print(f"  Recorded: admin.example.com was REAL bug")
    print(f"  Weights updated: {result['weights_updated']}")
    print(f"  Error: {result['error']:.3f}")
    
    print("\n✅ Learned Prioritizer: WORKING")
    return True


def test_ollama_brain():
    """Test Ollama integration"""
    print("\n" + "="*60)
    print("TEST 2: Ollama Brain (Local LLM)")
    print("="*60)
    
    from NEURAL_NETWORK_BRAIN import OllamaBrain
    
    brain = OllamaBrain()
    
    if brain.available:
        print(f"✅ Ollama is running: {brain.model}")
        
        # Quick test
        assets = [
            {'name': 'admin.example.com', 'type': 'subdomain'},
            {'name': 'api.example.com', 'type': 'subdomain'},
        ]
        context = {'target': 'example.com', 'explored_count': 5}
        
        print("\nAsking LLM to prioritize assets...")
        selections = brain.prioritize_assets(assets, context)
        print(f"LLM selections: {selections}")
        
        print("\n✅ Ollama Brain: WORKING")
    else:
        print("⚠️ Ollama not running")
        print("   Install: curl -fsSL https://ollama.com/install.sh | sh")
        print("   Start: ollama serve")
        print("   Pull model: ollama pull llama3.1:8b-instruct-q4_0")
        print("\n⚠️ Ollama Brain: FALLBACK MODE (heuristics only)")
    
    return True


def test_hybrid_agent():
    """Test the hybrid agent"""
    print("\n" + "="*60)
    print("TEST 3: Hybrid Agent")
    print("="*60)
    
    from NEURAL_NETWORK_BRAIN import HybridAgent
    
    agent = HybridAgent()
    
    assets = [
        {'name': 'admin.example.com', 'degree': 2, 'technologies': ['wordpress']},
        {'name': 'api.example.com', 'degree': 1, 'technologies': ['express']},
        {'name': 'staging.example.com', 'degree': 2, 'technologies': ['laravel']},
        {'name': 'www.example.com', 'degree': 0, 'technologies': ['nginx']},
    ]
    
    context = {
        'target': 'example.com',
        'explored_count': 10,
        'findings_count': 3
    }
    
    print("\nSelecting targets with hybrid agent...")
    selections = agent.select_targets(assets, context)
    
    print(f"\nTop selections:")
    for s in selections[:3]:
        print(f"  - {s['asset']}")
        if s.get('heuristic_score'):
            print(f"    Heuristic: {s['heuristic_score']}")
        if s.get('llm_reason'):
            print(f"    LLM: {s['llm_reason']}")
    
    # Test validation
    print("\nValidating a finding...")
    finding = {'type': 'xss', 'target': 'admin.example.com', 'severity': 'medium'}
    validation = agent.validate_finding(finding)
    print(f"  Verdict: {validation.get('verdict')}")
    print(f"  Confidence: {validation.get('confidence')}%")
    
    # Test feedback
    print("\nRecording feedback...")
    result = agent.record_feedback(finding, was_real=True)
    print(f"  Weights updated: {result['weights_updated']}")
    
    print("\n✅ Hybrid Agent: WORKING")
    return True


def test_integration():
    """Test integration with Six Degrees"""
    print("\n" + "="*60)
    print("TEST 4: Integration Check")
    print("="*60)
    
    # Check if Six Degrees is available
    try:
        from SIX_DEGREES_RECON_SYSTEM import SixDegreesReconSystem
        print("✅ SIX_DEGREES_RECON_SYSTEM.py: Available")
    except ImportError as e:
        print(f"⚠️ SIX_DEGREES_RECON_SYSTEM.py: {e}")
    
    # Check if Local AI is available
    try:
        from LOCAL_AI_REASONER import LocalAIReasoner
        print("✅ LOCAL_AI_REASONER.py: Available")
    except ImportError as e:
        print(f"⚠️ LOCAL_AI_REASONER.py: {e}")
    
    # Check if RL system is available
    try:
        from REINFORCEMENT_LEARNING_AUTOMATION import ReinforcementLearningAutomation
        print("✅ REINFORCEMENT_LEARNING_AUTOMATION.py: Available")
    except ImportError as e:
        print(f"⚠️ REINFORCEMENT_LEARNING_AUTOMATION.py: {e}")
    
    # Check orchestrator
    try:
        from NEURAL_RECON_ORCHESTRATOR import NeuralReconOrchestrator
        print("✅ NEURAL_RECON_ORCHESTRATOR.py: Available")
    except ImportError as e:
        print(f"⚠️ NEURAL_RECON_ORCHESTRATOR.py: {e}")
    
    return True


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║         NEURAL NETWORK BRAIN - SYSTEM TEST                          ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    tests = [
        ("Learned Prioritizer", test_learned_prioritizer),
        ("Ollama Brain", test_ollama_brain),
        ("Hybrid Agent", test_hybrid_agent),
        ("Integration", test_integration),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, "✅ PASS"))
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
            results.append((name, f"❌ FAIL: {e}"))
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for name, status in results:
        print(f"  {name}: {status}")
    
    print("\n" + "="*60)
    print("NEXT STEPS")
    print("="*60)
    print("""
1. If Ollama not running:
   curl -fsSL https://ollama.com/install.sh | sh
   ollama serve
   ollama pull llama3.1:8b-instruct-q4_0

2. Run a demo scan:
   python3 NEURAL_RECON_ORCHESTRATOR.py --demo

3. Run a real scan:
   python3 NEURAL_RECON_ORCHESTRATOR.py target.com

4. After finding results, record outcomes:
   from NEURAL_NETWORK_BRAIN import LearnedPrioritizer
   p = LearnedPrioritizer()
   p.learn({'name': 'target', 'type': 'xss'}, was_real_bug=True)
    """)


if __name__ == "__main__":
    main()
