#!/usr/bin/env python3
"""
TEST NEURAL INTEGRATION
Verify neural network brain integration across all systems

Tests:
- SENTINEL_AGENT.py neural scoring
- run_pipeline.py neural prioritization
- massive_bug_bounty_scaling.py neural target selection
- NEURAL_INTEGRATION_WRAPPER functionality
"""

import sys
import json
from pathlib import Path

def test_neural_wrapper():
    """Test NEURAL_INTEGRATION_WRAPPER"""
    print("\n" + "="*60)
    print("TESTING NEURAL INTEGRATION WRAPPER")
    print("="*60)
    
    try:
        from NEURAL_INTEGRATION_WRAPPER import get_neural_integration, score_asset, prioritize_targets
        
        # Test singleton
        neural = get_neural_integration()
        print(f"✅ Neural wrapper initialized: {neural.enabled}")
        
        # Test asset scoring
        test_asset = {
            'name': 'example.com',
            'type': 'domain',
            'severity_counts': {'critical': 1, 'high': 2, 'medium': 3, 'low': 4}
        }
        score = score_asset(test_asset)
        print(f"✅ Asset scoring: {score:.3f}")
        
        # Test target prioritization
        test_targets = [
            {'name': 'target1.com', 'type': 'domain'},
            {'name': 'target2.com', 'type': 'domain'},
            {'name': 'target3.com', 'type': 'domain'}
        ]
        ranked = prioritize_targets(test_targets, top_n=3)
        print(f"✅ Target prioritization: {len(ranked)} targets ranked")
        
        # Test quick scan
        quick_result = neural.quick_scan('example.com')
        print(f"✅ Quick scan: {quick_result['priority']} (score: {quick_result['score']:.3f})")
        
        # Test learning stats
        stats = neural.get_learning_stats()
        print(f"✅ Learning stats: {stats.get('status', 'unknown')}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_sentinel_integration():
    """Test SENTINEL_AGENT neural integration"""
    print("\n" + "="*60)
    print("TESTING SENTINEL_AGENT NEURAL INTEGRATION")
    print("="*60)
    
    try:
        # Check if SENTINEL_AGENT has neural imports
        with open('SENTINEL_AGENT.py', 'r', encoding='utf-8') as f:
            content = f.read()
            
        if 'NEURAL_BRAIN_ENABLED' in content:
            print("✅ SENTINEL_AGENT has neural integration code")
            
            if 'from NEURAL_INTEGRATION_WRAPPER import' in content:
                print("✅ SENTINEL_AGENT imports neural wrapper")
            else:
                print("⚠️  SENTINEL_AGENT uses direct neural imports")
                
            if 'self.neural_enabled' in content:
                print("✅ SENTINEL_AGENT has neural initialization")
            else:
                print("⚠️  SENTINEL_AGENT missing neural initialization")
                
            if 'neural_score' in content:
                print("✅ SENTINEL_AGENT has neural scoring")
            else:
                print("⚠️  SENTINEL_AGENT missing neural scoring")
                
            return True
        else:
            print("❌ SENTINEL_AGENT missing neural integration")
            return False
            
    except FileNotFoundError:
        print("❌ SENTINEL_AGENT.py not found")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_pipeline_integration():
    """Test run_pipeline neural integration"""
    print("\n" + "="*60)
    print("TESTING RUN_PIPELINE NEURAL INTEGRATION")
    print("="*60)
    
    try:
        with open('run_pipeline.py', 'r', encoding='utf-8') as f:
            content = f.read()
            
        if 'NEURAL_BRAIN_ENABLED' in content:
            print("✅ run_pipeline has neural integration code")
            
            if 'from NEURAL_INTEGRATION_WRAPPER import' in content:
                print("✅ run_pipeline imports neural wrapper")
            else:
                print("⚠️  run_pipeline uses different neural import")
                
            if 'neural.prioritize_targets' in content:
                print("✅ run_pipeline has neural prioritization")
            else:
                print("⚠️  run_pipeline missing neural prioritization")
                
            if 'enhance_pipeline_stage' in content:
                print("✅ run_pipeline has pipeline enhancement")
            else:
                print("⚠️  run_pipeline missing pipeline enhancement")
                
            return True
        else:
            print("❌ run_pipeline missing neural integration")
            return False
            
    except FileNotFoundError:
        print("❌ run_pipeline.py not found")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_massive_scaling_integration():
    """Test massive_bug_bounty_scaling neural integration"""
    print("\n" + "="*60)
    print("TESTING MASSIVE_BUG_BOUNTY_SCALING NEURAL INTEGRATION")
    print("="*60)
    
    try:
        with open('massive_bug_bounty_scaling.py', 'r', encoding='utf-8') as f:
            content = f.read()
            
        if 'NEURAL_BRAIN_ENABLED' in content:
            print("✅ massive_bug_bounty_scaling has neural integration code")
            
            if 'from NEURAL_INTEGRATION_WRAPPER import' in content:
                print("✅ massive_bug_bounty_scaling imports neural wrapper")
            else:
                print("⚠️  massive_bug_bounty_scaling uses different neural import")
                
            if 'neural.prioritize_targets' in content:
                print("✅ massive_bug_bounty_scaling has neural prioritization")
            else:
                print("⚠️  massive_bug_bounty_scaling missing neural prioritization")
                
            if 'neural.validate_finding' in content:
                print("✅ massive_bug_bounty_scaling has neural validation")
            else:
                print("⚠️  massive_bug_bounty_scaling missing neural validation")
                
            if 'neural.record_feedback' in content:
                print("✅ massive_bug_bounty_scaling has neural learning")
            else:
                print("⚠️  massive_bug_bounty_scaling missing neural learning")
                
            return True
        else:
            print("❌ massive_bug_bounty_scaling missing neural integration")
            return False
            
    except FileNotFoundError:
        print("❌ massive_bug_bounty_scaling.py not found")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_neural_brain_availability():
    """Test if NEURAL_NETWORK_BRAIN is available"""
    print("\n" + "="*60)
    print("TESTING NEURAL NETWORK BRAIN AVAILABILITY")
    print("="*60)
    
    try:
        from NEURAL_NETWORK_BRAIN import LearnedPrioritizer, OllamaBrain, HybridAgent
        print("✅ NEURAL_NETWORK_BRAIN.py imports successful")
        
        # Test LearnedPrioritizer
        prioritizer = LearnedPrioritizer()
        print(f"✅ LearnedPrioritizer initialized")
        print(f"   Weights file: {prioritizer.weights_file}")
        print(f"   Training history: {len(prioritizer.training_history)} examples")
        
        # Test HybridAgent
        hybrid = HybridAgent()
        print(f"✅ HybridAgent initialized")
        
        # Test OllamaBrain
        ollama = OllamaBrain()
        print(f"✅ OllamaBrain initialized (available: {ollama.available})")
        
        return True
        
    except ImportError as e:
        print(f"❌ NEURAL_NETWORK_BRAIN import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Run all integration tests"""
    print("\n" + "="*70)
    print("NEURAL INTEGRATION TEST SUITE")
    print("="*70)
    print("Testing neural network brain integration across all systems")
    print("="*70)
    
    results = {
        'neural_brain': test_neural_brain_availability(),
        'neural_wrapper': test_neural_wrapper(),
        'sentinel_agent': test_sentinel_integration(),
        'run_pipeline': test_pipeline_integration(),
        'massive_scaling': test_massive_scaling_integration()
    }
    
    # Summary
    print("\n" + "="*70)
    print("INTEGRATION TEST SUMMARY")
    print("="*70)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} : {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL NEURAL INTEGRATION TESTS PASSED!")
        print("Neural Network Brain successfully integrated across all systems")
    else:
        print(f"\n⚠️  {total - passed} integration tests failed")
        print("Check the failed components above")
    
    print("\n" + "="*70)
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
