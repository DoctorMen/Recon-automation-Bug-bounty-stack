#!/usr/bin/env python3
"""
NEURAL INTEGRATION WRAPPER
Unified neural network brain integration for all security systems

Provides simple interface for:
- SENTINEL_AGENT.py
- run_pipeline.py
- massive_bug_bounty_scaling.py
- Any other security scanning system

Usage:
    from NEURAL_INTEGRATION_WRAPPER import NeuralIntegration
    neural = NeuralIntegration()
    
    # Score assets
    score = neural.score_asset(asset)
    
    # Prioritize targets
    ranked = neural.prioritize_targets(targets)
    
    # Record feedback
    neural.record_feedback(asset, was_real_bug=True)
"""

import json
import os
from pathlib import Path
from datetime import datetime

# Import neural brain components
try:
    from NEURAL_NETWORK_BRAIN import LearnedPrioritizer, OllamaBrain, HybridAgent
    NEURAL_BRAIN_AVAILABLE = True
except ImportError:
    NEURAL_BRAIN_AVAILABLE = False
    print("⚠️  Neural Network Brain not available")

class NeuralIntegration:
    """
    Unified wrapper for neural network brain functionality
    Simplifies integration across all security systems
    """
    
    def __init__(self, enable_ollama=True):
        self.enabled = NEURAL_BRAIN_AVAILABLE
        
        if self.enabled:
            self.prioritizer = LearnedPrioritizer()
            self.hybrid_agent = HybridAgent()
            
            if enable_ollama:
                self.ollama = OllamaBrain()
                self.ollama_enabled = self.ollama.available
            else:
                self.ollama_enabled = False
                
            print(f"✅ Neural Integration initialized")
            print(f"   Prioritizer: ✓")
            print(f"   Hybrid Agent: ✓")
            print(f"   Ollama LLM: {'✓' if self.ollama_enabled else '✗'}")
        else:
            print("⚠️  Neural Integration disabled (NEURAL_NETWORK_BRAIN.py not found)")
    
    def score_asset(self, asset):
        """
        Score a single asset using neural prioritizer
        
        Args:
            asset: Dict with asset information (name, type, severity, etc.)
            
        Returns:
            Float score (0.0-1.0) or 0.0 if disabled
        """
        if not self.enabled:
            return 0.0
            
        try:
            return self.prioritizer.score(asset)
        except Exception as e:
            print(f"⚠️  Neural scoring error: {e}")
            return 0.0
    
    def prioritize_targets(self, targets, top_n=None):
        """
        Prioritize a list of targets using neural intelligence
        
        Args:
            targets: List of asset dictionaries
            top_n: Number of top targets to return (None for all)
            
        Returns:
            List of (asset, score) tuples sorted by score
        """
        if not self.enabled:
            # Fallback: simple scoring
            scored = [(t, 0.5) for t in targets]
            return scored[:top_n] if top_n else scored
            
        try:
            return self.prioritizer.prioritize(targets, top_n)
        except Exception as e:
            print(f"⚠️  Neural prioritization error: {e}")
            scored = [(t, 0.5) for t in targets]
            return scored[:top_n] if top_n else scored
    
    def select_targets_with_llm(self, targets, context):
        """
        Select targets using hybrid agent (heuristics + LLM)
        
        Args:
            targets: List of asset dictionaries
            context: Dict with scan context
            
        Returns:
            List of selected assets with scoring info
        """
        if not self.enabled:
            return targets[:5]  # Simple fallback
            
        try:
            return self.hybrid_agent.select_targets(targets, context)
        except Exception as e:
            print(f"⚠️  Hybrid selection error: {e}")
            return targets[:5]
    
    def validate_finding(self, finding):
        """
        Validate a finding using neural intelligence
        
        Args:
            finding: Dict with vulnerability information
            
        Returns:
            Dict with validation result
        """
        if not self.enabled:
            return {
                'verdict': 'unknown',
                'confidence': 50,
                'reason': 'Neural validation not available'
            }
            
        try:
            return self.hybrid_agent.validate_finding(finding)
        except Exception as e:
            print(f"⚠️  Neural validation error: {e}")
            return {
                'verdict': 'unknown',
                'confidence': 50,
                'reason': f'Error: {e}'
            }
    
    def record_feedback(self, asset, was_real_bug=False, was_false_positive=False):
        """
        Record feedback to improve neural learning
        
        Args:
            asset: Dict with asset information
            was_real_bug: Boolean - was this a real vulnerability?
            was_false_positive: Boolean - was this a false positive?
            
        Returns:
            Dict with learning result
        """
        if not self.enabled:
            return {'weights_updated': False, 'error': 'Neural brain not available'}
            
        try:
            result = self.prioritizer.learn(asset, was_real_bug, was_false_positive)
            
            # Also record in hybrid agent
            self.hybrid_agent.record_feedback(asset, was_real_bug)
            
            return result
        except Exception as e:
            print(f"⚠️  Neural learning error: {e}")
            return {'weights_updated': False, 'error': str(e)}
    
    def get_learning_stats(self):
        """
        Get neural learning statistics
        
        Returns:
            Dict with learning metrics
        """
        if not self.enabled:
            return {'status': 'disabled'}
            
        try:
            stats = {
                'status': 'active',
                'total_examples': len(self.prioritizer.training_history),
                'last_training': self.prioritizer.last_training_time,
                'weights_file': str(self.prioritizer.weights_file),
                'ollama_available': self.ollama_enabled
            }
            
            if self.prioritizer.training_history:
                recent = self.prioritizer.training_history[-10:]
                stats['recent_accuracy'] = sum(1 for t in recent if t.get('correct')) / len(recent)
                stats['real_bugs_found'] = sum(1 for t in recent if t.get('was_real_bug'))
                
            return stats
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def enhance_pipeline_stage(self, stage_name, data):
        """
        Enhance pipeline stage with neural intelligence
        
        Args:
            stage_name: Name of pipeline stage
            data: Stage data to enhance
            
        Returns:
            Enhanced data with neural scoring
        """
        if not self.enabled:
            return data
            
        enhancements = {
            'neural_score': 0.0,
            'neural_priority': 'medium',
            'neural_insights': []
        }
        
        try:
            if stage_name == 'recon':
                # Score discovered assets
                if isinstance(data, list):
                    scored_assets = []
                    for asset in data:
                        asset_dict = {
                            'name': asset.get('name', asset),
                            'type': asset.get('type', 'unknown'),
                            'stage': 'recon'
                        }
                        score = self.score_asset(asset_dict)
                        asset['neural_score'] = score
                        scored_assets.append(asset)
                    
                    # Sort by neural score
                    scored_assets.sort(key=lambda x: x.get('neural_score', 0), reverse=True)
                    enhancements['ranked_assets'] = scored_assets
                    
            elif stage_name == 'vulnerability':
                # Validate and score findings
                if isinstance(data, list):
                    enhanced_findings = []
                    for finding in data:
                        validation = self.validate_finding(finding)
                        finding['neural_validation'] = validation
                        enhanced_findings.append(finding)
                    
                    enhancements['validated_findings'] = enhanced_findings
                    
            elif stage_name == 'target_selection':
                # Prioritize targets for scanning
                if isinstance(data, list):
                    context = {'stage': 'selection', 'timestamp': datetime.now().isoformat()}
                    selected = self.select_targets_with_llm(data, context)
                    enhancements['selected_targets'] = selected
                    
            # Add learning stats
            enhancements['learning_stats'] = self.get_learning_stats()
            
        except Exception as e:
            print(f"⚠️  Pipeline enhancement error for {stage_name}: {e}")
            enhancements['error'] = str(e)
            
        return enhancements
    
    def quick_scan(self, target):
        """
        Quick neural scan of a target
        
        Args:
            target: Target domain/IP
            
        Returns:
            Dict with quick assessment
        """
        if not self.enabled:
            return {
                'target': target,
                'score': 0.5,
                'priority': 'medium',
                'recommendation': 'Standard scan recommended'
            }
            
        try:
            asset = {'name': target, 'type': 'domain'}
            score = self.score_asset(asset)
            
            if score > 0.7:
                priority = 'high'
                recommendation = 'Immediate scan recommended'
            elif score > 0.4:
                priority = 'medium'
                recommendation = 'Standard scan recommended'
            else:
                priority = 'low'
                recommendation = 'Optional scan'
                
            return {
                'target': target,
                'score': score,
                'priority': priority,
                'recommendation': recommendation,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'target': target,
                'score': 0.5,
                'priority': 'medium',
                'error': str(e)
            }


# Singleton instance for easy import
_neural_instance = None

def get_neural_integration():
    """Get singleton neural integration instance"""
    global _neural_instance
    if _neural_instance is None:
        _neural_instance = NeuralIntegration()
    return _neural_instance

# Convenience functions for direct import
def score_asset(asset):
    """Score an asset using neural brain"""
    return get_neural_integration().score_asset(asset)

def prioritize_targets(targets, top_n=None):
    """Prioritize targets using neural brain"""
    return get_neural_integration().prioritize_targets(targets, top_n)

def record_feedback(asset, was_real_bug=False):
    """Record feedback for neural learning"""
    return get_neural_integration().record_feedback(asset, was_real_bug)

def quick_scan(target):
    """Quick neural scan of target"""
    return get_neural_integration().quick_scan(target)
