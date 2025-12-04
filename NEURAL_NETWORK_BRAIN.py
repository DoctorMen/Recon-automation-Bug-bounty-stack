#!/usr/bin/env python3
"""
NEURAL NETWORK BRAIN - 3Blue1Brown Concepts Applied to Cybersecurity
=====================================================================
Implements neural network-inspired learning for bug bounty hunting.
Uses Ollama for local LLM (FREE, no API costs).

CONCEPTS APPLIED (from 3Blue1Brown Neural Networks playlist):
1. Weighted Sums - Assets scored by learned weights
2. Activation Functions - Sigmoid for confidence normalization
3. Gradient Descent - Weights adjust based on outcome feedback
4. Backpropagation - Credit assignment across agent chain
5. Multi-layer Architecture - Heuristics → Local LLM → Final decision

Copyright (c) 2025 DoctorMen
"""

import json
import math
import hashlib
import requests
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from collections import defaultdict
import logging
import re

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# LAYER 1: LEARNED PRIORITIZER (Neural-inspired weights)
# ============================================================================

class LearnedPrioritizer:
    """
    Neural-network-inspired scoring that learns from YOUR feedback.
    
    From 3Blue1Brown Episode 1: A neuron is just a weighted sum + activation function.
    This implements exactly that for asset prioritization.
    
    No API needed - runs entirely local, learns from your outcomes.
    """
    
    WEIGHTS_FILE = Path.home() / ".bug_bounty" / "learned_weights.json"
    FEEDBACK_FILE = Path.home() / ".bug_bounty" / "feedback_history.json"
    
    def __init__(self):
        self.weights = self._load_or_init_weights()
        self.feedback_history = self._load_feedback_history()
        self.learning_rate = 0.1
        self.weights_file = self.WEIGHTS_FILE
        self.last_training_time = None
        self.training_history = self.feedback_history  # Alias for compatibility
        
    def _load_or_init_weights(self) -> dict:
        """Load weights or initialize with research-based defaults"""
        if self.WEIGHTS_FILE.exists():
            try:
                return json.loads(self.WEIGHTS_FILE.read_text())
            except:
                pass
        
        # Initial weights based on CWE priority map (from your memory)
        # These EVOLVE based on YOUR results
        return {
            # === Naming Patterns (high signal) ===
            'admin_in_name': 0.85,       # CWE-284 access control
            'api_in_name': 0.75,         # API endpoints = IDOR/SSRF
            'staging_in_name': 0.80,     # Often has debug enabled
            'dev_in_name': 0.75,         # Development = weak auth
            'test_in_name': 0.65,        # Test environments
            'internal_in_name': 0.70,    # Internal = forgotten
            'debug_in_name': 0.90,       # Debug = info disclosure
            'beta_in_name': 0.70,        # Beta = less hardened
            'v1_in_name': 0.50,          # Older versions
            'v2_in_name': 0.40,          # Current versions
            'graphql_in_name': 0.80,     # GraphQL = IDOR, introspection
            'rest_in_name': 0.60,        # REST APIs
            'upload_in_name': 0.85,      # File upload = RCE potential
            'login_in_name': 0.75,       # Auth endpoints
            'auth_in_name': 0.80,        # Auth mechanisms
            'oauth_in_name': 0.70,       # OAuth = misconfig
            'callback_in_name': 0.75,    # Callbacks = SSRF
            'webhook_in_name': 0.80,     # Webhooks = SSRF
            
            # === Technology Signals ===
            'express_detected': 0.55,    # Node.js common vulns
            'nginx_detected': 0.30,      # Generally secure
            'apache_detected': 0.35,     # Check version
            'wordpress_detected': 0.70,  # Plugin vulns common
            'php_detected': 0.60,        # Type juggling, SQLi
            'java_detected': 0.45,       # Deserialization
            'dotnet_detected': 0.50,     # ViewState, SQLi
            'python_detected': 0.55,     # Template injection
            'ruby_detected': 0.60,       # Mass assignment
            'react_detected': 0.35,      # Frontend, less direct
            'angular_detected': 0.40,    # Frontend
            'laravel_detected': 0.65,    # Debug mode, .env
            'django_detected': 0.45,     # DEBUG=True common
            'spring_detected': 0.55,     # Actuator endpoints
            'flask_detected': 0.60,      # Debug mode
            'struts_detected': 0.85,     # CVE-heavy
            
            # === Port Signals ===
            'port_80': 0.20,             # HTTP standard
            'port_443': 0.25,            # HTTPS standard
            'port_8080': 0.65,           # Dev servers
            'port_8443': 0.70,           # Alt HTTPS
            'port_3000': 0.75,           # Node dev
            'port_5000': 0.75,           # Flask dev
            'port_9000': 0.70,           # PHP-FPM
            'port_8000': 0.70,           # Django dev
            'port_4000': 0.70,           # Various dev
            
            # === Security Headers (missing = opportunity) ===
            'missing_csp': 0.50,         # XSS potential
            'missing_hsts': 0.40,        # MITM potential
            'missing_xframe': 0.55,      # Clickjacking
            'missing_nosniff': 0.30,     # MIME sniffing
            
            # === Graph Position (Six Degrees) ===
            'degree_0': 0.20,            # Main target (heavily tested)
            'degree_1': 0.35,            # Direct subdomain
            'degree_2': 0.55,            # One hop away
            'degree_3': 0.70,            # Deeper = often forgotten
            'degree_4': 0.75,            # Very deep
            'degree_5': 0.80,            # Rarely tested
            
            # === Historical Success (your patterns) ===
            'similar_to_success': 0.85,  # Similar to past wins
            'similar_to_failure': -0.50, # Similar to past FPs
            
            # === Bias term ===
            'bias': 0.1
        }
    
    def _load_feedback_history(self) -> list:
        """Load feedback history"""
        if self.FEEDBACK_FILE.exists():
            try:
                return json.loads(self.FEEDBACK_FILE.read_text())
            except:
                pass
        return []
    
    def save(self):
        """Save weights and feedback to disk"""
        self.WEIGHTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.WEIGHTS_FILE.write_text(json.dumps(self.weights, indent=2))
        self.FEEDBACK_FILE.write_text(json.dumps(self.feedback_history[-1000:], indent=2))
        logger.info(f"Weights saved to {self.WEIGHTS_FILE}")
    
    def extract_features(self, asset: dict) -> dict:
        """
        Turn an asset into a feature vector.
        Each feature is 0.0 or 1.0 (binary activation).
        """
        features = {}
        name = asset.get('name', '').lower()
        url = asset.get('url', '').lower()
        combined = f"{name} {url}"
        
        # Naming features
        keywords = [
            'admin', 'api', 'staging', 'dev', 'test', 'internal', 'debug',
            'beta', 'v1', 'v2', 'graphql', 'rest', 'upload', 'login',
            'auth', 'oauth', 'callback', 'webhook'
        ]
        for keyword in keywords:
            features[f'{keyword}_in_name'] = 1.0 if keyword in combined else 0.0
        
        # Technology features
        tech = str(asset.get('technologies', [])).lower()
        headers = str(asset.get('headers', {})).lower()
        tech_combined = f"{tech} {headers}"
        
        techs = [
            'express', 'nginx', 'apache', 'wordpress', 'php', 'java',
            'dotnet', 'python', 'ruby', 'react', 'angular', 'laravel',
            'django', 'spring', 'flask', 'struts'
        ]
        for t in techs:
            features[f'{t}_detected'] = 1.0 if t in tech_combined else 0.0
        
        # Port features
        ports = asset.get('ports', [])
        if isinstance(ports, str):
            ports = [int(p) for p in re.findall(r'\d+', ports)]
        for p in [80, 443, 8080, 8443, 3000, 5000, 9000, 8000, 4000]:
            features[f'port_{p}'] = 1.0 if p in ports else 0.0
        
        # Security header features
        headers_str = str(asset.get('headers', {})).lower()
        features['missing_csp'] = 1.0 if 'content-security-policy' not in headers_str else 0.0
        features['missing_hsts'] = 1.0 if 'strict-transport-security' not in headers_str else 0.0
        features['missing_xframe'] = 1.0 if 'x-frame-options' not in headers_str else 0.0
        features['missing_nosniff'] = 1.0 if 'x-content-type-options' not in headers_str else 0.0
        
        # Graph position (degree)
        degree = asset.get('degree', 1)
        for d in range(6):
            features[f'degree_{d}'] = 1.0 if degree == d else 0.0
        
        return features
    
    def score(self, asset: dict) -> float:
        """
        Score an asset using weighted sum + sigmoid activation.
        
        From 3Blue1Brown: output = sigmoid(Σ(weight_i * input_i) + bias)
        """
        features = self.extract_features(asset)
        
        # Weighted sum (like a neuron)
        raw_score = self.weights.get('bias', 0.1)
        for feature, value in features.items():
            if feature in self.weights:
                raw_score += self.weights[feature] * value
        
        # Sigmoid activation (keeps output 0-1)
        # From 3Blue1Brown Episode 1: sigmoid squashes to probability
        return 1 / (1 + math.exp(-raw_score))
    
    def learn(self, asset: dict, was_real_bug: bool) -> dict:
        """
        Backpropagation-lite: adjust weights based on outcome.
        
        From 3Blue1Brown Episode 3: Learning means adjusting weights
        in the direction that reduces error.
        
        error = actual - predicted
        weight_update = learning_rate * error * feature_value
        """
        features = self.extract_features(asset)
        predicted = self.score(asset)
        actual = 1.0 if was_real_bug else 0.0
        error = actual - predicted
        
        updates = {}
        
        # Update each weight (gradient descent)
        for feature, value in features.items():
            if feature in self.weights and value > 0:
                old_weight = self.weights[feature]
                delta = self.learning_rate * error * value
                self.weights[feature] += delta
                
                # Clamp to reasonable range
                self.weights[feature] = max(-2.0, min(2.0, self.weights[feature]))
                
                if abs(delta) > 0.01:
                    updates[feature] = {
                        'old': round(old_weight, 3),
                        'new': round(self.weights[feature], 3),
                        'delta': round(delta, 3)
                    }
        
        # Save feedback for history
        self.feedback_history.append({
            'asset': asset.get('name', asset.get('url', 'unknown')),
            'features': {k: v for k, v in features.items() if v > 0},
            'predicted': round(predicted, 3),
            'actual': actual,
            'error': round(error, 3),
            'timestamp': datetime.now().isoformat()
        })
        
        self.save()
        
        return {
            'predicted': predicted,
            'actual': actual,
            'error': error,
            'weights_updated': len(updates),
            'significant_updates': updates
        }
    
    def prioritize(self, assets: list, top_n: int = 10) -> list:
        """Rank assets by learned scoring"""
        scored = [(asset, self.score(asset)) for asset in assets]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_n]
    
    def get_top_features(self, asset: dict) -> list:
        """Get the features contributing most to the score"""
        features = self.extract_features(asset)
        contributions = []
        
        for feature, value in features.items():
            if value > 0 and feature in self.weights:
                contribution = self.weights[feature] * value
                if abs(contribution) > 0.1:
                    contributions.append((feature, round(contribution, 3)))
        
        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        return contributions[:5]


# ============================================================================
# LAYER 2: OLLAMA BRAIN (Local LLM - FREE)
# ============================================================================

class OllamaBrain:
    """
    Uses local Ollama models instead of paid APIs.
    Quality: 70-85% of Claude depending on model.
    Cost: $0
    
    Best models for security work:
    - llama3.1:70b-instruct-q4_0 (best overall)
    - qwen2.5:72b-instruct-q4_K_M (best at code/reasoning)
    - deepseek-coder:33b (best for technical analysis)
    """
    
    def __init__(self, model: str = "llama3.1:8b-instruct-q4_0"):
        self.model = model
        self.base_url = "http://localhost:11434"
        self.available = self._check_availability()
        
        if self.available:
            logger.info(f"Ollama connected: {model}")
        else:
            logger.warning("Ollama not available. Install: curl -fsSL https://ollama.com/install.sh | sh")
    
    def _check_availability(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def _call(self, prompt: str, system: str = None, timeout: int = 120) -> str:
        """Call Ollama API"""
        if not self.available:
            return self._fallback_response(prompt)
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9
                    }
                },
                timeout=timeout
            )
            
            if response.status_code == 200:
                return response.json().get("message", {}).get("content", "")
            else:
                return self._fallback_response(prompt)
        except Exception as e:
            logger.error(f"Ollama call failed: {e}")
            return self._fallback_response(prompt)
    
    def _fallback_response(self, prompt: str) -> str:
        """Fallback when Ollama isn't available"""
        # Extract key terms and return heuristic response
        prompt_lower = prompt.lower()
        
        if 'prioritize' in prompt_lower or 'select' in prompt_lower:
            return json.dumps({
                "selections": [
                    {"asset": "admin", "reason": "Admin panels have highest value"},
                    {"asset": "api", "reason": "APIs often have IDOR/auth issues"},
                    {"asset": "staging", "reason": "Staging often has debug enabled"}
                ]
            })
        elif 'analyze' in prompt_lower or 'vulnerability' in prompt_lower:
            return json.dumps({
                "verdict": "NEEDS_VERIFICATION",
                "confidence": 50,
                "reasoning": "Ollama unavailable - manual verification required"
            })
        else:
            return "Analysis unavailable - Ollama not running"
    
    def prioritize_assets(self, assets: list, context: dict) -> list:
        """Ask LLM which assets to explore next"""
        
        # Limit assets to avoid token overflow
        assets_summary = [
            {
                "name": a.get('name', a.get('url', 'unknown'))[:100],
                "type": a.get('type', 'unknown'),
                "degree": a.get('degree', 1),
                "technologies": str(a.get('technologies', []))[:100]
            }
            for a in assets[:30]
        ]
        
        prompt = f"""You are an expert bug bounty hunter analyzing reconnaissance data.

DISCOVERED ASSETS:
{json.dumps(assets_summary, indent=2)}

CONTEXT:
- Target: {context.get('target', 'unknown')}
- Already explored: {context.get('explored_count', 0)} assets
- Current findings: {context.get('findings_count', 0)}

TASK: Pick the TOP 5 assets most likely to have security vulnerabilities.

For each, explain WHY in one sentence. Focus on:
1. Access control issues (IDOR, BOLA)
2. Injection vulnerabilities (SQLi, XSS)
3. Authentication bypasses
4. Information disclosure
5. SSRF opportunities

Respond in this JSON format ONLY:
{{
    "selections": [
        {{"asset": "asset_name", "reason": "why this is high value"}},
        ...
    ]
}}"""

        response = self._call(
            prompt, 
            system="You are a security researcher. Be concise. Output valid JSON only."
        )
        
        try:
            # Try to parse JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())["selections"]
        except:
            pass
        
        # Fallback parsing
        return self._parse_fuzzy(response, assets)
    
    def analyze_finding(self, finding: dict) -> dict:
        """Analyze if a finding is real or FP"""
        
        prompt = f"""Analyze this potential security finding:

{json.dumps(finding, indent=2)}

Is this a REAL vulnerability or a FALSE POSITIVE?

Consider:
1. Is there actual security impact?
2. Could this be intentional configuration?
3. What's the exploitation path?
4. Business impact if exploited?

Respond in JSON:
{{
    "verdict": "REAL" or "FALSE_POSITIVE" or "NEEDS_VERIFICATION",
    "confidence": 0-100,
    "reasoning": "brief explanation",
    "exploitation_path": "how to exploit if real",
    "business_impact": "what happens if exploited",
    "next_steps": ["what to do next"]
}}"""

        response = self._call(prompt)
        
        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        return {
            "verdict": "NEEDS_VERIFICATION",
            "confidence": 50,
            "reasoning": response[:200] if response else "Analysis failed"
        }
    
    def find_attack_chains(self, findings: list, graph_summary: dict) -> list:
        """Use LLM to find multi-step attack chains"""
        
        prompt = f"""You are an elite penetration tester analyzing an attack surface.

CURRENT FINDINGS:
{json.dumps(findings[:20], indent=2)}

GRAPH SUMMARY:
- Nodes: {graph_summary.get('total_nodes', 0)}
- Relationships: {graph_summary.get('total_edges', 0)}
- Technologies: {graph_summary.get('technologies', [])}

TASK: Identify the top 3 most promising multi-step attack chains.

For each chain:
1. Entry point (which finding to start with)
2. Pivot points (how to move laterally)
3. Target (what you'd ultimately compromise)
4. Probability estimate (0-100%)
5. Business impact if successful

Think like a nation-state APT. What would they do?

Respond in JSON:
{{
    "attack_chains": [
        {{
            "name": "chain name",
            "entry_point": "starting vulnerability",
            "steps": ["step 1", "step 2", "step 3"],
            "final_target": "what you compromise",
            "probability": 75,
            "impact": "critical/high/medium",
            "business_impact": "what happens"
        }}
    ]
}}"""

        response = self._call(prompt, timeout=180)
        
        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group()).get("attack_chains", [])
        except:
            pass
        
        return []
    
    def _parse_fuzzy(self, text: str, assets: list) -> list:
        """Fallback parser when JSON fails"""
        selections = []
        asset_names = [a.get('name', a.get('url', '')) for a in assets]
        
        lines = text.split('\n')
        for line in lines:
            for asset_name in asset_names:
                if asset_name.lower() in line.lower():
                    selections.append({
                        "asset": asset_name,
                        "reason": line.strip()[:100]
                    })
                    break
        
        return selections[:5]


# ============================================================================
# LAYER 3: HYBRID AGENT (Heuristics + LLM combined)
# ============================================================================

class HybridAgent:
    """
    Combines fast heuristic scoring with slower LLM reasoning.
    
    Architecture (like a neural network):
    - Layer 1: Learned weights (instant, pattern matching)
    - Layer 2: Local LLM (slower, deeper reasoning)
    - Layer 3: Combined decision with confidence
    
    This mimics how the brain has fast System 1 and slow System 2.
    """
    
    def __init__(self, ollama_model: str = "llama3.1:8b-instruct-q4_0"):
        self.prioritizer = LearnedPrioritizer()
        self.brain = OllamaBrain(model=ollama_model)
        self.decision_log = []
        
        # Credit assignment for backpropagation
        self.agent_performance = {
            'heuristic_agent': {'successes': 0, 'total': 0},
            'llm_agent': {'successes': 0, 'total': 0},
            'combined_agent': {'successes': 0, 'total': 0}
        }
    
    def select_targets(self, assets: list, context: dict) -> list:
        """
        Two-stage target selection.
        
        Stage 1: Heuristic pre-filter (instant, free)
        Stage 2: LLM picks final targets from pre-filtered list
        """
        
        # Stage 1: Fast heuristic scoring
        logger.info("Stage 1: Heuristic pre-filtering...")
        scored = self.prioritizer.prioritize(assets, top_n=30)
        candidates = [asset for asset, score in scored]
        
        heuristic_picks = [
            {
                "asset": asset.get('name', asset.get('url', 'unknown')),
                "score": round(score, 3),
                "top_features": self.prioritizer.get_top_features(asset)
            }
            for asset, score in scored[:5]
        ]
        
        logger.info(f"Heuristic top 5: {[p['asset'] for p in heuristic_picks]}")
        
        # Stage 2: LLM refinement (if available)
        if self.brain.available:
            logger.info("Stage 2: LLM refinement...")
            llm_picks = self.brain.prioritize_assets(candidates, context)
            
            # Merge heuristic and LLM picks
            final_picks = self._merge_picks(heuristic_picks, llm_picks)
        else:
            logger.info("Stage 2: Skipped (Ollama not available)")
            final_picks = heuristic_picks
        
        # Log decision for learning
        self.decision_log.append({
            'timestamp': datetime.now().isoformat(),
            'assets_evaluated': len(assets),
            'heuristic_picks': heuristic_picks,
            'llm_picks': llm_picks if self.brain.available else None,
            'final_picks': final_picks
        })
        
        return final_picks
    
    def _merge_picks(self, heuristic: list, llm: list) -> list:
        """Merge heuristic and LLM picks with weighted voting"""
        merged = {}
        
        # Add heuristic picks with weight
        for i, pick in enumerate(heuristic):
            name = pick['asset']
            merged[name] = {
                'asset': name,
                'heuristic_rank': i + 1,
                'heuristic_score': pick.get('score', 0),
                'llm_rank': None,
                'llm_reason': None,
                'combined_score': (5 - i) * 0.6  # Weight: 0.6 for heuristic
            }
        
        # Add LLM picks with weight
        for i, pick in enumerate(llm):
            name = pick.get('asset', '')
            if name in merged:
                merged[name]['llm_rank'] = i + 1
                merged[name]['llm_reason'] = pick.get('reason', '')
                merged[name]['combined_score'] += (5 - i) * 0.4  # Weight: 0.4 for LLM
            else:
                merged[name] = {
                    'asset': name,
                    'heuristic_rank': None,
                    'heuristic_score': None,
                    'llm_rank': i + 1,
                    'llm_reason': pick.get('reason', ''),
                    'combined_score': (5 - i) * 0.4
                }
        
        # Sort by combined score
        sorted_picks = sorted(merged.values(), key=lambda x: x['combined_score'], reverse=True)
        return sorted_picks[:5]
    
    def validate_finding(self, finding: dict) -> dict:
        """Multi-layer validation of a potential vulnerability"""
        
        # Layer 1: Instant heuristic checks (obvious FPs)
        if self._obvious_false_positive(finding):
            result = {
                "verdict": "FALSE_POSITIVE",
                "confidence": 95,
                "layer": "heuristic",
                "reasoning": "Failed heuristic checks"
            }
            self.agent_performance['heuristic_agent']['total'] += 1
            return result
        
        # Layer 2: LLM analysis
        if self.brain.available:
            llm_result = self.brain.analyze_finding(finding)
            llm_result['layer'] = 'llm'
            self.agent_performance['llm_agent']['total'] += 1
            return llm_result
        
        # Fallback
        return {
            "verdict": "NEEDS_VERIFICATION",
            "confidence": 50,
            "layer": "fallback",
            "reasoning": "No LLM available for deep analysis"
        }
    
    def _obvious_false_positive(self, finding: dict) -> bool:
        """Catch obvious FPs without using LLM"""
        finding_str = str(finding).lower()
        
        fp_indicators = [
            'example.com' in finding_str,
            'localhost' in finding_str and 'target' not in finding_str,
            'test-data' in finding_str,
            finding.get('status_code') == 404,
            finding.get('status_code') == 403 and 'bypass' not in finding_str,
            'cloudflare' in finding_str and finding.get('type') == 'exposed_config',
            finding.get('severity') == 'info' and 'chain' not in finding_str,
        ]
        
        return any(fp_indicators)
    
    def record_feedback(self, finding: dict, was_real: bool, agent_used: str = 'combined'):
        """
        Learn from outcomes - backpropagation of credit.
        
        From 3Blue1Brown Episode 4: Credit assignment determines
        which weights to adjust and by how much.
        """
        
        # Update prioritizer weights
        learning_result = self.prioritizer.learn(finding, was_real)
        
        # Update agent performance tracking
        agent_key = f'{agent_used}_agent'
        if agent_key in self.agent_performance:
            self.agent_performance[agent_key]['total'] += 1
            if was_real:
                self.agent_performance[agent_key]['successes'] += 1
        
        # Log learning
        logger.info(f"Feedback recorded: {finding.get('type', 'unknown')} "
                   f"was {'REAL' if was_real else 'FP'}")
        logger.info(f"Weights updated: {learning_result['weights_updated']}")
        
        return learning_result
    
    def get_agent_reliability(self) -> dict:
        """Get reliability stats for each agent layer"""
        reliability = {}
        
        for agent, stats in self.agent_performance.items():
            if stats['total'] > 0:
                reliability[agent] = {
                    'accuracy': stats['successes'] / stats['total'],
                    'total_decisions': stats['total'],
                    'successes': stats['successes']
                }
            else:
                reliability[agent] = {
                    'accuracy': 0.5,  # Unknown
                    'total_decisions': 0,
                    'successes': 0
                }
        
        return reliability


# ============================================================================
# INTEGRATION: Connect to SixDegreesReconSystem
# ============================================================================

class NeuralReconIntegration:
    """
    Integrates neural network brain with Six Degrees Recon System.
    
    This is the glue that connects learned prioritization with
    graph-based reconnaissance.
    """
    
    def __init__(self, ollama_model: str = "llama3.1:8b-instruct-q4_0"):
        self.agent = HybridAgent(ollama_model=ollama_model)
        self.session_findings = []
        self.session_decisions = []
    
    def enhance_node_selection(self, nodes: list, graph_stats: dict) -> list:
        """
        Enhance Six Degrees node selection with neural prioritization.
        
        Called by SixDegreesReconSystem to choose which nodes to explore next.
        """
        
        # Convert nodes to asset format
        assets = [
            {
                'name': node.value if hasattr(node, 'value') else str(node),
                'type': node.type.value if hasattr(node, 'type') else 'unknown',
                'degree': node.degree if hasattr(node, 'degree') else 1,
                'technologies': node.metadata.get('technologies', []) if hasattr(node, 'metadata') else [],
                'ports': node.metadata.get('ports', []) if hasattr(node, 'metadata') else []
            }
            for node in nodes
        ]
        
        context = {
            'target': graph_stats.get('seed_target', 'unknown'),
            'explored_count': graph_stats.get('explored', 0),
            'findings_count': len(self.session_findings)
        }
        
        # Get prioritized selections
        selections = self.agent.select_targets(assets, context)
        
        # Map back to original nodes
        selected_names = [s['asset'] for s in selections]
        prioritized_nodes = []
        
        for node in nodes:
            node_name = node.value if hasattr(node, 'value') else str(node)
            if node_name in selected_names:
                prioritized_nodes.append((node, selections[selected_names.index(node_name)]))
        
        return prioritized_nodes
    
    def validate_graph_finding(self, finding: dict) -> dict:
        """
        Validate a finding from the graph exploration.
        """
        result = self.agent.validate_finding(finding)
        
        # Track for session
        self.session_findings.append({
            'finding': finding,
            'validation': result,
            'timestamp': datetime.now().isoformat()
        })
        
        return result
    
    def find_attack_chains_in_graph(self, findings: list, graph_summary: dict) -> list:
        """
        Use LLM to find attack chains across the discovered graph.
        """
        return self.agent.brain.find_attack_chains(findings, graph_summary)
    
    def learn_from_session(self, was_successful: bool):
        """
        Learn from entire session outcome.
        
        Called when you get bounty payment (success) or rejection (failure).
        """
        for item in self.session_findings:
            finding = item['finding']
            validation = item['validation']
            
            # If session was successful and we predicted REAL, good!
            # If session was successful and we predicted FP, we were wrong
            predicted_real = validation.get('verdict') == 'REAL'
            
            if was_successful:
                # Our predictions that said REAL were correct
                # Our predictions that said FP were wrong
                self.agent.record_feedback(finding, predicted_real)
            else:
                # Our predictions that said REAL were wrong
                # Our predictions that said FP were correct
                self.agent.record_feedback(finding, not predicted_real)
        
        logger.info(f"Session learning complete: {len(self.session_findings)} findings processed")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Demonstrate the Neural Network Brain"""
    
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║    NEURAL NETWORK BRAIN - 3Blue1Brown Concepts for Bug Bounty       ║
║         Learned Weights | Local LLM | Zero API Costs                ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize
    agent = HybridAgent()
    
    # Demo assets
    assets = [
        {'name': 'admin.example.com', 'degree': 2, 'technologies': ['wordpress', 'php']},
        {'name': 'api.example.com', 'degree': 1, 'technologies': ['express', 'nodejs']},
        {'name': 'staging.example.com', 'degree': 2, 'technologies': ['laravel', 'php']},
        {'name': 'www.example.com', 'degree': 0, 'technologies': ['nginx', 'react']},
        {'name': 'cdn.example.com', 'degree': 1, 'technologies': ['cloudflare']},
        {'name': 'debug.internal.example.com', 'degree': 3, 'technologies': ['flask', 'python']},
        {'name': 'graphql.example.com', 'degree': 1, 'technologies': ['nodejs', 'apollo']},
        {'name': 'webhook.example.com', 'degree': 2, 'technologies': ['nodejs']},
    ]
    
    context = {
        'target': 'example.com',
        'explored_count': 10,
        'findings_count': 3
    }
    
    print("🔍 ANALYZING ASSETS...")
    print("="*60)
    
    # Get selections
    selections = agent.select_targets(assets, context)
    
    print("\n🎯 TOP TARGETS (Neural Network Prioritization):")
    print("-"*60)
    
    for i, pick in enumerate(selections, 1):
        print(f"\n{i}. {pick['asset']}")
        if pick.get('heuristic_score'):
            print(f"   Heuristic Score: {pick['heuristic_score']}")
        if pick.get('llm_reason'):
            print(f"   LLM Reason: {pick['llm_reason']}")
        print(f"   Combined Score: {pick.get('combined_score', 'N/A')}")
    
    # Demo validation
    print("\n\n🔬 VALIDATING A FINDING...")
    print("="*60)
    
    demo_finding = {
        'type': 'missing_security_header',
        'target': 'admin.example.com',
        'header': 'X-Frame-Options',
        'severity': 'medium'
    }
    
    validation = agent.validate_finding(demo_finding)
    
    print(f"\nVerdict: {validation.get('verdict')}")
    print(f"Confidence: {validation.get('confidence')}%")
    print(f"Layer: {validation.get('layer')}")
    print(f"Reasoning: {validation.get('reasoning', 'N/A')}")
    
    # Demo learning
    print("\n\n🧠 RECORDING FEEDBACK (Learning)...")
    print("="*60)
    
    learning_result = agent.record_feedback(demo_finding, was_real=True)
    
    print(f"Weights updated: {learning_result['weights_updated']}")
    print(f"Prediction error: {learning_result['error']:.3f}")
    
    if learning_result.get('significant_updates'):
        print("\nSignificant weight changes:")
        for feature, changes in learning_result['significant_updates'].items():
            print(f"  {feature}: {changes['old']} → {changes['new']} (Δ{changes['delta']})")
    
    print("\n" + "="*60)
    print("✅ NEURAL NETWORK BRAIN DEMONSTRATION COMPLETE")
    print("💡 Weights saved to: ~/.bug_bounty/learned_weights.json")
    print("🚀 System learns from YOUR outcomes - no API costs!")
    print("="*60)


if __name__ == "__main__":
    main()
