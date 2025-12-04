#!/usr/bin/env python3
"""
NEURAL RECON ORCHESTRATOR
=========================
Orchestrates all reconnaissance using neural network-inspired prioritization.
Integrates with:
- SIX_DEGREES_RECON_SYSTEM.py (graph-based recon)
- LOCAL_AI_REASONER.py (pattern matching)
- REINFORCEMENT_LEARNING_AUTOMATION.py (ML learning)
- NEURAL_NETWORK_BRAIN.py (3Blue1Brown concepts)

This is the MASTER CONTROLLER for intelligent bug bounty hunting.

Copyright (c) 2025 DoctorMen
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our neural components
from NEURAL_NETWORK_BRAIN import (
    LearnedPrioritizer,
    OllamaBrain,
    HybridAgent,
    NeuralReconIntegration
)

# Import existing systems
try:
    from SIX_DEGREES_RECON_SYSTEM import (
        SixDegreesReconSystem,
        ReconGraph,
        Node,
        NodeType
    )
    SIX_DEGREES_AVAILABLE = True
except ImportError:
    SIX_DEGREES_AVAILABLE = False
    print("Warning: SIX_DEGREES_RECON_SYSTEM.py not available")

try:
    from LOCAL_AI_REASONER import LocalAIReasoner
    LOCAL_AI_AVAILABLE = True
except ImportError:
    LOCAL_AI_AVAILABLE = False
    print("Warning: LOCAL_AI_REASONER.py not available")

try:
    from REINFORCEMENT_LEARNING_AUTOMATION import ReinforcementLearningAutomation
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False
    print("Warning: REINFORCEMENT_LEARNING_AUTOMATION.py not available")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('neural_recon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class NeuralReconOrchestrator:
    """
    Master orchestrator that combines all intelligence systems.
    
    Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    USER REQUEST                              │
    └─────────────────────────────────────────────────────────────┘
                                ↓
    ┌─────────────────────────────────────────────────────────────┐
    │              NEURAL RECON ORCHESTRATOR                       │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │  LAYER 1: Learned Prioritizer (Weights + Sigmoid)     │  │
    │  │  - Instant scoring based on learned patterns          │  │
    │  │  - Updates via gradient descent from feedback         │  │
    │  └───────────────────────────────────────────────────────┘  │
    │                          ↓                                   │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │  LAYER 2: Local AI Reasoner (Heuristics)              │  │
    │  │  - Decision trees for vulnerability patterns          │  │
    │  │  - Exploit chain detection                            │  │
    │  └───────────────────────────────────────────────────────┘  │
    │                          ↓                                   │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │  LAYER 3: Ollama Brain (Local LLM)                    │  │
    │  │  - Deep reasoning when needed                         │  │
    │  │  - Attack chain discovery                             │  │
    │  └───────────────────────────────────────────────────────┘  │
    │                          ↓                                   │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │  LAYER 4: Six Degrees Recon (Graph Exploration)       │  │
    │  │  - Node discovery and relationship mapping            │  │
    │  │  - Prioritized by neural scoring                      │  │
    │  └───────────────────────────────────────────────────────┘  │
    │                          ↓                                   │
    │  ┌───────────────────────────────────────────────────────┐  │
    │  │  LAYER 5: Reinforcement Learning (Continuous)         │  │
    │  │  - Learn from all outcomes                            │  │
    │  │  - Improve predictions over time                      │  │
    │  └───────────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────────┘
                                ↓
    ┌─────────────────────────────────────────────────────────────┐
    │              PRIORITIZED FINDINGS + ATTACK CHAINS            │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, ollama_model: str = "llama3.1:8b-instruct-q4_0"):
        # Initialize all layers
        self.prioritizer = LearnedPrioritizer()
        self.hybrid_agent = HybridAgent(ollama_model=ollama_model)
        self.neural_integration = NeuralReconIntegration(ollama_model=ollama_model)
        
        # Optional layers (if available)
        self.local_ai = LocalAIReasoner() if LOCAL_AI_AVAILABLE else None
        self.rl_system = ReinforcementLearningAutomation() if RL_AVAILABLE else None
        
        # Session tracking
        self.session_id = f"NRO-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_findings = []
        self.session_decisions = []
        self.session_start = datetime.now()
        
        logger.info(f"Neural Recon Orchestrator initialized: {self.session_id}")
        logger.info(f"Available layers: Prioritizer=✓, HybridAgent=✓, "
                   f"LocalAI={'✓' if self.local_ai else '✗'}, "
                   f"RL={'✓' if self.rl_system else '✗'}")
    
    def run_intelligent_recon(
        self,
        target: str,
        scope: List[str],
        max_degree: int = 2,
        dry_run: bool = False
    ) -> Dict:
        """
        Run full intelligent reconnaissance with neural prioritization.
        
        This is the main entry point for smart bug hunting.
        """
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         NEURAL RECONNAISSANCE ORCHESTRATOR                           ║
║     Learned Weights | Graph Search | Local LLM | Zero API Costs      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Session: {self.session_id}
║  Target: {target}
║  Scope: {', '.join(scope[:3])}{'...' if len(scope) > 3 else ''}
║  Max Degree: {max_degree}
╚══════════════════════════════════════════════════════════════════════╝
        """)
        
        results = {
            'session_id': self.session_id,
            'target': target,
            'scope': scope,
            'started_at': datetime.now().isoformat(),
            'phases': {},
            'prioritized_findings': [],
            'attack_chains': [],
            'learning_insights': {}
        }
        
        # PHASE 1: Initial Prioritization
        print("\n" + "="*60)
        print("📊 PHASE 1: Initial Target Analysis")
        print("="*60)
        
        initial_analysis = self._phase_initial_analysis(target, scope)
        results['phases']['initial_analysis'] = initial_analysis
        
        # PHASE 2: Graph Exploration (if Six Degrees available)
        if SIX_DEGREES_AVAILABLE:
            print("\n" + "="*60)
            print("🕸️ PHASE 2: Graph-Based Reconnaissance")
            print("="*60)
            
            graph_results = self._phase_graph_exploration(
                target, scope, max_degree, dry_run
            )
            results['phases']['graph_exploration'] = graph_results
        
        # PHASE 3: Neural Prioritization of Findings
        print("\n" + "="*60)
        print("🧠 PHASE 3: Neural Prioritization")
        print("="*60)
        
        prioritized = self._phase_neural_prioritization()
        results['prioritized_findings'] = prioritized
        
        # PHASE 4: Attack Chain Discovery
        print("\n" + "="*60)
        print("⚡ PHASE 4: Attack Chain Analysis")
        print("="*60)
        
        attack_chains = self._phase_attack_chain_discovery(results)
        results['attack_chains'] = attack_chains
        
        # PHASE 5: Generate Learning Insights
        print("\n" + "="*60)
        print("📈 PHASE 5: Learning Insights")
        print("="*60)
        
        insights = self._phase_learning_insights()
        results['learning_insights'] = insights
        
        # Save results
        results['completed_at'] = datetime.now().isoformat()
        results['duration_seconds'] = (
            datetime.now() - self.session_start
        ).total_seconds()
        
        self._save_session_results(results)
        self._print_summary(results)
        
        return results
    
    def _phase_initial_analysis(self, target: str, scope: List[str]) -> Dict:
        """Initial target analysis using learned patterns"""
        
        # Create initial asset from target
        initial_asset = {
            'name': target,
            'url': f"https://{target}",
            'degree': 0,
            'type': 'domain'
        }
        
        # Score using learned prioritizer
        score = self.prioritizer.score(initial_asset)
        features = self.prioritizer.get_top_features(initial_asset)
        
        print(f"Target: {target}")
        print(f"Initial Score: {score:.3f}")
        print(f"Top Features: {features}")
        
        # Use local AI reasoner if available
        predictions = []
        if self.local_ai:
            predictions = self.local_ai.predict_vulnerabilities([target])
            print(f"\nVulnerability Predictions:")
            for pred in predictions[:3]:
                print(f"  - {pred.get('predicted_vuln', 'unknown')}: "
                      f"{pred.get('confidence', 0):.0%}")
        
        return {
            'target': target,
            'initial_score': score,
            'key_features': features,
            'vulnerability_predictions': predictions
        }
    
    def _phase_graph_exploration(
        self,
        target: str,
        scope: List[str],
        max_degree: int,
        dry_run: bool
    ) -> Dict:
        """Run Six Degrees reconnaissance with neural prioritization"""
        
        # Initialize Six Degrees system
        recon = SixDegreesReconSystem(
            seed_target=target,
            scope=scope,
            max_degree=max_degree,
            dry_run=dry_run
        )
        
        # Run reconnaissance
        graph_results = recon.run()
        
        # Get all discovered nodes
        all_nodes = list(recon.graph.nodes.values())
        
        # Prioritize using neural scoring
        prioritized_nodes = self._prioritize_nodes(all_nodes)
        
        print(f"\nDiscovered {len(all_nodes)} nodes")
        print(f"Neural prioritization complete")
        print(f"Top 5 high-value targets:")
        
        for i, (node, score) in enumerate(prioritized_nodes[:5], 1):
            print(f"  {i}. {node.value} (score: {score:.3f}, degree: {node.degree})")
        
        # Store findings
        for node in all_nodes:
            for finding in node.findings:
                self.session_findings.append({
                    'node': node.value,
                    'finding': finding,
                    'node_score': self.prioritizer.score({
                        'name': node.value,
                        'degree': node.degree,
                        'type': node.type.value
                    })
                })
        
        return {
            'total_nodes': len(all_nodes),
            'graph_stats': graph_results.get('statistics', {}),
            'prioritized_nodes': [
                {'name': n.value, 'score': s, 'degree': n.degree}
                for n, s in prioritized_nodes[:10]
            ],
            'raw_findings': graph_results.get('findings', [])
        }
    
    def _prioritize_nodes(self, nodes: list) -> List:
        """Prioritize nodes using neural scoring"""
        scored = []
        
        for node in nodes:
            asset = {
                'name': node.value,
                'degree': node.degree,
                'type': node.type.value if hasattr(node.type, 'value') else str(node.type),
                'technologies': node.metadata.get('technologies', []) if hasattr(node, 'metadata') else []
            }
            score = self.prioritizer.score(asset)
            scored.append((node, score))
        
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored
    
    def _phase_neural_prioritization(self) -> List[Dict]:
        """Prioritize all findings using hybrid agent"""
        
        if not self.session_findings:
            print("No findings to prioritize")
            return []
        
        # Convert findings to assets for prioritization
        assets = [
            {
                'name': f['node'],
                'type': f['finding'].get('type', 'unknown'),
                'severity': f['finding'].get('severity', 'unknown'),
                **f['finding']
            }
            for f in self.session_findings
        ]
        
        # Get neural prioritization
        context = {
            'target': self.session_findings[0]['node'] if self.session_findings else 'unknown',
            'explored_count': len(set(f['node'] for f in self.session_findings)),
            'findings_count': len(self.session_findings)
        }
        
        prioritized = self.hybrid_agent.select_targets(assets[:30], context)
        
        print(f"Prioritized {len(prioritized)} findings")
        for i, p in enumerate(prioritized[:5], 1):
            print(f"  {i}. {p.get('asset', 'unknown')}")
            if p.get('llm_reason'):
                print(f"     Reason: {p['llm_reason']}")
        
        return prioritized
    
    def _phase_attack_chain_discovery(self, results: Dict) -> List[Dict]:
        """Discover attack chains using LLM reasoning"""
        
        # Collect all findings
        all_findings = []
        
        # From graph exploration
        if 'graph_exploration' in results.get('phases', {}):
            raw = results['phases']['graph_exploration'].get('raw_findings', [])
            all_findings.extend(raw)
        
        # From session findings
        all_findings.extend([f['finding'] for f in self.session_findings])
        
        if not all_findings:
            print("No findings to analyze for attack chains")
            return []
        
        # Get graph summary
        graph_summary = {
            'total_nodes': results.get('phases', {}).get('graph_exploration', {}).get('total_nodes', 0),
            'total_edges': 0,
            'technologies': []
        }
        
        # Find attack chains using LLM
        if self.hybrid_agent.brain.available:
            chains = self.hybrid_agent.brain.find_attack_chains(
                all_findings[:20],
                graph_summary
            )
            
            print(f"Discovered {len(chains)} attack chains")
            for i, chain in enumerate(chains[:3], 1):
                print(f"\n  Chain {i}: {chain.get('name', 'Unknown')}")
                print(f"    Entry: {chain.get('entry_point', 'N/A')}")
                print(f"    Impact: {chain.get('impact', 'N/A')}")
                print(f"    Probability: {chain.get('probability', 0)}%")
            
            return chains
        else:
            # Fallback: use local AI reasoner
            if self.local_ai:
                chains = self.local_ai.find_exploit_chains(all_findings)
                print(f"Found {len(chains)} potential chains (heuristic)")
                return chains
        
        return []
    
    def _phase_learning_insights(self) -> Dict:
        """Generate learning insights from session"""
        
        insights = {
            'session_summary': {
                'total_findings': len(self.session_findings),
                'unique_targets': len(set(f['node'] for f in self.session_findings)),
                'duration': (datetime.now() - self.session_start).total_seconds()
            },
            'weight_analysis': {},
            'recommendations': []
        }
        
        # Analyze current weights
        top_weights = sorted(
            self.prioritizer.weights.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:10]
        
        insights['weight_analysis'] = {
            'top_positive': [(k, v) for k, v in top_weights if v > 0][:5],
            'top_negative': [(k, v) for k, v in top_weights if v < 0][:5]
        }
        
        print(f"Session analyzed: {insights['session_summary']['total_findings']} findings")
        print(f"\nTop prioritization features:")
        for feature, weight in insights['weight_analysis']['top_positive']:
            print(f"  + {feature}: {weight:.3f}")
        
        # Generate recommendations
        if self.session_findings:
            high_score_findings = [
                f for f in self.session_findings
                if f.get('node_score', 0) > 0.7
            ]
            
            if high_score_findings:
                insights['recommendations'].append(
                    f"Focus on {len(high_score_findings)} high-score targets"
                )
        
        return insights
    
    def _save_session_results(self, results: Dict):
        """Save session results to file"""
        filename = f"neural_recon_{self.session_id}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Results saved to: {filename}")
    
    def _print_summary(self, results: Dict):
        """Print final summary"""
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    RECONNAISSANCE COMPLETE                           ║
╠══════════════════════════════════════════════════════════════════════╣
║  Session: {self.session_id}
║  Duration: {results['duration_seconds']:.1f} seconds
║  Total Findings: {len(self.session_findings)}
║  Attack Chains: {len(results.get('attack_chains', []))}
║  Prioritized Targets: {len(results.get('prioritized_findings', []))}
╚══════════════════════════════════════════════════════════════════════╝

💾 Results saved to: neural_recon_{self.session_id}.json

🧠 To record feedback and improve the system:
   orchestrator.record_outcome(was_successful=True/False)
        """)
    
    def record_outcome(self, was_successful: bool, bounty_amount: float = 0):
        """
        Record the outcome of this session to improve future predictions.
        
        Call this when you:
        - Get a bounty payment (was_successful=True, bounty_amount=amount)
        - Get rejected (was_successful=False)
        - Verify findings manually (was_successful=True/False)
        
        This triggers backpropagation-style learning across all weights.
        """
        
        print(f"\n🧠 Recording outcome: {'SUCCESS' if was_successful else 'FAILURE'}")
        
        # Learn from each finding
        for item in self.session_findings:
            self.prioritizer.learn(
                {
                    'name': item['node'],
                    **item['finding']
                },
                was_real_bug=was_successful
            )
        
        # Update RL system if available
        if self.rl_system and was_successful:
            self.rl_system.learn_from_assessment({
                'target': self.session_findings[0]['node'] if self.session_findings else 'unknown',
                'findings': self.session_findings,
                'bounty': bounty_amount
            })
        
        print(f"   Weights updated for {len(self.session_findings)} findings")
        print(f"   Future predictions will be {'boosted' if was_successful else 'adjusted'}")
        
        if bounty_amount > 0:
            print(f"   Bounty recorded: ${bounty_amount}")


# ============================================================================
# QUICK START FUNCTIONS
# ============================================================================

def quick_scan(target: str, scope: List[str] = None, max_degree: int = 2):
    """
    Quick scan with neural prioritization.
    
    Example:
        quick_scan("example.com")
        quick_scan("target.com", ["target.com", "*.target.com"], max_degree=3)
    """
    
    scope = scope or [target, f"*.{target}"]
    
    orchestrator = NeuralReconOrchestrator()
    results = orchestrator.run_intelligent_recon(
        target=target,
        scope=scope,
        max_degree=max_degree,
        dry_run=False
    )
    
    return orchestrator, results


def analyze_assets(assets: List[Dict]) -> List[Dict]:
    """
    Analyze and prioritize a list of assets.
    
    Example:
        assets = [
            {'name': 'admin.example.com', 'degree': 2},
            {'name': 'api.example.com', 'degree': 1},
        ]
        prioritized = analyze_assets(assets)
    """
    
    agent = HybridAgent()
    context = {'target': 'analysis', 'explored_count': 0, 'findings_count': 0}
    
    return agent.select_targets(assets, context)


def learn_from_result(finding: Dict, was_real: bool):
    """
    Teach the system about a finding outcome.
    
    Example:
        learn_from_result({'name': 'admin.example.com', 'type': 'xss'}, True)
        learn_from_result({'name': 'www.example.com', 'type': 'info_disclosure'}, False)
    """
    
    prioritizer = LearnedPrioritizer()
    result = prioritizer.learn(finding, was_real)
    
    print(f"Learning recorded: {'SUCCESS' if was_real else 'FP'}")
    print(f"Weights updated: {result['weights_updated']}")
    
    return result


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Neural Reconnaissance Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python NEURAL_RECON_ORCHESTRATOR.py target.com
  python NEURAL_RECON_ORCHESTRATOR.py target.com --scope target.com *.target.com
  python NEURAL_RECON_ORCHESTRATOR.py target.com --max-degree 3 --dry-run
  python NEURAL_RECON_ORCHESTRATOR.py --demo
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--scope", nargs="+", help="Authorized scope (domains)")
    parser.add_argument("--max-degree", type=int, default=2, help="Maximum degrees to explore")
    parser.add_argument("--dry-run", action="store_true", help="Don't run actual tools")
    parser.add_argument("--model", default="llama3.1:8b-instruct-q4_0", help="Ollama model to use")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    
    args = parser.parse_args()
    
    if args.demo or not args.target:
        # Demo mode
        print("Running demonstration...")
        
        orchestrator = NeuralReconOrchestrator(ollama_model=args.model)
        
        # Demo with example.com (dry run)
        results = orchestrator.run_intelligent_recon(
            target="example.com",
            scope=["example.com", "*.example.com"],
            max_degree=1,
            dry_run=True
        )
    else:
        # Real scan
        scope = args.scope or [args.target, f"*.{args.target}"]
        
        orchestrator = NeuralReconOrchestrator(ollama_model=args.model)
        results = orchestrator.run_intelligent_recon(
            target=args.target,
            scope=scope,
            max_degree=args.max_degree,
            dry_run=args.dry_run
        )


if __name__ == "__main__":
    main()
