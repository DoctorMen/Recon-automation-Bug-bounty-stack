#!/usr/bin/env python3
"""
Divergent Thinking Engine for Bug Bounty Automation
Enables creative, multi-path exploration and alternative solution generation

Copyright (c) 2025 Khallid Hakeem Nurse - All Rights Reserved
Proprietary and Confidential
Owner: Khallid Hakeem Nurse
"""
"""
Copyright (c) 2025 - All Rights Reserved
Proprietary and Confidential

DIVERGENT THINKING SYSTEM™
System ID: DIVERGENT_THINKING_20251105

This software and documentation contains proprietary and confidential information.
Unauthorized copying, modification, distribution, public display, or public performance
is strictly prohibited.

PROTECTED INTELLECTUAL PROPERTY:
1. Divergent thinking algorithms and implementations
2. Seven thinking mode methodologies (lateral, parallel, associative, generative, 
   combinatorial, perspective, constraint-free)
3. Creative path generation patterns
4. Attack vector combination algorithms
5. Integration architecture
6. All source code and documentation

TRADE SECRETS:
- Path prioritization algorithms
- Thinking mode selection logic
- Creative pattern databases
- Success prediction models

For licensing inquiries, contact the copyright holder.

LEGAL NOTICE: This system is protected by copyright law and trade secret law.
Violations may result in severe civil and criminal penalties, including but not limited to:
- Copyright infringement damages
- Trade secret misappropriation claims
- Injunctive relief
- Attorney's fees and costs

VALUE: Estimated at $350,000 - $950,000 over 3 years
"""

import asyncio
import json
import random
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set, Tuple
from enum import Enum
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThinkingMode(Enum):
    """Divergent thinking exploration modes"""
    LATERAL = "lateral"              # Sideways thinking, alternative approaches
    PARALLEL = "parallel"            # Multiple simultaneous paths
    ASSOCIATIVE = "associative"      # Connection-based exploration
    GENERATIVE = "generative"        # Create new possibilities
    COMBINATORIAL = "combinatorial"  # Combine existing elements
    PERSPECTIVE = "perspective"      # Different viewpoints
    CONSTRAINT = "constraint"        # Remove assumptions


class ExplorationStrategy(Enum):
    """Strategies for divergent exploration"""
    BREADTH_FIRST = "breadth_first"      # Wide exploration
    DEPTH_FIRST = "depth_first"          # Deep dive on promising paths
    RANDOM_WALK = "random_walk"          # Stochastic exploration
    EVOLUTIONARY = "evolutionary"        # Evolve best solutions
    HYBRID = "hybrid"                    # Adaptive combination


@dataclass
class DivergentPath:
    """Represents one divergent exploration path"""
    path_id: str
    name: str
    description: str
    thinking_mode: ThinkingMode
    hypothesis: str
    attack_vectors: List[str] = field(default_factory=list)
    target_areas: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    estimated_success_probability: float = 0.5
    creativity_score: float = 0.5  # How novel/creative the path is
    feasibility_score: float = 0.5  # How practical/feasible
    priority: int = 3
    parent_path_id: Optional[str] = None
    children_path_ids: List[str] = field(default_factory=list)
    exploration_results: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    explored_at: Optional[float] = None
    
    def get_value_score(self) -> float:
        """Calculate overall value score for prioritization"""
        return (
            self.estimated_success_probability * 0.4 +
            self.creativity_score * 0.3 +
            self.feasibility_score * 0.3
        )


@dataclass
class DivergentThought:
    """A creative thought/idea generated during divergent thinking"""
    thought_id: str
    category: str  # recon, exploitation, bypass, escalation, etc.
    content: str
    inspiration_source: str  # What triggered this thought
    novelty_score: float  # How unique/novel (0-1)
    relevance_score: float  # How relevant to current goal (0-1)
    actionable: bool
    associated_paths: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CreativeSession:
    """A divergent thinking brainstorming session"""
    session_id: str
    target: str
    goal: str
    thinking_modes: List[ThinkingMode]
    generated_paths: List[DivergentPath] = field(default_factory=list)
    generated_thoughts: List[DivergentThought] = field(default_factory=list)
    session_duration: int = 300  # 5 minutes default
    max_paths: int = 20
    started_at: Optional[float] = None
    completed_at: Optional[float] = None


class DivergentThinkingEngine:
    """
    Core engine for divergent thinking in bug bounty automation
    Generates multiple creative paths and alternative approaches
    """
    
    def __init__(self, knowledge_base: Optional[Dict] = None):
        self.knowledge_base = knowledge_base or {}
        self.sessions: Dict[str, CreativeSession] = {}
        self.all_paths: Dict[str, DivergentPath] = {}
        self.all_thoughts: Dict[str, DivergentThought] = {}
        self.exploration_history: List[Dict[str, Any]] = []
        
        # Pre-loaded creative prompts and patterns
        self.creative_patterns = self._initialize_creative_patterns()
        self.attack_vector_library = self._initialize_attack_vectors()
        
    def _initialize_creative_patterns(self) -> Dict[str, List[str]]:
        """Initialize creative thinking patterns"""
        return {
            'lateral': [
                "What if we approached this from the opposite direction?",
                "What would happen if we removed constraint X?",
                "How would a different type of attacker approach this?",
                "What adjacent systems could be leveraged?",
            ],
            'parallel': [
                "What are 5 completely different ways to achieve this?",
                "Can we test multiple hypotheses simultaneously?",
                "What complementary approaches could run in parallel?",
            ],
            'associative': [
                "What similar vulnerabilities exist in other contexts?",
                "What patterns connect these seemingly unrelated findings?",
                "What historical exploits share characteristics with this?",
            ],
            'generative': [
                "What new attack vectors haven't been tried yet?",
                "Can we create a hybrid technique?",
                "What novel combination of tools could reveal something?",
            ],
            'combinatorial': [
                "What happens if we chain these 3 vulnerabilities?",
                "Can we combine recon findings in unexpected ways?",
                "What multi-stage attack could these enable?",
            ],
            'perspective': [
                "How would a mobile attacker see this differently?",
                "What would internal threat actor notice?",
                "How does this look from the API consumer perspective?",
            ],
            'constraint': [
                "What if we had unlimited time/resources?",
                "What if rate limiting didn't exist?",
                "What becomes possible if we ignore conventional wisdom?",
            ]
        }
    
    def _initialize_attack_vectors(self) -> Dict[str, List[str]]:
        """Initialize library of attack vectors by category"""
        return {
            'authentication': [
                'JWT manipulation', 'Session fixation', 'OAuth misconfiguration',
                'SAML injection', '2FA bypass', 'Password reset poisoning'
            ],
            'authorization': [
                'IDOR', 'Privilege escalation', 'BOLA/BFLA',
                'ACL bypass', 'Role confusion', 'Permission boundary testing'
            ],
            'injection': [
                'SQLi', 'NoSQLi', 'Command injection', 'LDAP injection',
                'XML injection', 'Template injection', 'SSTI'
            ],
            'api': [
                'Mass assignment', 'GraphQL introspection', 'Rate limit bypass',
                'Parameter pollution', 'API versioning issues', 'Batch attack'
            ],
            'logic': [
                'Business logic flaw', 'Race condition', 'Time-of-check issues',
                'State manipulation', 'Workflow bypass', 'Input validation bypass'
            ],
            'client_side': [
                'XSS', 'CSRF', 'Clickjacking', 'DOM-based attacks',
                'Prototype pollution', 'PostMessage vulnerabilities'
            ],
            'infrastructure': [
                'Subdomain takeover', 'SSRF', 'Cache poisoning',
                'DNS rebinding', 'HTTP request smuggling', 'Deserialization'
            ],
            'data_exposure': [
                'Information disclosure', 'Debug endpoints', 'Source code leak',
                'Backup file exposure', 'GraphQL over-fetching', 'Sensitive data in responses'
            ]
        }
    
    async def start_divergent_session(
        self,
        target: str,
        goal: str,
        thinking_modes: Optional[List[ThinkingMode]] = None,
        max_paths: int = 20,
        duration: int = 300
    ) -> CreativeSession:
        """
        Start a divergent thinking session
        Generates multiple creative paths to explore
        """
        session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        
        if not thinking_modes:
            thinking_modes = list(ThinkingMode)  # Use all modes
        
        session = CreativeSession(
            session_id=session_id,
            target=target,
            goal=goal,
            thinking_modes=thinking_modes,
            max_paths=max_paths,
            session_duration=duration,
            started_at=time.time()
        )
        
        self.sessions[session_id] = session
        
        logger.info(f"Starting divergent thinking session: {session_id}")
        logger.info(f"Target: {target} | Goal: {goal}")
        logger.info(f"Modes: {[m.value for m in thinking_modes]}")
        
        # Generate paths using each thinking mode
        for mode in thinking_modes:
            paths = await self._generate_paths_for_mode(target, goal, mode, max_paths // len(thinking_modes))
            session.generated_paths.extend(paths)
        
        # Generate creative thoughts
        thoughts = await self._generate_creative_thoughts(target, goal, session.generated_paths)
        session.generated_thoughts.extend(thoughts)
        
        # Store paths
        for path in session.generated_paths:
            self.all_paths[path.path_id] = path
        
        # Store thoughts
        for thought in session.generated_thoughts:
            self.all_thoughts[thought.thought_id] = thought
        
        session.completed_at = time.time()
        
        logger.info(f"Session complete: Generated {len(session.generated_paths)} paths, {len(session.generated_thoughts)} thoughts")
        
        return session
    
    async def _generate_paths_for_mode(
        self,
        target: str,
        goal: str,
        mode: ThinkingMode,
        count: int
    ) -> List[DivergentPath]:
        """Generate divergent paths for a specific thinking mode"""
        paths = []
        
        if mode == ThinkingMode.LATERAL:
            paths = self._generate_lateral_paths(target, goal, count)
        elif mode == ThinkingMode.PARALLEL:
            paths = self._generate_parallel_paths(target, goal, count)
        elif mode == ThinkingMode.ASSOCIATIVE:
            paths = self._generate_associative_paths(target, goal, count)
        elif mode == ThinkingMode.GENERATIVE:
            paths = self._generate_generative_paths(target, goal, count)
        elif mode == ThinkingMode.COMBINATORIAL:
            paths = self._generate_combinatorial_paths(target, goal, count)
        elif mode == ThinkingMode.PERSPECTIVE:
            paths = self._generate_perspective_paths(target, goal, count)
        elif mode == ThinkingMode.CONSTRAINT:
            paths = self._generate_constraint_free_paths(target, goal, count)
        
        return paths
    
    def _generate_lateral_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate paths using lateral thinking"""
        paths = []
        
        lateral_approaches = [
            {
                'name': 'Reverse Engineering Approach',
                'hypothesis': 'Start from desired outcome and work backwards',
                'vectors': ['Identify final goal state', 'Map prerequisites', 'Find weakest link in chain'],
                'areas': ['authentication_flow', 'data_access_layer', 'business_logic']
            },
            {
                'name': 'Adjacent System Attack',
                'hypothesis': 'Compromise related systems to access target',
                'vectors': ['Third-party integrations', 'Partner APIs', 'Shared infrastructure'],
                'areas': ['oauth_providers', 'cdn', 'monitoring_systems']
            },
            {
                'name': 'Semantic Confusion',
                'hypothesis': 'Exploit differences in how systems interpret same data',
                'vectors': ['Encoding confusion', 'Parser differentials', 'Unicode tricks'],
                'areas': ['input_validation', 'character_encoding', 'locale_handling']
            },
            {
                'name': 'Time-Based Exploitation',
                'hypothesis': 'Leverage timing and sequence dependencies',
                'vectors': ['Race conditions', 'TTL manipulation', 'Scheduling attacks'],
                'areas': ['concurrent_operations', 'cache_timing', 'session_management']
            }
        ]
        
        for i, approach in enumerate(lateral_approaches[:count]):
            path_id = f"lateral_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=approach['name'],
                description=f"Lateral thinking: {approach['name']}",
                thinking_mode=ThinkingMode.LATERAL,
                hypothesis=approach['hypothesis'],
                attack_vectors=approach['vectors'],
                target_areas=approach['areas'],
                tools_required=['custom_scripts', 'burp_suite', 'manual_analysis'],
                estimated_success_probability=0.4,
                creativity_score=0.8,
                feasibility_score=0.6
            ))
        
        return paths
    
    def _generate_parallel_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate parallel exploration paths"""
        paths = []
        
        # Create paths that can be explored simultaneously
        parallel_strategies = [
            ('Wide Recon', 'Cast wide net across all subdomains', ['subfinder', 'amass', 'chaos']),
            ('Deep API Testing', 'Exhaustive API endpoint enumeration', ['ffuf', 'kiterunner', 'arjun']),
            ('Auth Mechanisms', 'Parallel testing of all auth methods', ['authz', 'jwt_tool', 'saml_raider']),
            ('JS Analysis', 'Concurrent JavaScript endpoint discovery', ['linkfinder', 'getjs', 'secertfinder']),
            ('Mobile Testing', 'Simultaneous mobile app analysis', ['mobsf', 'frida', 'objection']),
        ]
        
        for i, (name, hypothesis, tools) in enumerate(parallel_strategies[:count]):
            path_id = f"parallel_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=name,
                description=f"Parallel path: {name}",
                thinking_mode=ThinkingMode.PARALLEL,
                hypothesis=hypothesis,
                attack_vectors=[f"{name}_vector"],
                target_areas=[name.lower().replace(' ', '_')],
                tools_required=tools,
                estimated_success_probability=0.6,
                creativity_score=0.5,
                feasibility_score=0.8
            ))
        
        return paths
    
    def _generate_associative_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate paths based on pattern association"""
        paths = []
        
        # Associate current target with known patterns
        associations = [
            ('Similar CVE Pattern', 'Find CVEs with similar technology stack', 0.7),
            ('Industry-Specific Vulns', 'Common vulnerabilities in this industry', 0.6),
            ('Technology Fingerprint', 'Vulnerabilities specific to detected technologies', 0.8),
            ('Historical Patterns', 'Past bugs found in similar applications', 0.5),
        ]
        
        for i, (name, hypothesis, success_prob) in enumerate(associations[:count]):
            path_id = f"associative_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=name,
                description=f"Associative pattern: {name}",
                thinking_mode=ThinkingMode.ASSOCIATIVE,
                hypothesis=hypothesis,
                attack_vectors=['pattern_matching', 'historical_analysis'],
                target_areas=['cve_database', 'bug_bounty_history'],
                tools_required=['cve_search', 'nuclei_templates'],
                estimated_success_probability=success_prob,
                creativity_score=0.6,
                feasibility_score=0.7
            ))
        
        return paths
    
    def _generate_generative_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate completely novel exploration paths"""
        paths = []
        
        # Generate creative new approaches
        novel_ideas = [
            ('Chain Vulnerability Combos', 'Create new attack chains from low-severity bugs', ['logic_flow_analysis']),
            ('Inverse Security Controls', 'Security features as attack vectors', ['waf_analysis', 'security_header_testing']),
            ('Data Flow Poisoning', 'Corrupt data at source to affect downstream', ['data_injection', 'cache_poisoning']),
            ('Mutation Testing Attack', 'Mutate requests systematically to find edge cases', ['fuzzing', 'custom_mutations']),
        ]
        
        for i, (name, hypothesis, vectors) in enumerate(novel_ideas[:count]):
            path_id = f"generative_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=name,
                description=f"Novel approach: {name}",
                thinking_mode=ThinkingMode.GENERATIVE,
                hypothesis=hypothesis,
                attack_vectors=vectors,
                target_areas=['novel_exploration'],
                tools_required=['custom_tooling'],
                estimated_success_probability=0.3,
                creativity_score=0.9,
                feasibility_score=0.4
            ))
        
        return paths
    
    def _generate_combinatorial_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate paths by combining existing elements"""
        paths = []
        
        # Combine different attack categories
        categories = list(self.attack_vector_library.keys())
        
        for i in range(min(count, len(categories) - 1)):
            cat1 = categories[i]
            cat2 = categories[(i + 1) % len(categories)]
            
            vectors1 = self.attack_vector_library[cat1][:2]
            vectors2 = self.attack_vector_library[cat2][:2]
            
            path_id = f"combinatorial_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=f"Combined {cat1.title()} + {cat2.title()}",
                description=f"Hybrid attack combining {cat1} and {cat2}",
                thinking_mode=ThinkingMode.COMBINATORIAL,
                hypothesis=f"Combine {cat1} techniques with {cat2} to create novel attack",
                attack_vectors=vectors1 + vectors2,
                target_areas=[cat1, cat2],
                tools_required=['burp_suite', 'custom_scripts'],
                estimated_success_probability=0.5,
                creativity_score=0.7,
                feasibility_score=0.6
            ))
        
        return paths
    
    def _generate_perspective_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate paths from different attacker perspectives"""
        paths = []
        
        perspectives = [
            ('Insider Threat', 'Low-privilege internal user perspective', 0.6, ['internal_api', 'employee_endpoints']),
            ('Mobile User', 'Mobile app user attack surface', 0.7, ['mobile_api', 'deep_linking']),
            ('API Consumer', 'Third-party API integration viewpoint', 0.65, ['api_endpoints', 'webhooks']),
            ('Administrator', 'Admin panel and privileged function testing', 0.55, ['admin_panel', 'privileged_operations']),
        ]
        
        for i, (name, hypothesis, prob, areas) in enumerate(perspectives[:count]):
            path_id = f"perspective_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=f"{name} Perspective",
                description=f"Attack from {name} viewpoint",
                thinking_mode=ThinkingMode.PERSPECTIVE,
                hypothesis=hypothesis,
                attack_vectors=[f"{name.lower()}_attacks"],
                target_areas=areas,
                tools_required=['perspective_specific_tools'],
                estimated_success_probability=prob,
                creativity_score=0.6,
                feasibility_score=0.7
            ))
        
        return paths
    
    def _generate_constraint_free_paths(self, target: str, goal: str, count: int) -> List[DivergentPath]:
        """Generate paths removing conventional constraints"""
        paths = []
        
        unconstrained = [
            ('Ignore Rate Limits', 'What if we had unlimited requests?', ['distributed_attack', 'ip_rotation']),
            ('Zero-Day Hunting', 'Focus only on unknown vulnerabilities', ['custom_fuzzing', '0day_research']),
            ('Full Access Assumption', 'Start as if we already have access', ['privilege_escalation', 'lateral_movement']),
            ('Time-Unlimited Deep Dive', 'Thorough analysis without time pressure', ['comprehensive_audit', 'source_code_review']),
        ]
        
        for i, (name, hypothesis, vectors) in enumerate(unconstrained[:count]):
            path_id = f"constraint_{int(time.time())}_{i}"
            paths.append(DivergentPath(
                path_id=path_id,
                name=name,
                description=f"Constraint-free: {name}",
                thinking_mode=ThinkingMode.CONSTRAINT,
                hypothesis=hypothesis,
                attack_vectors=vectors,
                target_areas=['unconstrained_exploration'],
                tools_required=['advanced_tooling'],
                estimated_success_probability=0.4,
                creativity_score=0.8,
                feasibility_score=0.3
            ))
        
        return paths
    
    async def _generate_creative_thoughts(
        self,
        target: str,
        goal: str,
        paths: List[DivergentPath]
    ) -> List[DivergentThought]:
        """Generate creative thoughts/ideas during divergent thinking"""
        thoughts = []
        
        # Generate thoughts inspired by paths
        for path in paths[:10]:  # Limit to first 10 paths
            thought_id = f"thought_{int(time.time())}_{random.randint(1000, 9999)}"
            
            thoughts.append(DivergentThought(
                thought_id=thought_id,
                category=path.thinking_mode.value,
                content=f"Creative insight: {path.hypothesis} might reveal {random.choice(['hidden', 'critical', 'novel'])} vulnerability",
                inspiration_source=path.name,
                novelty_score=path.creativity_score,
                relevance_score=path.estimated_success_probability,
                actionable=path.feasibility_score > 0.5,
                associated_paths=[path.path_id]
            ))
        
        return thoughts
    
    def prioritize_paths(
        self,
        paths: List[DivergentPath],
        strategy: ExplorationStrategy = ExplorationStrategy.HYBRID
    ) -> List[DivergentPath]:
        """Prioritize divergent paths based on strategy"""
        
        if strategy == ExplorationStrategy.BREADTH_FIRST:
            # Prioritize high feasibility first
            return sorted(paths, key=lambda p: p.feasibility_score, reverse=True)
        
        elif strategy == ExplorationStrategy.DEPTH_FIRST:
            # Prioritize high creativity for deep exploration
            return sorted(paths, key=lambda p: p.creativity_score, reverse=True)
        
        elif strategy == ExplorationStrategy.RANDOM_WALK:
            # Random shuffle
            shuffled = paths.copy()
            random.shuffle(shuffled)
            return shuffled
        
        elif strategy == ExplorationStrategy.EVOLUTIONARY:
            # Prioritize high success probability
            return sorted(paths, key=lambda p: p.estimated_success_probability, reverse=True)
        
        else:  # HYBRID
            # Balanced score
            return sorted(paths, key=lambda p: p.get_value_score(), reverse=True)
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get summary of a divergent thinking session"""
        if session_id not in self.sessions:
            return {'error': 'Session not found'}
        
        session = self.sessions[session_id]
        
        paths_by_mode = {}
        for mode in ThinkingMode:
            mode_paths = [p for p in session.generated_paths if p.thinking_mode == mode]
            paths_by_mode[mode.value] = len(mode_paths)
        
        top_paths = self.prioritize_paths(session.generated_paths, ExplorationStrategy.HYBRID)[:5]
        
        return {
            'session_id': session_id,
            'target': session.target,
            'goal': session.goal,
            'total_paths': len(session.generated_paths),
            'total_thoughts': len(session.generated_thoughts),
            'paths_by_mode': paths_by_mode,
            'top_5_paths': [
                {
                    'name': p.name,
                    'mode': p.thinking_mode.value,
                    'hypothesis': p.hypothesis,
                    'value_score': p.get_value_score(),
                    'creativity': p.creativity_score,
                    'feasibility': p.feasibility_score,
                    'success_probability': p.estimated_success_probability
                }
                for p in top_paths
            ],
            'duration': session.completed_at - session.started_at if session.completed_at else None
        }
    
    def export_session(self, session_id: str, filepath: str):
        """Export session to JSON file"""
        if session_id not in self.sessions:
            logger.error(f"Session {session_id} not found")
            return
        
        session = self.sessions[session_id]
        
        export_data = {
            'session': {
                'session_id': session.session_id,
                'target': session.target,
                'goal': session.goal,
                'started_at': session.started_at,
                'completed_at': session.completed_at
            },
            'paths': [asdict(p) for p in session.generated_paths],
            'thoughts': [asdict(t) for t in session.generated_thoughts]
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Exported session to {filepath}")


async def demo_divergent_thinking():
    """Demo the divergent thinking engine"""
    
    engine = DivergentThinkingEngine()
    
    # Start a divergent thinking session
    session = await engine.start_divergent_session(
        target="example.com",
        goal="Find critical vulnerabilities",
        thinking_modes=[
            ThinkingMode.LATERAL,
            ThinkingMode.PARALLEL,
            ThinkingMode.COMBINATORIAL,
            ThinkingMode.PERSPECTIVE
        ],
        max_paths=16,
        duration=300
    )
    
    # Get summary
    summary = engine.get_session_summary(session.session_id)
    
    print("\n" + "="*80)
    print("DIVERGENT THINKING SESSION RESULTS")
    print("="*80)
    print(f"\nTarget: {summary['target']}")
    print(f"Goal: {summary['goal']}")
    print(f"\nGenerated {summary['total_paths']} exploration paths")
    print(f"Generated {summary['total_thoughts']} creative thoughts")
    
    print("\nPaths by Thinking Mode:")
    for mode, count in summary['paths_by_mode'].items():
        print(f"  {mode.capitalize()}: {count} paths")
    
    print("\n" + "-"*80)
    print("TOP 5 PATHS TO EXPLORE:")
    print("-"*80)
    
    for i, path in enumerate(summary['top_5_paths'], 1):
        print(f"\n{i}. {path['name']} [{path['mode'].upper()}]")
        print(f"   Hypothesis: {path['hypothesis']}")
        print(f"   Value Score: {path['value_score']:.2f}")
        print(f"   Creativity: {path['creativity']:.1f} | Feasibility: {path['feasibility']:.1f} | Success: {path['success_probability']:.1f}")
    
    print("\n" + "="*80)
    
    # Export
    engine.export_session(session.session_id, "divergent_session_export.json")


if __name__ == "__main__":
    asyncio.run(demo_divergent_thinking())
