#!/usr/bin/env python3
"""
AGENTIC REASONING LAYER FOR SIX DEGREES RECON
==============================================
This adds TRUE AI reasoning to the reconnaissance system.
Instead of rigid scripts, the AI makes contextual decisions
about what to explore next based on findings.

Key Differentiators:
1. Contextual reasoning about next steps
2. Pattern recognition from past successes
3. Adaptive strategy based on findings
4. Risk/reward prioritization

Copyright (c) 2025 DoctorMen
"""

import json
import os
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class ReconContext:
    """Current state and context for reasoning"""
    target: str
    findings_so_far: List[Dict]
    nodes_explored: int
    current_degree: int
    time_elapsed: float
    technologies_found: List[str]
    vulnerabilities_found: List[Dict]
    promising_patterns: List[str]
    dead_ends: List[str]
    scope: List[str]
    budget_remaining: float  # Time/resource budget


@dataclass 
class ExplorationDecision:
    """AI's decision about what to explore next"""
    action: str  # explore_deeper, pivot, skip, investigate_pattern
    target: str
    reasoning: str
    priority: float  # 0-1 score
    expected_value: str  # What we expect to find
    risk: str  # Potential issues
    alternatives: List[Dict] = field(default_factory=list)


class PatternDatabase:
    """
    Stores patterns learned from successful bug hunting.
    This is what makes the system ADAPTIVE.
    """
    
    def __init__(self, db_path: str = "pattern_knowledge.json"):
        self.db_path = db_path
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict:
        """Load learned patterns from disk"""
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r') as f:
                return json.load(f)
        
        # Default patterns from bug bounty experience
        return {
            "staging_debug": {
                "trigger": ["staging", "dev", "test", "debug"],
                "action": "deep_dive",
                "reasoning": "Staging/dev environments often have debug mode, verbose errors, and relaxed security",
                "success_rate": 0.75,
                "typical_findings": ["information_disclosure", "debug_endpoints", "weak_auth"]
            },
            "recent_acquisition": {
                "trigger": ["acquired", "merger", "new_subsidiary"],
                "action": "cross_check_patterns",
                "reasoning": "Recently acquired companies often have inconsistent security practices",
                "success_rate": 0.65,
                "typical_findings": ["config_differences", "outdated_systems", "integration_bugs"]
            },
            "api_versioning": {
                "trigger": ["api/v1", "api/v2", "/v1/", "/v2/"],
                "action": "check_old_versions",
                "reasoning": "Old API versions often lack security fixes from newer versions",
                "success_rate": 0.70,
                "typical_findings": ["deprecated_endpoints", "missing_auth", "information_disclosure"]
            },
            "subdomain_patterns": {
                "trigger": ["admin", "internal", "corp", "vpn", "jenkins", "gitlab"],
                "action": "priority_scan",
                "reasoning": "Administrative and internal subdomains often have higher value targets",
                "success_rate": 0.80,
                "typical_findings": ["admin_panels", "exposed_credentials", "internal_tools"]
            },
            "technology_vulns": {
                "wordpress": ["plugin_vulns", "xmlrpc", "user_enum"],
                "jenkins": ["no_auth", "script_console", "exposed_builds"],
                "gitlab": ["public_projects", "user_enum", "ci_variables"],
                "apache_struts": ["rce", "ognl_injection"],
                "spring": ["actuator_exposure", "spel_injection"],
                "laravel": ["debug_mode", "env_exposure"]
            },
            "error_patterns": {
                "trigger": ["stack trace", "debug", "error", "exception"],
                "action": "extract_information",
                "reasoning": "Verbose errors leak internal paths, versions, and architecture",
                "success_rate": 0.60,
                "typical_findings": ["information_disclosure", "path_traversal", "version_disclosure"]
            }
        }
    
    def find_matching_patterns(self, context: ReconContext) -> List[Dict]:
        """Find patterns that match current context"""
        matches = []
        
        # Check for trigger words in findings
        all_text = ' '.join([
            str(f) for f in context.findings_so_far
        ]).lower()
        
        for pattern_name, pattern_data in self.patterns.items():
            if pattern_name == "technology_vulns":
                # Special handling for tech-specific patterns
                for tech in context.technologies_found:
                    tech_lower = tech.lower()
                    if tech_lower in pattern_data:
                        matches.append({
                            "pattern": f"technology_{tech_lower}",
                            "action": "exploit_known_vulns",
                            "reasoning": f"{tech} has known vulnerabilities",
                            "typical_findings": pattern_data[tech_lower],
                            "priority": 0.9
                        })
            elif "trigger" in pattern_data:
                # Check for trigger words
                if any(trigger in all_text for trigger in pattern_data["trigger"]):
                    matches.append({
                        "pattern": pattern_name,
                        **pattern_data,
                        "priority": pattern_data.get("success_rate", 0.5)
                    })
        
        return sorted(matches, key=lambda x: x.get("priority", 0), reverse=True)
    
    def record_outcome(self, pattern: str, success: bool, findings: List[Dict]):
        """Update pattern success rates based on outcomes"""
        if pattern in self.patterns:
            old_rate = self.patterns[pattern].get("success_rate", 0.5)
            # Simple exponential moving average
            new_rate = 0.9 * old_rate + 0.1 * (1.0 if success else 0.0)
            self.patterns[pattern]["success_rate"] = new_rate
            
            # Save updated patterns
            with open(self.db_path, 'w') as f:
                json.dump(self.patterns, f, indent=2)


class AgenticReasoner:
    """
    The AI brain that makes intelligent decisions about reconnaissance.
    This is what makes it DIFFERENT from existing tools.
    """
    
    def __init__(self):
        self.pattern_db = PatternDatabase()
        self.decision_history = []
    
    def decide_next_action(self, context: ReconContext) -> ExplorationDecision:
        """
        Make an intelligent decision about what to explore next.
        This is the KEY DIFFERENTIATOR - actual reasoning, not scripts.
        """
        
        # 1. Check for matching patterns from past success
        patterns = self.pattern_db.find_matching_patterns(context)
        
        # 2. Analyze current situation
        situation_analysis = self._analyze_situation(context)
        
        # 3. Generate options
        options = self._generate_options(context, patterns, situation_analysis)
        
        # 4. Score and rank options
        best_option = self._select_best_option(options, context)
        
        # 5. Create decision with reasoning
        decision = ExplorationDecision(
            action=best_option["action"],
            target=best_option["target"],
            reasoning=best_option["reasoning"],
            priority=best_option["score"],
            expected_value=best_option.get("expected_value", "Unknown"),
            risk=best_option.get("risk", "Low"),
            alternatives=options[:3]  # Top 3 alternatives
        )
        
        self.decision_history.append({
            "timestamp": datetime.now().isoformat(),
            "context_summary": self._summarize_context(context),
            "decision": decision.action,
            "reasoning": decision.reasoning
        })
        
        return decision
    
    def _analyze_situation(self, context: ReconContext) -> Dict:
        """Analyze current reconnaissance situation"""
        
        analysis = {
            "exploration_depth": context.current_degree,
            "coverage": context.nodes_explored,
            "finding_rate": len(context.vulnerabilities_found) / max(context.nodes_explored, 1),
            "high_value_indicators": [],
            "risk_factors": [],
            "opportunities": []
        }
        
        # Look for high-value indicators
        vuln_severities = [v.get("severity", "low") for v in context.vulnerabilities_found]
        if "critical" in vuln_severities or "high" in vuln_severities:
            analysis["high_value_indicators"].append("High severity vulnerabilities found")
        
        # Check for interesting technologies
        interesting_tech = ["jenkins", "gitlab", "wordpress", "struts", "spring", "laravel"]
        for tech in context.technologies_found:
            if any(t in tech.lower() for t in interesting_tech):
                analysis["opportunities"].append(f"Interesting technology: {tech}")
        
        # Check resource budget
        if context.budget_remaining < 0.2:
            analysis["risk_factors"].append("Low time/resource budget")
        
        # Finding patterns
        if context.vulnerabilities_found:
            vuln_types = [v.get("type") for v in context.vulnerabilities_found]
            if len(set(vuln_types)) < len(vuln_types):
                analysis["opportunities"].append("Repeated vulnerability patterns detected")
        
        return analysis
    
    def _generate_options(self, context: ReconContext, patterns: List[Dict], 
                         situation: Dict) -> List[Dict]:
        """Generate possible next actions with scoring"""
        
        options = []
        
        # Option 1: Follow detected patterns
        for pattern in patterns[:3]:  # Top 3 patterns
            options.append({
                "action": pattern.get("action", "investigate"),
                "target": context.target,
                "reasoning": f"Pattern detected: {pattern.get('reasoning', 'Unknown')}",
                "expected_value": ', '.join(pattern.get("typical_findings", [])),
                "risk": "Low",
                "score": pattern.get("priority", 0.5) * 1.2  # Boost pattern-based decisions
            })
        
        # Option 2: Explore deeper in current degree
        if context.current_degree < 3:
            options.append({
                "action": "explore_deeper",
                "target": f"degree_{context.current_degree + 1}",
                "reasoning": "Unexplored nodes remain at next degree",
                "expected_value": "New attack surface",
                "risk": "Medium - might be out of scope",
                "score": 0.5 * (1.0 - context.current_degree * 0.2)  # Decrease with depth
            })
        
        # Option 3: Pivot to promising finding
        if situation.get("opportunities"):
            options.append({
                "action": "pivot",
                "target": situation["opportunities"][0],
                "reasoning": f"Opportunity identified: {situation['opportunities'][0]}",
                "expected_value": "Higher probability of findings",
                "risk": "Low",
                "score": 0.8
            })
        
        # Option 4: Focus on vulnerabilities found
        if context.vulnerabilities_found:
            options.append({
                "action": "exploit_chain",
                "target": context.vulnerabilities_found[0].get("target"),
                "reasoning": "Build on existing vulnerabilities for impact",
                "expected_value": "Higher severity through chaining",
                "risk": "Low",
                "score": 0.9 if "critical" in str(context.vulnerabilities_found) else 0.7
            })
        
        # Option 5: Wide scan if nothing specific found
        if not patterns and not context.vulnerabilities_found:
            options.append({
                "action": "wide_scan",
                "target": "all_subdomains",
                "reasoning": "No specific patterns found, cast wider net",
                "expected_value": "Discover new attack surface",
                "risk": "High resource usage",
                "score": 0.4
            })
        
        return sorted(options, key=lambda x: x["score"], reverse=True)
    
    def _select_best_option(self, options: List[Dict], context: ReconContext) -> Dict:
        """Select the best option considering context"""
        
        if not options:
            # Fallback option
            return {
                "action": "continue_standard",
                "target": context.target,
                "reasoning": "No specific opportunities identified, continue standard recon",
                "expected_value": "Standard findings",
                "risk": "Low",
                "score": 0.5
            }
        
        # Adjust scores based on context
        for option in options:
            # Penalize if low on budget
            if context.budget_remaining < 0.3 and option.get("risk") == "High resource usage":
                option["score"] *= 0.5
            
            # Boost if we haven't found much yet
            if not context.vulnerabilities_found and option["action"] in ["wide_scan", "explore_deeper"]:
                option["score"] *= 1.3
            
            # Boost exploit chains if we have findings
            if context.vulnerabilities_found and option["action"] == "exploit_chain":
                option["score"] *= 1.4
        
        return max(options, key=lambda x: x["score"])
    
    def _summarize_context(self, context: ReconContext) -> str:
        """Create a summary of current context"""
        return (f"Target: {context.target}, "
                f"Degree: {context.current_degree}, "
                f"Nodes: {context.nodes_explored}, "
                f"Vulns: {len(context.vulnerabilities_found)}, "
                f"Tech: {', '.join(context.technologies_found[:3])}")
    
    def learn_from_outcome(self, decision: ExplorationDecision, 
                          outcome: Dict) -> None:
        """
        Learn from the outcome of a decision.
        This is what makes the system ADAPTIVE.
        """
        
        success = len(outcome.get("vulnerabilities_found", [])) > 0
        
        # Extract pattern if there was one
        if "pattern" in decision.reasoning.lower():
            # Simple pattern extraction (could be enhanced)
            pattern_name = decision.reasoning.split("Pattern detected:")[0].strip()
            if pattern_name:
                self.pattern_db.record_outcome(
                    pattern_name, 
                    success,
                    outcome.get("vulnerabilities_found", [])
                )
        
        # Record decision outcome
        self.decision_history[-1]["outcome"] = {
            "success": success,
            "findings": len(outcome.get("vulnerabilities_found", [])),
            "new_nodes": outcome.get("new_nodes", 0)
        }
    
    def generate_strategy_report(self) -> Dict:
        """Generate a report on reasoning strategy"""
        
        successful_decisions = [
            d for d in self.decision_history 
            if d.get("outcome", {}).get("success", False)
        ]
        
        return {
            "total_decisions": len(self.decision_history),
            "successful_decisions": len(successful_decisions),
            "success_rate": len(successful_decisions) / max(len(self.decision_history), 1),
            "most_successful_patterns": self._get_top_patterns(),
            "decision_history": self.decision_history[-10:]  # Last 10 decisions
        }
    
    def _get_top_patterns(self) -> List[Dict]:
        """Get most successful patterns"""
        patterns = []
        for name, data in self.pattern_db.patterns.items():
            if isinstance(data, dict) and "success_rate" in data:
                patterns.append({
                    "pattern": name,
                    "success_rate": data["success_rate"],
                    "typical_findings": data.get("typical_findings", [])
                })
        
        return sorted(patterns, key=lambda x: x["success_rate"], reverse=True)[:5]


class IntelligentReconOrchestrator:
    """
    Orchestrates reconnaissance with AI-driven decisions.
    This combines the Six Degrees system with intelligent reasoning.
    """
    
    def __init__(self, seed_target: str, scope: List[str]):
        self.seed_target = seed_target
        self.scope = scope
        self.reasoner = AgenticReasoner()
        self.start_time = datetime.now()
        self.findings = []
        
        # Import the base Six Degrees system
        from SIX_DEGREES_RECON_SYSTEM import SixDegreesReconSystem
        self.recon_system = SixDegreesReconSystem(
            seed_target=seed_target,
            scope=scope,
            max_degree=6  # We'll control this intelligently
        )
    
    def run_intelligent_recon(self, time_budget_minutes: float = 30) -> Dict:
        """
        Run reconnaissance with intelligent decision-making.
        This is where the magic happens - AI reasoning about next steps.
        """
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║             INTELLIGENT AGENTIC RECONNAISSANCE SYSTEM                ║
║          AI-Driven Decisions | Adaptive Learning | Smart Pivots      ║
╚══════════════════════════════════════════════════════════════════════╝

🧠 AI Reasoner: Active
🎯 Target: {self.seed_target}
⏱️  Time Budget: {time_budget_minutes} minutes
📊 Learning Mode: Enabled
        """)
        
        while self._should_continue(time_budget_minutes):
            # 1. Build current context
            context = self._build_context()
            
            print(f"\n{'='*60}")
            print(f"🤖 AI REASONING - Cycle {len(self.reasoner.decision_history) + 1}")
            print(f"{'='*60}")
            
            # 2. Get AI decision
            decision = self.reasoner.decide_next_action(context)
            
            print(f"""
📍 Current State:
   Nodes Explored: {context.nodes_explored}
   Current Degree: {context.current_degree}
   Vulnerabilities Found: {len(context.vulnerabilities_found)}
   Technologies: {', '.join(context.technologies_found[:5])}

🧠 AI Decision:
   Action: {decision.action}
   Target: {decision.target}
   Priority: {decision.priority:.2f}
   Reasoning: {decision.reasoning}
   Expected: {decision.expected_value}
   Risk: {decision.risk}
""")
            
            # Show alternatives
            if decision.alternatives:
                print("📊 Other Options Considered:")
                for alt in decision.alternatives[:2]:
                    print(f"   - {alt['action']}: {alt['reasoning']} (score: {alt.get('score', 0):.2f})")
            
            # 3. Execute decision
            outcome = self._execute_decision(decision)
            
            # 4. Learn from outcome
            self.reasoner.learn_from_outcome(decision, outcome)
            
            print(f"""
📈 Outcome:
   New Nodes: {outcome.get('new_nodes', 0)}
   New Vulnerabilities: {len(outcome.get('vulnerabilities_found', []))}
   Success: {'✅ Yes' if outcome.get('vulnerabilities_found') else '❌ No'}
""")
        
        # Generate final report
        return self._generate_final_report()
    
    def _should_continue(self, time_budget_minutes: float) -> bool:
        """Check if we should continue reconnaissance"""
        elapsed = (datetime.now() - self.start_time).total_seconds() / 60
        
        if elapsed >= time_budget_minutes:
            print(f"\n⏱️  Time budget exhausted ({time_budget_minutes} minutes)")
            return False
        
        unexplored = self.recon_system.graph.get_unexplored_nodes()
        if not unexplored:
            print(f"\n✅ All nodes explored")
            return False
        
        # Check if we're making progress
        if len(self.reasoner.decision_history) > 10:
            recent_success = sum(
                1 for d in self.reasoner.decision_history[-5:]
                if d.get("outcome", {}).get("success", False)
            )
            if recent_success == 0:
                print(f"\n⚠️  No recent progress, stopping")
                return False
        
        return True
    
    def _build_context(self) -> ReconContext:
        """Build current context for reasoning"""
        elapsed = (datetime.now() - self.start_time).total_seconds() / 60
        
        # Get all findings from graph nodes
        all_findings = []
        all_techs = []
        
        for node in self.recon_system.graph.nodes.values():
            all_findings.extend(node.findings)
            if node.type.value == "technology":
                all_techs.append(node.value)
        
        return ReconContext(
            target=self.seed_target,
            findings_so_far=all_findings[:50],  # Last 50 findings
            nodes_explored=len([n for n in self.recon_system.graph.nodes.values() if n.explored]),
            current_degree=max([n.degree for n in self.recon_system.graph.nodes.values()], default=0),
            time_elapsed=elapsed,
            technologies_found=list(set(all_techs)),
            vulnerabilities_found=[f for f in all_findings if "severity" in f],
            promising_patterns=self._identify_patterns(all_findings),
            dead_ends=[],
            scope=self.scope,
            budget_remaining=1.0 - (elapsed / 30.0)  # Assuming 30 min budget
        )
    
    def _identify_patterns(self, findings: List[Dict]) -> List[str]:
        """Identify patterns in findings"""
        patterns = []
        
        # Look for repeated vulnerability types
        vuln_types = [f.get("type") for f in findings if f.get("type")]
        if vuln_types:
            from collections import Counter
            common = Counter(vuln_types).most_common(3)
            for vuln_type, count in common:
                if count > 2:
                    patterns.append(f"Repeated {vuln_type} ({count} instances)")
        
        return patterns
    
    def _execute_decision(self, decision: ExplorationDecision) -> Dict:
        """Execute the AI's decision"""
        outcome = {
            "action": decision.action,
            "target": decision.target,
            "vulnerabilities_found": [],
            "new_nodes": 0
        }
        
        # Map decision to actual reconnaissance action
        if decision.action == "explore_deeper":
            # Explore next degree
            unexplored = self.recon_system.graph.get_unexplored_nodes()
            for node in unexplored[:5]:  # Limit to 5 nodes
                self.recon_system._explore_node(node)
                outcome["new_nodes"] += len(self.recon_system.graph.get_neighbors(node.id))
        
        elif decision.action in ["investigate", "priority_scan", "pivot"]:
            # Focus on specific pattern or target
            unexplored = [
                n for n in self.recon_system.graph.get_unexplored_nodes()
                if decision.target.lower() in n.value.lower()
            ]
            for node in unexplored[:3]:
                self.recon_system._explore_node(node)
                outcome["vulnerabilities_found"].extend(node.findings)
        
        elif decision.action == "wide_scan":
            # Broad scan of unexplored nodes
            unexplored = self.recon_system.graph.get_unexplored_nodes()
            for node in unexplored[:10]:
                self.recon_system._explore_node(node)
                outcome["new_nodes"] += 1
        
        # Collect any new vulnerabilities
        for node in self.recon_system.graph.nodes.values():
            for finding in node.findings:
                if finding not in self.findings:
                    self.findings.append(finding)
                    outcome["vulnerabilities_found"].append(finding)
        
        return outcome
    
    def _generate_final_report(self) -> Dict:
        """Generate comprehensive final report"""
        strategy_report = self.reasoner.generate_strategy_report()
        graph_stats = self.recon_system.graph.get_statistics()
        
        report = {
            "seed_target": self.seed_target,
            "timestamp": datetime.now().isoformat(),
            "duration_minutes": (datetime.now() - self.start_time).total_seconds() / 60,
            "ai_strategy": strategy_report,
            "graph_statistics": graph_stats,
            "total_findings": len(self.findings),
            "findings_by_severity": self._group_findings_by_severity(),
            "successful_patterns": self.reasoner._get_top_patterns(),
            "all_findings": self.findings
        }
        
        # Print summary
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    INTELLIGENT RECON COMPLETE                        ║
╚══════════════════════════════════════════════════════════════════════╝

🧠 AI REASONING SUMMARY:
   Total Decisions: {strategy_report['total_decisions']}
   Successful Decisions: {strategy_report['successful_decisions']}
   Success Rate: {strategy_report['success_rate']:.1%}

📊 GRAPH STATISTICS:
   Total Nodes: {graph_stats['total_nodes']}
   Total Edges: {graph_stats['total_edges']}
   Explored: {graph_stats['explored']}

🚨 VULNERABILITIES FOUND: {len(self.findings)}
""")
        
        for sev, findings in self._group_findings_by_severity().items():
            if findings:
                print(f"   {sev.upper()}: {len(findings)}")
        
        print(f"""
🎯 TOP SUCCESSFUL PATTERNS:""")
        for pattern in self.reasoner._get_top_patterns()[:3]:
            print(f"   - {pattern['pattern']}: {pattern['success_rate']:.1%} success rate")
        
        # Save report
        report_file = f"intelligent_recon_{self.seed_target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Full report saved: {report_file}")
        
        return report
    
    def _group_findings_by_severity(self) -> Dict[str, List]:
        """Group findings by severity"""
        groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        for finding in self.findings:
            sev = finding.get("severity", "info").lower()
            if sev in groups:
                groups[sev].append(finding)
        
        return groups


def main():
    """Demo the intelligent reconnaissance system"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Intelligent Agentic Reconnaissance")
    parser.add_argument("target", help="Seed target domain")
    parser.add_argument("--scope", nargs="+", help="Authorized scope")
    parser.add_argument("--time-budget", type=int, default=10, help="Time budget in minutes")
    
    args = parser.parse_args()
    
    scope = args.scope or [args.target, f"*.{args.target}"]
    
    orchestrator = IntelligentReconOrchestrator(args.target, scope)
    report = orchestrator.run_intelligent_recon(args.time_budget)


if __name__ == "__main__":
    main()
