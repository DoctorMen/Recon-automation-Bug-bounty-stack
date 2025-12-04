#!/usr/bin/env python3
"""
ADVANCED AI-POWERED RECONNAISSANCE SYSTEM
=========================================
Implements 4 game-changing capabilities:
1. LLM Integration for deep reasoning
2. Cross-target learning database
3. Exploit chain building
4. Predictive vulnerability modeling

Copyright (c) 2025 DoctorMen
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# 1. LLM INTEGRATION FOR DEEPER REASONING
# ============================================================================

class LLMReasoner:
    """Uses Claude/GPT for intelligent decision-making"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.use_llm = bool(self.api_key)
        
        if self.use_llm:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                logger.info("✅ LLM active - Claude connected")
            except:
                self.use_llm = False
    
    def analyze(self, context: str, options: str) -> str:
        """Ask LLM what to explore next and why"""
        if not self.use_llm:
            return "Continue standard reconnaissance"
        
        try:
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=500,
                messages=[{
                    "role": "user", 
                    "content": f"Bug bounty recon situation:\n{context}\n\nOptions:\n{options}\n\nWhat should we explore next and why? Be specific and brief."
                }]
            )
            return response.content
        except:
            return "LLM analysis failed, continue standard recon"

# ============================================================================
# 2. CROSS-TARGET LEARNING DATABASE
# ============================================================================

class CrossTargetLearning:
    """Learns from ALL past targets"""
    
    def __init__(self, db_path: str = "learning.db"):
        self.conn = sqlite3.connect(db_path)
        self._init_db()
    
    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                target TEXT,
                tech TEXT,
                vuln_type TEXT,
                severity TEXT,
                success INTEGER,
                timestamp TEXT
            )
        """)
        self.conn.commit()
    
    def record(self, target: str, tech: str, vuln: str, severity: str, success: bool):
        """Record findings for future learning"""
        self.conn.execute(
            "INSERT INTO patterns VALUES (?, ?, ?, ?, ?, ?)",
            (target, tech, vuln, severity, int(success), datetime.now().isoformat())
        )
        self.conn.commit()
    
    def predict_for_tech(self, tech: str) -> List[Dict]:
        """Predict vulns based on technology"""
        cursor = self.conn.execute("""
            SELECT vuln_type, severity, AVG(success) as rate, COUNT(*) as count
            FROM patterns 
            WHERE tech LIKE ?
            GROUP BY vuln_type, severity
            ORDER BY rate DESC
        """, (f"%{tech}%",))
        
        return [
            {"vuln": row[0], "severity": row[1], "success_rate": row[2], "seen_count": row[3]}
            for row in cursor.fetchall()
        ]

# ============================================================================
# 3. EXPLOIT CHAIN BUILDER
# ============================================================================

class ExploitChainBuilder:
    """Chains vulnerabilities for maximum impact"""
    
    KNOWN_CHAINS = [
        {
            "name": "XSS→Account Takeover",
            "requires": ["xss"],
            "leads_to": "account_takeover",
            "impact": "critical"
        },
        {
            "name": "SSRF→Internal Access",
            "requires": ["ssrf"],
            "leads_to": "internal_access",
            "impact": "critical"
        },
        {
            "name": "SQLi→RCE",
            "requires": ["sql_injection"],
            "leads_to": "remote_code_execution",
            "impact": "critical"
        },
        {
            "name": "Info Leak→Privilege Escalation",
            "requires": ["information_disclosure"],
            "leads_to": "privilege_escalation",
            "impact": "high"
        }
    ]
    
    def find_chains(self, vulns: List[str]) -> List[Dict]:
        """Find possible exploit chains"""
        chains = []
        vuln_types = [v.lower() for v in vulns]
        
        for chain in self.KNOWN_CHAINS:
            if any(req in str(vuln_types) for req in chain["requires"]):
                chains.append({
                    "chain": chain["name"],
                    "current": chain["requires"][0],
                    "target": chain["leads_to"],
                    "impact": chain["impact"],
                    "action": f"Try to escalate {chain['requires'][0]} to {chain['leads_to']}"
                })
        
        return sorted(chains, key=lambda x: x["impact"] == "critical", reverse=True)

# ============================================================================
# 4. PREDICTIVE MODELING
# ============================================================================

class VulnerabilityPredictor:
    """Predicts likely vulnerabilities"""
    
    TECH_PATTERNS = {
        "wordpress": ["plugin_vulns", "xmlrpc", "user_enum"],
        "laravel": ["debug_mode", "mass_assignment", "sqli"],
        "nodejs": ["prototype_pollution", "nosql_injection"],
        "apache": ["directory_listing", "outdated_version"],
        "nginx": ["misconfig", "path_traversal"],
        "jenkins": ["no_auth", "script_console"],
        "gitlab": ["public_projects", "ci_variables"]
    }
    
    def predict(self, technologies: List[str]) -> List[Dict]:
        """Predict vulns based on tech stack"""
        predictions = []
        
        for tech in technologies:
            tech_lower = tech.lower()
            for pattern, vulns in self.TECH_PATTERNS.items():
                if pattern in tech_lower:
                    predictions.extend([
                        {"tech": tech, "predicted_vuln": v, "confidence": 0.7}
                        for v in vulns
                    ])
        
        return predictions

# ============================================================================
# MASTER SYSTEM INTEGRATING ALL CAPABILITIES
# ============================================================================

class AdvancedAIRecon:
    """The complete AI-powered reconnaissance system"""
    
    def __init__(self, target: str, api_key: Optional[str] = None):
        self.target = target
        self.llm = LLMReasoner(api_key)
        self.learning = CrossTargetLearning()
        self.chains = ExploitChainBuilder()
        self.predictor = VulnerabilityPredictor()
        self.findings = []
    
    def analyze_with_ai(self, context: Dict) -> str:
        """Use all AI capabilities to decide next action"""
        
        # 1. Get predictions
        predictions = self.predictor.predict(context.get("technologies", []))
        
        # 2. Check for chains
        vuln_types = [f.get("type") for f in self.findings]
        possible_chains = self.chains.find_chains(vuln_types)
        
        # 3. Learn from history
        historical = []
        for tech in context.get("technologies", []):
            historical.extend(self.learning.predict_for_tech(tech))
        
        # 4. Ask LLM for decision
        context_str = f"""
Target: {self.target}
Found: {len(self.findings)} vulnerabilities
Technologies: {context.get('technologies', [])}
Current vulns: {vuln_types[:5]}
Predictions: {[p['predicted_vuln'] for p in predictions[:3]]}
Possible chains: {[c['chain'] for c in possible_chains[:2]]}
Historical success: {[h['vuln'] for h in historical[:3]]}
        """
        
        options_str = """
1. Deep dive on predicted vulnerabilities
2. Try to build exploit chain
3. Pivot to new attack surface
4. Focus on high-confidence historical patterns
        """
        
        decision = self.llm.analyze(context_str, options_str)
        
        return self._execute_decision(decision, predictions, possible_chains)
    
    def _execute_decision(self, decision: str, predictions: List, chains: List) -> str:
        """Execute the AI's decision"""
        
        # Parse decision
        if "chain" in decision.lower() and chains:
            return f"Building chain: {chains[0]['action']}"
        elif "predicted" in decision.lower() and predictions:
            return f"Testing prediction: {predictions[0]['predicted_vuln']}"
        else:
            return "Continuing standard reconnaissance"
    
    def demo_run(self):
        """Demo the advanced capabilities"""
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║              ADVANCED AI RECONNAISSANCE SYSTEM                       ║
║    4 Game-Changing Capabilities Integrated                          ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 Target: {self.target}
        """)
        
        # Simulate findings
        self.findings = [
            {"type": "xss", "severity": "medium"},
            {"type": "information_disclosure", "severity": "low"}
        ]
        
        context = {
            "technologies": ["WordPress", "Apache", "PHP"],
            "subdomains": ["admin.example.com", "api.example.com"]
        }
        
        # CAPABILITY 1: Predictive Modeling
        print("\n1️⃣ PREDICTIVE MODELING")
        print("="*50)
        predictions = self.predictor.predict(context["technologies"])
        print(f"Based on tech stack, predicting:")
        for p in predictions[:3]:
            print(f"   - {p['predicted_vuln']} in {p['tech']} ({p['confidence']:.0%} confidence)")
        
        # CAPABILITY 2: Cross-Target Learning
        print("\n2️⃣ CROSS-TARGET LEARNING")
        print("="*50)
        # Record and learn
        self.learning.record(self.target, "WordPress", "plugin_vuln", "high", True)
        historical = self.learning.predict_for_tech("WordPress")
        if historical:
            print(f"Historical data suggests:")
            for h in historical[:3]:
                print(f"   - {h['vuln']}: {h['success_rate']:.0%} success rate")
        else:
            print("   Building knowledge base...")
        
        # CAPABILITY 3: Exploit Chains
        print("\n3️⃣ EXPLOIT CHAIN BUILDING")
        print("="*50)
        chains = self.chains.find_chains([f["type"] for f in self.findings])
        if chains:
            print(f"Possible exploit chains:")
            for c in chains:
                print(f"   - {c['chain']} → {c['impact']} impact")
                print(f"     Action: {c['action']}")
        else:
            print("   No chains available yet")
        
        # CAPABILITY 4: LLM Reasoning
        print("\n4️⃣ LLM REASONING")
        print("="*50)
        decision = self.analyze_with_ai(context)
        print(f"AI Decision: {decision}")
        
        print("\n" + "="*60)
        print("This is what makes us DIFFERENT:")
        print("- We PREDICT vulnerabilities before testing")
        print("- We LEARN from every target for the next")
        print("- We BUILD exploit chains intelligently")
        print("- We REASON about next steps with AI")
        print("="*60)

def main():
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    
    # Check for API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("⚠️  No ANTHROPIC_API_KEY found, using pattern-based reasoning")
        print("   For full LLM capabilities, set: export ANTHROPIC_API_KEY=your_key")
    
    system = AdvancedAIRecon(target, api_key)
    system.demo_run()

if __name__ == "__main__":
    main()
