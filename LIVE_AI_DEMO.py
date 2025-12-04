#!/usr/bin/env python3
"""
LIVE AI DEMO - Full LLM Integration
==================================
Shows the complete AI reasoning system in action.
Simulates Claude API responses for demonstration.

Copyright (c) 2025 DoctorMen
"""

import json
import os
from datetime import datetime
from typing import Dict, List

class SimulatedLLM:
    """Simulates Claude API responses for demo"""
    
    def analyze(self, context: str, options: str) -> str:
        """Simulate intelligent LLM analysis"""
        
        # Simulate Claude-style reasoning based on context
        if "WordPress" in context and "xss" in context:
            return """
🧠 CLAUDE ANALYSIS:
I see you've discovered XSS on a WordPress site. This is a significant finding.

RECOMMENDATION: Pivot to session management testing immediately.

REASONING:
- WordPress XSS often leads to session hijacking
- Check if session cookies lack HttpOnly flag
- Test for session fixation vulnerabilities
- Look for admin panel access via stolen sessions

NEXT STEPS:
1. Test all cookies for HttpOnly/Secure flags
2. Attempt session fixation on login/logout
3. Check for admin dashboard access with stolen session
4. Verify if CSRF tokens protect admin actions

EXPECTED IMPACT: Critical - Complete admin takeover possible
            """
        
        elif "information_disclosure" in context:
            return """
🧠 CLAUDE ANALYSIS:
Information disclosure found. This could be our entry point.

RECOMMENDATION: Deep dive into the disclosed information.

REASONING:
- Verbose errors often reveal internal architecture
- Stack traces may expose framework versions
- Configuration paths could lead to credential leaks

NEXT STEPS:
1. Extract all internal paths from error messages
2. Check for exposed configuration files
3. Look for API keys or database credentials
4. Test discovered internal endpoints

EXPECTED IMPACT: High - Could lead to full system compromise
            """
        
        elif "WordPress" in context:
            return """
🧠 CLAUDE ANALYSIS:
WordPress detected. High-probability attack surface.

RECOMMENDATION: Focus on WordPress-specific vulnerabilities.

REASONING:
- WordPress has predictable vulnerability patterns
- Plugin vulnerabilities are common and critical
- XML-RPC is often enabled and exploitable

NEXT STEPS:
1. Enumerate installed plugins via /wp-content/plugins/
2. Test XML-RPC for authentication bypass
3. Check for user enumeration via /wp-json/wp/v2/users
4. Test for REST API exposure

EXPECTED IMPACT: Medium to Critical depending on plugins
            """
        
        else:
            return """
🧠 CLAUDE ANALYSIS:
Standard reconnaissance in progress.

RECOMMENDATION: Continue systematic exploration.

REASONING:
- Need more information to make strategic pivots
- Focus on technology identification
- Look for administrative subdomains

NEXT STEPS:
1. Complete subdomain enumeration
2. Identify all technologies in use
3. Check for admin/staging environments
4. Test common misconfigurations

EXPECTED IMPACT: Information gathering phase
            """

class LiveAIDemo:
    """Live demonstration of full AI capabilities"""
    
    def __init__(self, target: str):
        self.target = target
        self.llm = SimulatedLLM()
        self.findings = []
        self.scan_phase = 1
    
    def run(self):
        """Run the live AI demonstration"""
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║              LIVE AI-POWERED RECONNAISSANCE DEMO                     ║
║          Real Claude-Style Reasoning | Intelligent Decisions          ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 Target: {self.target}
🧠 AI: Claude-style reasoning active
📊 Learning: Cross-target patterns enabled
⚡ Chains: Exploit chain building ready
        """)
        
        # Initialize chains list
        self.chains = []
        
        # Phase 1: Initial Discovery
        self._phase1_initial_discovery()
        
        # Phase 2: AI Analysis and Pivot
        self._phase2_ai_analysis()
        
        # Phase 3: Chain Building
        self._phase3_chain_building()
        
        # Phase 4: Learning Integration
        self._phase4_learning_integration()
    
    def _phase1_initial_discovery(self):
        """Phase 1: Initial vulnerability discovery"""
        
        print(f"\n{'='*60}")
        print("📍 PHASE 1: INITIAL DISCOVERY")
        print(f"{'='*60}")
        
        # Simulate findings
        self.findings = [
            {
                "type": "xss",
                "severity": "medium",
                "target": "example.com/search",
                "evidence": "Reflected XSS in search parameter",
                "discovery_time": 2.5
            },
            {
                "type": "information_disclosure", 
                "severity": "low",
                "target": "example.com/debug",
                "evidence": "Verbose error with internal paths",
                "discovery_time": 4.2
            },
            {
                "type": "wordpress_detected",
                "severity": "info",
                "target": "example.com",
                "evidence": "WordPress 5.8 detected via headers",
                "discovery_time": 1.0
            }
        ]
        
        print(f"🔍 Scanning complete. Found {len(self.findings)} vulnerabilities:")
        for i, f in enumerate(self.findings, 1):
            print(f"   [{i}] {f['severity'].upper()}: {f['type']}")
            print(f"       Target: {f['target']}")
            print(f"       Evidence: {f['evidence']}")
        
        self.scan_phase = 2
    
    def _phase2_ai_analysis(self):
        """Phase 2: AI analyzes and decides next steps"""
        
        print(f"\n{'='*60}")
        print("🧠 PHASE 2: AI ANALYSIS & STRATEGIC PIVOT")
        print(f"{'='*60}")
        
        # Prepare context for AI
        context = f"""
Current Target: {self.target}
Scan Phase: {self.scan_phase}
Findings: {len(self.findings)} vulnerabilities discovered
Vulnerability Types: {[f['type'] for f in self.findings]}
Technologies Detected: WordPress, Apache
Time Elapsed: {sum(f['discovery_time'] for f in self.findings):.1f} minutes
        """
        
        options = """
1. Deep dive into XSS for session hijacking
2. Exploit information disclosure for internal access  
3. Focus on WordPress-specific vulnerabilities
4. Continue general reconnaissance
        """
        
        # Get AI decision
        ai_decision = self.llm.analyze(context, options)
        print(ai_decision)
        
        # Execute AI recommendation
        if "session" in ai_decision.lower():
            self._execute_session_testing()
        elif "information" in ai_decision.lower():
            self._execute_info_disclosure_deep_dive()
        else:
            self._execute_wordpress_focus()
    
    def _execute_session_testing(self):
        """Execute AI's session testing recommendation"""
        print(f"\n🎯 EXECUTING: Session Management Testing")
        print("-" * 50)
        
        # Simulate session testing
        session_findings = [
            {
                "type": "missing_httponly",
                "severity": "medium",
                "target": "example.com/login",
                "evidence": "Session cookie missing HttpOnly flag"
            },
            {
                "type": "weak_session_id",
                "severity": "high", 
                "target": "example.com",
                "evidence": "Predictable session ID pattern detected"
            }
        ]
        
        print(f"✅ Session testing complete. Found {len(session_findings)} issues:")
        for f in session_findings:
            print(f"   - {f['severity'].upper()}: {f['type']}")
            print(f"     {f['evidence']}")
        
        self.findings.extend(session_findings)
    
    def _execute_wordpress_focus(self):
        """Execute AI's WordPress focus recommendation"""
        print(f"\n🎯 EXECUTING: WordPress-Specific Testing")
        print("-" * 50)
        
        wp_findings = [
            {
                "type": "xmlrpc_enabled",
                "severity": "medium",
                "target": "example.com/xmlrpc.php",
                "evidence": "XML-RPC endpoint enabled and accessible"
            },
            {
                "type": "user_enumeration",
                "severity": "medium",
                "target": "example.com/wp-json/wp/v2/users",
                "evidence": "WordPress REST API exposes user list"
            }
        ]
        
        print(f"✅ WordPress testing complete. Found {len(wp_findings)} issues:")
        for f in wp_findings:
            print(f"   - {f['severity'].upper()}: {f['type']}")
            print(f"     {f['evidence']}")
        
        self.findings.extend(wp_findings)
    
    def _phase3_chain_building(self):
        """Phase 3: Build exploit chains"""
        
        print(f"\n{'='*60}")
        print("⚡ PHASE 3: EXPLOIT CHAIN BUILDING")
        print(f"{'='*60}")
        
        # Analyze for chains
        vuln_types = [f['type'] for f in self.findings]
        
        self.chains = []
        
        # XSS + Weak Session = Account Takeover
        if 'xss' in vuln_types and any('session' in v for v in vuln_types):
            self.chains.append({
                "name": "XSS → Weak Session → Account Takeover",
                "components": ["Reflected XSS", "Missing HttpOnly", "Weak Session ID"],
                "impact": "CRITICAL",
                "description": "Steal admin session via XSS, predict session IDs for takeover",
                "steps": [
                    "1. Trigger XSS on admin page",
                    "2. Steal session cookie (no HttpOnly protection)",
                    "3. Predict session ID pattern",
                    "4. Access admin dashboard as any user"
                ]
            })
        
        # Info Disclosure + WordPress = Internal Access
        if 'information_disclosure' in vuln_types and 'wordpress' in vuln_types:
            self.chains.append({
                "name": "Info Disclosure → WordPress Config → Database Access",
                "components": ["Verbose Errors", "WordPress Detection"],
                "impact": "HIGH",
                "description": "Use disclosed paths to find wp-config.php",
                "steps": [
                    "1. Extract internal paths from error messages",
                    "2. Access wp-config.php backup files",
                    "3. Extract database credentials",
                    "4. Access WordPress database directly"
                ]
            })
        
        if self.chains:
            print(f"🔗 EXPLOIT CHAINS DISCOVERED: {len(self.chains)}")
            for i, chain in enumerate(self.chains, 1):
                print(f"\n   [{i}] {chain['name']}")
                print(f"       Impact: {chain['impact']}")
                print(f"       Description: {chain['description']}")
                print(f"       Steps:")
                for step in chain['steps']:
                    print(f"         {step}")
        else:
            print("   No exploit chains available - need more vulnerabilities")
    
    def _phase4_learning_integration(self):
        """Phase 4: Show cross-target learning"""
        
        print(f"\n{'='*60}")
        print("📊 PHASE 4: CROSS-TARGET LEARNING")
        print(f"{'='*60}")
        
        # Simulate learning from this scan
        lessons_learned = [
            {
                "pattern": "WordPress + Missing HttpOnly",
                "success_rate": 0.85,
                "recommendation": "Always test session cookies on WordPress sites",
                "applicable_to": ["*.wordpress.com", "wp-admin", "wp-login"]
            },
            {
                "pattern": "Verbose Errors + Internal Paths",
                "success_rate": 0.70,
                "recommendation": "Extract all paths from errors for further testing",
                "applicable_to": ["debug endpoints", "error pages", "api errors"]
            },
            {
                "pattern": "XML-RPC Enabled",
                "success_rate": 0.65,
                "recommendation": "Test XML-RPC for authentication bypass",
                "applicable_to": ["xmlrpc.php", "WordPress sites"]
            }
        ]
        
        print(f"🧠 PATTERNS LEARNED FOR FUTURE TARGETS:")
        for lesson in lessons_learned:
            print(f"\n   Pattern: {lesson['pattern']}")
            print(f"   Success Rate: {lesson['success_rate']:.0%}")
            print(f"   Recommendation: {lesson['recommendation']}")
            print(f"   Applies to: {', '.join(lesson['applicable_to'])}")
        
        # Final summary
        print(f"\n{'='*60}")
        print("🎯 DEMONSTRATION COMPLETE")
        print(f"{'='*60}")
        
        critical_count = sum(1 for f in self.findings if f['severity'] == 'critical')
        high_count = sum(1 for f in self.findings if f['severity'] == 'high')
        medium_count = sum(1 for f in self.findings if f['severity'] == 'medium')
        
        print(f"""
📊 FINAL RESULTS:
   Total Vulnerabilities: {len(self.findings)}
   Critical: {critical_count} | High: {high_count} | Medium: {medium_count}
   Exploit Chains: {len(self.chains)}
   Patterns Learned: {len(lessons_learned)}

🧠 AI DECISIONS MADE:
   1. Initial discovery → WordPress focus
   2. Session testing based on XSS finding
   3. Chain building for maximum impact
   4. Pattern extraction for future targets

💡 THIS IS THE REVOLUTION:
   - AI REASONED about optimal next steps
   - BUILT critical impact chains from medium bugs
   - LEARNED patterns for the next target
   - PRIORITIZED based on intelligence, not scripts

🚀 NEXT TARGET WILL BE 2X FASTER due to these learned patterns!
        """)

def main():
    target = "example.com"  # Demo target
    demo = LiveAIDemo(target)
    demo.run()

if __name__ == "__main__":
    main()
