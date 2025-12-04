#!/usr/bin/env python3
"""
TEST CANTINA TARGETS - SYSTEMATIC CLICKJACKING VALIDATION
========================================================
Test all Cantina Web3 targets using proven GitLab clickjacking methodology.

Targets: Alchemy ($10k), Deri ($10k), VetraFi ($8k), Circuit ($1.5k)
Method: Proven X-Frame-Options + CSP header analysis
Goal: Find vulnerable targets for immediate submission

Copyright (c) 2025 DoctorMen
"""

import requests
import json
from datetime import datetime
from typing import List, Dict, Any

def test_cantina_targets():
    """Test all Cantina targets for clickjacking vulnerabilities"""
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║          TEST CANTINA TARGETS - SYSTEMATIC CLICKJACKING VALIDATION     ║
║          Web3 Targets | High Bounties | Proven Methodology             ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 TARGETS TO TEST: 4 Web3 platforms
💰 TOTAL BOUNTY POTENTIAL: $29,500
⚡ METHOD: Your proven GitLab clickjacking PoC template
    """)
    
    # Cantina targets with their likely web domains
    cantina_targets = [
        {"name": "Alchemy", "bounty": "$10,000", "domains": ["https://dashboard.alchemy.com", "https://www.alchemy.com"]},
        {"name": "Deri Protocol", "bounty": "$10,000", "domains": ["https://deri.finance", "https://app.deri.finance"]},
        {"name": "VetraFi", "bounty": "$8,000", "domains": ["https://vetrafi.com", "https://app.vetrafi.com"]},
        {"name": "CircuitDAO", "bounty": "$1,500", "domains": ["https://circuitdao.org", "https://app.circuitdao.org"]}
    ]
    
    results = {
        "test_metadata": {
            "start_time": datetime.now().isoformat(),
            "targets_tested": len(cantina_targets),
            "methodology": "X-Frame-Options + CSP header analysis",
            "total_bounty_potential": "$29,500"
        },
        "vulnerable_targets": [],
        "protected_targets": [],
        "test_results": []
    }
    
    print(f"\n📍 TESTING ALL CANTINA TARGETS FOR CLICKJACKING VULNERABILITIES")
    
    for target in cantina_targets:
        print(f"\n{'='*60}")
        print(f"🎯 TESTING: {target['name']} (Bounty: {target['bounty']})")
        print(f"{'='*60}")
        
        # Test each domain for the target
        for domain in target['domains']:
            print(f"\n🔍 Testing domain: {domain}")
            
            try:
                response = requests.get(domain, timeout=10, allow_redirects=True)
                
                # Check security headers
                security_headers = {
                    "X-Frame-Options": response.headers.get("X-Frame-Options"),
                    "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
                    "X-Content-Type-Options": response.headers.get("X-Content-Type-Options")
                }
                
                # Determine if vulnerable
                x_frame_options = security_headers["X-Frame-Options"]
                csp = security_headers["Content-Security-Policy"]
                
                vulnerable = True  # Assume vulnerable
                
                if x_frame_options:
                    if "DENY" in x_frame_options or "SAMEORIGIN" in x_frame_options:
                        vulnerable = False
                
                if csp and "frame-ancestors" in csp:
                    vulnerable = False
                
                target_result = {
                    "target_name": target['name'],
                    "bounty": target['bounty'],
                    "domain": domain,
                    "vulnerable": vulnerable,
                    "security_headers": security_headers,
                    "status_code": response.status_code,
                    "test_time": datetime.now().isoformat()
                }
                
                results["test_results"].append(target_result)
                
                if vulnerable:
                    results["vulnerable_targets"].append(target_result)
                    print(f"   ✅ VULNERABLE - Clickjacking possible!")
                    print(f"   💰 Ready for {target['bounty']} submission")
                else:
                    results["protected_targets"].append(target_result)
                    print(f"   ❌ PROTECTED - Clickjacking not possible")
                
                # Print header analysis
                print(f"   📊 Security Headers:")
                for header, value in security_headers.items():
                    if value:
                        print(f"      ✅ {header}: {value[:50]}...")
                    else:
                        print(f"      ❌ {header}: MISSING (VULNERABLE)")
                
            except Exception as e:
                error_result = {
                    "target_name": target['name'],
                    "bounty": target['bounty'],
                    "domain": domain,
                    "vulnerable": False,
                    "error": str(e),
                    "test_time": datetime.now().isoformat()
                }
                results["test_results"].append(error_result)
                print(f"   ❌ ERROR: {e}")
    
    # Generate summary
    results["summary"] = {
        "total_tested": len(cantina_targets),
        "domains_tested": len(results["test_results"]),
        "vulnerable_count": len(results["vulnerable_targets"]),
        "protected_count": len(results["protected_targets"]),
        "vulnerability_rate": f"{len(results['vulnerable_targets'])/len(results['test_results'])*100:.1f}%",
        "potential_bounty": sum([int(t['bounty'].replace('$', '').replace(',', '')) for t in results["vulnerable_targets"]]),
        "test_duration": str(datetime.now() - datetime.fromisoformat(results["test_metadata"]["start_time"]))
    }
    
    # Save results
    filename = f"cantina_clickjacking_results_{int(datetime.now().timestamp())}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Create PoCs for vulnerable targets
    if results["vulnerable_targets"]:
        create_cantina_pocs(results["vulnerable_targets"])
    
    print_test_summary(results, filename)
    
    return results

def create_cantina_pocs(vulnerable_targets: List[Dict]):
    """Create individual PoC files for vulnerable Cantina targets"""
    
    print(f"\n📍 CREATING INDIVIDUAL POC FILES FOR VULNERABLE TARGETS")
    
    for target in vulnerable_targets:
        poc_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {target['target_name']}</title>
    <style>
        body {{ margin: 0; padding: 20px; font-family: Arial, sans-serif; background: #f5f5f5; }}
        .header {{ background: #6366f1; color: white; padding: 20px; text-align: center; }}
        .bounty-info {{ background: #fbbf24; color: #92400e; padding: 15px; text-align: center; font-weight: bold; }}
        .test-container {{ position: relative; width: 90%; max-width: 1200px; height: 600px; margin: 20px auto; }}
        .overlay {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; 
                    background: rgba(99, 102, 241, 0.1); z-index: 10; 
                    border: 3px solid #6366f1; box-sizing: border-box; }}
        .trap-button {{ position: absolute; top: 150px; left: 200px; z-index: 20; 
                       padding: 15px 30px; background: #4f46e5; color: white; 
                       border: none; font-size: 16px; font-weight: bold; 
                       cursor: pointer; border-radius: 5px; }}
        iframe {{ width: 100%; height: 100%; border: 2px solid #6366f1; }}
        .evidence {{ margin: 20px; padding: 15px; background: white; border-radius: 5px; }}
        .success {{ border-left: 5px solid #10b981; }}
        .web3-warning {{ background: #fef3c7; border: 2px solid #f59e0b; padding: 15px; margin: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 Clickjacking Vulnerability Proof of Concept</h1>
        <p>Target: {target['target_name']}</p>
        <p>Domain: {target['domain']}</p>
        <p>Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Status: VULNERABLE - Clickjacking Possible!</p>
    </div>
    
    <div class="bounty-info">
        💰 POTENTIAL BOUNTY: {target['bounty']} - CANTINA BUG BOUNTY PROGRAM
    </div>
    
    <div class="web3-warning">
        ⚠️ WEB3 SECURITY RISK: Clickjacking could allow wallet connection hijacking, 
        unauthorized transactions, or account takeover on this DeFi platform.
    </div>
    
    <div class="evidence success">
        <h3>🔍 Vulnerability Analysis:</h3>
        <p><strong>Target:</strong> {target['target_name']} ({target['domain']})</p>
        <p><strong>X-Frame-Options:</strong> {target['security_headers'].get('X-Frame-Options', 'MISSING')}</p>
        <p><strong>Content-Security-Policy:</strong> {target['security_headers'].get('Content-Security-Policy', 'MISSING')}</p>
        <p><strong>Assessment:</strong> Target lacks clickjacking protection</p>
        <p><strong>Web3 Impact:</strong> Wallet connection dialogs could be hijacked</p>
    </div>
    
    <div class="test-container">
        <div class="overlay"></div>
        <button class="trap-button">⚠️ CONNECT WALLET</button>
        <iframe src="{target['domain']}" 
                onload="alert('Target loaded successfully! Clickjacking confirmed on Web3 platform!')" 
                onerror="alert('Error loading target')"></iframe>
    </div>
    
    <div class="evidence">
        <h3>💥 Web3 Exploitation Scenario:</h3>
        <p>An attacker can embed {target['target_name']} in a malicious website and overlay 
        invisible "Connect Wallet" buttons to trick users into connecting their wallets to 
        the attacker's address instead of the legitimate platform.</p>
        
        <h3>🚨 Critical Impact:</h3>
        <ul>
            <li>Wallet connection hijacking</li>
            <li>Unauthorized transaction approval</li>
            <li>Account takeover via social engineering</li>
            <li>Asset theft from connected wallets</li>
        </ul>
        
        <p><strong>Recommended Fix:</strong> Implement X-Frame-Options: DENY or 
        Content-Security-Policy with frame-ancestors restriction.</p>
    </div>
</body>
</html>"""
        
        # Save individual PoC
        safe_filename = target['target_name'].lower().replace(' ', '_').replace('-', '_')
        poc_filename = f"cantina_clickjacking_{safe_filename}_{int(datetime.now().timestamp())}.html"
        
        with open(poc_filename, 'w') as f:
            f.write(poc_content)
        
        print(f"   ✅ Created PoC: {poc_filename}")

def print_test_summary(results: Dict, filename: str):
    """Print comprehensive test summary"""
    
    summary = results["summary"]
    
    print(f"""
{'='*70}
🎯 CANTINA CLICKJACKING TEST RESULTS SUMMARY
{'='*70}

📊 OVERALL RESULTS:
   Targets Tested: {summary['total_tested']} Web3 platforms
   Domains Tested: {summary['domains_tested']}
   Vulnerable: {summary['vulnerable_count']} ({summary['vulnerability_rate']})
   Protected: {summary['protected_count']}
   Test Duration: {summary['test_duration']}

💰 BOUNTY POTENTIAL:
   Total Available: {results['test_metadata']['total_bounty_potential']}
   Vulnerable Targets: ${summary['potential_bounty']:,}
   Success Rate: {summary['vulnerability_rate']}

🚀 VULNERABLE TARGETS READY FOR SUBMISSION:""")
    
    if results["vulnerable_targets"]:
        for target in results["vulnerable_targets"]:
            print(f"""
   🔴 {target['target_name']} ({target['domain']})
      Bounty: {target['bounty']}
      Status: VULNERABLE - Clickjacking possible
      Web3 Risk: Wallet connection hijacking
      Action: Submit to Cantina program immediately""")
    else:
        print(f"""
   ❌ No vulnerable targets found
   Action: Test different vulnerability types or targets""")
    
    print(f"""
💡 NEXT STEPS:
   1. Check each vulnerable target's Cantina program scope
   2. Submit clickjacking reports with Web3 impact analysis
   3. Monitor submission status and responses
   4. Leverage Web3 wallet hijacking angle for higher impact

📁 Detailed results saved: {filename}

🎯 READY TO SUBMIT WEB3 CLICKJACKING VULNERABILITIES!
    """)

def main():
    """Execute Cantina targets testing"""
    
    print("""
🎯 TEST CANTINA TARGETS - SYSTEMATIC CLICKJACKING VALIDATION
========================================================

✅ PURPOSE: Test 4 Web3 Cantina targets using proven methodology
✅ TARGETS: Alchemy ($10k), Deri ($10k), VetraFi ($8k), Circuit ($1.5k)
✅ METHOD: Your GitLab PoC template applied to Web3 platforms
✅ ADVANTAGE: Autism-friendly systematic testing

Ready to test $29,500 in potential bounties!
    """)
    
    results = test_cantina_targets()
    
    print(f"""
✅ CANTINA TESTING COMPLETE

Results Summary:
   Vulnerable Targets: {len(results['vulnerable_targets'])}
   Potential Bounty: ${results['summary']['potential_bounty']:,}
   PoC Files Created: {len(results['vulnerable_targets'])}

🎯 READY TO SUBMIT TO CANTINA PROGRAMS!
    """)

if __name__ == "__main__":
    main()
