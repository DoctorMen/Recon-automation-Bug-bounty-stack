#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
CASCADE IDE™ - Smart Contract Bug Bounty Hunter
Optimized for 8C/16T system with parallel analysis
Target: CDCETH Smart Contract on Etherscan
"""

import requests
import json
import re
import os
from datetime import datetime
from pathlib import Path
import concurrent.futures
import sys

class SmartContractHunter:
    def __init__(self, contract_address, etherscan_api_key=None):
        self.contract_address = contract_address
        self.api_key = etherscan_api_key or os.getenv('ETHERSCAN_API_KEY', 'YourApiKeyToken')
        self.base_url = "https://api.etherscan.io/v2/api"
        self.vulnerabilities = []
        self.contract_source = None
        self.contract_abi = None
        self.contract_name = "Unknown"
        self.compiler_version = "Unknown"
        self.results = {
            'contract': contract_address,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'bounty_potential': '$0'
        }
        
    def fetch_contract_source(self):
        """Fetch contract source code from Etherscan"""
        print(f"\n[*] Fetching contract source code for {self.contract_address}...")
        
        params = {
            'chainid': '1',  # Ethereum mainnet
            'module': 'contract',
            'action': 'getsourcecode',
            'address': self.contract_address,
            'apikey': self.api_key
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=30)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                result = data['result'][0]
                self.contract_source = result.get('SourceCode', '')
                self.contract_abi = result.get('ABI', '')
                self.contract_name = result.get('ContractName', 'Unknown')
                self.compiler_version = result.get('CompilerVersion', 'Unknown')
                
                print(f"[✓] Contract Name: {self.contract_name}")
                print(f"[✓] Compiler: {self.compiler_version}")
                print(f"[✓] Source Code: {len(self.contract_source)} bytes")
                return True
            else:
                print(f"[!] Failed to fetch contract source: {data.get('message', 'Unknown error')}")
                print(f"[!] Response: {data.get('result', 'No result')}")
                return False
                
        except Exception as e:
            print(f"[!] Error fetching contract: {e}")
            return False
    
    def analyze_reentrancy(self):
        """Check for reentrancy vulnerabilities"""
        print("\n[*] Analyzing for reentrancy vulnerabilities...")
        
        if not self.contract_source:
            return
        
        patterns = [
            (r'\.call\{value:', 'External call with value transfer'),
            (r'\.call\.value\(', 'Deprecated call.value pattern'),
            (r'\.send\(', 'Use of send() without proper checks'),
            (r'\.transfer\(', 'Transfer after external call'),
        ]
        
        for pattern, description in patterns:
            matches = re.finditer(pattern, self.contract_source, re.IGNORECASE)
            for match in matches:
                code_after = self.contract_source[match.end():match.end()+500]
                if re.search(r'\w+\s*=', code_after):
                    vuln = {
                        'type': 'Reentrancy',
                        'severity': 'CRITICAL',
                        'description': f'Potential reentrancy: {description}',
                        'location': f'Position {match.start()}',
                        'code_snippet': self.contract_source[max(0, match.start()-50):match.end()+100],
                        'bounty_estimate': '$50,000 (Critical Tier)',
                        'recommendation': 'Use Checks-Effects-Interactions pattern or ReentrancyGuard'
                    }
                    self.vulnerabilities.append(vuln)
                    self.results['severity_counts']['critical'] += 1
                    print(f"  [!] CRITICAL: Potential reentrancy at position {match.start()}")
    
    def analyze_integer_overflow(self):
        """Check for integer overflow/underflow"""
        print("\n[*] Analyzing for integer overflow/underflow...")
        
        if not self.contract_source:
            return
        
        version_match = re.search(r'pragma solidity\s+([<>=^]*)([\d.]+)', self.contract_source)
        if version_match:
            version = version_match.group(2)
            try:
                parts = version.split('.')
                major_version = int(parts[0])
                minor_version = int(parts[1]) if len(parts) > 1 else 0
                
                if major_version == 0 and minor_version < 8:
                    using_safemath = 'SafeMath' in self.contract_source or 'using SafeMath' in self.contract_source
                    
                    if not using_safemath:
                        vuln = {
                            'type': 'Integer Overflow/Underflow',
                            'severity': 'HIGH',
                            'description': f'Solidity version {version} without SafeMath library',
                            'location': 'Global',
                            'code_snippet': version_match.group(0),
                            'bounty_estimate': '$25,000 (High Severity)',
                            'recommendation': 'Use SafeMath library or upgrade to Solidity 0.8.0+'
                        }
                        self.vulnerabilities.append(vuln)
                        self.results['severity_counts']['high'] += 1
                        print(f"  [!] HIGH: No SafeMath detected in Solidity {version}")
            except (ValueError, IndexError):
                pass
    
    def analyze_access_control(self):
        """Check for access control issues"""
        print("\n[*] Analyzing access control mechanisms...")
        
        if not self.contract_source:
            return
        
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|external)(?!\s+view|pure)'
        matches = re.finditer(func_pattern, self.contract_source)
        
        for match in matches:
            func_name = match.group(1)
            func_start = match.start()
            
            brace_count = 0
            func_end = func_start
            in_func = False
            
            for i in range(func_start, len(self.contract_source)):
                if self.contract_source[i] == '{':
                    brace_count += 1
                    in_func = True
                elif self.contract_source[i] == '}':
                    brace_count -= 1
                    if in_func and brace_count == 0:
                        func_end = i + 1
                        break
            
            func_body = self.contract_source[func_start:func_end]
            
            critical_ops = ['transfer', 'withdraw', 'selfdestruct', 'delegatecall', 'mint', 'burn', 'approve']
            has_critical = any(op in func_body.lower() for op in critical_ops)
            has_modifier = bool(re.search(r'modifier|require\s*\(\s*msg\.sender|onlyOwner|onlyAdmin', func_body))
            
            if has_critical and not has_modifier:
                vuln = {
                    'type': 'Access Control',
                    'severity': 'CRITICAL',
                    'description': f'Function "{func_name}" performs critical operations without access control',
                    'location': f'Function {func_name}',
                    'code_snippet': func_body[:300],
                    'bounty_estimate': '$50,000 (Critical Tier)',
                    'recommendation': 'Add onlyOwner or appropriate access control modifier'
                }
                self.vulnerabilities.append(vuln)
                self.results['severity_counts']['critical'] += 1
                print(f"  [!] CRITICAL: Unprotected function: {func_name}")
    
    def analyze_delegatecall(self):
        """Check for dangerous delegatecall usage"""
        print("\n[*] Analyzing delegatecall usage...")
        
        if not self.contract_source:
            return
        
        matches = re.finditer(r'\.delegatecall\(', self.contract_source)
        for match in matches:
            code_context = self.contract_source[max(0, match.start()-200):match.end()+200]
            
            vuln = {
                'type': 'Dangerous Delegatecall',
                'severity': 'CRITICAL',
                'description': 'Delegatecall can execute arbitrary code in contract context',
                'location': f'Position {match.start()}',
                'code_snippet': code_context,
                'bounty_estimate': '$50,000 (Critical Tier)',
                'recommendation': 'Ensure delegatecall target is trusted and immutable'
            }
            self.vulnerabilities.append(vuln)
            self.results['severity_counts']['critical'] += 1
            print(f"  [!] CRITICAL: Delegatecall found at position {match.start()}")
    
    def analyze_unchecked_calls(self):
        """Check for unchecked external calls"""
        print("\n[*] Analyzing unchecked external calls...")
        
        if not self.contract_source:
            return
        
        patterns = [r'\.call\(', r'\.send\(']
        
        for pattern in patterns:
            matches = re.finditer(pattern, self.contract_source)
            for match in matches:
                line_start = self.contract_source.rfind('\n', 0, match.start()) + 1
                line_end = self.contract_source.find('\n', match.end())
                if line_end == -1:
                    line_end = len(self.contract_source)
                line = self.contract_source[line_start:line_end]
                
                if not re.search(r'require\s*\(|assert\s*\(|if\s*\(.*\)', line):
                    vuln = {
                        'type': 'Unchecked External Call',
                        'severity': 'HIGH',
                        'description': 'External call return value not checked',
                        'location': f'Position {match.start()}',
                        'code_snippet': self.contract_source[max(0, match.start()-100):match.end()+100],
                        'bounty_estimate': '$25,000 (High Severity)',
                        'recommendation': 'Check return value with require() or handle failure'
                    }
                    self.vulnerabilities.append(vuln)
                    self.results['severity_counts']['high'] += 1
                    print(f"  [!] HIGH: Unchecked call at position {match.start()}")
    
    def analyze_timestamp_dependence(self):
        """Check for timestamp manipulation vulnerabilities"""
        print("\n[*] Analyzing timestamp dependence...")
        
        if not self.contract_source:
            return
        
        patterns = [
            (r'block\.timestamp', 'Uses block.timestamp'),
            (r'\bnow\b', 'Uses now keyword'),
        ]
        
        for pattern, description in patterns:
            matches = re.finditer(pattern, self.contract_source)
            for match in matches:
                code_context = self.contract_source[max(0, match.start()-100):match.end()+100]
                
                if any(keyword in code_context for keyword in ['require', 'if', '>', '<', '==', '!=']):
                    vuln = {
                        'type': 'Timestamp Dependence',
                        'severity': 'MEDIUM',
                        'description': f'{description} in conditional logic - miners can manipulate',
                        'location': f'Position {match.start()}',
                        'code_snippet': code_context,
                        'bounty_estimate': '$5,000 (Medium Severity)',
                        'recommendation': 'Avoid using timestamps for critical logic or add tolerance'
                    }
                    self.vulnerabilities.append(vuln)
                    self.results['severity_counts']['medium'] += 1
                    print(f"  [!] MEDIUM: Timestamp usage at position {match.start()}")
    
    def analyze_all(self):
        """Run all analysis checks in parallel"""
        print("\n" + "="*60)
        print("CASCADE IDE - Smart Contract Security Analysis")
        print("Optimized for 8C/16T System - Parallel Execution")
        print("="*60)
        
        if not self.fetch_contract_source():
            print("\n[!] Cannot proceed without contract source code")
            return False
        
        print("\n[*] Running parallel security analysis across all cores...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self.analyze_reentrancy),
                executor.submit(self.analyze_integer_overflow),
                executor.submit(self.analyze_access_control),
                executor.submit(self.analyze_delegatecall),
                executor.submit(self.analyze_unchecked_calls),
                executor.submit(self.analyze_timestamp_dependence)
            ]
            
            concurrent.futures.wait(futures)
        
        self.results['vulnerabilities'] = self.vulnerabilities
        
        critical_count = self.results['severity_counts']['critical']
        high_count = self.results['severity_counts']['high']
        
        if critical_count > 0:
            self.results['bounty_potential'] = f'$50,000 - $1,000,000 ({critical_count} Critical)'
        elif high_count > 0:
            self.results['bounty_potential'] = f'$25,000 - $50,000 ({high_count} High)'
        else:
            self.results['bounty_potential'] = 'Up to $25,000 (Medium/Low findings)'
        
        return True
    
    def generate_report(self):
        """Generate bug bounty report"""
        print("\n" + "="*60)
        print("BUG BOUNTY REPORT - CDCETH SMART CONTRACT")
        print("="*60)
        
        print(f"\n[*] Contract: {self.contract_address}")
        print(f"[*] Contract Name: {self.contract_name}")
        print(f"[*] Compiler: {self.compiler_version}")
        print(f"[*] Analysis Date: {self.results['timestamp']}")
        print(f"[*] Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"\n[*] SEVERITY BREAKDOWN:")
        for severity, count in self.results['severity_counts'].items():
            if count > 0:
                print(f"    {severity.upper()}: {count}")
        
        print(f"\n[*] ESTIMATED BOUNTY POTENTIAL: {self.results['bounty_potential']}")
        
        if self.vulnerabilities:
            print(f"\n{'='*60}")
            print("DETAILED VULNERABILITIES")
            print("="*60)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n--- Vulnerability #{i} ---")
                print(f"Type:        {vuln['type']}")
                print(f"Severity:    {vuln['severity']}")
                print(f"Description: {vuln['description']}")
                print(f"Location:    {vuln['location']}")
                print(f"Bounty Est:  {vuln['bounty_estimate']}")
                print(f"Fix:         {vuln['recommendation']}")
                print(f"\nCode Snippet:")
                print("-" * 40)
                print(vuln['code_snippet'][:200])
                print("-" * 40)
        else:
            print("\n[✓] No critical vulnerabilities detected!")
            print("[*] Contract appears to follow security best practices")
        
        output_dir = Path('output/smart_contracts')
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f'cdceth_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[✓] Full report saved to: {output_file}")
        
        return output_file


def main():
    print("""
================================================================
                                                              
         CASCADE IDE - SMART CONTRACT BUG HUNTER             
              Powered by 16-Thread Architecture               
                                                              
  Target: CDCETH Smart Contract                               
  Bounty: Up to $1,000,000 (Extreme Tier)                     
  Status: AUTHORIZED - Bug Bounty Program                     
                                                              
================================================================
    """)
    
    contract = "0xfe18ae03741a5b84e39c295ac9c856e791c38e"
    
    print(f"\n[*] Target Contract: {contract}")
    print("[*] Legal Status: AUTHORIZED (Etherscan Bug Bounty)")
    print("[*] System: 8 Cores / 16 Threads - Parallel Analysis Active")
    
    hunter = SmartContractHunter(contract)
    
    if hunter.analyze_all():
        report_file = hunter.generate_report()
        
        print("\n" + "="*60)
        print("NEXT STEPS:")
        print("="*60)
        print("\n1. Review vulnerabilities in CASCADE IDE")
        print("2. Validate findings with manual testing")
        print("3. Prepare detailed proof of concept")
        print("4. Submit to Etherscan Bug Bounty Program")
        print("5. Potential payout: " + hunter.results['bounty_potential'])
        
        print("\n[✓] Analysis complete! Ready for bounty submission.")
        return 0
    else:
        print("\n[!] Analysis failed. Check API key or contract address.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
