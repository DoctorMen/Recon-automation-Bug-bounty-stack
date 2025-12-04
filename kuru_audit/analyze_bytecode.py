#!/usr/bin/env python3
"""
KURU BYTECODE ANALYZER
Decompile and analyze for vulnerabilities
"""

import json
import re
from pathlib import Path

class BytecodeAnalyzer:
    def __init__(self):
        self.bytecode = ""
        self.function_sigs = {}
        
    def load_bytecode(self, filepath):
        """Load bytecode from file"""
        with open(filepath) as f:
            self.bytecode = f.read().strip()
        print(f"Loaded {len(self.bytecode)} bytes")
        
    def load_abi(self, filepath):
        """Load ABI for function signature mapping"""
        with open(filepath) as f:
            data = json.load(f)
            
        # Get method identifiers
        if 'methodIdentifiers' in data:
            self.function_sigs = data['methodIdentifiers']
            print(f"Loaded {len(self.function_sigs)} function signatures")
            
    def find_constants(self):
        """Find hardcoded constants in bytecode"""
        print("\n" + "="*60)
        print("SEARCHING FOR CONSTANTS (MIN_LIQUIDITY, etc)")
        print("="*60)
        
        # Common patterns for MIN_LIQUIDITY in vaults
        # Usually 1000 (0x3e8) or 10000 (0x2710) or 1e15 wei
        patterns = {
            '1000': '0x3e8',
            '10000': '0x2710',
            '1e15': '0x38d7ea4c68000',
            '1e18': '0xde0b6b3a7640000',
            '1e6': '0xf4240',
        }
        
        bytecode_lower = self.bytecode.lower()
        
        found = []
        for name, pattern in patterns.items():
            # Remove 0x and search
            hex_val = pattern[2:].lower()
            # Look for PUSH operations with this value
            if hex_val in bytecode_lower:
                count = bytecode_lower.count(hex_val)
                found.append(f"  {name} ({pattern}): found {count} times")
                
        if found:
            print("Potential MIN_LIQUIDITY candidates:")
            for f in found:
                print(f)
        else:
            print("No common MIN_LIQUIDITY patterns found")
            
        # Look for sqrt operations (used in first deposit)
        # SQRT is often implemented as a series of operations
        # or a precompile call
        
        return found
        
    def find_access_control(self):
        """Find access control patterns"""
        print("\n" + "="*60)
        print("SEARCHING FOR ACCESS CONTROL PATTERNS")
        print("="*60)
        
        bytecode_lower = self.bytecode.lower()
        
        # Common patterns
        patterns = {
            'msg.sender check': '33',  # CALLER opcode
            'owner storage': '54',  # SLOAD opcode
            'require/revert': 'fd',  # REVERT opcode
        }
        
        for name, pattern in patterns.items():
            count = bytecode_lower.count(pattern)
            print(f"  {name}: {count} occurrences")
            
    def find_reentrancy_guards(self):
        """Check for reentrancy protection"""
        print("\n" + "="*60)
        print("SEARCHING FOR REENTRANCY GUARDS")
        print("="*60)
        
        bytecode_lower = self.bytecode.lower()
        
        # nonReentrant modifier typically uses a storage slot
        # Pattern: SLOAD, check value, SSTORE new value, ..., SSTORE back
        
        # Count SSTORE operations (55 opcode)
        sstore_count = bytecode_lower.count('55')
        print(f"  SSTORE operations: {sstore_count}")
        
        # Count external calls (CALL, DELEGATECALL, STATICCALL)
        call_count = bytecode_lower.count('f1')  # CALL
        delegatecall_count = bytecode_lower.count('f4')  # DELEGATECALL
        staticcall_count = bytecode_lower.count('fa')  # STATICCALL
        
        print(f"  CALL operations: {call_count}")
        print(f"  DELEGATECALL operations: {delegatecall_count}")
        print(f"  STATICCALL operations: {staticcall_count}")
        
        if call_count > 0 and sstore_count < call_count * 2:
            print("\n  ⚠️  WARNING: More CALLs than SSTORE pairs")
            print("  This could indicate missing reentrancy guards!")
            
    def analyze_function(self, func_name):
        """Analyze a specific function"""
        if func_name in self.function_sigs:
            sig = self.function_sigs[func_name]
            print(f"\nFunction: {func_name}")
            print(f"  Selector: 0x{sig}")
        else:
            print(f"Function {func_name} not found in ABI")
            
    def find_sqrt_implementation(self):
        """Check how sqrt is implemented (critical for first deposit)"""
        print("\n" + "="*60)
        print("ANALYZING SQRT IMPLEMENTATION")
        print("="*60)
        
        # sqrt can be:
        # 1. Inline assembly (Babylonian method)
        # 2. Library call
        # 3. Precompile
        
        bytecode_lower = self.bytecode.lower()
        
        # Look for division operations (04 = DIV)
        div_count = bytecode_lower.count('04')
        
        # Look for multiplication (02 = MUL)
        mul_count = bytecode_lower.count('02')
        
        print(f"  DIV operations: {div_count}")
        print(f"  MUL operations: {mul_count}")
        
        # Babylonian sqrt typically has many DIV/MUL in sequence
        if div_count > 10 and mul_count > 10:
            print("  Likely uses Babylonian sqrt method (inline)")
        else:
            print("  May use library or different sqrt implementation")
            
    def extract_immutable_refs(self, abi_path):
        """Extract immutable references (could reveal MIN_LIQUIDITY location)"""
        print("\n" + "="*60)
        print("EXTRACTING IMMUTABLE REFERENCES")
        print("="*60)
        
        with open(abi_path) as f:
            data = json.load(f)
            
        immutables = data.get('deployedBytecode', {}).get('immutableReferences', {})
        
        if immutables:
            print("Immutable variables found:")
            for ref_id, locations in immutables.items():
                print(f"  ID {ref_id}: {len(locations)} references")
                for loc in locations[:3]:  # Show first 3
                    print(f"    - offset: {loc.get('start')}, length: {loc.get('length')}")
        else:
            print("No immutable references found")
            
    def run_full_analysis(self):
        """Run complete bytecode analysis"""
        print("\n" + "="*70)
        print("🔍 KURU VAULT BYTECODE ANALYSIS")
        print("="*70)
        
        self.load_bytecode('kuru_audit/vault_bytecode.hex')
        self.load_abi('kuru_audit/abi/Vault.json')
        
        self.find_constants()
        self.find_access_control()
        self.find_reentrancy_guards()
        self.find_sqrt_implementation()
        self.extract_immutable_refs('kuru_audit/abi/Vault.json')
        
        # Analyze critical functions
        print("\n" + "="*60)
        print("CRITICAL FUNCTIONS")
        print("="*60)
        
        critical = ['deposit', 'withdraw', 'mint', 'redeem', 'transfer']
        for func in critical:
            for name, sig in self.function_sigs.items():
                if func in name.lower():
                    print(f"  {name}: 0x{sig}")

if __name__ == "__main__":
    analyzer = BytecodeAnalyzer()
    analyzer.run_full_analysis()
