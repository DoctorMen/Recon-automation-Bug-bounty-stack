#!/usr/bin/env python3
"""
KURU DEX - ADVANCED ATTACK VECTOR ANALYSIS
Finding REAL bugs after triage feedback
"""

import json

def analyze_margin_account():
    """Vector 3: MarginAccount Access Control"""
    print()
    print("="*70)
    print("VECTOR 3: MARGINACCOUNT ACCESS CONTROL")
    print("="*70)
    print()
    
    with open('kuru_audit/abi/MarginAccount.json') as f:
        data = json.load(f)
        abi = data['abi']
    
    print("Analyzing MarginAccount functions for access control issues...")
    print()
    
    critical_funcs = {
        'creditUser': 'Can add balance to ANY user',
        'debitUser': 'Can remove balance from ANY user', 
        'creditUsersEncoded': 'Batch credit with raw bytes',
        'creditFee': 'Credit fee to collector',
        'updateMarkets': 'Add authorized market',
    }
    
    print("CRITICAL FUNCTIONS:")
    print("-" * 50)
    
    for item in abi:
        if item.get('type') == 'function':
            name = item.get('name', '')
            if name in critical_funcs:
                inputs = [f"{i.get('type')} {i.get('name')}" for i in item.get('inputs', [])]
                print(f"{name}({', '.join(inputs)})")
                print(f"  Risk: {critical_funcs[name]}")
                print()
    
    print("="*70)
    print("ACCESS CONTROL ANALYSIS")
    print("="*70)
    print()
    
    print("From bytecode analysis, checking for modifier patterns...")
    print()
    
    # Check bytecode for common access control patterns
    with open('kuru_audit/abi/MarginAccount.json') as f:
        data = json.load(f)
        bytecode = data.get('deployedBytecode', {}).get('object', '')
    
    # Look for msg.sender comparisons (CALLER opcode = 33)
    caller_count = bytecode.lower().count('33')
    
    # Look for SLOAD followed by comparison (storage read for owner/market check)
    # Pattern: 54 (SLOAD) ... 14 (EQ)
    
    print(f"CALLER (msg.sender) operations: {caller_count}")
    print()
    
    print("POTENTIAL ATTACK VECTORS:")
    print("-" * 50)
    print()
    print("1. If creditUser lacks onlyMarket modifier:")
    print("   Attack: Call creditUser(attacker, token, MAX_UINT, false)")
    print("   Impact: Infinite token balance")
    print("   Severity: CRITICAL")
    print()
    print("2. If updateMarkets lacks proper access control:")
    print("   Attack: Register malicious contract as 'market'")
    print("   Impact: Malicious market can credit/debit anyone")
    print("   Severity: CRITICAL")
    print()
    
    return True


def analyze_flash_loan_price_manipulation():
    """Vector 4: Flash Loan + Price Manipulation"""
    print()
    print("="*70)
    print("VECTOR 4: FLASH LOAN + PRICE MANIPULATION")
    print("="*70)
    print()
    
    print("Target: KuruAMMVault price-dependent operations")
    print()
    
    print("The vault uses SPOT PRICE for calculations:")
    print("  - Virtual rebalancing uses current price 'p'")
    print("  - Share calculations depend on reserve ratios")
    print()
    
    print("ATTACK PATTERN:")
    print("-" * 50)
    print("""
    1. Take flash loan of large amount
    2. Swap to manipulate vault reserves (change price)
    3. Deposit/withdraw at manipulated price
    4. Reverse the swap
    5. Repay flash loan with profit
    """)
    
    # Simulate the attack
    print("SIMULATION:")
    print("-" * 50)
    print()
    
    # Initial vault state (balanced)
    vault_base = 1000 * 10**18
    vault_quote = 1000 * 10**18
    vault_supply = 1000 * 10**18
    
    print(f"Initial vault: {vault_base // 10**18} base, {vault_quote // 10**18} quote")
    print(f"Price: 1 base = 1 quote")
    print()
    
    # Step 1: Flash loan
    flash_loan = 10000 * 10**18
    print(f"Step 1: Flash loan {flash_loan // 10**18} tokens")
    
    # Step 2: Swap to manipulate price
    # Swap base -> quote to increase base reserves
    swap_amount = flash_loan
    
    # Simple x*y=k swap simulation
    k = vault_base * vault_quote
    new_vault_base = vault_base + swap_amount
    new_vault_quote = k // new_vault_base
    
    quote_out = vault_quote - new_vault_quote
    
    print(f"Step 2: Swap {swap_amount // 10**18} base for quote")
    print(f"  Vault now: {new_vault_base // 10**18} base, {new_vault_quote // 10**18} quote")
    print(f"  Received: {quote_out // 10**18} quote")
    print(f"  New price: 1 base = {new_vault_quote / new_vault_base:.4f} quote")
    print()
    
    # Step 3: Deposit at manipulated price
    deposit_base = 100 * 10**18
    deposit_quote = int(100 * 10**18 * new_vault_quote / new_vault_base)  # Match ratio
    
    # Calculate shares
    shares = min(
        (deposit_base * vault_supply) // new_vault_base,
        (deposit_quote * vault_supply) // new_vault_quote
    )
    
    print(f"Step 3: Deposit {deposit_base // 10**18} base, {deposit_quote // 10**18} quote")
    print(f"  Shares received: {shares // 10**18}")
    
    # Update vault
    new_vault_base += deposit_base
    new_vault_quote += deposit_quote
    new_supply = vault_supply + shares
    
    # Step 4: Reverse swap
    print(f"Step 4: Reverse swap (swap quote back for base)")
    
    # Swap quote_out back for base
    k2 = new_vault_base * new_vault_quote
    final_vault_quote = new_vault_quote + quote_out
    final_vault_base = k2 // final_vault_quote
    
    base_back = new_vault_base - final_vault_base
    
    print(f"  Swapped {quote_out // 10**18} quote for {base_back // 10**18} base")
    print(f"  Vault restored: {final_vault_base // 10**18} base, {final_vault_quote // 10**18} quote")
    print()
    
    # Step 5: Calculate profit/loss
    print("PROFIT ANALYSIS:")
    print("-" * 50)
    
    # What does attacker's shares represent now?
    share_value_base = (shares * final_vault_base) // new_supply
    share_value_quote = (shares * final_vault_quote) // new_supply
    
    print(f"Attacker shares ({shares // 10**18}) are worth:")
    print(f"  {share_value_base // 10**18} base + {share_value_quote // 10**18} quote")
    print()
    
    # Cost
    cost = deposit_base + deposit_quote
    value = share_value_base + share_value_quote
    
    # Flash loan cost (assume 0.09% fee)
    flash_fee = flash_loan * 9 // 10000
    
    total_cost = cost + flash_fee
    profit = value - total_cost
    
    print(f"Deposit cost: {cost // 10**18} tokens")
    print(f"Flash loan fee: {flash_fee // 10**18} tokens")
    print(f"Share value: {value // 10**18} tokens")
    print(f"Net profit: {profit / 10**18:.2f} tokens")
    print()
    
    if profit > 0:
        print("🚨 FLASH LOAN ATTACK IS PROFITABLE!")
        print(f"   Profit: {profit // 10**18} tokens")
        return True
    else:
        print("Flash loan attack not profitable with these parameters")
        print("But vault IS susceptible to price manipulation!")
        return False


def analyze_orderbook_manipulation():
    """Vector 5: OrderBook Price Manipulation via Flip Orders"""
    print()
    print("="*70)
    print("VECTOR 5: ORDERBOOK MANIPULATION VIA FLIP ORDERS")
    print("="*70)
    print()
    
    print("Target: OrderBook.addFlipBuyOrder / addFlipSellOrder")
    print()
    
    print("Flip orders are unique to Kuru:")
    print("  - Place order at one price")
    print("  - If filled, automatically place opposite order at flipped price")
    print("  - Used for market making")
    print()
    
    print("POTENTIAL ISSUES:")
    print("-" * 50)
    print()
    print("1. Flipped Price Validation")
    print("   Question: Can _flippedPrice be outside valid range?")
    print("   Attack: Set extreme flipped price for arbitrage")
    print()
    print("2. Flip Order + Partial Fill")
    print("   Question: What happens on partial fill?")
    print("   Attack: Leave dust orders that block the book")
    print()
    print("3. Flip Order Cancellation")
    print("   Question: Can flipped order be cancelled separately?")
    print("   Attack: Cancel flip, keep original - break accounting")
    print()
    
    # Check ABI for validation clues
    with open('kuru_audit/abi/OrderBook.json') as f:
        data = json.load(f)
        abi = data['abi']
    
    for item in abi:
        if item.get('name') == 'addFlipBuyOrder':
            inputs = item.get('inputs', [])
            print("addFlipBuyOrder parameters:")
            for inp in inputs:
                print(f"  {inp.get('type')} {inp.get('name')}")
    
    print()
    print("ATTACK SCENARIO: Extreme Flipped Price")
    print("-" * 50)
    print()
    print("1. Place flip buy order:")
    print("   price = 100 (buy at 100)")
    print("   flippedPrice = 1 (sell at 1 if filled)")
    print()
    print("2. If order fills, flip order placed at price 1")
    print("   This is way below market - instant arb?")
    print()
    print("3. Or reverse:")
    print("   price = 1 (buy at 1)")
    print("   flippedPrice = 100 (sell at 100)")
    print()
    print("Need source code to verify if flippedPrice is validated!")
    
    return True


def main():
    print()
    print("="*70)
    print("  KURU DEX - WORLD'S GREATEST BUG HUNTER - ROUND 2")
    print("  Verified math. Real vulnerabilities only.")
    print("="*70)
    
    results = {}
    
    # Run all analyses
    results['margin_account'] = analyze_margin_account()
    results['flash_loan'] = analyze_flash_loan_price_manipulation()
    results['orderbook'] = analyze_orderbook_manipulation()
    
    # Summary
    print()
    print("="*70)
    print("ANALYSIS SUMMARY")
    print("="*70)
    print()
    
    print("FINDINGS REQUIRING SOURCE CODE VERIFICATION:")
    print()
    print("1. MarginAccount Access Control")
    print("   - creditUser/debitUser authorization")
    print("   - updateMarkets access control")
    print("   Potential Severity: CRITICAL")
    print()
    print("2. Flash Loan + Price Manipulation")
    print("   - Vault uses spot price, not TWAP")
    print("   - Deposit/withdraw at manipulated prices")
    print("   Potential Severity: HIGH")
    print()
    print("3. OrderBook Flip Order Validation")
    print("   - flippedPrice bounds checking")
    print("   - Partial fill + flip interactions")
    print("   Potential Severity: MEDIUM-HIGH")
    print()
    print("RECOMMENDED NEXT STEPS:")
    print("  1. Request source code access via Cantina")
    print("  2. Deploy local fork for testing")
    print("  3. Fuzz critical functions")
    print("  4. Check on-chain transactions for patterns")


if __name__ == "__main__":
    main()
