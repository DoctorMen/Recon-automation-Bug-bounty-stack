
KURU DEX BUG BOUNTY - REVISED FINDINGS
======================================

After thorough triage review, the original First Depositor attack was
found to be INVALID due to dead shares protection.

NEW FINDINGS REQUIRING VERIFICATION:

==============================================================================
FINDING 1: MarginAccount Access Control (Potential CRITICAL)
==============================================================================

Target: creditUser(), debitUser(), updateMarkets()

Hypothesis:
  If these functions lack proper access control (onlyMarket, onlyOwner),
  attackers could:
  - Credit themselves infinite tokens
  - Debit other users tokens  
  - Register malicious contracts as markets

Evidence Required:
  - Source code showing modifier
  - Or live test calling function without auth

Test Plan:
  1. Try calling creditUser directly (should revert if protected)
  2. Try calling updateMarkets directly (should revert if protected)
  3. Check if any address can be registered as market

Potential Bounty: ,000 (Critical) if unprotected

==============================================================================
FINDING 2: Vault Price Manipulation via Flash Loan (Potential HIGH)
==============================================================================

Target: KuruAMMVault deposit/withdraw with spot price calculations

Hypothesis:
  Vault uses spot price for share calculations.
  Flash loan can temporarily manipulate reserves.
  Deposit at manipulated price = more shares than deserved.

Evidence Required:
  - Verify vault uses spot price (not TWAP)
  - Calculate profitable flash loan parameters
  - Demonstrate profit after fees

Test Plan:
  1. Monitor vault deposits for price sensitivity
  2. Calculate minimum flash loan for profitable attack
  3. Simulate full attack with fees

Potential Bounty: ,000 (High) if exploitable

==============================================================================
FINDING 3: Flip Order Price Bounds (Potential MEDIUM-HIGH)
==============================================================================

Target: addFlipBuyOrder(), addFlipSellOrder()

Hypothesis:
  _flippedPrice parameter may not be validated against market bounds.
  Extreme flipped prices could create instant arbitrage opportunities.

Evidence Required:
  - Check if flippedPrice has bounds validation
  - Test placing flip order with extreme price

Test Plan:
  1. Place flip buy at price=100, flippedPrice=1
  2. See if flip order gets placed when filled
  3. Check if arbitrage is possible

Potential Bounty: ,000-,000 (Medium-High) if exploitable

==============================================================================
FINDING 4: Array Length Mismatch in anyToAnySwap (Potential MEDIUM)
==============================================================================

Target: Router.anyToAnySwap()

Hypothesis:
  Function takes multiple arrays that should be same length.
  If not validated, mismatched arrays could cause:
  - Reading uninitialized values
  - Wrong swap directions
  - Accounting errors

Evidence Required:
  - Try calling with mismatched array lengths
  - Check for revert or unexpected behavior

Test Plan:
  1. Call with markets.length=3, isBuy.length=2
  2. Observe behavior
  3. Check for exploitable state

Potential Bounty: ,000-,000 (Medium) if exploitable

==============================================================================
RECOMMENDED NEXT STEPS
==============================================================================

1. REQUEST SOURCE CODE via Cantina
   - Needed to verify access control modifiers
   - Needed to verify price calculation methods

2. DEPLOY LOCAL FORK
   - Test live contract behavior
   - Call functions without auth to test protection

3. MONITOR MAINNET TRANSACTIONS
   - Look for patterns in successful transactions
   - Identify any unusual behaviors

4. FUZZING CAMPAIGN
   - Fuzz creditUsersEncoded with malformed data
   - Fuzz flip order parameters
   - Fuzz array lengths in batch functions

==============================================================================
