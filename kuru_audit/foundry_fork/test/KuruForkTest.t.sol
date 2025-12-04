// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/interfaces/IKuru.sol";

/**
 * @title KuruForkTest
 * @notice Fork tests against live Monad mainnet Kuru contracts
 * @dev Run with: forge test --fork-url https://rpc.monad.xyz -vvvv
 */
contract KuruForkTest is Test {
    // Monad Mainnet Contract Addresses (from Cantina bug bounty scope)
    // CONFIRMED MAINNET ADDRESSES
    address constant KURU_FLOW_ENTRYPOINT = 0xb3e6778480b2E488385E8205eA05E20060B813cb;
    address constant KURU_FLOW_ROUTER = 0x465D06d4521ae9Ce724E0c182Daad5D8a2Ff7040;
    address constant KURU_AMM_VAULT_IMPL = 0xDC2A82E321866C30d62077945e067172C5f970F4;
    address constant KURU_FORWARDER = 0x974E61BBa9C4704E8Bcc1923fdC3527B41323FAA;
    address constant KURU_UTILS = 0xD8Ea5Ea6A4ebc202C77c795cb2a35835afd127f6;
    address constant MARGIN_ACCOUNT_IMPL = 0x57cF97FE1FAC7D78B07e7e0761410cb2e91F0ca7;
    address constant ROUTER_IMPL = 0x0F2A2a5c0A78c406c26Adb2F1681D3e47322A9CD;
    address constant ROUTER = 0xd651346d7c789536ebf06dc72aE3C8502cd695CC;
    address constant ORDERBOOK_IMPL = 0xea2Cc8769Fb04Ff1893Ed11cf517b7F040C823CD;
    
    // Note: MarginAccount proxy address not in provided list, using impl for now
    address constant MARGIN_ACCOUNT = 0x57cF97FE1FAC7D78B07e7e0761410cb2e91F0ca7;
    
    // Interfaces
    IMarginAccount public marginAccount;
    IRouter public router;
    IOrderBook public orderBook;
    
    // Test accounts
    address public attacker;
    address public victim;
    
    function setUp() public {
        // Create test accounts
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        
        // Fund accounts
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
        
        // Connect to contracts
        marginAccount = IMarginAccount(MARGIN_ACCOUNT_IMPL);
        router = IRouter(ROUTER);
        orderBook = IOrderBook(ORDERBOOK_IMPL);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 1: MARGINACCOUNT ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test if creditUser can be called by non-market addresses
     * @dev This should REVERT if access control is properly implemented
     */
    function test_CreditUser_AccessControl() public {
        console.log("=== TEST: MarginAccount creditUser Access Control ===");
        console.log("");
        
        address token = address(0x1); // Dummy token
        uint256 amount = 1000 ether;
        
        vm.startPrank(attacker);
        
        console.log("Attacker:", attacker);
        console.log("Attempting to credit self with", amount / 1e18, "tokens...");
        
        // This should REVERT if properly protected
        bool success;
        try marginAccount.creditUser(attacker, token, amount, false) {
            success = true;
            console.log("!!! CRITICAL: creditUser succeeded without authorization !!!");
        } catch Error(string memory reason) {
            success = false;
            console.log("GOOD: creditUser reverted with:", reason);
        } catch {
            success = false;
            console.log("GOOD: creditUser reverted (no reason)");
        }
        
        vm.stopPrank();
        
        // If this assertion fails, we found a CRITICAL vulnerability
        assertFalse(success, "CRITICAL: creditUser should not be callable by non-market");
    }
    
    /**
     * @notice Test if debitUser can be called by non-market addresses
     */
    function test_DebitUser_AccessControl() public {
        console.log("=== TEST: MarginAccount debitUser Access Control ===");
        console.log("");
        
        address token = address(0x1);
        uint256 amount = 100 ether;
        
        vm.startPrank(attacker);
        
        console.log("Attacker attempting to debit victim's balance...");
        
        bool success;
        try marginAccount.debitUser(victim, token, amount) {
            success = true;
            console.log("!!! CRITICAL: debitUser succeeded without authorization !!!");
        } catch {
            success = false;
            console.log("GOOD: debitUser reverted");
        }
        
        vm.stopPrank();
        
        assertFalse(success, "CRITICAL: debitUser should not be callable by non-market");
    }
    
    /**
     * @notice Test if updateMarkets can be called by non-router addresses
     */
    function test_UpdateMarkets_AccessControl() public {
        console.log("=== TEST: MarginAccount updateMarkets Access Control ===");
        console.log("");
        
        // Attacker tries to register themselves as a market
        vm.startPrank(attacker);
        
        console.log("Attacker attempting to register self as market...");
        
        bool success;
        try marginAccount.updateMarkets(attacker) {
            success = true;
            console.log("!!! CRITICAL: updateMarkets succeeded !!!");
            console.log("Attacker is now registered as market!");
            
            // Now attacker could credit themselves
            console.log("Attempting to credit self after becoming market...");
            try marginAccount.creditUser(attacker, address(0x1), 1000000 ether, false) {
                console.log("!!! DOUBLE CRITICAL: Credit succeeded after market registration !!!");
            } catch {
                console.log("Credit still failed after market registration");
            }
        } catch {
            success = false;
            console.log("GOOD: updateMarkets reverted");
        }
        
        vm.stopPrank();
        
        assertFalse(success, "CRITICAL: updateMarkets should require authorization");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 2: ROUTER ARRAY LENGTH VALIDATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test anyToAnySwap with mismatched array lengths
     */
    function test_AnyToAnySwap_ArrayMismatch() public {
        console.log("=== TEST: Router anyToAnySwap Array Mismatch ===");
        console.log("");
        
        // Create mismatched arrays
        address[] memory markets = new address[](3);
        markets[0] = address(0x1);
        markets[1] = address(0x2);
        markets[2] = address(0x3);
        
        bool[] memory isBuy = new bool[](2); // MISMATCHED!
        isBuy[0] = true;
        isBuy[1] = false;
        
        bool[] memory nativeSend = new bool[](1); // MISMATCHED!
        nativeSend[0] = false;
        
        vm.startPrank(attacker);
        vm.deal(attacker, 10 ether);
        
        console.log("Calling anyToAnySwap with:");
        console.log("  markets.length:", markets.length);
        console.log("  isBuy.length:", isBuy.length);
        console.log("  nativeSend.length:", nativeSend.length);
        
        bool success;
        try router.anyToAnySwap{value: 1 ether}(
            markets,
            isBuy,
            nativeSend,
            address(0),
            address(0),
            1 ether,
            0
        ) returns (uint256 out) {
            success = true;
            console.log("!!! WARNING: Swap succeeded with mismatched arrays !!!");
            console.log("Output:", out);
        } catch Error(string memory reason) {
            success = false;
            console.log("GOOD: Reverted with:", reason);
        } catch {
            success = false;
            console.log("GOOD: Reverted (array validation or other check)");
        }
        
        vm.stopPrank();
        
        // We expect this to revert
        assertFalse(success, "Should validate array lengths");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 3: FLIP ORDER PRICE BOUNDS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test flip order with extreme flipped price
     */
    function test_FlipOrder_ExtremePriceBounds() public {
        console.log("=== TEST: OrderBook Flip Order Price Bounds ===");
        console.log("");
        
        vm.startPrank(attacker);
        
        // Try to place flip order with extreme price difference
        uint32 price = 1000; // Buy at 1000
        uint32 flippedPrice = 1; // Sell at 1 (extreme!)
        uint96 size = 1e18;
        
        console.log("Placing flip buy order:");
        console.log("  price:", price);
        console.log("  flippedPrice:", flippedPrice);
        console.log("  Ratio:", price / flippedPrice, ":1");
        
        bool success;
        try orderBook.addFlipBuyOrder(price, flippedPrice, size, false) {
            success = true;
            console.log("!!! WARNING: Flip order with extreme price accepted !!!");
        } catch Error(string memory reason) {
            success = false;
            console.log("GOOD: Reverted with:", reason);
        } catch {
            success = false;
            console.log("GOOD: Reverted (price validation)");
        }
        
        vm.stopPrank();
        
        // Document finding
        if (success) {
            console.log("");
            console.log("FINDING: Extreme flip prices may be exploitable");
            console.log("  Need to check if this creates arbitrage opportunity");
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 4: CREDITUSERSENCODED FUZZING
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Fuzz creditUsersEncoded with various malformed inputs
     */
    function testFuzz_CreditUsersEncoded(bytes calldata data) public {
        // Skip very long inputs to save gas
        vm.assume(data.length < 1000);
        
        vm.startPrank(attacker);
        
        bool success;
        try marginAccount.creditUsersEncoded(data) {
            success = true;
        } catch {
            success = false;
        }
        
        vm.stopPrank();
        
        // If it succeeded, that's suspicious (should be access controlled)
        assertFalse(success, "creditUsersEncoded should be access controlled");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 5: CHECK CONTRACT OWNERSHIP
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Query contract owners to understand access control structure
     */
    function test_CheckOwnership() public view {
        console.log("=== Checking Contract Ownership ===");
        console.log("");
        
        try marginAccount.owner() returns (address owner) {
            console.log("MarginAccount owner:", owner);
        } catch {
            console.log("MarginAccount: owner() not available or reverted");
        }
        
        try router.owner() returns (address owner) {
            console.log("Router owner:", owner);
        } catch {
            console.log("Router: owner() not available or reverted");
        }
        
        try orderBook.owner() returns (address owner) {
            console.log("OrderBook owner:", owner);
        } catch {
            console.log("OrderBook: owner() not available or reverted");
        }
    }
}

/**
 * @title KuruExploitTest
 * @notice Specific exploit scenario tests
 */
contract KuruExploitTest is Test {
    // Will be populated with actual exploit scenarios
    // once access control issues are confirmed
    
    function test_Placeholder() public pure {
        // Placeholder for exploit tests
        assertTrue(true);
    }
}
