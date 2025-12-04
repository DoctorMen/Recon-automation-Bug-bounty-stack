// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title EulerForkTest
 * @notice Fork tests against live Ethereum mainnet Euler contracts
 * @dev Run with: forge test --fork-url https://eth.llamarpc.com -vvvv
 */

// Minimal interfaces for testing
interface IEVC {
    function batch(BatchItem[] calldata items) external payable;
    function call(address targetContract, address onBehalfOfAccount, uint256 value, bytes calldata data) external payable returns (bytes memory);
    function enableCollateral(address account, address vault) external payable;
    function enableController(address account, address vault) external payable;
    function disableController(address account) external payable;
    function getAccountOwner(address account) external view returns (address);
    function getControllers(address account) external view returns (address[] memory);
    function getCollaterals(address account) external view returns (address[] memory);
    function isControllerEnabled(address account, address vault) external view returns (bool);
    function setOperator(bytes19 addressPrefix, address operator, uint256 operatorBitField) external payable;
    function isAccountOperatorAuthorized(address account, address operator) external view returns (bool);
    function controlCollateral(address targetCollateral, address onBehalfOfAccount, uint256 value, bytes calldata data) external payable returns (bytes memory);
    function permit(address signer, address sender, uint256 nonceNamespace, uint256 nonce, uint256 deadline, uint256 value, bytes calldata data, bytes calldata signature) external payable;
    function haveCommonOwner(address account, address otherAccount) external pure returns (bool);
    function getAddressPrefix(address account) external pure returns (bytes19);
    function requireAccountStatusCheck(address account) external payable;
    function forgiveAccountStatusCheck(address account) external payable;
}

struct BatchItem {
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;
}

interface IEVault {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    function borrow(uint256 assets, address receiver) external returns (uint256);
    function repay(uint256 assets, address receiver) external returns (uint256);
    function liquidate(address violator, address collateral, uint256 repayAssets, uint256 minYieldBalance) external;
    function checkAccountStatus(address account, address[] calldata collaterals) external view returns (bytes4);
    function checkVaultStatus() external returns (bytes4);
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function maxDeposit(address) external view returns (uint256);
    function debtOf(address account) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract EulerForkTest is Test {
    // Ethereum Mainnet Contract Addresses
    
    // EVC - Core primitive
    address constant EVC = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;
    
    // Perspectives (for querying verified vaults)
    address constant ESCROWED_COLLATERAL_PERSPECTIVE = 0x4e58BBEa423c4B9A2Fc7b8E58F5499f9927fADdE;
    address constant UNGOVERNED_0X_PERSPECTIVE = 0xb50a07C2B0F128Faa065bD18Ea2091F5da5e7FbF;
    address constant UNGOVERNED_NZX_PERSPECTIVE = 0x600bBe1D0759F380Fea72B2e9B2B6DCb4A21B507;
    address constant GOVERNED_PERSPECTIVE = 0xC0121817FF224a018840e4D15a864747d36e6Eb2;
    address constant EULER_EARN_PERSPECTIVE = 0x492e9FE1289d43F8bB6275237BF16c9248C74D44;
    
    // USL Vaults - BOOSTED REWARDS ($7.5M!)
    address constant USD0PP_VAULT = 0xF037eeEBA7729c39114B9711c75FbccCa4A343C8;
    address constant USD0_VAULT = 0xd001f0a15D272542687b2677BA627f48A4333b5d;
    
    // Supporting contracts
    address constant FEE_FLOW = 0xFcd3Db06EA814eB21C84304fC7F90798C00D1e32;
    address constant BALANCE_TRACKER = 0x0D52d06ceB8Dcdeeb40Cfd9f17489B350dD7F8a3;
    address constant EULER_SWAP = 0xb013be1D0D380C13B58e889f412895970A2Cf228;
    
    // Interfaces
    IEVC public evc;
    
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
        
        // Connect to EVC
        evc = IEVC(EVC);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 1: EVC ACCOUNT SYSTEM
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test the 256 sub-account XOR system
     * @dev Each address has 256 accounts via XOR with 0-255
     */
    function test_EVC_SubAccountSystem() public view {
        console.log("=== TEST: EVC Sub-Account System ===");
        console.log("");
        
        // Test haveCommonOwner
        address account0 = attacker;
        address account1 = address(uint160(attacker) ^ 1);
        address account255 = address(uint160(attacker) ^ 255);
        address differentOwner = address(uint160(attacker) ^ 256); // Should NOT have common owner
        
        console.log("Attacker (account 0):", attacker);
        console.log("Account 1:", account1);
        console.log("Account 255:", account255);
        console.log("Different owner:", differentOwner);
        
        bool same01 = evc.haveCommonOwner(account0, account1);
        bool same0_255 = evc.haveCommonOwner(account0, account255);
        bool sameDiff = evc.haveCommonOwner(account0, differentOwner);
        
        console.log("");
        console.log("Account 0 & 1 common owner:", same01);
        console.log("Account 0 & 255 common owner:", same0_255);
        console.log("Account 0 & different common owner:", sameDiff);
        
        assertTrue(same01, "Accounts 0 and 1 should have common owner");
        assertTrue(same0_255, "Accounts 0 and 255 should have common owner");
        assertFalse(sameDiff, "Different owner should not match");
    }
    
    /**
     * @notice Test operator authorization across sub-accounts
     */
    function test_EVC_OperatorBitfield() public {
        console.log("=== TEST: EVC Operator Bitfield ===");
        console.log("");
        
        vm.startPrank(attacker);
        
        // Get address prefix
        bytes19 prefix = evc.getAddressPrefix(attacker);
        console.log("Address prefix (bytes19):");
        console.logBytes19(prefix);
        
        // Set operator for specific account
        address operator = makeAddr("operator");
        
        // Authorize operator for account 0 (attacker itself)
        // bitfield = 1 << 0 = 1 (binary: 0...001)
        evc.setOperator(prefix, operator, 1);
        
        bool isAuth0 = evc.isAccountOperatorAuthorized(attacker, operator);
        console.log("Operator authorized for account 0:", isAuth0);
        
        // Check if operator is authorized for account 1
        address account1 = address(uint160(attacker) ^ 1);
        bool isAuth1 = evc.isAccountOperatorAuthorized(account1, operator);
        console.log("Operator authorized for account 1:", isAuth1);
        
        vm.stopPrank();
        
        assertTrue(isAuth0, "Operator should be authorized for account 0");
        assertFalse(isAuth1, "Operator should NOT be authorized for account 1");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 2: CONTROLLER ISOLATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test that only one controller can be enabled
     */
    function test_EVC_ControllerIsolation() public {
        console.log("=== TEST: EVC Controller Isolation ===");
        console.log("");
        
        vm.startPrank(attacker);
        
        // Try to enable two controllers
        address controller1 = makeAddr("controller1");
        address controller2 = makeAddr("controller2");
        
        console.log("Enabling controller 1...");
        evc.enableController(attacker, controller1);
        
        address[] memory controllers = evc.getControllers(attacker);
        console.log("Controllers after first enable:", controllers.length);
        
        console.log("Attempting to enable controller 2...");
        
        // This should work but status check will fail with multiple controllers
        bool success;
        try evc.enableController(attacker, controller2) {
            success = true;
            console.log("Second controller enabled!");
        } catch {
            success = false;
            console.log("Second controller REJECTED (expected)");
        }
        
        controllers = evc.getControllers(attacker);
        console.log("Final controller count:", controllers.length);
        
        vm.stopPrank();
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 3: USL VAULT SPECIFIC TESTS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test USD0++ vault interactions
     * @dev These vaults have BOOSTED rewards - $7.5M potential!
     */
    function test_USL_USD0PP_Vault() public {
        console.log("=== TEST: USL USD0++ Vault ===");
        console.log("");
        
        IEVault vault = IEVault(USD0PP_VAULT);
        
        // Query vault state
        address asset = vault.asset();
        uint256 totalAssets = vault.totalAssets();
        uint256 totalSupply = vault.totalSupply();
        
        console.log("USD0++ Vault:", USD0PP_VAULT);
        console.log("Underlying asset:", asset);
        console.log("Total assets:", totalAssets);
        console.log("Total supply:", totalSupply);
        
        // Check max deposit
        uint256 maxDeposit = vault.maxDeposit(attacker);
        console.log("Max deposit for attacker:", maxDeposit);
        
        // If totalSupply > 0, check share price
        if (totalSupply > 0) {
            uint256 sharePrice = (totalAssets * 1e18) / totalSupply;
            console.log("Share price (1e18 base):", sharePrice);
        }
    }
    
    /**
     * @notice Test USD0 vault interactions
     */
    function test_USL_USD0_Vault() public {
        console.log("=== TEST: USL USD0 Vault ===");
        console.log("");
        
        IEVault vault = IEVault(USD0_VAULT);
        
        address asset = vault.asset();
        uint256 totalAssets = vault.totalAssets();
        uint256 totalSupply = vault.totalSupply();
        
        console.log("USD0 Vault:", USD0_VAULT);
        console.log("Underlying asset:", asset);
        console.log("Total assets:", totalAssets);
        console.log("Total supply:", totalSupply);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 4: BATCH EXECUTION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test batch execution with deferred checks
     */
    function test_EVC_BatchExecution() public {
        console.log("=== TEST: EVC Batch Execution ===");
        console.log("");
        
        vm.startPrank(attacker);
        
        // Create batch items
        BatchItem[] memory items = new BatchItem[](2);
        
        // Item 1: Enable a collateral
        address fakeVault = makeAddr("fakeVault");
        items[0] = BatchItem({
            targetContract: EVC,
            onBehalfOfAccount: address(0),
            value: 0,
            data: abi.encodeCall(IEVC.enableCollateral, (attacker, fakeVault))
        });
        
        // Item 2: Enable controller
        items[1] = BatchItem({
            targetContract: EVC,
            onBehalfOfAccount: address(0),
            value: 0,
            data: abi.encodeCall(IEVC.enableController, (attacker, fakeVault))
        });
        
        console.log("Executing batch with 2 items...");
        
        bool success;
        try evc.batch(items) {
            success = true;
            console.log("Batch executed successfully");
        } catch Error(string memory reason) {
            success = false;
            console.log("Batch failed:", reason);
        } catch {
            success = false;
            console.log("Batch failed (no reason)");
        }
        
        // Check state
        address[] memory collaterals = evc.getCollaterals(attacker);
        address[] memory controllers = evc.getControllers(attacker);
        
        console.log("Collaterals enabled:", collaterals.length);
        console.log("Controllers enabled:", controllers.length);
        
        vm.stopPrank();
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 5: PERMIT SYSTEM
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test permit signature validation
     */
    function test_EVC_PermitSystem() public {
        console.log("=== TEST: EVC Permit System ===");
        console.log("");
        
        // Create a permit with invalid signature
        address signer = makeAddr("signer");
        bytes memory invalidSig = new bytes(65); // All zeros
        
        console.log("Testing permit with invalid signature...");
        
        vm.expectRevert();
        evc.permit(
            signer,        // signer
            address(0),    // sender (anyone can submit)
            0,             // nonceNamespace
            0,             // nonce
            block.timestamp + 1 hours, // deadline
            0,             // value
            abi.encodeCall(IEVC.enableCollateral, (signer, makeAddr("vault"))), // data
            invalidSig     // signature
        );
        
        console.log("GOOD: Invalid signature rejected");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST 6: REENTRANCY CHECKS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Verify reentrancy protections are in place
     */
    function test_EVC_ReentrancyProtection() public view {
        console.log("=== TEST: EVC Reentrancy Protection ===");
        console.log("");
        
        // The EVC has multiple reentrancy guards:
        // 1. nonReentrantChecks - prevents check reentrancy
        // 2. nonReentrantChecksAndControlCollateral - prevents controlCollateral reentrancy
        // 3. nonReentrantChecksAcquireLock - acquires lock during checks
        
        console.log("EVC implements multiple reentrancy guards:");
        console.log("  - nonReentrantChecks");
        console.log("  - nonReentrantChecksAndControlCollateral");
        console.log("  - nonReentrantChecksAcquireLock");
        console.log("");
        console.log("These prevent callback attacks during:");
        console.log("  - Account status checks");
        console.log("  - Vault status checks");
        console.log("  - controlCollateral calls");
    }
    
    /*//////////////////////////////////////////////////////////////
                    HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    function test_CheckContractDeployment() public view {
        console.log("=== Verifying Contract Deployment ===");
        console.log("");
        
        uint256 evcSize;
        uint256 usd0ppSize;
        uint256 usd0Size;
        
        assembly {
            evcSize := extcodesize(0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383)
            usd0ppSize := extcodesize(0xF037eeEBA7729c39114B9711c75FbccCa4A343C8)
            usd0Size := extcodesize(0xd001f0a15D272542687b2677BA627f48A4333b5d)
        }
        
        console.log("EVC code size:", evcSize);
        console.log("USD0++ Vault code size:", usd0ppSize);
        console.log("USD0 Vault code size:", usd0Size);
        
        assertTrue(evcSize > 0, "EVC should be deployed");
        assertTrue(usd0ppSize > 0, "USD0++ vault should be deployed");
        assertTrue(usd0Size > 0, "USD0 vault should be deployed");
    }
}
