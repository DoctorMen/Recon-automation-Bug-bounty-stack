// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IMarginAccount
 * @notice Interface for Kuru MarginAccount contract
 * @dev Critical functions for access control testing
 */
interface IMarginAccount {
    // User Operations
    function deposit(address _user, address _token, uint256 _amount) external payable;
    function withdraw(uint256 _amount, address _token) external;
    function batchWithdrawMaxTokens(address[] calldata _tokens) external;
    function getBalance(address _user, address _token) external view returns (uint256);
    
    // Market Operations - CRITICAL: Check access control
    function creditUser(address _user, address _token, uint256 _amount, bool _useMargin) external;
    function debitUser(address _user, address _token, uint256 _amount) external;
    function creditUsersEncoded(bytes calldata _encodedData) external;
    function creditFee(address _assetA, uint256 _feeA, address _assetB, uint256 _feeB) external;
    
    // Router Operations
    function updateMarkets(address _marketAddress) external;
    
    // Admin
    function toggleProtocolState(bool _state) external;
    function setFeeCollector(address _feeCollector) external;
    function owner() external view returns (address);
    
    // Events
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdrawal(address indexed user, address indexed token, uint256 amount);
}

/**
 * @title IRouter
 * @notice Interface for Kuru Router contract
 */
interface IRouter {
    function anyToAnySwap(
        address[] calldata _marketAddresses,
        bool[] calldata _isBuy,
        bool[] calldata _nativeSend,
        address _debitToken,
        address _creditToken,
        uint256 _amount,
        uint256 _minAmountOut
    ) external payable returns (uint256 _amountOut);
    
    function deployProxy(
        uint8 _type,
        address _baseAssetAddress,
        address _quoteAssetAddress,
        uint96 _sizePrecision,
        uint32 _pricePrecision,
        uint32 _tickSize,
        uint96 _minSize,
        uint96 _maxSize,
        uint256 _takerFeeBps,
        uint256 _makerFeeBps,
        uint96 _kuruAmmSpread
    ) external returns (address proxy);
    
    function computeAddress(
        address _baseAssetAddress,
        address _quoteAssetAddress,
        uint96 _sizePrecision,
        uint32 _pricePrecision,
        uint32 _tickSize,
        uint96 _minSize,
        uint96 _maxSize,
        uint256 _takerFeeBps,
        uint256 _makerFeeBps,
        uint96 _kuruAmmSpread,
        address oldImplementation,
        bool old
    ) external view returns (address proxy);
    
    function owner() external view returns (address);
    function marginAccount() external view returns (address);
}

/**
 * @title IOrderBook
 * @notice Interface for Kuru OrderBook contract
 */
interface IOrderBook {
    // Order placement
    function addBuyOrder(uint32 _price, uint96 _size, bool _postOnly) external;
    function addSellOrder(uint32 _price, uint96 _size, bool _postOnly) external;
    
    // Flip orders - CRITICAL: Check price bounds
    function addFlipBuyOrder(uint32 _price, uint32 _flippedPrice, uint96 _size, bool _provisionOrRevert) external;
    function addFlipSellOrder(uint32 _price, uint32 _flippedPrice, uint96 _size, bool _provisionOrRevert) external;
    
    // Market orders
    function placeAndExecuteMarketBuy(uint96 _quoteSize, uint256 _minAmountOut, bool _isMargin, bool _isFillOrKill) external payable;
    function placeAndExecuteMarketSell(uint96 _size, uint256 _minAmountOut, bool _isMargin, bool _isFillOrKill) external payable;
    
    // Cancellation
    function batchCancelOrders(uint40[] calldata _orderIds) external;
    function batchCancelFlipOrders(uint40[] calldata _orderIds) external;
    
    // Liquidity
    function addPairedLiquidity(uint32 _bidPrice, uint32 _askPrice, uint96 _bidSize, uint96 _askSize) external;
    function batchProvisionLiquidity(uint32[] calldata prices, uint32[] calldata flipPrices, uint96[] calldata sizes, bool[] calldata isBuy, bool _provisionOrRevert) external;
    
    // View
    function bestBidAsk() external view returns (uint32, uint32);
    function getMarketParams() external view returns (bytes memory);
    function owner() external view returns (address);
}

/**
 * @title IVault
 * @notice Interface for Kuru Active Vault
 */
interface IVault {
    function deposit(uint256 baseDeposit, uint256 quoteDeposit, uint256 minQuoteConsumed, address receiver) external payable returns (uint256);
    function withdraw(uint256 _shares, address _receiver, address _owner) external returns (uint256, uint256);
    function mint(uint256 shares, address receiver) external payable returns (uint256, uint256);
    
    function previewDeposit(uint256 asset1, uint256 asset2) external view returns (uint256);
    function previewMint(uint256 shares) external view returns (uint256, uint256);
    function previewWithdraw(uint256 shares) external view returns (uint256, uint256);
    
    function totalAssets() external view returns (uint256, uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
    
    function owner() external view returns (address);
}

/**
 * @title IERC20
 * @notice Standard ERC20 interface
 */
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
