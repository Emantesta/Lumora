// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IPriceOracle, ICrossChainModule, IAMMPool, IGovernanceModule, IGovernanceToken, ICrossChainRetryOracle} from "./Interfaces.sol";


/// @title OrderBook - Advanced DEX order book with perpetual futures, AMM, governance, and cross-chain functionality
/// @notice Manages limit, market, stop-loss, and perpetual orders with concentrated liquidity and gasless trading
/// @dev Uses UUPS proxy, integrates with PriceOracle, GovernanceModule, AMMPool, GovernanceToken, and CrossChainModule
contract OrderBook is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable
{
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;
    using ECDSAUpgradeable for bytes32;

    // Storage and rest of the contract remains unchanged
    uint256[] public bidHeap; // Max-heap for bids
    uint256[] public askHeap; // Min-heap for asks
    mapping(uint256 => Order) public orders; // Order ID to Order
    mapping(address => uint256[]) public userOrders; // User to order IDs
    mapping(uint256 => uint256) public orderHeapIndex; // Order ID to heap index
    mapping(uint256 => bool) public orderExists; // Order existence
    mapping(address => uint256[]) public stopLossOrders; // User to stop-loss order IDs
    address[] private userList;
    uint256 public nextOrderId; // Global order ID counter
    IGovernanceModule public governanceModule;
    IAMMPool public ammPool;
    IGovernanceToken public governanceToken;
    ICrossChainModule public crossChainModule;
    ICrossChainRetryOracle public retryOracle;
    IPriceOracle public priceOracle;
    IERC20Upgradeable public usdc; // USDC contract for perpetuals collateral
    uint256 public constant MAX_ORDERS_PER_USER = 100;
    uint256 public constant MAX_MATCHES_PER_TX = 10;
    FeeTier[2] public feeTiers; // Fixed-size array for 2 fee tiers
    mapping(address => uint8) public userTypes; // 0 = retail, 1 = institutional
    mapping(uint16 => mapping(uint256 => bool)) public crossChainOrders; // chainId => orderId => status
    mapping(uint16 => mapping(uint256 => bool)) public crossChainMatches; // chainId => matchId => status
    bool public emergencyWithdrawalEnabled;
    uint256 public nextMatchId; // Match ID counter
    mapping(address => uint256) public nonces; // Nonce for signed orders
    Snapshot[] public snapshots; // Order book snapshots
    uint256 public lpRewardPool; // LP reward pool balance
    uint256 public governanceRewardPool; // Governance reward pool balance
    mapping(address => uint256) public stakedTokens; // Staked governance tokens
    uint256 public totalStaked; // Total staked tokens
    mapping(uint256 => Proposal) public proposals; // Governance proposals
    uint256 public nextProposalId; // Proposal counter
    uint256 public constant VOTING_DURATION = 3 days;
    uint256 public volatilityThreshold; // Volatility threshold
    uint256 public liquidityRangeMultiplier; // Liquidity range multiplier
    mapping(address => TraderReward) public traderRewards; // Trader rewards
    uint256 public rewardRateBps; // Reward rate per fee
    uint256 public minFeesForReward; // Minimum fees for reward
    uint256 public rewardClaimCooldown; // Reward claim cooldown
    uint64 public oracleStalenessThreshold; // Oracle price staleness threshold
    // Perpetual-specific storage
    uint256 public constant FUNDING_INTERVAL = 1 hours; // Funding rate applied hourly
    uint256 public constant MAX_LEVERAGE = 50; // Max 50x leverage
    mapping(address => uint256) public userEquity; // Tracks user collateral (USDC)
    mapping(address => int256) public userFundingBalance; // Net funding payments per user
    uint256 public fundingRateCapBps = 10; // Max 0.1% per hour
    uint256 public liquidationFeeBps = 50; // 0.5% liquidation fee

    // Structs and Enums (unchanged)
    struct Order {
        address user;
        address tokenA;
        address tokenB;
        uint96 price;
        uint96 amount;
        uint96 triggerPrice;
        uint64 timestamp;
        uint64 expiryTimestamp;
        uint256 orderId;
        bool isBuy;
        bool isMarket;
        bool isStopLoss;
        bool locked;
        bool useConcentratedLiquidity;
        bool isPerpetual;
        uint256 leverage;
        uint256 initialMargin;
        uint256 maintenanceMargin;
        uint256 lastFundingTimestamp;
        int256 cumulativeFunding;
    }

    struct FeeTier {
        uint256 orderSizeThreshold;
        uint256 feeRateBps;
    }

    struct Snapshot {
        uint64 timestamp;
        uint256[] bidOrderIds;
        uint256[] askOrderIds;
    }

    struct SignedOrder {
        address user;
        bool isBuy;
        bool isMarket;
        bool isStopLoss;
        uint96 price;
        uint96 triggerPrice;
        uint96 amount;
        uint64 expiryTimestamp;
        address tokenA;
        address tokenB;
        bool useConcentratedLiquidity;
        uint256 nonce;
        bytes signature;
    }

    struct Proposal {
        uint256 proposalId;
        address proposer;
        string description;
        uint256 voteCount;
        uint64 endTime;
        bool executed;
        ProposalType proposalType;
        bytes data;
        mapping(address => bool) hasVoted;
    }

    enum ProposalType {
        ParameterChange,
        Upgrade,
        TreasuryAllocation,
        Other
    }

    struct TraderReward {
        uint256 accumulatedFees;
        uint64 lastClaimTimestamp;
        uint256 unclaimedTokens;
    }

    struct Transfer {
        address user;
        address token;
        uint256 amount;
    }

    // Custom Errors (unchanged)
    error InvalidOrder();
    error InvalidOrderId(uint256 orderId);
    error NotOrderOwner(address user);
    error OrderLocked(uint256 orderId);
    error OrderNotLocked(uint256 orderId);
    error InvalidGovernance(address governance);
    error Unauthorized();
    error InvalidAmount(uint256 amount);
    error InvalidPrice(uint256 price);
    error TooManyOrders(address user);
    error NoMatchableOrders();
    error InvalidTokenPair(address tokenA, address tokenB);
    error InsufficientLiquidity(uint256 amountOut);
    error SlippageExceeded(uint256 amountOut, uint256 minAmountOut);
    error CrossChainOrderExists(uint16 chainId, uint256 orderId);
    error EmergencyWithdrawalDisabled();
    error InvalidChainId(uint16 chainId);
    error OrderExpired(uint256 orderId);
    error InvalidFeeTier(uint256 threshold, uint256 feeRate);
    error InvalidUserType(uint8 userType);
    error CrossChainMatchExists(uint16 chainId, uint256 matchId);
    error InvalidExpiry(uint256 expiryTimestamp);
    error InvalidSignature();
    error InvalidNonce(uint256 nonce);
    error NoLiquidityProviders();
    error InvalidTriggerPrice(uint256 triggerPrice);
    error InvalidProposal(uint256 proposalId);
    error AlreadyVoted(address user);
    error ProposalEnded(uint256 proposalId);
    error InsufficientStake(address user, uint256 balance);
    error InvalidProposalType(uint8 proposalType);
    error InvalidVolatility(uint256 volatility);
    error NoValidPrice();
    error PriceOracleError();
    error InsufficientFeesForReward(address user, uint256 fees);
    error RewardCooldownActive(address user, uint256 nextClaimTime);
    error InvalidAddress(address addr, string message);
    error InvalidOperation(string message);
    error PriceOracleStale(uint256 timestamp);
    error NotPerpetualOrder(uint256 orderId);
    error FundingNotDue(uint256 orderId);
    error ExcessiveLeverage(uint256 leverage);
    error InsufficientMargin(uint256 margin);
    error MarginTransferFailed();
    error PositionNotLiquidatable(uint256 orderId);

    // Events (unchanged)
    event OrderPlaced(
        address indexed user,
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint256 price,
        uint256 triggerPrice,
        uint256 amount,
        uint256 orderId,
        address tokenA,
        address tokenB,
        uint256 expiryTimestamp,
        bool useConcentratedLiquidity
    );
    event PerpetualOrderPlaced(bytes32 orderId, address indexed user, bool isBuy, uint256 leverage, uint256 margin);
    event FundingRateApplied(address indexed user, bytes32 orderId, int256 fundingAmount);
    event PositionLiquidated(bytes32 orderId, address indexed user, uint256 collateralReturned, uint256 fee);
    event OrderCancelled(address indexed user, uint256 orderId);
    event OrderLockedEvent(uint256 orderId);
    event OrderUnlocked(uint256 orderId);
    event OrdersMatched(
        uint256 bidOrderId,
        uint256 askOrderId,
        uint256 price,
        uint256 amount,
        uint256 fee
    );
    event GovernanceModuleSet(address indexed governanceModule);
    event AMMPoolSet(address indexed ammPool);
    event GovernanceTokenSet(address indexed governanceToken);
    event CrossChainModuleSet(address indexed crossChainModule);
    event RetryOracleSet(address indexed retryOracle);
    event PriceOracleSet(address indexed priceOracle);
    event USDCSet(address indexed usdc);
    event FeeTiersUpdated(FeeTier[2] feeTiers);
    event UserTypeSet(address indexed user, uint8 userType);
    event CrossChainOrderPlaced(
        uint256 orderId,
        uint16 dstChainId,
        address user,
        bool isBuy,
        uint256 price,
        uint256 amount
    );
    event CrossChainMatchExecuted(
        uint256 matchId,
        uint16 chainId,
        uint256 bidOrderId,
        uint256 askOrderId,
        uint256 amount
    );
    event BatchOrdersCancelled(uint256[] orderIds);
    event EmergencyWithdrawalEnabled(bool enabled);
    event EmergencyWithdrawal(address indexed user, uint256 amountA, uint256 amountB);
    event ExpiredOrdersCleaned(uint256[] orderIds);
    event LPRewardsDistributed(uint256 amount);
    event GovernanceRewardsDistributed(uint256 amount);
    event SnapshotTaken(uint256 snapshotId, uint256 timestamp);
    event OffChainOrderSubmitted(uint256 orderId);
    event StopLossTriggered(uint256 orderId, uint256 triggerPrice);
    event TokensStaked(address indexed user, uint256 amount);
    event TokensUnstaked(address indexed user, uint256 amount);
    event ProposalCreated(uint256 proposalId, address indexed proposer, string description, ProposalType proposalType);
    event Voted(address indexed voter, uint256 proposalId, uint256 weight);
    event ProposalExecuted(uint256 proposalId);
    event LiquidityRangeSet(uint256 minPrice, uint256 maxPrice);
    event VolatilityThresholdSet(uint256 threshold);
    event LiquidityRangeMultiplierSet(uint256 multiplier);
    event TraderRewardsClaimed(address indexed user, uint256 amount);
    event RewardParametersSet(uint256 rewardRateBps, uint256 minFeesForReward, uint256 rewardClaimCooldown);
    event OracleStalenessThresholdSet(uint256 threshold);
    event FundingParametersSet(uint256 fundingRateCapBps, uint256 liquidationFeeBps, uint256 maxLeverage);

    /// @dev EIP-712 typehash for signed orders
    bytes32 private constant ORDER_TYPEHASH = keccak256(
        "Order(address user,bool isBuy,bool isMarket,bool isStopLoss,uint96 price,uint96 triggerPrice,uint96 amount,uint64 expiryTimestamp,address tokenA,address tokenB,bool useConcentratedLiquidity,uint256 nonce)"
    );

    /// @dev Disable initializer on implementation
    constructor() {
        _disableInitializers();
    }


    /// @notice Initializes the contract
    function initialize(
        address _governanceModule,
        address _ammPool,
        address _governanceToken,
        address _crossChainModule,
        address _retryOracle,
        address _priceOracle,
        address _usdc
    ) external initializer {
        if (_governanceModule == address(0)) revert InvalidGovernance(_governanceModule);
        if (_ammPool == address(0)) revert InvalidAddress(_ammPool, "Invalid AMMPool address");
        if (_governanceToken == address(0)) revert InvalidAddress(_governanceToken, "Invalid GovernanceToken address");
        if (_crossChainModule == address(0)) revert InvalidAddress(_crossChainModule, "Invalid CrossChainModule address");
        if (_retryOracle == address(0)) revert InvalidAddress(_retryOracle, "Invalid RetryOracle address");
        if (_priceOracle == address(0)) revert InvalidAddress(_priceOracle, "Invalid PriceOracle address");
        if (_usdc == address(0)) revert InvalidAddress(_usdc, "Invalid USDC address");

        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __EIP712_init("OrderBook", "1");

        governanceModule = IGovernanceModule(_governanceModule);
        ammPool = IAMMPool(_ammPool);
        governanceToken = IGovernanceToken(_governanceToken);
        crossChainModule = ICrossChainModule(_crossChainModule);
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        priceOracle = IPriceOracle(_priceOracle);
        usdc = IERC20Upgradeable(_usdc);

        nextOrderId = 1;
        nextMatchId = 1;
        nextProposalId = 1;
        volatilityThreshold = 1e16; // 1% volatility
        liquidityRangeMultiplier = 2;
        rewardRateBps = 100; // 1% of fees
        minFeesForReward = 1e16; // Minimum fees
        rewardClaimCooldown = 1 days;
        oracleStalenessThreshold = 1 hours;

        feeTiers[0] = FeeTier({orderSizeThreshold: 0, feeRateBps: 30});
        feeTiers[1] = FeeTier({orderSizeThreshold: 1e18, feeRateBps: 10});

        emit GovernanceModuleSet(_governanceModule);
        emit AMMPoolSet(_ammPool);
        emit GovernanceTokenSet(_governanceToken);
        emit CrossChainModuleSet(_crossChainModule);
        emit RetryOracleSet(_retryOracle);
        emit PriceOracleSet(_priceOracle);
        emit USDCSet(_usdc);
        emit FeeTiersUpdated(feeTiers);
        emit VolatilityThresholdSet(volatilityThreshold);
        emit LiquidityRangeMultiplierSet(liquidityRangeMultiplier);
        emit RewardParametersSet(rewardRateBps, minFeesForReward, rewardClaimCooldown);
        emit OracleStalenessThresholdSet(oracleStalenessThreshold);
        emit FundingParametersSet(fundingRateCapBps, liquidationFeeBps, MAX_LEVERAGE);
    }

    /// @dev Authorizes upgrades via governance
    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(governanceModule)) revert Unauthorized();
    }

    /// @notice Places a limit, market, or stop-loss order
    function placeOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp,
        bool useConcentratedLiquidity
    ) external whenNotPaused nonReentrant returns (uint256 orderId) {
        orderId = _placeOrder(
            msg.sender,
            isBuy,
            isMarket,
            isStopLoss,
            price,
            triggerPrice,
            amount,
            tokenA,
            tokenB,
            expiryTimestamp,
            useConcentratedLiquidity,
            false,
            0,
            0
        );
        if (isMarket) {
            _matchOrders(0, MAX_MATCHES_PER_TX);
        }
        return orderId;
    }

    /// @notice Places a perpetual order
    function placePerpetualOrder(
        address tokenA,
        address tokenB,
        uint256 amount,
        bool isBuy,
        uint256 leverage,
        uint256 margin
    ) external whenNotPaused nonReentrant returns (uint256 orderId) {
        if (leverage > MAX_LEVERAGE) revert ExcessiveLeverage(leverage);
        if (margin < amount.div(leverage)) revert InsufficientMargin(margin);
        if (!usdc.transferFrom(msg.sender, address(this), margin)) revert MarginTransferFailed();

        orderId = nextOrderId++;
        Order storage order = orders[orderId];
        order.user = msg.sender;
        order.tokenA = tokenA;
        order.tokenB = tokenB;
        order.amount = uint96(amount);
        order.isBuy = isBuy;
        order.isPerpetual = true;
        order.leverage = leverage;
        order.initialMargin = margin;
        order.maintenanceMargin = margin.mul(80).div(100); // 80% of initial margin
        order.timestamp = uint64(block.timestamp);
        order.lastFundingTimestamp = block.timestamp;

        userOrders[msg.sender].push(orderId);
        userEquity[msg.sender] = userEquity[msg.sender].add(margin);
        orderExists[orderId] = true;

        emit PerpetualOrderPlaced(bytes32(orderId), msg.sender, isBuy, leverage, margin);
        _matchPerpetualOrder(orderId);
        return orderId;
    }

    /// @notice Places a cross-chain perpetual order
    function placeCrossChainPerpetualOrder(
        address targetChain,
        address tokenA,
        address tokenB,
        uint256 amount,
        bool isBuy,
        uint256 leverage,
        uint256 margin
    ) external whenNotPaused nonReentrant {
        if (leverage > MAX_LEVERAGE) revert ExcessiveLeverage(leverage);
        if (margin < amount.div(leverage)) revert InsufficientMargin(margin);
        if (!usdc.transferFrom(msg.sender, address(this), margin)) revert MarginTransferFailed();

        bytes memory orderData = abi.encode(
            msg.sender,
            tokenA,
            tokenB,
            amount,
            isBuy,
            leverage,
            margin,
            block.timestamp
        );
        crossChainModule.sendCrossChainOrder(targetChain, orderData);
    }

    /// @notice Receives cross-chain perpetual order
    function receiveCrossChainPerpetualOrder(bytes memory orderData) external nonReentrant {
        if (msg.sender != address(crossChainModule)) revert Unauthorized();
        (
            address user,
            address tokenA,
            address tokenB,
            uint256 amount,
            bool isBuy,
            uint256 leverage,
            uint256 margin,
            uint256 timestamp
        ) = abi.decode(orderData, (address, address, address, uint256, bool, uint256, uint256, uint256));

        uint256 orderId = this.placePerpetualOrder(tokenA, tokenB, amount, isBuy, leverage, margin);
        orders[orderId].timestamp = uint64(timestamp); // Preserve original timestamp
    }

    /// @notice Applies funding rate for a perpetual order
    function applyFunding(uint256 orderId) external nonReentrant {
        Order storage order = orders[orderId];
        if (!order.isPerpetual) revert NotPerpetualOrder(orderId);
        if (block.timestamp < order.lastFundingTimestamp + FUNDING_INTERVAL) revert FundingNotDue(orderId);

        uint256 spotPrice = priceOracle.getSpotPrice(order.tokenA, order.tokenB);
        uint256 indexPrice = priceOracle.getIndexPrice(order.tokenA, order.tokenB);

        // Calculate funding rate: (spot - index) / index * interval / 24 hours
        int256 premium = int256(spotPrice) - int256(indexPrice);
        int256 fundingRate = (premium * int256(FUNDING_INTERVAL) * 1e4) / (int256(indexPrice) * 24 hours);
        if (fundingRate > int256(fundingRateCapBps)) fundingRate = int256(fundingRateCapBps);
        if (fundingRate < -int256(fundingRateCapBps)) fundingRate = -int256(fundingRateCapBps);

        // Calculate funding payment: position size * funding rate
        uint256 positionSize = uint256(order.amount) * order.leverage; // Cast uint96 to uint256
        int256 fundingAmount = (int256(positionSize) * fundingRate) / 1e4;
        if (!order.isBuy) fundingAmount = -fundingAmount; // Shorts pay/receive opposite of longs

        // Update order and user balances
        order.cumulativeFunding += fundingAmount;
        userFundingBalance[order.user] += fundingAmount;
        order.lastFundingTimestamp = block.timestamp;

        emit FundingRateApplied(order.user, bytes32(orderId), fundingAmount);
    }

    /// @notice Batch applies funding for multiple orders
    function batchApplyFunding(uint256[] calldata orderIds) external nonReentrant {
        for (uint256 i = 0; i < orderIds.length; i++) {
            this.applyFunding(orderIds[i]);
        }
    }

    /// @notice Liquidates an under-margined position
    function liquidatePosition(uint256 orderId) external nonReentrant {
        Order storage order = orders[orderId];
        if (!order.isPerpetual) revert NotPerpetualOrder(orderId);
        if (!_isUnderMargined(order)) revert PositionNotLiquidatable(orderId);

        uint256 collateral = order.initialMargin;
        uint256 liquidationFee = collateral.mul(liquidationFeeBps).div(1e4);
        uint256 remainingCollateral = collateral.sub(liquidationFee);

        userEquity[order.user] = userEquity[order.user].sub(collateral);
        if (!usdc.transfer(order.user, remainingCollateral)) revert MarginTransferFailed();
        if (!usdc.transfer(ammPool.treasury(), liquidationFee)) revert MarginTransferFailed();

        delete orders[orderId];
        orderExists[orderId] = false;
        _removeUserOrder(order.user, orderId);

        emit PositionLiquidated(bytes32(orderId), order.user, remainingCollateral, liquidationFee);
    }

    /// @notice Places a signed order (gasless)
    function placeOrderWithSignature(SignedOrder calldata signedOrder) external whenNotPaused nonReentrant {
        bytes32 structHash = keccak256(
            abi.encode(
                ORDER_TYPEHASH,
                signedOrder.user,
                signedOrder.isBuy,
                signedOrder.isMarket,
                signedOrder.isStopLoss,
                signedOrder.price,
                signedOrder.triggerPrice,
                signedOrder.amount,
                signedOrder.expiryTimestamp,
                signedOrder.tokenA,
                signedOrder.tokenB,
                signedOrder.useConcentratedLiquidity,
                signedOrder.nonce
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(signedOrder.signature);
        if (signer != signedOrder.user) revert InvalidSignature();
        if (nonces[signedOrder.user] != signedOrder.nonce) revert InvalidNonce(signedOrder.nonce);
        nonces[signedOrder.user]++;

        _placeOrder(
            signedOrder.user,
            signedOrder.isBuy,
            signedOrder.isMarket,
            signedOrder.isStopLoss,
            signedOrder.price,
            signedOrder.triggerPrice,
            signedOrder.amount,
            signedOrder.tokenA,
            signedOrder.tokenB,
            signedOrder.expiryTimestamp,
            signedOrder.useConcentratedLiquidity,
            false,
            0,
            0
        );

        if (signedOrder.isMarket) {
            _matchOrders(0, MAX_MATCHES_PER_TX);
        }
    }

    /// @notice Submits an off-chain order (for layer-2)
    function submitOffChainOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp,
        bool useConcentratedLiquidity
    ) external whenNotPaused nonReentrant {
        _restrictGovernance();
        _placeOrder(
            msg.sender,
            isBuy,
            isMarket,
            isStopLoss,
            price,
            triggerPrice,
            amount,
            tokenA,
            tokenB,
            expiryTimestamp,
            useConcentratedLiquidity,
            false,
            0,
            0
        );
        emit OffChainOrderSubmitted(nextOrderId - 1);
    }

    /// @notice Places a cross-chain order
    function placeOrderCrossChain(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp,
        bool useConcentratedLiquidity,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused nonReentrant {
        if (dstChainId == 0) revert InvalidChainId(dstChainId);
        _validateOrder(isBuy, isMarket, isStopLoss, price, triggerPrice, amount, tokenA, tokenB, expiryTimestamp);

        ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(uint64(dstChainId));
        if (!status.retryRecommended || !status.bridgeOperational) revert InvalidOperation("Retry not recommended");

        uint256 orderId;
        unchecked {
            orderId = nextOrderId++;
        }
        if (crossChainOrders[dstChainId][orderId]) revert CrossChainOrderExists(dstChainId, orderId);

        IERC20Upgradeable collateralToken = IERC20Upgradeable(isBuy ? tokenB : tokenA);
        uint256 collateral = isMarket ? amount : uint256(price) * amount;
        SafeERC20Upgradeable.safeTransferFrom(collateralToken, msg.sender, address(this), collateral);

        bytes memory payload = abi.encode(
            msg.sender,
            isBuy,
            isMarket,
            isStopLoss,
            price,
            triggerPrice,
            amount,
            tokenA,
            tokenB,
            orderId,
            expiryTimestamp,
            useConcentratedLiquidity
        );

        uint16[] memory dstChainIds = new uint16[](1);
        dstChainIds[0] = dstChainId;
        string[] memory axelarChainIds = new string[](1);
        axelarChainIds[0] = ammPool.chainIdToAxelarChain(dstChainId);
        bytes[] memory payloads = new bytes[](1);
        payloads[0] = payload;
        bytes[] memory adapterParamsArray = new bytes[](1);
        adapterParamsArray[0] = adapterParams;
        uint256[] memory retryDelays = new uint256[](1);
        retryDelays[0] = block.timestamp + status.recommendedRetryDelay;

        crossChainModule.batchCrossChainMessages{value: msg.value}(
            dstChainIds,
            axelarChainIds,
            payloads,
            adapterParamsArray,
            retryDelays
        );
        crossChainOrders[dstChainId][orderId] = true;

        emit CrossChainOrderPlaced(orderId, dstChainId, msg.sender, isBuy, price, amount);
    }

    /// @notice Receives cross-chain orders
    function receiveCrossChainOrder(uint16 srcChainId, bytes calldata payload) external nonReentrant {
        if (msg.sender != address(crossChainModule)) revert Unauthorized();
        (
            address user,
            bool isBuy,
            bool isMarket,
            bool isStopLoss,
            uint96 price,
            uint96 triggerPrice,
            uint96 amount,
            address tokenA,
            address tokenB,
            uint256 orderId,
            uint64 expiryTimestamp,
            bool useConcentratedLiquidity
        ) = abi.decode(payload, (address, bool, bool, bool, uint96, uint96, uint96, address, address, uint256, uint64, bool));

        if (orderExists[orderId]) revert InvalidOrderId(orderId);
        if (userOrders[user].length >= MAX_ORDERS_PER_USER) return;
        _validateOrder(isBuy, isMarket, isStopLoss, price, triggerPrice, amount, tokenA, tokenB, expiryTimestamp);

        Order storage order = orders[orderId];
        order.user = user;
        order.isBuy = isBuy;
        order.isMarket = isMarket;
        order.isStopLoss = isStopLoss;
        order.price = price;
        order.triggerPrice = triggerPrice;
        order.amount = amount;
        order.timestamp = uint64(block.timestamp);
        order.expiryTimestamp = expiryTimestamp;
        order.locked = false;
        order.orderId = orderId;
        order.tokenA = tokenA;
        order.tokenB = tokenB;
        order.useConcentratedLiquidity = useConcentratedLiquidity;

        userOrders[user].push(orderId);
        orderExists[orderId] = true;

        if (isStopLoss) {
            stopLossOrders[user].push(orderId);
        } else if (!isMarket) {
            if (isBuy) {
                bidHeap.push(orderId);
                orderHeapIndex[orderId] = bidHeap.length - 1;
                _heapifyUpBids(bidHeap.length - 1);
            } else {
                askHeap.push(orderId);
                orderHeapIndex[orderId] = askHeap.length - 1;
                _heapifyUpAsks(askHeap.length - 1);
            }
        }

        emit OrderPlaced(
            user,
            isBuy,
            isMarket,
            isStopLoss,
            price,
            triggerPrice,
            amount,
            orderId,
            tokenA,
            tokenB,
            expiryTimestamp,
            useConcentratedLiquidity
        );
    }

    /// @notice Cancels a limit or stop-loss order
    function cancelOrder(uint256 orderId) external whenNotPaused nonReentrant {
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        Order storage order = orders[orderId];
        if (order.user != msg.sender) revert NotOrderOwner(msg.sender);
        if (order.locked) revert OrderLocked(orderId);
        if (order.expiryTimestamp != 0 && order.expiryTimestamp <= block.timestamp) revert OrderExpired(orderId);

        if (order.isPerpetual) {
            uint256 collateral = order.initialMargin;
            userEquity[order.user] = userEquity[order.user] - collateral; // Updated: Direct arithmetic
            if (!usdc.transfer(order.user, collateral)) revert MarginTransferFailed();
        } else {
            IERC20Upgradeable collateralToken = IERC20Upgradeable(order.isBuy ? order.tokenB : order.tokenA);
            uint256 collateral = order.isMarket ? uint256(order.amount) : uint256(order.price) * order.amount;
            collateralToken.safeTransfer(order.user, collateral);
        }

        if (order.isStopLoss) {
            _removeStopLossOrder(order.user, orderId);
        }
        _removeOrder(orderId, order.isBuy);

        // Remove user from userList if no orders remain
        if (userOrders[order.user].length == 0 && stopLossOrders[order.user].length == 0) {
            for (uint256 i = 0; i < userList.length; i++) {
                if (userList[i] == order.user) {
                    userList[i] = userList[userList.length - 1];
                    userList.pop();
                    break;
                }
            }
        }

        emit OrderCancelled(msg.sender, orderId);
    }

    /// @notice Matches orders
    function matchOrders(uint256 minAmountOut) external whenNotPaused nonReentrant {
        if (bidHeap.length == 0 && askHeap.length == 0) revert NoMatchableOrders();
        // Prioritize perpetual orders
        for (uint256 i = 0; i < userOrders[msg.sender].length; i++) {
            uint256 orderId = userOrders[msg.sender][i]; // Fixed: Corrected userOrders access
            Order storage order = orders[orderId];
            if (order.isPerpetual) {
                _matchPerpetualOrder(orderId);
            }
        }
        _checkStopLossOrders();
        _matchOrders(minAmountOut, MAX_MATCHES_PER_TX); // Fixed: Corrected constant name
    }

    /// @notice Matches multiple orders
    function matchMultipleOrders(uint256 maxMatches, uint256 minAmountOut) external whenNotPaused nonReentrant {
        if (bidHeap.length == 0 && askHeap.length == 0) revert NoMatchableOrders();
        if (maxMatches == 0 || maxMatches > MAX_MATCHES_PER_TX) revert InvalidAmount(maxMatches);
        // Prioritize perpetual orders
        for (uint256 i = 0; i < userOrders[msg.sender].length; i++) {
            uint256 orderId = userOrders[msg.sender][i];
            Order storage order = orders[orderId];
            if (order.isPerpetual && maxMatches > 0) {
                _matchPerpetualOrder(orderId);
                maxMatches--;
            }
        }
        _checkStopLossOrders();
        _matchOrders(minAmountOut, maxMatches);
    }

    /// @notice Matches orders cross-chain
    function matchOrdersCrossChain(
        uint16 dstChainId,
        uint256 minAmountOut,
        bytes calldata adapterParams
    ) external payable whenNotPaused nonReentrant {
        if (dstChainId == 0) revert InvalidChainId(dstChainId);
        if (bidHeap.length == 0 || askHeap.length == 0) revert NoMatchableOrders();

        ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(uint64(dstChainId));
        if (!status.retryRecommended || !status.bridgeOperational) revert InvalidOperation("Retry not recommended");

        uint256 matchId;
        unchecked {
            matchId = nextMatchId++;
        }
        if (crossChainMatches[dstChainId][matchId]) revert CrossChainMatchExists(dstChainId, matchId);

        uint256 bidId = bidHeap[0];
        uint256 askId = askHeap[0];
        Order storage bid = orders[bidId];
        Order storage ask = orders[askId];

        if (
            bid.expiryTimestamp != 0 && bid.expiryTimestamp <= block.timestamp ||
            ask.expiryTimestamp != 0 && ask.expiryTimestamp <= block.timestamp ||
            bid.price < ask.price || bid.locked || ask.locked ||
            (bid.isPerpetual != ask.isPerpetual)
        ) revert NoMatchableOrders();

        uint256 tradeAmount = bid.amount < ask.amount ? bid.amount : ask.amount;
        uint256 tradePrice = bid.isMarket || ask.isMarket ? ask.price : (uint256(bid.price) + ask.price) / 2;

        bytes memory payload = abi.encode(
            matchId,
            bidId,
            askId,
            tradeAmount,
            tradePrice,
            minAmountOut,
            bid.tokenA,
            bid.tokenB
        );

        crossChainModule.batchCrossChainMessages{value: msg.value}(
            _toArrayUint16(dstChainId),
            _toArrayString(ammPool.chainIdToAxelarChain(dstChainId)),
            _toArrayBytes(payload),
            _toArrayBytes(adapterParams),
            _toArrayUint256(block.timestamp + status.recommendedRetryDelay)
        );
        ammPool.rebalanceReserves(dstChainId);
        crossChainMatches[dstChainId][matchId] = true;

        emit CrossChainMatchExecuted(matchId, dstChainId, bidId, askId, tradeAmount);
    }

    /// @notice Stakes governance tokens
    function stakeTokens(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount(amount);
        governanceToken.transferFrom(msg.sender, address(this), amount);
        stakedTokens[msg.sender] += amount;
        totalStaked += amount;
        emit TokensStaked(msg.sender, amount);
    }

    /// @notice Unstakes governance tokens
    function unstakeTokens(uint256 amount) external nonReentrant {
        if (amount == 0 || amount > stakedTokens[msg.sender]) revert InvalidAmount(amount);
        stakedTokens[msg.sender] -= amount;
        totalStaked -= amount;
        governanceToken.transfer(msg.sender, amount);
        emit TokensUnstaked(msg.sender, amount);
    }

    /// @notice Creates a governance proposal
    function createProposal(
        string calldata description,
        ProposalType proposalType,
        bytes calldata data
    ) external {
        if (stakedTokens[msg.sender] == 0) revert InsufficientStake(msg.sender, stakedTokens[msg.sender]);
        if (uint8(proposalType) > uint8(ProposalType.Other)) revert InvalidProposalType(uint8(proposalType));

        uint256 proposalId;
        unchecked {
            proposalId = nextProposalId++;
        }
        Proposal storage proposal = proposals[proposalId];
        proposal.proposalId = proposalId;
        proposal.proposer = msg.sender;
        proposal.description = description;
        proposal.endTime = uint64(block.timestamp + VOTING_DURATION);
        proposal.proposalType = proposalType;
        proposal.data = data;
        emit ProposalCreated(proposalId, msg.sender, description, proposalType);
    }

    /// @notice Votes on a proposal
    function voteOnProposal(uint256 proposalId) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert InvalidProposal(proposalId);
        if (proposal.endTime < block.timestamp) revert ProposalEnded(proposalId);
        if (proposal.hasVoted[msg.sender]) revert AlreadyVoted(msg.sender);
        if (stakedTokens[msg.sender] == 0) revert InsufficientStake(msg.sender, stakedTokens[msg.sender]);

        proposal.hasVoted[msg.sender] = true;
        proposal.voteCount += stakedTokens[msg.sender];
        emit Voted(msg.sender, proposalId, stakedTokens[msg.sender]);
    }

    /// @notice Executes a proposal
    function executeProposal(uint256 proposalId) external nonReentrant {
        _restrictGovernance();
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert InvalidProposal(proposalId);
        if (proposal.endTime > block.timestamp) revert InvalidOperation("Voting ongoing");
        if (proposal.executed) revert InvalidOperation("Already executed");
        if (proposal.voteCount < totalStaked / 2) revert InvalidOperation("Insufficient votes");

        proposal.executed = true;

        if (proposal.proposalType == ProposalType.ParameterChange) {
            (string memory paramName, uint256 value) = abi.decode(proposal.data, (string, uint256));
            _executeParameterChange(paramName, value);
        } else if (proposal.proposalType == ProposalType.Upgrade) {
            (address newImplementation) = abi.decode(proposal.data, (address));
            _upgradeTo(newImplementation);
        } else if (proposal.proposalType == ProposalType.TreasuryAllocation) {
            (address recipient, uint256 amount, address token) = abi.decode(proposal.data, (address, uint256, address));
            IERC20Upgradeable(token).safeTransfer(recipient, amount);
        }

        emit ProposalExecuted(proposalId);
    }

    /// @notice Claims trader rewards
    function claimTraderRewards() external nonReentrant {
        TraderReward storage reward = traderRewards[msg.sender];
        if (reward.accumulatedFees < minFeesForReward) {
            revert InsufficientFeesForReward(msg.sender, reward.accumulatedFees);
        }
        if (block.timestamp < reward.lastClaimTimestamp + rewardClaimCooldown) {
            revert RewardCooldownActive(msg.sender, reward.lastClaimTimestamp + rewardClaimCooldown);
        }

        uint256 rewardAmount = reward.unclaimedTokens;
        reward.unclaimedTokens = 0;
        reward.lastClaimTimestamp = uint64(block.timestamp);

        if (rewardAmount > 0) {
            governanceToken.transfer(msg.sender, rewardAmount);
            emit TraderRewardsClaimed(msg.sender, rewardAmount);
        }
    }

    /// @notice Distributes governance rewards
    function distributeGovernanceRewards() external nonReentrant {
        _restrictGovernance();
        if (governanceRewardPool == 0) revert NoLiquidityProviders();
        uint256 amount = governanceRewardPool;
        governanceRewardPool = 0;
        IERC20Upgradeable(address(governanceToken)).safeTransfer(address(this), amount);
        emit GovernanceRewardsDistributed(amount);
    }

    /// @notice Distributes LP rewards
    function distributeLPRewards() external nonReentrant {
        _restrictGovernance();
        if (lpRewardPool == 0) revert NoLiquidityProviders();
        uint256 amount = lpRewardPool;
        lpRewardPool = 0;
        IERC20Upgradeable(ammPool.token1()).safeTransfer(address(ammPool), amount);
        emit LPRewardsDistributed(amount);
    }

    /// @notice Sets liquidity range
    function setLiquidityRange(uint256 minPrice, uint256 maxPrice) external {
        _restrictGovernance();
        if (minPrice >= maxPrice || minPrice == 0) revert InvalidPrice(minPrice);
        _adjustLiquidityRange();
        ammPool.adjustLiquidityRange(minPrice, maxPrice);
        emit LiquidityRangeSet(minPrice, maxPrice);
    }

    /// @notice Sets volatility threshold
    function setVolatilityThreshold(uint256 _threshold) external {
        _restrictGovernance();
        if (_threshold == 0) revert InvalidVolatility(_threshold);
        volatilityThreshold = _threshold;
        emit VolatilityThresholdSet(_threshold);
    }

    /// @notice Sets liquidity range multiplier
    function setLiquidityRangeMultiplier(uint256 _multiplier) external {
        _restrictGovernance();
        if (_multiplier == 0) revert InvalidAmount(_multiplier);
        liquidityRangeMultiplier = _multiplier;
        emit LiquidityRangeMultiplierSet(_multiplier);
    }

    /// @notice Sets reward parameters
    function setRewardParameters(
        uint256 _rewardRateBps,
        uint256 _minFeesForReward,
        uint256 _rewardClaimCooldown
    ) external {
        _restrictGovernance();
        if (_rewardRateBps > 10000) revert InvalidFeeTier(0, _rewardRateBps);
        rewardRateBps = _rewardRateBps;
        minFeesForReward = _minFeesForReward;
        rewardClaimCooldown = _rewardClaimCooldown;
        emit RewardParametersSet(_rewardRateBps, _minFeesForReward, _rewardClaimCooldown);
    }

    /// @notice Sets oracle staleness threshold
    function setOracleStalenessThreshold(uint64 _threshold) external {
        _restrictGovernance();
        if (_threshold == 0) revert InvalidAmount(_threshold);
        oracleStalenessThreshold = _threshold;
        emit OracleStalenessThresholdSet(_threshold);
    }

    /// @notice Locks an order
    function lockOrder(uint256 orderId) external nonReentrant {
        _restrictGovernance();
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        Order storage order = orders[orderId];
        if (order.locked) revert OrderLocked(orderId);
        order.locked = true;
        emit OrderLockedEvent(orderId);
    }

    /// @notice Unlocks an order
    function unlockOrder(uint256 orderId) external nonReentrant {
        _restrictGovernance();
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        Order storage order = orders[orderId];
        if (!order.locked) revert OrderNotLocked(orderId);
        order.locked = false;
        emit OrderUnlocked(orderId);
    }

    /// @notice Cancels multiple orders
    function batchCancelOrders(uint256[] calldata orderIds) external nonReentrant {
        _restrictGovernance();
        for (uint256 i = 0; i < orderIds.length; i++) {
            if (orderExists[orderIds[i]]) {
                Order storage order = orders[orderIds[i]];
                if (!order.locked && (order.expiryTimestamp == 0 || order.expiryTimestamp > block.timestamp)) {
                    if (order.isPerpetual) {
                        uint256 collateral = order.initialMargin;
                        userEquity[order.user] = userEquity[order.user].sub(collateral);
                        if (!usdc.transfer(order.user, collateral)) revert MarginTransferFailed();
                    } else {
                        IERC20Upgradeable collateralToken = IERC20Upgradeable(order.isBuy ? order.tokenB : order.tokenA);
                        uint256 collateral = order.isMarket ? uint256(order.amount) : uint256(order.price) * order.amount;
                        collateralToken.safeTransfer(order.user, collateral);
                    }
                    if (order.isStopLoss) {
                        _removeStopLossOrder(order.user, orderIds[i]);
                    }
                    _removeOrder(orderIds[i], order.isBuy);
                    emit OrderCancelled(order.user, orderIds[i]);
                }
            }
        }
        emit BatchOrdersCancelled(orderIds);
    }

    /// @notice Cleans expired orders
    function cleanExpiredOrders(uint256 maxOrders) external nonReentrant {
        _restrictGovernance();
        uint256[] memory expiredIds = new uint256[](maxOrders);
        uint256 count = 0;

        for (uint256 i = bidHeap.length; i > 0 && count < maxOrders; ) {
            unchecked {
                --i;
            }
            uint256 orderId = bidHeap[i];
            Order storage order = orders[orderId];
            if (order.expiryTimestamp != 0 && order.expiryTimestamp <= block.timestamp) {
                expiredIds[count] = orderId;
                _removeOrder(orderId, true);
                unchecked {
                    ++count;
                }
            }
        }

        for (uint256 i = askHeap.length; i > 0 && count < maxOrders; ) {
            unchecked {
                --i;
            }
            uint256 orderId = askHeap[i];
            Order storage order = orders[orderId];
            if (order.expiryTimestamp != 0 && order.expiryTimestamp <= block.timestamp) {
                expiredIds[count] = orderId;
                _removeOrder(orderId, false);
                unchecked {
                    ++count;
                }
            }
        }

        if (count < maxOrders) {
            assembly {
                mstore(expiredIds, count)
            }
        }

        emit ExpiredOrdersCleaned(expiredIds);
    }

    /// @notice Takes order book snapshot
    function takeSnapshot() public nonReentrant {
        _restrictGovernance();
        snapshots.push(Snapshot({timestamp: uint64(block.timestamp), bidOrderIds: bidHeap, askOrderIds: askHeap}));
        emit SnapshotTaken(snapshots.length - 1, block.timestamp);
    }

    /// @notice Enables emergency withdrawals
    function enableEmergencyWithdrawal(bool enabled) external {
        _restrictGovernance();
        emergencyWithdrawalEnabled = enabled;
        emit EmergencyWithdrawalEnabled(enabled);
    }

    /// @notice Allows emergency withdrawal
    function emergencyWithdraw() external nonReentrant {
        if (!emergencyWithdrawalEnabled) revert EmergencyWithdrawalDisabled();
        if (!paused()) revert InvalidOperation("Contract not paused");

        uint256[] storage userOrderIds = userOrders[msg.sender];
        uint256 totalA = 0;
        uint256 totalB = 0;
        uint256 totalCollateral = 0;

        for (uint256 i = userOrderIds.length; i > 0; ) {
            unchecked {
                --i;
            }
            uint256 orderId = userOrderIds[i];
            Order storage order = orders[orderId];
            if (order.user == msg.sender) {
                if (order.isPerpetual) {
                    totalCollateral += order.initialMargin;
                    userEquity[msg.sender] = userEquity[msg.sender].sub(order.initialMargin);
                } else {
                    uint256 collateral = order.isMarket ? uint256(order.amount) : uint256(order.price) * order.amount;
                    if (order.isBuy) {
                        totalB += collateral;
                    } else {
                        totalA += collateral;
                    }
                }
                if (order.isStopLoss) {
                    _removeStopLossOrder(msg.sender, orderId);
                }
                _removeOrder(orderId, order.isBuy);
            }
        }

        if (totalA > 0) IERC20Upgradeable(ammPool.token0()).safeTransfer(msg.sender, totalA);
        if (totalB > 0) IERC20Upgradeable(ammPool.token1()).safeTransfer(msg.sender, totalB);
        if (totalCollateral > 0) usdc.safeTransfer(msg.sender, totalCollateral);

        emit EmergencyWithdrawal(msg.sender, totalA, totalB);
    }

    /// @notice Pauses the contract
    function pause() external {
        _restrictGovernance();
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external {
        _restrictGovernance();
        _unpause();
    }

    /// @notice Sets fee tiers
    function setFeeTiers(FeeTier[2] calldata _feeTiers) external {
        _restrictGovernance();
        for (uint256 i = 0; i < 2; i++) {
            if (_feeTiers[i].feeRateBps == 0 || _feeTiers[i].feeRateBps > 1000) {
                revert InvalidFeeTier(_feeTiers[i].orderSizeThreshold, _feeTiers[i].feeRateBps);
            }
            feeTiers[i] = _feeTiers[i];
        }
        emit FeeTiersUpdated(_feeTiers);
    }

    /// @notice Sets user type
    function setUserType(address user, uint8 userType) external {
        _restrictGovernance();
        if (userType > 1) revert InvalidUserType(userType);
        userTypes[user] = userType;
        emit UserTypeSet(user, userType);
    }

    /// @notice Retrieves order by ID
    function getOrder(uint256 orderId) external view returns (Order memory) {
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        return orders[orderId];
    }

    /// @notice Retrieves bid order IDs
    function getBids() external view returns (uint256[] memory) {
        return bidHeap;
    }

    /// @notice Retrieves ask order IDs
    function getAsks() external view returns (uint256[] memory) {
        return askHeap;
    }

    /// @notice Retrieves fee tiers
    function getFeeTiers() external view returns (FeeTier[2] memory) {
        return feeTiers;
    }

    /// @notice Retrieves snapshot
    function getSnapshot(uint256 snapshotId) external view returns (Snapshot memory) {
        return snapshots[snapshotId];
    }

    /// @notice Retrieves stop-loss orders for a user
    function getStopLossOrders(address user) external view returns (uint256[] memory) {
        return stopLossOrders[user];
    }

    /// @notice Retrieves aggregated price
    function getAggregatedPrice(address tokenA, address tokenB) public view returns (uint256) {
        try priceOracle.getCurrentPairPrice(address(this), tokenA) returns (uint256 price, bool cachedStatus, uint256 timestamp) {
            if (price == 0) revert NoValidPrice();
            if (cachedStatus && block.timestamp > timestamp + oracleStalenessThreshold) {
                revert PriceOracleStale(block.timestamp);
            }
            return price;
        } catch {
            revert PriceOracleError();
        }
    }

    /// @dev Internal function to place an order
    function _placeOrder(
        address user,
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp,
        bool useConcentratedLiquidity,
        bool isPerpetual,
        uint256 leverage,
        uint256 margin
    ) internal returns (uint256 orderId) {
        _validateOrder(isBuy, isMarket, isStopLoss, price, triggerPrice, amount, tokenA, tokenB, expiryTimestamp);
        if (userOrders[user].length >= MAX_ORDERS_PER_USER) revert TooManyOrders(user);

        if (!isPerpetual) {
            IERC20Upgradeable collateralToken = IERC20Upgradeable(isBuy ? tokenB : tokenA);
            uint256 collateral = isMarket ? amount : uint256(price) * amount;
            collateralToken.safeTransferFrom(user, address(this), collateral);
        }

        unchecked {
            orderId = nextOrderId++;
        }
        Order storage order = orders[orderId];
        order.user = user;
        order.isBuy = isBuy;
        order.isMarket = isMarket;
        order.isStopLoss = isStopLoss;
        order.price = price;
        order.triggerPrice = triggerPrice;
        order.amount = amount;
        order.timestamp = uint64(block.timestamp);
        order.expiryTimestamp = expiryTimestamp;
        order.locked = false;
        order.orderId = orderId;
        order.tokenA = tokenA;
        order.tokenB = tokenB;
        order.useConcentratedLiquidity = useConcentratedLiquidity;
        order.isPerpetual = isPerpetual;
        order.leverage = leverage;
        order.initialMargin = margin;
        order.maintenanceMargin = (margin * 80) / 100; // Updated: Use direct arithmetic
        order.lastFundingTimestamp = isPerpetual ? block.timestamp : 0;

        userOrders[user].push(orderId);
        orderExists[orderId] = true;

        // Add user to userList if not already present
        bool userExists = false;
        for (uint256 i = 0; i < userList.length; i++) {
            if (userList[i] == user) {
                userExists = true;
                break;
            }
        }
        if (!userExists) {
            userList.push(user);
        }

        if (isStopLoss) {
            stopLossOrders[user].push(orderId);
        } else if (!isMarket && !isPerpetual) {
            if (isBuy) {
                bidHeap.push(orderId);
                orderHeapIndex[orderId] = bidHeap.length - 1;
                _heapifyUpBids(bidHeap.length - 1);
            } else {
                askHeap.push(orderId);
                orderHeapIndex[orderId] = askHeap.length - 1;
                _heapifyUpAsks(askHeap.length - 1);
            }
        }

        emit OrderPlaced(
            user,
            isBuy,
            isMarket,
            isStopLoss,
            price,
            triggerPrice,
            amount,
            orderId,
            tokenA,
            tokenB,
            expiryTimestamp,
            useConcentratedLiquidity
        );

        return orderId;
    }

    /// @dev Matches a perpetual order
    function _matchPerpetualOrder(uint256 orderId) internal {
        Order storage order = orders[orderId];
        if (!order.isPerpetual) revert NotPerpetualOrder(orderId);

        // Check for liquidation
        if (_isUnderMargined(order)) {
            this.liquidatePosition(orderId);
            return;
        }

        // Apply funding if due
        if (block.timestamp >= order.lastFundingTimestamp + FUNDING_INTERVAL) {
            this.applyFunding(orderId);
        }

        // Simplified matching logic for perpetuals (assumes AMM counterparty)
        uint256 positionSize = uint256(order.amount).mul(order.leverage);
        uint256 currentPrice = priceOracle.getSpotPrice(order.tokenA, order.tokenB);
        uint256 tradeValue = positionSize.mul(currentPrice).div(1e18);

        // Approve tokens for AMM swap
        usdc.approve(address(ammPool), order.initialMargin);

        // Perform swap via AMM
        uint256 amountOut = ammPool.swap(
            order.isBuy ? positionSize : 0,
            order.isBuy ? 0 : positionSize,
            address(this),
            ""
        );

        // Update trader rewards
        uint256 fee = tradeValue.mul(feeTiers[0].feeRateBps).div(1e4);
        _updateTraderRewards(order.user, fee);

        // Update order price to current market price
        order.price = uint96(currentPrice);
    }

    /// @dev Checks if a position is under-margined
    function _isUnderMargined(Order memory order) internal view returns (bool) {
        if (!order.isPerpetual) return false;
        uint256 positionSize = uint256(order.amount) * order.leverage;
        uint256 currentPrice = priceOracle.getSpotPrice(order.tokenA, order.tokenB);
        uint256 positionValue = (positionSize * currentPrice) / 1e18;
        int256 unrealizedPnL = order.isBuy
            ? (int256(currentPrice) - int256(uint256(order.price))) * int256(positionSize) / int256(1e18)
            : (int256(uint256(order.price)) - int256(currentPrice)) * int256(positionSize) / int256(1e18);

        uint256 availableMargin = order.initialMargin + uint256(unrealizedPnL) - uint256(order.cumulativeFunding);
        return availableMargin < order.maintenanceMargin;
    }

    /// @dev Validates order parameters
    function _validateOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp
    ) internal view {
        if (amount == 0) revert InvalidAmount(amount);
        if (tokenA != ammPool.token0() || tokenB != ammPool.token1()) revert InvalidTokenPair(tokenA, tokenB);
        if (expiryTimestamp != 0 && expiryTimestamp <= block.timestamp) revert InvalidExpiry(expiryTimestamp);
        if (isStopLoss && triggerPrice == 0) revert InvalidTriggerPrice(triggerPrice);
    }

    /// @dev Checks and triggers stop-loss orders
    function _checkStopLossOrders() internal {
        uint256 currentPrice = getAggregatedPrice(ammPool.token0(), ammPool.token1());
        uint256 gasLimit = gasleft();
        uint256 gasPerIteration = 50000; // Estimated gas per user iteration

        for (uint256 i = 0; i < userList.length; i++) {
            if (gasLimit < gasPerIteration) break;
            address user = userList[i];
            uint256[] storage userStopLoss = stopLossOrders[user];
            for (uint256 j = userStopLoss.length; j > 0; ) {
                unchecked {
                    --j;
                }
                uint256 orderId = userStopLoss[j];
                Order memory order = orders[orderId];
                if (
                    (order.isBuy && currentPrice <= order.triggerPrice) ||
                    (!order.isBuy && currentPrice >= order.triggerPrice)
                ) {
                    emit StopLossTriggered(orderId, order.triggerPrice);
                    _removeStopLossOrder(user, orderId);
                    if (order.isBuy) {
                        bidHeap.push(orderId);
                        orderHeapIndex[orderId] = bidHeap.length - 1;
                        _heapifyUpBids(bidHeap.length - 1);
                    } else {
                        askHeap.push(orderId);
                        orderHeapIndex[orderId] = askHeap.length - 1;
                        _heapifyUpAsks(askHeap.length - 1);
                    }
                }
            }
            gasLimit -= gasPerIteration;
        }
    }

    /// @dev Removes stop-loss order
    function _removeStopLossOrder(address user, uint256 orderId) internal {
        uint256[] storage userStopLoss = stopLossOrders[user];
        for (uint256 i = 0; i < userStopLoss.length; i++) {
            if (userStopLoss[i] == orderId) {
                userStopLoss[i] = userStopLoss[userStopLoss.length - 1];
                userStopLoss.pop();
                break;
            }
        }

        // Remove user from userList if no orders remain
        if (userOrders[user].length == 0 && stopLossOrders[user].length == 0) {
            for (uint256 i = 0; i < userList.length; i++) {
                if (userList[i] == user) {
                    userList[i] = userList[userList.length - 1];
                    userList.pop();
                    break;
                }
            }
        }
    }

    /// @dev Matches orders with batch processing
    function _matchOrders(uint256 minAmountOut, uint256 maxMatches) internal {
        uint256 currentPrice = getAggregatedPrice(ammPool.token0(), ammPool.token1());
        uint256 matches = 0;
        uint256 gasLimit = gasleft();
        uint256 gasPerMatch = 100000;

        _adjustLiquidityRange();

        uint256[] memory bidHeapCache = bidHeap;
        uint256[] memory askHeapCache = askHeap;

        Transfer[] memory transfers = new Transfer[](maxMatches * 3);
        uint256 transferCount = 0;
        uint256[] memory matchedOrderIds = new uint256[](maxMatches * 2);
        uint256 matchOrderCount = 0;
        uint256[] memory tradePrices = new uint256[](maxMatches);
        uint256[] memory tradeAmounts = new uint256[](maxMatches);
        uint256[] memory totalFees = new uint256[](maxMatches);

        while (bidHeapCache.length > 0 && askHeapCache.length > 0 && matches < maxMatches && gasLimit >= gasPerMatch) {
            uint256 bidId = bidHeapCache[0];
            uint256 askId = askHeapCache[0];
            Order memory bid = orders[bidId];
            Order memory ask = orders[askId];

            if (
                (bid.expiryTimestamp != 0 && bid.expiryTimestamp <= block.timestamp) ||
                (ask.expiryTimestamp != 0 && ask.expiryTimestamp <= block.timestamp)
            ) {
                if (bid.expiryTimestamp != 0 && bid.expiryTimestamp <= block.timestamp) {
                    _removeOrder(bidId, true);
                    bidHeapCache = bidHeap;
                }
                if (ask.expiryTimestamp != 0 && ask.expiryTimestamp <= block.timestamp) {
                    _removeOrder(askId, false);
                    askHeapCache = askHeap;
                }
                continue;
            }

            bool isMarketMatch = bid.isMarket || ask.isMarket;
            if (!isMarketMatch && bid.price < ask.price || bid.locked || ask.locked || (bid.isPerpetual != ask.isPerpetual)) {
                break;
            }

            uint256 tradePrice;
            if (isMarketMatch) {
                tradePrice = ask.price;
                if (tradePrice == 0 || tradePrice > currentPrice * 115 / 100 || tradePrice < currentPrice * 85 / 100) {
                    revert InvalidPrice(tradePrice);
                }
            } else {
                tradePrice = bid.useConcentratedLiquidity || ask.useConcentratedLiquidity ?
                    ammPool.getConcentratedPrice() :
                    (uint256(bid.price) + ask.price) / 2;
            }
            uint256 tradeValue;
            unchecked {
                tradeValue = tradePrice * min(bid.amount, ask.amount);
            }

            uint256 feeRate = _getFeeRate(msg.sender, tradeValue);
            uint256 tradeAmount = min(bid.amount, ask.amount);
            uint256 totalFee;
            unchecked {
                totalFee = (tradeAmount * tradePrice * feeRate) / 10000; // Updated: Direct arithmetic
            }

            // Store values for event emission
            tradePrices[matches] = tradePrice;
            tradeAmounts[matches] = tradeAmount;
            totalFees[matches] = totalFee;

            // Update trader rewards
            _updateTraderRewards(bid.user, totalFee);
            _updateTraderRewards(ask.user, totalFee);

            uint256 lpFee;
            uint256 govFee;
            uint256 treasuryFee;
            unchecked {
                lpFee = totalFee / 4;
                govFee = totalFee / 4;
                treasuryFee = totalFee - lpFee - govFee;
                lpRewardPool += lpFee;
                governanceRewardPool += govFee;
            }

            IERC20Upgradeable(bid.tokenB).approve(address(ammPool), tradeAmount * tradePrice);
            IERC20Upgradeable(ask.tokenA).approve(address(ammPool), tradeAmount);

            uint256 amountOut = ammPool.swap(
                bid.tokenA == ammPool.token0() ? tradeAmount : 0,
                bid.tokenA == ammPool.token0() ? 0 : tradeAmount,
                address(this),
                ""
            );

            if (amountOut < minAmountOut) revert SlippageExceeded(amountOut, minAmountOut);

            transfers[transferCount++] = Transfer({user: bid.user, token: bid.tokenA, amount: tradeAmount});
            transfers[transferCount++] = Transfer({user: ask.user, token: ask.tokenB, amount: (tradeAmount * tradePrice) - totalFee});
            transfers[transferCount++] = Transfer({user: ammPool.treasury(), token: ask.tokenB, amount: treasuryFee});

            orders[bidId].amount -= uint96(tradeAmount);
            orders[askId].amount -= uint96(tradeAmount);

            matchedOrderIds[matchOrderCount++] = bidId;
            matchedOrderIds[matchOrderCount++] = askId;

            if (orders[bidId].amount == 0) {
                _removeOrder(bidId, true);
                bidHeapCache = bidHeap;
                // Remove bid.user from userList if no orders remain
                if (userOrders[bid.user].length == 0 && stopLossOrders[bid.user].length == 0) {
                    for (uint256 i = 0; i < userList.length; i++) {
                        if (userList[i] == bid.user) {
                            userList[i] = userList[userList.length - 1];
                            userList.pop();
                            break;
                        }
                    }
                }
            } else {
                _heapifyDownBids(0);
            }
            if (orders[askId].amount == 0) {
                _removeOrder(askId, false);
                askHeapCache = askHeap;
                // Remove ask.user from userList if no orders remain
                if (userOrders[ask.user].length == 0 && stopLossOrders[ask.user].length == 0) {
                    for (uint256 i = 0; i < userList.length; i++) {
                        if (userList[i] == ask.user) {
                            userList[i] = userList[userList.length - 1];
                            userList.pop();
                            break;
                        }
                    }
                }
            } else {
                _heapifyDownAsks(0);
            }

            unchecked {
                ++matches;
                gasLimit -= gasPerMatch;
            }
        }

        // Execute batch transfers
        for (uint256 i = 0; i < transferCount; i++) {
            IERC20Upgradeable(transfers[i].token).safeTransfer(transfers[i].user, transfers[i].amount);
        }

        // Emit batched events
        for (uint256 i = 0; i < matches; i++) {
            emit OrdersMatched(
                matchedOrderIds[i * 2],
                matchedOrderIds[i * 2 + 1],
                tradePrices[i],
                tradeAmounts[i],
                totalFees[i]
            );
        }

        bidHeap = bidHeapCache;
        askHeap = askHeapCache;
    }

    /// @dev Removes an order
    function _removeOrder(uint256 orderId, bool isBuy) internal {
        Order memory order = orders[orderId];
        uint256 index = orderHeapIndex[orderId];
        uint256[] storage heap = isBuy ? bidHeap : askHeap;

        if (!order.isMarket && !order.isStopLoss && !order.isPerpetual) {
            heap[index] = heap[heap.length - 1];
            orderHeapIndex[heap[index]] = index;
            heap.pop();
            if (index < heap.length) {
                isBuy ? _heapifyDownBids(index) : _heapifyDownAsks(index);
            }
        }

        delete orderHeapIndex[orderId];
        delete orderExists[orderId];
        delete orders[orderId];

        _removeUserOrder(order.user, orderId);
    }

    /// @dev Heapifies up bids
    function _heapifyUpBids(uint256 index) internal {
        uint256[] memory heapCache = bidHeap;
        mapping(uint256 => Order) storage ordersCache = orders;

        while (index > 0) {
            uint256 parent = (index - 1) / 2;
            uint256 childId = heapCache[index];
            uint256 parentId = heapCache[parent];
            Order memory child = ordersCache[childId];
            Order memory parentOrder = ordersCache[parentId];

            if (
                child.price > parentOrder.price ||
                (child.price == parentOrder.price && child.timestamp < parentOrder.timestamp)
            ) {
                heapCache[index] = parentId;
                heapCache[parent] = childId;
                orderHeapIndex[childId] = parent;
                orderHeapIndex[parentId] = index;
                index = parent;
            } else {
                break;
            }
        }

        bidHeap = heapCache;
    }

    /// @dev Heapifies down bids
    function _heapifyDownBids(uint256 index) internal {
        uint256[] memory heapCache = bidHeap;
        mapping(uint256 => Order) storage ordersCache = orders;
        uint256 length = heapCache.length;

        while (true) {
            uint256 left = 2 * index + 1;
            uint256 right = 2 * index + 2;
            uint256 largest = index;
            uint256 largestId = heapCache[largest];

            if (left < length) {
                uint256 leftId = heapCache[left];
                if (
                    ordersCache[leftId].price > ordersCache[largestId].price ||
                    (ordersCache[leftId].price == ordersCache[largestId].price &&
                        ordersCache[leftId].timestamp < ordersCache[largestId].timestamp)
                ) {
                    largest = left;
                    largestId = leftId;
                }
            }

            if (right < length) {
                uint256 rightId = heapCache[right];
                if (
                    ordersCache[rightId].price > ordersCache[largestId].price ||
                    (ordersCache[rightId].price == ordersCache[largestId].price &&
                        ordersCache[rightId].timestamp < ordersCache[largestId].timestamp)
                ) {
                    largest = right;
                }
            }

            if (largest != index) {
                uint256 swapId = heapCache[largest];
                heapCache[largest] = heapCache[index];
                heapCache[index] = swapId;
                orderHeapIndex[heapCache[index]] = index;
                orderHeapIndex[swapId] = largest;
                index = largest;
            } else {
                break;
            }
        }

        bidHeap = heapCache;
    }

    /// @dev Heapifies up asks
    function _heapifyUpAsks(uint256 index) internal {
        uint256[] memory heapCache = askHeap;
        mapping(uint256 => Order) storage ordersCache = orders;

        while (index > 0) {
            uint256 parent = (index - 1) / 2;
            uint256 childId = heapCache[index];
            uint256 parentId = heapCache[parent];
            Order memory child = ordersCache[childId];
            Order memory parentOrder = ordersCache[parentId];

            if (
                child.price < parentOrder.price ||
                (child.price == parentOrder.price && child.timestamp < parentOrder.timestamp)
            ) {
                heapCache[index] = parentId;
                heapCache[parent] = childId;
                orderHeapIndex[childId] = parent;
                orderHeapIndex[parentId] = index;
                index = parent;
            } else {
                break;
            }
        }

        askHeap = heapCache;
    }

    /// @dev Heapifies down asks
    function _heapifyDownAsks(uint256 index) internal {
        uint256[] memory heapCache = askHeap;
        mapping(uint256 => Order) storage ordersCache = orders;
        uint256 length = heapCache.length;

        while (true) {
            uint256 left = 2 * index + 1;
            uint256 right = 2 * index + 2;
            uint256 smallest = index;
            uint256 smallestId = heapCache[smallest];

            if (left < length) {
                uint256 leftId = heapCache[left];
                if (
                    ordersCache[leftId].price < ordersCache[smallestId].price ||
                    (ordersCache[leftId].price == ordersCache[smallestId].price &&
                        ordersCache[leftId].timestamp < ordersCache[smallestId].timestamp)
                ) {
                    smallest = left;
                    smallestId = leftId;
                }
            }

            if (right < length) {
                uint256 rightId = heapCache[right];
                if (
                    ordersCache[rightId].price < ordersCache[smallestId].price ||
                    (ordersCache[rightId].price == ordersCache[smallestId].price &&
                        ordersCache[rightId].timestamp < ordersCache[smallestId].timestamp)
                ) {
                    smallest = right;
                }
            }

            if (smallest != index) {
                uint256 swapId = heapCache[smallest];
                heapCache[smallest] = heapCache[index];
                heapCache[index] = swapId;
                orderHeapIndex[heapCache[index]] = index;
                orderHeapIndex[swapId] = smallest;
                index = smallest;
            } else {
                break;
            }
        }

        askHeap = heapCache;
    }

    /// @dev Removes user order
    function _removeUserOrder(address user, uint256 orderId) internal {
        uint256[] storage userOrderIds = userOrders[user];
        for (uint256 i = 0; i < userOrderIds.length; i++) {
            if (userOrderIds[i] == orderId) {
                userOrderIds[i] = userOrderIds[userOrderIds.length - 1];
                userOrderIds.pop();
                break;
            }
        }
    }

        /// @dev Gets fee rate for a user based on order size and user type
    function _getFeeRate(address user, uint256 tradeValue) internal view returns (uint256) {
        uint256 feeRate = feeTiers[0].feeRateBps;
        if (tradeValue >= feeTiers[1].orderSizeThreshold) {
            feeRate = feeTiers[1].feeRateBps;
        }
        if (userTypes[user] == 1) { // Institutional user
            feeRate = feeRate.mul(80).div(100); // 20% discount
        }
        return feeRate;
    }

    /// @dev Updates trader rewards based on fees paid
    function _updateTraderRewards(address user, uint256 fee) internal {
        TraderReward storage reward = traderRewards[user];
        reward.accumulatedFees = reward.accumulatedFees.add(fee);
        uint256 newReward = fee.mul(rewardRateBps).div(1e4);
        reward.unclaimedTokens = reward.unclaimedTokens.add(newReward);
    }

    /// @dev Adjusts liquidity range based on volatility
    function _adjustLiquidityRange() internal {
        uint256 volatility = ammPool.getVolatility();
        if (volatility > volatilityThreshold) {
            uint256 currentPrice = getAggregatedPrice(ammPool.token0(), ammPool.token1());
            uint256 range = currentPrice.mul(liquidityRangeMultiplier).div(1e18);
            uint256 minPrice = currentPrice.sub(range);
            uint256 maxPrice = currentPrice.add(range);
            ammPool.adjustLiquidityRange(minPrice, maxPrice);
            emit LiquidityRangeSet(minPrice, maxPrice);
        }
    }

    /// @dev Executes parameter change from governance proposal
    function _executeParameterChange(string memory paramName, uint256 value) internal {
        bytes32 paramHash = keccak256(abi.encodePacked(paramName));
        if (paramHash == keccak256(abi.encodePacked("volatilityThreshold"))) {
            if (value == 0) revert InvalidVolatility(value);
            volatilityThreshold = value;
            emit VolatilityThresholdSet(value);
        } else if (paramHash == keccak256(abi.encodePacked("liquidityRangeMultiplier"))) {
            if (value == 0) revert InvalidAmount(value);
            liquidityRangeMultiplier = value;
            emit LiquidityRangeMultiplierSet(value);
        } else if (paramHash == keccak256(abi.encodePacked("rewardRateBps"))) {
            if (value > 10000) revert InvalidFeeTier(0, value);
            rewardRateBps = value;
            emit RewardParametersSet(rewardRateBps, minFeesForReward, rewardClaimCooldown);
        } else if (paramHash == keccak256(abi.encodePacked("minFeesForReward"))) {
            minFeesForReward = value;
            emit RewardParametersSet(rewardRateBps, minFeesForReward, rewardClaimCooldown);
        } else if (paramHash == keccak256(abi.encodePacked("rewardClaimCooldown"))) {
            rewardClaimCooldown = value;
            emit RewardParametersSet(rewardRateBps, minFeesForReward, rewardClaimCooldown);
        } else if (paramHash == keccak256(abi.encodePacked("oracleStalenessThreshold"))) {
            if (value == 0) revert InvalidAmount(value);
            oracleStalenessThreshold = uint64(value);
            emit OracleStalenessThresholdSet(value);
        } else if (paramHash == keccak256(abi.encodePacked("fundingRateCapBps"))) {
            if (value > 100) revert InvalidFeeTier(0, value); // Max 1%
            fundingRateCapBps = value;
            emit FundingParametersSet(fundingRateCapBps, liquidationFeeBps, MAX_LEVERAGE);
        } else if (paramHash == keccak256(abi.encodePacked("liquidationFeeBps"))) {
            if (value > 500) revert InvalidFeeTier(0, value); // Max 5%
            liquidationFeeBps = value;
            emit FundingParametersSet(fundingRateCapBps, liquidationFeeBps, MAX_LEVERAGE);
        } else {
            revert InvalidOperation("Unknown parameter");
        }
    }

    /// @dev Restricts function to governance module
    function _restrictGovernance() internal view {
        if (msg.sender != address(governanceModule)) revert Unauthorized();
    }

    /// @dev Utility to convert uint16 to array
    function _toArrayUint16(uint16 value) internal pure returns (uint16[] memory) {
        uint16[] memory arr = new uint16[](1);
        arr[0] = value;
        return arr;
    }

    /// @dev Utility to convert string to array
    function _toArrayString(string memory value) internal pure returns (string[] memory) {
        string[] memory arr = new string[](1);
        arr[0] = value;
        return arr;
    }

    /// @dev Utility to convert bytes to array
    function _toArrayBytes(bytes memory value) internal pure returns (bytes[] memory) {
        bytes[] memory arr = new bytes[](1);
        arr[0] = value;
        return arr;
    }

    /// @dev Utility to convert uint256 to array
    function _toArrayUint256(uint256 value) internal pure returns (uint256[] memory) {
        uint256[] memory arr = new uint256[](1);
        arr[0] = value;
        return arr;
    }

    /// @dev Utility to find minimum of two uint256 values
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /// @notice Sets the governance module address
    function setGovernanceModule(address _governanceModule) external {
        _restrictGovernance();
        if (_governanceModule == address(0)) revert InvalidGovernance(_governanceModule);
        governanceModule = IGovernanceModule(_governanceModule);
        emit GovernanceModuleSet(_governanceModule);
    }

    /// @notice Sets the AMM pool address
    function setAMMPool(address _ammPool) external {
        _restrictGovernance();
        if (_ammPool == address(0)) revert InvalidAddress(_ammPool, "Invalid AMMPool address");
        ammPool = IAMMPool(_ammPool);
        emit AMMPoolSet(_ammPool);
    }

    /// @notice Sets the governance token address
    function setGovernanceToken(address _governanceToken) external {
        _restrictGovernance();
        if (_governanceToken == address(0)) revert InvalidAddress(_governanceToken, "Invalid GovernanceToken address");
        governanceToken = IGovernanceToken(_governanceToken);
        emit GovernanceTokenSet(_governanceToken);
    }

    /// @notice Sets the cross-chain module address
    function setCrossChainModule(address _crossChainModule) external {
        _restrictGovernance();
        if (_crossChainModule == address(0)) revert InvalidAddress(_crossChainModule, "Invalid CrossChainModule address");
        crossChainModule = ICrossChainModule(_crossChainModule);
        emit CrossChainModuleSet(_crossChainModule);
    }

    /// @notice Sets the retry oracle address
    function setRetryOracle(address _retryOracle) external {
        _restrictGovernance();
        if (_retryOracle == address(0)) revert InvalidAddress(_retryOracle, "Invalid RetryOracle address");
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        emit RetryOracleSet(_retryOracle);
    }

    /// @notice Sets the price oracle address
    function setPriceOracle(address _priceOracle) external {
        _restrictGovernance();
        if (_priceOracle == address(0)) revert InvalidAddress(_priceOracle, "Invalid PriceOracle address");
        priceOracle = IPriceOracle(_priceOracle);
        emit PriceOracleSet(_priceOracle);
    }

    /// @notice Sets the USDC address
    function setUSDC(address _usdc) external {
        _restrictGovernance();
        if (_usdc == address(0)) revert InvalidAddress(_usdc, "Invalid USDC address");
        usdc = IERC20Upgradeable(_usdc);
        emit USDCSet(_usdc);
    }

    /// @notice Retrieves user orders
    function getUserOrders(address user) external view returns (uint256[] memory) {
        return userOrders[user];
    }

    /// @notice Retrieves user equity (collateral balance)
    function getUserEquity(address user) external view returns (uint256) {
        return userEquity[user];
    }

    /// @notice Retrieves user funding balance
    function getUserFundingBalance(address user) external view returns (int256) {
        return userFundingBalance[user];
    }

    /// @notice Retrieves trader rewards for a user
    function getTraderRewards(address user) external view returns (TraderReward memory) {
        return traderRewards[user];
    }

    /// @notice Retrieves proposal details
    function getProposal(uint256 proposalId) external view returns (
        uint256 id,
        address proposer,
        string memory description,
        uint256 voteCount,
        uint64 endTime,
        bool executed,
        ProposalType proposalType
    ) {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.proposalId,
            proposal.proposer,
            proposal.description,
            proposal.voteCount,
            proposal.endTime,
            proposal.executed,
            proposal.proposalType
        );
    }

    /// @notice Checks if a user has voted on a proposal
    function hasVoted(address user, uint256 proposalId) external view returns (bool) {
        return proposals[proposalId].hasVoted[user];
    }

    /// @notice Retrieves total staked tokens
    function getTotalStaked() external view returns (uint256) {
        return totalStaked;
    }

    /// @notice Retrieves staked tokens for a user
    function getStakedTokens(address user) external view returns (uint256) {
        return stakedTokens[user];
    }

    /// @notice Retrieves LP reward pool balance
    function getLPRewardPool() external view returns (uint256) {
        return lpRewardPool;
    }

    /// @notice Retrieves governance reward pool balance
    function getGovernanceRewardPool() external view returns (uint256) {
        return governanceRewardPool;
    }

    /// @notice Retrieves funding parameters
    function getFundingParameters() external view returns (uint256, uint256, uint256) {
        return (fundingRateCapBps, liquidationFeeBps, MAX_LEVERAGE);
    }

    /// @notice Fallback function to receive native tokens
    receive() external payable {}
}
