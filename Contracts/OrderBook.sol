// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "./PriceOracle.sol";
import "./GovernanceModule.sol";
import "./AMMPool.sol";
import "./GovernanceToken.sol";
import "./CrossChainModule.sol";
import "./CrossChainRetryOracle.sol";

/// @title OrderBook - Advanced DEX order book with AMM, governance token, and multi-oracle integration
/// @notice Manages limit, market, and stop-loss orders with concentrated liquidity, gasless trading, and cross-chain functionality
/// @dev Uses UUPS proxy, GovernanceModule, AMMPool, GovernanceToken, CrossChainModule, and PriceOracle for price data
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

    /// @notice Structure representing an order
    struct Order {
        address user; // Order creator
        bool isBuy; // True for buy, false for sell
        bool isMarket; // True for market order
        bool isStopLoss; // True for stop-loss order
        uint256 price; // Price per token in wei (0 for market)
        uint256 triggerPrice; // Trigger price for stop-loss
        uint256 amount; // Token amount
        uint256 timestamp; // Creation time
        uint256 expiryTimestamp; // Expiry time (0 for no expiry)
        bool locked; // True if locked for lending
        uint256 orderId; // Unique global order ID
        address tokenA; // Base token
        address tokenB; // Quote token
        bool useConcentratedLiquidity; // Use AMM concentrated liquidity
    }

    /// @notice Structure for fee tiers
    struct FeeTier {
        uint256 orderSizeThreshold; // Minimum order size in wei
        uint256 feeRateBps; // Fee rate in basis points
    }

    /// @notice Structure for order book snapshot
    struct Snapshot {
        uint256 timestamp; // Snapshot time
        uint256[] bidOrderIds; // Active bid IDs
        uint256[] askOrderIds; // Active ask IDs
    }

    /// @notice Structure for signed order
    struct SignedOrder {
        address user;
        bool isBuy;
        bool isMarket;
        bool isStopLoss;
        uint256 price;
        uint256 triggerPrice;
        uint256 amount;
        uint256 expiryTimestamp;
        address tokenA;
        address tokenB;
        bool useConcentratedLiquidity;
        uint256 nonce;
        bytes signature;
    }

    /// @notice Structure for governance proposal
    struct Proposal {
        uint256 proposalId; // Unique ID
        address proposer; // Creator
        string description; // Proposal details
        uint256 voteCount; // Total votes
        uint256 endTime; // Voting deadline
        bool executed; // Execution status
        ProposalType proposalType; // Type of proposal
        bytes data; // Encoded data for execution
        mapping(address => bool) hasVoted; // Voter tracking
    }

    /// @notice Enum for proposal types
    enum ProposalType {
        ParameterChange, // Change contract parameters
        Upgrade, // Upgrade contract implementation
        TreasuryAllocation, // Allocate treasury funds
        Other // General proposals
    }

    /// @notice Structure for trader rewards
    struct TraderReward {
        uint256 accumulatedFees; // Fees paid by trader
        uint256 lastClaimTimestamp; // Last reward claim time
        uint256 unclaimedTokens; // Unclaimed governance tokens
    }

    /// @notice Max-heap for bids (price desc, timestamp asc)
    uint256[] public bidHeap;
    /// @notice Min-heap for asks (price asc, timestamp asc)
    uint256[] public askHeap;
    /// @notice Mapping of order IDs to Order structs
    mapping(uint256 => Order) public orders;
    /// @notice Mapping of user addresses to their order IDs
    mapping(address => uint256[]) public userOrders;
    /// @notice Mapping of order IDs to heap index
    mapping(uint256 => uint256) public orderHeapIndex;
    /// @notice Mapping to track order existence
    mapping(uint256 => bool) public orderExists;
    /// @notice Stop-loss orders by user
    mapping(address => uint256[]) public stopLossOrders;
    /// @notice Global order ID counter
    uint256 public nextOrderId;
    /// @notice Governance module
    GovernanceModule public governanceModule;
    /// @notice AMM pool for liquidity
    AMMPool public ammPool;
    /// @notice Governance token for voting and rewards
    GovernanceToken public governanceToken;
    /// @notice Cross-chain module
    CrossChainModule public crossChainModule;
    /// @notice Cross-chain retry oracle
    CrossChainRetryOracle public retryOracle;
    /// @notice Price oracle for price data
    PriceOracle public priceOracle;
    /// @notice Maximum orders per user
    uint256 public constant MAX_ORDERS_PER_USER = 100;
    /// @notice Maximum matches per transaction
    uint256 public constant MAX_MATCHES_PER_TX = 10;
    /// @notice Fee tiers array
    FeeTier[] public feeTiers;
    /// @notice User types (0 = retail, 1 = institutional)
    mapping(address => uint8) public userTypes;
    /// @notice Cross-chain order mappings (chainId => orderId => status)
    mapping(uint16 => mapping(uint256 => bool)) public crossChainOrders;
    /// @notice Cross-chain match results (chainId => matchId => status)
    mapping(uint16 => mapping(uint256 => bool)) public crossChainMatches;
    /// @notice Emergency withdrawal enabled flag
    bool public emergencyWithdrawalEnabled;
    /// @notice Match ID counter for cross-chain matches
    uint256 public nextMatchId;
    /// @notice Nonce for signed orders
    mapping(address => uint256) public nonces;
    /// @notice Snapshots of order book
    Snapshot[] public snapshots;
    /// @notice LP reward pool balance
    uint256 public lpRewardPool;
    /// @notice Governance reward pool balance
    uint256 public governanceRewardPool;
    /// @notice Staked governance tokens
    mapping(address => uint256) public stakedTokens;
    /// @notice Total staked tokens
    uint256 public totalStaked;
    /// @notice Governance proposals
    mapping(uint256 => Proposal) public proposals;
    /// @notice Proposal counter
    uint256 public nextProposalId;
    /// @notice Voting duration
    uint256 public constant VOTING_DURATION = 3 days;
    /// @notice Volatility threshold for liquidity adjustment
    uint256 public volatilityThreshold;
    /// @notice Liquidity range multiplier
    uint256 public liquidityRangeMultiplier;
    /// @notice Trader rewards mapping
    mapping(address => TraderReward) public traderRewards;
    /// @notice Reward rate per fee (in basis points)
    uint256 public rewardRateBps;
    /// @notice Minimum fees for reward eligibility
    uint256 public minFeesForReward;
    /// @notice Reward claim cooldown
    uint256 public rewardClaimCooldown;
    /// @notice Oracle price staleness threshold
    uint256 public oracleStalenessThreshold;

    /// @notice Custom errors
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

    /// @notice Events
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
    event OrderCancelled(address indexed user, uint256 orderId);
    event OrderLocked(uint256 orderId);
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
    event FeeTiersUpdated(FeeTier[] feeTiers);
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

    /// @dev EIP-712 typehash for signed orders
    bytes32 private constant ORDER_TYPEHASH = keccak256(
        "Order(address user,bool isBuy,bool isMarket,bool isStopLoss,uint256 price,uint256 triggerPrice,uint256 amount,uint256 expiryTimestamp,address tokenA,address tokenB,bool useConcentratedLiquidity,uint256 nonce)"
    );

    /// @dev Disable initializer on implementation
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _governanceModule GovernanceModule address
    /// @param _ammPool AMMPool address
    /// @param _governanceToken GovernanceToken address
    /// @param _crossChainModule CrossChainModule address
    /// @param _retryOracle CrossChainRetryOracle address
    /// @param _priceOracle PriceOracle address
    function initialize(
        address _governanceModule,
        address _ammPool,
        address _governanceToken,
        address _crossChainModule,
        address _retryOracle,
        address _priceOracle
    ) external initializer {
        if (_governanceModule == address(0)) revert InvalidGovernance(_governanceModule);
        if (_ammPool == address(0)) revert InvalidAddress(_ammPool, "Invalid AMMPool address");
        if (_governanceToken == address(0)) revert InvalidAddress(_governanceToken, "Invalid GovernanceToken address");
        if (_crossChainModule == address(0)) revert InvalidAddress(_crossChainModule, "Invalid CrossChainModule address");
        if (_retryOracle == address(0)) revert InvalidAddress(_retryOracle, "Invalid RetryOracle address");
        if (_priceOracle == address(0)) revert InvalidAddress(_priceOracle, "Invalid PriceOracle address");

        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __EIP712_init("OrderBook", "1");

        governanceModule = GovernanceModule(_governanceModule);
        ammPool = AMMPool(_ammPool);
        governanceToken = GovernanceToken(_governanceToken);
        crossChainModule = CrossChainModule(_crossChainModule);
        retryOracle = CrossChainRetryOracle(_retryOracle);
        priceOracle = PriceOracle(_priceOracle);

        nextOrderId = 1;
        nextMatchId = 1;
        nextProposalId = 1;
        volatilityThreshold = 1e16; // 1% volatility
        liquidityRangeMultiplier = 2;
        rewardRateBps = 100; // 1% of fees as rewards
        minFeesForReward = 1e16; // Minimum fees for reward eligibility
        rewardClaimCooldown = 1 days;
        oracleStalenessThreshold = 1 hours;

        feeTiers.push(FeeTier({orderSizeThreshold: 0, feeRateBps: 30}));
        feeTiers.push(FeeTier({orderSizeThreshold: 1e18, feeRateBps: 10}));

        emit GovernanceModuleSet(_governanceModule);
        emit AMMPoolSet(_ammPool);
        emit GovernanceTokenSet(_governanceToken);
        emit CrossChainModuleSet(_crossChainModule);
        emit RetryOracleSet(_retryOracle);
        emit PriceOracleSet(_priceOracle);
        emit FeeTiersUpdated(feeTiers);
        emit VolatilityThresholdSet(volatilityThreshold);
        emit LiquidityRangeMultiplierSet(liquidityRangeMultiplier);
        emit RewardParametersSet(rewardRateBps, minFeesForReward, rewardClaimCooldown);
        emit OracleStalenessThresholdSet(oracleStalenessThreshold);
    }

    /// @dev Authorizes upgrades via governance
    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(governanceModule)) revert Unauthorized();
    }

    /// @notice Places a limit, market, or stop-loss order
    /// @param isBuy True for buy order, false for sell
    /// @param isMarket True for market order
    /// @param isStopLoss True for stop-loss order
    /// @param price Price per token in wei (0 for market)
    /// @param triggerPrice Trigger price for stop-loss
    /// @param amount Token amount
    /// @param tokenA Base token address
    /// @param tokenB Quote token address
    /// @param expiryTimestamp Expiry time (0 for no expiry)
    /// @param useConcentratedLiquidity True to use AMM concentrated liquidity
    function placeOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint256 price,
        uint256 triggerPrice,
        uint256 amount,
        address tokenA,
        address tokenB,
        uint256 expiryTimestamp,
        bool useConcentratedLiquidity
    ) external whenNotPaused nonReentrant {
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
            useConcentratedLiquidity
        );
        if (isMarket) {
            matchOrders(0);
        }
    }

    /// @notice Places a signed order (gasless)
    /// @param signedOrder Signed order data
    function placeOrderWithSignature(SignedOrder calldata signedOrder) external whenNotPaused nonReentrant {
        bytes32 structHash = keccak256(abi.encode(
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
        ));
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
            signedOrder.useConcentratedLiquidity
        );

        if (signedOrder.isMarket) {
            matchOrders(0);
        }
    }

    /// @notice Submits an off-chain order (for layer-2)
    /// @param isBuy True for buy order, false for sell
    /// @param isMarket True for market order
    /// @param isStopLoss True for stop-loss order
    /// @param price Price per token in wei (0 for market)
    /// @param triggerPrice Trigger price for stop-loss
    /// @param amount Token amount
    /// @param tokenA Base token address
    /// @param tokenB Quote token address
    /// @param expiryTimestamp Expiry time (0 for no expiry)
    /// @param useConcentratedLiquidity True to use AMM concentrated liquidity
    function submitOffChainOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint256 price,
        uint256 triggerPrice,
        uint256 amount,
        address tokenA,
        address tokenB,
        uint256 expiryTimestamp,
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
            useConcentratedLiquidity
        );
        emit OffChainOrderSubmitted(nextOrderId - 1);
    }

    /// @notice Places a cross-chain order
    /// @param isBuy True for buy order, false for sell
    /// @param isMarket True for market order
    /// @param isStopLoss True for stop-loss order
    /// @param price Price per token in wei (0 for market)
    /// @param triggerPrice Trigger price for stop-loss
    /// @param amount Token amount
    /// @param tokenA Base token address
    /// @param tokenB Quote token address
    /// @param expiryTimestamp Expiry time (0 for no expiry)
    /// @param useConcentratedLiquidity True to use AMM concentrated liquidity
    /// @param dstChainId Destination chain ID
    /// @param adapterParams Cross-chain adapter parameters
    function placeOrderCrossChain(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint256 price,
        uint256 triggerPrice,
        uint256 amount,
        address tokenA,
        address tokenB,
        uint256 expiryTimestamp,
        bool useConcentratedLiquidity,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused nonReentrant {
        if (dstChainId == 0) revert InvalidChainId(dstChainId);
        _validateOrder(isBuy, isMarket, isStopLoss, price, triggerPrice, amount, tokenA, tokenB, expiryTimestamp);

        // Check retry oracle for network status
        CrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(uint64(dstChainId));
        if (!status.retryRecommended || !status.bridgeOperational) revert CrossChainModule.RetryNotRecommended(dstChainId);

        uint256 orderId = nextOrderId++;
        if (crossChainOrders[dstChainId][orderId]) revert CrossChainOrderExists(dstChainId, orderId);

        IERC20Upgradeable collateralToken = IERC20Upgradeable(isBuy ? tokenB : tokenA);
        uint256 collateral = isMarket ? amount : price.mul(amount);
        collateralToken.safeTransferFrom(msg.sender, address(this), collateral);

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

        crossChainModule.batchCrossChainMessages{value: msg.value}(
            _toArray(dstChainId),
            _toArray(ammPool.chainIdToAxelarChain(dstChainId)),
            _toArray(payload),
            _toArray(adapterParams),
            _toArray(block.timestamp + status.recommendedRetryDelay)
        );
        crossChainOrders[dstChainId][orderId] = true;

        emit CrossChainOrderPlaced(orderId, dstChainId, msg.sender, isBuy, price, amount);
    }

    /// @notice Receives cross-chain orders
    /// @param srcChainId Source chain ID
    /// @param payload Encoded order data
    function receiveCrossChainOrder(uint16 srcChainId, bytes calldata payload) external nonReentrant {
        if (msg.sender != address(crossChainModule)) revert Unauthorized();
        (
            address user,
            bool isBuy,
            bool isMarket,
            bool isStopLoss,
            uint256 price,
            uint256 triggerPrice,
            uint256 amount,
            address tokenA,
            address tokenB,
            uint256 orderId,
            uint256 expiryTimestamp,
            bool useConcentratedLiquidity
        ) = abi.decode(payload, (address, bool, bool, bool, uint256, uint256, uint256, address, address, uint256, uint256, bool));

        if (orderExists[orderId]) revert InvalidOrderId(orderId);
        if (userOrders[user].length >= MAX_ORDERS_PER_USER) return;
        _validateOrder(isBuy, isMarket, isStopLoss, price, triggerPrice, amount, tokenA, tokenB, expiryTimestamp);

        Order memory order = Order({
            user: user,
            isBuy: isBuy,
            isMarket: isMarket,
            isStopLoss: isStopLoss,
            price: price,
            triggerPrice: triggerPrice,
            amount: amount,
            timestamp: block.timestamp,
            expiryTimestamp: expiryTimestamp,
            locked: false,
            orderId: orderId,
            tokenA: tokenA,
            tokenB: tokenB,
            useConcentratedLiquidity: useConcentratedLiquidity
        });

        orders[orderId] = order;
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
    /// @param orderId Order ID to cancel
    function cancelOrder(uint256 orderId) external whenNotPaused nonReentrant {
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        Order storage order = orders[orderId];
        if (order.user != msg.sender) revert NotOrderOwner(msg.sender);
        if (order.locked) revert OrderLocked(orderId);
        if (order.expiryTimestamp != 0 && order.expiryTimestamp <= block.timestamp)
            revert OrderExpired(orderId);

        if (order.isStopLoss) {
            _removeStopLossOrder(order.user, orderId);
        }
        _removeOrder(orderId, order.isBuy);
        emit OrderCancelled(msg.sender, orderId);
    }

    /// @notice Matches orders
    /// @param minAmountOut Minimum amount out for slippage protection
    function matchOrders(uint256 minAmountOut) external whenNotPaused nonReentrant {
        if (bidHeap.length == 0 && askHeap.length == 0) revert NoMatchableOrders();
        _checkStopLossOrders();
        _matchOrders(minAmountOut, MAX_MATCHES_PER_TX);
    }

    /// @notice Matches multiple orders
    /// @param maxMatches Maximum number of matches to process
    /// @param minAmountOut Minimum amount out for slippage protection
    function matchMultipleOrders(uint256 maxMatches, uint256 minAmountOut) external whenNotPaused nonReentrant {
        if (bidHeap.length == 0 && askHeap.length == 0) revert NoMatchableOrders();
        if (maxMatches == 0 || maxMatches > MAX_MATCHES_PER_TX) revert InvalidAmount(maxMatches);
        _checkStopLossOrders();
        _matchOrders(minAmountOut, maxMatches);
    }

    /// @notice Matches orders across chains
    /// @param dstChainId Destination chain ID
    /// @param minAmountOut Minimum amount out for slippage protection
    /// @param adapterParams Cross-chain adapter parameters
    function matchOrdersCrossChain(
        uint16 dstChainId,
        uint256 minAmountOut,
        bytes calldata adapterParams
    ) external payable whenNotPaused nonReentrant {
        if (dstChainId == 0) revert InvalidChainId(dstChainId);
        if (bidHeap.length == 0 || askHeap.length == 0) revert NoMatchableOrders();

        // Check retry oracle for network status
        CrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(uint64(dstChainId));
        if (!status.retryRecommended || !status.bridgeOperational) revert CrossChainModule.RetryNotRecommended(dstChainId);

        uint256 matchId = nextMatchId++;
        if (crossChainMatches[dstChainId][matchId]) revert CrossChainMatchExists(dstChainId, matchId);

        uint256 bidId = bidHeap[0];
        uint256 askId = askHeap[0];
        Order storage bid = orders[bidId];
        Order storage ask = orders[askId];

        if (
            bid.expiryTimestamp != 0 && bid.expiryTimestamp <= block.timestamp ||
            ask.expiryTimestamp != 0 && ask.expiryTimestamp <= block.timestamp ||
            bid.price < ask.price || bid.locked || ask.locked
        ) revert NoMatchableOrders();

        uint256 tradeAmount = bid.amount.min(ask.amount);
        uint256 tradePrice = bid.isMarket || ask.isMarket ? ask.price : (bid.price.add(ask.price)).div(2);

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
            _toArray(dstChainId),
            _toArray(ammPool.chainIdToAxelarChain(dstChainId)),
            _toArray(payload),
            _toArray(adapterParams),
            _toArray(block.timestamp + status.recommendedRetryDelay)
        );
        ammPool.rebalanceReserves(dstChainId);
        crossChainMatches[dstChainId][matchId] = true;

        emit CrossChainMatchExecuted(matchId, dstChainId, bidId, askId, tradeAmount);
    }

    /// @notice Stakes governance tokens for rewards and voting
    /// @param amount Amount of tokens to stake
    function stakeTokens(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount(amount);
        governanceToken.transferFrom(msg.sender, address(this), amount);
        stakedTokens[msg.sender] = stakedTokens[msg.sender].add(amount);
        totalStaked = totalStaked.add(amount);
        emit TokensStaked(msg.sender, amount);
    }

    /// @notice Unstakes governance tokens
    /// @param amount Amount of tokens to unstake
    function unstakeTokens(uint256 amount) external nonReentrant {
        if (amount == 0 || amount > stakedTokens[msg.sender]) revert InvalidAmount(amount);
        stakedTokens[msg.sender] = stakedTokens[msg.sender].sub(amount);
        totalStaked = totalStaked.sub(amount);
        governanceToken.transfer(msg.sender, amount);
        emit TokensUnstaked(msg.sender, amount);
    }

    /// @notice Creates a governance proposal
    /// @param description Proposal description
    /// @param proposalType Type of proposal
    /// @param data Encoded data for execution
    function createProposal(
        string calldata description,
        ProposalType proposalType,
        bytes calldata data
    ) external {
        if (stakedTokens[msg.sender] == 0) revert InsufficientStake(msg.sender, stakedTokens[msg.sender]);
        if (uint8(proposalType) > uint8(ProposalType.Other)) revert InvalidProposalType(uint8(proposalType));

        uint256 proposalId = nextProposalId++;
        Proposal storage proposal = proposals[proposalId];
        proposal.proposalId = proposalId;
        proposal.proposer = msg.sender;
        proposal.description = description;
        proposal.endTime = block.timestamp.add(VOTING_DURATION);
        proposal.proposalType = proposalType;
        proposal.data = data;
        emit ProposalCreated(proposalId, msg.sender, description, proposalType);
    }

    /// @notice Votes on a proposal
    /// @param proposalId Proposal ID to vote on
    function voteOnProposal(uint256 proposalId) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert InvalidProposal(proposalId);
        if (proposal.endTime < block.timestamp) revert ProposalEnded(proposalId);
        if (proposal.hasVoted[msg.sender]) revert AlreadyVoted(msg.sender);
        if (stakedTokens[msg.sender] == 0) revert InsufficientStake(msg.sender, stakedTokens[msg.sender]));

        proposal.hasVoted[msg.sender] = true;
        proposal.voteCount = proposal.voteCount.add(stakedTokens[msg.sender]);
        emit Voted(msg.sender, proposalId, stakedTokens[msg.sender]);
    }

    /// @notice Executes a proposal
    /// @param proposalId Proposal ID to execute
    function executeProposal(uint256 proposalId) external nonReentrant {
        _restrictGovernance();
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == 0) revert InvalidProposal(proposalId);
        if (proposal.endTime > block.timestamp) revert InvalidOperation("Voting ongoing");
        if (proposal.executed) revert InvalidOperation("Already executed");
        if (proposal.voteCount < totalStaked.div(2)) revert InvalidOperation("Insufficient votes");

        proposal.executed = true;

        // Execute based on proposal type
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
        // ProposalType.Other requires custom handling, executed externally if needed

        emit ProposalExecuted(proposalId);
    }

    /// @notice Claims trader rewards
    function claimTraderRewards() external nonReentrant {
        TraderReward storage reward = traderRewards[msg.sender];
        if (reward.accumulatedFees < minFeesForReward) revert InsufficientFeesForReward(msg.sender, reward.accumulatedFees);
        if (block.timestamp < reward.lastClaimTimestamp + rewardClaimCooldown)
            revert RewardCooldownActive(msg.sender, reward.lastClaimTimestamp + rewardClaimCooldown);

        uint256 rewardAmount = reward.unclaimedTokens;
        reward.unclaimedTokens = 0;
        reward.lastClaimTimestamp = block.timestamp;

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

    /// @notice Sets liquidity range for concentrated liquidity
    /// @param minPrice Minimum price for liquidity range
    /// @param maxPrice Maximum price for liquidity range
    function setLiquidityRange(uint256 minPrice, uint256 maxPrice) external {
        _restrictGovernance();
        if (minPrice >= maxPrice || minPrice == 0) revert InvalidPrice(minPrice);
        _adjustLiquidityRange();
        ammPool.adjustLiquidityRange(minPrice, maxPrice);
        emit LiquidityRangeSet(minPrice, maxPrice);
    }

    /// @notice Sets volatility threshold
    /// @param _threshold New volatility threshold
    function setVolatilityThreshold(uint256 _threshold) external {
        _restrictGovernance();
        if (_threshold == 0) revert InvalidVolatility(_threshold);
        volatilityThreshold = _threshold;
        emit VolatilityThresholdSet(_threshold);
    }

    /// @notice Sets liquidity range multiplier
    /// @param _multiplier New liquidity range multiplier
    function setLiquidityRangeMultiplier(uint256 _multiplier) external {
        _restrictGovernance();
        if (_multiplier == 0) revert InvalidAmount(_multiplier);
        liquidityRangeMultiplier = _multiplier;
        emit LiquidityRangeMultiplierSet(_multiplier);
    }

    /// @notice Sets reward parameters
    /// @param _rewardRateBps Reward rate in basis points
    /// @param _minFeesForReward Minimum fees for reward eligibility
    /// @param _rewardClaimCooldown Reward claim cooldown period
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
    /// @param _threshold New staleness threshold
    function setOracleStalenessThreshold(uint256 _threshold) external {
        _restrictGovernance();
        if (_threshold == 0) revert InvalidAmount(_threshold);
        oracleStalenessThreshold = _threshold;
        emit OracleStalenessThresholdSet(_threshold);
    }

    /// @notice Locks an order
    /// @param orderId Order ID to lock
    function lockOrder(uint256 orderId) external nonReentrant {
        _restrictGovernance();
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        Order storage order = orders[orderId];
        if (order.locked) revert OrderLocked(orderId);
        order.locked = true;
        emit OrderLocked(orderId);
    }

    /// @notice Unlocks an order
    /// @param orderId Order ID to unlock
    function unlockOrder(uint256 orderId) external nonReentrant {
        _restrictGovernance();
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        Order storage order = orders[orderId];
        if (!order.locked) revert OrderNotLocked(orderId);
        order.locked = false;
        emit OrderUnlocked(orderId);
    }

    /// @notice Cancels multiple orders
    /// @param orderIds Array of order IDs to cancel
    function batchCancelOrders(uint256[] calldata orderIds) external nonReentrant {
        _restrictGovernance();
        for (uint256 i = 0; i < orderIds.length; ++i) {
            if (orderExists[orderIds[i]]) {
                Order storage order = orders[orderIds[i]];
                if (!order.locked && (order.expiryTimestamp == 0 || order.expiryTimestamp > block.timestamp)) {
                    if (order.isStopLoss) {
                        _removeStopLossOrders(order.user, orderIds[i]);
                    }
                    _removeOrder(orderIds[i], order.isBuy);
                    emit OrderCancelled(order.user, orderIds[i]);
                }
            }
        }
        emit BatchOrdersCancelled(orderIds);
    }

    /// @notice Cleans expired orders
    /// @param maxOrders Maximum number of orders to clean
    function cleanExpiredOrders(uint256 maxOrders) external nonReentrant {
        _restrictGovernance();
        uint256[] memory expiredIds = new uint256[](maxOrders);
        uint256 count = 0;

        for (uint256 i = bidHeap.length; i > 0 && count < maxOrders; i--) {
            uint256 orderId = bidHeap[i - 1];
            Order storage order = orders[orderId];
            if (order.expiryTimestamp != 0 && order.expiryTimestamp <= block.timestamp) {
                expiredIds[count] = orderId;
                _removeOrder(orderId, true);
                count++;
            }
        }

        for (uint256 i = askHeap.length; i > 0 && count < maxOrders; i--) {
            uint256 orderId = askHeap[i - 1];
            Order storage order = orders[orderId];
            if (order.expiryTimestamp != 0 && order.expiryTimestamp <= block.timestamp) {
                expiredIds[count] = orderId;
                _removeOrder(orderId, false);
                count++;
            }
        }

        if (count < maxOrders) {
            assembly { mstore(expiredIds, count) }
        }

        emit ExpiredOrdersCleaned(expiredIds);
    }

    /// @notice Takes order book snapshot
    function takeSnapshot() public nonReentrant {
        _restrictGovernance();
        snapshots.push(Snapshot({
            timestamp: block.timestamp,
            bidOrderIds: bidHeap,
            askOrderIds: askHeap
        }));
        emit SnapshotTaken(snapshots.length - 1, block.timestamp);
    }

    /// @notice Enables emergency withdrawals
    /// @param enabled True to enable, false to disable
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

        for (uint256 i = userOrderIds.length; i > 0; i--) {
            uint256 orderId = userOrderIds[i - 1];
            Order storage order = orders[orderId];
            if (order.user == msg.sender) {
                uint256 collateral = order.isMarket ? order.amount : order.price.mul(order.amount);
                if (order.isBuy) {
                    totalB = totalB.add(collateral);
                } else {
                    totalA = totalA.add(collateral);
                }
                if (order.isStopLoss) {
                    _removeStopLossOrder(msg.sender, orderId);
                }
                _removeOrder(orderId, order.isBuy);
            }
        }

        if (totalA > 0) IERC20Upgradeable(ammPool.token0()).safeTransfer(msg.sender, totalA);
        if (totalB > 0) IERC20Upgradeable(ammPool.token1()).safeTransfer(msg.sender, totalB);

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
    /// @param _feeTiers Array of fee tiers
    function setFeeTiers(FeeTier[] calldata _feeTiers) external {
        _restrictGovernance();
        if (_feeTiers.length == 0) revert InvalidFeeTier(0, 0);
        for (uint256 i = 0; i < _feeTiers.length; i++) {
            if (_feeTiers[i].feeRateBps == 0 || _feeTiers[i].feeRateBps > 1000)
                revert InvalidFeeTier(_feeTiers[i].orderSizeThreshold, _feeTiers[i].feeRateBps);
        }
        delete feeTiers;
        for (uint256 i = 0; i < _feeTiers.length; i++) {
            feeTiers.push(_feeTiers[i]);
        }
        emit FeeTiersUpdated(_feeTiers);
    }

    /// @notice Sets user type
    /// @param user User address
    /// @param userType User type (0 = retail, 1 = institutional)
    function setUserType(address user, uint8 userType) external {
        _restrictGovernance();
        if (userType > 1) revert InvalidUserType(userType);
        userTypes[user] = userType;
        emit UserTypeSet(user, userType);
    }

    /// @notice Retrieves order by ID
    /// @param orderId Order ID
    /// @return Order details
    function getOrder(uint256 orderId) external view returns (Order memory) {
        if (!orderExists[orderId]) revert InvalidOrderId(orderId);
        return orders[orderId];
    }

    /// @notice Retrieves bid order IDs
    /// @return Array of bid order IDs
    function getBids() external view returns (uint256[] memory) {
        return bidHeap;
    }

    /// @notice Retrieves ask order IDs
    /// @return Array of ask order IDs
    function getAsks() external view returns (uint256[] memory) {
        return askHeap;
    }

    /// @notice Retrieves fee tiers
    /// @return Array of fee tiers
    function getFeeTiers() external view returns (FeeTier[] memory) {
        return feeTiers;
    }

    /// @notice Retrieves snapshot
    /// @param snapshotId Snapshot ID
    /// @return Snapshot details
    function getSnapshot(uint256 snapshotId) external view returns (Snapshot memory) {
        return snapshots[snapshotId];
    }

    /// @notice Retrieves stop-loss orders for a user
    /// @param user User address
    /// @return Array of stop-loss order IDs
    function getStopLossOrders(address user) external view returns (uint256[] memory) {
        return stopLossOrders[user];
    }

    /// @notice Retrieves aggregated price from PriceOracle
    /// @param tokenA Base token address
    /// @param tokenB Quote token address
    /// @return Aggregated price in 1e18 precision
    function getAggregatedPrice(address tokenA, address tokenB) public view returns (uint256) {
        try priceOracle.getCurrentPairPrice(address(this), tokenA) returns (uint256 price, bool cachedStatus) {
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
        uint256 price,
        uint256 triggerPrice,
        uint256 amount,
        address tokenA,
        address tokenB,
        uint256 expiryTimestamp,
        bool useConcentratedLiquidity
    ) internal {
        _validateOrder(isBuy, isMarket, isStopLoss, price, triggerPrice, amount, tokenA, tokenB, expiryTimestamp);
        if (userOrders[user].length >= MAX_ORDERS_PER_USER) revert TooManyOrders(user);

        IERC20Upgradeable collateralToken = IERC20Upgradeable(isBuy ? tokenB : tokenA);
        uint256 collateral = isMarket ? amount : price.mul(amount);
        collateralToken.safeTransferFrom(user, address(this), collateral);

        uint256 orderId = nextOrderId++;
        Order memory order = Order({
            user: user,
            isBuy: isBuy,
            isMarket: isMarket,
            isStopLoss: isStopLoss,
            price: price,
            triggerPrice: triggerPrice,
            amount: amount,
            timestamp: block.timestamp,
            expiryTimestamp: expiryTimestamp,
            locked: false,
            orderId: orderId,
            tokenA: tokenA,
            tokenB: tokenB,
            useConcentratedLiquidity: useConcentratedLiquidity
        });

        orders[orderId] = order;
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

    /// @dev Validates order parameters
    function _validateOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint256 price,
        uint256 triggerPrice,
        uint256 amount,
        address tokenA,
        address tokenB,
        uint256 expiryTimestamp
    ) internal view {
        if (!isMarket && !isStopLoss && price == 0) revert InvalidPrice(price);
        if (isStopLoss && triggerPrice == 0) revert InvalidTriggerPrice(triggerPrice);
        if (amount == 0) revert InvalidAmount(amount);
        if (tokenA != ammPool.token0() || tokenB != ammPool.token1())
            revert InvalidTokenPair(tokenA, tokenB);
        if (expiryTimestamp != 0 && expiryTimestamp <= block.timestamp)
            revert InvalidExpiry(expiryTimestamp);
    }

    /// @dev Checks and triggers stop-loss orders
    function _checkStopLossOrders() internal {
        uint256 currentPrice = getAggregatedPrice(ammPool.token0(), ammPool.token1());
        address[] memory users = new address[](userOrders.length);
        uint256 userCount = 0;

        // Collect unique users with orders
        for (uint256 i = 0; i < userOrders.length; i++) {
            if (userOrders[i].length > 0) {
                users[userCount] = userOrders[i];
                userCount++;
            }
        }

        // Iterate over users with stop-loss orders
        for (uint256 i = 0; i < userCount; i++) {
            address user = users[i];
            uint256[] storage userStopLoss = stopLossOrders[user];
            for (uint256 j = userStopLoss.length; j > 0; j--) {
                uint256 orderId = userStopLoss[j - 1];
                Order storage order = orders[orderId];
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
    }

    /// @dev Matches orders internally
    function _matchOrders(uint256 minAmountOut, uint256 maxMatches) internal {
        uint256 currentPrice = getAggregatedPrice(ammPool.token0(), ammPool.token1());
        uint256 matches = 0;

        // Adjust liquidity range dynamically
        _adjustLiquidityRange();

        while (bidHeap.length > 0 && askHeap.length > 0 && matches < maxMatches) {
            uint256 bidId = bidHeap[0];
            uint256 askId = askHeap[0];
            Order storage bid = orders[bidId];
            Order storage ask = orders[askId];

            if (
                bid.expiryTimestamp != 0 && bid.expiryTimestamp <= block.timestamp ||
                ask.expiryTimestamp != 0 && ask.expiryTimestamp <= block.timestamp
            ) {
                if (bid.expiryTimestamp != 0 && bid.expiryTimestamp <= block.timestamp) {
                    _removeOrder(bidId, true);
                }
                if (ask.expiryTimestamp != 0 && ask.expiryTimestamp <= block.timestamp) {
                    _removeOrder(askId, false);
                }
                continue;
            }

            bool isMarketMatch = bid.isMarket || ask.isMarket;
            if (!isMarketMatch && bid.price < ask.price || bid.locked || ask.locked) break;

            uint256 tradePrice;
            if (isMarketMatch) {
                tradePrice = ask.price;
                if (tradePrice == 0 || tradePrice > currentPrice.mul(105).div(100) || tradePrice < currentPrice.mul(95).div(100))
                    revert InvalidPrice(tradePrice);
            } else {
                tradePrice = bid.useConcentratedLiquidity || ask.useConcentratedLiquidity
                    ? ammPool.getConcentratedPrice(bid.tokenA, bid.tokenB)
                    : (bid.price.add(ask.price)).div(2);
            }

            uint256 tradeValue = tradePrice.mul(bid.amount.min(ask.amount));
            uint256 feeRate = _getFeeRate(msg.sender, tradeValue);
            uint256 tradeAmount = bid.amount.min(ask.amount);
            uint256 totalFee = tradeAmount.mul(tradePrice).mul(feeRate).div(10000);

            // Update trader rewards
            _updateTraderRewards(bid.user, totalFee);
            _updateTraderRewards(ask.user, totalFee);

            // Split fee: 50% treasury, 25% LP, 25% governance
            uint256 lpFee = totalFee.div(4);
            uint256 govFee = totalFee.div(4);
            uint256 treasuryFee = totalFee.sub(lpFee).sub(govFee);
            lpRewardPool = lpRewardPool.add(lpFee);
            governanceRewardPool = governanceRewardPool.add(govFee);

            IERC20Upgradeable(bid.tokenB).approve(address(ammPool), tradeAmount.mul(tradePrice));
            IERC20Upgradeable(ask.tokenA).approve(address(ammPool), tradeAmount);
            uint256 amountOut = ammPool.swap(
                bid.tokenA == ammPool.token0() ? tradeAmount : 0,
                bid.tokenA == ammPool.token0() ? 0 : tradeAmount,
                address(this),
                ""
            );

            if (amountOut < minAmountOut) revert SlippageExceeded(amountOut, minAmountOut);

            IERC20Upgradeable(bid.tokenA).safeTransfer(bid.user, tradeAmount);
            IERC20Upgradeable(ask.tokenB).safeTransfer(ask.user, tradeAmount.mul(tradePrice).sub(totalFee));
            IERC20Upgradeable(ask.tokenB).safeTransfer(ammPool.treasury(), treasuryFee);

            bid.amount = bid.amount.sub(tradeAmount);
            ask.amount = ask.amount.sub(tradeAmount);

            if (bid.amount == 0) {
                _removeOrder(bidId, true);
            } else {
                _heapifyDownBids(0);
            }
            if (ask.amount == 0) {
                _removeOrder(askId, false);
            } else {
                _heapifyDownAsks(0);
            }

            emit OrdersMatched(bidId, askId, tradePrice, tradeAmount, totalFee);
            matches++;
        }
    }

    /// @dev Removes an order
    function _removeOrder(uint256 orderId, bool isBuy) internal {
        Order storage order = orders[orderId];
        uint256 index = orderHeapIndex[orderId];
        uint256[] storage heap = isBuy ? bidHeap : askHeap;

        IERC20Upgradeable collateralToken = IERC20Upgradeable(isBuy ? order.tokenB : order.tokenA);
        uint256 collateral = order.isMarket ? order.amount : order.price.mul(order.amount);
        collateralToken.safeTransfer(order.user, collateral);

        if (!order.isMarket && !order.isStopLoss) {
            heap[index] = heap[heap.length - 1];
            orderHeapIndex[heap[index]] = index;
            heap.pop();
            if (index < heap.length) {
                if (isBuy) {
                    _heapifyDownBids(index);
                } else {
                    _heapifyDownAsks(index);
                }
            }
        }

        delete orderHeapIndex[orderId];
        delete orderExists[orderId];
        delete orders[orderId];

        _removeUserOrder(order.user, orderId);
    }

    /// @dev Heapifies up bids
    function _heapifyUpBids(uint256 index) internal {
        while (index > 0) {
            uint256 parent = (index - 1) / 2;
            uint256 childId = bidHeap[index];
            uint256 parentId = bidHeap[parent];
            Order storage child = orders[childId];
            Order storage parentOrder = orders[parentId];

            if (
                child.price > parentOrder.price ||
                (child.price == parentOrder.price && child.timestamp < parentOrder.timestamp)
            ) {
                bidHeap[index] = parentId;
                bidHeap[parent] = childId;
                orderHeapIndex[childId] = parent;
                orderHeapIndex[parentId] = index;
                index = parent;
            } else {
                break;
            }
        }
    }

    /// @dev Heapifies down bids
    function _heapifyDownBids(uint256 index) internal {
        uint256 length = bidHeap.length;
        while (true) {
            uint256 left = 2 * index + 1;
            uint256 right = 2 * index + 2;
            uint256 largest = index;
            uint256 largestId = bidHeap[largest];

            if (left < length) {
                uint256 leftId = bidHeap[left];
                if (
                    orders[leftId].price > orders[largestId].price ||
                    (orders[leftId].price == orders[largestId].price &&
                        orders[leftId].timestamp < orders[largestId].timestamp)
                ) {
                    largest = left;
                    largestId = leftId;
                }
            }

            if (right < length) {
                uint256 rightId = bidHeap[right];
                if (
                    orders[rightId].price > orders[largestId].price ||
                    (orders[rightId].price == orders[largestId].price &&
                        orders[rightId].timestamp < orders[largestId].timestamp)
                ) {
                    largest = right;
                }
            }

            if (largest != index) {
                uint256 swapId = bidHeap[largest];
                bidHeap[largest] = bidHeap[index];
                bidHeap[index] = swapId;
                orderHeapIndex[bidHeap[index]] = index;
                orderHeapIndex[swapId] = largest;
                index = largest;
            } else {
                break;
            }
        }
    }

    /// @dev Heapifies up asks
    function _heapifyUpAsks(uint256 index) internal {
        while (index > 0) {
            uint256 parent = (index - 1) / 2;
            uint256 childId = askHeap[index];
            uint256 parentId = askHeap[parent];
            Order storage child = orders[childId];
            Order storage parentOrder = orders[parentId];

            if (
                child.price < parentOrder.price ||
                (child.price == parentOrder.price && child.timestamp < parentOrder.timestamp)
            ) {
                askHeap[index] = parentId;
                askHeap[parent] = childId;
                orderHeapIndex[childId] = parent;
                orderHeapIndex[parentId] = index;
                index = parent;
            } else {
                break;
            }
        }
    }

    /// @dev Heapifies down asks
    function _heapifyDownAsks(uint256 index) internal {
        uint256 length = askHeap.length;
        while (true) {
            uint256 left = 2 * index + 1;
            uint256 right = 2 * index + 2;
            uint256 smallest = index;
            uint256 smallestId = askHeap[smallest];

            if (left < length) {
                uint256 leftId = askHeap[left];
                if (
                    orders[leftId].price < orders[smallestId].price ||
                    (orders[leftId].price == orders[smallestId].price &&
                    orders[leftId].timestamp < orders[smallestId].timestamp)
                ) {
                    smallest = left;
                    smallestId = leftId;
                }
            }

            if (right < length) {
                uint256 rightId = askHeap[right];
                if (
                    orders[rightId].price < orders[smallestId].price ||
                    (orders[rightId].price == orders[smallestId].price &&
                    orders[rightId].timestamp < orders[smallestId].timestamp)
                )
                {
                    smallest = right;
                }
            }

            if (smallest != index) {
                uint256 swapId = askHeap[smallest];
                askHeap[smallest] = askHeap[index];
                askHeap[index] = swapId;
                orderHeapIndex[askHeap[index]] = index;
                orderHeapIndex[swapId] = smallest;
                index = smallest;
            } else {
                break;
            }
        }
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

    /// @dev Gets fee rate for a user
    function _getFeeRate(address user, uint256 tradeValue) internal view returns (uint256) {
        uint8 userType = userTypes[user];
        uint256 baseFee = feeTiers[feeTiers.length - 1].feeRateBps;

        for (uint256 i = 0; i < feeTiers.length; i++) {
            if (tradeValue >= feeTiers[i].orderSizeThreshold) {
                baseFee = feeTiers[i].feeRateBps;
                break;
            }
        }

        return userType == 1 ? baseFee.div(2) : baseFee;
    }

    /// @dev Restricts to governance
    function _restrictGovernance() internal view {
        if (msg.sender != address(governanceModule)) revert Unauthorized();
    }

    /// @dev Adjusts liquidity range based on market volatility
    function _adjustLiquidityRange() internal {
        uint256 volatility = ammPool.getVolatility();
        if (volatility > volatilityThreshold) {
            uint256 currentPrice = getAggregatedPrice(ammPool.token0(), ammPool.token1());
            uint256 rangeDelta = currentPrice.mul(volatility).mul(liquidityRangeMultiplier).div(1e18);
            uint256 minPrice = currentPrice.sub(rangeDelta);
            uint256 maxPrice = currentPrice.add(rangeDelta);
            ammPool.adjustLiquidityRange(minPrice, maxPrice);
            emit LiquidityRangeSet(minPrice, maxPrice);
        }
    }

    /// @dev Updates trader rewards
    function _updateTraderRewards(address user, uint256 fee) internal {
        TraderReward storage reward = traderRewards[user];
        reward.accumulatedFees = reward.accumulatedFees.add(fee);
        if (reward.accumulatedFees >= minFeesForReward) {
            uint256 rewardAmount = fee.mul(rewardRateBps).div(10000);
            reward.unclaimedTokens = reward.unclaimedTokens.add(rewardAmount);
        }
    }

    /// @dev Executes parameter change proposal
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
            oracleStalenessThreshold = value;
            emit OracleStalenessThresholdSet(value);
        } else {
                revert InvalidOperation("Unknown parameter");
            }
        }

        /// @dev Converts single value to array
        function _toArray(uint16 item) internal pure returns (uint16[] memory) {
            uint16[] memory arr = new uint64[](1);
            arr[0] = item;
            return arr;
        }

        /// @dev Converts single value to array
        function _toArray(string memory item) internal pure returns (string memory[] memory) {
            string memory[] memory arr = new string memory[][](1);
            arr[0].memory = item;
            return arr;
        }

        /// @dev Converts single value to array
        function _toArray(bytes memory item) internal pure returns bytes {
            bytes memory[] memory arr = new bytes[][](1);
            arr[0]. = bytes memory(item);
            return arr;
        }

        /// @dev Converts single value to array
        function _toArray(uint256 items) internal pure returns (uint256[] memory) {
            uint256[] memory arr = new uint256[](1);
            arr[0]. = item;
            return arr;
        }

        /// @dev Returns minimum value
        function min(uint256 a, uint256 b) internal pure returns (uint256) {
            return a <= b ? a : b;
        }
}
