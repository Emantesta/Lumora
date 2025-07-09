// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC721ReceiverUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import {FullMath} from "@uniswap/v3-core/contracts/libraries/FullMath.sol";
import {TickMath} from "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import {ConcentratedLiquidity} from "./ConcentratedLiquidity.sol";
import {CrossChainModule} from "./CrossChainModule.sol";
import {FallbackPool} from "./FallbackPool.sol";
import {GovernanceModule} from "./GovernanceModule.sol";
import {DynamicFeeLibrary} from "./DynamicFeeLibrary.sol";
import {TickMathLibrary} from "./TickMathLibrary.sol";
import {IAMMPool, IPositionManager, IPriceOracle, ICommonStructs} from "./Interfaces.sol";
import {UD60x18, ud} from "@prb/math/src/UD60x18.sol";

// Interface for OrderBook.sol
interface IOrderBook {
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
    ) external returns (uint256 orderId);

    function placePerpetualOrder(
        address tokenA,
        address tokenB,
        uint256 amount,
        bool isBuy,
        uint256 leverage,
        uint256 margin
    ) external returns (uint256 orderId);

    function matchOrders(uint256 minAmountOut) external;

    function getAggregatedPrice(address tokenA, address tokenB) external view returns (uint256);

    function getOrder(uint256 orderId) external view returns (
        address user,
        address tokenA,
        address tokenB,
        uint96 price,
        uint96 amount,
        uint96 triggerPrice,
        uint64 timestamp,
        uint64 expiryTimestamp,
        uint256 returnedorderId,
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        bool locked,
        bool useConcentratedLiquidity,
        bool isPerpetual,
        uint256 leverage,
        uint256 initialMargin,
        uint256 maintenanceMargin,
        uint256 lastFundingTimestamp,
        int256 cumulativeFunding
    );

    function getBids() external view returns (uint256[] memory);
    function getAsks() external view returns (uint256[] memory);

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
    ) external;
}

// Uniswap V2 Callee Interface for flash swaps
interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

/// @title AMMPool - Main upgradeable AMM pool contract with modularized functionality and OrderBook integration
/// @notice Acts as the entry point for AMM operations, delegating to specialized modules and the OrderBook
/// @dev Retains state and external API, uses UUPS upgradeability, integrates with modules and OrderBook
contract AMMPool is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IERC721ReceiverUpgradeable,
    IAMMPool
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable constants
    bytes32 public immutable VERSION;
    uint256 public immutable MIN_TIMELOCK;
    uint256 public immutable MAX_TIMELOCK;
    uint256 public immutable MAX_BATCH_SIZE;
    uint256 public immutable MAX_GAS_LIMIT;
    uint256 public immutable GOVERNANCE_TIMELOCK;
    uint256 public immutable MAX_RETRIES;
    uint256 public immutable MAX_ORACLE_RETRIES;
    uint24 public immutable TICK_SPACING;
    uint128 public immutable MAX_LIQUIDITY_PER_TICK;
    uint256 public immutable RETRY_DELAY;

    // Storage variables
    address public override tokenA;
    address public override tokenB;
    address public treasury;
    address public tokenBridge;
    address public axelarGasService;
    address public positionManager;
    address public positionAdjuster;
    address public governance;
    address public crossChainModuleAddress;
    address public primaryPriceOracle;
    address[] public fallbackPriceOracles;
    address public orderBook; // Reference to OrderBook contract
    uint256 public lpFeeShare;
    uint256 public treasuryFeeShare;
    uint256 public totalLiquidity;
    uint256 public amplificationFactor;
    uint256 public targetReserveRatio;
    uint256 public emaPeriod;
    uint256 public volatilityThreshold;
    uint256 public priceDeviationThreshold;
    bool public paused;
    uint256 public lastPrice;
    int24 public currentTick;
    uint256 public feeGrowthGlobal0X128;
    uint256 public feeGrowthGlobal1X128;
    uint256 public positionCounter;
    uint256 public failedMessageCount;
    uint256 public proposalCount;

    // DynamicFeeLibrary state
    DynamicFeeLibrary.State public feeState;

    struct Reserves {
        uint64 reserveA;
        uint64 reserveB;
        uint128 crossChainReserveA;
        uint128 crossChainReserveB;
    }
    Reserves public reserves;

    struct FallbackReserves {
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalLiquidity;
    }
    FallbackReserves public fallbackReserves;

    struct Tick {
        uint128 liquidityGross;
        int128 liquidityNet;
        uint256 feeGrowthOutside0X128;
        uint256 feeGrowthOutside1X128;
    }

    struct Position {
        address owner;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint128 tokensOwed0;
        uint128 tokensOwed1;
    }

    struct GovernanceProposal {
        address target;
        bytes data;
        uint256 proposedAt;
        bool executed;
    }

    // Mappings
    mapping(address => uint256) public liquidityBalance;
    mapping(address => mapping(address => uint256)) public lpFees;
    mapping(uint16 => bool) public chainPaused;
    mapping(uint16 => bytes) public trustedRemotePools;
    mapping(uint16 => mapping(uint64 => bool)) public usedNonces;
    mapping(uint16 => uint256) public chainTimelocks;
    mapping(address => uint8) public tokenBridgeType;
    mapping(uint8 => address) public crossChainMessengers;
    mapping(uint16 => string) public chainIdToAxelarChain;
    mapping(string => uint16) public axelarChainToChainId;
    mapping(uint16 => bytes32) public wormholeTrustedSenders;
    mapping(address => uint256) public fallbackLiquidityBalance;
    mapping(uint256 => bool) public inFallbackPool;
    mapping(uint256 => address) public authorizedAdjusters;
    mapping(uint256 => ICommonStructs.FailedMessage) public failedMessages;
    mapping(uint256 => GovernanceProposal) public governanceProposals;
    mapping(bytes32 => bool) public validatedMessages;
    mapping(int24 => Tick) public ticks;
    mapping(uint256 => Position) internal _positions;

    // Module contracts
    ConcentratedLiquidity public concentratedLiquidity;
    CrossChainModule public crossChainModule;
    FallbackPool public fallbackPool;
    GovernanceModule public governanceModule;

    // Constants
    uint256 public constant PRICE_HISTORY_SIZE = 20;
    uint256 public constant VOLATILITY_WINDOW = 10;
    uint256 public constant MAX_AMPLIFICATION = 1000;
    uint256 public constant MIN_AMPLIFICATION = 1;

    // Custom errors
    error InvalidAmount(uint256 amountA, uint256 amountB);
    error InvalidToken(address token);
    error InsufficientOutputAmount(uint256 amountOut, uint256 minAmountOut);
    error InsufficientReserve(uint256 amountOut, uint256 reserve);
    error InvalidChainId(uint16 chainId);
    error InvalidAxelarChain(string axelarChain);
    error InvalidNonce(uint64 receivedNonce, uint64 expectedNonce);
    error TimelockNotExpired(uint256 currentTime, uint256 timelock);
    error InsufficientFee(uint256 provided, uint256 required);
    error InvalidFeeRange(uint256 baseFee, uint256 maxFee);
    error InvalidFeeShare(uint256 lpFeeShare, uint256 treasuryFeeShare);
    error InvalidAddress(address addr, string message);
    error InvalidCrossChainMessage(string message);
    error ContractPaused();
    error ChainPausedError(uint16 chainId);
    error InvalidTimelock(uint256 timelock);
    error InvalidBridgeType(uint8 bridgeType);
    error InvalidReserveRatio(uint256 ratio);
    error BatchSizeExceeded(uint256 size);
    error GasLimitExceeded(uint256 gasUsed);
    error InvalidPrice(uint256 expected, uint256 actual);
    error Unauthorized();
    error InvalidAdapterParams();
    error PoolPaused();
    error ProposalNotFound(uint256 proposalId);
    error ProposalNotReady(uint256 proposalId);
    error ProposalAlreadyExecuted(uint256 proposalId);
    error GovernanceProposalFailed();
    error NegativeOraclePrice(int256 price);
    error OracleFailure();
    error PendingVRFRequest();
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error InvalidMessengerType(uint8 messengerType);
    error InvalidWormholeVAA();
    error MessengerNotSet(uint8 messengerType);
    error InvalidTick(int24 tick);
    error InvalidTickRange(int24 tickLower, int24 tickUpper);
    error PositionNotFound(uint256 positionId);
    error NotPositionOwner(uint256 positionId);
    error InsufficientLiquidity(uint128 liquidity);
    error InvalidAmplificationFactor(uint256 A);
    error TickNotInitialized(int24 tick);
    error PriceOutOfRange();
    error RetryNotReady(uint256 messageId, uint256 nextRetryTimestamp);
    error InvalidBatchSize(uint256 size);
    error InsufficientGasForBatch(uint256 required, uint256 provided);
    error InvalidOperation(string message);
    error UnauthorizedAdjuster(address caller);
    error InvalidMessage();
    error MessageNotFound(uint256 messageId);
    error OrderBookNotSet();
    error OrderBookInteractionFailed(string reason);
    error InsufficientOrderBookLiquidity(uint256 amountOut);

    // Events
    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event Swap(address indexed user, address indexed inputToken, uint256 amountIn, uint256 amountOut, uint256 fee);
    event FeesUpdated(uint16 indexed chainId, uint256 baseFee, uint256 maxFee, uint256 lpFeeShare, uint256 treasuryFeeShare);
    event Paused(address indexed caller);
    event Unpaused(address indexed caller);
    event ChainPaused(uint16 indexed chainId, address indexed caller);
    event ChainUnpaused(uint16 indexed chainId, address indexed caller);
    event ChainTimelockUpdated(uint16 indexed chainId, uint256 newTimelock);
    event TrustedRemotePoolAdded(uint16 indexed chainId, bytes poolAddress);
    event TokenBridgeUpdated(address indexed newTokenBridge);
    event TokenBridgeTypeUpdated(address indexed token, uint8 bridgeType);
    event ReservesRebalanced(uint16 indexed chainId, uint256 amountA, uint256 amountB, uint8 messengerType);
    event TargetReserveRatioUpdated(uint256 newRatio);
    event LPFeeClaimed(address indexed provider, address indexed token, uint256 amount);
    event EmergencyWithdrawal(address indexed user, uint256 amountA, uint256 amountB);
    event GovernanceUpdated(address indexed newGovernance);
    event PriceOracleUpdated(address indexed primaryOracle, address[] fallbackOracles);
    event EmaPeriodUpdated(uint256 newPeriod);
    event CrossChainMessengerUpdated(uint8 indexed messengerType, address indexed newMessenger);
    event AxelarGasServiceUpdated(address indexed newGasService);
    event ChainIdMappingUpdated(uint16 chainId, string axelarChain);
    event WormholeTrustedSenderUpdated(uint16 chainId, bytes32 senderAddress);
    event GovernanceProposalCreated(uint256 indexed proposalId, address target, bytes data, uint256 proposedAt);
    event GovernanceProposalExecuted(uint256 indexed proposalId);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event AllLPFeesClaimed(address indexed provider, uint256 amountA, uint256 amountB);
    event OracleFailover(address indexed failedOracle, address indexed newOracle);
    event FeesCollected(uint256 indexed positionId, uint256 feesOwed0, uint256 feesOwed1);
    event FallbackPoolEntered(uint256 indexed positionId, uint256 liquidity);
    event FallbackPoolExited(uint256 indexed positionId, uint256 liquidity);
    event AmplificationFactorUpdated(uint256 newA);
    event TokenTransferred(address indexed token, address indexed from, address indexed to, uint256 amount);
    event PositionUpdated(uint256 indexed positionId, int24 tickLower, int24 tickUpper, uint128 liquidity);
    event PositionAdjusterUpdated(address indexed newAdjuster);
    event PositionManagerUpdated(address indexed newPositionManager);
    event OrderBookSet(address indexed orderBook);
    event OrderBookSwap(address indexed user, address indexed inputToken, uint256 amountIn, uint256 amountOut, uint256 orderId);
    event OrderBookPerpetualPlaced(uint256 indexed orderId, address indexed user, bool isBuy, uint256 leverage, uint256 margin);

    // Modifiers
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier whenChainNotPaused(uint16 chainId) {
        if (chainPaused[chainId]) revert ChainPausedError(chainId);
        _;
    }

    modifier onlyGovernance() {
        if (msg.sender != address(governanceModule)) revert Unauthorized();
        _;
    }

    modifier onlyPositionOwner(uint256 positionId) {
        if (_positions[positionId].owner != msg.sender) revert NotPositionOwner(positionId);
        _;
    }

    modifier onlyAuthorizedAdjusters(uint256 positionId) {
        if (msg.sender != _positions[positionId].owner && msg.sender != authorizedAdjusters[positionId]) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyPositionAdjuster() {
        if (msg.sender != positionAdjuster) revert Unauthorized();
        _;
    }

    modifier onlyConcentratedLiquidity() {
        if (msg.sender != address(concentratedLiquidity)) revert Unauthorized();
        _;
    }

    modifier onlyPositionManager() {
        if (msg.sender != positionManager) revert Unauthorized();
        _;
    }

    modifier onlyCrossChainModule() {
        if (msg.sender != crossChainModuleAddress) revert Unauthorized();
        _;
    }

    modifier onlyGovernanceModule() {
        if (msg.sender != address(governanceModule)) revert Unauthorized();
        _;
    }

    modifier onlyLiquidityOrCrossChain() {
        if (msg.sender != address(concentratedLiquidity) && msg.sender != crossChainModuleAddress) revert Unauthorized();
        _;
    }

    /// @notice Adjusts the liquidity range for a position
    /// @param minPrice The minimum price for the liquidity range
    /// @param maxPrice The maximum price for the liquidity range
    // In AMMPool.sol, line 393
    function adjustLiquidityRange(uint256 minPrice, uint256 maxPrice) external override onlyPositionAdjuster {
        // Convert prices to ticks
        int24 tickLower = TickMathLibrary.priceToTick(minPrice);
        int24 tickUpper = TickMathLibrary.priceToTick(maxPrice);

        // Validate tick range
        if (tickLower >= tickUpper || tickLower < TickMath.MIN_TICK || tickUpper > TickMath.MAX_TICK) {
            revert InvalidTickRange(tickLower, tickUpper);
        }

        // Adjust liquidity range through the concentrated liquidity module
        // Assuming positionId is managed externally or a default position is used
        // For simplicity, adjust the first position owned by the caller or revert
        for (uint256 i = 1; i <= positionCounter; i++) {
            if (_positions[i].owner == msg.sender) {
                concentratedLiquidity.adjust(i, tickLower, tickUpper, _positions[i].liquidity);
                emit PositionUpdated(i, tickLower, tickUpper, _positions[i].liquidity);
                return;
            }
        }
        revert PositionNotFound(0); // No position found for the caller
    }

    /// @notice Returns the current volatility from the fee state
    /// @return The current volatility value
    function getVolatility() external view override returns (uint256) {
        return feeState.emaVolatility;
    }

    /// @notice Returns the concentrated price based on the current tick
    /// @return The current concentrated price
    function getConcentratedPrice() external view override returns (uint256) {
        uint160 sqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(feeState.currentTick);
        // Convert sqrtPriceX96 to price (assuming tokenA/tokenB pair)
        uint256 price = FullMath.mulDiv(uint256(sqrtPriceX96) * uint256(sqrtPriceX96), 1e18, 2**192);
        return price;
    }

    // Constructor
    constructor(
        string memory _version,
        uint256 _minTimelock,
        uint256 _maxTimelock,
        uint256 _maxBatchSize,
        uint256 _maxGasLimit,
        uint256 _governanceTimelock,
        uint256 _maxRetries
    ) {
        VERSION = bytes32(bytes(_version));
        MIN_TIMELOCK = _minTimelock;
        MAX_TIMELOCK = _maxTimelock;
        MAX_BATCH_SIZE = _maxBatchSize;
        MAX_GAS_LIMIT = _maxGasLimit;
        GOVERNANCE_TIMELOCK = _governanceTimelock;
        MAX_RETRIES = _maxRetries;
        MAX_ORACLE_RETRIES = 3;
        TICK_SPACING = 60;
        MAX_LIQUIDITY_PER_TICK = type(uint128).max;
        RETRY_DELAY = 1 hours;
        _disableInitializers();
    }

    // Initializer
    function initialize(
        ICommonStructs.InitParams memory params,
        address _retryOracle,
        bytes32 _oracleJobId,
        address _linkToken,
        address _orderBook
    ) external initializer {
        if (params.tokenA >= params.tokenB) revert InvalidAddress(params.tokenA, "TokenA must be less than TokenB");
        if (
            params.tokenA == address(0) ||
            params.tokenB == address(0) ||
            params.treasury == address(0) ||
            params.layerZeroEndpoint == address(0) ||
            params.axelarGateway == address(0) ||
            params.axelarGasService == address(0) ||
            params.wormholeCore == address(0) ||
            params.tokenBridge == address(0) ||
            params.primaryPriceOracle == address(0) ||
            params.governance == address(0) ||
            params.positionManager == address(0) ||
            _retryOracle == address(0) ||
            _oracleJobId == bytes32(0) ||
            _linkToken == address(0) ||
            _orderBook == address(0)
        ) revert InvalidAddress(address(0), "Zero address not allowed");
        if (params.defaultTimelock < MIN_TIMELOCK || params.defaultTimelock > MAX_TIMELOCK)
            revert InvalidTimelock(params.defaultTimelock);
        if (params.targetReserveRatio == 0)
            revert InvalidReserveRatio(params.targetReserveRatio);

        // Initialize feeState
        feeState.emaPeriod = 100;
        feeState.volatilityThreshold = 1e16;
        feeState.priceDeviationThreshold = 1e16;
        feeState.primaryPriceOracle = params.primaryPriceOracle;
        feeState.fallbackPriceOracles = params.fallbackPriceOracles;
        feeState.chainFees[1] = DynamicFeeLibrary.FeeConfig({
            baseFee: 20,
            maxFee: 100,
            volatilityMultiplier: 2
        });
        feeState.priceHistory = new uint256[](PRICE_HISTORY_SIZE);
        feeState.useConstantSum = true;
        feeState.currentTick = 0;

        // Validate fallback oracles
        bool hasValidOracle;
        for (uint256 i = 0; i < params.fallbackPriceOracles.length; i++) {
            if (params.fallbackPriceOracles[i] != address(0)) {
                hasValidOracle = true;
                break;
            }
        }
        if (!hasValidOracle) revert InvalidAddress(address(0), "No valid fallback oracle");

        // Initialize OpenZeppelin contracts
        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        // Assign state variables
        tokenA = params.tokenA;
        tokenB = params.tokenB;
        treasury = params.treasury;
        crossChainMessengers[0] = params.layerZeroEndpoint;
        crossChainMessengers[1] = params.axelarGateway;
        crossChainMessengers[2] = params.wormholeCore;
        axelarGasService = params.axelarGasService;
        tokenBridge = params.tokenBridge;
        primaryPriceOracle = params.primaryPriceOracle;
        fallbackPriceOracles = params.fallbackPriceOracles;
        governance = params.governance;
        positionManager = params.positionManager;
        orderBook = _orderBook;
        chainTimelocks[1] = params.defaultTimelock;
        targetReserveRatio = params.targetReserveRatio;
        lpFeeShare = 8333;
        treasuryFeeShare = 1667;
        emaPeriod = 100;
        volatilityThreshold = 1e16;
        priceDeviationThreshold = 1e16;
        tokenBridgeType[params.tokenA] = 1;
        tokenBridgeType[params.tokenB] = 1;
        amplificationFactor = 100;
        currentTick = 0;

        // Deploy modules
        concentratedLiquidity = new ConcentratedLiquidity(address(this));
        crossChainModule = new CrossChainModule(address(this), _retryOracle, _oracleJobId, _linkToken);
        fallbackPool = new FallbackPool(address(this));
        governanceModule = new GovernanceModule(address(this));
        crossChainModuleAddress = address(crossChainModule);

        emit PositionManagerUpdated(params.positionManager);
        emit OrderBookSet(_orderBook);
    }

    // Authorize upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // --- Uniswap V2-Compliant Functions ---

    /// @notice Uniswap V2-compliant swap function with OrderBook integration
    /// @param amount0Out Amount of tokenA (token0) to output
    /// @param amount1Out Amount of tokenB (token1) to output
    /// @param to Recipient of output tokens
    /// @param data Callback data for flash swaps (optional)
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external whenNotPaused nonReentrant returns (uint256) {
        if (amount0Out == 0 && amount1Out == 0) revert InvalidAmount(0, 0);
        if (amount0Out > 0 && amount1Out > 0) revert InvalidAmount(amount0Out, amount1Out);
        if (to == address(0)) revert InvalidAddress(to, "Invalid recipient");

        bool isTokenAInput = amount1Out > 0;
        address inputToken = isTokenAInput ? tokenA : tokenB;
        address outputToken = isTokenAInput ? tokenB : tokenA;
        uint256 amountOut = isTokenAInput ? amount1Out : amount0Out;

        uint256 fee = _getDynamicFee(1);
        uint256 amountIn = (amountOut * (reserves.reserveA + amountOut)) / (reserves.reserveB - amountOut);
        uint256 amountInWithFee = (amountIn * (10000 - fee)) / 10000;
        uint256 lpFee;
        uint256 treasuryFee;
        unchecked {
            lpFee = (amountIn * fee * lpFeeShare) / 10000;
            treasuryFee = (amountIn * fee * treasuryFeeShare) / 10000;
        }

        // Attempt to match with OrderBook first
        uint256 orderBookAmountOut = _tryOrderBookSwap(isTokenAInput, amountInWithFee, amountOut, to);
        bool useOrderBook = orderBookAmountOut >= amountOut;

        if (!useOrderBook) {
            // Fallback to AMM logic
            uint256 calculatedAmountOut = _swapConcentratedLiquidity(isTokenAInput, amountInWithFee);
            bool useFallback = false;
            if (calculatedAmountOut == 0) {
                if (feeState.useConstantSum && feeState.emaVolatility < feeState.volatilityThreshold) {
                    calculatedAmountOut = _swapConstantSum(amountInWithFee, reserves.reserveA, reserves.reserveB);
                } else {
                    calculatedAmountOut = (reserves.reserveB * amountInWithFee) / (reserves.reserveA + amountInWithFee);
                }
                if (calculatedAmountOut < amountOut || calculatedAmountOut > reserves.reserveB) {
                    calculatedAmountOut = _swapFallbackPool(isTokenAInput, amountInWithFee);
                    if (
                        calculatedAmountOut < amountOut ||
                        calculatedAmountOut > (isTokenAInput ? fallbackReserves.reserveB : fallbackReserves.reserveA)
                    ) {
                        revert InsufficientOutputAmount(calculatedAmountOut, amountOut);
                    }
                    useFallback = true;
                }
            }
            if (calculatedAmountOut < amountOut) revert InsufficientOutputAmount(calculatedAmountOut, amountOut);

            if (useFallback) {
                _updateFallbackReserves(isTokenAInput, amountIn, amountOut);
            } else {
                _updateReserves(isTokenAInput, amountIn, amountOut);
            }

            _validatePrice(inputToken, amountIn, amountOut);

            IERC20Upgradeable(inputToken).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20Upgradeable(outputToken).safeTransfer(to, amountOut);
            if (treasuryFee > 0) {
                IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
            }
            lpFees[msg.sender][inputToken] += lpFee;

            _updateVolatility();
        } else {
            // OrderBook handled the swap
            lpFees[msg.sender][inputToken] += lpFee;
            if (treasuryFee > 0) {
                IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
            }
            amountOut = orderBookAmountOut; // Update amountOut to reflect OrderBook swap
        }

        if (data.length > 0) {
            IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
        }

        emit Swap(msg.sender, inputToken, amountIn, amountOut, fee);
        return amountOut; // Return the amountOut
    }

    /// @notice Returns address of token0 (tokenA)
    function token0() external view returns (address) {
        return tokenA;
    }

    /// @notice Returns address of token1 (tokenB)
    function token1() external view returns (address) {
        return tokenB;
    }

    /// @notice Returns current dynamic fee for a chain
    /// @param chainId Chain ID (default 1 for local chain)
    /// @return fee Current fee in basis points
    function getCurrentFee(uint16 chainId) external view returns (uint256 fee) {
        return _getDynamicFee(chainId);
    }

    /// @notice Returns reserves in Uniswap V2-compliant format
    /// @return reserveA Reserve of tokenA (token0)
    /// @return reserveB Reserve of tokenB (token1)
    function getReserves() external view returns (uint64 reserveA, uint64 reserveB) {
        return (reserves.reserveA, reserves.reserveB);
    }

    // --- Core AMM Functions ---

    function addLiquidity(uint256 amountA, uint256 amountB) external whenNotPaused nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        uint256 liquidity;
        if (feeState.useConstantSum && feeState.emaVolatility < feeState.volatilityThreshold) {
            liquidity = FullMath.mulDiv(amountA + amountB, 1e18, 2 * 1e18);
        } else {
            if (totalLiquidity == 0) {
                UD60x18 sqrtResult = ud(amountA * amountB).sqrt();
                liquidity = sqrtResult.unwrap();
            } else {
                uint256 liquidityA = FullMath.mulDiv(amountA, totalLiquidity, reserves.reserveA);
                uint256 liquidityB = FullMath.mulDiv(amountB, totalLiquidity, reserves.reserveB);
                liquidity = liquidityA < liquidityB ? liquidityA : liquidityB;
            }
        }

        unchecked {
            liquidityBalance[msg.sender] += liquidity;
            totalLiquidity += liquidity;
            reserves.reserveA += uint64(amountA);
            reserves.reserveB += uint64(amountB);
        }

        DynamicFeeLibrary.updateVolatility(feeState, this, tokenA, tokenB);
        emit LiquidityAdded(msg.sender, amountA, amountB, liquidity);
    }

    function removeLiquidity(uint256 liquidity) external whenNotPaused nonReentrant {
        if (liquidity == 0 || liquidityBalance[msg.sender] < liquidity)
            revert InvalidAmount(liquidity, liquidityBalance[msg.sender]);
        if (totalLiquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = FullMath.mulDiv(liquidity, reserves.reserveA, totalLiquidity);
        uint256 amountB = FullMath.mulDiv(liquidity, reserves.reserveB, totalLiquidity);

        unchecked {
            liquidityBalance[msg.sender] -= liquidity;
            totalLiquidity -= liquidity;
            reserves.reserveA -= uint64(amountA);
            reserves.reserveB -= uint64(amountB);
        }

        IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountA);
        IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountB);

        DynamicFeeLibrary.updateVolatility(feeState, this, tokenA, tokenB);
        emit LiquidityRemoved(msg.sender, amountA, amountB, liquidity);
    }

    function swap(
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient
    ) external whenNotPaused nonReentrant returns (uint256 amountOut) {
        if (inputToken != tokenA && inputToken != tokenB) 
            revert TickMathLibrary.InvalidToken(inputToken);
        if (amountIn == 0) 
            revert TickMathLibrary.ZeroAmount();
        if (recipient == address(0)) 
            revert DynamicFeeLibrary.InvalidAddress(recipient, "Invalid recipient");
        if (paused || chainPaused[1]) 
            revert PoolPaused();

        bool isTokenAInput = inputToken == tokenA;
        uint256 fee = DynamicFeeLibrary.getDynamicFee(feeState, 1);
        uint256 amountInWithFee = (amountIn * (10000 - fee)) / 10000;
        uint256 lpFee = (amountIn * fee * lpFeeShare) / 10000;
        uint256 treasuryFee = (amountIn * fee * treasuryFeeShare) / 10000;

        // Attempt to match with OrderBook first
        amountOut = _tryOrderBookSwap(isTokenAInput, amountInWithFee, minAmountOut, recipient);
        bool usedOrderBook = amountOut >= minAmountOut;

        if (!usedOrderBook) {
            // Fallback to AMM logic
            bool usedConcentratedLiquidity = false;
            amountOut = concentratedLiquidity.swapConcentratedLiquidity(isTokenAInput, amountInWithFee);
            if (amountOut > 0) {
                usedConcentratedLiquidity = true;
                _updateReserves(isTokenAInput, amountIn, amountOut);
            } else {
                (uint256 reserveIn, uint256 reserveOut) = isTokenAInput
                    ? (uint256(reserves.reserveA), uint256(reserves.reserveB))
                    : (uint256(reserves.reserveB), uint256(reserves.reserveA));

                if (feeState.useConstantSum && feeState.emaVolatility < feeState.volatilityThreshold) {
                    amountOut = governanceModule.swapConstantSum(amountInWithFee, reserveIn, reserveOut);
                } else {
                    amountOut = (reserveOut * amountInWithFee) / (reserveIn + amountInWithFee);
                }

                if (amountOut >= minAmountOut && amountOut <= reserveOut) {
                    _updateReserves(isTokenAInput, amountIn, amountOut);
                } else {
                    amountOut = fallbackPool.swapFallbackPool(isTokenAInput, amountInWithFee);
                    (uint256 reserveA, uint256 reserveB,) = fallbackPool.getFallbackReserves();
                    if (amountOut < minAmountOut || amountOut > (isTokenAInput ? reserveB : reserveA)) {
                        revert InsufficientOutputAmount(amountOut, minAmountOut);
                    }
                    fallbackPool.updateFallbackReserves(isTokenAInput, amountIn, amountOut);
                }
            }

            // Validate price
            DynamicFeeLibrary.validatePrice(feeState, this, isTokenAInput ? tokenA : tokenB, amountIn, amountOut, tokenA, tokenB);

            // Update tick and price only for non-concentrated liquidity swaps
            if (!usedConcentratedLiquidity) {
                int24 _currentTick = feeState.currentTick;
                uint160 sqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(_currentTick);
                uint160 nextSqrtPriceX96 = TickMathLibrary.calculateNextPrice(this, sqrtPriceX96, isTokenAInput, amountInWithFee);
                feeState.currentTick = TickMathLibrary.sqrtPriceX96ToTick(nextSqrtPriceX96);
            }

            // Transfer tokens
            address outputToken = isTokenAInput ? tokenB : tokenA;
            IERC20Upgradeable(inputToken).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20Upgradeable(outputToken).safeTransfer(recipient, amountOut);
            if (treasuryFee > 0) {
                IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
            }
            lpFees[recipient][inputToken] += lpFee;

            // Update volatility
            DynamicFeeLibrary.updateVolatility(feeState, this, tokenA, tokenB);
        } else {
            // OrderBook handled the swap
            lpFees[recipient][inputToken] += lpFee;
            if (treasuryFee > 0) {
                IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
            }
        }

        emit Swap(msg.sender, inputToken, amountIn, amountOut, fee);
        return amountOut;
    }

    // --- OrderBook Integration Functions ---

    /// @notice Attempts to execute a swap through the OrderBook
    function _tryOrderBookSwap(
        bool isTokenAInput,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient
    ) internal returns (uint256 amountOut) {
        if (orderBook == address(0)) return 0; // OrderBook not set

        try IOrderBook(orderBook).getAggregatedPrice(tokenA, tokenB) returns (uint256 orderBookPrice) {
            // Check if OrderBook has better price
            uint256 ammPrice = getOraclePrice();
            if ((isTokenAInput && orderBookPrice < ammPrice) || (!isTokenAInput && orderBookPrice > ammPrice)) {
                // Place market order in OrderBook
                IERC20Upgradeable(isTokenAInput ? tokenA : tokenB).safeTransferFrom(msg.sender, address(this), amountIn);
                IERC20Upgradeable(isTokenAInput ? tokenA : tokenB).approve(orderBook, amountIn);

                uint256 orderId = IOrderBook(orderBook).placeOrder(
                    isTokenAInput, // isBuy
                    true, // isMarket
                    false, // isStopLoss
                    0, // price (0 for market order)
                    0, // triggerPrice
                    uint96(amountIn),
                    tokenA, // Use state variable
                    tokenB, // Use state variable
                    0, // expiryTimestamp (0 for immediate execution)
                    false // useConcentratedLiquidity
                );

                // Match orders
                IOrderBook(orderBook).matchOrders(minAmountOut);

                // Retrieve order details
                (, , , , uint96 executedAmount, , , , , , , , , , , , , , , ) = IOrderBook(orderBook).getOrder(orderId);
                amountOut = executedAmount;

                if (amountOut >= minAmountOut) {
                    IERC20Upgradeable(isTokenAInput ? tokenB : tokenA).safeTransfer(recipient, amountOut);
                    emit OrderBookSwap(msg.sender, isTokenAInput ? tokenA : tokenB, amountIn, amountOut, orderId);
                } else {
                    revert InsufficientOrderBookLiquidity(amountOut);
                }
            }
        } catch {
            // Fallback to AMM if OrderBook fails
            return 0;
        }

        return amountOut;
    }

    /// @notice Places a perpetual order through the OrderBook
    /// @notice Places a perpetual order through the OrderBook
    function placePerpetualOrder(
        address _tokenA,
        address _tokenB,
        uint256 amount,
        bool isBuy,
        uint256 leverage,
        uint256 margin
    ) external whenNotPaused nonReentrant returns (uint256 orderId) {
        if (orderBook == address(0)) revert OrderBookNotSet();
        if (_tokenA != tokenA && _tokenA != tokenB) 
            revert TickMathLibrary.InvalidToken(_tokenA);

        IERC20Upgradeable usdc = IERC20Upgradeable(_tokenA);
        usdc.safeTransferFrom(msg.sender, address(this), margin);
        usdc.approve(orderBook, margin);

        try IOrderBook(orderBook).placePerpetualOrder(_tokenA, _tokenB, amount, isBuy, leverage, margin) returns (uint256 _orderId) {
            orderId = _orderId;
            emit OrderBookPerpetualPlaced(orderId, msg.sender, isBuy, leverage, margin);
        } catch {
            revert OrderBookInteractionFailed("Failed to place perpetual order");
        }
    }

    // --- Concentrated Liquidity Functions ---

    function addConcentratedLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB
    ) external whenNotPaused nonReentrant returns (uint256 positionId) {
        positionId = concentratedLiquidity.addConcentratedLiquidity(msg.sender, tickLower, tickUpper, amountA, amountB);

        // Optionally add to OrderBook as a limit order
        if (orderBook != address(0)) {
            try IOrderBook(orderBook).placeOrder(
                true, // isBuy (assuming providing liquidity as a bid)
                false, // isMarket
                false, // isStopLoss
                uint96(getOraclePrice()), // Current price
                0, // triggerPrice
                uint96(amountA), // amount
                tokenA,
                tokenB,
                uint64(block.timestamp + 1 days), // expiry
                true // useConcentratedLiquidity
            ) {} catch {
                // Continue even if OrderBook placement fails
            }
        }

        return positionId;
    }

    function removeConcentratedLiquidity(uint256 positionId, uint128 liquidity)
        external
        whenNotPaused
        nonReentrant
        onlyPositionOwner(positionId)
    {
        concentratedLiquidity.removeConcentratedLiquidity(positionId, liquidity);
    }

    function collectFees(uint256 positionId) external override whenNotPaused nonReentrant onlyPositionManager {
        concentratedLiquidity.collectFees(positionId);
    }

    function collectFeesInternal(uint256 positionId) external onlyPositionAdjuster {
        concentratedLiquidity.collectFeesInternal(positionId);
    }

    function authorizeAdjuster(uint256 positionId, address adjuster) external onlyPositionOwner(positionId) {
        if (adjuster == address(0)) revert InvalidAddress(adjuster, "Invalid adjuster address");
        authorizedAdjusters[positionId] = adjuster;
        emit PositionAdjusterUpdated(adjuster);
    }

    function addLiquidityFromFees(uint256 positionId, uint256 amount0, uint256 amount1) 
        external 
        override 
        whenNotPaused 
        nonReentrant 
        onlyPositionManager 
    {
        concentratedLiquidity.addLiquidityFromFees(positionId, amount0, amount1);
    }

    function adjust(
        uint256 positionId,
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity
    ) external whenNotPaused nonReentrant onlyAuthorizedAdjusters(positionId) {
        concentratedLiquidity.adjust(positionId, tickLower, tickUpper, uint128(liquidity));
    }

    function getFeeGrowthInside(int24 tickLower, int24 tickUpper, uint256 positionId) 
        external 
        view 
        returns (uint128 feesOwed0, uint128 feesOwed1) 
    {
        return concentratedLiquidity.getFeeGrowthInside(positionId);
    }

    // --- Fallback Pool Functions ---

    function exitFallbackPool(uint256 positionId) external override whenNotPaused nonReentrant onlyPositionOwner(positionId) {
        fallbackPool.exitFallbackPool(positionId);
    }

    function exitFallbackPoolInternal(uint256 positionId) external onlyPositionAdjuster {
        fallbackPool.exitFallbackPoolInternal(positionId);
    }

    function compoundFallbackFeesInternal(uint256 positionId, uint256 tokensOwed0, uint256 tokensOwed1) external onlyPositionAdjuster {
        fallbackPool.compoundFallbackFeesInternal(positionId, tokensOwed0, tokensOwed1);
    }

    function transferToken(address token, address recipient, uint256 amount) external onlyPositionAdjuster {
        fallbackPool.transferToken(token, recipient, amount);
    }

    // --- Cross-Chain Functions ---

    function addLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        crossChainModule.addLiquidityCrossChain{value: msg.value}(msg.sender, amountA, amountB, dstChainId, adapterParams);

        // Optionally add to OrderBook on destination chain
        if (orderBook != address(0)) {
            bytes memory payload = abi.encode(
                msg.sender,
                false, // isBuy
                false, // isMarket
                false, // isStopLoss
                uint96(getOraclePrice()), // price
                0, // triggerPrice
                uint96(amountA), // amount
                tokenA,
                tokenB,
                uint64(block.timestamp + 1 days), // expiry
                true // useConcentratedLiquidity
            );
            try IOrderBook(orderBook).placeOrderCrossChain(
                false, false, false, uint96(getOraclePrice()), 0, uint96(amountA),
                tokenA, tokenB, uint64(block.timestamp + 1 days), true, dstChainId, adapterParams
            ) {} catch {
                // Continue even if OrderBook cross-chain placement fails
            }
        }
    }

    function addConcentratedLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        int24 tickLower,
        int24 tickUpper,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        crossChainModule.addConcentratedLiquidityCrossChain{value: msg.value}(
            msg.sender, amountA, amountB, tickLower, tickUpper, dstChainId, adapterParams
        );
    }

    function addConcentratedLiquidityCrossChain(
        uint256 positionId,
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint16 srcChainId,
        address recipient
    ) external override whenNotPaused nonReentrant onlyPositionManager {
        concentratedLiquidity.addConcentratedLiquidityCrossChain(
            positionId, owner, tickLower, tickUpper, srcChainId, recipient
        );
    }

    function swapCrossChain(
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant returns (uint256 amountOut) {
        return crossChainModule.swapCrossChain{value: msg.value}(
            msg.sender, inputToken, amountIn, minAmountOut, dstChainId, adapterParams
        );
    }

    function receiveMessage(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external nonReentrant whenNotPaused whenChainNotPaused(srcChainId) {
        crossChainModule.receiveMessage(srcChainId, srcAddress, payload, additionalParams);
    }

    // --- Cross-Chain Batch Messaging ---

    function batchCrossChainMessages(
        uint16 dstChainId,
        bytes memory payload,
        bytes memory adapterParams
    ) external payable whenNotPaused nonReentrant {
        uint16[] memory dstChainIds = new uint16[](1);
        string[] memory dstAxelarChains = new string[](1);
        bytes[] memory payloads = new bytes[](1);
        bytes[] memory adapterParamsArray = new bytes[](1);
        uint256[] memory timelocks = new uint256[](1);
        dstChainIds[0] = dstChainId;
        dstAxelarChains[0] = chainIdToAxelarChain[dstChainId];
        payloads[0] = payload;
        adapterParamsArray[0] = adapterParams;
        timelocks[0] = chainTimelocks[dstChainId] < MIN_TIMELOCK || chainTimelocks[dstChainId] > MAX_TIMELOCK
            ? MIN_TIMELOCK
            : chainTimelocks[dstChainId];
        crossChainModule.batchCrossChainMessages{value: msg.value}(
            dstChainIds,
            dstAxelarChains,
            payloads,
            adapterParamsArray,
            timelocks
        );
    }

    function batchCrossChainMessages(
        uint16[] calldata dstChainIds,
        string[] calldata dstAxelarChains,
        bytes[] calldata payloads,
        bytes[] calldata adapterParams,
        uint256[] calldata timelocks
    ) external payable whenNotPaused nonReentrant {
        crossChainModule.batchCrossChainMessages{value: msg.value}(
            dstChainIds, dstAxelarChains, payloads, adapterParams, timelocks
        );
    }

    // --- Cross-Chain Retry Mechanism ---

    function retryFailedMessage(uint256 messageId) external payable nonReentrant {
        crossChainModule.retryFailedMessage{value: msg.value}(messageId);
    }

    function retryFailedMessagesBatch(uint256[] calldata messageIds) external payable nonReentrant {
        crossChainModule.retryFailedMessagesBatch{value: msg.value}(messageIds);
    }

    // --- Governance Functions ---

    function updateAmplificationFactor(uint256 newA) external onlyGovernance {
        governanceModule.updateAmplificationFactor(newA);
    }

    function updatePositionAdjuster(address newAdjuster) external onlyGovernance {
        governanceModule.updatePositionAdjuster(newAdjuster);
    }

    function updateFeeConfig(uint16 chainId, uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) external onlyGovernance {
        governanceModule.updateFeeConfig(chainId, baseFee, maxFee, volatilityMultiplier);
    }

    function updatePositionManager(address newPositionManager) external onlyGovernance {
        governanceModule.updatePositionManager(newPositionManager);
    }

    function updateVolatilityThreshold(uint256 newThreshold) external override onlyGovernance {
        governanceModule.updateVolatilityThreshold(newThreshold);
    }

    function proposeGovernanceChange(address target, bytes calldata data) external onlyGovernance returns (uint256 proposalId) {
        return governanceModule.proposeGovernanceChange(target, data);
    }

    function executeGovernanceProposal(uint256 proposalId) external onlyGovernance {
        governanceModule.executeGovernanceProposal(proposalId);
    }

    function rebalanceReserves(uint16 chainId) external onlyGovernanceModule nonReentrant {
        (uint64 reserveA, uint64 reserveB) = (reserves.reserveA, reserves.reserveB);
        uint256 targetRatio = targetReserveRatio;
        uint256 currentRatio = reserveA == 0 ? 0 : (reserveB * 1e18) / reserveA;

        if (currentRatio > targetRatio) {
            uint256 excessB = reserveB - ((reserveA * targetRatio) / 1e18);
            IERC20Upgradeable(tokenB).safeTransfer(treasury, excessB);
            reserves.reserveB -= uint64(excessB);
            emit ReservesRebalanced(chainId, reserveA, reserveB - uint64(excessB), 0);
        } else if (currentRatio < targetRatio) {
            uint256 neededB = ((reserveA * targetRatio) / 1e18) - reserveB;
            IERC20Upgradeable(tokenB).safeTransferFrom(treasury, address(this), neededB);
            reserves.reserveB += uint64(neededB);
            emit ReservesRebalanced(chainId, reserveA, reserveB + uint64(neededB), 0);
        }
    }

    function updateTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external onlyGovernance {
        governanceModule.updateTrustedRemotePool(chainId, poolAddress);
    }

    function updateTokenBridge(address newTokenBridge) external onlyGovernance {
        governanceModule.updateTokenBridge(newTokenBridge);
    }

    function updateTokenBridgeType(address token, uint8 bridgeType) external onlyGovernance {
        governanceModule.updateTokenBridgeType(token, bridgeType);
    }

    function updateTargetReserveRatio(uint256 newRatio) external onlyGovernance {
        governanceModule.updateTargetReserveRatio(newRatio);
    }

    function updatePriceOracle(address newPrimaryOracle, address[] calldata newFallbackOracles) external onlyGovernance {
        governanceModule.updatePriceOracle(newPrimaryOracle, newFallbackOracles);
    }

    function updateEmaPeriod(uint256 newPeriod) external onlyGovernance {
        governanceModule.updateEmaPeriod(newPeriod);
    }

    function updateCrossChainMessenger(uint8 messengerType, address newMessenger) external onlyGovernance {
        governanceModule.updateCrossChainMessenger(messengerType, newMessenger);
    }

    function updateAxelarGasService(address newGasService) external onlyGovernance {
        governanceModule.updateAxelarGasService(newGasService);
    }

    function updateChainIdMapping(uint16 chainId, string calldata axelarChain) external onlyGovernance {
        governanceModule.updateChainIdMapping(chainId, axelarChain);
    }

    function updateWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) external onlyGovernance {
        governanceModule.updateWormholeTrustedSender(chainId, senderAddress);
    }

    function setOrderBook(address newOrderBook) external onlyGovernance {
        if (newOrderBook == address(0)) revert InvalidAddress(newOrderBook, "Invalid OrderBook address");
        orderBook = newOrderBook;
        emit OrderBookSet(newOrderBook);
    }

    // --- Other Functions ---

    function claimLPFee(address token) external nonReentrant {
        if (token != tokenA && token != tokenB) revert InvalidToken(token);
        uint256 feeAmount = lpFees[msg.sender][token];
        if (feeAmount == 0) revert InvalidAmount(feeAmount, 0);

        lpFees[msg.sender][token] = 0;
        IERC20Upgradeable(token).safeTransfer(msg.sender, feeAmount);
        emit LPFeeClaimed(msg.sender, token, feeAmount);
    }

    function claimAllLPFees() external nonReentrant {
        uint256 feeAmountA = lpFees[msg.sender][tokenA];
        uint256 feeAmountB = lpFees[msg.sender][tokenB];
        if (feeAmountA == 0 && feeAmountB == 0) revert InvalidAmount(0, 0);

        if (feeAmountA > 0) {
            lpFees[msg.sender][tokenA] = 0;
            IERC20Upgradeable(tokenA).safeTransfer(msg.sender, feeAmountA);
        }
        if (feeAmountB > 0) {
            lpFees[msg.sender][tokenB] = 0;
            IERC20Upgradeable(tokenB).safeTransfer(msg.sender, feeAmountB);
        }

        emit AllLPFeesClaimed(msg.sender, feeAmountA, feeAmountB);
    }

    function getEstimatedCrossChainFee(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) public view returns (uint256 nativeFee, uint256 zroFee) {
        return crossChainModule.getEstimatedCrossChainFee(dstChainId, payload, adapterParams);
    }

    function emergencyWithdraw() external nonReentrant {
        if (!paused) revert InvalidOperation("Contract not paused");
        uint256 liquidity = liquidityBalance[msg.sender];
        if (liquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = FullMath.mulDiv(liquidity, reserves.reserveA, totalLiquidity);
        uint256 amountB = FullMath.mulDiv(liquidity, reserves.reserveB, totalLiquidity);

        unchecked {
            liquidityBalance[msg.sender] -= liquidity;
            totalLiquidity -= liquidity;
            reserves.reserveA -= uint64(amountA);
            reserves.reserveB -= uint64(amountB);
        }

        IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountA);
        IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountB);
        emit EmergencyWithdrawal(msg.sender, amountA, amountB);
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function pauseChain(uint16 chainId) external onlyOwner {
        chainPaused[chainId] = true;
        emit ChainPaused(chainId, msg.sender);
    }

    function unpauseChain(uint16 chainId) external onlyOwner {
        chainPaused[chainId] = false;
        emit ChainUnpaused(chainId, msg.sender);
    }

    // --- View Functions ---

    function emaVolatility() external view override returns (uint256) {
        return feeState.emaVolatility;
    }

    function emaVol() external view override returns (uint256) {
        return feeState.emaVolatility;
    }

    function getCurrentTick() external view returns (int24) {
        return feeState.currentTick;
    }

    function getPosition(uint256 positionId) external view returns (
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity,
        uint256 tokensOwed0,
        uint256 tokensOwed1
    ) {
        Position storage position = _positions[positionId];
        return (
            position.owner,
            position.tickLower,
            position.tickUpper,
            position.liquidity,
            position.tokensOwed0,
            position.tokensOwed1
        );
    }

    function positions(uint256 positionId) external view override returns (
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity,
        uint256 feeGrowthInside0LastX128,
        uint256 feeGrowthInside1LastX128,
        uint128 tokensOwed0,
        uint128 tokensOwed1
    ) {
        Position storage position = _positions[positionId];
        return (
            position.owner,
            position.tickLower,
            position.tickUpper,
            position.liquidity,
            position.feeGrowthInside0LastX128,
            position.feeGrowthInside1LastX128,
            position.tokensOwed0,
            position.tokensOwed1
        );
    }

    function getCrossChainReserves() external view returns (uint128 reserveA, uint128 reserveB) {
        return (reserves.crossChainReserveA, reserves.crossChainReserveB);
    }

    function getFallbackReserves() external view returns (uint256 reserveA, uint256 reserveB, uint256 fallbackTotalLiquidity) {
        return (fallbackReserves.reserveA, fallbackReserves.reserveB, fallbackReserves.totalLiquidity);
    }

    function getVolatilityThreshold() external view override returns (uint256) {
        return feeState.volatilityThreshold;
    }

    function getLiquidity() external view returns (uint256) {
        return totalLiquidity;
    }

    function getLiquidityForAmounts(int24 tickLower, int24 tickUpper, uint256 amountA, uint256 amountB, int24 _currentTick) 
        external 
        view 
        returns (uint256 liquidity) 
    {
        return concentratedLiquidity.getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB, _currentTick);
    }

    function getLiquidityBalance(address provider) external view returns (uint256) {
        return liquidityBalance[provider];
    }

    function getFallbackLiquidityBalance(address provider) external view returns (uint256) {
        return fallbackLiquidityBalance[provider];
    }

    function getDynamicFee(uint16 chainId) external view returns (uint256) {
        return DynamicFeeLibrary.getDynamicFee(feeState, chainId);
    }

    function getLPFees(address provider, address token) external view returns (uint256) {
        return lpFees[provider][token];
    }

    function isInFallbackPool(uint256 positionId) external view returns (bool) {
        return inFallbackPool[positionId];
    }

    function getChainFeeConfig(uint16 chainId) external view returns (uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) {
        DynamicFeeLibrary.FeeConfig storage config = feeState.chainFees[chainId];
        return (config.baseFee, config.maxFee, config.volatilityMultiplier);
    }

    function getFailedMessage(uint256 messageId) external view returns (ICommonStructs.FailedMessage memory) {
        ICommonStructs.FailedMessage storage message = failedMessages[messageId];
        return ICommonStructs.FailedMessage(
            message.dstChainId,
            message.dstAxelarChain,
            message.payload,
            message.adapterParams,
            message.retries,
            message.timestamp,
            message.messengerType,
            message.nextRetryTimestamp
        );
    }

    function getGovernanceProposal(uint256 proposalId) external view returns (
        address target,
        bytes memory data,
        uint256 proposedAt,
        bool executed
    ) {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        return (proposal.target, proposal.data, proposal.proposedAt, proposal.executed);
    }

    function getPriceHistory() external view returns (uint256[] memory) {
        return feeState.priceHistory;
    }

    function getAmplificationFactor() external view returns (uint256) {
        return amplificationFactor;
    }

    function getTicks(int24 tick) external view returns (Tick memory) {
        return ticks[tick];
    }

    function getTickSpacing() external view returns (uint24) {
        return TICK_SPACING;
    }

    function getOrderBookPrice() external view returns (uint256) {
        if (orderBook == address(0)) return 0;
        try IOrderBook(orderBook).getAggregatedPrice(tokenA, tokenB) returns (uint256 price) {
            return price;
        } catch {
            return 0;
        }
    }

    // --- Setter Functions ---

    function setAmplificationFactor(uint256 newA) external onlyGovernanceModule {
        if (newA < MIN_AMPLIFICATION || newA > MAX_AMPLIFICATION) revert InvalidAmplificationFactor(newA);
        amplificationFactor = newA;
        emit AmplificationFactorUpdated(newA);
    }

    function setPositionAdjuster(address newAdjuster) external onlyGovernanceModule {
        positionAdjuster = newAdjuster;
        emit PositionAdjusterUpdated(newAdjuster);
    }

    function setPositionManager(address newPositionManager) external onlyGovernanceModule {
        positionManager = newPositionManager;
        emit PositionManagerUpdated(newPositionManager);
    }

    function setVolatilityThreshold(uint256 newThreshold) external onlyGovernanceModule {
        feeState.volatilityThreshold = newThreshold;
        emit VolatilityThresholdUpdated(newThreshold);
    }

    function setPositionByLiquidity(uint256 positionId, Position memory position) external onlyConcentratedLiquidity {
        _positions[positionId] = position;
    }

    function setFeeGrowthGlobal0X128(uint256 feeGrowth) external onlyConcentratedLiquidity {
        feeGrowthGlobal0X128 = feeGrowth;
    }

    function setFeeGrowthGlobal1X128(uint256 feeGrowth) external onlyConcentratedLiquidity {
        feeGrowthGlobal1X128 = feeGrowth;
    }

    function setTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external onlyGovernanceModule {
        trustedRemotePools[chainId] = poolAddress;
        emit TrustedRemotePoolAdded(chainId, poolAddress);
    }

    function setTokenBridge(address newTokenBridge) external onlyGovernanceModule {
        tokenBridge = newTokenBridge;
        emit TokenBridgeUpdated(newTokenBridge);
    }

    function setTokenBridgeType(address token, uint8 bridgeType) external onlyGovernanceModule {
        tokenBridgeType[token] = bridgeType;
        emit TokenBridgeTypeUpdated(token, bridgeType);
    }

    function setTargetReserveRatio(uint256 newRatio) external onlyGovernanceModule {
        if (newRatio == 0) revert InvalidReserveRatio(newRatio);
        targetReserveRatio = newRatio;
        emit TargetReserveRatioUpdated(newRatio);
    }

    function setPriceOracle(address newPrimaryOracle, address[] calldata newFallbackOracles) external onlyGovernanceModule {
        primaryPriceOracle = newPrimaryOracle;
        fallbackPriceOracles = newFallbackOracles;
        emit PriceOracleUpdated(newPrimaryOracle, newFallbackOracles);
    }

    function setEmaPeriod(uint256 newPeriod) external onlyGovernanceModule {
        emaPeriod = newPeriod;
        emit EmaPeriodUpdated(newPeriod);
    }

    function setCrossChainMessenger(uint8 messengerType, address newMessenger) external onlyGovernanceModule {
        crossChainMessengers[messengerType] = newMessenger;
        emit CrossChainMessengerUpdated(messengerType, newMessenger);
    }

    function setAxelarGasService(address newGasService) external onlyGovernanceModule {
        axelarGasService = newGasService;
        emit AxelarGasServiceUpdated(newGasService);
    }

    function setChainIdMapping(uint16 chainId, string calldata axelarChain) external onlyGovernanceModule {
        chainIdToAxelarChain[chainId] = axelarChain;
        axelarChainToChainId[axelarChain] = chainId;
        emit ChainIdMappingUpdated(chainId, axelarChain);
    }

    function setWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) external onlyGovernanceModule {
        wormholeTrustedSenders[chainId] = senderAddress;
        emit WormholeTrustedSenderUpdated(chainId, senderAddress);
    }

    function setGovernance(address newGovernance) external onlyGovernanceModule {
        governance = newGovernance;
        emit GovernanceUpdated(newGovernance);
    }

    function setEmaVol(uint256 newEmaVol) external onlyGovernanceModule {
        feeState.emaVolatility = newEmaVol;
    }

    function setCurrentTick(int24 tick) external onlyConcentratedLiquidity {
        currentTick = tick;
        feeState.currentTick = tick;
    }

    function setTick(int24 tick, Tick memory tickInfo) external onlyConcentratedLiquidity {
        ticks[tick] = tickInfo;
    }

    function deleteTick(int24 tick) external onlyConcentratedLiquidity {
        delete ticks[tick];
    }

    // --- Internal Helper Functions ---

    function getOraclePrice() public returns (uint256 price) {
        for (uint256 i = 0; i <= MAX_ORACLE_RETRIES; i++) {
            try IPriceOracle(primaryPriceOracle).getPrice(tokenA, tokenB) returns (int256 oraclePrice) {
                if (oraclePrice <= 0) revert NegativeOraclePrice(oraclePrice);
                return uint256(oraclePrice);
            } catch {
                if (i == MAX_ORACLE_RETRIES) break;
            }
        }
        for (uint256 i = 0; i < fallbackPriceOracles.length; i++) {
            if (fallbackPriceOracles[i] == address(0)) continue;
            try IPriceOracle(fallbackPriceOracles[i]).getPrice(tokenA, tokenB) returns (int256 fallbackPrice) {
                if (fallbackPrice <= 0) revert NegativeOraclePrice(fallbackPrice);
                emit OracleFailover(primaryPriceOracle, fallbackPriceOracles[i]);
                return uint256(fallbackPrice);
            } catch {}
        }
        revert OracleFailure();
    }

    function _updateReserves(bool isTokenAInput, uint256 amountIn, uint256 amountOut) internal {
        if (isTokenAInput) {
            if (reserves.reserveB < amountOut) revert InsufficientReserve(amountOut, reserves.reserveB);
            unchecked {
                reserves.reserveA += uint64(amountIn);
                reserves.reserveB -= uint64(amountOut);
            }
        } else {
            if (reserves.reserveA < amountOut) revert InsufficientReserve(amountOut, reserves.reserveA);
            unchecked {
                reserves.reserveB += uint64(amountIn);
                reserves.reserveA -= uint64(amountOut);
            }
        }
    }

    function _updateFallbackReserves(bool isTokenAInput, uint256 amountIn, uint256 amountOut) internal {
        if (isTokenAInput) {
            if (fallbackReserves.reserveB < amountOut) revert InsufficientReserve(amountOut, fallbackReserves.reserveB);
            unchecked {
                fallbackReserves.reserveA += amountIn;
                fallbackReserves.reserveB -= amountOut;
            }
        } else {
            if (fallbackReserves.reserveA < amountOut) revert InsufficientReserve(amountOut, fallbackReserves.reserveA);
            unchecked {
                fallbackReserves.reserveB += amountIn;
                fallbackReserves.reserveA -= amountOut;
            }
        }
    }

    function _validatePrice(address inputToken, uint256 amountIn, uint256 amountOut) internal {
        DynamicFeeLibrary.validatePrice(feeState, this, inputToken, amountIn, amountOut, tokenA, tokenB);
    }

    function _updateVolatility() internal {
        DynamicFeeLibrary.updateVolatility(feeState, this, tokenA, tokenB);
    }

    function _getDynamicFee(uint16 chainId) internal view returns (uint256) {
        return DynamicFeeLibrary.getDynamicFee(feeState, chainId);
    }

    function _swapConcentratedLiquidity(bool isTokenAInput, uint256 amountIn) internal returns (uint256 amountOut) {
        return concentratedLiquidity.swapConcentratedLiquidity(isTokenAInput, amountIn);
    }

    function _swapConstantSum(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal view returns (uint256 amountOut) {
        return governanceModule.swapConstantSum(amountIn, reserveIn, reserveOut);
    }

    function _swapFallbackPool(bool isTokenAInput, uint256 amountIn) internal returns (uint256 amountOut) {
        amountOut = fallbackPool.swapFallbackPool(isTokenAInput, amountIn);
        if (amountOut > 0) {
            fallbackPool.updateFallbackReserves(isTokenAInput, amountIn, amountOut);
        }
        return amountOut;
    }

    function sqrt(UD60x18 x) internal pure returns (UD60x18) {
        return x.sqrt();
    }

    // --- CrossChainModule Helper Functions ---

    function setPosition(uint256 positionId, Position memory position) external onlyCrossChainModule {
        _positions[positionId] = position;
    }

    function setChainFeeConfig(uint16 chainId, uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) external onlyGovernanceModule {
        feeState.chainFees[chainId] = DynamicFeeLibrary.FeeConfig({
            baseFee: baseFee,
            maxFee: maxFee,
            volatilityMultiplier: volatilityMultiplier
        });
        emit FeesUpdated(chainId, baseFee, maxFee, lpFeeShare, treasuryFeeShare);
    }

    function incrementPositionCounter() external onlyLiquidityOrCrossChain {
        positionCounter++;
    }

    function updateTick(int24 tick, uint256 liquidityDelta, bool upper) external onlyCrossChainModule {
        Tick storage tickInfo = ticks[tick];
        uint128 delta = uint128(liquidityDelta);
        if (tickInfo.liquidityGross == 0 && liquidityDelta > 0) {
            tickInfo.feeGrowthOutside0X128 = feeGrowthGlobal0X128;
            tickInfo.feeGrowthOutside1X128 = feeGrowthGlobal1X128;
        }
        tickInfo.liquidityGross = upper
            ? tickInfo.liquidityGross - delta
            : tickInfo.liquidityGross + delta;
        tickInfo.liquidityNet = upper
            ? tickInfo.liquidityNet - int128(delta)
            : tickInfo.liquidityNet + int128(delta);
    }

    function checkAndMoveToFallback(uint256 positionId) external onlyCrossChainModule {
        fallbackPool.checkAndMoveToFallback(positionId);
    }

    function updateLiquidityBalance(address provider, uint256 liquidity, bool add) external onlyCrossChainModule {
        liquidityBalance[provider] = add
            ? liquidityBalance[provider] + liquidity
            : liquidityBalance[provider] - liquidity;
    }

    function incrementTotalLiquidity(uint256 liquidity) external onlyCrossChainModule {
        totalLiquidity += liquidity;
    }

    function updateCrossChainReserves(uint256 amountA, uint256 amountB) external onlyCrossChainModule {
        if (amountA > type(uint128).max || amountB > type(uint128).max) revert InvalidAmount(amountA, amountB);
        reserves.crossChainReserveA += uint128(amountA);
        reserves.crossChainReserveB += uint128(amountB);
    }

    function updateVolatility() external onlyCrossChainModule {
        governanceModule.updateVolatility();
    }

    function setUsedNonces(uint16 chainId, uint64 nonce, bool used) external override onlyCrossChainModule {
        usedNonces[chainId][nonce] = used;
    }

    function setValidatedMessages(bytes32 messageHash, bool validated) external onlyCrossChainModule {
        validatedMessages[messageHash] = validated;
    }

    function setFailedMessage(uint256 messageId, ICommonStructs.FailedMessage memory message) external override onlyCrossChainModule {
        failedMessages[messageId] = message;
    }

    function deleteFailedMessage(uint256 messageId) external onlyCrossChainModule {
        delete failedMessages[messageId];
    }

    function updateFailedMessage(uint256 messageId, uint256 retries, uint256 nextRetryTimestamp) external onlyCrossChainModule {
        failedMessages[messageId].retries = retries;
        failedMessages[messageId].nextRetryTimestamp = nextRetryTimestamp;
    }

    function incrementFailedMessageCount() external onlyCrossChainModule {
        failedMessageCount++;
    }

    function emitCrossChainLiquiditySent(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock,
        uint256 positionId
    ) external onlyCrossChainModule {
        emit CrossChainLiquiditySent(provider, amountA, amountB, dstChainId, nonce, timelock, positionId);
    }

    function emitCrossChainLiquidityReceived(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 srcChainId,
        uint64 nonce,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit CrossChainLiquidityReceived(provider, amountA, amountB, srcChainId, nonce, messengerType);
    }

    function emitCrossChainSwap(
        address user,
        address inputToken,
        uint256 amountIn,
        uint256 amountOut,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit CrossChainSwap(user, inputToken, amountIn, amountOut, dstChainId, nonce, timelock, messengerType);
    }

    function emitFailedMessageStored(
        uint256 messageId,
        uint16 dstChainId,
        string memory dstAxelarChain,
        uint256 timestamp,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit FailedMessageStored(messageId, dstChainId, dstAxelarChain, timestamp, messengerType);
    }

    function emitFailedMessageRetried(
        uint256 messageId,
        uint16 dstChainId,
        uint256 retries,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit FailedMessageRetried(messageId, dstChainId, retries, messengerType);
    }

    function emitFailedMessageRetryScheduled(uint256 messageId, uint256 nextRetryTimestamp) external onlyCrossChainModule {
        emit FailedMessageRetryScheduled(messageId, nextRetryTimestamp);
    }

    function emitBatchMessagesSent(
        uint16[] memory dstChainIds,
        uint8 messengerType,
        uint256 totalNativeFee
    ) external onlyCrossChainModule {
        emit BatchMessagesSent(dstChainIds, messengerType, totalNativeFee);
    }

    function emitBatchRetryProcessed(
        uint256[] memory messageIds,
        uint256 successfulRetries,
        uint256 failedRetries
    ) external onlyCrossChainModule {
        emit BatchRetryProcessed(messageIds, successfulRetries, failedRetries);
    }

    function emitPositionCreated(
        uint256 positionId,
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) external onlyConcentratedLiquidity {
        emit PositionCreated(positionId, owner, tickLower, tickUpper, liquidity);
    }

    function emitPositionUpdated(
        uint256 positionId,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) external onlyConcentratedLiquidity {
        emit PositionUpdated(positionId, tickLower, tickUpper, liquidity);
    }

    function emitFeesCollected(uint256 positionId, uint256 fees0, uint256 fees1) external onlyConcentratedLiquidity {
        emit FeesCollected(positionId, fees0, fees1);
    }

    // --- Mock Functions for Testing ---

    function setMockReserves(uint64 reserveA, uint64 reserveB) external {
        reserves.reserveA = reserveA;
        reserves.reserveB = reserveB;
    }

    function setMockLiquidity(uint256 liquidity) external {
        totalLiquidity = liquidity;
    }

    // --- ERC721 Receiver ---

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        return IERC721ReceiverUpgradeable.onERC721Received.selector;
    }
}