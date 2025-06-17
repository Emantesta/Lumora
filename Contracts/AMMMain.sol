// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin imports for upgradeable contracts
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC721ReceiverUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";

// Module contracts
import {ConcentratedLiquidity} from "./ConcentratedLiquidity.sol";
import {CrossChainModule} from "./CrossChainModule.sol";
import {FallbackPool} from "./FallbackPool.sol";
import {GovernanceModule} from "./GovernanceModule.sol";

// Interfaces
import {IAMMPool, IPositionManager, IPriceOracle, ICommonStructs} from "./Interfaces.sol";

// PRB Math for UD60x18
import {UD60x18, ud} from "@prb/math/src/UD60x18.sol";

/// @title AMMPool - Main upgradeable AMM pool contract with modularized functionality
/// @notice Acts as the entry point for AMM operations, delegating to specialized modules
/// @dev Retains state and external API, uses UUPS upgradeability, and integrates with modules
contract AMMPool is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IERC721ReceiverUpgradeable,
    IAMMPool
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable constants (unchanged)
    bytes32 public immutable VERSION;
    uint256 public immutable MIN_TIMELOCK;
    uint256 public immutable MAX_TIMELOCK;
    uint256 public immutable MAX_BATCH_SIZE;
    uint256 public immutable MAX_GAS_LIMIT;
    uint256 public immutable GOVERNANCE_TIMELOCK;
    uint256 public immutable MAX_RETRIES;
    uint256 public immutable MAX_ORACLE_RETRIES;
    uint24 public immutable TICK_SPACING;
    uint256 public immutable MAX_LIQUIDITY_PER_TICK;
    uint256 public immutable RETRY_DELAY;

    // Storage variables (unchanged)
    address public override tokenA;
    address public override tokenB;
    struct Reserves {
        uint64 reserveA;
        uint64 reserveB;
        uint128 crossChainReserveA;
        uint128 crossChainReserveB;
    }
    Reserves public reserves;

    struct FeeConfig {
        uint256 baseFee;
        uint256 maxFee;
        uint256 volatilityMultiplier;
    }
    mapping(uint16 => FeeConfig) public chainFees;

    uint256 public lpFeeShare;
    uint256 public treasuryFeeShare;
    address public treasury;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidityBalance;
    mapping(address => mapping(address => uint256)) public lpFees;
    bool public paused;
    mapping(uint16 => bool) public chainPaused;
    address public tokenBridge;
    address public positionManager;
    mapping(uint16 => bytes) public trustedRemotePools;
    mapping(uint16 => mapping(uint64 => bool)) public usedNonces;
    mapping(uint16 => uint256) public chainTimelocks;
    mapping(address => uint8) public tokenBridgeType;
    uint256 public targetReserveRatio;
    address public primaryPriceOracle;
    address[] public fallbackPriceOracles;
    address public governance;
    uint256 public emaVolatility;
    uint256 public emaPeriod;
    uint256 public volatilityThreshold;
    uint256 public lastPrice;
    bool public useConstantSum;
    uint256 public priceDeviationThreshold;

    // Cross-chain messengers
    mapping(uint8 => address) public crossChainMessengers;
    address public axelarGasService;
    mapping(uint16 => string) public chainIdToAxelarChain;
    mapping(string => uint16) public axelarChainToChainId;
    mapping(uint16 => bytes32) public wormholeTrustedSenders;

    // Concentrated liquidity state
    mapping(uint256 => Position) public override positions;
    uint256 public override positionCounter;
    mapping(int24 => Tick) public ticks;
    int24 public currentTick;
    uint256 public feeGrowthGlobal0X128;
    uint256 public feeGrowthGlobal1X128;

    // Dynamic curves
    uint256 public amplificationFactor;
    uint256 public constant MAX_AMPLIFICATION = 1000;
    uint256 public constant MIN_AMPLIFICATION = 1;

    // Fallback pool state
    struct FallbackReserves {
        uint256 reserveA;
        uint256 reserveB;
        uint256 totalLiquidity;
    }
    FallbackReserves public fallbackReserves;
    mapping(address => uint256) public fallbackLiquidityBalance;
    mapping(uint256 => bool) public inFallbackPool;
    address public positionAdjuster;

    struct FailedMessage {
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 timestamp;
        uint8 messengerType;
        uint256 nextRetryTimestamp;
    }
    mapping(uint256 => FailedMessage) public failedMessages;
    uint256 public failedMessageCount;

    struct GovernanceProposal {
        address target;
        bytes data;
        uint256 proposedAt;
        bool executed;
    }
    mapping(uint256 => address) public authorizedAdjusters;
    mapping(uint256 => GovernanceProposal) public governanceProposals;
    uint256 public proposalCount;

    // Historical price data
    uint256[] public priceHistory;
    uint256 public priceHistoryIndex;
    uint256 public constant PRICE_HISTORY_SIZE = 20;
    uint256 public constant VOLATILITY_WINDOW = 10;

    // Cross-chain validation cache
    mapping(bytes32 => bool) public validatedMessages;

    // Module contracts
    ConcentratedLiquidity public concentratedLiquidity;
    CrossChainModule public crossChainModule;
    FallbackPool public fallbackPool;
    GovernanceModule public governanceModule;

    // NEW: CrossChainModule address for access control
    address public crossChainModuleAddress;

    // Custom errors (unchanged)
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
    error InsufficientLiquidity(uint256 liquidity);
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

    // Events (unchanged)
    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event Swap(address indexed user, address indexed inputToken, uint256 amountIn, uint256 amountOut);
    event FeesUpdated(uint16 indexed chainId, uint256 baseFee, uint256 maxFee, uint256 lpFeeShare, uint256 treasuryFeeShare);
    event Paused(address indexed caller);
    event Unpaused(address indexed caller);
    event ChainPaused(uint16 indexed chainId, address indexed caller);
    event ChainUnpaused(uint16 indexed chainId, address indexed caller);
    event CrossChainLiquiditySent(address indexed provider, uint256 amountA, uint256 amountB, uint16 indexed chainId, uint64 nonce, uint256 estimatedConfirmationTime, uint8 messengerType);
    event CrossChainLiquidityReceived(address indexed provider, uint256 amountA, uint256 amountB, uint16 indexed chainId, uint64 nonce, uint8 messengerType);
    event CrossChainSwap(address indexed user, address indexed inputToken, uint256 amountIn, uint256 amountOut, uint16 indexed chainId, uint64 nonce, uint256 estimatedConfirmationTime, uint8 messengerType);
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
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes sender, uint256 timestamp, uint8 messengerType);
    event BatchMessagesSent(uint16[] dstChainIds, uint8 messengerType, uint256 totalNativeFee);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries, uint8 messengerType);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event AllLPFeesClaimed(address indexed provider, uint256 amountA, uint256 amountB);
    event OracleFailover(address indexed failedOracle, address indexed newOracle);
    event FeesCollected(uint256 indexed positionId, uint256 amount0, uint256 amount1);
    event FallbackPoolEntered(uint256 indexed positionId, uint256 liquidity);
    event FallbackPoolExited(uint256 indexed positionId, uint256 liquidity);
    event AmplificationFactorUpdated(uint256 newA);
    event TokenTransferred(address indexed token, address indexed from, address indexed to, uint256 amount);
    event PositionUpdated(uint256 indexed positionId, int24 tickLower, int24 tickUpper, uint256 liquidity);
    event PositionAdjusterUpdated(address indexed newAdjuster);
    event FailedMessageRetryScheduled(uint256 indexed messageId, uint256 nextRetryTimestamp);
    event BatchRetryProcessed(uint256[] messageIds, uint256 successfulRetries, uint256 failedRetries);
    event PositionManagerUpdated(address indexed newPositionManager);
    event VolatilityThresholdUpdated(uint256 newThreshold);

    // Modifiers (unchanged)
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    modifier whenChainNotPaused(uint16 chainId) {
        if (chainPaused[chainId]) revert ChainPausedError(chainId);
        _;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert Unauthorized();
        _;
    }

    modifier onlyPositionOwner(uint256 positionId) {
        if (positions[positionId].owner != msg.sender) revert NotPositionOwner(positionId);
        _;
    }

    modifier onlyAuthorizedAdjusters(uint256 positionId) {
        if (msg.sender != positions[positionId].owner && msg.sender != authorizedAdjusters[positionId]) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyPositionAdjuster() {
        if (msg.sender != positionAdjuster) revert Unauthorized();
        _;
    }

    modifier onlyPositionManager() {
        if (msg.sender != positionManager) revert Unauthorized();
        _;
    }

    // NEW: Modifier for CrossChainModule access
    modifier onlyCrossChainModule() {
        if (msg.sender != crossChainModuleAddress) revert Unauthorized();
        _;
    }

    // Constructor (unchanged)
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

    // Initializer (updated to set crossChainModuleAddress)
    function initialize(ICommonStructs.InitParams memory params) external initializer {
        // Validate inputs
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
            params.positionManager == address(0)
        ) revert InvalidAddress(address(0), "Zero address not allowed");
        if (params.defaultTimelock < MIN_TIMELOCK || params.defaultTimelock > MAX_TIMELOCK)
            revert InvalidTimelock(params.defaultTimelock);
        if (params.targetReserveRatio == 0)
            revert InvalidReserveRatio(params.targetReserveRatio);

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
        chainTimelocks[1] = params.defaultTimelock;
        targetReserveRatio = params.targetReserveRatio;
        chainFees[1] = FeeConfig({baseFee: 20, maxFee: 100, volatilityMultiplier: 2});
        lpFeeShare = 8333;
        treasuryFeeShare = 1667;
        emaPeriod = 100;
        volatilityThreshold = 1e16;
        priceDeviationThreshold = 1e16;
        tokenBridgeType[params.tokenA] = 1;
        tokenBridgeType[params.tokenB] = 1;
        amplificationFactor = 100;
        currentTick = 0;

        priceHistory = new uint256[](PRICE_HISTORY_SIZE);

        // Deploy and initialize modules
        concentratedLiquidity = new ConcentratedLiquidity(address(this));
        crossChainModule = new CrossChainModule(address(this));
        fallbackPool = new FallbackPool(address(this));
        governanceModule = new GovernanceModule(address(this));

        // Set crossChainModuleAddress
        crossChainModuleAddress = address(crossChainModule);

        emit PositionManagerUpdated(params.positionManager);
    }

    // Authorize upgrades (unchanged)
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // --- Concentrated Liquidity Functions ---

    function addConcentratedLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB
    ) external whenNotPaused nonReentrant returns (uint256 positionId) {
        return concentratedLiquidity.addConcentratedLiquidity(msg.sender, tickLower, tickUpper, amountA, amountB);
    }

    function removeConcentratedLiquidity(uint256 positionId, uint256 liquidity)
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

    function adjust(
        uint256 positionId,
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity
    ) external override whenNotPaused nonReentrant onlyAuthorizedAdjusters(positionId) {
        concentratedLiquidity.adjust(positionId, tickLower, tickUpper, liquidity);
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

    // --- Core AMM Functions ---

    function addLiquidity(uint256 amountA, uint256 amountB) external whenNotPaused nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        uint256 liquidity;
        if (useConstantSum && emaVolatility < volatilityThreshold) {
            liquidity = (amountA + amountB) / 2;
        } else {
            if (totalLiquidity == 0) {
                UD60x18 sqrtResult = sqrt(ud(amountA * amountB));
                liquidity = sqrtResult.unwrap();
            } else {
                liquidity = (amountA * totalLiquidity) / reserves.reserveA;
                uint256 liquidityB = (amountB * totalLiquidity) / reserves.reserveB;
                liquidity = liquidity < liquidityB ? liquidity : liquidityB;
            }
        }

        unchecked {
            liquidityBalance[msg.sender] += liquidity;
            totalLiquidity += liquidity;
            reserves.reserveA += uint64(amountA);
            reserves.reserveB += uint64(amountB);
        }

        governanceModule.updateVolatility();
        emit LiquidityAdded(msg.sender, amountA, amountB, liquidity);
    }

    function removeLiquidity(uint256 liquidity) external whenNotPaused nonReentrant {
        if (liquidity == 0 || liquidityBalance[msg.sender] < liquidity)
            revert InvalidAmount(liquidity, liquidityBalance[msg.sender]);
        if (totalLiquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = (liquidity * reserves.reserveA) / totalLiquidity;
        uint256 amountB = (liquidity * reserves.reserveB) / totalLiquidity;

        unchecked {
            liquidityBalance[msg.sender] -= liquidity;
            totalLiquidity -= liquidity;
            reserves.reserveA -= uint64(amountA);
            reserves.reserveB -= uint64(amountB);
        }

        IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountA);
        IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountB);

        governanceModule.updateVolatility();
        emit LiquidityRemoved(msg.sender, amountA, amountB, liquidity);
    }

    function swap(address inputToken, uint256 amountIn, uint256 minAmountOut)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 amountOut)
    {
        if (inputToken != tokenA && inputToken != tokenB) revert InvalidToken(inputToken);
        if (amountIn == 0) revert InvalidAmount(amountIn, 0);

        bool isTokenAInput = inputToken == tokenA;
        uint256 fee = governanceModule.getDynamicFee(1);
        uint256 amountInWithFee = (amountIn * (10000 - fee)) / 10000;
        uint256 lpFee = (amountIn * fee * lpFeeShare) / 10000;
        uint256 treasuryFee = (amountIn * fee * treasuryFeeShare) / 10000;

        amountOut = concentratedLiquidity.swapConcentratedLiquidity(isTokenAInput, amountInWithFee);
        if (amountOut == 0) {
            (uint256 reserveIn, uint256 reserveOut) = isTokenAInput
                ? (uint256(reserves.reserveA), uint256(reserves.reserveB))
                : (uint256(reserves.reserveB), uint256(reserves.reserveA));

            if (useConstantSum && emaVolatility < volatilityThreshold) {
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

        governanceModule.validatePrice(inputToken, amountIn, amountOut);

        address outputToken = isTokenAInput ? tokenB : tokenA;
        IERC20Upgradeable(inputToken).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20Upgradeable(outputToken).safeTransfer(msg.sender, amountOut);
        IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
        lpFees[msg.sender][inputToken] += lpFee;

        governanceModule.updateVolatility();
        emit Swap(msg.sender, inputToken, amountIn, amountOut);
    }

    // --- Cross-Chain Functions ---

    function addLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        crossChainModule.addLiquidityCrossChain{value: msg.value}(msg.sender, amountA, amountB, dstChainId, adapterParams);
    }

    function addConcentratedLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        int24 tickLower,
        int24 tickUpper,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable override whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        crossChainModule.addConcentratedLiquidityCrossChain{value: msg.value}(
            msg.sender, amountA, amountB, tickLower, tickUpper, dstChainId, adapterParams
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
    ) external payable override whenNotPaused nonReentrant {
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

    function rebalanceReserves(uint16 chainId) external onlyGovernance {
        governanceModule.rebalanceReserves(chainId);
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
        // Note: CrossChainModule should implement this if needed
        return (0, 0); // Placeholder
    }

    function emergencyWithdraw() external nonReentrant {
        if (!paused) revert InvalidOperation("Contract not paused");
        uint256 liquidity = liquidityBalance[msg.sender];
        if (liquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = (liquidity * reserves.reserveA) / totalLiquidity;
        uint256 amountB = (liquidity * reserves.reserveB) / totalLiquidity;

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

    function emaVol() external view returns (uint256) {
        return emaVolatility;
    }

    function getcurrentTick() external view returns (int24) {
        return currentTick;
    }

    function getPosition(uint256 positionId) external view returns (
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity,
        uint256 tokensOwed0,
        uint256 tokensOwed1
    ) {
        Position storage position = positions[positionId];
        return (
            position.owner,
            position.tickLower,
            position.tickUpper,
            position.liquidity,
            position.tokensOwed0,
            position.tokensOwed1
        );
    }

    function getReserves() external view returns (uint64 reserveA, uint64 reserveB) {
        return (reserves.reserveA, reserves.reserveB);
    }

    function getCrossChainReserves() external view returns (uint128 reserveA, uint128 reserveB) {
        return (reserves.crossChainReserveA, reserves.crossChainReserveB);
    }

    function getFallbackReserves() external view returns (uint256 reserveA, uint256 reserveB, uint256 fallbackTotalLiquidity) {
        return (fallbackReserves.reserveA, fallbackReserves.reserveB, fallbackReserves.totalLiquidity);
    }

    function getVolatilityThreshold() external view override returns (uint256) {
        return volatilityThreshold;
    }

    function getLiquidityBalance(address provider) external view returns (uint256) {
        return liquidityBalance[provider];
    }

    function getFallbackLiquidityBalance(address provider) external view returns (uint256) {
        return fallbackLiquidityBalance[provider];
    }

    function getLPFees(address provider, address token) external view returns (uint256) {
        return lpFees[provider][token];
    }

    function isInFallbackPool(uint256 positionId) external view returns (bool) {
        return inFallbackPool[positionId];
    }

    function getChainFeeConfig(uint16 chainId) external view returns (uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) {
        FeeConfig storage config = chainFees[chainId];
        return (config.baseFee, config.maxFee, config.volatilityMultiplier);
    }

    function getFailedMessage(uint256 messageId) external view returns (
        uint16 dstChainId,
        string memory dstAxelarChain,
        bytes memory payload,
        bytes memory adapterParams,
        uint256 retries,
        uint256 timestamp,
        uint8 messengerType,
        uint256 nextRetryTimestamp
    ) {
        FailedMessage storage message = failedMessages[messageId];
        return (
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
        return priceHistory;
    }

    function getAmplificationFactor() external view returns (uint256) {
        return amplificationFactor;
    }

    function getTickSpacing() external view returns (uint24) {
        return TICK_SPACING;
    }

    // New constant getter functions
    function MIN_AMPLIFICATION() external pure returns (uint256) {
        return 1;
    }

    function MAX_AMPLIFICATION() external pure returns (uint256) {
        return 1000;
    }

    function GOVERNANCE_TIMELOCK() external pure returns (uint256) {
        return 86400; // 1 day
    }

    function VOLATILITY_WINDOW() external pure returns (uint256) {
        return 10;
    }

    function setAmplificationFactor(uint256 newA) external onlyGovernanceModule {
    amplificationFactor = newA;
    }

    function setPositionAdjuster(address newAdjuster) external onlyGovernanceModule {
        positionAdjuster = newAdjuster;
    }

    function setChainFeeConfig(uint16 chainId, uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) 
        external 
        onlyGovernanceModule 
    {
        chainFees[chainId] = FeeConfig(baseFee, maxFee, volatilityMultiplier);
    }

    function setPositionManager(address newPositionManager) external onlyGovernanceModule {
        positionManager = newPositionManager;
    }

    function setVolatilityThreshold(uint256 newThreshold) external onlyGovernanceModule {
        volatilityThreshold = newThreshold;
    }

    function setTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external onlyGovernanceModule {
        trustedRemotePools[chainId] = poolAddress;
    }

    function setTokenBridge(address newTokenBridge) external onlyGovernanceModule {
        tokenBridge = newTokenBridge;
    }

    function setTokenBridgeType(address token, uint8 bridgeType) external onlyGovernanceModule {
        tokenBridgeType[token] = bridgeType;
    }

    function setTargetReserveRatio(uint256 newRatio) external onlyGovernanceModule {
        targetReserveRatio = newRatio;
    }

    function setPriceOracle(address newPrimaryOracle, address[] calldata newFallbackOracles) 
        external 
        onlyGovernanceModule 
    {
        primaryPriceOracle = newPrimaryOracle;
        fallbackPriceOracles = newFallbackOracles;
    }

    function setEmaPeriod(uint256 newPeriod) external onlyGovernanceModule {
        emaPeriod = newPeriod;
    }

    function setCrossChainMessenger(uint8 messengerType, address newMessenger) external onlyGovernanceModule {
        crossChainMessengers[messengerType] = newMessenger;
    }

    function setAxelarGasService(address newGasService) external onlyGovernanceModule {
        axelarGasService = newGasService;
    }

    function setChainIdMapping(uint16 chainId, string calldata axelarChain) external onlyGovernanceModule {
        chainIdToAxelarChain[chainId] = axelarChain;
        axelarChainToChainId[axelarChain] = chainId;
    }

    function setWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) external onlyGovernanceModule {
        wormholeTrustedSenders[chainId] = senderAddress;
    }

    function setGovernance(address newGovernance) external onlyGovernanceModule {
        governance = newGovernance;
    }

    function setEmaVol(uint256 newEmaVol) external onlyGovernanceModule {
        emaVolatility = newEmaVol;
    }

    // NEW: View functions for concentrated liquidity
    function getFeeGrowthInside(int24 tickLower, int24 tickUpper, uint8 tokenId) external view returns (uint256) {
        if (tickLower >= tickUpper) revert InvalidTickRange(tickLower, tickUpper);
        Tick storage lower = ticks[tickLower];
        Tick storage upper = ticks[tickUpper];
        uint256 feeGrowthInside = tokenId == 0 ? feeGrowthGlobal0X128 : feeGrowthGlobal1X128;
        if (currentTick >= tickLower && currentTick < tickUpper) {
            return feeGrowthInside;
        } else if (currentTick < tickLower) {
            return lower.feeGrowthOutside0X128;
        } else {
            return upper.feeGrowthOutside0X128;
        }
    }

    function getLiquidityForAmounts(int24 tickLower, int24 tickUpper, uint256 amountA, uint256 amountB) external view returns (uint256 liquidity) {
        if (tickLower >= tickUpper) revert InvalidTickRange(tickLower, tickUpper);
        uint256 price = lastPrice; // Simplified; use oracle price in production
        if (price == 0) return amountA < amountB ? amountA : amountB;
        return (amountA * price) / 1e18 < amountB ? (amountA * price) / 1e18 : amountB;
    }

    // --- Internal Helper Functions ---

    function _updateReserves(bool isTokenAInput, uint256 amountIn, uint256 amountOut) internal {
        if (isTokenAInput) {
            unchecked {
                reserves.reserveA += uint64(amountIn);
                reserves.reserveB -= uint64(amountOut);
            }
        } else {
            unchecked {
                reserves.reserveB += uint64(amountIn);
                reserves.reserveA -= uint64(amountOut);
            }
        }
    }

    function sqrt(UD60x18 x) internal pure returns (UD60x18) {
        return x.sqrt();
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

    // --- CrossChainModule Helper Functions ---

    function setPosition(uint256 positionId, Position memory position) external onlyCrossChainModule {
        positions[positionId] = position;
    }

    function incrementPositionCounter() external onlyCrossChainModule {
        positionCounter++;
    }

    function updateTick(int24 tick, uint256 liquidityDelta, bool upper) external onlyCrossChainModule {
        Tick storage tickInfo = ticks[tick];
        if (tickInfo.liquidityGross == 0 && liquidityDelta > 0) {
            tickInfo.initialized = true;
        }
        tickInfo.liquidityGross = upper
            ? tickInfo.liquidityGross - uint128(liquidityDelta)
            : tickInfo.liquidityGross + uint128(liquidityDelta);
        tickInfo.liquidityNet = upper
            ? tickInfo.liquidityNet - int128(int256(liquidityDelta))
            : tickInfo.liquidityNet + int128(int256(liquidityDelta));
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
        reserves.crossChainReserveA += uint128(amountA);
        reserves.crossChainReserveB += uint128(amountB);
    }

    function updateVolatility() external onlyCrossChainModule {
        governanceModule.updateVolatility();
    }

    function setUsedNonces(uint16 chainId, uint64 nonce, bool used) external onlyCrossChainModule {
        usedNonces[chainId][nonce] = used;
    }

    function setValidatedMessages(bytes32 messageHash, bool validated) external onlyCrossChainModule {
        validatedMessages[messageHash] = validated;
    }

    function setFailedMessage(uint256 messageId, FailedMessage memory message) external onlyCrossChainModule {
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
        uint16 chainId,
        uint64 nonce,
        uint256 estimatedConfirmationTime,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit CrossChainLiquiditySent(provider, amountA, amountB, chainId, nonce, estimatedConfirmationTime, messengerType);
    }

    function emitCrossChainLiquidityReceived(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 chainId,
        uint64 nonce,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit CrossChainLiquidityReceived(provider, amountA, amountB, chainId, nonce, messengerType);
    }

    function emitCrossChainSwap(
        address user,
        address inputToken,
        uint256 amountIn,
        uint256 amountOut,
        uint16 chainId,
        uint64 nonce,
        uint256 estimatedConfirmationTime,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit CrossChainSwap(user, inputToken, amountIn, amountOut, chainId, nonce, estimatedConfirmationTime, messengerType);
    }

    function emitFailedMessageStored(
        uint256 messageId,
        uint16 dstChainId,
        bytes memory sender,
        uint256 timestamp,
        uint8 messengerType
    ) external onlyCrossChainModule {
        emit FailedMessageStored(messageId, dstChainId, sender, timestamp, messengerType);
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

    function emitBatchMessagesSent(uint16[] memory dstChainIds, uint8 messengerType, uint256 totalNativeFee) external onlyCrossChainModule {
        emit BatchMessagesSent(dstChainIds, messengerType, totalNativeFee);
    }

    function emitBatchRetryProcessed(uint256[] memory messageIds, uint256 successfulRetries, uint256 failedRetries) external onlyCrossChainModule {
        emit BatchRetryProcessed(messageIds, successfulRetries, failedRetries);
    }

    function emitPositionCreated(uint256 positionId, address owner, int24 tickLower, int24 tickUpper, uint256 liquidity) external onlyCrossChainModule {
        emit PositionUpdated(positionId, tickLower, tickUpper, liquidity);
    }
}