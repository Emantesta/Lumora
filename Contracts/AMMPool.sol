// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin imports for upgradeable contracts and token handling
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC721ReceiverUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import { IAMMPool, IPositionManager, IPriceOracle } from "./Interfaces.sol";
import {UD60x18, ud} from "@prb/math/src/UD60x18.sol";
import {TickMath} from "./external/uniswap/v3/TickMath.sol";

// Axelar interfaces
interface IAxelarGateway {
    function callContract(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload
    ) external;

    function validateContractCall(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external returns (bool);
}

interface IAxelarGasService {
    function payNativeGasForContractCall(
        address sender,
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable;
}

// Wormhole interfaces
interface IWormhole {
    function publishMessage(
        uint32 nonce,
        bytes calldata payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    function parseAndVerifyVM(bytes calldata encodedVM)
        external
        view
        returns (
            uint16 emitterChainId,
            bytes32 emitterAddress,
            uint64 sequence,
            bytes memory payload
        );
}

// Generalized cross-chain messenger interface
interface ICrossChainMessenger {
    function sendMessage(
        uint16 dstChainId,
        string memory dstAxelarChain,
        bytes calldata destinationAddress,
        bytes calldata payload,
        bytes calldata adapterParams,
        address refundAddress
    ) external payable;

    function estimateFees(
        uint16 dstChainId,
        string memory dstAxelarChain,
        address userApplication,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);

    function receiveMessage(
        uint16 srcChainId,
        string memory srcAxelarChain,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external;
}

// LayerZero interface
interface ILayerZeroEndpoint {
    function send(
        uint16 dstChainId,
        bytes calldata remoteAndLocalAddresses,
        bytes calldata payload,
        address payable refundAddress,
        address zroPaymentAddress,
        bytes calldata adapterParams
    ) external payable;

    function estimateFees(
        uint16 dstChainId,
        address userApplication,
        bytes calldata payload,
        bool payInZRO,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);

    function getInboundNonce(uint16 srcChainId, bytes calldata srcAddress) external view returns (uint64);
}

// Token bridge interface
interface ITokenBridge {
    function burn(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function mint(address token, uint256 amount, address recipient) external;
    function lock(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function release(address token, uint256 amount, address recipient) external;
}

// Governance interface
interface IGovernance {
    function isProposalPassed(uint256 proposalId) external view returns (bool);
    function propose(address target, bytes calldata data) external returns (uint256);
}

// Chainlink Oracle interface
interface IChainlinkOracle is AggregatorV3Interface {}


/// @title AMMPool - An upgradeable AMM pool with cross-chain capabilities, concentrated liquidity, dynamic curves, and fallback pool
/// @notice Implements a Uniswap V3-style AMM with cross-chain support, Curve-inspired dynamic curves, and a fallback pool
/// @dev Uses OpenZeppelin upgradeable contracts, integrates with PriceOracle.sol, and handles token pair orientation
contract AMMPool is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IERC721ReceiverUpgradeable,
    IAMMPool
{
    using SafeERC20Upgradeable for IERC20Upgradeable;
    using TickMath for int24;
    using TickMath for uint160;

    // Immutable constants
    bytes32 public immutable VERSION;
    uint256 public immutable MIN_TIMELOCK;
    uint256 public immutable MAX_TIMELOCK;
    uint256 public immutable MAX_BATCH_SIZE;
    uint256 public immutable MAX_GAS_LIMIT;
    uint256 public immutable GOVERNANCE_TIMELOCK;
    uint256 public immutable MAX_RETRIES;
    uint256 public immutable MAX_ORACLE_RETRIES;
    int24 public immutable TICK_SPACING;
    uint256 public immutable MAX_LIQUIDITY_PER_TICK;
    uint256 public immutable RETRY_DELAY;

    // Storage variables
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
        uint256 baseFee; // Base fee in basis points
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

    // Concentrated liquidity
    struct Position {
        address owner;
        int24 tickLower;
        int24 tickUpper;
        uint256 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint256 tokensOwed0;
        uint256 tokensOwed1;
    }
    mapping(uint256 => Position) public override positions;
    uint256 public override positionCounter;
    mapping(int24 => Tick) public ticks;
    struct Tick {
        uint256 liquidityGross;
        int256 liquidityNet;
        uint256 feeGrowthOutside0X128;
        uint256 feeGrowthOutside1X128;
    }
    int24 public currentTick;
    uint256 public feeGrowthGlobal0X128;
    uint256 public feeGrowthGlobal1X128;

    // Dynamic curves
    uint256 public amplificationFactor;
    uint256 public constant MAX_AMPLIFICATION = 1000;
    uint256 public constant MIN_AMPLIFICATION = 1;

    // Fallback pool
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

    // Events
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
    event VolatilityThresholdUpdated(uint256 newThreshold);
    event CrossChainMessengerUpdated(uint8 indexed messengerType, address indexed newMessenger);
    event AxelarGasServiceUpdated(address indexed newGasService);
    event ChainIdMappingUpdated(uint16 chainId, string axelarChain);
    event WormholeTrustedSenderUpdated(uint16 chainId, bytes32 senderAddress);
    event GovernanceProposalCreated(uint256 indexed proposalId, address target, bytes data, uint256 proposedAt);
    event GovernanceProposalExecuted(uint256 indexed proposalId);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes sender, uint256 timestamp, uint8 messengerType);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries, uint8 messengerType);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event AllLPFeesClaimed(address indexed provider, uint256 amountA, uint256 amountB);
    event OracleFailover(address indexed failedOracle, address indexed newOracle);
    event PositionUpdated(uint256 indexed positionId, int24 tickLower, int24 tickUpper, uint256 liquidity);
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
        if (msg.sender != governance) revert Unauthorized();
        _;
    }

    modifier onlyPositionOwner(uint256 positionId) {
        if (positions[positionId].owner != msg.sender) revert NotPositionOwner(positionId);
        _;
    }

    modifier onlyAuthorizedAdjusters(uint256 positionId) {
    Position storage position = positions[positionId];
    if (msg.sender != position.owner && msg.sender != authorizedAdjusters[positionId]) {
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

    // Initialize
    function initialize(
        address _tokenA,
        address _tokenB,
        address _treasury,
        address _layerZeroEndpoint,
        address _axelarGateway,
        address _axelarGasService,
        address _wormholeCore,
        address _tokenBridge,
        address _primaryPriceOracle,
        address[] memory _fallbackPriceOracles,
        address _governance,
        address _positionManager,
        uint256 _defaultTimelock,
        uint256 _targetReserveRatio
    ) external initializer {
        if (_tokenA >= _tokenB) revert InvalidAddress(_tokenA, "TokenA must be less than TokenB");
        if (_tokenA == address(0) || _tokenB == address(0) || _treasury == address(0) ||
            _layerZeroEndpoint == address(0) || _axelarGateway == address(0) ||
            _axelarGasService == address(0) || _wormholeCore == address(0) ||
            _tokenBridge == address(0) || _primaryPriceOracle == address(0) ||
            _governance == address(0) || _positionManager == address(0))
            revert InvalidAddress(address(0), "Zero address not allowed");
        if (_defaultTimelock < MIN_TIMELOCK || _defaultTimelock > MAX_TIMELOCK)
            revert InvalidTimelock(_defaultTimelock);
        if (_targetReserveRatio == 0)
            revert InvalidReserveRatio(_targetReserveRatio);

        bool hasValidOracle;
        for (uint256 i = 0; i < _fallbackPriceOracles.length; i++) {
            if (_fallbackPriceOracles[i] != address(0)) {
                hasValidOracle = true;
                break;
            }
        }
        if (!hasValidOracle) revert InvalidAddress(address(0), "No valid fallback oracle");

        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        tokenA = _tokenA;
        tokenB = _tokenB;
        treasury = _treasury;
        crossChainMessengers[0] = _layerZeroEndpoint;
        crossChainMessengers[1] = _axelarGateway;
        crossChainMessengers[2] = _wormholeCore;
        axelarGasService = _axelarGasService;
        tokenBridge = _tokenBridge;
        primaryPriceOracle = _primaryPriceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        governance = _governance;
        positionManager = _positionManager;
        chainTimelocks[1] = _defaultTimelock;
        targetReserveRatio = _targetReserveRatio;
        chainFees[1] = FeeConfig({baseFee: 20, maxFee: 100, volatilityMultiplier: 2});
        lpFeeShare = 8333;
        treasuryFeeShare = 1667;
        emaPeriod = 100;
        volatilityThreshold = 1e16;
        priceDeviationThreshold = 1e16;
        tokenBridgeType[_tokenA] = 1;
        tokenBridgeType[_tokenB] = 1;
        amplificationFactor = 100;
        currentTick = 0;

        priceHistory = new uint256[](PRICE_HISTORY_SIZE);

        emit PositionManagerUpdated(_positionManager);
    }

    // Authorize upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // --- Concentrated Liquidity Functions ---

    function addConcentratedLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB
    ) external whenNotPaused nonReentrant returns (uint256 positionId) {
        if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);

        uint256 liquidity = _getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);

        if (amountA > 0) IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        if (amountB > 0) IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        _updateTick(tickLower, liquidity, true);
        _updateTick(tickUpper, liquidity, false);

        positionId = positionCounter++;
        positions[positionId] = Position({
            owner: msg.sender,
            tickLower: tickLower,
            tickUpper: tickUpper,
            liquidity: liquidity,
            feeGrowthInside0LastX128: _getFeeGrowthInside(tickLower, tickUpper, 0),
            feeGrowthInside1LastX128: _getFeeGrowthInside(tickLower, tickUpper, 1),
            tokensOwed0: 0,
            tokensOwed1: 0
        });

        IPositionManager(positionManager).mintPosition(positionId, msg.sender);

        emit PositionCreated(positionId, msg.sender, tickLower, tickUpper, liquidity);
        _updateVolatility();

        _checkAndMoveToFallback(positionId);
        return positionId;
    }

    function removeConcentratedLiquidity(uint256 positionId, uint256 liquidity)
        external
        whenNotPaused
        nonReentrant
        onlyPositionOwner(positionId)
    {
        Position storage position = positions[positionId];
        if (position.liquidity < liquidity) revert InsufficientLiquidity(liquidity);

        _collectFees(positionId);

        _updateTick(position.tickLower, liquidity, false);
        _updateTick(position.tickUpper, liquidity, true);

        (uint256 amount0, uint256 amount1) = _getAmountsForLiquidity(position.tickLower, position.tickUpper, liquidity);

        unchecked {
            position.liquidity -= liquidity;
        }

        if (amount0 > 0) IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amount0);
        if (amount1 > 0) IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amount1);

        emit PositionUpdated(positionId, position.tickLower, position.tickUpper, position.liquidity);
        _updateVolatility();

        if (inFallbackPool[positionId] && position.liquidity > 0) {
            _exitFallbackPool(positionId);
        }
    }

    function collectFees(uint256 positionId) external override whenNotPaused nonReentrant onlyPositionManager {
        _collectFees(positionId);
        Position storage position = positions[positionId];
        if (position.tokensOwed0 > 0 || position.tokensOwed1 > 0) {
            emit FeesCollected(positionId, position.tokensOwed0, position.tokensOwed1);
        }
    }

    function collectFeesInternal(uint256 positionId) external onlyPositionAdjuster {
    _collectFees(positionId);
    }

    function authorizeAdjuster(uint256 positionId, address adjuster) external onlyPositionOwner(positionId) {
    if (adjuster == address(0)) revert InvalidAddress(adjuster, "Invalid adjuster address");
    authorizedAdjusters[positionId] = adjuster;
    emit PositionAdjusterUpdated(adjuster);
    }

    function emaVol() external view returns (uint256) {
        return emaVolatility;
    }

    function getcurrentTick() external view returns (int24) {
        return currentTick;
    }

    /// @notice Adjusts an existing position's tick range and liquidity
    /// @param positionId The ID of the position to adjust
    /// @param tickLower The new lower tick of the position
    /// @param tickUpper The new upper tick of the position
    /// @param liquidity The new liquidity amount for the position
    function adjust(
        uint256 positionId,
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity
    ) external override whenNotPaused nonReentrant onlyAuthorizedAdjusters(positionId) {
        // Validate position and inputs
        Position storage position = positions[positionId];
        if (position.liquidity == 0) revert PositionNotFound(positionId);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);

        // Collect outstanding fees
        _collectFees(positionId);

        // Cache position owner for gas efficiency
        address owner = position.owner;

        // Remove liquidity from old tick range
        _updateTick(position.tickLower, position.liquidity, false);
        _updateTick(position.tickUpper, position.liquidity, true);

        // Calculate token amounts for new liquidity
        (uint256 amount0, uint256 amount1) = _getAmountsForLiquidity(tickLower, tickUpper, liquidity);

        // Validate reserve updates to prevent overflow
        if (amount0 > type(uint64).max || amount1 > type(uint64).max) {
            revert InvalidAmount(amount0, amount1);
        }

        // Handle token transfers
        if (amount0 > 0 || amount1 > 0) {
            // Check allowances
            if (amount0 > 0) {
                uint256 allowanceA = IERC20Upgradeable(tokenA).allowance(owner, address(this));
                if (allowanceA < amount0) revert InvalidAmount(allowanceA, amount0);
                IERC20Upgradeable(tokenA).safeTransferFrom(owner, address(this), amount0);
                emit TokenTransferred(tokenA, owner, address(this), amount0);
            }
            if (amount1 > 0) {
                uint256 allowanceB = IERC20Upgradeable(tokenB).allowance(owner, address(this));
                if (allowanceB < amount1) revert InvalidAmount(allowanceB, amount1);
                IERC20Upgradeable(tokenB).safeTransferFrom(owner, address(this), amount1);
                emit TokenTransferred(tokenB, owner, address(this), amount1);
            }
        }

        // Handle liquidity delta (refund excess if new liquidity is lower)
        if (liquidity < position.liquidity) {
            uint256 excessLiquidity = position.liquidity - liquidity;
            (uint256 excessAmount0, uint256 excessAmount1) = _getAmountsForLiquidity(
                tickLower,
                tickUpper,
                excessLiquidity
            );
            if (excessAmount0 > 0) {
                IERC20Upgradeable(tokenA).safeTransfer(owner, excessAmount0);
                emit TokenTransferred(tokenA, address(this), owner, excessAmount0);
            }
            if (excessAmount1 > 0) {
                IERC20Upgradeable(tokenB).safeTransfer(owner, excessAmount1);
                emit TokenTransferred(tokenB, address(this), owner, excessAmount1);
            }
        }

        // Update position
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = liquidity;
        position.feeGrowthInside0LastX128 = _getFeeGrowthInside(tickLower, tickUpper, 0);
        position.feeGrowthInside1LastX128 = _getFeeGrowthInside(tickLower, tickUpper, 1);

        // Add liquidity to new tick range
        _updateTick(tickLower, liquidity, true);
        _updateTick(tickUpper, liquidity, false);

        // Update reserves
        unchecked {
            reserves.reserveA += uint64(amount0);
            reserves.reserveB += uint64(amount1);
        }

        // Check fallback pool eligibility
        _checkAndMoveToFallback(positionId);

        // Update volatility and emit event
        _updateVolatility();
        emit PositionUpdated(positionId, tickLower, tickUpper, liquidity);
        }

    // --- Fallback Pool Functions ---

    function _checkAndMoveToFallback(uint256 positionId) internal {
        Position storage position = positions[positionId];
        if (_isInRange(position.tickLower, position.tickUpper)) return;

        (uint256 amount0, uint256 amount1) = _getAmountsForLiquidity(position.tickLower, position.tickUpper, position.liquidity);

        uint256 fallbackLiquidity;
        if (fallbackReserves.totalLiquidity == 0) {
            UD60x18 sqrtResult = sqrt(ud(amount0 * amount1));
            fallbackLiquidity = sqrtResult.unwrap();
        } else {
            fallbackLiquidity = (amount0 * fallbackReserves.totalLiquidity) / fallbackReserves.reserveA;
            uint256 liquidityB = (amount1 * fallbackReserves.totalLiquidity) / fallbackReserves.reserveB;
            fallbackLiquidity = liquidityB < fallbackLiquidity ? liquidityB : fallbackLiquidity;
        }

        unchecked {
            fallbackReserves.reserveA += amount0;
            fallbackReserves.reserveB += amount1;
            fallbackReserves.totalLiquidity += fallbackLiquidity;
            fallbackLiquidityBalance[position.owner] += fallbackLiquidity;
        }

        inFallbackPool[positionId] = true;
        emit FallbackPoolEntered(positionId, position.liquidity);
    }

    function _exitFallbackPool(uint256 positionId) internal {
        Position storage position = positions[positionId];
        if (!inFallbackPool[positionId]) return;

        uint256 fallbackLiquidity = fallbackLiquidityBalance[position.owner];
        if (fallbackLiquidity == 0) return;

        uint256 amountA = (fallbackLiquidity * fallbackReserves.reserveA) / fallbackReserves.totalLiquidity;
        uint256 amountB = (fallbackLiquidity * fallbackReserves.reserveB) / fallbackReserves.totalLiquidity;

        unchecked {
            fallbackReserves.reserveA -= amountA;
            fallbackReserves.reserveB -= amountB;
            fallbackReserves.totalLiquidity -= fallbackLiquidity;
            fallbackLiquidityBalance[position.owner] -= fallbackLiquidity;
        }

        position.liquidity += _getLiquidityForAmounts(position.tickLower, position.tickUpper, amountA, amountB);

        inFallbackPool[positionId] = false;
        emit FallbackPoolExited(positionId, position.liquidity);
    }

    function exitFallbackPool(uint256 positionId) external override whenNotPaused nonReentrant onlyPositionOwner(positionId) {
    _exitFallbackPool(positionId);
    }

    function exitFallbackPoolInternal(uint256 positionId) external onlyPositionAdjuster {
    _exitFallbackPool(positionId);
    }

    function compoundFallbackFeesInternal(uint256 positionId, uint256 tokensOwed0, uint256 tokensOwed1) external onlyPositionAdjuster {
    Position storage position = positions[positionId];
    if (!inFallbackPool[positionId]) revert InvalidOperation("Position not in fallback pool");
    if (tokensOwed0 == 0 && tokensOwed1 == 0) revert InvalidAmount(0, 0);

    uint256 additionalLiquidity;
    if (fallbackReserves.totalLiquidity == 0) {
        UD60x18 sqrtResult = sqrt(ud(tokensOwed0 * tokensOwed1));
        additionalLiquidity = sqrtResult.unwrap();
    } else {
        additionalLiquidity = (tokensOwed0 * fallbackReserves.totalLiquidity) / fallbackReserves.reserveA;
        uint256 liquidityB = (tokensOwed1 * fallbackReserves.totalLiquidity) / fallbackReserves.reserveB;
        additionalLiquidity = liquidityB < additionalLiquidity ? liquidityB : additionalLiquidity;
    }

    unchecked {
        fallbackReserves.reserveA += tokensOwed0;
        fallbackReserves.reserveB += tokensOwed1;
        fallbackReserves.totalLiquidity += additionalLiquidity;
        fallbackLiquidityBalance[position.owner] += additionalLiquidity;
        position.liquidity += additionalLiquidity;
        position.tokensOwed0 = 0;
        position.tokensOwed1 = 0;
    }

    emit FallbackPoolEntered(positionId, additionalLiquidity);
    }

    function transferToken(address token, address recipient, uint256 amount) external onlyPositionAdjuster {
    if (token != tokenA && token != tokenB) revert InvalidToken(token);
    if (amount == 0) revert InvalidAmount(amount, 0);
    IERC20Upgradeable(token).safeTransfer(recipient, amount);
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

        _updateVolatility();
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

        _updateVolatility();
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
        uint256 fee = _getDynamicFee(1);
        uint256 amountInWithFee = (amountIn * (10000 - fee)) / 10000;
        uint256 lpFee = (amountIn * fee * lpFeeShare) / 10000;
        uint256 treasuryFee = (amountIn * fee * treasuryFeeShare) / 10000;

        amountOut = _swapConcentratedLiquidity(isTokenAInput, amountInWithFee);
        if (amountOut == 0) {
            (uint256 reserveIn, uint256 reserveOut) = isTokenAInput
                ? (uint256(reserves.reserveA), uint256(reserves.reserveB))
                : (uint256(reserves.reserveB), uint256(reserves.reserveA));

            if (useConstantSum && emaVolatility < volatilityThreshold) {
                amountOut = _swapConstantSum(amountInWithFee, reserveIn, reserveOut);
            } else {
                amountOut = (reserveOut * amountInWithFee) / (reserveIn + amountInWithFee);
            }

            if (amountOut >= minAmountOut && amountOut <= reserveOut) {
                _updateReserves(isTokenAInput, amountIn, amountOut);
            } else {
                amountOut = _swapFallbackPool(isTokenAInput, amountInWithFee);
                if (amountOut < minAmountOut || amountOut > (isTokenAInput ? fallbackReserves.reserveB : fallbackReserves.reserveA)) {
                    revert InsufficientOutputAmount(amountOut, minAmountOut);
                }
                _updateFallbackReserves(isTokenAInput, amountIn, amountOut);
            }
        }

        _validatePrice(inputToken, amountIn, amountOut);

        address outputToken = isTokenAInput ? tokenB : tokenA;
        IERC20Upgradeable(inputToken).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20Upgradeable(outputToken).safeTransfer(msg.sender, amountOut);
        IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
        lpFees[msg.sender][inputToken] += lpFee;

        _updateVolatility();
        emit Swap(msg.sender, inputToken, amountIn, amountOut);
    }

    // --- Cross-Chain Functions ---

    function addLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        _bridgeTokens(tokenA, amountA, msg.sender, dstChainId);
        _bridgeTokens(tokenB, amountB, msg.sender, dstChainId);

        string memory AxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, amountA, amountB, nonce, block.timestamp + timelock, false, int24(0), int24(0));

        _sendCrossChainMessage(dstChainId, AxelarChain, destinationAddress, payload, adapterParams, nonce, timelock, 0);
        emit CrossChainLiquiditySent(msg.sender, amountA, amountB, dstChainId, nonce, block.timestamp + timelock, 0);
    }

    function addConcentratedLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        int24 tickLower,
        int24 tickUpper,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable override whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        _bridgeTokens(tokenA, amountA, msg.sender, dstChainId);
        _bridgeTokens(tokenB, amountB, msg.sender, dstChainId);

        string memory AxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, amountA, amountB, nonce, block.timestamp + timelock, true, tickLower, tickUpper, tokenA, tokenB);

        _sendCrossChainMessage(dstChainId, AxelarChain, destinationAddress, payload, adapterParams, nonce, timelock, 0);
        emit CrossChainLiquiditySent(msg.sender, amountA, amountB, dstChainId, nonce, block.timestamp + timelock, 0);
    }

    function receiveMessage(
    uint16 srcChainId,
    string memory srcAxelarChain,
    bytes calldata srcAddress,
    bytes calldata payload,
    bytes calldata additionalParams
) external nonReentrant whenNotPaused whenChainNotPaused(srcChainId) {
    _validateCrossChainMessage(srcChainId, srcAddress, payload, additionalParams);

    (
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint64 nonce,
        uint256 timelock,
        bool isConcentrated,
        int24 tickLower,
        int24 tickUpper,
        address receivedTokenA,
        address receivedTokenB
    ) = abi.decode(payload, (address, uint256, uint256, uint64, uint256, bool, int24, int24, address, address));

    if (usedNonces[srcChainId][nonce]) revert InvalidNonce(nonce, nonce);
    if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
    if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
    if (isConcentrated && (receivedTokenA != tokenA || receivedTokenB != tokenB)) revert InvalidToken(receivedTokenA);

    usedNonces[srcChainId][nonce] = true;

    _receiveBridgedTokens(tokenA, amountA);
    _receiveBridgedTokens(tokenB, amountB);

    uint256 liquidity;
    uint256 positionId;
    if (isConcentrated) {
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);
        liquidity = _getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB);
        positionId = positionCounter++;
        positions[positionId] = Position({
            owner: provider,
            tickLower: tickLower,
            tickUpper: tickUpper,
            liquidity: liquidity,
            feeGrowthInside0LastX128: _getFeeGrowthInside(tickLower, tickUpper, 0),
            feeGrowthInside1LastX128: _getFeeGrowthInside(tickLower, tickUpper, 1),
            tokensOwed0: 0,
            tokensOwed1: 0
        });
        _updateTick(tickLower, liquidity, true);
        _updateTick(tickUpper, liquidity, false);
        IPositionManager(positionManager).mintPosition(positionId, provider);
        emit PositionCreated(positionId, provider, tickLower, tickUpper, liquidity);
        _checkAndMoveToFallback(positionId);
    } else {
        if (totalLiquidity == 0) {
            UD60x18 sqrtResult = sqrt(ud(amountA * amountB));
            liquidity = sqrtResult.unwrap();
        } else {
            liquidity = (amountA * totalLiquidity) / reserves.reserveA;
            uint256 liquidityB = (amountB * totalLiquidity) / reserves.reserveB;
            liquidity = liquidity < liquidityB ? liquidity : liquidityB;
        }
        unchecked {
            liquidityBalance[provider] += liquidity;
            totalLiquidity += liquidity;
            reserves.crossChainReserveA += uint128(amountA);
            reserves.crossChainReserveB += uint128(amountB);
        }
    }

    _updateVolatility();
    emit CrossChainLiquidityReceived(provider, amountA, amountB, srcChainId, nonce, _getMessengerType());
}

    // --- Cross-Chain Retry Mechanism ---

    function retryFailedMessage(uint256 messageId) external payable nonReentrant {
        FailedMessage storage message = failedMessages[messageId];
        if (message.retries >= MAX_RETRIES) revert MaxRetriesExceeded(messageId);
        if (message.timestamp == 0) revert MessageNotFailed(messageId);
        if (block.timestamp < message.nextRetryTimestamp) revert RetryNotReady(messageId, message.nextRetryTimestamp);

        unchecked {
            message.retries += 1;
            message.nextRetryTimestamp = block.timestamp + (RETRY_DELAY * (2 ** message.retries));
        }

        bool success;
        address messenger = crossChainMessengers[message.messengerType];
        if (messenger == address(0)) revert MessengerNotSet(message.messengerType);

        (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(
            message.dstChainId,
            message.dstAxelarChain,
            address(this),
            message.payload,
            message.adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
            message.dstChainId,
            message.dstAxelarChain,
            trustedRemotePools[message.dstChainId],
            message.payload,
            message.adapterParams,
            payable(msg.sender)
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            success = true;
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries, message.messengerType);
        } catch {
            emit FailedMessageRetryScheduled(messageId, message.nextRetryTimestamp);
        }

        if (success) {
            delete failedMessages[messageId];
            unchecked {
                failedMessageCount--;
            }
        }
    }

    function retryFailedMessagesBatch(uint256[] calldata messageIds) external payable nonReentrant {
        if (messageIds.length == 0 || messageIds.length > MAX_BATCH_SIZE) revert InvalidBatchSize(messageIds.length);

        uint256 totalNativeFee;
        uint256 successfulRetries;
        uint256 failedRetries;
        uint256[] memory processedIds = new uint256[](messageIds.length);

        for (uint256 i = 0; i < messageIds.length; i++) {
            FailedMessage storage message = failedMessages[messageIds[i]];
            if (message.retries >= MAX_RETRIES || message.timestamp == 0 || block.timestamp < message.nextRetryTimestamp) continue;

            address messenger = crossChainMessengers[message.messengerType];
            if (messenger == address(0)) continue;

            (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(
                message.dstChainId,
                message.dstAxelarChain,
                address(this),
                message.payload,
                message.adapterParams
            );
            totalNativeFee += nativeFee;
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);

        uint256 gasPerMessage = gasleft() / messageIds.length;
        uint256 refundAmount = msg.value;

        for (uint256 i = 0; i < messageIds.length; i++) {
            if (gasleft() < gasPerMessage) revert InsufficientGasForBatch(gasPerMessage, gasleft());

            FailedMessage storage message = failedMessages[messageIds[i]];
            if (message.retries >= MAX_RETRIES || message.timestamp == 0 || block.timestamp < message.nextRetryTimestamp) {
                failedRetries++;
                continue;
            }

            address messenger = crossChainMessengers[message.messengerType];
            if (messenger == address(0)) {
                failedRetries++;
                continue;
            }

            (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(
                message.dstChainId,
                message.dstAxelarChain,
                address(this),
                message.payload,
                message.adapterParams
            );

            unchecked {
                message.retries += 1;
                message.nextRetryTimestamp = block.timestamp + (RETRY_DELAY * (2 ** message.retries));
            }

            bool success;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                message.dstChainId,
                message.dstAxelarChain,
                trustedRemotePools[message.dstChainId],
                message.payload,
                message.adapterParams,
                payable(msg.sender)
            ) {
                success = true;
                refundAmount -= nativeFee;
                successfulRetries++;
                processedIds[i] = messageIds[i];
                emit FailedMessageRetried(messageIds[i], message.dstChainId, message.retries, message.messengerType);
            } catch {
                failedRetries++;
                emit FailedMessageRetryScheduled(messageIds[i], message.nextRetryTimestamp);
            }

            if (success) {
                delete failedMessages[messageIds[i]];
                unchecked {
                    failedMessageCount--;
                }
            }
        }

        if (refundAmount > 0) {
            payable(msg.sender).transfer(refundAmount);
        }

        emit BatchRetryProcessed(processedIds, successfulRetries, failedRetries);
    }

    // --- Helper Functions ---

    function _swapConcentratedLiquidity(bool isTokenAInput, uint256 amountIn) internal returns (uint256 amountOut) {
        int24 tick = currentTick;
        bool zeroForOne = isTokenAInput;
        uint256 liquidity = _getLiquidityAtTick(tick);

        if (liquidity == 0) return 0;

        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        uint160 sqrtPriceNextX96 = _calculateNextPrice(sqrtPriceX96, amountIn, liquidity, zeroForOne);
        amountOut = _calculateAmountOut(sqrtPriceX96, sqrtPriceNextX96, liquidity, zeroForOne);

        uint256 feeAmount = (amountIn * _getDynamicFee(1)) / 10000;
        if (zeroForOne) {
            feeGrowthGlobal0X128 += (feeAmount << 128) / liquidity;
        } else {
            feeGrowthGlobal1X128 += (feeAmount << 128) / liquidity;
        }

        currentTick = TickMath.getTickAtSqrtRatio(sqrtPriceNextX96);
        return amountOut;
    }

    function _swapConstantSum(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal view returns (uint256) {
        uint256 totalReserve = reserveIn + reserveOut;
        uint256 newReserveIn = reserveIn + amountIn;
        uint256 newReserveOut = (totalReserve * reserveOut) / (newReserveIn * amplificationFactor + totalReserve);
        return reserveOut - newReserveOut;
    }

    function _swapFallbackPool(bool isTokenAInput, uint256 amountIn) internal view returns (uint256 amountOut) {
        (uint256 reserveIn, uint256 reserveOut) = isTokenAInput
            ? (fallbackReserves.reserveA, fallbackReserves.reserveB)
            : (fallbackReserves.reserveB, fallbackReserves.reserveA);

        if (useConstantSum && emaVolatility < volatilityThreshold) {
            return _swapConstantSum(amountIn, reserveIn, reserveOut);
        } else {
            return (reserveOut * amountIn) / (reserveIn + amountIn);
        }
    }

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

    function _updateFallbackReserves(bool isTokenAInput, uint256 amountIn, uint256 amountOut) internal {
        if (isTokenAInput) {
            unchecked {
                fallbackReserves.reserveA += amountIn;
                fallbackReserves.reserveB -= amountOut;
            }
        } else {
            unchecked {
                fallbackReserves.reserveB += amountIn;
                fallbackReserves.reserveA -= amountOut;
            }
        }
    }

    function _isValidTickRange(int24 tickLower, int24 tickUpper) internal view returns (bool) {
        return tickLower < tickUpper &&
               tickLower % TICK_SPACING == 0 &&
               tickUpper % TICK_SPACING == 0 &&
               tickLower >= TickMath.MIN_TICK &&
               tickUpper <= TickMath.MAX_TICK;
    }

    function _updateTick(int24 tick, uint256 liquidityDelta, bool upper) internal {
        Tick storage tickInfo = ticks[tick];
        if (tickInfo.liquidityGross == 0) {
            tickInfo.feeGrowthOutside0X128 = feeGrowthGlobal0X128;
            tickInfo.feeGrowthOutside1X128 = feeGrowthGlobal1X128;
        }

        unchecked {
            tickInfo.liquidityGross = upper
                ? tickInfo.liquidityGross - liquidityDelta
                : tickInfo.liquidityGross + liquidityDelta;
            tickInfo.liquidityNet = upper
                ? tickInfo.liquidityNet - int256(liquidityDelta)
                : tickInfo.liquidityNet + int256(liquidityDelta);
        }

        if (tickInfo.liquidityGross == 0) {
            delete ticks[tick];
        }
    }

    function _getLiquidityForAmounts(
        int24 tickLower,
        int24 tickUpper,
        uint256 amount0,
        uint256 amount1
    ) internal view returns (uint256 liquidity) {
        uint160 sqrtPriceLowerX96 = TickMath.getSqrtRatioAtTick(tickLower);
        uint160 sqrtPriceUpperX96 = TickMath.getSqrtRatioAtTick(tickUpper);
        uint160 sqrtPriceCurrentX96 = TickMath.getSqrtRatioAtTick(currentTick);

        if (sqrtPriceCurrentX96 <= sqrtPriceLowerX96) {
            liquidity = (amount0 * (uint256(sqrtPriceUpperX96) - uint256(sqrtPriceLowerX96))) / uint256(sqrtPriceUpperX96);
        } else if (sqrtPriceCurrentX96 < sqrtPriceUpperX96) {
            uint256 liquidity0 = (amount0 * (uint256(sqrtPriceUpperX96) - uint256(sqrtPriceCurrentX96))) / uint256(sqrtPriceUpperX96);
            uint256 liquidity1 = (amount1 * (uint256(sqrtPriceCurrentX96) - uint256(sqrtPriceLowerX96))) / uint256(sqrtPriceCurrentX96);
            liquidity = liquidity0 < liquidity1 ? liquidity0 : liquidity1;
        } else {
            liquidity = (amount1 * (uint256(sqrtPriceUpperX96) - uint256(sqrtPriceLowerX96))) / uint256(sqrtPriceLowerX96);
        }
    }

    function _getAmountsForLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity
    ) internal view returns (uint256 amount0, uint256 amount1) {
        uint160 sqrtPriceLowerX96 = TickMath.getSqrtRatioAtTick(tickLower);
        uint160 sqrtPriceUpperX96 = TickMath.getSqrtRatioAtTick(tickUpper);
        uint160 sqrtPriceCurrentX96 = TickMath.getSqrtRatioAtTick(currentTick);

        if (sqrtPriceCurrentX96 <= sqrtPriceLowerX96) {
            amount0 = (liquidity * (uint256(sqrtPriceUpperX96) - uint256(sqrtPriceLowerX96))) / uint256(sqrtPriceUpperX96);
        } else if (sqrtPriceCurrentX96 < sqrtPriceUpperX96) {
            amount0 = (liquidity * (uint256(sqrtPriceUpperX96) - uint256(sqrtPriceCurrentX96))) / uint256(sqrtPriceUpperX96);
            amount1 = (liquidity * (uint256(sqrtPriceCurrentX96) - uint256(sqrtPriceLowerX96))) / uint256(sqrtPriceCurrentX96);
        } else {
            amount1 = (liquidity * (uint256(sqrtPriceUpperX96) - uint256(sqrtPriceLowerX96))) / uint256(sqrtPriceLowerX96);
        }
    }

    function _getFeeGrowthInside(int24 tickLower, int24 tickUpper, uint8 tokenIndex) internal view returns (uint256) {
        Tick storage lower = ticks[tickLower];
        Tick storage upper = ticks[tickUpper];
        uint256 feeGrowthGlobal = tokenIndex == 0 ? feeGrowthGlobal0X128 : feeGrowthGlobal1X128;
        uint256 feeGrowthOutsideLower = tokenIndex == 0 ? lower.feeGrowthOutside0X128 : lower.feeGrowthOutside1X128;
        uint256 feeGrowthOutsideUpper = tokenIndex == 0 ? upper.feeGrowthOutside0X128 : upper.feeGrowthOutside1X128;

        uint256 feeGrowthInside;
        if (currentTick < tickLower) {
            feeGrowthInside = feeGrowthOutsideLower - feeGrowthOutsideUpper;
        } else if (currentTick >= tickUpper) {
            feeGrowthInside = feeGrowthOutsideUpper - feeGrowthOutsideLower;
        } else {
            feeGrowthInside = feeGrowthGlobal - feeGrowthOutsideLower - feeGrowthOutsideUpper;
        }
        return feeGrowthInside;
    }

    function _collectFees(uint256 positionId) internal {
        Position storage position = positions[positionId];
        uint256 feeGrowthInside0 = _getFeeGrowthInside(position.tickLower, position.tickUpper, 0);
        uint256 feeGrowthInside1 = _getFeeGrowthInside(position.tickUpper, position.tickUpper, 1);

        unchecked {
            position.tokensOwed0 += ((feeGrowthInside0 - position.feeGrowthInside0LastX128) * position.liquidity) >> 128;
            position.tokensOwed1 += ((feeGrowthInside1 - position.feeGrowthInside1LastX128) * position.liquidity) >> 128;
            position.feeGrowthInside0LastX128 = feeGrowthInside0;
            position.feeGrowthInside1LastX128 = feeGrowthInside1;
        }
    }

    function _tickToSqrtPriceX96(int24 tick) internal pure returns (uint160 sqrtPriceX96) {
        sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
    }

    function _sqrtPriceX96ToTick(uint160 sqrtPriceX96) internal pure returns (int24 tick) {
        tick = TickMath.getTickAtSqrtRatio(sqrtPriceX96);
    }

    function _calculateNextPrice(
        uint160 sqrtPriceX96,
        uint256 amountIn,
        uint256 liquidity,
        bool zeroForOne
    ) internal pure returns (uint160 sqrtPriceNextX96) {
        uint256 delta = (amountIn << 96) / liquidity;
        sqrtPriceNextX96 = zeroForOne ? sqrtPriceX96 - uint160(delta) : sqrtPriceX96 + uint160(delta);
        if (sqrtPriceNextX96 < TickMath.MIN_SQRT_RATIO || sqrtPriceNextX96 > TickMath.MAX_SQRT_RATIO) {
            revert PriceOutOfRange();
        }
    }

    function _calculateAmountOut(
        uint160 sqrtPriceX96,
        uint160 sqrtPriceNextX96,
        uint256 liquidity,
        bool zeroForOne
    ) internal pure returns (uint256 amountOut) {
        uint256 deltaPrice = zeroForOne ? uint256(sqrtPriceX96) - uint256(sqrtPriceNextX96) : uint256(sqrtPriceNextX96) - uint256(sqrtPriceX96);
        amountOut = (liquidity * deltaPrice) >> 96;
    }

    function _isInRange(int24 tickLower, int24 tickUpper) internal view returns (bool) {
        return currentTick >= tickLower && currentTick < tickUpper;
    }

    function _getLiquidityAtTick(int24 tick) internal view returns (uint256 liquidity) {
        int24 tickLower = (tick / TICK_SPACING) * TICK_SPACING;
        int24 tickUpper = tickLower + TICK_SPACING;
        for (int24 i = TickMath.MIN_TICK; i <= tickUpper; i += TICK_SPACING) {
            if (i > tick) break;
            if (ticks[i].liquidityGross > 0) {
                liquidity += uint256(ticks[i].liquidityNet);
            }
        }
    }

    function _getDynamicFee(uint16 chainId) internal view returns (uint256 fee) {
        FeeConfig storage config = chainFees[chainId];
        if (config.baseFee == 0) return 20;

        uint256 volatilityAdjustment = (emaVolatility * config.volatilityMultiplier) / 1e18;
        fee = config.baseFee + volatilityAdjustment;
        if (fee > config.maxFee) fee = config.maxFee;

        if (emaVolatility < volatilityThreshold / 2) {
            fee = config.baseFee;
        } else if (emaVolatility > volatilityThreshold * 2) {
            fee = config.maxFee;
        }

        if (fee < 10 || fee > 1000) revert InvalidFeeRange(fee, config.maxFee);
    }

    function _updateVolatility() internal {
        (uint256 price, bool success) = _getOraclePrice();
        if (!success) return;

        if (lastPrice == 0) {
            lastPrice = price;
            priceHistory[priceHistoryIndex] = price;
            priceHistoryIndex = (priceHistoryIndex + 1) % PRICE_HISTORY_SIZE;
            return;
        }

        priceHistory[priceHistoryIndex] = price;
        priceHistoryIndex = (priceHistoryIndex + 1) % PRICE_HISTORY_SIZE;

        uint256 volatilitySum;
        uint256 count;
        uint256 previousPrice = lastPrice;

        for (uint256 i = 1; i <= VOLATILITY_WINDOW && i <= PRICE_HISTORY_SIZE; i++) {
            uint256 index = (priceHistoryIndex + PRICE_HISTORY_SIZE - i) % PRICE_HISTORY_SIZE;
            if (priceHistory[index] == 0) break;

            uint256 priceChange = priceHistory[index] > previousPrice
                ? priceHistory[index] - previousPrice
                : previousPrice - priceHistory[index];
            UD60x18 volatility = ud(priceChange).div(ud(previousPrice)).mul(ud(1e18));

            uint256 weight = VOLATILITY_WINDOW - i + 1;
            volatilitySum += volatility.unwrap() * weight;
            count += weight;
            previousPrice = priceHistory[index];
        }

        if (count > 0) {
            emaVolatility = (volatilitySum * 1e18) / count;
            emaVolatility = (emaVolatility * 2 + emaVolatility * (emaPeriod - 2)) / emaPeriod;
        }

        lastPrice = price;
        useConstantSum = emaVolatility < volatilityThreshold;
    }

    function _getOraclePrice() internal returns (uint256 price, bool success) {
        try IPriceOracle(primaryPriceOracle).getCurrentPairPrice(tokenA, tokenB) returns (uint256 _price, bool _isToken0Base) {
            price = _isToken0Base ? _price : 1e36 / _price;
            success = true;
        } catch {
            for (uint256 i = 0; i < fallbackPriceOracles.length; i++) {
                try IPriceOracle(fallbackPriceOracles[i]).getCurrentPairPrice(tokenA, tokenB) returns (uint256 _price, bool _isToken0Base) {
                    price = _isToken0Base ? _price : 1e36 / _price;
                    success = true;
                    emit OracleFailover(primaryPriceOracle, fallbackPriceOracles[i]);
                    primaryPriceOracle = fallbackPriceOracles[i];
                    break;
                } catch {
                    continue;
                }
            }
        }
        return (price, success);
    }

    function _validatePrice(address inputToken, uint256 amountIn, uint256 amountOut) internal {
        (uint256 oraclePrice, bool success) = _getOraclePrice();
        if (!success) return;

        uint256 expectedPrice = inputToken == tokenA ? (amountIn * 1e18) / amountOut : (amountOut * 1e18) / amountIn;
        uint256 deviation = expectedPrice > oraclePrice ? expectedPrice - oraclePrice : oraclePrice - expectedPrice;
        if (deviation * 1e18 / oraclePrice > priceDeviationThreshold) {
            revert InvalidPrice(oraclePrice, expectedPrice);
        }
    }

    // --- Governance Functions ---

    function updateAmplificationFactor(uint256 newA) external onlyGovernance {
        if (newA < MIN_AMPLIFICATION || newA > MAX_AMPLIFICATION) revert InvalidAmplificationFactor(newA);
        amplificationFactor = newA;
        emit AmplificationFactorUpdated(newA);
    }

    function updatePositionAdjuster(address newAdjuster) external onlyGovernance {
        if (newAdjuster == address(0)) revert InvalidAddress(newAdjuster, "Invalid adjuster address");
        positionAdjuster = newAdjuster;
        emit PositionAdjusterUpdated(newAdjuster);
    }

    function updateFeeConfig(uint16 chainId, uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) external onlyGovernance {
        if (baseFee > maxFee || baseFee < 10 || maxFee > 1000) revert InvalidFeeRange(baseFee, maxFee);
        chainFees[chainId] = FeeConfig({baseFee: baseFee, maxFee: maxFee, volatilityMultiplier: volatilityMultiplier});
        emit FeesUpdated(chainId, baseFee, maxFee, lpFeeShare, treasuryFeeShare);
    }

    function updatePositionManager(address newPositionManager) external onlyGovernance {
        if (newPositionManager == address(0)) revert InvalidAddress(newPositionManager, "Invalid position manager address");
        positionManager = newPositionManager;
        emit PositionManagerUpdated(newPositionManager);
    }

    // --- Existing Functions ---

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
        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        for (uint8 i = 0; i < 3; i++) {
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            try ICrossChainMessenger(messenger).estimateFees(dstChainId, dstAxelarChain, address(this), payload, adapterParams)
                returns (uint256 _nativeFee, uint256 _zroFee) {
                return (_nativeFee, _zroFee);
            } catch {
                continue;
            }
        }
        revert MessengerNotSet(0);
    }

    function swapCrossChain(
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant returns (uint256 amountOut) {
        if (inputToken != tokenA && inputToken != tokenB) revert InvalidToken(inputToken);
        if (amountIn == 0) revert InvalidAmount(amountIn, 0);
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        uint256 fee = _getDynamicFee(dstChainId);
        uint256 amountInWithFee = (amountIn * (10000 - fee)) / 10000;
        uint256 lpFee = (amountIn * fee * lpFeeShare) / 10000;
        uint256 treasuryFee = (amountIn * fee * treasuryFeeShare) / 10000;

        amountOut = _estimateSwapAmountOut(inputToken == tokenA, amountInWithFee);
        if (amountOut < minAmountOut) revert InsufficientOutputAmount(amountOut, minAmountOut);

        IERC20Upgradeable(inputToken).safeTransferFrom(msg.sender, address(this), amountIn);
        _bridgeTokens(inputToken, amountIn, msg.sender, dstChainId);

        string memory AxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, inputToken, amountIn, amountOut, minAmountOut, nonce, block.timestamp + timelock);

        _sendCrossChainMessage(
            dstChainId,
            AxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            nonce,
            timelock,
            0
        );
        lpFees[msg.sender][inputToken] += lpFee;
        IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
        emit CrossChainSwap(msg.sender, inputToken, amountIn, amountOut, dstChainId, nonce, block.timestamp + timelock, 0);

        return amountOut;
    }

    function _bridgeTokens(address token, uint256 amount, address recipient, uint16 dstChainId) internal {
        uint8 bridgeType = tokenBridgeType[token];
        if (bridgeType == 0) revert InvalidBridgeType(bridgeType);

        if (bridgeType == 1) {
            IERC20Upgradeable(token).safeApprove(tokenBridge, amount);
            ITokenBridge(tokenBridge).burn(token, amount, recipient, dstChainId);
        } else if (bridgeType == 2) {
            IERC20Upgradeable(token).safeApprove(tokenBridge, amount);
            ITokenBridge(tokenBridge).lock(token, amount, recipient, dstChainId);
        } else {
            revert InvalidBridgeType(bridgeType);
        }
    }

    function _receiveBridgedTokens(address token, uint256 amount) internal {
        uint8 bridgeType = tokenBridgeType[token];
        if (bridgeType == 0) revert InvalidBridgeType(bridgeType);

        if (bridgeType == 1) {
            ITokenBridge(tokenBridge).mint(token, amount, address(this));
        } else if (bridgeType == 2) {
            ITokenBridge(tokenBridge).release(token, amount, address(this));
        } else {
            revert InvalidBridgeType(bridgeType);
        }
    }

    function _sendCrossChainMessage(
        uint16 dstChainId,
        string memory AxelarChain,
        bytes memory destinationAddress,
        bytes memory payload,
        bytes memory adapterParams,
        uint64 nonce,
        uint256 timelock,
        uint8 messengerType
    ) internal {
        address messenger = crossChainMessengers[messengerType];
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(
            dstChainId,
            AxelarChain,
            address(this),
            payload,
            adapterParams
        );

        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
            dstChainId,
            AxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            payable(msg.sender)
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
        } catch {
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: AxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                messengerType: messengerType,
                nextRetryTimestamp: block.timestamp + RETRY_DELAY
            });
            emit FailedMessageStored(messageId, dstChainId, abi.encodePacked(msg.sender), block.timestamp, messengerType);
        }
    }

    function _validateCrossChainMessage(
        uint16 srcChainId,
        bytes memory srcAddress,
        bytes memory payload,
        bytes memory additionalParams
    ) internal {
        bytes32 payloadHash = keccak256(payload);
        if (validatedMessages[payloadHash]) revert InvalidMessage();
        if (keccak256(srcAddress) != keccak256(trustedRemotePools[srcChainId])) revert InvalidAddress(address(0), "Invalid source address");

        address messenger = crossChainMessengers[_getMessengerType()];
        if (messenger == address(0)) revert MessengerNotSet(0);

        try ICrossChainMessenger(messenger).receiveMessage(
            srcChainId,
            chainIdToAxelarChain[srcChainId],
            srcAddress,
            payload,
            additionalParams
        ) {
            validatedMessages[payloadHash] = true;
        } catch {
            revert InvalidCrossChainMessage("Validation failed");
        }
    }

    function _getNonce(uint16 chainId, uint8 messengerType) internal view returns(uint64) {
        address messenger = crossChainMessengers[messengerType];
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        if (messengerType == 0) {
            return ILayerZeroEndpoint(messenger).getInboundNonce(chainId, trustedRemotePools[chainId]);
        } else if (messengerType == 2) {
            (, , uint64 sequence, ) = IWormhole(messenger).parseAndVerifyVM(new bytes(0));
            return sequence;
        } else {
            return uint64(block.timestamp % type(uint64).max);
        }
    }

    function _getDynamicTimelock(uint16 chainId) internal view returns(uint256) {
        uint256 timelock = chainTimelocks[chainId];
        if (timelock == (0) || timelock < MIN_TIMELOCK || timelock > MAX_TIMELOCK) {
            return MIN_TIMELOCK;
        }
        return timelock;
    }

    function _estimateSwapAmountOut(bool isTokenAInput, uint256 amountInWithFee) internal view returns (uint256 amountOut) {
        uint256 reserveIn; 
        uint256 reserveOut;
        if (isTokenAInput) {
            reserveIn = uint256(reserves.reserveA + fallbackReserves.reserveA);
            reserveOut = uint256(reserves.reserveB + fallbackReserves.reserveB);
        } else {
            reserveIn = uint256(reserves.reserveB + fallbackReserves.reserveB);
            reserveOut = uint256(reserves.reserveA + fallbackReserves.reserveA);
        }

        if (useConstantSum && emaVolatility < volatilityThreshold) {
            return _swapConstantSum(amountInWithFee, reserveIn, reserveOut);
    } else {
            return (reserveOut * amountInWithFee) / (reserveIn + amountInWithFee);
    }
 }

    function _getMessengerType() internal view returns (uint8) {
    for (uint8 i = 0; i < 2; i++) {
        if (crossChainMessengers[i] != address(0)) {
            return i;
        }
    }
    revert MessengerNotSet(0);
 }

    function sqrt(UD60x18 x) internal pure returns (UD60x18) {
        return x.sqrt();
    }

    // --- Emergency Functions ---

    function emergencyWithdraw() external nonReentrant {
        uint256 liquidity = liquidityBalance[msg.sender];
        if (liquidity == (0)) revert InvalidAmount(0, (0));

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

    // --- Getter Functions ---

    function getReserves() external view returns (uint64 reserveA, uint64 reserveB) {
        return (reserves.reserveA, reserves.reserveB);
    }

    function getCrossChainReserves() external view returns (uint128 crossChainReserveA, uint128 crossChainReserveB) {
        return (reserves.crossChainReserveA, reserves.crossChainReserveB);
    }

    function getFallbackReserves() external view returns (uint256 reserveA, uint256 reserveB, uint256 fallbackTotalLiquidity) {
    return (fallbackReserves.reserveA, fallbackReserves.reserveB, fallbackReserves.totalLiquidity);
    }

    function getFeeConfig(uint16 chainId) external view returns (uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) {
        FeeConfig memory config = chainFees[chainId];
        return (config.baseFee, config.maxFee, config.volatilityMultiplier);
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

    function getChainTimelock(uint16 chainId) external view returns (uint256) {
        return chainTimelocks[chainId];
    }

    function getTrustedRemotePool(uint16 chainId) external view returns (bytes memory) {
        return trustedRemotePools[chainId];
    }

    function getTokenBridgeType(address token) external view returns (uint8) {
        return tokenBridgeType[token];
    }

    function getCrossChainMessenger(uint8 messengerType) external view returns (address) {
        return crossChainMessengers[messengerType];
    }

    function getChainIdMapping(uint16 chainId) external view returns (string memory) {
        return chainIdToAxelarChain[chainId];
    }

    function getWormholeTrustedSender(uint16 chainId) external view returns (bytes32) {
        return wormholeTrustedSenders[chainId];
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
        FailedMessage memory message = failedMessages[messageId];
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
        GovernanceProposal memory proposal = governanceProposals[proposalId];
        return (proposal.target, proposal.data, proposal.proposedAt, proposal.executed);
    }

    // --- IERC721Receiver Implementation ---

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    // --- Configuration Functions ---

    function updateTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external onlyGovernance {
        if (poolAddress.length == 0) revert InvalidAddress(address(0), "Invalid pool address");
        trustedRemotePools[chainId] = poolAddress;
        emit TrustedRemotePoolAdded(chainId, poolAddress);
    }

    function updateTokenBridge(address newTokenBridge) external onlyGovernance {
        if (newTokenBridge == address(0)) revert InvalidAddress(newTokenBridge, "Invalid token bridge address");
        tokenBridge = newTokenBridge;
        emit TokenBridgeUpdated(newTokenBridge);
    }

    function updateTokenBridgeType(address token, uint8 bridgeType) external onlyGovernance {
        if (bridgeType == 0) revert InvalidBridgeType(bridgeType);
        tokenBridgeType[token] = bridgeType;
        emit TokenBridgeTypeUpdated(token, bridgeType);
    }

    function updateCrossChainMessenger(uint8 messengerType, address newMessenger) external onlyGovernance {
        if (newMessenger == address(0)) revert InvalidAddress(newMessenger, "Invalid messenger address");
        crossChainMessengers[messengerType] = newMessenger;
        emit CrossChainMessengerUpdated(messengerType, newMessenger);
    }

    function updateAxelarGasService(address newGasService) external onlyGovernance {
        if (newGasService == address(0)) revert InvalidAddress(newGasService, "Invalid gas service address");
        axelarGasService = newGasService;
        emit AxelarGasServiceUpdated(newGasService);
    }

    function updateChainIdMapping(uint16 chainId, string calldata axelarChain) external onlyGovernance {
        if (bytes(axelarChain).length == 0) revert InvalidAxelarChain(axelarChain);
        chainIdToAxelarChain[chainId] = axelarChain;
        axelarChainToChainId[axelarChain] = chainId;
        emit ChainIdMappingUpdated(chainId, axelarChain);
    }

    function updateWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) external onlyGovernance {
        if (senderAddress == bytes32(0)) revert InvalidAddress(address(0), "Invalid sender address");
        wormholeTrustedSenders[chainId] = senderAddress;
        emit WormholeTrustedSenderUpdated(chainId, senderAddress);
    }

    function updateChainTimelock(uint16 chainId, uint256 newTimelock) external onlyGovernance {
        if (newTimelock < MIN_TIMELOCK || newTimelock > MAX_TIMELOCK) revert InvalidTimelock(newTimelock);
        chainTimelocks[chainId] = newTimelock;
        emit ChainTimelockUpdated(chainId, newTimelock);
    }

    function updateTargetReserveRatio(uint256 newRatio) external onlyGovernance {
        if (newRatio == 0) revert InvalidReserveRatio(newRatio);
        targetReserveRatio = newRatio;
        emit TargetReserveRatioUpdated(newRatio);
    }

    function updatePriceOracle(address newPrimaryOracle, address[] calldata newFallbackOracles) external onlyGovernance {
        if (newPrimaryOracle == address(0)) revert InvalidAddress(newPrimaryOracle, "Invalid oracle address");
        bool hasValidOracle;
        for (uint256 i = 0; i < newFallbackOracles.length; i++) {
            if (newFallbackOracles[i] != address(0)) {
                hasValidOracle = true;
                break;
            }
        }
        if (!hasValidOracle) revert InvalidAddress(address(0), "No valid fallback oracle");
        primaryPriceOracle = newPrimaryOracle;
        fallbackPriceOracles = newFallbackOracles;
        emit PriceOracleUpdated(newPrimaryOracle, newFallbackOracles);
    }

    function updateEmaPeriod(uint256 newPeriod) external onlyGovernance {
        if (newPeriod == 0) revert InvalidAmount(newPeriod, 0);
        emaPeriod = newPeriod;
        emit EmaPeriodUpdated(newPeriod);
    }

    function updateVolatilityThreshold(uint256 newThreshold) external onlyGovernance {
        if (newThreshold == 0) revert InvalidAmount(newThreshold, 0);
        volatilityThreshold = newThreshold;
        emit VolatilityThresholdUpdated(newThreshold);
    }

    function proposeGovernanceAction(address target, bytes calldata data) external onlyGovernance returns (uint256 proposalId) {
        if (target == address(0)) revert InvalidAddress(target, "Invalid target address");
        proposalId = proposalCount++;
        governanceProposals[proposalId] = GovernanceProposal({
            target: target,
            data: data,
            proposedAt: block.timestamp,
            executed: false
        });
        emit GovernanceProposalCreated(proposalId, target, data, block.timestamp);
        return proposalId;
    }

    function executeGovernanceProposal(uint256 proposalId) external onlyGovernance {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.proposedAt == 0) revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (block.timestamp < proposal.proposedAt + GOVERNANCE_TIMELOCK) revert ProposalNotReady(proposalId);

        proposal.executed = true;
        (bool success,) = proposal.target.call(proposal.data);
        if (!success) revert GovernanceProposalFailed();
        emit GovernanceProposalExecuted(proposalId);
    }

    function recoverFailedMessage(uint256 messageId, address recipient) external onlyGovernance {
    FailedMessage storage message = failedMessages[messageId];
    if (message.timestamp == 0) revert MessageNotFound(messageId);
    if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient address");

    (
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint64 nonce,
        uint256 timelock,
        bool isConcentrated,
        int24 tickLower,
        int24 tickUpper,
        address receivedTokenA,
        address receivedTokenB
    ) = abi.decode(message.payload, (address, uint256, uint256, uint64, uint256, bool, int24, int24, address, address));

    if (amountA > 0) IERC20Upgradeable(tokenA).safeTransfer(recipient, amountA);
    if (amountB > 0) IERC20Upgradeable(tokenB).safeTransfer(recipient, amountB);

    delete failedMessages[messageId];
    unchecked {
        failedMessageCount--;
    }
    emit FailedMessageRecovered(messageId, recipient);
    }
}