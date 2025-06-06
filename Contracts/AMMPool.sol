// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin imports for upgradeable contracts and token handling
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {UD60x18, ud} from "@prb/math/src/UD60x18.sol"; // Adjust based on actual PRBMath library

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
        string calldata dstAxelarChain,
        bytes calldata destinationAddress,
        bytes calldata payload,
        bytes calldata adapterParams,
        address refundAddress
    ) external payable;

    function estimateFees(
        uint16 dstChainId,
        string calldata dstAxelarChain,
        address userApplication,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);

    function receiveMessage(
        uint16 srcChainId,
        string calldata srcAxelarChain,
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

// PriceOracle interface
interface IPriceOracle {
    function getPrice(address asset) external returns (uint256);
    function getCurrentPrice(address asset) external view returns (uint256);
    function getCurrentPairPrice(address baseToken, address quoteToken) external view returns (uint256, bool);
}

/// @title AMMPool - An upgradeable AMM pool with cross-chain capabilities
/// @notice Implements a Uniswap-style AMM with cross-chain support for LayerZero, Axelar, and Wormhole
/// @dev Uses OpenZeppelin upgradeable contracts, integrates with PriceOracle.sol, and handles token pair orientation
contract AMMPool is Initializable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable constants
    string public immutable VERSION;
    uint256 public immutable MIN_TIMELOCK;
    uint256 public immutable MAX_TIMELOCK;
    uint256 public immutable MAX_BATCH_SIZE;
    uint256 public immutable MAX_GAS_LIMIT;
    uint256 public immutable GOVERNANCE_TIMELOCK;
    uint256 public immutable MAX_RETRIES;
    uint256 public immutable MAX_ORACLE_ATTEMPTS;

    // Storage variables
    address public tokenA;
    address public tokenB;

    struct Reserves {
        uint256 reserveA;
        uint256 reserveB;
        uint256 crossChainReserveA;
        uint256 crossChainReserveB;
    }
    Reserves public reserves;

    struct FeeConfig {
        uint256 baseFee;
        uint256 maxFee;
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

    // New storage for cross-chain messengers
    mapping(uint8 => address) public crossChainMessengers; // 0 = LayerZero, 1 = Axelar, 2 = Wormhole
    address public axelarGasService; // Axelar gas service for gas payments
    mapping(uint16 => string) public chainIdToAxelarChain; // LayerZero/Wormhole chainId to Axelar chain name
    mapping(string => uint16) public axelarChainToChainId; // Axelar chain name to chainId
    mapping(uint16 => bytes32) public wormholeTrustedSenders; // Wormhole trusted sender addresses

    struct FailedMessage {
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 timestamp;
        uint8 messengerType; // 0 = LayerZero, 1 = Axelar, 2 = Wormhole
    }
    mapping(uint256 => FailedMessage) public failedMessages;
    uint256 public failedMessageCount;

    struct GovernanceProposal {
        address target;
        bytes data;
        uint256 proposedAt;
        bool executed;
    }
    mapping(uint256 => GovernanceProposal) public governanceProposals;
    uint256 public proposalCount;

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
    error NegativeOraclePrice(int256 price);
    error OracleFailure();
    error PendingVRFRequest();
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error InvalidMessengerType(uint8 messengerType);
    error InvalidWormholeVAA();
    error MessengerNotSet(uint8 messengerType);

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
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes payload, uint8 messengerType);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries, uint8 messengerType);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event AllLPFeesClaimed(address indexed provider, uint256 amountA, uint256 amountB);
    event OracleFailover(address indexed failedOracle, address indexed newOracle);

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
        VERSION = _version;
        MIN_TIMELOCK = _minTimelock;
        MAX_TIMELOCK = _maxTimelock;
        MAX_BATCH_SIZE = _maxBatchSize;
        MAX_GAS_LIMIT = _maxGasLimit;
        GOVERNANCE_TIMELOCK = _governanceTimelock;
        MAX_RETRIES = _maxRetries;
        MAX_ORACLE_ATTEMPTS = 3;
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
        uint256 _defaultTimelock,
        uint256 _targetReserveRatio
    ) external initializer {
        if (_tokenA >= _tokenB) revert InvalidAddress(_tokenA, "TokenA must be less than TokenB");
        if (_tokenA == address(0) || _tokenB == address(0) || _treasury == address(0) ||
            _layerZeroEndpoint == address(0) || _axelarGateway == address(0) ||
            _axelarGasService == address(0) || _wormholeCore == address(0) ||
            _tokenBridge == address(0) || _primaryPriceOracle == address(0) ||
            _governance == address(0)) 
            revert InvalidAddress(address(0), "Zero address not allowed");
        if (_defaultTimelock < MIN_TIMELOCK || _defaultTimelock > MAX_TIMELOCK) 
            revert InvalidTimelock(_defaultTimelock);
        if (_targetReserveRatio == 0) 
            revert InvalidReserveRatio(_targetReserveRatio);

        // Validate fallback oracles
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
        crossChainMessengers[0] = _layerZeroEndpoint; // LayerZero
        crossChainMessengers[1] = _axelarGateway; // Axelar
        crossChainMessengers[2] = _wormholeCore; // Wormhole
        axelarGasService = _axelarGasService;
        tokenBridge = _tokenBridge;
        primaryPriceOracle = _primaryPriceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        governance = _governance;
        chainTimelocks[1] = _defaultTimelock;
        targetReserveRatio = _targetReserveRatio;
        chainFees[1] = FeeConfig({baseFee: 20, maxFee: 100});
        lpFeeShare = 8333;
        treasuryFeeShare = 1667;
        emaPeriod = 100;
        volatilityThreshold = 1e16;
        priceDeviationThreshold = 1e16;
        tokenBridgeType[_tokenA] = 1;
        tokenBridgeType[_tokenB] = 1;
    }

    // Authorize upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // Core AMM functions
    function addLiquidity(uint256 amountA, uint256 amountB) external whenNotPaused nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        uint256 liquidity;
        if (totalLiquidity == 0) {
            UD60x18 sqrtResult = ud(amountA * amountB).sqrt();
            liquidity = sqrtResult.unwrap();
        } else {
            liquidity = (amountA * totalLiquidity) / reserves.reserveA;
            uint256 liquidityB = (amountB * totalLiquidity) / reserves.reserveB;
            liquidity = liquidity < liquidityB ? liquidity : liquidityB;
        }

        unchecked {
            liquidityBalance[msg.sender] += liquidity;
            totalLiquidity += liquidity;
            reserves.reserveA += amountA;
            reserves.reserveB += amountB;
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
            reserves.reserveA -= amountA;
            reserves.reserveB -= amountB;
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

        (uint256 reserveIn, uint256 reserveOut) = inputToken == tokenA 
            ? (reserves.reserveA, reserves.reserveB) 
            : (reserves.reserveB, reserves.reserveA);
        uint256 currentFee = _getDynamicFee(1);
        uint256 amountInWithFee = (amountIn * (10000 - currentFee)) / 10000;
        uint256 lpFee = (amountIn * currentFee * lpFeeShare) / 10000;
        uint256 treasuryFee = (amountIn * currentFee * treasuryFeeShare) / 10000;

        if (useConstantSum) {
            amountOut = amountInWithFee;
        } else {
            amountOut = (reserveOut * amountInWithFee) / (reserveIn + amountInWithFee);
        }

        if (amountOut < minAmountOut) revert InsufficientOutputAmount(amountOut, minAmountOut);
        if (amountOut > reserveOut) revert InsufficientReserve(amountOut, reserveOut);

        _validatePrice(inputToken, amountIn, amountOut);

        if (inputToken == tokenA) {
            unchecked {
                reserves.reserveA += amountIn;
                reserves.reserveB -= amountOut;
            }
            IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountOut);
        } else {
            unchecked {
                reserves.reserveB += amountIn;
                reserves.reserveA -= amountOut;
            }
            IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountOut);
        }

        IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
        lpFees[msg.sender][inputToken] += lpFee;

        _updateVolatility();
        emit Swap(msg.sender, inputToken, amountIn, amountOut);
    }

    function claimLPFees(address token) external nonReentrant {
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

    // Cross-chain functions
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

    function addLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridgeType[tokenA] != 1 && tokenBridgeType[tokenA] != 2) revert InvalidBridgeType(tokenBridgeType[tokenA]);
        if (tokenBridgeType[tokenB] != 1 && tokenBridgeType[tokenB] != 2) revert InvalidBridgeType(tokenBridgeType[tokenB]);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        uint256 balanceBeforeA = IERC20Upgradeable(tokenA).balanceOf(address(this));
        uint256 balanceBeforeB = IERC20Upgradeable(tokenB).balanceOf(address(this));

        if (tokenBridgeType[tokenA] == 1) {
            ITokenBridge(tokenBridge).burn(tokenA, amountA, msg.sender, dstChainId);
        } else {
            ITokenBridge(tokenBridge).lock(tokenA, amountA, msg.sender, dstChainId);
        }
        if (IERC20Upgradeable(tokenA).balanceOf(address(this)) != balanceBeforeA) revert InvalidAmount(amountA, 0);

        if (tokenBridgeType[tokenB] == 1) {
            ITokenBridge(tokenBridge).burn(tokenB, amountB, msg.sender, dstChainId);
        } else {
            ITokenBridge(tokenBridge).lock(tokenB, amountB, msg.sender, dstChainId);
        }
        if (IERC20Upgradeable(tokenB).balanceOf(address(this)) != balanceBeforeB) revert InvalidAmount(amountB, 0);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, amountA, amountB, nonce, block.timestamp + timelock);

        bool success;
        for (uint8 i = 0; i < 3; i++) { // Try LayerZero, Axelar, Wormhole
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(dstChainId, dstAxelarChain, address(this), payload, adapterParams);
            if (msg.value < nativeFee) continue;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                dstChainId,
                dstAxelarChain,
                destinationAddress,
                payload,
                adapterParams,
                payable(msg.sender)
            ) {
                if (msg.value > nativeFee) {
                    payable(msg.sender).transfer(msg.value - nativeFee);
                }
                emit CrossChainLiquiditySent(msg.sender, amountA, amountB, dstChainId, nonce, block.timestamp + timelock, i);
                success = true;
                break;
            } catch {
                continue;
            }
        }
        if (!success) {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                messengerType: 0 // Default to LayerZero for failed message
            });
            emit FailedMessageStored(failedMessageCount, dstChainId, payload, 0);
            failedMessageCount++;
        }
    }

    function receiveMessage(
        uint16 srcChainId,
        string calldata srcAxelarChain,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external nonReentrant whenNotPaused whenChainNotPaused(srcChainId) {
        if (trustedRemotePools[srcChainId].length == 0) revert InvalidChainId(srcChainId);
        if (keccak256(srcAddress) != keccak256(trustedRemotePools[srcChainId])) revert InvalidAddress(msg.sender, "Invalid source address");

        uint8 messengerType;
        if (msg.sender == crossChainMessengers[0]) {
            messengerType = 0; // LayerZero
        } else if (msg.sender == crossChainMessengers[1]) {
            messengerType = 1; // Axelar
        } else if (msg.sender == crossChainMessengers[2]) {
            messengerType = 2; // Wormhole
        } else {
            revert Unauthorized();
        }

        // Validate message based on protocol
        if (messengerType == 0) {
            // LayerZero: Already validated by caller
        } else if (messengerType == 1) {
            // Axelar: Validate using gateway
            (bytes32 commandId, , , bytes32 payloadHash) = abi.decode(additionalParams, (bytes32, string, string, bytes32));
            if (!IAxelarGateway(crossChainMessengers[1]).validateContractCall(commandId, srcAxelarChain, string(srcAddress), payloadHash))
                revert InvalidAxelarChain(srcAxelarChain);
        } else if (messengerType == 2) {
            // Wormhole: Verify VAA
            (uint16 emitterChainId, bytes32 emitterAddress, uint64 sequence, bytes memory vaaPayload) = 
                IWormhole(crossChainMessengers[2]).parseAndVerifyVM(additionalParams);
            if (emitterChainId != srcChainId || emitterAddress != wormholeTrustedSenders[srcChainId] || keccak256(vaaPayload) != keccak256(payload))
                revert InvalidWormholeVAA();
        }

        (address provider, uint256 amountA, uint256 amountB, uint64 nonce, uint256 timelock) = 
            abi.decode(payload, (address, uint256, uint256, uint64, uint256));
        if (usedNonces[srcChainId][nonce]) revert InvalidNonce(nonce, nonce);
        if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);

        usedNonces[srcChainId][nonce] = true;

        uint256 balanceBeforeA = IERC20Upgradeable(tokenA).balanceOf(address(this));
        if (tokenBridgeType[tokenA] == 1) {
            ITokenBridge(tokenBridge).mint(tokenA, amountA, address(this));
        } else if (tokenBridgeType[tokenA] == 2) {
            ITokenBridge(tokenBridge).release(tokenA, amountA, address(this));
        } else {
            revert InvalidBridgeType(tokenBridgeType[tokenA]);
        }
        if (IERC20Upgradeable(tokenA).balanceOf(address(this)) < balanceBeforeA + amountA) 
            revert InvalidAmount(amountA, 0);

        uint256 balanceBeforeB = IERC20Upgradeable(tokenB).balanceOf(address(this));
        if (tokenBridgeType[tokenB] == 1) {
            ITokenBridge(tokenBridge).mint(tokenB, amountB, address(this));
        } else if (tokenBridgeType[tokenB] == 2) {
            ITokenBridge(tokenBridge).release(tokenB, amountB, address(this));
        } else {
            revert InvalidBridgeType(tokenBridgeType[tokenB]);
        }
        if (IERC20Upgradeable(tokenB).balanceOf(address(this)) < balanceBeforeB + amountB) 
            revert InvalidAmount(amountB, 0);

        uint256 liquidity;
        if (totalLiquidity == 0) {
            UD60x18 sqrtResult = ud(amountA * amountB).sqrt();
            liquidity = sqrtResult.unwrap();
        } else {
            liquidity = (amountA * totalLiquidity) / reserves.reserveA;
            uint256 liquidityB = (amountB * totalLiquidity) / reserves.reserveB;
            liquidity = liquidity < liquidityB ? liquidity : liquidityB;
        }

        unchecked {
            liquidityBalance[provider] += liquidity;
            totalLiquidity += liquidity;
            reserves.crossChainReserveA += amountA;
            reserves.crossChainReserveB += amountB;
        }

        _updateVolatility();
        emit CrossChainLiquidityReceived(provider, amountA, amountB, srcChainId, nonce, messengerType);
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
        if (tokenBridgeType[inputToken] != 1 && tokenBridgeType[inputToken] != 2) 
            revert InvalidBridgeType(tokenBridgeType[inputToken]);

        (uint256 reserveIn, uint256 reserveOut) = inputToken == tokenA 
            ? (reserves.reserveA, reserves.reserveB) 
            : (reserves.reserveB, reserves.reserveA);
        uint256 currentFee = _getDynamicFee(dstChainId);
        uint256 amountInWithFee = (amountIn * (10000 - currentFee)) / 10000;
        uint256 lpFee = (amountIn * currentFee * lpFeeShare) / 10000;
        uint256 treasuryFee = (amountIn * currentFee * treasuryFeeShare) / 10000;

        if (useConstantSum) {
            amountOut = amountInWithFee;
        } else {
            amountOut = (reserveOut * amountInWithFee) / (reserveIn + amountInWithFee);
        }

        if (amountOut < minAmountOut) revert InsufficientOutputAmount(amountOut, minAmountOut);
        if (amountOut > reserveOut) revert InsufficientReserve(amountOut, reserveOut);

        _validatePrice(inputToken, amountIn, amountOut);

        uint256 balanceBefore = IERC20Upgradeable(inputToken).balanceOf(address(this));
        IERC20Upgradeable(inputToken).safeTransferFrom(msg.sender, address(this), amountIn);
        if (IERC20Upgradeable(inputToken).balanceOf(address(this)) < balanceBefore + amountIn) 
            revert InvalidAmount(amountIn, 0);

        if (tokenBridgeType[inputToken] == 1) {
            ITokenBridge(tokenBridge).burn(inputToken, amountIn, msg.sender, dstChainId);
        } else {
            ITokenBridge(tokenBridge).lock(inputToken, amountIn, msg.sender, dstChainId);
        }

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, inputToken, amountIn, amountOut, minAmountOut, nonce, block.timestamp + timelock);

        bool success;
        for (uint8 i = 0; i < 3; i++) {
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(dstChainId, dstAxelarChain, address(this), payload, adapterParams);
            if (msg.value < nativeFee) continue;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                dstChainId,
                dstAxelarChain,
                destinationAddress,
                payload,
                adapterParams,
                payable(msg.sender)
            ) {
                if (msg.value > nativeFee) {
                    payable(msg.sender).transfer(msg.value - nativeFee);
                }
                lpFees[msg.sender][inputToken] += lpFee;
                IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
                emit CrossChainSwap(msg.sender, inputToken, amountIn, amountOut, dstChainId, nonce, block.timestamp + timelock, i);
                success = true;
                break;
            } catch {
                continue;
            }
        }
        if (!success) {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                messengerType: 0
            });
            emit FailedMessageStored(failedMessageCount, dstChainId, payload, 0);
            failedMessageCount++;
        }

        return amountOut;
    }

    function batchCrossChainMessages(
        uint16 dstChainId,
        bytes[] calldata payloads,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        if (payloads.length == 0) revert InvalidAmount(0, 0);
        if (payloads.length > MAX_BATCH_SIZE) revert BatchSizeExceeded(payloads.length);
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        _validateAdapterParams(adapterParams);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        uint256 totalNativeFee;
        uint256 gasUsed;
        uint8 successfulMessengerType;

        for (uint8 m = 0; m < 3; m++) {
            address messenger = crossChainMessengers[m];
            if (messenger == address(0)) continue;
            bool batchSuccess = true;
            uint256 batchNativeFee;

            for (uint256 i = 0; i < payloads.length; i++) {
                uint256 gasStart = gasleft();
                (address sender, uint256 amountA, uint256 amountB, uint64 payloadNonce, uint256 payloadTimelock) = 
                    abi.decode(payloads[i], (address, uint256, uint256, uint64, uint256));
                if (payloadNonce != nonce + uint64(i)) revert InvalidNonce(payloadNonce, nonce + uint64(i));
                if (payloadTimelock < block.timestamp + MIN_TIMELOCK) revert InvalidTimelock(payloadTimelock);

                (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(dstChainId, dstAxelarChain, address(this), payloads[i], adapterParams);
                batchNativeFee += nativeFee;

                try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                    dstChainId,
                    dstAxelarChain,
                    destinationAddress,
                    payloads[i],
                    adapterParams,
                    payable(msg.sender)
                ) {
                    if (amountB > 0) {
                        emit CrossChainLiquiditySent(sender, amountA, amountB, dstChainId, nonce + uint64(i), payloadTimelock, m);
                    } else {
                        (, address inputToken, uint256 amountIn, uint256 amountOut, , ,) = 
                            abi.decode(payloads[i], (address, address, uint256, uint256, uint256, uint64, uint256));
                        emit CrossChainSwap(sender, inputToken, amountIn, amountOut, dstChainId, nonce + uint64(i), payloadTimelock, m);
                    }
                } catch {
                    batchSuccess = false;
                    break;
                }

                gasUsed += gasStart - gasleft();
                if (gasUsed > MAX_GAS_LIMIT) revert GasLimitExceeded(gasUsed);
            }

            if (batchSuccess) {
                totalNativeFee = batchNativeFee;
                successfulMessengerType = m;
                break;
            }
        }

        if (totalNativeFee == 0) {
            for (uint256 i = 0; i < payloads.length; i++) {
                failedMessages[failedMessageCount] = FailedMessage({
                    dstChainId: dstChainId,
                    dstAxelarChain: dstAxelarChain,
                    payload: payloads[i],
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    messengerType: 0
                });
                emit FailedMessageStored(failedMessageCount, dstChainId, payloads[i], 0);
                failedMessageCount++;
            }
        } else {
            if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);
            if (msg.value > totalNativeFee) {
                payable(msg.sender).transfer(msg.value - totalNativeFee);
            }
        }
    }

    function retryFailedMessage(uint256 messageId) external payable onlyOwner nonReentrant {
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotFailed(messageId);
        if (message.retries >= MAX_RETRIES) revert MaxRetriesExceeded(messageId);

        address messenger = crossChainMessengers[message.messengerType];
        if (messenger == address(0)) revert MessengerNotSet(message.messengerType);

        (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(
            message.dstChainId, message.dstAxelarChain, address(this), message.payload, message.adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        message.retries++;
        message.timestamp = block.timestamp;

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
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries, message.messengerType);
            delete failedMessages[messageId];
        } catch {
            emit FailedMessageStored(messageId, message.dstChainId, message.payload, message.messengerType);
        }
    }

    function recoverFailedMessage(uint256 messageId, address recipient) external onlyOwner nonReentrant {
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotFailed(messageId);
        if (message.retries < MAX_RETRIES) revert MessageNotFailed(messageId);

        (address sender, uint256 amountA, uint256 amountB, , ) = abi.decode(message.payload, (address, uint256, uint256, uint64, uint256));
        if (amountB > 0) {
            IERC20Upgradeable(tokenA).safeTransfer(recipient, amountA);
            IERC20Upgradeable(tokenB).safeTransfer(recipient, amountB);
        } else {
            (, address inputToken, uint256 amountIn, , , , ) = 
                abi.decode(message.payload, (address, address, uint256, uint256, uint256, uint64, uint256));
            IERC20Upgradeable(inputToken).safeTransfer(recipient, amountIn);
        }

        emit FailedMessageRecovered(messageId, recipient);
        delete failedMessages[messageId];
    }

    function receiveSwapCrossChain(
        uint16 srcChainId,
        string calldata srcAxelarChain,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external nonReentrant whenNotPaused whenChainNotPaused(srcChainId) {
        if (trustedRemotePools[srcChainId].length == 0) revert InvalidChainId(srcChainId);
        if (keccak256(srcAddress) != keccak256(trustedRemotePools[srcChainId])) revert InvalidAddress(msg.sender, "Invalid source address");

        uint8 messengerType;
        if (msg.sender == crossChainMessengers[0]) {
            messengerType = 0; // LayerZero
        } else if (msg.sender == crossChainMessengers[1]) {
            messengerType = 1; // Axelar
        } else if (msg.sender == crossChainMessengers[2]) {
            messengerType = 2; // Wormhole
        } else {
            revert Unauthorized();
        }

        if (messengerType == 0) {
            // LayerZero: Already validated
        } else if (messengerType == 1) {
            (bytes32 commandId, , , bytes32 payloadHash) = abi.decode(additionalParams, (bytes32, string, string, bytes32));
            if (!IAxelarGateway(crossChainMessengers[1]).validateContractCall(commandId, srcAxelarChain, string(srcAddress), payloadHash))
                revert InvalidAxelarChain(srcAxelarChain);
        } else if (messengerType == 2) {
            (uint16 emitterChainId, bytes32 emitterAddress, , bytes memory vaaPayload) = 
                IWormhole(crossChainMessengers[2]).parseAndVerifyVM(additionalParams);
            if (emitterChainId != srcChainId || emitterAddress != wormholeTrustedSenders[srcChainId] || keccak256(vaaPayload) != keccak256(payload))
                revert InvalidWormholeVAA();
        }

        (address user, address inputToken, uint256 amountIn, uint256 amountOut, uint256 minAmountOut, uint64 nonce, uint256 timelock) = 
            abi.decode(payload, (address, address, uint256, uint256, uint256, uint64, uint256));
        if (usedNonces[srcChainId][nonce]) revert InvalidNonce(nonce, nonce);
        if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
        if (inputToken != tokenA && inputToken != tokenB) revert InvalidToken(inputToken);
        if (amountOut < minAmountOut) revert InsufficientOutputAmount(amountOut, minAmountOut);
        if (tokenBridgeType[inputToken] != 1 && tokenBridgeType[inputToken] != 2) 
            revert InvalidBridgeType(tokenBridgeType[inputToken]);

        usedNonces[srcChainId][nonce] = true;

        address outputToken = inputToken == tokenA ? tokenB : tokenA;
        uint256 balanceBefore = IERC20Upgradeable(outputToken).balanceOf(address(this));

        if (tokenBridgeType[outputToken] == 1) {
            ITokenBridge(tokenBridge).mint(outputToken, amountOut, user);
        } else {
            ITokenBridge(tokenBridge).release(outputToken, amountOut, user);
        }

        if (IERC20Upgradeable(outputToken).balanceOf(user) < balanceBefore + amountOut) 
            revert InvalidAmount(amountOut, 0);

        if (inputToken == tokenA) {
            unchecked {
                reserves.crossChainReserveA += amountIn;
                reserves.crossChainReserveB -= amountOut;
            }
            if (amountOut > reserves.reserveB) revert InsufficientReserve(amountOut, reserves.reserveB);
        } else {
            unchecked {
                reserves.crossChainReserveB += amountIn;
                reserves.crossChainReserveA -= amountOut;
            }
            if (amountOut > reserves.reserveA) revert InsufficientReserve(amountOut, reserves.reserveA);
        }

        _updateVolatility();
        emit CrossChainSwap(user, inputToken, amountIn, amountOut, srcChainId, nonce, block.timestamp, messengerType);
    }

    function rebalanceReserves(uint16 dstChainId, bytes calldata adapterParams) 
        external 
        onlyOwner 
        whenNotPaused 
        whenChainNotPaused(dstChainId) 
        nonReentrant 
    {
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        uint256 totalReserveA = reserves.reserveA + reserves.crossChainReserveA;
        uint256 totalReserveB = reserves.reserveB + reserves.crossChainReserveB;
        if (totalReserveA == 0 || totalReserveB == 0) return;

        uint256 currentRatio = (totalReserveA * 1e18) / totalReserveB;
        if (currentRatio == targetReserveRatio) return;

        uint256 amountA;
        uint256 amountB;
        if (currentRatio > targetReserveRatio) {
            amountA = ((totalReserveA * 1e18 - totalReserveB * targetReserveRatio) * reserves.reserveA) / (totalReserveA * 1e18);
            amountB = 0;
        } else {
            amountB = ((totalReserveB * targetReserveRatio - totalReserveA * 1e18) * reserves.reserveB) / (totalReserveB * targetReserveRatio);
            amountA = 0;
        }

        if (amountA > 0) {
            if (tokenBridgeType[tokenA] != 1 && tokenBridgeType[tokenA] != 2) 
                revert InvalidBridgeType(tokenBridgeType[tokenA]);
            IERC20Upgradeable(tokenA).safeTransfer(tokenBridge, amountA);
            if (tokenBridgeType[tokenA] == 1) {
                ITokenBridge(tokenBridge).burn(tokenA, amountA, address(this), dstChainId);
            } else {
                ITokenBridge(tokenBridge).lock(tokenA, amountA, address(this), dstChainId);
            }
            unchecked { reserves.reserveA -= amountA; }
        } else if (amountB > 0) {
            if (tokenBridgeType[tokenB] != 1 && tokenBridgeType[tokenB] != 2) 
                revert InvalidBridgeType(tokenBridgeType[tokenB]);
            IERC20Upgradeable(tokenB).safeTransfer(tokenBridge, amountB);
            if (tokenBridgeType[tokenB] == 1) {
                ITokenBridge(tokenBridge).burn(tokenB, amountB, address(this), dstChainId);
            } else {
                ITokenBridge(tokenBridge).lock(tokenB, amountB, address(this), dstChainId);
            }
            unchecked { reserves.reserveB -= amountB; }
        }

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemotePools[dstChainId];
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(address(this), amountA, amountB, nonce, block.timestamp + timelock);

        bool success;
        for (uint8 i = 0; i < 3; i++) {
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(dstChainId, dstAxelarChain, address(this), payload, adapterParams);
            if (address(this).balance < nativeFee) continue;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                dstChainId,
                dstAxelarChain,
                destinationAddress,
                payload,
                adapterParams,
                payable(msg.sender)
            ) {
                emit ReservesRebalanced(dstChainId, amountA, amountB, i);
                success = true;
                break;
            } catch {
                continue;
            }
        }
        if (!success) {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                messengerType: 0
            });
            emit FailedMessageStored(failedMessageCount, dstChainId, payload, 0);
            failedMessageCount++;
        }
    }

    function syncCrossChainReserves(uint16 chainId, bytes calldata adapterParams) 
        external 
        onlyOwner 
        nonReentrant 
    {
        if (trustedRemotePools[chainId].length == 0) revert InvalidChainId(chainId);

        string memory dstAxelarChain = chainIdToAxelarChain[chainId];
        bytes memory destinationAddress = trustedRemotePools[chainId];
        uint64 nonce = _getNonce(chainId, 0);
        bytes memory payload = abi.encode(address(this), reserves.crossChainReserveA, reserves.crossChainReserveB, nonce, block.timestamp);

        bool success;
        for (uint8 i = 0; i < 3; i++) {
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            (uint256 nativeFee,) = ICrossChainMessenger(messenger).estimateFees(chainId, dstAxelarChain, address(this), payload, adapterParams);
            if (address(this).balance < nativeFee) continue;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                chainId,
                dstAxelarChain,
                destinationAddress,
                payload,
                adapterParams,
                payable(msg.sender)
            ) {
                success = true;
                break;
            } catch {
                continue;
            }
        }
        if (!success) {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: chainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                messengerType: 0
            });
            emit FailedMessageStored(failedMessageCount, chainId, payload, 0);
            failedMessageCount++;
        }
    }

    // Helper functions
    function _getNonce(uint16 chainId, uint8 messengerType) internal view returns (uint64) {
        if (messengerType == 0) {
            return ILayerZeroEndpoint(crossChainMessengers[0]).getInboundNonce(chainId, trustedRemotePools[chainId]);
        } else if (messengerType == 1) {
            return uint64(block.timestamp); // Axelar uses timestamp-based nonces
        } else if (messengerType == 2) {
            return uint64(block.timestamp); // Wormhole uses sequence numbers, approximated here
        }
        revert InvalidMessengerType(messengerType);
    }

    function emergencyWithdraw() external nonReentrant {
        if (!paused) revert Unauthorized();
        uint256 liquidity = liquidityBalance[msg.sender];
        if (liquidity == 0) revert InvalidAmount(liquidity, 0);
        if (totalLiquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = (liquidity * reserves.reserveA) / totalLiquidity;
        uint256 amountB = (liquidity * reserves.reserveB) / totalLiquidity;

        unchecked {
            liquidityBalance[msg.sender] = 0;
            totalLiquidity -= liquidity;
            reserves.reserveA -= amountA;
            reserves.reserveB -= amountB;
        }

        IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountA);
        IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountB);

        emit EmergencyWithdrawal(msg.sender, amountA, amountB);
    }

    function getReserves() external view returns (uint256, uint256, uint256, uint256) {
        return (reserves.reserveA, reserves.reserveB, reserves.crossChainReserveA, reserves.crossChainReserveB);
    }

    function getCrossChainState(uint16 chainId) 
        external 
        view 
        returns (address, address, address, address, uint256, bytes memory, uint256, uint256) 
    {
        FeeConfig memory feeConfig = chainFees[chainId];
        return (
            crossChainMessengers[0], // LayerZero
            crossChainMessengers[1], // Axelar
            crossChainMessengers[2], // Wormhole
            tokenBridge,
            chainTimelocks[chainId],
            trustedRemotePools[chainId],
            feeConfig.baseFee,
            feeConfig.maxFee
        );
    }

    function getPriceImpact(uint256 amountIn, address inputToken) external view returns (uint256) {
        (uint256 reserveIn,) = inputToken == tokenA 
            ? (reserves.reserveA + reserves.crossChainReserveA, reserves.reserveB + reserves.crossChainReserveB) 
            : (reserves.reserveB + reserves.crossChainReserveB, reserves.reserveA + reserves.crossChainReserveA);
        return (amountIn * 1e18) / (reserveIn + amountIn);
    }

    function _updateVolatility() internal {
        uint256 totalReserveA = reserves.reserveA + reserves.crossChainReserveA;
        uint256 totalReserveB = reserves.reserveB + reserves.crossChainReserveB;
        if (totalReserveA == 0 || totalReserveB == 0) return;

        uint256 currentPrice = (totalReserveB * 1e18) / totalReserveA;
        if (lastPrice != 0) {
            uint256 priceChange = currentPrice > lastPrice ? currentPrice - lastPrice : lastPrice - currentPrice;
            uint256 volatility = (priceChange * 1e18) / lastPrice;

            uint256 alpha = 2e18 / (emaPeriod + 1);
            emaVolatility = (alpha * volatility + (1e18 - alpha) * emaVolatility) / 1e18;

            useConstantSum = emaVolatility < volatilityThreshold;
        }
        lastPrice = currentPrice;
    }

    function _getDynamicFee(uint16 chainId) internal view returns (uint256) {
        FeeConfig memory feeConfig = chainFees[chainId];
        if (feeConfig.baseFee == 0) {
            feeConfig = chainFees[1];
        }
        if (emaVolatility < volatilityThreshold) {
            return feeConfig.baseFee;
        }
        uint256 feeRange = feeConfig.maxFee - feeConfig.baseFee;
        uint256 volatilityFactor = emaVolatility > 1e18 ? 1e18 : emaVolatility;
        return feeConfig.baseFee + (feeRange * volatilityFactor) / 1e18;
    }

    function _getDynamicTimelock(uint16 chainId) internal view returns (uint256) {
        uint256 timelock = chainTimelocks[chainId];
        if (timelock == 0) revert InvalidTimelock(0);
        if (emaVolatility > volatilityThreshold) {
            timelock = timelock * 2 > MAX_TIMELOCK ? MAX_TIMELOCK : timelock * 2;
        }
        return timelock;
    }

    function _validatePrice(address inputToken, uint256 amountIn, uint256 amountOut) internal {
        bool isTokenAInput = inputToken == tokenA;
        address baseToken = isTokenAInput ? tokenA : tokenB;
        address quoteToken = isTokenAInput ? tokenB : tokenA;

        (uint256 oraclePrice, bool isCached) = _getOraclePrice(primaryPriceOracle, baseToken, quoteToken);
        uint256 attempts;
        if (oraclePrice == 0) {
            if (!isCached) {
                revert PendingVRFRequest();
            }
            attempts++;
            for (uint256 i = 0; i < fallbackPriceOracles.length && attempts < MAX_ORACLE_ATTEMPTS; i++) {
                if (fallbackPriceOracles[i] == address(0)) continue;
                (oraclePrice, isCached) = _getOraclePrice(fallbackPriceOracles[i], baseToken, quoteToken);
                attempts++;
                if (oraclePrice > 0) {
                    emit OracleFailover(primaryPriceOracle, fallbackPriceOracles[i]);
                    break;
                }
                if (!isCached) revert PendingVRFRequest();
            }
            if (oraclePrice == 0) revert OracleFailure();
        }

        uint256 oraclePriceScaled = oraclePrice;
        uint256 expectedPrice = isTokenAInput ? (amountIn * 1e18) / amountOut : (amountOut * 1e18) / amountIn;

        if (!isTokenAInput) {
            oraclePriceScaled = (1e18 * 1e18) / oraclePriceScaled;
        }

        uint256 maxDeviation = (oraclePriceScaled * priceDeviationThreshold) / 1e18;
        if (expectedPrice > oraclePriceScaled + maxDeviation || expectedPrice < oraclePriceScaled - maxDeviation) {
            revert InvalidPrice(expectedPrice, oraclePriceScaled);
        }
    }

    function _getOraclePrice(address oracle, address baseToken, address quoteToken) internal view returns (uint256 price, bool isCached) {
    try IChainlinkOracle(oracle).latestRoundData() returns (
        uint80 roundId,
        int256 _price,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) {
        if (_price <= 0 || updatedAt == 0 || updatedAt > block.timestamp || answeredInRound != roundId) {
            return (0, true);
        }
        uint8 decimals = IChainlinkOracle(oracle).decimals();
        price = uint256(_price) * 1e18 / (10 ** decimals);
        isCached = true;
    } catch {
        try IPriceOracle(oracle).getCurrentPairPrice(baseToken, quoteToken) returns (uint256 _price, bool _isCached) {
            price = _price;
            isCached = _isCached;
        } catch {
            price = 0;
            isCached = true;
        }
    }
}

    function _validateAdapterParams(bytes calldata adapterParams) internal pure {
        if (adapterParams.length < 2) revert InvalidAdapterParams();
    }

    // Governance functions
    function proposeGovernanceUpdate(address target, bytes calldata data) 
        external 
        onlyGovernance 
        returns (uint256) 
    {
        uint256 proposalId = proposalCount++;
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
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (block.timestamp < proposal.proposedAt + GOVERNANCE_TIMELOCK) 
            revert ProposalNotReady(proposalId);

        proposal.executed = true;
        (bool success,) = proposal.target.call(proposal.data);
        if (!success) revert("Proposal execution failed");
        emit GovernanceProposalExecuted(proposalId);
    }

    function updateFees(
        uint16 chainId,
        uint256 _baseFee,
        uint256 _maxFee,
        uint256 _lpFeeShare,
        uint256 _treasuryFeeShare
    ) external onlyGovernance {
        if (_baseFee > _maxFee || _maxFee > 1000) revert InvalidFeeRange(_baseFee, _maxFee);
        if (_lpFeeShare + _treasuryFeeShare != 10000) revert InvalidFeeShare(_lpFeeShare, _treasuryFeeShare);
        chainFees[chainId] = FeeConfig({baseFee: _baseFee, maxFee: _maxFee});
        if (chainId == 1) {
            lpFeeShare = _lpFeeShare;
            treasuryFeeShare = _treasuryFeeShare;
        }
        emit FeesUpdated(chainId, _baseFee, _maxFee, _lpFeeShare, _treasuryFeeShare);
    }

    function pause() external onlyGovernance {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyGovernance {
        if (!paused) revert Unauthorized();
        paused = false;
        emit Unpaused(msg.sender);
    }

    function pauseChain(uint16 chainId) external onlyGovernance {
        if (chainPaused[chainId]) revert ChainPaused(chainId);
        chainPaused[chainId] = true;
        emit ChainPaused(chainId, msg.sender);
    }

    function unpauseChain(uint16 chainId) external onlyGovernance {
        if (!chainPaused[chainId]) revert Unauthorized();
        chainPaused[chainId] = false;
        emit ChainUnpaused(chainId, msg.sender);
    }

    function updateCrossChainMessenger(uint8 messengerType, address newMessenger) external onlyGovernance {
        if (messengerType > 2) revert InvalidMessengerType(messengerType);
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
        chainIdToAxelarChain[chainId] = axelarChain;
        axelarChainToChainId[axelarChain] = chainId;
        emit ChainIdMappingUpdated(chainId, axelarChain);
    }

    function updateWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) external onlyGovernance {
        wormholeTrustedSenders[chainId] = senderAddress;
        emit WormholeTrustedSenderUpdated(chainId, senderAddress);
    }

    function updateTokenBridge(address _tokenBridge) external onlyGovernance {
        if (_tokenBridge == address(0)) revert InvalidAddress(_tokenBridge, "Invalid token bridge address");
        tokenBridge = _tokenBridge;
        emit TokenBridgeUpdated(_tokenBridge);
    }

    function addTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external onlyGovernance {
        if (poolAddress.length == 0) revert InvalidAddress(address(0), "Invalid pool address");
        trustedRemotePools[chainId] = poolAddress;
        emit TrustedRemotePoolAdded(chainId, poolAddress);
    }

    function updateChainTimelock(uint16 chainId, uint256 _timelock) external onlyGovernance {
        if (_timelock < MIN_TIMELOCK || _timelock > MAX_TIMELOCK) revert InvalidTimelock(_timelock);
        chainTimelocks[chainId] = _timelock;
        emit ChainTimelockUpdated(chainId, _timelock);
    }

    function updateTokenBridgeType(address token, uint8 bridgeType) external onlyGovernance {
        if (bridgeType != 1 && bridgeType != 2) revert InvalidBridgeType(bridgeType);
        tokenBridgeType[token] = bridgeType;
        emit TokenBridgeTypeUpdated(token, bridgeType);
    }

    function updateTargetReserveRatio(uint256 _targetReserveRatio) external onlyGovernance {
        if (_targetReserveRatio == 0) revert InvalidReserveRatio(_targetReserveRatio);
        targetReserveRatio = _targetReserveRatio;
        emit TargetReserveRatioUpdated(_targetReserveRatio);
    }

    function updatePriceOracles(address _primaryPriceOracle, address[] memory _fallbackPriceOracles) 
        external 
        onlyGovernance 
    {
        if (_primaryPriceOracle == address(0)) revert InvalidAddress(_primaryPriceOracle, "Invalid primary oracle address");
        for (uint256 i = 0; i < _fallbackPriceOracles.length; i++) {
            if (_fallbackPriceOracles[i] == address(0)) continue;
            try IChainlinkOracle(_fallbackPriceOracles[i]).latestAnswer() returns (int256 answer) {
                if (answer <= 0) revert InvalidAddress(_fallbackPriceOracles[i], "Untrusted oracle");
            } catch {
                try IPriceOracle(_fallbackPriceOracles[i]).getCurrentPairPrice(tokenA, tokenB) returns (uint256 price, bool) {
                    if (price == 0) revert InvalidAddress(_fallbackPriceOracles[i], "Untrusted oracle");
                } catch {
                    revert InvalidAddress(_fallbackPriceOracles[i], "Not a valid oracle");
                }
            }
        }
        primaryPriceOracle = _primaryPriceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        emit PriceOracleUpdated(_primaryPriceOracle, _fallbackPriceOracles);
    }

    function updateGovernance(address _governance) external onlyGovernance {
        if (_governance == address(0)) revert InvalidAddress(_governance, "Invalid governance address");
        governance = _governance;
        emit GovernanceUpdated(_governance);
    }

    function updateEmaPeriod(uint256 _emaPeriod) external onlyGovernance {
        if (_emaPeriod == 0) revert InvalidAmount(_emaPeriod, 0);
        emaPeriod = _emaPeriod;
        emit EmaPeriodUpdated(_emaPeriod);
    }

    function updateVolatilityThreshold(uint256 _volatilityThreshold) external onlyGovernance {
        if (_volatilityThreshold == 0) revert InvalidAmount(_volatilityThreshold, 0);
        volatilityThreshold = _volatilityThreshold;
        emit VolatilityThresholdUpdated(_volatilityThreshold);
    }

    function updatePriceDeviationThreshold(uint256 _priceDeviationThreshold) external onlyGovernance {
        if (_priceDeviationThreshold == 0) revert InvalidAmount(_priceDeviationThreshold, 0);
        priceDeviationThreshold = _priceDeviationThreshold;
    }

    receive() external payable {}

    // Storage gap for future upgrades
    uint256[50] private __gap;
}