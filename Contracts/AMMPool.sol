// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// PRBMath for precise square root calculations
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {UD60x18, ud} from "@prb/math/UD60x18.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

// LayerZero interface for cross-chain communication
interface ILayerZeroEndpoint {
    function send(
        uint16 dstChainId,
        bytes calldata remoteAndLocalAddresses,
        bytes calldata payload,
        address payable refundAddress,
        address zroPaymentAddress,
        bytes calldata adapterParams
    ) external payable;

    function lzReceive(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external;

    function estimateFees(
        uint16 dstChainId,
        address userApplication,
        bytes calldata payload,
        bool payInZRO,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);

    function getInboundNonce(uint16 srcChainId, bytes calldata srcAddress) external view returns (uint64);
}

// Token bridge interface for cross-chain token transfers
interface ITokenBridge {
    function burn(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function mint(address token, uint256 amount, address recipient) external;
    function lock(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function release(address token, uint256 amount, address recipient) external;
}

// Governance interface for decentralized control
interface IGovernance {
    function isProposalPassed(uint256 proposalId) external view returns (bool);
    function propose(address target, bytes calldata data) external returns (uint256);
}

/// @title AMMPool - An upgradeable AMM pool with cross-chain capabilities
/// @notice Implements a Uniswap-style AMM with LayerZero cross-chain support, dynamic fees, and volatility-based curve switching
/// @dev Uses OpenZeppelin upgradeable contracts for security and flexibility
contract AMMPool is Initializable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Constants
    string public VERSION;
    uint256 public constant MIN_TIMELOCK = 1 days;
    uint256 public constant MAX_TIMELOCK = 7 days;
    uint256 public constant MAX_BATCH_SIZE = 100;
    uint256 public constant MAX_GAS_LIMIT = 1_000_000;
    uint256 public constant GOVERNANCE_TIMELOCK = 2 days;
    uint256 public constant MAX_RETRIES = 3;

    /// @notice Token A address (must be less than tokenB for pair ordering)
    address public tokenA;
    /// @notice Token B address
    address public tokenB;

    /// @notice Structure to track local and cross-chain reserves
    struct Reserves {
        uint256 reserveA; // Local reserve of tokenA
        uint256 reserveB; // Local reserve of tokenB
        uint256 crossChainReserveA; // Cross-chain reserve of tokenA
        uint256 crossChainReserveB; // Cross-chain reserve of tokenB
    }
    Reserves public reserves;

    /// @notice Chain-specific fee configurations
    struct FeeConfig {
        uint256 baseFee; // Base fee in basis points (e.g., 20 = 0.02%)
        uint256 maxFee; // Maximum fee in basis points (e.g., 100 = 1%)
    }
    mapping(uint16 => FeeConfig) public chainFees;

    /// @notice Default LP fee share (in basis points, e.g., 8333 = 83.33%)
    uint256 public lpFeeShare;
    /// @notice Default treasury fee share (in basis points, e.g., 1667 = 16.67%)
    uint256 public treasuryFeeShare;
    /// @notice Treasury address for fee collection
    address public treasury;
    /// @notice Total liquidity in the pool
    uint256 public totalLiquidity;
    /// @notice Liquidity balance per provider
    mapping(address => uint256) public liquidityBalance;
    /// @notice Accumulated LP fees per provider per token
    mapping(address => mapping(address => uint256)) public lpFees;
    /// @notice Global pause status
    bool public paused;
    /// @notice Chain-specific pause status
    mapping(uint16 => bool) public chainPaused;
    /// @notice LayerZero endpoint address
    address public layerZeroEndpoint;
    /// @notice Token bridge address
    address public tokenBridge;
    /// @notice Trusted remote pool addresses by chain ID
    mapping(uint16 => bytes) public trustedRemotePools;
    /// @notice Used nonces to prevent replay attacks
    mapping(uint16 => mapping(uint64 => bool)) public usedNonces;
    /// @notice Timelock duration per chain (in seconds)
    mapping(uint16 => uint256) public chainTimelocks;
    /// @notice Token bridge type (1 = burn/mint, 2 = lock/release)
    mapping(address => uint8) public tokenBridgeType;
    /// @notice Desired reserveA/reserveB ratio (in 1e18 precision)
    uint256 public targetReserveRatio;
    /// @notice Primary Chainlink oracle for tokenA/tokenB price
    address public primaryPriceOracle;
    /// @notice Array of fallback Chainlink oracles for redundancy
    address[] public fallbackPriceOracles;
    /// @notice Governance contract address
    address public governance;
    /// @notice EMA volatility for dynamic fee and curve switching
    uint256 public emaVolatility;
    /// @notice EMA period (default 100 blocks)
    uint256 public emaPeriod;
    /// @notice Volatility threshold for curve switching (in 1e18 precision)
    uint256 public volatilityThreshold;
    /// @notice Last recorded price (in 1e18 precision)
    uint256 public lastPrice;
    /// @notice Whether to use constant sum curve (true) or constant product (false)
    bool public useConstantSum;
    /// @notice Price deviation threshold (in 1e18 precision)
    uint256 public priceDeviationThreshold;

    /// @notice Structure to track failed cross-chain messages
    struct FailedMessage {
        uint16 dstChainId;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 timestamp;
    }
    mapping(uint256 => FailedMessage) public failedMessages;
    uint256 public failedMessageCount;

    /// @notice Structure to track governance proposals
    struct AMMGovernanceProposal {
        address target; // Target contract address
        bytes data; // Call data
        uint256 proposedAt; // Proposal timestamp
        bool executed; // Execution status
    }
    mapping(uint256 => AMMGovernanceProposal) public governanceProposals;
    uint256 public proposalCount;

    // Custom errors
    error InvalidAmount(uint256 amountA, uint256 amountB);
    error InvalidToken(address token);
    error InsufficientOutputAmount(uint256 amountOut, uint256 minAmountOut);
    error InsufficientReserve(uint256 amountOut, uint256 reserve);
    error InvalidChainId(uint16 chainId);
    error InvalidNonce(uint64 receivedNonce, uint64 expectedNonce);
    error TimelockNotExpired(uint256 currentTime, uint256 timelock);
    error InsufficientFee(uint256 provided, uint256 required);
    error InvalidFeeRange(uint256 baseFee, uint256 maxFee);
    error InvalidFeeShare(uint256 lpFeeShare, uint256 treasuryFeeShare);
    error InvalidAddress(address addr);
    error ContractPaused();
    error ChainPaused(uint16 chainId);
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
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error ProposalExecutionFailed();

    // Events
    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event Swap(address indexed user, address indexed inputToken, uint256 amountIn, uint256 amountOut);
    event FeesUpdated(uint16 indexed chainId, uint256 baseFee, uint256 maxFee, uint256 lpFeeShare, uint256 treasuryFeeShare);
    event Paused(address indexed caller);
    event Unpaused(address indexed caller);
    event AMMPoolChainPaused(uint16 indexed chainId, address indexed caller);
    event ChainUnpaused(uint16 indexed chainId, address indexed caller);
    event CrossChainLiquiditySent(address indexed provider, uint256 amountA, uint256 amountB, uint16 indexed chainId, uint64 nonce, uint256 estimatedConfirmationTime);
    event CrossChainLiquidityReceived(address indexed provider, uint256 amountA, uint256 amountB, uint16 indexed chainId, uint64 nonce);
    event CrossChainSwap(address indexed user, address indexed inputToken, uint256 amountIn, uint256 amountOut, uint16 indexed chainId, uint64 nonce, uint256 estimatedConfirmationTime);
    event ChainTimelockUpdated(uint16 indexed chainId, uint256 newTimelock);
    event TrustedRemotePoolAdded(uint16 indexed chainId, bytes poolAddress);
    event TokenBridgeUpdated(address indexed newTokenBridge);
    event TokenBridgeTypeUpdated(address indexed token, uint8 bridgeType);
    event ReservesRebalanced(uint16 indexed chainId, uint256 amountA, uint256 amountB);
    event TargetReserveRatioUpdated(uint256 newRatio);
    event LPFeeClaimed(address indexed provider, address indexed token, uint256 amount);
    event EmergencyWithdrawal(address indexed user, uint256 amountA, uint256 amountB);
    event GovernanceUpdated(address indexed newGovernance);
    event PriceOracleUpdated(address indexed primaryOracle, address[] fallbackOracles);
    event EmaPeriodUpdated(uint256 newPeriod);
    event VolatilityThresholdUpdated(uint256 newThreshold);
    event LayerZeroEndpointUpdated(address indexed newEndpoint);
    event GovernanceProposalCreated(uint256 indexed proposalId, address target, bytes data, uint256 proposedAt);
    event GovernanceProposalExecuted(uint256 indexed proposalId);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes payload);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event AllLPFeesClaimed(address indexed provider, uint256 amountA, uint256 amountB);

    /// @notice Modifier to check if the contract is not paused
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    /// @notice Modifier to check if a specific chain is not paused
    modifier whenChainNotPaused(uint16 chainId) {
        if (chainPaused[chainId]) revert ChainPaused(chainId);
        _;
    }

    /// @notice Modifier to restrict calls to LayerZero endpoint
    modifier onlyLayerZero() {
        if (msg.sender != layerZeroEndpoint) revert Unauthorized();
        _;
    }

    /// @notice Modifier to restrict calls to governance contract
    modifier onlyGovernance() {
        if (msg.sender != governance) revert Unauthorized();
        _;
    }

    /// @notice Constructor disables initializers for upgradeable contracts
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the AMM pool
    /// @param _tokenA Address of token A (must be less than tokenB)
    /// @param _tokenB Address of token B
    /// @param _treasury Treasury address for fee collection
    /// @param _layerZeroEndpoint LayerZero endpoint address
    /// @param _tokenBridge Token bridge address
    /// @param _primaryPriceOracle Primary Chainlink oracle address
    /// @param _fallbackPriceOracles Array of fallback Chainlink oracle addresses
    /// @param _governance Governance contract address
    /// @param _defaultTimelock Default timelock duration for chain ID 1
    /// @param _targetReserveRatio Desired reserveA/reserveB ratio
    function initialize(
        address _tokenA,
        address _tokenB,
        address _treasury,
        address _layerZeroEndpoint,
        address _tokenBridge,
        address _primaryPriceOracle,
        address[] memory _fallbackPriceOracles,
        address _governance,
        uint256 _defaultTimelock,
        uint256 _targetReserveRatio
    ) external initializer {
        if (_tokenA >= _tokenB) revert InvalidAddress(_tokenA);
        if (_tokenA == address(0) || _tokenB == address(0) || _treasury == address(0) ||
            _layerZeroEndpoint == address(0) || _tokenBridge == address(0) ||
            _primaryPriceOracle == address(0) || _governance == address(0)) 
            revert InvalidAddress(address(0));
        if (_defaultTimelock < MIN_TIMELOCK || _defaultTimelock > MAX_TIMELOCK) 
            revert InvalidTimelock(_defaultTimelock);
        if (_targetReserveRatio == 0) 
            revert InvalidReserveRatio(_targetReserveRatio);

        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        VERSION = "1.0.0";
        tokenA = _tokenA;
        tokenB = _tokenB;
        treasury = _treasury;
        layerZeroEndpoint = _layerZeroEndpoint;
        tokenBridge = _tokenBridge;
        primaryPriceOracle = _primaryPriceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        governance = _governance;
        chainTimelocks[1] = _defaultTimelock;
        targetReserveRatio = _targetReserveRatio;
        chainFees[1] = FeeConfig({baseFee: 20, maxFee: 100}); // 0.02% base, 1% max
        lpFeeShare = 8333; // 83.33%
        treasuryFeeShare = 1667; // 16.67%
        emaPeriod = 100;
        volatilityThreshold = 1e16; // 1%
        priceDeviationThreshold = 1e16; // 1%
        tokenBridgeType[_tokenA] = 1; // Burn/mint
        tokenBridgeType[_tokenB] = 1; // Burn/mint
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Adds liquidity to the pool
    /// @param amountA Amount of tokenA to add
    /// @param amountB Amount of tokenB to add
    function addLiquidity(uint256 amountA, uint256 amountB) external whenNotPaused nonReentrant {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);

        IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountA);
        IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountB);

        uint256 liquidity;
        if (totalLiquidity == 0) {
            UD60x18 sqrtResult = ud(amountA).mul(ud(amountB)).sqrt();
            liquidity = sqrtResult.unwrap();
        } else {
            liquidity = (amountA * totalLiquidity) / reserves.reserveA;
            uint256 liquidityB = (amountB * totalLiquidity) / reserves.reserveB;
            liquidity = liquidity < liquidityB ? liquidity : liquidityB;
        }

        if (liquidity == 0) revert InvalidAmount(amountA, amountB);

        liquidityBalance[msg.sender] += liquidity;
        totalLiquidity += liquidity;
        reserves.reserveA += amountA;
        reserves.reserveB += amountB;

        _updateVolatility();
        emit LiquidityAdded(msg.sender, amountA, amountB, liquidity);
    }

    /// @notice Removes liquidity from the pool
    /// @param liquidity Amount of liquidity tokens to burn
    function removeLiquidity(uint256 liquidity) external whenNotPaused nonReentrant {
        if (liquidity == 0 || liquidityBalance[msg.sender] < liquidity) 
            revert InvalidAmount(liquidity, liquidityBalance[msg.sender]);
        if (totalLiquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = (liquidity * reserves.reserveA) / totalLiquidity;
        uint256 amountB = (liquidity * reserves.reserveB) / totalLiquidity;

        liquidityBalance[msg.sender] -= liquidity;
        totalLiquidity -= liquidity;
        reserves.reserveA -= amountA;
        reserves.reserveB -= amountB;

        IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountA);
        IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountB);

        _updateVolatility();
        emit LiquidityRemoved(msg.sender, amountA, amountB, liquidity);
    }

    /// @notice Swaps tokens with dynamic fees and slippage protection
    /// @param inputToken Token to swap from
    /// @param amountIn Amount of input token
    /// @param minAmountOut Minimum acceptable output amount
    /// @return amountOut Actual output amount
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
        uint256 currentFee = _getDynamicFee(1); // Default chain ID for local swaps
        uint256 amountInWithFee = (amountIn * (10000 - currentFee)) / 10000;
        uint256 lpFee = (amountIn * currentFee * lpFeeShare) / (10000 * 10000);
        uint256 treasuryFee = (amountIn * currentFee * treasuryFeeShare) / (10000 * 10000);

        if (useConstantSum) {
            amountOut = amountInWithFee;
        } else {
            amountOut = (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee);
        }

        if (amountOut < minAmountOut) revert InsufficientOutputAmount(amountOut, minAmountOut);
        if (amountOut > reserveOut) revert InsufficientReserve(amountOut, reserveOut);

        _validatePrice(inputToken, amountIn, amountOut);

        if (inputToken == tokenA) {
            reserves.reserveA += amountIn;
            reserves.reserveB -= amountOut;
            IERC20Upgradeable(tokenA).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountOut);
        } else {
            reserves.reserveB += amountIn;
            reserves.reserveA -= amountOut;
            IERC20Upgradeable(tokenB).safeTransferFrom(msg.sender, address(this), amountIn);
            IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountOut);
        }

        IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
        lpFees[msg.sender][inputToken] += lpFee;

        _updateVolatility();
        emit Swap(msg.sender, inputToken, amountIn, amountOut);
    }

    /// @notice Claims accumulated LP fees for a single token
    /// @param token Token to claim fees for
    function claimLPFees(address token) external nonReentrant {
        if (token != tokenA && token != tokenB) revert InvalidToken(token);
        uint256 feeAmount = lpFees[msg.sender][token];
        if (feeAmount == 0) revert InvalidAmount(feeAmount, 0);

        lpFees[msg.sender][token] = 0;
        IERC20Upgradeable(token).safeTransfer(msg.sender, feeAmount);
        emit LPFeeClaimed(msg.sender, token, feeAmount);
    }

    /// @notice Claims accumulated LP fees for both tokens
    /// @dev Added to improve UX by allowing simultaneous fee claims
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

    /// @notice Estimates LayerZero fees for cross-chain operations
    /// @param dstChainId Destination chain ID
    /// @param payload Message payload
    /// @param adapterParams LayerZero adapter parameters
    /// @return nativeFee Native token fee
    /// @return zroFee ZRO token fee
    function getEstimatedLayerZeroFee(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) public view returns (uint256 nativeFee, uint256 zroFee) {
        _validateAdapterParams(adapterParams);
        return ILayerZeroEndpoint(layerZeroEndpoint).estimateFees(dstChainId, address(this), payload, false, adapterParams);
    }

    /// @notice Adds liquidity to a remote chain
    /// @param amountA Amount of tokenA to add
    /// @param amountB Amount of tokenB to add
    /// @param dstChainId Destination chain ID
    /// @param adapterParams LayerZero adapter parameters
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

        uint64 nonce = ILayerZeroEndpoint(layerZeroEndpoint).getInboundNonce(dstChainId, trustedRemotePools[dstChainId]);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, amountA, amountB, nonce, block.timestamp + timelock);

        (uint256 nativeFee,) = getEstimatedLayerZeroFee(dstChainId, payload, adapterParams);
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
            dstChainId,
            abi.encodePacked(trustedRemotePools[dstChainId], address(this)),
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        ) {
            if (msg.value > nativeFee) {
                Address.sendValue(payable(msg.sender), msg.value - nativeFee);
            }
            emit CrossChainLiquiditySent(msg.sender, amountA, amountB, dstChainId, nonce, block.timestamp + timelock);
        } catch {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: dstChainId,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp
            });
            emit FailedMessageStored(failedMessageCount, dstChainId, payload);
            failedMessageCount++;
        }
    }

    /// @notice Receives cross-chain liquidity
    /// @dev Called by LayerZero endpoint to process incoming liquidity
    /// @param srcChainId Source chain ID
    /// @param srcAddress Source pool address
    /// @param nonce Message nonce
    /// @param payload Encoded liquidity data
    function lzReceive(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external onlyLayerZero whenNotPaused whenChainNotPaused(srcChainId) nonReentrant {
        if (trustedRemotePools[srcChainId].length == 0) revert InvalidChainId(srcChainId);
        if (keccak256(srcAddress) != keccak256(trustedRemotePools[srcChainId])) revert InvalidAddress(msg.sender);
        if (usedNonces[srcChainId][nonce]) revert InvalidNonce(nonce, nonce);

        (address provider, uint256 amountA, uint256 amountB, uint64 receivedNonce, uint256 timelock) = 
            abi.decode(payload, (address, uint256, uint256, uint64, uint256));
        if (receivedNonce != nonce) revert InvalidNonce(receivedNonce, nonce);
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
            UD60x18 sqrtResult = ud(amountA).mul(ud(amountB)).sqrt();
            liquidity = sqrtResult.unwrap();
        } else {
            liquidity = (amountA * totalLiquidity) / reserves.reserveA;
            uint256 liquidityB = (amountB * totalLiquidity) / reserves.reserveB;
            liquidity = liquidity < liquidityB ? liquidity : liquidityB;
        }

        if (liquidity == 0) revert InvalidAmount(amountA, amountB);

        liquidityBalance[provider] += liquidity;
        totalLiquidity += liquidity;
        reserves.crossChainReserveA += amountA;
        reserves.crossChainReserveB += amountB;

        _updateVolatility();
        emit CrossChainLiquidityReceived(provider, amountA, amountB, srcChainId, nonce);
    }

    /// @notice Performs a cross-chain swap
    /// @dev Initiates a swap on a remote chain using LayerZero and token bridge
    /// @param inputToken Token to swap from
    /// @param amountIn Amount of input token
    /// @param minAmountOut Minimum acceptable output amount
    /// @param dstChainId Destination chain ID
    /// @param adapterParams LayerZero adapter parameters
    /// @return amountOut Calculated output amount
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
        uint256 lpFee = (amountIn * currentFee * lpFeeShare) / (10000 * 10000);
        uint256 treasuryFee = (amountIn * currentFee * treasuryFeeShare) / (10000 * 10000);

        if (useConstantSum) {
            amountOut = amountInWithFee;
        } else {
            amountOut = (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee);
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

        uint64 nonce = ILayerZeroEndpoint(layerZeroEndpoint).getInboundNonce(dstChainId, trustedRemotePools[dstChainId]);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(msg.sender, inputToken, amountIn, amountOut, minAmountOut, nonce, block.timestamp + timelock);

        (uint256 nativeFee,) = getEstimatedLayerZeroFee(dstChainId, payload, adapterParams);
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
            dstChainId,
            abi.encodePacked(trustedRemotePools[dstChainId], address(this)),
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        ) {
            if (msg.value > nativeFee) {
                Address.sendValue(payable(msg.sender), msg.value - nativeFee);
            }
            lpFees[msg.sender][inputToken] += lpFee;
            IERC20Upgradeable(inputToken).safeTransfer(treasury, treasuryFee);
            emit CrossChainSwap(msg.sender, inputToken, amountIn, amountOut, dstChainId, nonce, block.timestamp);
        } catch {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: dstChainId,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp
            });
            emit FailedMessageStored(failedMessageCount, dstChainId, payload);
            failedMessageCount++;
        }

        return amountOut;
    }

    /// @notice Batches cross-chain messages for liquidity or swaps
    /// @dev Optimized by caching common data and reducing redundant checks
    /// @param dstChainId Destination chain ID
    /// @param payloads Array of message payloads
    /// @param adapterParams LayerZero adapter parameters
    function batchCrossChainMessages(
        uint16 dstChainId,
        bytes[] calldata payloads,
        bytes calldata adapterParams
    ) external payable whenNotPaused whenChainNotPaused(dstChainId) nonReentrant {
        if (payloads.length == 0) revert InvalidAmount(0, 0);
        if (payloads.length > MAX_BATCH_SIZE) revert BatchSizeExceeded(payloads.length);
        if (trustedRemotePools[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        _validateAdapterParams(adapterParams);

        uint256 totalNativeFee;
        uint64 nonce = ILayerZeroEndpoint(layerZeroEndpoint).getInboundNonce(dstChainId, trustedRemotePools[dstChainId]);
        bytes memory remoteAndLocalAddresses = abi.encodePacked(trustedRemotePools[dstChainId], address(this));
        uint256 timelock = _getDynamicTimelock(dstChainId);
        uint256 gasUsed;

        for (uint256 i; i < payloads.length; ++i) {
            uint256 gasStart = gasleft();
            bool isLiquidity = payloads[i].length == 132; // Liquidity payload: (address, uint256, uint256, uint64, uint256)
            if (isLiquidity) {
                (address sender, uint256 amountA, uint256 amountB, uint64 payloadNonce, uint256 payloadTimelock) = 
                    abi.decode(payloads[i], (address, uint256, uint256, uint64, uint256));
                if (payloadNonce != nonce + uint64(i)) revert InvalidNonce(payloadNonce, nonce + uint64(i));
                if (payloadTimelock < block.timestamp + MIN_TIMELOCK) revert InvalidTimelock(payloadTimelock);

                (uint256 nativeFee,) = getEstimatedLayerZeroFee(dstChainId, payloads[i], adapterParams);
                totalNativeFee += nativeFee;

                try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
                    dstChainId,
                    remoteAndLocalAddresses,
                    payloads[i],
                    payable(msg.sender),
                    address(0),
                    adapterParams
                ) {
                    emit CrossChainLiquiditySent(sender, amountA, amountB, dstChainId, nonce + uint64(i), payloadTimelock);
                } catch {
                    failedMessages[failedMessageCount] = FailedMessage({
                        dstChainId: dstChainId,
                        payload: payloads[i],
                        adapterParams: adapterParams,
                        retries: 0,
                        timestamp: block.timestamp
                    });
                    emit FailedMessageStored(failedMessageCount, dstChainId, payloads[i]);
                    failedMessageCount++;
                }
            } else {
                (address sender, address inputToken, uint256 amountIn, uint256 amountOut, uint256 minAmountOut, uint64 payloadNonce, uint256 payloadTimelock) = 
                    abi.decode(payloads[i], (address, address, uint256, uint256, uint256, uint64, uint256));
                if (payloadNonce != nonce + uint64(i)) revert InvalidNonce(payloadNonce, nonce + uint64(i));
                if (payloadTimelock < block.timestamp + MIN_TIMELOCK) revert InvalidTimelock(payloadTimelock);

                (uint256 nativeFee,) = getEstimatedLayerZeroFee(dstChainId, payloads[i], adapterParams);
                totalNativeFee += nativeFee;

                try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
                    dstChainId,
                    remoteAndLocalAddresses,
                    payloads[i],
                    payable(msg.sender),
                    address(0),
                    adapterParams
                ) {
                    emit CrossChainSwap(sender, inputToken, amountIn, amountOut, dstChainId, nonce + uint64(i), payloadTimelock);
                } catch {
                    failedMessages[failedMessageCount] = FailedMessage({
                        dstChainId: dstChainId,
                        payload: payloads[i],
                        adapterParams: adapterParams,
                        retries: 0,
                        timestamp: block.timestamp
                    });
                    emit FailedMessageStored(failedMessageCount, dstChainId, payloads[i]);
                    failedMessageCount++;
                }
            }

            gasUsed += gasStart - gasleft();
            if (gasUsed > MAX_GAS_LIMIT) revert GasLimitExceeded(gasUsed);
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);
        if (msg.value > totalNativeFee) {
            Address.sendValue(payable(msg.sender), msg.value - totalNativeFee);
        }
    }

    /// @notice Retries a failed cross-chain message
    /// @param messageId ID of the failed message
    function retryFailedMessage(uint256 messageId) external payable onlyOwner nonReentrant {
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotFailed(messageId);
        if (message.retries >= MAX_RETRIES) revert MaxRetriesExceeded(messageId);

        (uint256 nativeFee,) = getEstimatedLayerZeroFee(message.dstChainId, message.payload, message.adapterParams);
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        message.retries++;
        message.timestamp = block.timestamp;

        try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
            message.dstChainId,
            abi.encodePacked(trustedRemotePools[message.dstChainId], address(this)),
            message.payload,
            payable(msg.sender),
            address(0),
            message.adapterParams
        ) {
            if (msg.value > nativeFee) {
                Address.sendValue(payable(msg.sender), msg.value - nativeFee);
            }
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries);
            delete failedMessages[messageId];
        } catch {
            emit FailedMessageStored(messageId, message.dstChainId, message.payload);
        }
    }

    /// @notice Recovers a failed cross-chain message after max retries
    /// @param messageId ID of the failed message
    /// @param recipient Address to receive recovered tokens
    function recoverFailedMessage(uint256 messageId, address recipient) external onlyOwner nonReentrant {
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotFailed(messageId);
        if (message.retries < MAX_RETRIES) revert MessageNotFailed(messageId);

        bool isLiquidity = message.payload.length == 132;
        if (isLiquidity) {
            (address sender, uint256 amountA, uint256 amountB, , ) = 
                abi.decode(message.payload, (address, uint256, uint256, uint64, uint256));
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

    /// @notice Receives a cross-chain swap
    /// @param srcChainId Source chain ID
    /// @param srcAddress Source pool address
    /// @param nonce Message nonce
    /// @param payload Encoded swap data
    function receiveSwapCrossChain(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external onlyLayerZero whenNotPaused whenChainNotPaused(srcChainId) nonReentrant {
        if (trustedRemotePools[srcChainId].length == 0) revert InvalidChainId(srcChainId);
        if (keccak256(srcAddress) != keccak256(trustedRemotePools[srcChainId])) revert InvalidAddress(msg.sender);
        if (usedNonces[srcChainId][nonce]) revert InvalidNonce(nonce, nonce);

        (address user, address inputToken, uint256 amountIn, uint256 amountOut, uint256 minAmountOut, uint64 receivedNonce, uint256 timelock) = 
            abi.decode(payload, (address, address, uint256, uint256, uint256, uint64, uint256));
        if (receivedNonce != nonce) revert InvalidNonce(receivedNonce, nonce);
        if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
        if (inputToken != tokenA && inputToken != tokenB) revert InvalidToken(inputToken);
        if (amountOut < minAmountOut) revert InsufficientOutputAmount(amountOut, minAmountOut);
        if (tokenBridgeType[inputToken] != 1 && tokenBridgeType[inputToken] != 2) 
            revert InvalidBridgeType(tokenBridgeType[inputToken]);

        usedNonces[srcChainId][nonce] = true;

        address outputToken = inputToken == tokenA ? tokenB : tokenA;
        uint256 balanceBefore = IERC20Upgradeable(outputToken).balanceOf(user);

        if (tokenBridgeType[outputToken] == 1) {
            ITokenBridge(tokenBridge).mint(outputToken, amountOut, user);
        } else {
            ITokenBridge(tokenBridge).release(outputToken, amountOut, user);
        }

        if (IERC20Upgradeable(outputToken).balanceOf(user) < balanceBefore + amountOut) 
            revert InvalidAmount(amountOut, 0);

        if (inputToken == tokenA) {
            reserves.crossChainReserveA += amountIn;
            if (amountOut > reserves.crossChainReserveB) revert InsufficientReserve(amountOut, reserves.crossChainReserveB);
            reserves.crossChainReserveB -= amountOut;
        } else {
            reserves.crossChainReserveB += amountIn;
            if (amountOut > reserves.crossChainReserveA) revert InsufficientReserve(amountOut, reserves.crossChainReserveA);
            reserves.crossChainReserveA -= amountOut;
        }

        _updateVolatility();
        emit CrossChainSwap(user, inputToken, amountIn, amountOut, srcChainId, nonce, block.timestamp);
    }

    /// @notice Rebalances reserves across chains
    /// @dev Adjusts reserves to match targetReserveRatio by transferring excess tokens
    /// @param dstChainId Destination chain ID
    /// @param adapterParams LayerZero adapter parameters
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
            reserves.reserveA -= amountA;
        } else if (amountB > 0) {
            if (tokenBridgeType[tokenB] != 1 && tokenBridgeType[tokenB] != 2) 
                revert InvalidBridgeType(tokenBridgeType[tokenB]);
            IERC20Upgradeable(tokenB).safeTransfer(tokenBridge, amountB);
            if (tokenBridgeType[tokenB] == 1) {
                ITokenBridge(tokenBridge).burn(tokenB, amountB, address(this), dstChainId);
            } else {
                ITokenBridge(tokenBridge).lock(tokenB, amountB, address(this), dstChainId);
            }
            reserves.reserveB -= amountB;
        }

        uint64 nonce = ILayerZeroEndpoint(layerZeroEndpoint).getInboundNonce(dstChainId, trustedRemotePools[dstChainId]);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(address(this), amountA, amountB, nonce, block.timestamp + timelock);
        bytes memory remoteAndLocalAddresses = abi.encodePacked(trustedRemotePools[dstChainId], address(this));

        (uint256 nativeFee,) = getEstimatedLayerZeroFee(dstChainId, payload, adapterParams);
        if (address(this).balance < nativeFee) revert InsufficientFee(address(this).balance, nativeFee);

        try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
            dstChainId,
            remoteAndLocalAddresses,
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        ) {
            emit ReservesRebalanced(dstChainId, amountA, amountB);
        } catch {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: dstChainId,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp
            });
            emit FailedMessageStored(failedMessageCount, dstChainId, payload);
            failedMessageCount++;
        }
    }

    /// @notice Synchronizes cross-chain reserves with remote pool
    /// @param chainId Target chain ID
    /// @param adapterParams LayerZero adapter parameters
    function syncCrossChainReserves(uint16 chainId, bytes calldata adapterParams) 
        external 
        onlyOwner 
        nonReentrant 
    {
        if (trustedRemotePools[chainId].length == 0) revert InvalidChainId(chainId);

        uint64 nonce = ILayerZeroEndpoint(layerZeroEndpoint).getInboundNonce(chainId, trustedRemotePools[chainId]);
        bytes memory payload = abi.encode(address(this), reserves.crossChainReserveA, reserves.crossChainReserveB, nonce, block.timestamp);
        bytes memory remoteAndLocalAddresses = abi.encodePacked(trustedRemotePools[chainId], address(this));

        (uint256 nativeFee,) = getEstimatedLayerZeroFee(chainId, payload, adapterParams);
        if (address(this).balance < nativeFee) revert InsufficientFee(address(this).balance, nativeFee);

        try ILayerZeroEndpoint(layerZeroEndpoint).send{value: nativeFee}(
            chainId,
            remoteAndLocalAddresses,
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        ) {
        } catch {
            failedMessages[failedMessageCount] = FailedMessage({
                dstChainId: chainId,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp
            });
            emit FailedMessageStored(failedMessageCount, chainId, payload);
            failedMessageCount++;
        }
    }

    /// @notice Allows users to withdraw liquidity during a pause
    /// @dev Only callable when contract is paused
    function emergencyWithdraw() external nonReentrant {
        if (!paused) revert Unauthorized();
        uint256 liquidity = liquidityBalance[msg.sender];
        if (liquidity == 0) revert InvalidAmount(liquidity, 0);
        if (totalLiquidity == 0) revert InvalidAmount(0, 0);

        uint256 amountA = (liquidity * reserves.reserveA) / totalLiquidity;
        uint256 amountB = (liquidity * reserves.reserveB) / totalLiquidity;

        liquidityBalance[msg.sender] = 0;
        totalLiquidity -= liquidity;
        reserves.reserveA -= amountA;
        reserves.reserveB -= amountB;

        IERC20Upgradeable(tokenA).safeTransfer(msg.sender, amountA);
        IERC20Upgradeable(tokenB).safeTransfer(msg.sender, amountB);

        emit EmergencyWithdrawal(msg.sender, amountA, amountB);
    }

    /// @notice Gets current reserves (local and cross-chain)
    /// @return reserveA Local reserve of tokenA
    /// @return reserveB Local reserve of tokenB
    /// @return crossChainReserveA Cross-chain reserve of tokenA
    /// @return crossChainReserveB Cross-chain reserve of tokenB
    function getReserves() external view returns (uint256, uint256, uint256, uint256) {
        return (reserves.reserveA, reserves.reserveB, reserves.crossChainReserveA, reserves.crossChainReserveB);
    }

    /// @notice Gets cross-chain state for monitoring
    /// @param chainId Chain ID to query
    /// @return layerZeroEndpoint LayerZero endpoint address
    /// @return tokenBridge Token bridge address
    /// @return timelock Chain-specific timelock
    /// @return trustedPool Trusted remote pool address
    /// @return baseFee Base fee for the chain
    /// @return maxFee Maximum fee for the chain
    function getCrossChainState(uint16 chainId) 
        external 
        view 
        returns (address, address, uint256, bytes memory, uint256, uint256) 
    {
        FeeConfig memory feeConfig = chainFees[chainId];
        return (layerZeroEndpoint, tokenBridge, chainTimelocks[chainId], trustedRemotePools[chainId], 
                feeConfig.baseFee, feeConfig.maxFee);
    }

    /// @notice Calculates price impact for a trade
    /// @param amountIn Input amount
    /// @param inputToken Input token address
    /// @return Price impact in 1e18 precision
    function getPriceImpact(uint256 amountIn, address inputToken) external view returns (uint256) {
        (uint256 reserveIn,) = inputToken == tokenA 
            ? (reserves.reserveA + reserves.crossChainReserveA, reserves.reserveB + reserves.crossChainReserveB) 
            : (reserves.reserveB + reserves.crossChainReserveB, reserves.reserveA + reserves.crossChainReserveA);
        return (amountIn * 1e18) / (reserveIn + amountIn);
    }

    /// @notice Updates volatility EMA and switches curve if needed
    /// @dev Called after liquidity or swap operations
    function _updateVolatility() internal {
        uint256 totalReserveA = reserves.reserveA + reserves.crossChainReserveA;
        uint256 totalReserveB = reserves.reserveB + reserves.crossChainReserveB;
        if (totalReserveA == 0) return;

        uint256 currentPrice = (totalReserveB * 1e18) / totalReserveA;
        if (lastPrice != 0) {
            uint256 priceChange = currentPrice > lastPrice ? currentPrice - lastPrice : lastPrice - currentPrice;
            uint256 volatility = (priceChange * 1e18) / lastPrice;

            uint256 alpha = (2 * 1e18) / (emaPeriod + 1);
            emaVolatility = (alpha * volatility + (1e18 - alpha) * emaVolatility) / 1e18;

            useConstantSum = emaVolatility < volatilityThreshold;
        }
        lastPrice = currentPrice;
    }

    /// @notice Calculates dynamic fee based on volatility and chain
    /// @param chainId Chain ID
    /// @return Fee in basis points
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

    /// @notice Calculates dynamic timelock based on chain conditions
    /// @param chainId Chain ID
    /// @return Timelock duration in seconds
    function _getDynamicTimelock(uint16 chainId) internal view returns (uint256) {
        uint256 timelock = chainTimelocks[chainId];
        if (timelock == 0) revert InvalidTimelock(0);
        if (emaVolatility > volatilityThreshold) {
            timelock = timelock * 2 > MAX_TIMELOCK ? MAX_TIMELOCK : timelock * 2;
        }
        return timelock;
    }

    /// @notice Validates swap price against Chainlink oracles
    /// @dev Tries primary oracle, then iterates through fallback oracles
    /// @param inputToken Input token address
    /// @param amountIn Input amount
    /// @param amountOut Output amount
    function _validatePrice(address inputToken, uint256 amountIn, uint256 amountOut) internal view {
        (int256 price, uint8 decimals) = _getOraclePrice(primaryPriceOracle);
        if (price <= 0) {
            for (uint256 i = 0; i < fallbackPriceOracles.length; i++) {
                (price, decimals) = _getOraclePrice(fallbackPriceOracles[i]);
                if (price > 0) break;
            }
            if (price <= 0) revert NegativeOraclePrice(price);
        }
        uint256 oraclePriceScaled = uint256(price) * 1e18 / (10 ** decimals);

        uint256 expectedPrice = inputToken == tokenA ? (amountIn * 1e18) / amountOut : (amountOut * 1e18) / amountIn;
        uint256 maxDeviation = (oraclePriceScaled * priceDeviationThreshold) / 1e18;
        if (expectedPrice > oraclePriceScaled + maxDeviation || expectedPrice < oraclePriceScaled - maxDeviation) {
            revert InvalidPrice(expectedPrice, oraclePriceScaled);
        }
    }

    /// @notice Fetches price from a Chainlink oracle
    /// @param oracle Oracle address
    /// @return price Price from oracle
    /// @return decimals Oracle decimals
    function _getOraclePrice(address oracle) internal view returns (int256 price, uint8 decimals) {
        try AggregatorV3Interface(oracle).latestRoundData() returns (
            uint80,
            int256 answer,
            uint256,
            uint256 updatedAt,
            uint80
        ) {
            if (answer <= 0) revert NegativeOraclePrice(answer);
            if (updatedAt < block.timestamp - 1 hours) revert OracleFailure();
            price = answer;
            decimals = AggregatorV3Interface(oracle).decimals();
        } catch {
            revert OracleFailure();
        }
    }

    /// @notice Validates LayerZero adapter parameters
    /// @param adapterParams Adapter parameters
    function _validateAdapterParams(bytes calldata adapterParams) internal pure {
        if (adapterParams.length < 2) revert InvalidAdapterParams();
    }

    /// @notice Proposes a governance update
    /// @param target Target contract address
    /// @param data Call data
    /// @return proposalId Proposal ID
    function proposeGovernanceUpdate(address target, bytes calldata data) 
        external 
        onlyGovernance 
        returns (uint256) 
    {
        uint256 proposalId = proposalCount++;
        governanceProposals[proposalId] = AMMGovernanceProposal({
            target: target,
            data: data,
            proposedAt: block.timestamp,
            executed: false
        });
        emit GovernanceProposalCreated(proposalId, target, data, block.timestamp);
        return proposalId;
    }

    /// @notice Executes a governance proposal after timelock
    /// @param proposalId Proposal ID
    function executeGovernanceProposal(uint256 proposalId) external onlyGovernance {
        AMMGovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (block.timestamp < proposal.proposedAt + GOVERNANCE_TIMELOCK) 
            revert ProposalNotReady(proposalId);

        proposal.executed = true;
        (bool success, bytes memory result) = proposal.target.call(proposal.data);
        if (!success) {
            if (result.length > 0) {
                assembly {
                    let returndata_size := mload(result)
                    revert(add(32, result), returndata_size)
                }
            } else {
                revert ProposalExecutionFailed();
            }
        }
        emit GovernanceProposalExecuted(proposalId);
    }

    /// @notice Updates fee parameters for a specific chain
    /// @param chainId Chain ID
    /// @param _baseFee Base fee in basis points
    /// @param _maxFee Maximum fee in basis points
    /// @param _lpFeeShare LP fee share in basis points
    /// @param _treasuryFeeShare Treasury fee share in basis points
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

    /// @notice Pauses the contract
    function pause() external onlyGovernance {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpauses the contract
    function unpause() external onlyGovernance {
        if (!paused) revert Unauthorized();
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Pauses a specific chain
    /// @param chainId Chain ID
    function pauseChain(uint16 chainId) external onlyGovernance {
        if (chainPaused[chainId]) revert ChainPaused(chainId);
        chainPaused[chainId] = true;
        emit AMMPoolChainPaused(chainId, msg.sender);
    }

    /// @notice Unpauses a specific chain
    /// @param chainId Chain ID
    function unpauseChain(uint16 chainId) external onlyGovernance {
        if (!chainPaused[chainId]) revert Unauthorized();
        chainPaused[chainId] = false;
        emit ChainUnpaused(chainId, msg.sender);
    }

    /// @notice Updates LayerZero endpoint
    /// @param _layerZeroEndpoint New endpoint address
    function updateLayerZeroEndpoint(address _layerZeroEndpoint) external onlyGovernance {
        if (_layerZeroEndpoint == address(0)) revert InvalidAddress(_layerZeroEndpoint);
        layerZeroEndpoint = _layerZeroEndpoint;
        emit LayerZeroEndpointUpdated(_layerZeroEndpoint);
    }

    /// @notice Updates token bridge
    /// @param _tokenBridge New token bridge address
    function updateTokenBridge(address _tokenBridge) external onlyGovernance {
        if (_tokenBridge == address(0)) revert InvalidAddress(_tokenBridge);
        tokenBridge = _tokenBridge;
        emit TokenBridgeUpdated(_tokenBridge);
    }

    /// @notice Adds trusted remote pool
    /// @param chainId Chain ID
    /// @param poolAddress Remote pool address
    function addTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external onlyGovernance {
        if (poolAddress.length == 0) revert InvalidAddress(address(0));
        trustedRemotePools[chainId] = poolAddress;
        emit TrustedRemotePoolAdded(chainId, poolAddress);
    }

    /// @notice Updates chain-specific timelock
    /// @param chainId Chain ID
    /// @param _timelock New timelock duration
    function updateChainTimelock(uint16 chainId, uint256 _timelock) external onlyGovernance {
        if (_timelock < MIN_TIMELOCK || _timelock > MAX_TIMELOCK) revert InvalidTimelock(_timelock);
        chainTimelocks[chainId] = _timelock;
        emit ChainTimelockUpdated(chainId, _timelock);
    }

    /// @notice Updates token bridge type
    /// @param token Token address
    /// @param bridgeType Bridge type (1 = burn/mint, 2 = lock/release)
    function updateTokenBridgeType(address token, uint8 bridgeType) external onlyGovernance {
        if (bridgeType != 1 && bridgeType != 2) revert InvalidBridgeType(bridgeType);
        tokenBridgeType[token] = bridgeType;
        emit TokenBridgeTypeUpdated(token, bridgeType);
    }

    /// @notice Updates target reserve ratio
    /// @param _targetReserveRatio New reserve ratio
    function updateTargetReserveRatio(uint256 _targetReserveRatio) external onlyGovernance {
        if (_targetReserveRatio == 0) revert InvalidReserveRatio(_targetReserveRatio);
        targetReserveRatio = _targetReserveRatio;
        emit TargetReserveRatioUpdated(_targetReserveRatio);
    }

    /// @notice Updates price oracles
    /// @param _primaryPriceOracle New primary oracle address
    /// @param _fallbackPriceOracles New fallback oracle addresses
    function updatePriceOracles(address _primaryPriceOracle, address[] memory _fallbackPriceOracles) 
        external 
        onlyGovernance 
    {
        if (_primaryPriceOracle == address(0)) revert InvalidAddress(_primaryPriceOracle);
        primaryPriceOracle = _primaryPriceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        emit PriceOracleUpdated(_primaryPriceOracle, _fallbackPriceOracles);
    }

    /// @notice Updates governance contract
    /// @param _governance New governance address
    function updateGovernance(address _governance) external onlyGovernance {
        if (_governance == address(0)) revert InvalidAddress(_governance);
        governance = _governance;
        emit GovernanceUpdated(_governance);
    }

    /// @notice Updates EMA period
    /// @param _emaPeriod New EMA period
    function updateEmaPeriod(uint256 _emaPeriod) external onlyGovernance {
        if (_emaPeriod == 0) revert InvalidAmount(_emaPeriod, 0);
        emaPeriod = _emaPeriod;
        emit EmaPeriodUpdated(_emaPeriod);
    }

    /// @notice Updates volatility threshold
    /// @param _volatilityThreshold New volatility threshold
    function updateVolatilityThreshold(uint256 _volatilityThreshold) external onlyGovernance {
        if (_volatilityThreshold == 0) revert InvalidAmount(_volatilityThreshold, 0);
        volatilityThreshold = _volatilityThreshold;
        emit VolatilityThresholdUpdated(_volatilityThreshold);
    }

    /// @notice Updates price deviation threshold
    /// @param _priceDeviationThreshold New price deviation threshold
    function updatePriceDeviationThreshold(uint256 _priceDeviationThreshold) external onlyGovernance {
        if (_priceDeviationThreshold == 0) revert InvalidAmount(_priceDeviationThreshold, 0);
        priceDeviationThreshold = _priceDeviationThreshold;
    }

    /// @notice Allows contract to receive native tokens
    receive() external payable {}
}