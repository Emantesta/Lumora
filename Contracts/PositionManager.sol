// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin-specific imports
import { ERC721Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import { IERC721ReceiverUpgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import { StringsUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol";
import { Base64Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/Base64Upgradeable.sol";
import { SafeERC20Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import { IAMMPool, ICrossChainMessenger, ITokenBridge, ILayerZeroEndpoint, IAxelarGateway, IWormhole, ICrossChainModule } from "./Interfaces.sol";
import { TickMath } from "@uniswap/v3-core/contracts/libraries/TickMath.sol";

/// @title PositionManager - Enhanced upgradeable ERC721 contract for managing NFT-based liquidity positions
/// @notice Manages NFT positions with automatic fee bridging, batch operations, and multi-bridge support via CrossChainModule
/// @dev Implements ERC721Upgradeable with cross-chain functionality, oracle-based retries, and gas optimizations
contract PositionManager is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    ERC721Upgradeable,
    IERC721ReceiverUpgradeable
{
    using StringsUpgradeable for uint256;
    using Base64Upgradeable for bytes;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Constants
    string public constant VERSION = "1.4.0"; // Updated version for CrossChainModule integration
    uint256 public constant MAX_CROSS_CHAIN_RETRIES = 3;
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant MAX_FAILED_MESSAGES = 1000;
    uint256 public constant MIN_ADAPTER_PARAMS_LENGTH = 16;
    uint256 public constant DEFAULT_FEE_AGGREGATION_THRESHOLD = 0.01 ether;
    uint256 public constant MIN_GAS_PER_MESSAGE = 100_000;
    uint8 public constant HIGH_CONGESTION_LEVEL = 8;

    // Storage variables
    address public ammPool;
    address public crossChainMessenger;
    address public crossChainModule; // New reference to CrossChainModule
    string public baseURI;
    uint8 public messengerType; // 0 = LayerZero, 1 = Axelar, 2 = Wormhole
    mapping(uint64 => bytes) public trustedRemoteManagers;
    mapping(uint64 => string) public chainIdToAxelarChain;
    mapping(uint256 => Position) public positionData;
    mapping(uint256 => bool) public isCrossChainPosition;
    mapping(uint64 => uint64) public nonces;
    uint256 public failedMessageCount;
    mapping(uint8 => address) public tokenBridges;
    mapping(uint256 => FeeTracking) public feeTracking;
    mapping(address => AggregatedFees) public aggregatedFees;
    mapping(address => address) public feeDestinations;
    mapping(address => mapping(uint64 => uint256)) public userChainFeeThresholds;
    uint256 public defaultFeeAggregationThreshold = DEFAULT_FEE_AGGREGATION_THRESHOLD;
    uint256 public retryDelay = 1 hours;
    mapping(uint256 => FailedMessage) internal failedMessages;
    mapping(bytes32 => bool) public validatedMessages; // Tracks processed cross-chain messages

    // Structs
    struct Position {
        address pool;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint16 sourceChainId;
        address tokenA;
        address tokenB;
    }

    struct FeeTracking {
        uint256 lastBridged0;
        uint256 lastBridged1;
        uint256 accumulated0;
        uint256 accumulated1;
        uint16 lastDstChainId;
    }

    struct AggregatedFees {
        uint256 total0;
        uint256 total1;
    }

    struct FailedMessage {
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 timestamp;
        uint256 nextRetryTimestamp;
        uint8 messengerType;
    }

    // Errors
    error InvalidAMMPool();
    error InvalidTokenId(uint256 tokenId);
    error NotTokenOwner(uint256 tokenId);
    error InvalidChainId(uint64 chainId);
    error InvalidMessenger();
    error InsufficientFee(uint256 provided, uint256 required);
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error RetryNotReady(uint256 messageId, uint256 nextRetryTimestamp);
    error InvalidPositionData(uint256 tokenId);
    error CrossChainPosition(uint256 tokenId);
    error Unauthorized();
    error PositionExists(uint256 tokenId);
    error InvalidBatchSize(uint256 size);
    error FeesNotCollected(uint256 tokenId);
    error InvalidMessengerType(uint8 messengerType);
    error InvalidBridgeType();
    error InvalidFeeDestination(address destination);
    error InsufficientAggregatedFees();
    error InvalidAddress(address addr, string message);
    error ContractPaused();
    error TimelockNotExpired(uint256 current, uint256 required);
    error InvalidLiquidity(uint256 tokenId);
    error FeesPending(uint256 tokenId);
    error InvalidOwner(uint256 tokenId);
    error MaxFailedMessagesReached();
    error InvalidAxelarChain();
    error InvalidAdapterParamsLength(uint256 length);
    error InvalidFeeThreshold(uint256 threshold);
    error InvalidFeeAmount(uint256 provided, uint256 available);
    error CompoundingFailed(uint256 tokenId);
    error InvalidCrossChainMessage(string message);
    error InvalidWormholeVAA();
    error InsufficientGasForBatch(uint256 required, uint256 provided);
    error InvalidMessage();
    error InvalidTickRange(int24 tickLower, int24 tickUpper);
    error OracleNotConfigured(uint64 chainId);
    error RetryNotRecommended(uint64 chainId);

    // Events
    event PositionMinted(uint256 indexed tokenId, address indexed owner, address indexed pool, int24 tickLower, int24 tickUpper, uint256 liquidity);
    event BatchPositionsMinted(uint256[] indexed tokenIds, address indexed owner, address indexed pool, uint256 count);
    event PositionBurned(uint256 indexed tokenId, address indexed owner);
    event BatchPositionsTransferred(uint256[] indexed tokenIds, address indexed owner, address indexed pool, uint256 count);
    event CrossChainPositionSent(uint256 indexed tokenId, address indexed owner, address indexed recipient, uint16 dstChainId, uint64 nonce, uint256 timelock);
    event CrossChainPositionReceived(uint256 indexed tokenId, address indexed owner, uint16 indexed srcChainId, uint64 nonce);
    event FeesBridgedCrossChain(uint256 indexed tokenId, address indexed owner, uint256 amount0, uint256 amount1, uint16 dstChainId, uint256 bridgeType, uint64 nonce);
    event BatchFeesBridged(address indexed owner, uint256[] tokenIds, uint256 total0, uint256 total1, uint16 dstChainId, uint256 bridgeType, uint64 nonce);
    event FeesAggregated(address indexed owner, uint256 amount0, uint256 amount1);
    event FeeDestinationUpdated(address indexed owner, address destination);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes payload);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries);
    event FailedMessageRetryScheduled(uint256 indexed messageId, uint256 nextRetryTimestamp);
    event TrustedRemoteManagerUpdated(uint64 indexed chainId, bytes managerAddress);
    event CrossChainMessengerUpdated(address indexed newMessenger, uint8 messengerType);
    event TokenBridgeUpdated(uint8 indexed bridgeType, address indexed newBridge);
    event BaseURIUpdated(string newBaseURI);
    event MessengerTypeUpdated(uint8 newMessengerType);
    event ChainIdUpdated(uint64 indexed chainId, string axelarChain);
    event FeeAggregationThresholdUpdated(address indexed user, uint64 indexed chainId, uint256 newThreshold);
    event DefaultFeeAggregationThresholdUpdated(uint256 newThreshold);
    event RetryDelayUpdated(uint256 newDelay);
    event BatchFeeEstimate(uint256 totalFee, uint256 count);
    event FeesCompounded(uint256 indexed tokenId, address indexed owner, uint256 amount0, uint256 amount1);
    event CrossChainModuleUpdated(address indexed newModule);

    // Modifiers
    modifier onlyAMMPool() {
        if (msg.sender != ammPool) revert Unauthorized();
        _;
    }

    modifier onlyTokenOwner(uint256 tokenId) {
        if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(tokenId);
        _;
    }

    modifier whenNotPausedCrossChain() {
        if (paused()) revert ContractPaused();
        _;
    }

    modifier validAdapterParams(bytes calldata adapterParams) {
        if (adapterParams.length < MIN_ADAPTER_PARAMS_LENGTH) revert InvalidAdapterParamsLength(adapterParams.length);
        _;
    }

    // Receive function
    receive() external payable {}

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _ammPool,
        address _crossChainMessenger,
        address _crossChainModule,
        uint8 _messengerType,
        string memory _name,
        string memory _symbol
    ) external initializer {
        if (_ammPool == address(0)) revert InvalidAddress(_ammPool, "Invalid AMM pool");
        if (_crossChainMessenger == address(0)) revert InvalidAddress(_crossChainMessenger, "Invalid messenger");
        if (_crossChainModule == address(0)) revert InvalidAddress(_crossChainModule, "Invalid cross-chain module");
        if (_messengerType > 2) revert InvalidMessengerType(_messengerType);

        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __ERC721_init(_name, _symbol);

        ammPool = _ammPool;
        crossChainMessenger = _crossChainMessenger;
        crossChainModule = _crossChainModule;
        messengerType = _messengerType;
        baseURI = "";
        emit CrossChainMessengerUpdated(_crossChainMessenger, _messengerType);
        emit MessengerTypeUpdated(_messengerType);
        emit CrossChainModuleUpdated(_crossChainModule);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // --- New Functions for CrossChainModule Integration ---

    /// @notice Updates the CrossChainModule address
    /// @param newModule The new CrossChainModule address
    function updateCrossChainModule(address newModule) external onlyOwner whenNotPaused {
        if (newModule == address(0)) revert InvalidAddress(newModule, "Invalid module address");
        crossChainModule = newModule;
        emit CrossChainModuleUpdated(newModule);
    }

    /// @notice Gets the dynamic timelock for a chain using CrossChainModule
    /// @param chainId The destination chain ID
    /// @return timelock The dynamic timelock
    function _getDynamicTimelock(uint64 chainId) internal view returns (uint256 timelock) {
        try ICrossChainModule(crossChainModule).getDynamicTimelock(uint16(chainId)) returns (uint256 _timelock) {
            timelock = _timelock;
        } catch {
            timelock = 1 hours; // Fallback timelock
        }
    }

    // --- Fee Management Functions ---

    function setUserChainFeeThreshold(uint64 chainId, uint256 threshold) external whenNotPaused {
        if (threshold == 0) revert InvalidFeeThreshold(threshold);
        userChainFeeThresholds[msg.sender][chainId] = threshold;
        emit FeeAggregationThresholdUpdated(msg.sender, chainId, threshold);
    }

    function getFeeAggregationThreshold(address user, uint64 chainId) public view returns (uint256) {
        uint256 userThreshold = userChainFeeThresholds[user][chainId];
        return userThreshold > 0 ? userThreshold : defaultFeeAggregationThreshold;
    }

    function estimateBatchFees(
        uint256[] calldata tokenIds,
        uint64 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external view validAdapterParams(adapterParams) returns (uint256 total0, uint256 total1, uint256 nativeFee) {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType();

        for (uint256 i = 0; i < length; i++) {
            uint256 tokenId = tokenIds[i];
            if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
            if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(tokenId);

            (, , , , , uint256 tokensOwed0, uint256 tokensOwed1) = IAMMPool(ammPool).positions(tokenId);
            FeeTracking memory fees = feeTracking[tokenId];
            total0 += (fees.accumulated0 - fees.lastBridged0 + tokensOwed0);
            total1 += (fees.accumulated1 - fees.lastBridged1 + tokensOwed1);
        }

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        if (bytes(dstAxelarChain).length == 0 && messengerType == 1) revert InvalidAxelarChain();
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        bytes memory payload = abi.encode(msg.sender, tokenIds, total0, total1, _getNonce(dstChainId));

        (nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
            uint16(dstChainId),
            payload,
            adapterParams
        );

        return (total0, total1, nativeFee);
    }

    function compoundFees(uint256 tokenId) external nonReentrant onlyTokenOwner(tokenId) whenNotPaused {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);

        _aggregateFees(tokenId);
        FeeTracking storage fees = feeTracking[tokenId];
        uint256 amount0 = fees.accumulated0 - fees.lastBridged0;
        uint256 amount1 = fees.accumulated1 - fees.lastBridged1;

        if (amount0 == 0 && amount1 == 0) revert FeesNotCollected(tokenId);

        address owner = ownerOf(tokenId);
        aggregatedFees[owner].total0 -= amount0;
        aggregatedFees[owner].total1 -= amount1;
        fees.lastBridged0 = fees.accumulated0;
        fees.lastBridged1 = fees.accumulated1;

        try IAMMPool(ammPool).addLiquidityFromFees(tokenId, amount0, amount1) {
            (, , , uint128 liquidity, , , ,) = IAMMPool(ammPool).positions(tokenId);
            positionData[tokenId].liquidity = liquidity;
            emit FeesCompounded(tokenId, owner, amount0, amount1);
        } catch {
            aggregatedFees[owner].total0 += amount0;
            aggregatedFees[owner].total1 += amount1;
            fees.lastBridged0 -= amount0;
            fees.lastBridged1 -= amount1;
            revert CompoundingFailed(tokenId);
        }
    }

    // --- NFT Management Functions ---

    function mintPosition(uint256 positionId, address recipient) external nonReentrant onlyAMMPool whenNotPaused {
        if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient");
        if (_exists(positionId)) revert PositionExists(positionId);

        (
            address owner,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            ,,
            ,
        ) = IAMMPool(ammPool).positions(positionId);
        if (owner == address(0) || liquidity == 0) revert InvalidPositionData(positionId);

        positionData[positionId] = Position({
            pool: ammPool,
            tickLower: tickLower,
            tickUpper: tickUpper,
            liquidity: liquidity,
            sourceChainId: 0,
            tokenA: IAMMPool(ammPool).tokenA(),
            tokenB: IAMMPool(ammPool).tokenB()
        });

        _aggregateFees(positionId);
        _safeMint(recipient, positionId);

        emit PositionMinted(positionId, recipient, ammPool, tickLower, tickUpper, liquidity);
    }

    function batchMintPositions(
        uint256[] calldata positionIds,
        address[] calldata recipients
    ) external nonReentrant onlyAMMPool whenNotPaused {
        uint256 length = positionIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE || length != recipients.length) revert InvalidBatchSize(length);

        uint256[] memory mintedIds = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            uint256 positionId = positionIds[i];
            address recipient = recipients[i];
            if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient");
            if (_exists(positionId)) revert PositionExists(positionId);

            (
                address owner,
                int24 tickLower,
                int24 tickUpper,
                uint128 liquidity,
                ,,
                ,
            ) = IAMMPool(ammPool).positions(positionId);
            if (owner == address(0) || liquidity == 0) revert InvalidPositionData(positionId);

            positionData[positionId] = Position({
                pool: ammPool,
                tickLower: tickLower,
                tickUpper: tickUpper,
                liquidity: liquidity,
                sourceChainId: 0,
                tokenA: IAMMPool(ammPool).tokenA(),
                tokenB: IAMMPool(ammPool).tokenB()
            });

            _aggregateFees(positionId);
            _safeMint(recipient, positionId);
            mintedIds[i] = positionId;

            emit PositionMinted(positionId, recipient, ammPool, tickLower, tickUpper, liquidity);
        }

        emit BatchPositionsMinted(mintedIds, msg.sender, ammPool, length);
    }

    function burnPosition(uint256 tokenId) external nonReentrant onlyTokenOwner(tokenId) whenNotPaused {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (isCrossChainPosition[tokenId]) revert CrossChainPosition(tokenId);

        (
            address owner,
            ,
            ,
            uint128 liquidity,
            ,,
            uint256 tokensOwed0,
            uint256 tokensOwed1
        ) = IAMMPool(ammPool).positions(tokenId);
        if (liquidity > 0) revert InvalidLiquidity(tokenId);
        if (tokensOwed0 > 0 || tokensOwed1 > 0) revert FeesPending(tokenId);
        if (owner != msg.sender) revert InvalidOwner(tokenId);

        _aggregateFees(tokenId);
        delete positionData[tokenId];
        delete feeTracking[tokenId];
        _burn(tokenId);

        emit PositionBurned(tokenId, msg.sender);
    }

    function transferToPool(uint256 tokenId) external nonReentrant onlyTokenOwner(tokenId) whenNotPaused {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);

        _aggregateFees(tokenId);
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId;
        safeTransferFrom(msg.sender, ammPool, tokenId);

        emit BatchPositionsTransferred(tokenIds, msg.sender, ammPool, 1);
    }

    function batchTransferToPool(uint256[] calldata tokenIds) external nonReentrant whenNotPaused {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);

        for (uint256 i = 0; i < length; i++) {
            uint256 tokenId = tokenIds[i];
            if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
            if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(tokenId);

            _aggregateFees(tokenId);
            safeTransferFrom(msg.sender, ammPool, tokenId);
        }

        emit BatchPositionsTransferred(tokenIds, msg.sender, ammPool, length);
    }

    // --- Fee Management Functions ---

    function setFeeDestination(address destination) external whenNotPaused {
        if (destination == address(0)) revert InvalidFeeDestination(destination);
        feeDestinations[msg.sender] = destination;
        emit FeeDestinationUpdated(msg.sender, destination);
    }

    function _aggregateFees(uint256 tokenId) internal {
        (, , , , , uint256 tokensOwed0, uint256 tokensOwed1) = IAMMPool(ammPool).positions(tokenId);
        if (tokensOwed0 == 0 && tokensOwed1 == 0) return;

        IAMMPool(ammPool).collectFees(tokenId);
        address owner = ownerOf(tokenId);
        feeTracking[tokenId].accumulated0 += tokensOwed0;
        feeTracking[tokenId].accumulated1 += tokensOwed1;
        aggregatedFees[owner].total0 += tokensOwed0;
        aggregatedFees[owner].total1 += tokensOwed1;
        emit FeesAggregated(owner, tokensOwed0, tokensOwed1);
    }

    function collectAndBridgeFees(
        uint256 tokenId,
        uint64 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyTokenOwner(tokenId) whenNotPausedCrossChain validAdapterParams(adapterParams) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType();

        _aggregateFees(tokenId);
        FeeTracking storage fees = feeTracking[tokenId];
        uint256 amount0 = fees.accumulated0 - fees.lastBridged0;
        uint256 amount1 = fees.accumulated1 - fees.lastBridged1;

        if (amount0 == 0 && amount1 == 0) revert FeesNotCollected(tokenId);

        fees.lastBridged0 = fees.accumulated0;
        fees.lastBridged1 = fees.accumulated1;
        fees.lastDstChainId = dstChainId;

        address recipient = feeDestinations[msg.sender] != address(0) ? feeDestinations[msg.sender] : msg.sender;
        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        if (bytes(dstAxelarChain).length == 0 && messengerType == 1) revert InvalidAxelarChain();
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(msg.sender, tokenId, amount0, amount1, nonce);

        (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
            uint16(dstChainId),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        if (amount0 > 0) {
            IERC20Upgradeable(IAMMPool(ammPool).tokenA()).safeTransfer(crossChainModule, amount0);
            ICrossChainModule(crossChainModule).bridgeTokens(IAMMPool(ammPool).tokenA(), amount0, recipient, uint16(dstChainId));
        }
        if (amount1 > 0) {
            IERC20Upgradeable(IAMMPool(ammPool).tokenB()).safeTransfer(crossChainModule, amount1);
            ICrossChainModule(crossChainModule).bridgeTokens(IAMMPool(ammPool).tokenB(), amount1, recipient, uint16(dstChainId));
        }

        uint64 initialNonce = nonces[dstChainId];
        try ICrossChainModule(crossChainModule).sendCrossChainMessage{value: nativeFee}(
            uint16(dstChainId),
            dstAxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            nonce,
            _getDynamicTimelock(dstChainId),
            messengerType
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            nonces[dstChainId]++;
            emit FeesBridgedCrossChain(tokenId, msg.sender, amount0, amount1, dstChainId, bridgeType, nonce);
        } catch {
            if (failedMessageCount >= MAX_FAILED_MESSAGES) revert MaxFailedMessagesReached();
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: uint16(dstChainId),
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + retryDelay,
                messengerType: messengerType
            });
            nonces[dstChainId] = initialNonce;
            emit FailedMessageStored(messageId, uint16(dstChainId), payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + retryDelay);
        }
    }

    function batchBridgeFees(
        uint256[] calldata tokenIds,
        uint64 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedCrossChain validAdapterParams(adapterParams) {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType();

        uint256 total0;
        uint256 total1;

        for (uint256 i = 0; i < length; i++) {
            uint256 tokenId = tokenIds[i];
            if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
            if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(tokenId);

            _aggregateFees(tokenId);
            FeeTracking storage fees = feeTracking[tokenId];
            uint256 amount0 = fees.accumulated0 - fees.lastBridged0;
            uint256 amount1 = fees.accumulated1 - fees.lastBridged1;

            total0 += amount0;
            total1 += amount1;
            fees.lastBridged0 = fees.accumulated0;
            fees.lastBridged1 = fees.accumulated1;
            fees.lastDstChainId = dstChainId;
        }

        if (total0 == 0 && total1 == 0) revert FeesNotCollected(0);

        address recipient = feeDestinations[msg.sender] != address(0) ? feeDestinations[msg.sender] : msg.sender;
        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        if (bytes(dstAxelarChain).length == 0 && messengerType == 1) revert InvalidAxelarChain();
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(msg.sender, tokenIds, total0, total1, nonce);

        (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
            uint16(dstChainId),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        if (total0 > 0) {
            IERC20Upgradeable(IAMMPool(ammPool).tokenA()).safeTransfer(crossChainModule, total0);
            ICrossChainModule(crossChainModule).bridgeTokens(IAMMPool(ammPool).tokenA(), total0, recipient, uint16(dstChainId));
        }
        if (total1 > 0) {
            IERC20Upgradeable(IAMMPool(ammPool).tokenB()).safeTransfer(crossChainModule, total1);
            ICrossChainModule(crossChainModule).bridgeTokens(IAMMPool(ammPool).tokenB(), total1, recipient, uint16(dstChainId));
        }

        uint64 initialNonce = nonces[dstChainId];
        try ICrossChainModule(crossChainModule).sendCrossChainMessage{value: nativeFee}(
            uint16(dstChainId),
            dstAxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            nonce,
            _getDynamicTimelock(dstChainId),
            messengerType
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            nonces[dstChainId]++;
            emit BatchFeesBridged(msg.sender, tokenIds, total0, total1, dstChainId, bridgeType, nonce);
        } catch {
            if (failedMessageCount >= MAX_FAILED_MESSAGES) revert MaxFailedMessagesReached();
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: uint16(dstChainId),
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + retryDelay,
                messengerType: messengerType
            });
            nonces[dstChainId] = initialNonce;
            emit FailedMessageStored(messageId, uint16(dstChainId), payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + retryDelay);
        }
    }

    function bridgeAggregatedFees(
        uint64 dstChainId,
        uint8 bridgeType,
        uint256 amount0,
        uint256 amount1,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedCrossChain validAdapterParams(adapterParams) {
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType();

        AggregatedFees storage fees = aggregatedFees[msg.sender];
        uint256 threshold = getFeeAggregationThreshold(msg.sender, dstChainId);
        if (fees.total0 < threshold && fees.total1 < threshold) {
            revert InsufficientAggregatedFees();
        }
        if (amount0 > fees.total0 || amount1 > fees.total1) {
            revert InvalidFeeAmount(amount0 > fees.total0 ? amount0 : amount1, amount0 > fees.total0 ? fees.total0 : fees.total1);
        }

        fees.total0 -= amount0;
        fees.total1 -= amount1;

        address recipient = feeDestinations[msg.sender] != address(0) ? feeDestinations[msg.sender] : msg.sender;
        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        if (bytes(dstAxelarChain).length == 0 && messengerType == 1) revert InvalidAxelarChain();
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(msg.sender, new uint256[](0), amount0, amount1, nonce);

        (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
            uint16(dstChainId),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        if (amount0 > 0) {
            IERC20Upgradeable(IAMMPool(ammPool).tokenA()).safeTransfer(crossChainModule, amount0);
            ICrossChainModule(crossChainModule).bridgeTokens(IAMMPool(ammPool).tokenA(), amount0, recipient, uint16(dstChainId));
        }
        if (amount1 > 0) {
            IERC20Upgradeable(IAMMPool(ammPool).tokenB()).safeTransfer(crossChainModule, amount1);
            ICrossChainModule(crossChainModule).bridgeTokens(IAMMPool(ammPool).tokenB(), amount1, recipient, uint16(dstChainId));
        }

        uint64 initialNonce = nonces[dstChainId];
        try ICrossChainModule(crossChainModule).sendCrossChainMessage{value: nativeFee}(
            uint16(dstChainId),
            dstAxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            nonce,
            _getDynamicTimelock(dstChainId),
            messengerType
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            nonces[dstChainId]++;
            emit BatchFeesBridged(msg.sender, new uint256[](0), amount0, amount1, dstChainId, bridgeType, nonce);
        } catch {
            if (failedMessageCount >= MAX_FAILED_MESSAGES) revert MaxFailedMessagesReached();
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: uint16(dstChainId),
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + retryDelay,
                messengerType: messengerType
            });
            nonces[dstChainId] = initialNonce;
            emit FailedMessageStored(messageId, uint16(dstChainId), payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + retryDelay);
        }
    }

    // --- Cross-Chain Functions ---

    function transferPositionCrossChain(
        uint256 tokenId,
        uint64 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyTokenOwner(tokenId) whenNotPausedCrossChain validAdapterParams(adapterParams) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        _aggregateFees(tokenId);
        Position memory position = positionData[tokenId];
        (
            ,
            ,
            ,
            uint128 liquidity,
            ,,
            uint256 tokensOwed0,
            uint256 tokensOwed1
        ) = IAMMPool(ammPool).positions(tokenId);
        if (liquidity == 0) revert InvalidLiquidity(tokenId);
        if (tokensOwed0 > 0 || tokensOwed1 > 0) revert FeesPending(tokenId);

        isCrossChainPosition[tokenId] = true;
        _burn(tokenId);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        if (bytes(dstAxelarChain).length == 0 && messengerType == 1) revert InvalidAxelarChain();
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(
            msg.sender,
            tokenId,
            position.tickLower,
            position.tickUpper,
            liquidity,
            nonce,
            block.timestamp + timelock,
            position.tokenA,
            position.tokenB
        );

        (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
            uint16(dstChainId),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        uint64 initialNonce = nonces[dstChainId];
        try ICrossChainModule(crossChainModule).sendCrossChainMessage{value: nativeFee}(
            uint16(dstChainId),
            dstAxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            nonce,
            timelock,
            messengerType
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            nonces[dstChainId]++;
            emit CrossChainPositionSent(tokenId, msg.sender, msg.sender, uint16(dstChainId), nonce, timelock);
        } catch {
            if (failedMessageCount >= MAX_FAILED_MESSAGES) {
                isCrossChainPosition[tokenId] = false;
                _safeMint(msg.sender, tokenId);
                revert MaxFailedMessagesReached();
            }
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: uint16(dstChainId),
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + retryDelay,
                messengerType: messengerType
            });
            nonces[dstChainId] = initialNonce;
            isCrossChainPosition[tokenId] = false;
            _safeMint(msg.sender, tokenId);
            emit FailedMessageStored(messageId, uint16(dstChainId), payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + retryDelay);
        }
    }

    function batchTransferPositionsCrossChain(
        uint256[] calldata tokenIds,
        uint64 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedCrossChain validAdapterParams(adapterParams) {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        if (bytes(dstAxelarChain).length == 0 && messengerType == 1) revert InvalidAxelarChain();
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes[] memory payloads = new bytes[](length);
        uint256 totalNativeFee;
        bool[] memory successes = new bool[](length);

        for (uint256 i = 0; i < length; i++) {
            uint256 tokenId = tokenIds[i];
            if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
            if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(tokenId);

            _aggregateFees(tokenId);
            Position memory position = positionData[tokenId];
            (
                ,
                ,
                ,
                uint128 liquidity,
                ,,
                uint256 tokensOwed0,
                uint256 tokensOwed1
            ) = IAMMPool(ammPool).positions(tokenId);
            if (liquidity == 0) revert InvalidLiquidity(tokenId);
            if (tokensOwed0 > 0 || tokensOwed1 > 0) revert FeesPending(tokenId);

            isCrossChainPosition[tokenId] = true;
            _burn(tokenId);
            payloads[i] = abi.encode(
                msg.sender,
                tokenId,
                position.tickLower,
                position.tickUpper,
                liquidity,
                nonce + uint64(i),
                block.timestamp + timelock,
                position.tokenA,
                position.tokenB
            );

            (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
                uint16(dstChainId),
                payloads[i],
                adapterParams
            );
            totalNativeFee += nativeFee;
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);

        emit BatchFeeEstimate(totalNativeFee, length);

        uint64 initialNonce = nonces[dstChainId];
        uint256 successfulMessages;

        for (uint256 i = 0; i < length; i++) {
            if (gasleft() < MIN_GAS_PER_MESSAGE) {
                for (uint256 j = 0; j <= i; j++) {
                    if (!successes[j]) {
                        isCrossChainPosition[tokenIds[j]] = false;
                        _safeMint(msg.sender, tokenIds[j]);
                    }
                }
                revert InsufficientGasForBatch(MIN_GAS_PER_MESSAGE, gasleft());
            }

            uint256 messageFee = totalNativeFee / length;
            try ICrossChainModule(crossChainModule).sendCrossChainMessage{value: messageFee}(
                uint16(dstChainId),
                dstAxelarChain,
                destinationAddress,
                payloads[i],
                adapterParams,
                nonce + uint64(i),
                timelock,
                messengerType
            ) {
                successes[i] = true;
                successfulMessages++;
                emit CrossChainPositionSent(tokenIds[i], msg.sender, msg.sender, uint16(dstChainId), nonce + uint64(i), timelock);
            } catch {
                if (failedMessageCount >= MAX_FAILED_MESSAGES) {
                    for (uint256 j = 0; j <= i; j++) {
                        if (!successes[j]) {
                            isCrossChainPosition[tokenIds[j]] = false;
                            _safeMint(msg.sender, tokenIds[j]);
                        }
                    }
                    revert MaxFailedMessagesReached();
                }
                uint256 messageId = failedMessageCount++;
                failedMessages[messageId] = FailedMessage({
                    dstChainId: uint16(dstChainId),
                    dstAxelarChain: dstAxelarChain,
                    payload: payloads[i],
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    nextRetryTimestamp: block.timestamp + retryDelay,
                    messengerType: messengerType
                });
                emit FailedMessageStored(messageId, uint16(dstChainId), payloads[i]);
                emit FailedMessageRetryScheduled(messageId, block.timestamp + retryDelay);
            }
        }

        if (successfulMessages == length) {
            nonces[dstChainId] += uint64(length);
            if (msg.value > totalNativeFee) {
                payable(msg.sender).transfer(msg.value - totalNativeFee);
            }
        } else {
            nonces[dstChainId] = initialNonce;
            for (uint256 i = 0; i < length; i++) {
                if (!successes[i]) {
                    isCrossChainPosition[tokenIds[i]] = false;
                    _safeMint(msg.sender, tokenIds[i]);
                }
            }
        }
    }

    function receiveCrossChainPosition(
        uint64 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external nonReentrant whenNotPausedCrossChain {
        if (keccak256(srcAddress) != keccak256(trustedRemoteManagers[srcChainId])) revert Unauthorized();
        if (msg.sender != crossChainModule) revert Unauthorized();

        ICrossChainModule(crossChainModule).validateCrossChainMessage(
            uint16(srcChainId),
            srcAddress,
            payload,
            additionalParams
        );

        (
            address recipient,
            uint256 tokenId,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint64 nonce,
            uint256 timelock,
            address tokenA,
            address tokenB
        ) = abi.decode(payload, (address, uint256, int24, int24, uint128, uint64, uint256, address, address));

        bytes32 messageHash = keccak256(abi.encode(srcChainId, srcAddress, payload));
        if (validatedMessages[messageHash]) revert InvalidCrossChainMessage("Message already processed");
        validatedMessages[messageHash] = true;

        if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
        if (_exists(tokenId)) revert PositionExists(tokenId);
        if (recipient == address(0) || liquidity == 0) revert InvalidPositionData(tokenId);
        if (IAMMPool(ammPool).tokenA() != tokenA || IAMMPool(ammPool).tokenB() != tokenB) revert InvalidPositionData(tokenId);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);

        positionData[tokenId] = Position({
            pool: ammPool,
            tickLower: tickLower,
            tickUpper: tickUpper,
            liquidity: liquidity,
            sourceChainId: uint16(srcChainId),
            tokenA: tokenA,
            tokenB: tokenB
        });

        _safeMint(recipient, tokenId);

        IAMMPool(ammPool).addConcentratedLiquidityCrossChain(
            tokenId,
            address(0),
            tickLower,
            tickUpper,
            uint16(srcChainId),
            recipient
        );

        emit CrossChainPositionReceived(tokenId, recipient, uint16(srcChainId), nonce);
    }

    // --- Retry Mechanism ---

    function retryFailedMessage(uint256 messageId) external payable nonReentrant whenNotPaused {
        FailedMessage storage message = failedMessages[messageId];
        if (message.retries >= MAX_CROSS_CHAIN_RETRIES) revert MaxRetriesExceeded(messageId);
        if (message.timestamp == 0) revert MessageNotFailed(messageId);
        if (block.timestamp < message.nextRetryTimestamp) {
            revert RetryNotReady(messageId, message.nextRetryTimestamp);
        }

        (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
            message.dstChainId,
            message.payload,
            message.adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        message.retries++;
        message.nextRetryTimestamp = block.timestamp + (retryDelay * (2 ** message.retries));

        uint64 initialNonce = nonces[message.dstChainId];
        try ICrossChainModule(crossChainModule).retryFailedMessage{value: nativeFee}(messageId) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            nonces[message.dstChainId]++;
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries);
            delete failedMessages[messageId];
            if (failedMessageCount > 0) failedMessageCount--;
        } catch {
            nonces[message.dstChainId] = initialNonce;
            emit FailedMessageRetryScheduled(messageId, message.nextRetryTimestamp);
        }
    }

    function retryFailedMessagesBatch(uint256[] calldata messageIds) external payable nonReentrant whenNotPaused {
        uint256 length = messageIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);

        uint256 totalNativeFee;
        for (uint256 i = 0; i < length; i++) {
            FailedMessage memory message = failedMessages[messageIds[i]];
            if (message.retries >= MAX_CROSS_CHAIN_RETRIES || message.timestamp == 0 || block.timestamp < message.nextRetryTimestamp) continue;
            (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
                message.dstChainId,
                message.payload,
                message.adapterParams
            );
            totalNativeFee += nativeFee;
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);

        uint256 refundAmount = msg.value;
        uint256 successfulRetries;
        uint256[] memory processedIds = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            if (gasleft() < MIN_GAS_PER_MESSAGE) revert InsufficientGasForBatch(MIN_GAS_PER_MESSAGE, gasleft());

            FailedMessage storage message = failedMessages[messageIds[i]];
            if (message.retries >= MAX_CROSS_CHAIN_RETRIES || message.timestamp == 0 || block.timestamp < message.nextRetryTimestamp) continue;

            (uint256 nativeFee,) = ICrossChainModule(crossChainModule).getEstimatedCrossChainFee(
                message.dstChainId,
                message.payload,
                message.adapterParams
            );

            bool success;
            try ICrossChainModule(crossChainModule).retryFailedMessage{value: nativeFee}(messageIds[i]) {
                refundAmount -= nativeFee;
                success = true;
                successfulRetries++;
                processedIds[i] = messageIds[i];
                emit FailedMessageRetried(messageIds[i], message.dstChainId, message.retries + 1);
            } catch {
                message.retries++;
                message.nextRetryTimestamp = block.timestamp + (retryDelay * (2 ** message.retries));
                emit FailedMessageRetryScheduled(messageIds[i], message.nextRetryTimestamp);
            }

            if (success) {
                nonces[message.dstChainId]++;
                delete failedMessages[messageIds[i]];
                if (failedMessageCount > 0) failedMessageCount--;
            }
        }

        if (refundAmount > 0) {
            payable(msg.sender).transfer(refundAmount);
        }
    }

    // --- Metadata Functions ---

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);

        if (bytes(baseURI).length > 0) {
            return string(abi.encodePacked(baseURI, tokenId.toString()));
        }

        Position memory position = positionData[tokenId];
        FeeTracking memory fees = feeTracking[tokenId];
        bytes memory json = abi.encodePacked(
            '{"name":"AMMPool Position #', tokenId.toString(),
            '","description":"Liquidity position in AMMPool","attributes":[',
            '{"trait_type":"Pool","value":"', StringsUpgradeable.toHexString(position.pool), '"},',
            '{"trait_type":"TokenA","value":"', StringsUpgradeable.toHexString(position.tokenA), '"},',
            '{"trait_type":"TokenB","value":"', StringsUpgradeable.toHexString(position.tokenB), '"},',
            '{"trait_type":"TickLower","value":"', int24ToString(position.tickLower), '"},',
            '{"trait_type":"TickUpper","value":"', int24ToString(position.tickUpper), '"},',
            '{"trait_type":"Liquidity","value":"', position.liquidity.toString(), '"},',
            '{"trait_type":"SourceChainId","value":"', uint256(position.sourceChainId).toString(), '"},',
            '{"trait_type":"Amount0","value":"', fees.accumulated0.toString(), '"},',
            '{"trait_type":"Amount1","value":"', fees.accumulated1.toString(), '"}]}'
        );

        return string(abi.encodePacked("data:application/json;base64,", Base64Upgradeable.encode(json)));
    }

    // --- View Functions ---

    function getPositionData(uint256 tokenId) external view returns (Position memory position, FeeTracking memory tracking) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        return (positionData[tokenId], feeTracking[tokenId]);
    }

    function getAggregatedFees(address owner) external view returns (uint256 total0, uint256 total1) {
        AggregatedFees memory fees = aggregatedFees[owner];
        return (fees.total0, fees.total1);
    }

    // --- Governance Functions ---

    function updateTrustedRemoteManager(uint64 chainId, bytes calldata managerAddress) external onlyOwner whenNotPaused {
        if (chainId == 0) revert InvalidChainId(chainId);
        if (managerAddress.length == 0) revert InvalidAddress(address(0), "Invalid manager address");
        trustedRemoteManagers[chainId] = managerAddress;
        emit TrustedRemoteManagerUpdated(chainId, managerAddress);
    }

    function updateCrossChainMessenger(address newMessenger, uint8 newMessengerType) external onlyOwner whenNotPaused {
        if (newMessenger == address(0)) revert InvalidAddress(newMessenger, "Invalid messenger");
        if (newMessengerType > 2) revert InvalidMessengerType(newMessengerType);
        crossChainMessenger = newMessenger;
        messengerType = newMessengerType;
        emit CrossChainMessengerUpdated(newMessenger, newMessengerType);
        emit MessengerTypeUpdated(newMessengerType);
    }

    function updateTokenBridge(uint8 bridgeType, address newBridge) external onlyOwner whenNotPaused {
        if (newBridge == address(0)) revert InvalidAddress(newBridge, "Invalid bridge address");
        tokenBridges[bridgeType] = newBridge;
        IERC20Upgradeable(IAMMPool(ammPool).tokenA()).safeApprove(newBridge, type(uint256).max);
        IERC20Upgradeable(IAMMPool(ammPool).tokenB()).safeApprove(newBridge, type(uint256).max);
        emit TokenBridgeUpdated(bridgeType, newBridge);
    }

    function updateBaseURI(string memory newBaseURI) external onlyOwner whenNotPaused {
        baseURI = newBaseURI;
        emit BaseURIUpdated(newBaseURI);
    }

    function updateChainId(uint64 chainId, string memory axelarChain) external onlyOwner whenNotPaused {
        if (chainId == 0) revert InvalidChainId(chainId);
        if (bytes(axelarChain).length == 0) revert InvalidAxelarChain();
        chainIdToAxelarChain[chainId] = axelarChain;
        emit ChainIdUpdated(chainId, axelarChain);
    }

    function updateDefaultFeeAggregationThreshold(uint256 newThreshold) external onlyOwner whenNotPaused {
        if (newThreshold == 0) revert InvalidFeeThreshold(newThreshold);
        defaultFeeAggregationThreshold = newThreshold;
        emit DefaultFeeAggregationThresholdUpdated(newThreshold);
    }

    function updateRetryDelay(uint256 newDelay) external onlyOwner whenNotPaused {
        if (newDelay == 0) revert InvalidAddress(address(0), "Invalid retry delay");
        retryDelay = newDelay;
        emit RetryDelayUpdated(newDelay);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // --- Helper Functions ---

    function _getNonce(uint64 dstChainId) internal returns (uint64) {
        try ICrossChainModule(crossChainModule).getNonce(uint16(dstChainId), messengerType) returns (uint64 nonce) {
            return nonce;
        } catch {
            if (messengerType == 0) {
                return ILayerZeroEndpoint(crossChainMessenger).getInboundNonce(dstChainId, trustedRemoteManagers[dstChainId]);
            } else {
                return nonces[dstChainId];
            }
        }
    }

    function _isValidTickRange(int24 tickLower, int24 tickUpper) internal pure returns (bool) {
        return
            tickLower < tickUpper &&
            tickLower >= TickMath.MIN_TICK &&
            tickUpper <= TickMath.MAX_TICK;
    }

    function int24ToString(int24 value) internal pure returns (string memory) {
        return value >= 0 ? uint256(uint24(value)).toString() : string(abi.encodePacked("-", uint256(uint24(-value)).toString()));
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        return IERC721ReceiverUpgradeable.onERC721Received.selector;
    }

    // --- Storage Gap ---
    uint256[48] private __gap; // Adjusted for new crossChainModule variable
}