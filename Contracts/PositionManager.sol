// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin specific imports
import { ERC721Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import { IERC721ReceiverUpgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import { StringsUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol";
import { Base64Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/Base64Upgradeable.sol";
import "./Interfaces.sol"; 

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
}

interface ILayerZeroEndpoint {
    function getInboundNonce(uint16 srcChainId, bytes calldata srcAddress) external view returns (uint64);
}

interface IWormhole {
    function publishMessage(
        uint32 nonce,
        bytes calldata payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);
}

interface ITokenBridge {
    function burn(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function mint(address token, uint256 amount, address recipient) external;
}

/// @title PositionManager - Enhanced upgradeable ERC721 contract for managing NFT-based liquidity positions
/// @notice Manages NFT positions with automatic fee bridging, batch operations, and multi-bridge support
/// @dev Implements ERC721Upgradeable with cross-chain functionality and gas optimizations
contract PositionManager is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    ERC721Upgradeable
{
    using StringsUpgradeable for uint256;
    using Base64Upgradeable for bytes;

    // Constants
    string public constant VERSION = "1.2.0";
    uint256 public constant MAX_CROSS_CHAIN_RETRIES = 3;
    uint256 public constant RETRY_DELAY = 1 hours;
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant FEE_AGGREGATION_THRESHOLD = 0.01 ether; // Minimum fee amount to trigger bridging

    // Storage variables
    address public ammPool;
    address public crossChainMessenger;
    string public baseURI;
    uint8 public messengerType; // 0 = LayerZero, 1 = Axelar, 2 = Wormhole
    mapping(uint16 => bytes) public trustedRemoteManagers;
    mapping(uint16 => string) public chainIdToAxelarChain;
    mapping(uint256 => Position) public positionData;
    mapping(uint256 => bool) public isCrossChainPosition;
    mapping(uint16 => uint64) public nonces;
    uint256 public failedMessageCount;
    mapping(uint8 => address) public tokenBridges; // Mapping of bridgeType to bridge address
    mapping(uint256 => FeeTracking) public feeTracking; // Tracks fees per position
    mapping(address => AggregatedFees) public aggregatedFees; // Aggregated fees per user
    mapping(address => address) public feeDestinations; // User-defined fee destinations

    // Structs
    struct Position {
        address pool;
        int24 tickLower;
        int24 tickUpper;
        uint256 liquidity;
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
    }
    mapping(uint256 => FailedMessage) public failedMessages;

    // Errors
    error InvalidAMMPool(address pool);
    error InvalidTokenId(uint256 tokenId);
    error NotTokenOwner(uint256 tokenId);
    error InvalidChainId(uint16 chainId);
    error InvalidMessenger(address messenger);
    error InsufficientFee(uint256 provided, uint256 required);
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error RetryNotReady(uint256 messageId, uint256 nextRetryTimestamp);
    error InvalidPositionData(uint256 tokenId);
    error CrossChainPosition(uint256 tokenId);
    error Unauthorized();
    error PositionAlreadyExists(uint256 tokenId);
    error InvalidBatchSize(uint256 size);
    error FeesNotCollected(uint256 tokenId);
    error InvalidMessengerType(uint8 messengerType);
    error InvalidBridgeType(uint8 bridgeType);
    error InvalidFeeDestination(address destination);
    error InsufficientAggregatedFees();
    error InvalidAddress(address addr, string message);
    error ContractPaused();

    // Events
    event PositionMinted(uint256 indexed tokenId, address indexed owner, address indexed pool, int24 tickLower, int24 tickUpper, uint256 liquidity);
    event BatchPositionsMinted(uint256[] indexed tokenIds, address indexed owner, address indexed pool, uint256 count);
    event PositionBurned(uint256 indexed tokenId, address indexed owner);
    event BatchPositionsTransferred(uint256[] indexed tokenIds, address indexed owner, address indexed pool, uint256 count);
    event CrossChainPositionSent(uint256 indexed tokenId, address indexed owner, address indexed recipient, uint16 dstChainId, uint64 nonce, uint256 timelock);
    event CrossChainPositionReceived(uint256 indexed tokenId, address indexed owner, uint16 indexed srcChainId, uint64 nonce);
    event FeesBridgedCrossChain(uint256 indexed tokenId, address indexed owner, uint256 amount0, uint256 amount1, uint16 dstChainId, uint8 bridgeType, uint64 nonce);
    event BatchFeesBridged(address indexed owner, uint256[] tokenIds, uint256 total0, uint256 total1, uint16 dstChainId, uint8 bridgeType, uint64 nonce);
    event FeesAggregated(address indexed owner, uint256 amount0, uint256 amount1);
    event FeeDestinationUpdated(address indexed owner, address destination);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes payload);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries);
    event FailedMessageRetryScheduled(uint256 indexed messageId, uint256 nextRetryTimestamp);
    event TrustedRemoteManagerUpdated(uint16 indexed chainId, bytes managerAddress);
    event CrossChainMessengerUpdated(address indexed newMessenger, uint8 messengerType);
    event TokenBridgeUpdated(uint8 bridgeType, address indexed newBridge);
    event BaseURIUpdated(string newBaseURI);
    event MessengerTypeUpdated(uint8 newMessengerType);

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

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _ammPool,
        address _crossChainMessenger,
        uint8 _messengerType,
        string memory _name,
        string memory _symbol
    ) external initializer {
        if (_ammPool == address(0)) revert InvalidAMMPool(_ammPool);
        if (_crossChainMessenger == address(0)) revert InvalidMessenger(_crossChainMessenger);
        if (_messengerType > 2) revert InvalidMessengerType(_messengerType);

        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __ERC721_init(_name, _symbol);

        ammPool = _ammPool;
        crossChainMessenger = _crossChainMessenger;
        messengerType = _messengerType;
        emit CrossChainMessengerUpdated(_crossChainMessenger, _messengerType);
        emit MessengerTypeUpdated(_messengerType);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // --- NFT Management Functions ---

    function mintPosition(uint256 positionId, address recipient) external nonReentrant onlyAMMPool {
        if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient");
        if (_exists(positionId)) revert PositionAlreadyExists(positionId);

        (
            address owner,
            int24 tickLower,
            int24 tickUpper,
            uint256 liquidity,
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

        _aggregateFees(positionId); // Initialize fee aggregation
        _safeMint(recipient, positionId);

        emit PositionMinted(positionId, recipient, ammPool, tickLower, tickUpper, liquidity);
    }

    function batchMintPositions(
        uint256[] calldata positionIds,
        address[] calldata recipients
    ) external nonReentrant onlyAMMPool {
        uint256 length = positionIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE || length != recipients.length) revert InvalidBatchSize(length);

        uint256[] memory mintedIds = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            uint256 positionId = positionIds[i];
            address recipient = recipients[i];
            if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient");
            if (_exists(positionId)) revert PositionAlreadyExists(positionId);

            (
                address owner,
                int24 tickLower,
                int24 tickUpper,
                uint256 liquidity,
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

            _aggregateFees(positionId); // Initialize fee aggregation
            _safeMint(recipient, positionId);
            mintedIds[i] = positionId;

            emit PositionMinted(positionId, recipient, ammPool, tickLower, tickUpper, liquidity);
        }

        emit BatchPositionsMinted(mintedIds, msg.sender, ammPool, length);
    }

    function burnPosition(uint256 tokenId) external nonReentrant onlyTokenOwner(tokenId) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (isCrossChainPosition[tokenId]) revert CrossChainPosition(tokenId);

        (
            address owner,
            ,
            ,
            uint256 liquidity,
            ,,
            uint256 tokensOwed0,
            uint256 tokensOwed1
        ) = IAMMPool(ammPool).positions(tokenId);
        if (liquidity > 0 || tokensOwed0 > 0 || tokensOwed1 > 0 || owner != msg.sender) revert InvalidPositionData(tokenId);

        _aggregateFees(tokenId); // Aggregate any remaining fees before burning
        delete positionData[tokenId];
        delete feeTracking[tokenId];
        _burn(tokenId);

        emit PositionBurned(tokenId, msg.sender);
    }

    function transferToPool(uint256 tokenId) external nonReentrant onlyTokenOwner(tokenId) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);

        _aggregateFees(tokenId); // Aggregate fees before transfer
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId;
        safeTransferFrom(msg.sender, ammPool, tokenId);

        emit BatchPositionsTransferred(tokenIds, msg.sender, ammPool, 1);
    }

    function batchTransferToPool(uint256[] calldata tokenIds) external nonReentrant {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);

        for (uint256 i = 0; i < length; i++) {
            uint256 tokenId = tokenIds[i];
            if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
            if (ownerOf(tokenId) != msg.sender) revert NotTokenOwner(tokenId);

            _aggregateFees(tokenId); // Aggregate fees before transfer
            safeTransferFrom(msg.sender, ammPool, tokenId);
        }

        emit BatchPositionsTransferred(tokenIds, msg.sender, ammPool, length);
    }

    // --- Fee Management Functions ---

    function setFeeDestination(address destination) external {
        if (destination == address(0)) revert InvalidFeeDestination(destination);
        feeDestinations[msg.sender] = destination;
        emit FeeDestinationUpdated(msg.sender, destination);
    }

    function _aggregateFees(uint256 tokenId) internal {
        (, , , , , , uint256 tokensOwed0, uint256 tokensOwed1) = IAMMPool(ammPool).positions(tokenId);
        if (tokensOwed0 > 0 || tokensOwed1 > 0) {
            IAMMPool(ammPool).collectFees(tokenId);
            address owner = ownerOf(tokenId);
            feeTracking[tokenId].accumulated0 += tokensOwed0;
            feeTracking[tokenId].accumulated1 += tokensOwed1;
            aggregatedFees[owner].total0 += tokensOwed0;
            aggregatedFees[owner].total1 += tokensOwed1;
            emit FeesAggregated(owner, tokensOwed0, tokensOwed1);
        }
    }

    function collectAndBridgeFees(
        uint256 tokenId,
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyTokenOwner(tokenId) whenNotPausedCrossChain {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType(bridgeType);

        _aggregateFees(tokenId);
        FeeTracking storage fees = feeTracking[tokenId];
        uint256 amount0 = fees.accumulated0 - fees.lastBridged0;
        uint256 amount1 = fees.accumulated1 - fees.lastBridged1;

        if (amount0 == 0 && amount1 == 0) revert FeesNotCollected(tokenId);

        address recipient = feeDestinations[msg.sender] != address(0) ? feeDestinations[msg.sender] : msg.sender;
        address bridge = tokenBridges[bridgeType];

        fees.lastBridged0 = fees.accumulated0;
        fees.lastBridged1 = fees.accumulated1;
        fees.lastDstChainId = dstChainId;

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(msg.sender, tokenId, amount0, amount1, nonce);

        (uint256 nativeFee,) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            dstChainId,
            dstAxelarChain,
            address(this),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        if (amount0 > 0) {
            ITokenBridge(bridge).burn(IAMMPool(ammPool).tokenA(), amount0, recipient, dstChainId);
        }
        if (amount1 > 0) {
            ITokenBridge(bridge).burn(IAMMPool(ammPool).tokenB(), amount1, recipient, dstChainId);
        }

        try ICrossChainMessenger(crossChainMessenger).sendMessage{value: nativeFee}(
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
            nonces[dstChainId]++;
            emit FeesBridgedCrossChain(tokenId, msg.sender, amount0, amount1, dstChainId, bridgeType, nonce);
        } catch {
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + RETRY_DELAY
            });
            emit FailedMessageStored(messageId, dstChainId, payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + RETRY_DELAY);
        }
    }

    function batchBridgeFees(
        uint256[] calldata tokenIds,
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedCrossChain {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType(bridgeType);

        uint256 total0;
        uint256 total1;
        address recipient = feeDestinations[msg.sender] != address(0) ? feeDestinations[msg.sender] : msg.sender;
        address bridge = tokenBridges[bridgeType];

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

        if (total0 > 0) {
            ITokenBridge(bridge).burn(IAMMPool(ammPool).tokenA(), total0, recipient, dstChainId);
        }
        if (total1 > 0) {
            ITokenBridge(bridge).burn(IAMMPool(ammPool).tokenB(), total1, recipient, dstChainId);
        }

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(msg.sender, tokenIds, total0, total1, nonce);

        (uint256 nativeFee,) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            dstChainId,
            dstAxelarChain,
            address(this),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ICrossChainMessenger(crossChainMessenger).sendMessage{value: nativeFee}(
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
            nonces[dstChainId]++;
            emit BatchFeesBridged(msg.sender, tokenIds, total0, total1, dstChainId, bridgeType, nonce);
        } catch {
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + RETRY_DELAY
            });
            emit FailedMessageStored(messageId, dstChainId, payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + RETRY_DELAY);
        }
    }

    function bridgeAggregatedFees(
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedCrossChain {
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType(bridgeType);

        AggregatedFees storage fees = aggregatedFees[msg.sender];
        if (fees.total0 < FEE_AGGREGATION_THRESHOLD && fees.total1 < FEE_AGGREGATION_THRESHOLD) revert InsufficientAggregatedFees();

        address recipient = feeDestinations[msg.sender] != address(0) ? feeDestinations[msg.sender] : msg.sender;
        address bridge = tokenBridges[bridgeType];

        uint256 amount0 = fees.total0;
        uint256 amount1 = fees.total1;
        fees.total0 = 0;
        fees.total1 = 0;

        if (amount0 > 0) {
            ITokenBridge(bridge).burn(IAMMPool(ammPool).tokenA(), amount0, recipient, dstChainId);
        }
        if (amount1 > 0) {
            ITokenBridge(bridge).burn(IAMMPool(ammPool).tokenB(), amount1, recipient, dstChainId);
        }

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(msg.sender, new uint256[](0), amount0, amount1, nonce);

        (uint256 nativeFee,) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            dstChainId,
            dstAxelarChain,
            address(this),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ICrossChainMessenger(crossChainMessenger).sendMessage{value: nativeFee}(
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
            nonces[dstChainId]++;
            emit BatchFeesBridged(msg.sender, new uint256[](0), amount0, amount1, dstChainId, bridgeType, nonce);
        } catch {
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + RETRY_DELAY
            });
            emit FailedMessageStored(messageId, dstChainId, payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + RETRY_DELAY);
        }
    }

    // --- Cross-Chain Functions ---

    function transferPositionCrossChain(
        uint256 tokenId,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyTokenOwner(tokenId) whenNotPausedCrossChain {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        _aggregateFees(tokenId);
        Position memory position = positionData[tokenId];
        (
            ,
            ,
            ,
            uint256 liquidity,
            ,,
            uint256 tokensOwed0,
            uint256 tokensOwed1
        ) = IAMMPool(ammPool).positions(tokenId);
        if (liquidity == 0) revert InvalidPositionData(tokenId);
        if (tokensOwed0 > 0 || tokensOwed1 > 0) revert FeesNotCollected(tokenId);

        isCrossChainPosition[tokenId] = true;
        _burn(tokenId);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        uint256 timelock = block.timestamp + 1 hours;
        bytes memory payload = abi.encode(
            msg.sender,
            tokenId,
            position.tickLower,
            position.tickUpper,
            liquidity,
            nonce,
            timelock,
            position.tokenA,
            position.tokenB
        );

        (uint256 nativeFee,) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            dstChainId,
            dstAxelarChain,
            address(this),
            payload,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        bool success;
        try ICrossChainMessenger(crossChainMessenger).sendMessage{value: nativeFee}(
            dstChainId,
            dstAxelarChain,
            destinationAddress,
            payload,
            adapterParams,
            payable(msg.sender)
        ) {
            success = true;
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            nonces[dstChainId]++;
        } catch {
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + RETRY_DELAY
            });
            emit FailedMessageStored(messageId, dstChainId, payload);
            emit FailedMessageRetryScheduled(messageId, block.timestamp + RETRY_DELAY);
        }

        if (success) {
            emit CrossChainPositionSent(tokenId, msg.sender, msg.sender, dstChainId, nonce, timelock);
        }
    }

    function batchTransferPositionsCrossChain(
        uint256[] calldata tokenIds,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedCrossChain {
        uint256 length = tokenIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        uint256 timelock = block.timestamp + 1 hours;
        bytes[] memory payloads = new bytes[](length);
        uint256 totalNativeFee;

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
                uint256 liquidity,
                ,,
                uint256 tokensOwed0,
                uint256 tokensOwed1
            ) = IAMMPool(ammPool).positions(tokenId);
            if (liquidity == 0) revert InvalidPositionData(tokenId);
            if (tokensOwed0 > 0 || tokensOwed1 > 0) revert FeesNotCollected(tokenId);

            isCrossChainPosition[tokenId] = true;
            _burn(tokenId);
            payloads[i] = abi.encode(
                msg.sender,
                tokenId,
                position.tickLower,
                position.tickUpper,
                liquidity,
                nonce + uint64(i),
                timelock,
                position.tokenA,
                position.tokenB
            );

            (uint256 nativeFee,) = ICrossChainMessenger(crossChainMessenger).estimateFees(
                dstChainId,
                dstAxelarChain,
                address(this),
                payloads[i],
                adapterParams
            );
            totalNativeFee += nativeFee;
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);

        bool success = true;
        for (uint256 i = 0; i < length; i++) {
            try ICrossChainMessenger(crossChainMessenger).sendMessage{value: totalNativeFee / length}(
                dstChainId,
                dstAxelarChain,
                destinationAddress,
                payloads[i],
                adapterParams,
                payable(msg.sender)
            ) {
                emit CrossChainPositionSent(tokenIds[i], msg.sender, msg.sender, dstChainId, nonce + uint64(i), timelock);
            } catch {
                success = false;
                uint256 messageId = failedMessageCount++;
                failedMessages[messageId] = FailedMessage({
                    dstChainId: dstChainId,
                    dstAxelarChain: dstAxelarChain,
                    payload: payloads[i],
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    nextRetryTimestamp: block.timestamp + RETRY_DELAY
                });
                emit FailedMessageStored(messageId, dstChainId, payloads[i]);
                emit FailedMessageRetryScheduled(messageId, block.timestamp + RETRY_DELAY);
            }
        }

        if (success) {
            nonces[dstChainId] += uint64(length);
            if (msg.value > totalNativeFee) {
                payable(msg.sender).transfer(msg.value - totalNativeFee);
            }
        }
    }

    function receiveCrossChainPosition(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload
    ) external nonReentrant whenNotPausedCrossChain {
        if (keccak256(srcAddress) != keccak256(trustedRemoteManagers[srcChainId])) revert Unauthorized();
        if (msg.sender != crossChainMessenger) revert Unauthorized();

        (
            address recipient,
            uint256 tokenId,
            int24 tickLower,
            int24 tickUpper,
            uint256 liquidity,
            uint64 nonce,
            uint256 timelock,
            address tokenA,
            address tokenB
        ) = abi.decode(payload, (address, uint256, int24, int24, uint256, uint64, uint256, address, address));

        if (block.timestamp < timelock) revert Unauthorized(); // Timelock check
        if (_exists(tokenId)) revert PositionAlreadyExists(tokenId);
        if (recipient == address(0) || liquidity == 0) revert InvalidPositionData(tokenId);
        if (IAMMPool(ammPool).tokenA() != tokenA || IAMMPool(ammPool).tokenB() != tokenB) revert InvalidPositionData(tokenId);

        positionData[tokenId] = Position({
            pool: ammPool,
            tickLower: tickLower,
            tickUpper: tickUpper,
            liquidity: liquidity,
            sourceChainId: srcChainId,
            tokenA: tokenA,
            tokenB: tokenB
        });

        _safeMint(recipient, tokenId);

        IAMMPool(ammPool).addConcentratedLiquidityCrossChain(
            0,
            0,
            tickLower,
            tickUpper,
            srcChainId,
            ""
        );

        emit CrossChainPositionReceived(tokenId, recipient, srcChainId, nonce);
    }

    // --- Retry Mechanism ---

    function retryFailedMessage(uint256 messageId) external payable nonReentrant whenNotPausedCrossChain {
        FailedMessage storage message = failedMessages[messageId];
        if (message.retries >= MAX_CROSS_CHAIN_RETRIES) revert MaxRetriesExceeded(messageId);
        if (message.timestamp == 0) revert MessageNotFailed(messageId);
        if (block.timestamp < message.nextRetryTimestamp) revert RetryNotReady(messageId, message.nextRetryTimestamp);

        unchecked {
            message.retries++;
            message.nextRetryTimestamp = block.timestamp + (RETRY_DELAY * (2 ** message.retries));
        }

        (uint256 nativeFee,) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            message.dstChainId,
            message.dstAxelarChain,
            address(this),
            message.payload,
            message.adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        bool success;
        try ICrossChainMessenger(crossChainMessenger).sendMessage{value: nativeFee}(
            message.dstChainId,
            message.dstAxelarChain,
            trustedRemoteManagers[message.dstChainId],
            message.payload,
            message.adapterParams,
            payable(msg.sender)
        ) {
            success = true;
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries);
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

    // --- Metadata Functions ---

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);

        if (bytes(baseURI).length > 0) {
            return string(abi.encodePacked(baseURI, tokenId.toString()));
        }

        Position memory position = positionData[tokenId];
        FeeTracking memory fees = feeTracking[tokenId];
        string memory json = string(abi.encodePacked(
            "{\"name\":\"AMMPool Position #",
            tokenId.toString(),
            "\",\"description\":\"Liquidity position in AMMPool\",\"attributes\":",
            "[{\"trait_type\":\"Pool\",\"value\":\"", _toHexString(position.pool), "\"},",
            "{\"trait_type\":\"TokenA\",\"value\":\"", _toHexString(position.tokenA), "\"},",
            "{\"trait_type\":\"TokenB\",\"value\":\"", _toHexString(position.tokenB), "\"},",
            "{\"trait_type\":\"TickLower\",\"value\":\"", int24ToString(position.tickLower), "\"},",
            "{\"trait_type\":\"TickUpper\",\"value\":\"", int24ToString(position.tickUpper), "\"},",
            "{\"trait_type\":\"Liquidity\",\"value\":\"", position.liquidity.toString(), "\"},",
            "{\"trait_type\":\"SourceChainId\",\"value\":\"", uint256(position.sourceChainId).toString(), "\"},",
            "{\"trait_type\":\"AccumulatedFees0\",\"value\":\"", fees.accumulated0.toString(), "\"},",
            "{\"trait_type\":\"AccumulatedFees1\",\"value\":\"", fees.accumulated1.toString(), "\"}]}"
        ));

        return string(abi.encodePacked("data:application/json;base64,", Base64Upgradeable.encode(bytes(json))));
    }

    // --- View Functions ---

    function getPositionData(uint256 tokenId) external view returns (Position memory, FeeTracking memory) {
        if (!_exists(tokenId)) revert InvalidTokenId(tokenId);
        return (positionData[tokenId], feeTracking[tokenId]);
    }

    function getAggregatedFees(address owner) external view returns (uint256 total0, uint256 total1) {
        AggregatedFees memory fees = aggregatedFees[owner];
        return (fees.total0, fees.total1);
    }

    // --- Governance Functions ---

    function updateTrustedRemoteManager(uint16 chainId, bytes calldata managerAddress) external onlyOwner {
        if (chainId == 0) revert InvalidChainId(chainId);
        trustedRemoteManagers[chainId] = managerAddress;
        emit TrustedRemoteManagerUpdated(chainId, managerAddress);
    }

    function updateCrossChainMessenger(address newMessenger, uint8 newMessengerType) external onlyOwner {
        if (newMessenger == address(0)) revert InvalidMessenger(newMessenger);
        if (newMessengerType > 2) revert InvalidMessengerType(newMessengerType);
        crossChainMessenger = newMessenger;
        messengerType = newMessengerType;
        emit CrossChainMessengerUpdated(newMessenger, newMessengerType);
        emit MessengerTypeUpdated(newMessengerType);
    }

    function updateTokenBridge(uint8 bridgeType, address newBridge) external onlyOwner {
        if (newBridge == address(0)) revert InvalidAddress(newBridge, "Invalid bridge");
        tokenBridges[bridgeType] = newBridge;
        emit TokenBridgeUpdated(bridgeType, newBridge);
    }

    function updateBaseURI(string calldata newBaseURI) external onlyOwner {
        baseURI = newBaseURI;
        emit BaseURIUpdated(newBaseURI);
    }

    function updateChainIdMapping(uint16 chainId, string calldata axelarChain) external onlyOwner {
        if (chainId == 0) revert InvalidChainId(chainId);
        chainIdToAxelarChain[chainId] = axelarChain;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // --- Helper Functions ---

    function _getNonce(uint16 dstChainId) internal returns (uint64) {
        if (messengerType == 0) {
            return ILayerZeroEndpoint(crossChainMessenger).getInboundNonce(dstChainId, trustedRemoteManagers[dstChainId]);
        } else if (messengerType == 1) {
            return nonces[dstChainId];
        } else if (messengerType == 2) {
            return IWormhole(crossChainMessenger).publishMessage(0, "", 1);
        } else {
            revert InvalidMessengerType(messengerType);
        }
    }

    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = new bytes(40);
        for (uint256 i = 0; i < 20; i++) {
            uint8 b = uint8(uint160(addr) >> (8 * (19 - i)));
            buffer[2 * i] = _toHexChar(b >> 4);
            buffer[2 * i + 1] = _toHexChar(b & 0x0f);
        }
        return string(abi.encodePacked("0x", buffer));
    }

    function _toHexChar(uint8 b) internal pure returns (bytes1) {
        return b < 10 ? bytes1(b + 48) : bytes1(b + 87);
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
        return this.onERC721Received.selector;
    }

    // --- Storage Gap ---
    uint256[49] private __gap;
}