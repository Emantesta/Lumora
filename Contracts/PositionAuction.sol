// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin-specific imports
import { ERC721Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import { IERC721ReceiverUpgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// Interface for PositionManager
interface IPositionManager {
    function ownerOf(uint256 tokenId) external view returns (address);
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

// Interfaces for cross-chain messaging and token bridging
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
        address destinationContract,
        bytes calldata destinationAddress,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);
}

interface ITokenBridge {
    function burn(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function mint(address token, uint256 amount, address recipient) external;
}

// Interface for CrossChainRetryOracle
interface ICrossChainRetryOracle {
    struct NetworkStatus {
        uint64 gasPrice;
        uint32 confirmationTime;
        uint8 congestionLevel;
        bool bridgeOperational;
        uint32 recommendedRetryDelay;
        bool retryRecommended;
        uint256 lastUpdated;
        uint64 randomRetryDelay;
        int256 lastGasPrice;
        int256 lastTokenPrice;
    }

    function getNetworkStatus(uint64 chainId) external view returns (NetworkStatus memory);
    function requestNetworkStatusUpdate(uint64 chainId, bytes32 jobId, uint256 fee) external returns (bytes32);
}

/// @title PositionAuction - Upgradeable auction contract for PositionManager NFTs with cross-chain and governance
/// @notice Allows auctions of liquidity position NFTs with multiple payment tokens, reserve price, and buy-now option
/// @dev Integrates with PositionManager, ITokenBridge, and CrossChainRetryOracle for cross-chain auctions and fund settlement
contract PositionAuction is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    IERC721ReceiverUpgradeable
{
    using SafeERC20 for IERC20;

    // Constants
    uint256 public constant MIN_AUCTION_DURATION = 1 hours;
    uint256 public constant MAX_AUCTION_DURATION = 7 days;
    uint256 public constant MIN_BID_INCREMENT = 1e15; // 0.001 tokens (assuming 18 decimals)
    uint256 public constant FEE_DENOMINATOR = 10000; // Basis points (100.00%)
    uint256 public constant MAX_CROSS_CHAIN_RETRIES = 3;
    uint256 public constant RETRY_DELAY = 1 hours;
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant MIN_LIQUIDITY_THRESHOLD = 1e16; // Minimum balance for ERC20 liquidity check
    uint256 public constant MIN_TIMELOCK = 1 hours;
    uint256 public constant MAX_TIMELOCK = 1 days;
    uint256 public constant MESSAGE_EXPIRATION = 30 days;

    // Storage variables
    address public positionManager; // Address of the PositionManager contract
    address public protocolTreasury; // Address for collecting fees
    address public governance; // Governance contract for managing settings
    address public tokenBridge; // Address of the token bridge contract
    address public crossChainMessenger; // Cross-chain messaging contract
    address public retryOracle; // CrossChainRetryOracle contract
    bytes32 public oracleJobId; // Chainlink job ID for oracle requests
    address public linkToken; // LINK token address for oracle requests
    uint256 public auctionFeePercent; // Fee percentage (e.g., 250 = 2.5%)
    uint8 public messengerType; // 0 = LayerZero, 1 = Axelar, 2 = Wormhole
    mapping(uint16 => bytes) public trustedRemoteManagers; // Chain ID to trusted manager address
    mapping(uint16 => string) public chainIdToAxelarChain; // Chain ID to Axelar chain ID
    mapping(uint256 => Auction) public auctions; // Auction ID to auction details
    mapping(uint256 => bool) public isCrossChainAuction; // Tracks cross-chain auctions
    mapping(address => bool) public allowedPaymentTokens; // Supported ERC20 tokens
    mapping(uint256 => FailedMessage) public failedMessages; // Failed cross-chain messages
    mapping(uint16 => uint64) public nonces; // Nonces for cross-chain messaging
    mapping(uint16 => uint256) public chainTimelocks; // Dynamic timelocks per chain
    mapping(bytes32 => uint256) public validatedMessages; // Tracks validated cross-chain messages with expiration
    uint256 public auctionCount; // Total number of auctions
    uint256 public failedMessageCount; // Total failed messages

    // Structs
    struct Auction {
        uint256 tokenId; // NFT token ID
        address seller; // Seller of the NFT
        address paymentToken; // ERC20 token for bidding
        uint256 startPrice; // Starting bid price
        uint256 reservePrice; // Minimum acceptable bid
        uint256 buyNowPrice; // Price for instant purchase
        uint256 highestBid; // Current highest bid
        address highestBidder; // Address of the highest bidder
        uint256 endTime; // Auction end timestamp
        bool ended; // Whether the auction has ended
        uint16 sourceChainId; // Chain ID for cross-chain auctions (0 if local)
    }

    struct FailedMessage {
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint8 retries; // Changed to uint8 to optimize storage
        uint256 timestamp;
        uint256 nextRetryTimestamp;
        uint8 messengerType;
    }

    // Events
    event AuctionCreated(
        uint256 indexed auctionId,
        uint256 indexed tokenId,
        address indexed seller,
        address paymentToken,
        uint256 startPrice,
        uint256 reservePrice,
        uint256 buyNowPrice,
        uint256 endTime,
        uint16 sourceChainId
    );
    event BatchAuctionsCreated(
        uint256[] indexed auctionIds,
        uint256[] tokenIds,
        address indexed seller,
        uint16[] dstChainIds
    );
    event BidPlaced(
        uint256 indexed auctionId,
        uint256 indexed tokenId,
        address indexed bidder,
        uint256 bidAmount
    );
    event BuyNowExecuted(
        uint256 indexed auctionId,
        uint256 indexed tokenId,
        address indexed buyer,
        uint256 price
    );
    event AuctionEnded(
        uint256 indexed auctionId,
        uint256 indexed tokenId,
        address indexed winner,
        uint256 finalPrice
    );
    event BatchAuctionsEnded(
        uint256[] indexed auctionIds,
        uint256[] tokenIds,
        address[] winners
    );
    event AuctionCancelled(
        uint256 indexed auctionId,
        uint256 indexed tokenId
    );
    event CrossChainAuctionCreated(
        uint256 indexed auctionId,
        uint256 indexed tokenId,
        address indexed seller,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock
    );
    event CrossChainBidReceived(
        uint256 indexed auctionId,
        uint256 indexed tokenId,
        address indexed bidder,
        uint256 bidAmount,
        uint16 srcChainId,
        uint64 nonce,
        uint256 timelock
    );
    event CrossChainFundsReceived(
        uint256 indexed auctionId,
        address indexed token,
        uint256 amount,
        address indexed recipient,
        uint16 srcChainId
    );
    event FailedMessageStored(
        uint256 indexed messageId,
        uint16 indexed dstChainId,
        bytes payload,
        uint8 messengerType,
        uint256 nextRetryTimestamp
    );
    event FailedMessageRetried(
        uint256 indexed messageId,
        uint16 indexed dstChainId,
        uint8 retries,
        uint8 messengerType
    );
    event GovernanceUpdated(address indexed newGovernance);
    event ProtocolTreasuryUpdated(address indexed newTreasury);
    event AuctionFeeUpdated(uint256 newFeePercent);
    event PaymentTokenUpdated(address indexed paymentToken, bool allowed);
    event CrossChainMessengerUpdated(address indexed newMessenger, uint8 messengerType);
    event TokenBridgeUpdated(address indexed newTokenBridge);
    event TrustedRemoteManagerUpdated(uint16 indexed chainId, bytes managerAddress);
    event ChainTimelockUpdated(uint16 indexed chainId, uint256 timelock);
    event RetryOracleUpdated(address indexed newRetryOracle, bytes32 jobId, address linkToken);
    event BatchFeeEstimated(uint256[] auctionIds, uint16[] dstChainIds, uint256 totalNativeFee);
    event ContractPaused(address indexed by);
    event ContractUnpaused(address indexed by);
    event ContractUpgraded(address indexed newImplementation);
    event EmergencyWithdrawal(address indexed token, uint256 amount, address indexed to);
    event OracleFallback(uint16 indexed chainId, string reason);

    // Errors
    error InvalidPositionManager();
    error InvalidPaymentToken(address token);
    error InvalidGovernanceAddress(address governance);
    error InvalidTreasuryAddress(address treasury);
    error InvalidTokenId(uint256 tokenId);
    error NotTokenOwner(uint256 tokenId);
    error AuctionAlreadyExists(uint256 tokenId);
    error AuctionNotActive(uint256 auctionId);
    error ErrAuctionEnded(uint256 auctionId);
    error InvalidAuctionDuration(uint256 duration);
    error BidTooLow(uint256 bidAmount, uint256 minimumBid);
    error ReservePriceNotMet(uint256 bidAmount, uint256 reservePrice);
    error InvalidBuyNowPrice(uint256 buyNowPrice, uint256 reservePrice);
    error InvalidFeePercent(uint256 feePercent);
    error InsufficientBalance(uint256 balance, uint256 required);
    error TransferFailed(address token, address to, uint256 amount);
    error ErrContractPaused();
    error InvalidChainId(uint16 chainId);
    error InvalidMessengerType(uint8 messengerType);
    error InsufficientLiquidity(address paymentToken);
    error NotGovernance();
    error InvalidBatchSize(uint256 size);
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error RetryNotReady(uint256 messageId, uint256 nextRetryTimestamp);
    error InsufficientFee(uint256 provided, uint256 required);
    error Unauthorized();
    error InvalidTokenBridge();
    error InvalidRetryOracle();
    error InvalidLinkToken();
    error InvalidOracleJobId();
    error InvalidTimelock(uint256 timelock);
    error MessageAlreadyProcessed(bytes32 messageHash);
    error MessageExpired(bytes32 messageHash);
    error RetryNotRecommended(uint16 chainId);
    error BridgeNotOperational(uint16 chainId);
    error InsufficientLinkBalance(uint256 balance, uint256 required);
    error OracleRequestFailed(bytes32 requestId);
    error InvalidAdapterParams();
    error InvalidManagerAddress();

    // Modifiers
    modifier onlyValidAuction(uint256 auctionId) {
        if (auctions[auctionId].tokenId == 0 || auctions[auctionId].ended) {
            revert AuctionNotActive(auctionId);
        }
        _;
    }

    modifier whenNotPausedAuction() {
        if (paused()) revert ErrContractPaused();
        _;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the auction contract
    /// @param _positionManager Address of the PositionManager contract
    /// @param _protocolTreasury Address for collecting fees
    /// @param _governance Governance contract address
    /// @param _crossChainMessenger Cross-chain messaging contract
    /// @param _tokenBridge Token bridge contract address
    /// @param _retryOracle CrossChainRetryOracle contract address
    /// @param _oracleJobId Chainlink job ID for oracle requests
    /// @param _linkToken LINK token address for oracle requests
    /// @param _messengerType Type of cross-chain messenger (0 = LayerZero, 1 = Axelar, 2 = Wormhole)
    /// @param _auctionFeePercent Fee percentage (in basis points)
    function initialize(
        address _positionManager,
        address _protocolTreasury,
        address _governance,
        address _crossChainMessenger,
        address _tokenBridge,
        address _retryOracle,
        bytes32 _oracleJobId,
        address _linkToken,
        uint8 _messengerType,
        uint256 _auctionFeePercent
    ) external initializer {
        _validateInitializeParams(
            _positionManager,
            _protocolTreasury,
            _governance,
            _crossChainMessenger,
            _tokenBridge,
            _retryOracle,
            _oracleJobId,
            _linkToken,
            _messengerType,
            _auctionFeePercent
        );

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        positionManager = _positionManager;
        protocolTreasury = _protocolTreasury;
        governance = _governance;
        crossChainMessenger = _crossChainMessenger;
        tokenBridge = _tokenBridge;
        retryOracle = _retryOracle;
        oracleJobId = _oracleJobId;
        linkToken = _linkToken;
        messengerType = _messengerType;
        auctionFeePercent = _auctionFeePercent;

        emit GovernanceUpdated(_governance);
        emit ProtocolTreasuryUpdated(_protocolTreasury);
        emit AuctionFeeUpdated(_auctionFeePercent);
        emit CrossChainMessengerUpdated(_crossChainMessenger, _messengerType);
        emit TokenBridgeUpdated(_tokenBridge);
        emit RetryOracleUpdated(_retryOracle, _oracleJobId, _linkToken);
    }

    /// @notice Authorize contract upgrades (restricted to governance)
    /// @param newImplementation Address of the new contract implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyGovernance {
        emit ContractUpgraded(newImplementation);
    }

    /// @notice Create a new auction (local or cross-chain)
    /// @param tokenId NFT token ID
    /// @param paymentToken ERC20 token for bidding
    /// @param startPrice Starting bid price
    /// @param reservePrice Minimum acceptable bid
    /// @param buyNowPrice Price for instant purchase
    /// @param duration Auction duration
    /// @param dstChainId Destination chain ID (0 for local)
    /// @param adapterParams Cross-chain adapter parameters
    /// @return auctionId The created auction ID
    function createAuction(
        uint256 tokenId,
        address paymentToken,
        uint256 startPrice,
        uint256 reservePrice,
        uint256 buyNowPrice,
        uint256 duration,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant whenNotPausedAuction returns (uint256) {
        _validateAuctionParams(tokenId, paymentToken, duration, reservePrice, startPrice, buyNowPrice, dstChainId, adapterParams);

        // Check oracle for cross-chain auction feasibility
        if (dstChainId != 0) {
            ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(dstChainId);
            if (!status.bridgeOperational) revert BridgeNotOperational(dstChainId);
            if (!status.retryRecommended) revert RetryNotRecommended(dstChainId);
        }

        // Transfer NFT to the auction contract
        IPositionManager(positionManager).safeTransferFrom(msg.sender, address(this), tokenId);

        uint256 auctionId = auctionCount++;
        auctions[auctionId] = Auction({
            tokenId: tokenId,
            seller: msg.sender,
            paymentToken: paymentToken,
            startPrice: startPrice,
            reservePrice: reservePrice,
            buyNowPrice: buyNowPrice,
            highestBid: 0,
            highestBidder: address(0),
            endTime: block.timestamp + duration,
            ended: false,
            sourceChainId: dstChainId == 0 ? 0 : _getCurrentChainId()
        });

        if (dstChainId != 0) {
            uint256 timelock = _getDynamicTimelock(dstChainId);
            _sendCrossChainAuction(
                auctionId,
                tokenId,
                paymentToken,
                startPrice,
                reservePrice,
                buyNowPrice,
                duration,
                dstChainId,
                adapterParams,
                timelock
            );
        }

        emit AuctionCreated(
            auctionId,
            tokenId,
            msg.sender,
            paymentToken,
            startPrice,
            reservePrice,
            buyNowPrice,
            block.timestamp + duration,
            dstChainId
        );
        return auctionId;
    }

    /// @notice Create multiple auctions in a batch
    /// @param tokenIds Array of NFT token IDs
    /// @param paymentTokens Array of ERC20 tokens for bidding
    /// @param startPrices Array of starting bid prices
    /// @param reservePrices Array of minimum acceptable bids
    /// @param buyNowPrices Array of instant purchase prices
    /// @param durations Array of auction durations
    /// @param dstChainIds Array of destination chain IDs (0 for local)
    /// @param adapterParams Array of cross-chain adapter parameters
    /// @return auctionIds Array of created auction IDs
    function batchCreateAuctions(
        uint256[] calldata tokenIds,
        address[] calldata paymentTokens,
        uint256[] calldata startPrices,
        uint256[] calldata reservePrices,
        uint256[] calldata buyNowPrices,
        uint256[] calldata durations,
        uint16[] calldata dstChainIds,
        bytes[] calldata adapterParams
    ) external payable nonReentrant whenNotPausedAuction returns (uint256[] memory) {
        uint256 length = tokenIds.length;
        if (
            length == 0 ||
            length > MAX_BATCH_SIZE ||
            length != paymentTokens.length ||
            length != startPrices.length ||
            length != reservePrices.length ||
            length != buyNowPrices.length ||
            length != durations.length ||
            length != dstChainIds.length ||
            length != adapterParams.length
        ) {
            revert InvalidBatchSize(length);
        }

        uint256[] memory auctionIds = new uint256[](length);
        bool[] memory successes = new bool[](length);

        for (uint256 i = 0; i < length; ++i) {
            try this.createAuction(
                tokenIds[i],
                paymentTokens[i],
                startPrices[i],
                reservePrices[i],
                buyNowPrices[i],
                durations[i],
                dstChainIds[i],
                adapterParams[i]
            ) returns (uint256 auctionId) {
                auctionIds[i] = auctionId;
                successes[i] = true;
            } catch {
                successes[i] = false;
                emit AuctionCreated(
                    0,
                    tokenIds[i],
                    msg.sender,
                    paymentTokens[i],
                    startPrices[i],
                    reservePrices[i],
                    buyNowPrices[i],
                    0,
                    dstChainIds[i]
                );
            }
        }

        emit BatchAuctionsCreated(auctionIds, tokenIds, msg.sender, dstChainIds);
        return auctionIds;
    }

    /// @notice Estimate fees for batch auction creation
    /// @param tokenIds Array of NFT token IDs
    /// @param paymentTokens Array of ERC20 tokens for bidding
    /// @param startPrices Array of starting bid prices
    /// @param reservePrices Array of minimum acceptable bids
    /// @param buyNowPrices Array of instant purchase prices
    /// @param durations Array of auction durations
    /// @param dstChainIds Array of destination chain IDs (0 for local)
    /// @param adapterParams Array of cross-chain adapter parameters
    /// @return totalNativeFee Total estimated native fee for cross-chain messages
    function estimateBatchAuctionFees(
        uint256[] calldata tokenIds,
        address[] calldata paymentTokens,
        uint256[] calldata startPrices,
        uint256[] calldata reservePrices,
        uint256[] calldata buyNowPrices,
        uint256[] calldata durations,
        uint16[] calldata dstChainIds,
        bytes[] calldata adapterParams
    ) external view returns (uint256 totalNativeFee) {
        uint256 length = tokenIds.length;
        if (
            length == 0 ||
            length > MAX_BATCH_SIZE ||
            length != paymentTokens.length ||
            length != startPrices.length ||
            length != reservePrices.length ||
            length != buyNowPrices.length ||
            length != durations.length ||
            length != dstChainIds.length ||
            length != adapterParams.length
        ) {
            revert InvalidBatchSize(length);
        }

        totalNativeFee = 0;
        for (uint256 i = 0; i < length; ++i) {
            if (dstChainIds[i] == 0) continue;
            if (trustedRemoteManagers[dstChainIds[i]].length == 0) revert InvalidChainId(dstChainIds[i]);
            _validateAdapterParams(adapterParams[i]);

            string memory dstAxelarChain = chainIdToAxelarChain[dstChainIds[i]];
            bytes memory destinationAddress = trustedRemoteManagers[dstChainIds[i]];
            uint64 nonce = nonces[dstChainIds[i]];
            uint256 timelock = chainTimelocks[dstChainIds[i]] == 0 ? MIN_TIMELOCK : chainTimelocks[dstChainIds[i]];
            bytes memory payload = abi.encode(
                auctionCount + i,
                tokenIds[i],
                msg.sender,
                paymentTokens[i],
                startPrices[i],
                reservePrices[i],
                buyNowPrices[i],
                durations[i],
                nonce,
                timelock
            );

            (uint256 nativeFee, ) = ICrossChainMessenger(crossChainMessenger).estimateFees(
                dstChainIds[i],
                dstAxelarChain,
                address(this),
                destinationAddress,
                payload,
                adapterParams[i]
            );
            totalNativeFee += nativeFee;
        }

        emit BatchFeeEstimated(new uint256[](length), dstChainIds, totalNativeFee);
        return totalNativeFee;
    }

    /// @notice Place a bid on an active auction
    /// @param auctionId The auction ID
    /// @param bidAmount The bid amount
    function placeBid(uint256 auctionId, uint256 bidAmount)
        external
        nonReentrant
        onlyValidAuction(auctionId)
        whenNotPausedAuction
    {
        Auction storage auction = auctions[auctionId];
        if (block.timestamp >= auction.endTime) revert ErrAuctionEnded(auctionId);

        _validateBid(auction, bidAmount);

        // Refund previous bidder
        if (auction.highestBidder != address(0)) {
            if (isCrossChainAuction[auctionId]) {
                _bridgeTokens(auction.paymentToken, auction.highestBid, auction.highestBidder, auction.sourceChainId);
            } else {
                IERC20(auction.paymentToken).safeTransfer(auction.highestBidder, auction.highestBid);
            }
        }

        // Transfer bid amount
        uint256 balanceBefore = IERC20(auction.paymentToken).balanceOf(address(this));
        IERC20(auction.paymentToken).safeTransferFrom(msg.sender, address(this), bidAmount);
        if (IERC20(auction.paymentToken).balanceOf(address(this)) < balanceBefore + bidAmount) {
            revert TransferFailed(auction.paymentToken, address(this), bidAmount);
        }

        auction.highestBid = bidAmount;
        auction.highestBidder = msg.sender;

        emit BidPlaced(auctionId, auction.tokenId, msg.sender, bidAmount);
    }

    /// @notice Place a cross-chain bid
    /// @param auctionId The auction ID
    /// @param bidAmount The bid amount
    /// @param dstChainId Destination chain ID
    /// @param adapterParams Cross-chain adapter parameters
    function placeCrossChainBid(
        uint256 auctionId,
        uint256 bidAmount,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyValidAuction(auctionId) whenNotPausedAuction {
        Auction storage auction = auctions[auctionId];
        if (block.timestamp >= auction.endTime) revert ErrAuctionEnded(auctionId);
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        _validateAdapterParams(adapterParams);

        // Check oracle for cross-chain bid feasibility
        ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(dstChainId);
        if (!status.bridgeOperational) revert BridgeNotOperational(dstChainId);
        if (!status.retryRecommended) revert RetryNotRecommended(dstChainId);

        _validateBid(auction, bidAmount);

        // Transfer bid amount to contract
        uint256 balanceBefore = IERC20(auction.paymentToken).balanceOf(address(this));
        IERC20(auction.paymentToken).safeTransferFrom(msg.sender, address(this), bidAmount);
        if (IERC20(auction.paymentToken).balanceOf(address(this)) < balanceBefore + bidAmount) {
            revert TransferFailed(auction.paymentToken, address(this), bidAmount);
        }

        // Bridge bid funds to destination chain
        _bridgeTokens(auction.paymentToken, bidAmount, address(this), dstChainId);

        // Prepare cross-chain message
        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(auctionId, auction.tokenId, msg.sender, bidAmount, nonce, timelock);

        (uint256 nativeFee, ) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            dstChainId,
            dstAxelarChain,
            address(this),
            destinationAddress,
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
                nextRetryTimestamp: block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay),
                messengerType: messengerType
            });
            emit FailedMessageStored(messageId, dstChainId, payload, messengerType, failedMessages[messageId].nextRetryTimestamp);
        }

        if (success) {
            emit CrossChainBidReceived(auctionId, auction.tokenId, msg.sender, bidAmount, _getCurrentChainId(), nonce, timelock);
        }
    }

    /// @notice Execute buy-now option
    /// @param auctionId The auction ID
    function buyNow(uint256 auctionId)
        external
        nonReentrant
        onlyValidAuction(auctionId)
        whenNotPausedAuction
    {
        Auction storage auction = auctions[auctionId];
        if (block.timestamp >= auction.endTime) revert ErrAuctionEnded(auctionId);
        if (auction.buyNowPrice == 0) revert InvalidBuyNowPrice(0, auction.reservePrice);

        // Transfer payment
        uint256 balanceBefore = IERC20(auction.paymentToken).balanceOf(address(this));
        IERC20(auction.paymentToken).safeTransferFrom(msg.sender, address(this), auction.buyNowPrice);
        if (IERC20(auction.paymentToken).balanceOf(address(this)) < balanceBefore + auction.buyNowPrice) {
            revert TransferFailed(auction.paymentToken, address(this), auction.buyNowPrice);
        }

        // Refund previous bidder
        if (auction.highestBidder != address(0)) {
            if (isCrossChainAuction[auctionId]) {
                _bridgeTokens(auction.paymentToken, auction.highestBid, auction.highestBidder, auction.sourceChainId);
            } else {
                IERC20(auction.paymentToken).safeTransfer(auction.highestBidder, auction.highestBid);
            }
        }

        // Finalize auction
        _finalizeAuction(auctionId, msg.sender, auction.buyNowPrice);

        emit BuyNowExecuted(auctionId, auction.tokenId, msg.sender, auction.buyNowPrice);
    }

    /// @notice End an auction
    /// @param auctionId The auction ID
    function endAuction(uint256 auctionId) external nonReentrant onlyValidAuction(auctionId) whenNotPausedAuction {
        Auction storage auction = auctions[auctionId];
        if (block.timestamp < auction.endTime) revert AuctionNotActive(auctionId);

        if (auction.highestBid < auction.reservePrice && auction.highestBidder != address(0)) {
            // Reserve price not met: refund bidder and return NFT to seller
            if (isCrossChainAuction[auctionId]) {
                _bridgeTokens(auction.paymentToken, auction.highestBid, auction.highestBidder, auction.sourceChainId);
            } else {
                IERC20(auction.paymentToken).safeTransfer(auction.highestBidder, auction.highestBid);
            }
            IPositionManager(positionManager).safeTransferFrom(address(this), auction.seller, auction.tokenId);
        } else if (auction.highestBidder == address(0)) {
            // No bids: return NFT to seller
            IPositionManager(positionManager).safeTransferFrom(address(this), auction.seller, auction.tokenId);
        } else {
            // Finalize with highest bidder
            _finalizeAuction(auctionId, auction.highestBidder, auction.highestBid);
        }

        emit AuctionEnded(auctionId, auction.tokenId, auction.highestBidder, auction.highestBid);
    }

    /// @notice End multiple auctions in a batch
    /// @param auctionIds Array of auction IDs
    function batchEndAuctions(uint256[] calldata auctionIds)
        external
        nonReentrant
        whenNotPausedAuction
    {
        uint256 length = auctionIds.length;
        if (length == 0 || length > MAX_BATCH_SIZE) revert InvalidBatchSize(length);

        uint256[] memory tokenIds = new uint256[](length);
        address[] memory winners = new address[](length);
        bool[] memory successes = new bool[](length);

        for (uint256 i = 0; i < length; ++i) {
            try this.endAuction(auctionIds[i]) {
                Auction storage auction = auctions[auctionIds[i]];
                tokenIds[i] = auction.tokenId;
                winners[i] = auction.highestBidder;
                successes[i] = true;
            } catch {
                successes[i] = false;
                emit AuctionEnded(auctionIds[i], auctions[auctionIds[i]].tokenId, address(0), 0);
            }
        }

        emit BatchAuctionsEnded(auctionIds, tokenIds, winners);
    }

    /// @notice Cancel an auction (only by seller, before bids)
    /// @param auctionId The auction ID
    function cancelAuction(uint256 auctionId) external nonReentrant onlyValidAuction(auctionId) whenNotPausedAuction {
        Auction storage auction = auctions[auctionId];
        if (auction.seller != msg.sender) revert NotTokenOwner(auction.tokenId);
        if (auction.highestBidder != address(0)) revert AuctionNotActive(auctionId);

        auction.ended = true;
        IPositionManager(positionManager).safeTransferFrom(address(this), auction.seller, auction.tokenId);

        emit AuctionCancelled(auctionId, auction.tokenId);
    }

    /// @notice Receive cross-chain auction creation
    /// @param srcChainId Source chain ID
    /// @param srcAddress Source address
    /// @param payload Encoded auction data
    function receiveCrossChainAuction(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload
    ) external nonReentrant whenNotPausedAuction {
        _validateCrossChainMessage(srcChainId, srcAddress);

        (
            uint256 auctionId,
            uint256 tokenId,
            address seller,
            address paymentToken,
            uint256 startPrice,
            uint256 reservePrice,
            uint256 buyNowPrice,
            uint256 duration,
            uint64 nonce,
            uint256 timelock
        ) = abi.decode(payload, (uint256, uint256, address, address, uint256, uint256, uint256, uint256, uint64, uint256));

        _validateAuctionParams(tokenId, paymentToken, duration, reservePrice, startPrice, buyNowPrice, srcChainId, "");

        bytes32 messageHash = keccak256(abi.encode(srcChainId, srcAddress, payload));
        if (validatedMessages[messageHash] != 0) revert MessageAlreadyProcessed(messageHash);
        if (block.timestamp >= validatedMessages[messageHash] + MESSAGE_EXPIRATION) revert MessageExpired(messageHash);
        validatedMessages[messageHash] = block.timestamp;

        auctions[auctionId] = Auction({
            tokenId: tokenId,
            seller: seller,
            paymentToken: paymentToken,
            startPrice: startPrice,
            reservePrice: reservePrice,
            buyNowPrice: buyNowPrice,
            highestBid: 0,
            highestBidder: address(0),
            endTime: block.timestamp + duration,
            ended: false,
            sourceChainId: srcChainId
        });
        isCrossChainAuction[auctionId] = true;

        emit AuctionCreated(
            auctionId,
            tokenId,
            seller,
            paymentToken,
            startPrice,
            reservePrice,
            buyNowPrice,
            block.timestamp + duration,
            srcChainId
        );
    }

    /// @notice Receive cross-chain bid
    /// @param srcChainId Source chain ID
    /// @param srcAddress Source address
    /// @param payload Encoded bid data
    function receiveCrossChainBid(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload
    ) external nonReentrant whenNotPausedAuction {
        _validateCrossChainMessage(srcChainId, srcAddress);

        (uint256 auctionId, uint256 tokenId, address bidder, uint256 bidAmount, uint64 nonce, uint256 timelock) = 
            abi.decode(payload, (uint256, uint256, address, uint256, uint64, uint256));

        Auction storage auction = auctions[auctionId];
        if (auction.tokenId != tokenId || auction.ended) revert AuctionNotActive(auctionId);
        if (block.timestamp >= auction.endTime) revert ErrAuctionEnded(auctionId);
        if (block.timestamp < timelock) revert InvalidTimelock(timelock);

        bytes32 messageHash = keccak256(abi.encode(srcChainId, srcAddress, payload));
        if (validatedMessages[messageHash] != 0) revert MessageAlreadyProcessed(messageHash);
        if (block.timestamp >= validatedMessages[messageHash] + MESSAGE_EXPIRATION) revert MessageExpired(messageHash);
        validatedMessages[messageHash] = block.timestamp;

        _validateBid(auction, bidAmount);

        // Refund previous bidder
        if (auction.highestBidder != address(0)) {
            _bridgeTokens(auction.paymentToken, auction.highestBid, auction.highestBidder, srcChainId);
        }

        // Update bid
        auction.highestBid = bidAmount;
        auction.highestBidder = bidder;

        emit CrossChainBidReceived(auctionId, tokenId, bidder, bidAmount, srcChainId, nonce, timelock);
    }

    /// @notice Receive bridged funds for an auction
    /// @param srcChainId Source chain ID
    /// @param token ERC20 token address
    /// @param amount Amount of tokens
    /// @param recipient Recipient address
    function receiveCrossChainFunds(
        uint16 srcChainId,
        address token,
        uint256 amount,
        address recipient
    ) external nonReentrant whenNotPausedAuction {
        if (msg.sender != tokenBridge) revert Unauthorized();
        if (!allowedPaymentTokens[token]) revert InvalidPaymentToken(token);
        if (amount == 0) revert InsufficientBalance(amount, 1);

        ITokenBridge(tokenBridge).mint(token, amount, recipient);
        emit CrossChainFundsReceived(0, token, amount, recipient, srcChainId);
    }

    /// @notice Retry failed cross-chain message
    /// @param messageId The failed message ID
    function retryFailedMessage(uint256 messageId) external payable nonReentrant whenNotPausedAuction {
        FailedMessage storage message = failedMessages[messageId];
        if (message.retries >= MAX_CROSS_CHAIN_RETRIES) revert MaxRetriesExceeded(messageId);
        if (message.timestamp == 0) revert MessageNotFailed(messageId);
        if (block.timestamp < message.nextRetryTimestamp) revert RetryNotReady(messageId, message.nextRetryTimestamp);

        // Consult oracle for retry recommendation
        ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(message.dstChainId);
        if (!status.bridgeOperational) revert BridgeNotOperational(message.dstChainId);
        if (!status.retryRecommended) revert RetryNotRecommended(message.dstChainId);

        message.retries++;
        message.nextRetryTimestamp = block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay);

        (uint256 nativeFee, ) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            message.dstChainId,
            message.dstAxelarChain,
            address(this),
            trustedRemoteManagers[message.dstChainId],
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
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries, message.messengerType);
        } catch {
            emit FailedMessageStored(messageId, message.dstChainId, message.payload, message.messengerType, message.nextRetryTimestamp);
        }

        if (success) {
            delete failedMessages[messageId];
            if (failedMessageCount > 0) failedMessageCount--;
        }
    }

    /// @notice Request a network status update from the oracle
    /// @param chainId Chain ID to query
    /// @param fee Fee for the oracle request
    /// @return requestId The oracle request ID
    function requestOracleNetworkStatusUpdate(uint16 chainId, uint256 fee) external onlyGovernance returns (bytes32 requestId) {
        uint256 linkBalance = IERC20(linkToken).balanceOf(address(this));
        if (linkBalance < fee) revert InsufficientLinkBalance(linkBalance, fee);

        try ICrossChainRetryOracle(retryOracle).requestNetworkStatusUpdate(chainId, oracleJobId, fee) returns (bytes32 _requestId) {
            requestId = _requestId;
        } catch {
            revert OracleRequestFailed(bytes32(0));
        }
    }

    /// @notice Emergency withdrawal of tokens or NFTs
    /// @param token Address of the token (or 0 for NFTs)
    /// @param amount Amount to withdraw (or tokenId for NFTs)
    /// @param to Recipient address
    function emergencyWithdraw(address token, uint256 amount, address to) external onlyGovernance whenNotPaused {
        if (to == address(0)) revert InvalidGovernanceAddress(to);
        if (token == address(0)) {
            // Withdraw NFT
            IPositionManager(positionManager).safeTransferFrom(address(this), to, amount);
        } else {
            // Withdraw ERC20
            IERC20(token).safeTransfer(to, amount);
        }
        emit EmergencyWithdrawal(token, amount, to);
    }

    /// @notice Update governance contract
    /// @param newGovernance New governance address
    function updateGovernance(address newGovernance) external onlyGovernance whenNotPaused {
        if (newGovernance == address(0)) revert InvalidGovernanceAddress(newGovernance);
        governance = newGovernance;
        emit GovernanceUpdated(newGovernance);
    }

    /// @notice Update protocol treasury
    /// @param newTreasury New treasury address
    function updateProtocolTreasury(address newTreasury) external onlyGovernance whenNotPaused {
        if (newTreasury == address(0)) revert InvalidTreasuryAddress(newTreasury);
        protocolTreasury = newTreasury;
        emit ProtocolTreasuryUpdated(newTreasury);
    }

    /// @notice Update auction fee percentage
    /// @param newFeePercent New fee percentage (in basis points)
    function updateAuctionFee(uint256 newFeePercent) external onlyGovernance whenNotPaused {
        if (newFeePercent > FEE_DENOMINATOR) revert InvalidFeePercent(newFeePercent);
        auctionFeePercent = newFeePercent;
        emit AuctionFeeUpdated(newFeePercent);
    }

    /// @notice Update payment token allowance
    /// @param paymentToken ERC20 token address
    /// @param allowed Whether the token is allowed
    function updatePaymentToken(address paymentToken, bool allowed) external onlyGovernance whenNotPaused {
        if (paymentToken == address(0)) revert InvalidPaymentToken(paymentToken);
        if (allowed && !_isValidERC20(paymentToken)) revert InvalidPaymentToken(paymentToken);
        allowedPaymentTokens[paymentToken] = allowed;
        emit PaymentTokenUpdated(paymentToken, allowed);
    }

    /// @notice Update cross-chain messenger
    /// @param newMessenger New messenger contract address
    /// @param newMessengerType New messenger type (0 = LayerZero, 1 = Axelar, 2 = Wormhole)
    function updateCrossChainMessenger(address newMessenger, uint8 newMessengerType)
        external
        onlyGovernance
        whenNotPaused
    {
        if (newMessenger == address(0)) revert InvalidPaymentToken(newMessenger);
        if (newMessengerType > 2) revert InvalidMessengerType(newMessengerType);
        crossChainMessenger = newMessenger;
        messengerType = newMessengerType;
        emit CrossChainMessengerUpdated(newMessenger, newMessengerType);
    }

    /// @notice Update token bridge
    /// @param newTokenBridge New token bridge contract address
    function updateTokenBridge(address newTokenBridge) external onlyGovernance whenNotPaused {
        if (newTokenBridge == address(0)) revert InvalidTokenBridge();
        tokenBridge = newTokenBridge;
        emit TokenBridgeUpdated(newTokenBridge);
    }

    /// @notice Update retry oracle
    /// @param newRetryOracle New oracle contract address
    /// @param newOracleJobId New Chainlink job ID
    /// @param newLinkToken New LINK token address
    function updateRetryOracle(address newRetryOracle, bytes32 newOracleJobId, address newLinkToken)
        external
        onlyGovernance
        whenNotPaused
    {
        if (newRetryOracle == address(0)) revert InvalidRetryOracle();
        if (newOracleJobId == bytes32(0)) revert InvalidOracleJobId();
        if (newLinkToken == address(0)) revert InvalidLinkToken();
        retryOracle = newRetryOracle;
        oracleJobId = newOracleJobId;
        linkToken = newLinkToken;
        emit RetryOracleUpdated(newRetryOracle, newOracleJobId, newLinkToken);
    }

    /// @notice Update trusted remote manager
    /// @param chainId Chain ID
    /// @param managerAddress Trusted manager address
    function updateTrustedRemoteManager(uint16 chainId, bytes calldata managerAddress)
        external
        onlyGovernance
        whenNotPaused
    {
        if (chainId == 0) revert InvalidChainId(chainId);
        if (managerAddress.length == 0) revert InvalidManagerAddress();
        trustedRemoteManagers[chainId] = managerAddress;
        emit TrustedRemoteManagerUpdated(chainId, managerAddress);
    }

    /// @notice Update chain ID mapping
    /// @param chainId Chain ID
    /// @param axelarChain Axelar chain ID
    function updateChainId(uint16 chainId, string memory axelarChain) external onlyGovernance whenNotPaused {
        if (chainId == 0) revert InvalidChainId(chainId);
        chainIdToAxelarChain[chainId] = axelarChain;
    }

    /// @notice Update chain timelock
    /// @param chainId Chain ID
    /// @param timelock Timelock duration
    function updateChainTimelock(uint16 chainId, uint256 timelock) external onlyGovernance whenNotPaused {
        if (chainId == 0) revert InvalidChainId(chainId);
        if (timelock < MIN_TIMELOCK || timelock > MAX_TIMELOCK) revert InvalidTimelock(timelock);
        chainTimelocks[chainId] = timelock;
        emit ChainTimelockUpdated(chainId, timelock);
    }

    /// @notice Pause the contract
    function pause() external onlyGovernance {
        _pause();
        emit ContractPaused(msg.sender);
    }

    /// @notice Unpause the contract
    function unpause() external onlyGovernance {
        _unpause();
        emit ContractUnpaused(msg.sender);
    }

    /// @notice Get auction details
    /// @param auctionId The auction ID
    /// @return Auction struct
    function getAuction(uint256 auctionId) external view returns (Auction memory) {
        return auctions[auctionId];
    }

    /// @notice Handle receiving NFTs
    /// @param operator The address which called the transfer function
    /// @param from The address which previously owned the token
    /// @param tokenId The NFT identifier
    /// @param data Additional data
    /// @return Selector to confirm ERC721 receipt
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure override returns (bytes4) {
        return IERC721ReceiverUpgradeable.onERC721Received.selector;
    }

    // --- Internal Functions ---

    /// @notice Send cross-chain auction creation message
    /// @param auctionId The auction ID
    /// @param tokenId NFT token ID
    /// @param paymentToken ERC20 token for bidding
    /// @param startPrice Starting bid price
    /// @param reservePrice Minimum acceptable bid
    /// @param buyNowPrice Price for instant purchase
    /// @param duration Auction duration
    /// @param dstChainId Destination chain ID
    /// @param adapterParams Cross-chain adapter parameters
    /// @param timelock Timelock duration
    function _sendCrossChainAuction(
        uint256 auctionId,
        uint256 tokenId,
        address paymentToken,
        uint256 startPrice,
        uint256 reservePrice,
        uint256 buyNowPrice,
        uint256 duration,
        uint16 dstChainId,
        bytes calldata adapterParams,
        uint256 timelock
    ) internal {
        if (trustedRemoteManagers[dstChainId].length == 0) revert InvalidChainId(dstChainId);
        _validateAdapterParams(adapterParams);

        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        bytes memory destinationAddress = trustedRemoteManagers[dstChainId];
        uint64 nonce = _getNonce(dstChainId);
        bytes memory payload = abi.encode(
            auctionId,
            tokenId,
            msg.sender,
            paymentToken,
            startPrice,
            reservePrice,
            buyNowPrice,
            duration,
            nonce,
            timelock
        );

        (uint256 nativeFee, ) = ICrossChainMessenger(crossChainMessenger).estimateFees(
            dstChainId,
            dstAxelarChain,
            address(this),
            destinationAddress,
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
            isCrossChainAuction[auctionId] = true;
        } catch {
            uint256 messageId = failedMessageCount++;
            ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(dstChainId);
            failedMessages[messageId] = FailedMessage({
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                timestamp: block.timestamp,
                nextRetryTimestamp: block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay),
                messengerType: messengerType
            });
            emit FailedMessageStored(messageId, dstChainId, payload, messengerType, failedMessages[messageId].nextRetryTimestamp);
        }

        if (success) {
            emit CrossChainAuctionCreated(auctionId, tokenId, msg.sender, dstChainId, nonce, timelock);
        }
    }

    /// @notice Finalize an auction
    /// @param auctionId The auction ID
    /// @param winner The winner's address
    /// @param finalPrice The final price
    function _finalizeAuction(uint256 auctionId, address winner, uint256 finalPrice) internal {
        Auction storage auction = auctions[auctionId];
        auction.ended = true;

        // Calculate fees and payouts
        uint256 feeAmount = (finalPrice * auctionFeePercent) / FEE_DENOMINATOR;
        uint256 sellerPayout = finalPrice - feeAmount;

        // Transfer NFT to winner
        IPositionManager(positionManager).safeTransferFrom(address(this), winner, auction.tokenId);

        // Handle fund settlement
        if (isCrossChainAuction[auctionId]) {
            if (sellerPayout > 0) {
                _bridgeTokens(auction.paymentToken, sellerPayout, auction.seller, auction.sourceChainId);
            }
            if (feeAmount > 0) {
                _bridgeTokens(auction.paymentToken, feeAmount, protocolTreasury, auction.sourceChainId);
            }
        } else {
            if (sellerPayout > 0) {
                IERC20(auction.paymentToken).safeTransfer(auction.seller, sellerPayout);
            }
            if (feeAmount > 0) {
                IERC20(auction.paymentToken).safeTransfer(protocolTreasury, feeAmount);
            }
        }
    }

    /// @notice Bridge tokens to another chain
    /// @param token ERC20 token address
    /// @param amount Amount to bridge
    /// @param recipient Recipient address
    /// @param dstChainId Destination chain ID
    function _bridgeTokens(address token, uint256 amount, address recipient, uint16 dstChainId) internal {
        if (amount == 0) return;
        IERC20(token).safeApprove(tokenBridge, amount);
        ITokenBridge(tokenBridge).burn(token, amount, recipient, dstChainId);
        IERC20(token).safeApprove(tokenBridge, 0); // Reset approval
    }

    /// @notice Check if ERC20 token is valid and has sufficient liquidity
    /// @param token ERC20 token address
    /// @return True if valid and liquid
    function _isValidERC20(address token) internal view returns (bool) {
        try IERC20(token).balanceOf(address(this)) returns (uint256 balance) {
            if (balance < MIN_LIQUIDITY_THRESHOLD) return false;
        } catch {
            return false;
        }
        try IERC20(token).totalSupply() returns (uint256) {
            return true;
        } catch {
            return false;
        }
    }

    /// @notice Get nonce for cross-chain messaging
    /// @param dstChainId Destination chain ID
    /// @return nonce The current nonce
    function _getNonce(uint16 dstChainId) internal returns (uint64) {
        if (messengerType == 0) {
            return uint64(nonces[dstChainId]);
        } else if (messengerType == 1 || messengerType == 2) {
            return nonces[dstChainId];
        }
        revert InvalidMessengerType(messengerType);
    }

    /// @notice Get current chain ID
    /// @return chainId The current chain ID
    function _getCurrentChainId() internal view returns (uint16) {
        return uint16(block.chainid);
    }

    /// @notice Get dynamic timelock for a chain
    /// @param chainId Chain ID
    /// @return timelock The timelock duration
    function _getDynamicTimelock(uint16 chainId) internal view returns (uint256 timelock) {
        timelock = chainTimelocks[chainId];
        if (timelock < MIN_TIMELOCK || timelock > MAX_TIMELOCK) {
            timelock = MIN_TIMELOCK;
        }
        try ICrossChainRetryOracle(retryOracle).getNetworkStatus(chainId) returns (ICrossChainRetryOracle.NetworkStatus memory status) {
            if (status.congestionLevel >= 8) {
                timelock += timelock / 4; // Increase by 25% for high congestion
                if (timelock > MAX_TIMELOCK) timelock = MAX_TIMELOCK;
            }
        } catch {
            emit OracleFallback(chainId, "Failed to fetch network status");
        }
    }

    /// @notice Retrieve network status from oracle
    /// @param chainId Chain ID
    /// @return status The network status
    function _getOracleNetworkStatus(uint16 chainId) internal view returns (ICrossChainRetryOracle.NetworkStatus memory status) {
        try ICrossChainRetryOracle(retryOracle).getNetworkStatus(chainId) returns (ICrossChainRetryOracle.NetworkStatus memory _status) {
            status = _status;
        } catch {
            emit OracleFallback(chainId, "Invalid retry oracle");
            revert InvalidRetryOracle();
        }
    }

    /// @notice Validate auction parameters
    /// @param tokenId NFT token ID
    /// @param paymentToken ERC20 token for bidding
    /// @param duration Auction duration
    /// @param reservePrice Minimum acceptable bid
    /// @param startPrice Starting bid price
    /// @param buyNowPrice Price for instant purchase
    /// @param chainId Chain ID
    /// @param adapterParams Cross-chain adapter parameters
    function _validateAuctionParams(
        uint256 tokenId,
        address paymentToken,
        uint256 duration,
        uint256 reservePrice,
        uint256 startPrice,
        uint256 buyNowPrice,
        uint16 chainId,
        bytes memory adapterParams
    ) internal view {
        if (!allowedPaymentTokens[paymentToken]) revert InvalidPaymentToken(paymentToken);
        if (!_isValidERC20(paymentToken)) revert InvalidPaymentToken(paymentToken);
        if (IPositionManager(positionManager).ownerOf(tokenId) != msg.sender && chainId == 0) revert NotTokenOwner(tokenId);
        if (auctions[tokenId].tokenId != 0) revert AuctionAlreadyExists(tokenId);
        if (duration < MIN_AUCTION_DURATION || duration > MAX_AUCTION_DURATION) revert InvalidAuctionDuration(duration);
        if (reservePrice < startPrice) revert ReservePriceNotMet(reservePrice, startPrice);
        if (buyNowPrice > 0 && buyNowPrice < reservePrice) revert InvalidBuyNowPrice(buyNowPrice, reservePrice);
        if (chainId != 0 && trustedRemoteManagers[chainId].length == 0) revert InvalidChainId(chainId);
        if (chainId != 0 && bytes(adapterParams).length > 0) _validateAdapterParams(adapterParams);
    }

    /// @notice Validate cross-chain message
    /// @param srcChainId Source chain ID
    /// @param srcAddress Source address
    function _validateCrossChainMessage(uint16 srcChainId, bytes calldata srcAddress) internal view {
        if (keccak256(srcAddress) != keccak256(trustedRemoteManagers[srcChainId])) revert Unauthorized();
        if (msg.sender != crossChainMessenger) revert Unauthorized();
    }

    /// @notice Validate bid parameters
    /// @param auction The auction struct
    /// @param bidAmount The bid amount
    function _validateBid(Auction storage auction, uint256 bidAmount) internal view {
        uint256 minimumBid = auction.highestBid == 0
            ? auction.startPrice
            : auction.highestBid + MIN_BID_INCREMENT;
        if (bidAmount < minimumBid) revert BidTooLow(bidAmount, minimumBid);
        if (bidAmount < auction.reservePrice) revert ReservePriceNotMet(bidAmount, auction.reservePrice);
    }

    /// @notice Validate adapter parameters
    /// @param adapterParams Cross-chain adapter parameters
    function _validateAdapterParams(bytes memory adapterParams) internal pure {
        if (adapterParams.length > 0) {
            // Basic validation (e.g., non-empty and reasonable length)
            if (adapterParams.length > 1024) revert InvalidAdapterParams();
        }
    }

    /// @notice Validate initialization parameters
    /// @param _positionManager PositionManager address
    /// @param _protocolTreasury Treasury address
    /// @param _governance Governance address
    /// @param _crossChainMessenger Messenger address
    /// @param _tokenBridge Token bridge address
    /// @param _retryOracle Retry oracle address
    /// @param _oracleJobId Oracle job ID
    /// @param _linkToken LINK token address
    /// @param _messengerType Messenger type
    /// @param _auctionFeePercent Fee percentage
    function _validateInitializeParams(
        address _positionManager,
        address _protocolTreasury,
        address _governance,
        address _crossChainMessenger,
        address _tokenBridge,
        address _retryOracle,
        bytes32 _oracleJobId,
        address _linkToken,
        uint8 _messengerType,
        uint256 _auctionFeePercent
    ) internal pure {
        if (_positionManager == address(0)) revert InvalidPositionManager();
        if (_protocolTreasury == address(0)) revert InvalidTreasuryAddress(_protocolTreasury);
        if (_governance == address(0)) revert InvalidGovernanceAddress(_governance);
        if (_crossChainMessenger == address(0)) revert InvalidPaymentToken(_crossChainMessenger);
        if (_tokenBridge == address(0)) revert InvalidTokenBridge();
        if (_retryOracle == address(0)) revert InvalidRetryOracle();
        if (_oracleJobId == bytes32(0)) revert InvalidOracleJobId();
        if (_linkToken == address(0)) revert InvalidLinkToken();
        if (_messengerType > 2) revert InvalidMessengerType(_messengerType);
        if (_auctionFeePercent > FEE_DENOMINATOR) revert InvalidFeePercent(_auctionFeePercent);
    }
}
