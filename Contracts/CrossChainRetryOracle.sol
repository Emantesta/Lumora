// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CCIPReceiver} from "@chainlink/contracts-ccip/src/v0.8/ccip/applications/CCIPReceiver.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import {VRFConsumerBaseV2} from "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol";
import {VRFCoordinatorV2Interface} from "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import {AutomationCompatibleInterface} from "@chainlink/contracts/src/v0.8/interfaces/AutomationCompatibleInterface.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title CrossChainRetryOracle - A secure, upgradeable oracle with Chainlink integrations
/// @notice Manages cross-chain network status using CCIP, Chainlink Nodes, Price Feeds, VRF, and Automation.
/// @dev Integrates with AMMPool.sol for retry decisions, supports Sonic Blockchain via CCIP.
contract CrossChainRetryOracle is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    CCIPReceiver,
    ChainlinkClient,
    VRFConsumerBaseV2,
    AutomationCompatibleInterface
{
    using Chainlink for Chainlink.Request;
    using Strings for uint256;

    /// @notice Network status for a destination chain
    struct NetworkStatus {
        uint64 gasPrice; // Gas price in Wei
        uint32 confirmationTime; // Average confirmation time in seconds
        uint8 congestionLevel; // Congestion level (0-10)
        bool bridgeOperational; // Bridge operational status
        uint32 recommendedRetryDelay; // Recommended retry delay in seconds
        bool retryRecommended; // Whether retry is recommended
        uint64 lastUpdated; // Timestamp of last update
        uint64 randomRetryDelay; // Randomized retry delay from VRF
        int256 lastGasPrice; // Last fetched gas price (normalized)
        int256 lastTokenPrice; // Last fetched token price (normalized)
    }

    /// @notice Chain configuration for status updates, price feeds, and automation
    struct ChainConfig {
        address gasPriceFeed; // Chainlink gas price feed
        uint8 gasPriceFeedDecimals; // Decimals for gas price feed
        address tokenPriceFeed; // Chainlink token price feed
        uint8 tokenPriceFeedDecimals; // Decimals for token price feed
        bytes trustedSender; // Trusted CCIP sender address
        bool active; // Whether chain is supported
        bool automateStatus; // Enable automated status updates
        bool automateRandomDelay; // Enable automated random delay updates
        bool automatePriceFeeds; // Enable automated price feed updates
        uint256 statusUpdateInterval; // Interval for status updates (seconds)
        uint256 randomDelayUpdateInterval; // Interval for random delay updates (seconds)
        uint256 priceFeedUpdateInterval; // Interval for price feed updates (seconds)
        uint256 automationFee; // LINK fee for automated status/price requests
    }

    /// @notice Price feed data
    struct PriceData {
        int256 price; // Normalized price
        uint256 updatedAt; // Timestamp of last update
        bool valid; // Whether the price is valid
    }

    /// @notice Chainlink request metadata
    struct RequestMetadata {
        uint16 chainId;
        uint64 requestTime;
        bool isPriceFeedRequest; // True for price feed, false for status
    }

    // Storage
    mapping(uint16 => NetworkStatus) public networkStatuses;
    mapping(uint16 => ChainConfig) public chainConfigs;
    mapping(bytes32 => RequestMetadata) private requestMetadata; // Chainlink Node requests
    mapping(uint256 => uint16) private vrfRequestIdToChainId; // VRF requests
    mapping(uint16 => uint256) public chainHeartbeats; // Max staleness per chain
    uint16[] public activeChainIds; // List of active chain IDs
    address public chainlinkToken; // LINK token address
    address public chainlinkOracle; // Chainlink Node oracle address
    uint256 public maxRetryDelay; // Maximum retry delay (seconds)
    uint256 public minGasPrice; // Minimum gas price (Wei)
    uint256 public maxGasPrice; // Maximum gas price (Wei)
    bool public useFallbackPriceFeeds; // Enable fallback to price feeds
    uint256 public minHeartbeat; // Minimum heartbeat for dynamic adjustment
    uint256 public maxHeartbeat; // Maximum heartbeat for dynamic adjustment
    uint8 public maxFallbackRetries; // Maximum retries for price feeds
    uint64 public vrfSubscriptionId; // VRF subscription ID
    bytes32 public vrfKeyHash; // VRF key hash for gas lane
    uint32 public vrfCallbackGasLimit; // Gas limit for VRF callback
    uint16 public vrfRequestConfirmations; // Minimum block confirmations for VRF
    uint32 public minRandomRetryDelay; // Minimum random retry delay (seconds)
    uint32 public maxRandomRetryDelay; // Maximum random retry delay (seconds)
    int256 public defaultGasPrice; // Default gas price if feed fails
    int256 public defaultTokenPrice; // Default token price if feed fails
    address public automationRegistrar; // Chainlink Automation registrar address
    uint256 public automationUpkeepId; // Chainlink Automation upkeep ID
    bytes32 public automationStatusJobId; // Job ID for automated status requests
    bytes32 public automationPriceFeedJobId; // Job ID for automated price feed requests
    uint256 public requestTimeout; // Timeout for Chainlink Node requests (seconds)

    // Constants
    uint8 private constant MAX_CONGESTION_LEVEL = 10;
    uint32 private constant MIN_CONFIRMATION_TIME = 1;
    uint32 private constant MAX_CONFIRMATION_TIME = 3600; // 1 hour
    uint256 private constant DEFAULT_HEARTBEAT = 1 hours;
    uint256 private constant DEFAULT_MIN_HEARTBEAT = 30 minutes;
    uint256 private constant DEFAULT_MAX_HEARTBEAT = 1 days;
    uint256 private constant DEFAULT_MAX_RETRY_DELAY = 1 days;
    uint256 private constant DEFAULT_MIN_GAS_PRICE = 1e9; // 1 Gwei
    uint256 private constant DEFAULT_MAX_GAS_PRICE = 1e12; // 1000 Gwei
    uint8 private constant DEFAULT_MAX_FALLBACK_RETRIES = 3;
    uint32 private constant DEFAULT_VRF_CALLBACK_GAS_LIMIT = 100_000;
    uint16 private constant DEFAULT_VRF_REQUEST_CONFIRMATIONS = 3;
    uint32 private constant DEFAULT_MIN_RANDOM_RETRY_DELAY = 60; // 1 minute
    uint32 private constant DEFAULT_MAX_RANDOM_RETRY_DELAY = 3600; // 1 hour
    int256 private constant DEFAULT_GAS_PRICE = 10e9; // 10 Gwei
    int256 private constant DEFAULT_TOKEN_PRICE = 2000e8; // $2000 per ETH (8 decimals)
    uint256 private constant DEFAULT_AUTOMATION_FEE = 0.1 ether; // 0.1 LINK
    uint256 private constant MIN_UPDATE_INTERVAL = 300; // 5 minutes
    uint256 private constant DEFAULT_REQUEST_TIMEOUT = 1 hours;
    uint8 private constant NORMALIZED_DECIMALS = 18; // Normalize prices to 18 decimals

    // Custom errors
    error InvalidChainId(uint16 chainId);
    error InvalidSender(bytes sender);
    error InvalidGasPrice(uint64 gasPrice);
    error InvalidConfirmationTime(uint32 confirmationTime);
    error InvalidCongestionLevel(uint8 congestionLevel);
    error StaleData(uint16 chainId, uint64 lastUpdated);
    error ChainNotConfigured(uint16 chainId);
    error InvalidRequestId(bytes32 requestId);
    error InsufficientLink(uint256 balance, uint256 required);
    error InvalidHeartbeat(uint256 heartbeat);
    error InvalidConfig(address gasPriceFeed, address tokenPriceFeed, bytes trustedSender);
    error InvalidHeartbeatBounds(uint256 minHeartbeat, uint256 maxHeartbeat);
    error PriceFeedFailed(uint16 chainId, bool isGasPrice);
    error InvalidVrfConfig(address coordinator, uint64 subscriptionId);
    error InvalidRandomRetryDelayBounds(uint32 minDelay, uint32 maxDelay);
    error InvalidVrfRequestId(uint256 requestId);
    error InvalidPriceFeed(address priceFeed);
    error InvalidAutomationConfig(address registrar, bytes32 statusJobId, bytes32 priceFeedJobId);
    error InvalidUpdateInterval(uint256 interval);
    error AutomationNotRegistered();
    error RequestTimedOut(bytes32 requestId);
    error InvalidPriceFeedDecimals(uint8 decimals);
    error ChainAlreadyConfigured(uint16 chainId);
    error ChainNotFound(uint16 chainId);

    // Events
    event NetworkStatusUpdated(uint16 indexed chainId, NetworkStatus status);
    event StatusRequested(uint16 indexed chainId, bytes32 indexed requestId);
    event StatusRequestFulfilled(uint16 indexed chainId, bytes32 indexed requestId);
    event PriceFeedRequested(uint16 indexed chainId, bytes32 indexed requestId);
    event PriceFeedRequestFulfilled(uint16 indexed chainId, bytes32 indexed requestId, int256 gasPrice, int256 tokenPrice);
    event ChainConfigUpdated(
        uint16 indexed chainId,
        address gasPriceFeed,
        uint8 gasPriceFeedDecimals,
        address tokenPriceFeed,
        uint8 tokenPriceFeedDecimals,
        bytes trustedSender,
        bool active,
        bool automateStatus,
        bool automateRandomDelay,
        bool automatePriceFeeds,
        uint256 statusUpdateInterval,
        uint256 randomDelayUpdateInterval,
        uint256 priceFeedUpdateInterval,
        uint256 automationFee
    );
    event HeartbeatUpdated(uint16 indexed chainId, uint256 heartbeat);
    event ChainlinkConfigUpdated(address chainlinkToken, address chainlinkOracle);
    event FallbackPriceFeedsToggled(bool enabled);
    event MaxRetryDelayUpdated(uint256 maxRetryDelay);
    event GasPriceBoundsUpdated(uint256 minGasPrice, uint256 maxGasPrice);
    event HeartbeatBoundsUpdated(uint256 minHeartbeat, uint256 maxHeartbeat);
    event MaxFallbackRetriesUpdated(uint8 maxRetries);
    event BatchNetworkStatusUpdated(uint16[] chainIds);
    event VrfConfigUpdated(address coordinator, uint64 subscriptionId, bytes32 keyHash, uint32 callbackGasLimit, uint16 requestConfirmations);
    event RandomRetryDelayRequested(uint16 indexed chainId, uint256 indexed requestId);
    event RandomRetryDelayFulfilled(uint16 indexed chainId, uint256 indexed requestId, uint32 randomDelay);
    event RandomRetryDelayBoundsUpdated(uint32 minDelay, uint32 maxDelay);
    event DefaultPricesUpdated(int256 defaultGasPrice, int256 defaultTokenPrice);
    event AutomationConfigUpdated(address registrar, uint256 upkeepId, bytes32 statusJobId, bytes32 priceFeedJobId);
    event AutomationTasksPerformed(
        uint16[] statusChainIds,
        bytes32[] statusRequestIds,
        uint16[] randomDelayChainIds,
        uint256[] vrfRequestIds,
        uint16[] priceFeedChainIds,
        bytes32[] priceFeedRequestIds
    );
    event RequestCancelled(bytes32 indexed requestId);
    event ActiveChainIdsUpdated(uint16[] chainIds);
    event RequestTimeoutUpdated(uint256 timeout);

    /// @notice Constructor to disable initializers
    constructor(address router, address vrfCoordinator) CCIPReceiver(router) VRFConsumerBaseV2(vrfCoordinator) {
        require(vrfCoordinator != address(0), "Invalid VRF coordinator");
        _disableInitializers();
    }

    /// @notice Initialize the contract
    function initialize(
        address _router,
        address _chainlinkToken,
        address _chainlinkOracle,
        address _vrfCoordinator,
        uint64 _vrfSubscriptionId
    ) external initializer {
        require(_router != address(0), "Invalid router");
        require(_chainlinkToken != address(0), "Invalid LINK token");
        require(_chainlinkOracle != address(0), "Invalid Chainlink oracle");
        require(_vrfCoordinator != address(0), "Invalid VRF coordinator");
        require(_vrfSubscriptionId != 0, "Invalid VRF subscription ID");

        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __CCIPReceiver_init(_router);

        chainlinkToken = _chainlinkToken;
        chainlinkOracle = _chainlinkOracle;
        setChainlinkToken(_chainlinkToken);
        maxRetryDelay = DEFAULT_MAX_RETRY_DELAY;
        minGasPrice = DEFAULT_MIN_GAS_PRICE;
        maxGasPrice = DEFAULT_MAX_GAS_PRICE;
        minHeartbeat = DEFAULT_MIN_HEARTBEAT;
        maxHeartbeat = DEFAULT_MAX_HEARTBEAT;
        maxFallbackRetries = DEFAULT_MAX_FALLBACK_RETRIES;
        vrfSubscriptionId = _vrfSubscriptionId;
        vrfKeyHash = bytes32(0);
        vrfCallbackGasLimit = DEFAULT_VRF_CALLBACK_GAS_LIMIT;
        vrfRequestConfirmations = DEFAULT_VRF_REQUEST_CONFIRMATIONS;
        minRandomRetryDelay = DEFAULT_MIN_RANDOM_RETRY_DELAY;
        maxRandomRetryDelay = DEFAULT_MAX_RANDOM_RETRY_DELAY;
        defaultGasPrice = DEFAULT_GAS_PRICE;
        defaultTokenPrice = DEFAULT_TOKEN_PRICE;
        requestTimeout = DEFAULT_REQUEST_TIMEOUT;

        emit ChainlinkConfigUpdated(_chainlinkToken, _chainlinkOracle);
        emit MaxRetryDelayUpdated(maxRetryDelay);
        emit GasPriceBoundsUpdated(minGasPrice, maxGasPrice);
        emit HeartbeatBoundsUpdated(minHeartbeat, maxHeartbeat);
        emit MaxFallbackRetriesUpdated(maxFallbackRetries);
        emit VrfConfigUpdated(_vrfCoordinator, _vrfSubscriptionId, vrfKeyHash, vrfCallbackGasLimit, vrfRequestConfirmations);
        emit RandomRetryDelayBoundsUpdated(minRandomRetryDelay, maxRandomRetryDelay);
        emit DefaultPricesUpdated(defaultGasPrice, defaultTokenPrice);
        emit AutomationConfigUpdated(automationRegistrar, automationUpkeepId, automationStatusJobId, automationPriceFeedJobId);
        emit RequestTimeoutUpdated(requestTimeout);
    }

    /// @notice Receive network status via CCIP, supporting batch updates
    function _ccipReceive(Client.Any2EVMMessage memory message) internal override nonReentrant whenNotPaused {
        uint16[] memory chainIds;
        NetworkStatus[] memory statuses;

        try this._decodeBatchMessage(message.data) returns (uint16[] memory _chainIds, NetworkStatus[] memory _statuses) {
            chainIds = _chainIds;
            statuses = _statuses;
        } catch {
            uint16 chainId = message.destChainId;
            ChainConfig storage config = chainConfigs[chainId];
            if (!config.active) revert ChainNotConfigured(chainId);
            if (keccak256(message.sender) != keccak256(config.trustedSender)) revert InvalidSender(message.sender);

            (
                uint64 gasPrice,
                uint32 confirmationTime,
                uint8 congestionLevel,
                bool bridgeOperational,
                uint32 recommendedRetryDelay,
                bool retryRecommended
            ) = abi.decode(message.data, (uint64, uint32, uint8, bool, uint32, bool));

            _validateStatus(gasPrice, confirmationTime, congestionLevel, recommendedRetryDelay);

            NetworkStatus memory status = NetworkStatus({
                gasPrice: gasPrice,
                confirmationTime: confirmationTime,
                congestionLevel: congestionLevel,
                bridgeOperational: bridgeOperational,
                recommendedRetryDelay: recommendedRetryDelay,
                retryRecommended: retryRecommended,
                lastUpdated: uint64(block.timestamp),
                randomRetryDelay: networkStatuses[chainId].randomRetryDelay == 0 ? minRandomRetryDelay : networkStatuses[chainId].randomRetryDelay,
                lastGasPrice: networkStatuses[chainId].lastGasPrice,
                lastTokenPrice: networkStatuses[chainId].lastTokenPrice
            });

            networkStatuses[chainId] = status;
            emit NetworkStatusUpdated(chainId, status);
            return;
        }

        for (uint256 i = 0; i < chainIds.length; i++) {
            uint16 chainId = chainIds[i];
            ChainConfig storage config = chainConfigs[chainId];
            if (!config.active) revert ChainNotConfigured(chainId);
            if (keccak256(message.sender) != keccak256(config.trustedSender)) revert InvalidSender(message.sender);

            NetworkStatus memory status = statuses[i];
            _validateStatus(status.gasPrice, status.confirmationTime, status.congestionLevel, status.recommendedRetryDelay);
            status.lastUpdated = uint64(block.timestamp);
            status.randomRetryDelay = networkStatuses[chainId].randomRetryDelay == 0 ? minRandomRetryDelay : networkStatuses[chainId].randomRetryDelay;
            status.lastGasPrice = networkStatuses[chainId].lastGasPrice;
            status.lastTokenPrice = networkStatuses[chainId].lastTokenPrice;
            networkStatuses[chainId] = status;
            emit NetworkStatusUpdated(chainId, status);
        }
        emit BatchNetworkStatusUpdated(chainIds);
    }

    /// @notice Decode batch message for multiple chain updates
    function _decodeBatchMessage(bytes memory data) external pure returns (uint16[] memory chainIds, NetworkStatus[] memory statuses) {
        (chainIds, statuses) = abi.decode(data, (uint16[], NetworkStatus[]));
    }

    /// @notice Request network status update via Chainlink Node
    function requestNetworkStatusUpdate(uint16 chainId, bytes32 jobId, uint256 fee) public nonReentrant whenNotPaused returns (bytes32 requestId) {
        if (!chainConfigs[chainId].active) revert ChainNotConfigured(chainId);
        uint256 linkBalance = IERC20(chainlinkToken).balanceOf(address(this));
        if (linkBalance < fee) revert InsufficientLink(linkBalance, fee);

        Chainlink.Request memory req = buildChainlinkRequest(jobId, address(this), this.fulfillNetworkStatus.selector);
        req.add("chainId", chainId.toString());
        requestId = sendChainlinkRequestTo(chainlinkOracle, req, fee);
        requestMetadata[requestId] = RequestMetadata(chainId, uint64(block.timestamp), false);

        emit StatusRequested(chainId, requestId);
    }

    /// @notice Request price feed update via Chainlink Node
    function requestPriceFeedUpdate(uint16 chainId, uint256 fee) public nonReentrant whenNotPaused returns (bytes32 requestId) {
        if (!chainConfigs[chainId].active) revert ChainNotConfigured(chainId);
        uint256 linkBalance = IERC20(chainlinkToken).balanceOf(address(this));
        if (linkBalance < fee) revert InsufficientLink(linkBalance, fee);

        Chainlink.Request memory req = buildChainlinkRequest(automationPriceFeedJobId, address(this), this.fulfillPriceFeedUpdate.selector);
        req.add("chainId", chainId.toString());
        requestId = sendChainlinkRequestTo(chainlinkOracle, req, fee);
        requestMetadata[requestId] = RequestMetadata(chainId, uint64(block.timestamp), true);

        emit PriceFeedRequested(chainId, requestId);
    }

    /// @notice Fulfill Chainlink request with network status
    function fulfillNetworkStatus(bytes32 requestId, bytes memory data) external nonReentrant whenNotPaused {
        RequestMetadata memory meta = requestMetadata[requestId];
        if (meta.chainId == 0) revert InvalidRequestId(requestId);
        if (!chainConfigs[meta.chainId].active) revert ChainNotConfigured(meta.chainId);
        if (block.timestamp > meta.requestTime + requestTimeout) revert RequestTimedOut(requestId);

        (
            uint64 gasPrice,
            uint32 confirmationTime,
            uint8 congestionLevel,
            bool bridgeOperational,
            uint32 recommendedRetryDelay,
            bool retryRecommended
        ) = abi.decode(data, (uint64, uint32, uint8, bool, uint32, bool));

        _validateStatus(gasPrice, confirmationTime, congestionLevel, recommendedRetryDelay);

        NetworkStatus memory status = NetworkStatus({
            gasPrice: gasPrice,
            confirmationTime: confirmationTime,
            congestionLevel: congestionLevel,
            bridgeOperational: bridgeOperational,
            recommendedRetryDelay: recommendedRetryDelay,
            retryRecommended: retryRecommended,
            lastUpdated: uint64(block.timestamp),
            randomRetryDelay: networkStatuses[meta.chainId].randomRetryDelay,
            lastGasPrice: networkStatuses[meta.chainId].lastGasPrice,
            lastTokenPrice: networkStatuses[meta.chainId].lastTokenPrice
        });

        _adjustHeartbeat(meta.chainId, congestionLevel);
        networkStatuses[meta.chainId] = status;
        delete requestMetadata[requestId];
        emit StatusRequestFulfilled(meta.chainId, requestId);
        emit NetworkStatusUpdated(meta.chainId, status);
    }

    /// @notice Fulfill Chainlink request with price feed data
    function fulfillPriceFeedUpdate(bytes32 requestId, bytes memory data) external nonReentrant whenNotPaused {
        RequestMetadata memory meta = requestMetadata[requestId];
        if (meta.chainId == 0) revert InvalidRequestId(requestId);
        if (!chainConfigs[meta.chainId].active) revert ChainNotConfigured(meta.chainId);
        if (block.timestamp > meta.requestTime + requestTimeout) revert RequestTimedOut(requestId);
        if (!meta.isPriceFeedRequest) revert InvalidRequestId(requestId);

        (int256 gasPrice, int256 tokenPrice) = abi.decode(data, (int256, int256));
        if (gasPrice <= 0 || tokenPrice <= 0) revert PriceFeedFailed(meta.chainId, true);

        NetworkStatus storage status = networkStatuses[meta.chainId];
        status.lastGasPrice = _normalizePrice(gasPrice, chainConfigs[meta.chainId].gasPriceFeedDecimals);
        status.lastTokenPrice = _normalizePrice(tokenPrice, chainConfigs[meta.chainId].tokenPriceFeedDecimals);
        status.lastUpdated = uint64(block.timestamp);

        _adjustHeartbeat(meta.chainId, status.congestionLevel);
        emit PriceFeedRequestFulfilled(meta.chainId, requestId, status.lastGasPrice, status.lastTokenPrice);
        emit NetworkStatusUpdated(meta.chainId, status);
        delete requestMetadata[requestId];
    }

    /// @notice Request a random retry delay via Chainlink VRF
    function requestRandomRetryDelay(uint16 chainId) public nonReentrant whenNotPaused returns (uint256 requestId) {
        if (!chainConfigs[chainId].active) revert ChainNotConfigured(chainId);
        if (vrfSubscriptionId == 0) revert InvalidVrfConfig(address(vrfCoordinator), vrfSubscriptionId);

        requestId = VRFCoordinatorV2Interface(vrfCoordinator).requestRandomWords(
            vrfKeyHash,
            vrfSubscriptionId,
            vrfRequestConfirmations,
            vrfCallbackGasLimit,
            1
        );
        vrfRequestIdToChainId[requestId] = chainId;

        emit RandomRetryDelayRequested(chainId, requestId);
    }

    /// @notice Fulfill VRF request with random words
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override nonReentrant whenNotPaused {
        uint16 chainId = vrfRequestIdToChainId[requestId];
        if (chainId == 0) revert InvalidVrfRequestId(requestId);
        if (!chainConfigs[chainId].active) revert ChainNotConfigured(chainId);

        uint32 range = maxRandomRetryDelay - minRandomRetryDelay + 1;
        uint32 randomDelay = minRandomRetryDelay + uint32(randomWords[0] % range);

        NetworkStatus storage status = networkStatuses[chainId];
        status.randomRetryDelay = uint64(randomDelay);
        status.lastUpdated = uint64(block.timestamp);

        _adjustHeartbeat(chainId, status.congestionLevel);
        emit RandomRetryDelayFulfilled(chainId, requestId, randomDelay);
        emit NetworkStatusUpdated(chainId, status);
        delete vrfRequestIdToChainId[requestId];
    }

    /// @notice Get network status for a chain with price feed fallback
    function getNetworkStatus(uint16 chainId) external view returns (NetworkStatus memory status) {
        status = networkStatuses[chainId];
        if (status.lastUpdated == 0) revert ChainNotConfigured(chainId);

        uint256 heartbeat = chainHeartbeats[chainId] == 0 ? DEFAULT_HEARTBEAT : chainHeartbeats[chainId];
        if (block.timestamp > status.lastUpdated + heartbeat) revert StaleData(chainId, status.lastUpdated);

        if (useFallbackPriceFeeds && chainConfigs[chainId].gasPriceFeed != address(0)) {
            PriceData memory gasPriceData = _getPriceFeedData(chainConfigs[chainId].gasPriceFeed, true, chainId, heartbeat);
            if (gasPriceData.valid) {
                uint64 gasPrice = uint64(uint256(gasPriceData.price));
                if (gasPrice >= minGasPrice && gasPrice <= maxGasPrice) {
                    status.gasPrice = gasPrice;
                    status.retryRecommended = gasPrice < status.gasPrice * 2 && status.bridgeOperational;
                    status.recommendedRetryDelay = gasPrice > status.gasPrice
                        ? status.recommendedRetryDelay * 2
                        : status.recommendedRetryDelay / 2;
                }
            }
        }
    }

    /// @notice Get price feed data for a chain
    function getPriceFeedData(uint16 chainId, bool isGasPrice) external view returns (PriceData memory priceData) {
        if (!chainConfigs[chainId].active) revert ChainNotConfigured(chainId);
        address priceFeed = isGasPrice ? chainConfigs[chainId].gasPriceFeed : chainConfigs[chainId].tokenPriceFeed;
        if (priceFeed == address(0)) revert InvalidPriceFeed(priceFeed);

        uint256 heartbeat = chainHeartbeats[chainId] == 0 ? DEFAULT_HEARTBEAT : chainHeartbeats[chainId];
        priceData = _getPriceFeedData(priceFeed, isGasPrice, chainId, heartbeat);
    }

    /// @notice Internal function to fetch price feed data with retry logic
    function _getPriceFeedData(address priceFeed, bool isGasPrice, uint16 chainId, uint256 heartbeat)
        private
        view
        returns (PriceData memory priceData)
    {
        bool success = false;
        uint8 retries = 0;
        int256 price;
        uint256 updatedAt;

        while (!success && retries < maxFallbackRetries) {
            try AggregatorV3Interface(priceFeed).latestRoundData() returns (uint80, int256 _price, uint256, uint256 _updatedAt, uint80) {
                if (_price > 0 && block.timestamp <= _updatedAt + heartbeat) {
                    price = _price;
                    updatedAt = _updatedAt;
                    success = true;
                }
            } catch {
                retries++;
            }
        }

        if (!success) {
            price = isGasPrice ? defaultGasPrice : defaultTokenPrice;
            updatedAt = block.timestamp;
            priceData = PriceData(price, updatedAt, false);
        } else {
            priceData = PriceData(_normalizePrice(price, isGasPrice ? chainConfigs[chainId].gasPriceFeedDecimals : chainConfigs[chainId].tokenPriceFeedDecimals), updatedAt, true);
        }
    }

    /// @notice Check if upkeep is needed for automated tasks
    function checkUpkeep(bytes calldata checkData) external view override returns (bool upkeepNeeded, bytes memory performData) {
        uint16 chainId;
        if (checkData.length > 0) {
            chainId = abi.decode(checkData, (uint16));
        }

        uint256 linkBalance = IERC20(chainlinkToken).balanceOf(address(this));
        uint16[] memory statusChainIds = new uint16[](activeChainIds.length);
        uint16[] memory randomDelayChainIds = new uint16[](activeChainIds.length);
        uint16[] memory priceFeedChainIds = new uint16[](activeChainIds.length);
        uint256 statusCount = 0;
        uint256 randomDelayCount = 0;
        uint256 priceFeedCount = 0;

        uint16[] memory chainsToCheck = chainId == 0 ? activeChainIds : new uint16[](1);
        if (chainId != 0) {
            chainsToCheck[0] = chainId;
        }

        for (uint256 i = 0; i < chainsToCheck.length; i++) {
            uint16 currentChainId = chainsToCheck[i];
            if (!chainConfigs[currentChainId].active) continue;

            ChainConfig storage config = chainConfigs[currentChainId];
            NetworkStatus storage status = networkStatuses[currentChainId];
            uint256 heartbeat = chainHeartbeats[currentChainId] == 0 ? DEFAULT_HEARTBEAT : chainHeartbeats[currentChainId];

            // Check status updates
            if (
                config.automateStatus &&
                linkBalance >= config.automationFee &&
                (block.timestamp >= status.lastUpdated + config.statusUpdateInterval ||
                 block.timestamp >= status.lastUpdated + heartbeat ||
                 status.congestionLevel >= 8)
            ) {
                statusChainIds[statusCount] = currentChainId;
                statusCount++;
            }

            // Check random delay updates
            if (
                config.automateRandomDelay &&
                block.timestamp >= status.lastUpdated + config.randomDelayUpdateInterval &&
                vrfSubscriptionId != 0
            ) {
                randomDelayChainIds[randomDelayCount] = currentChainId;
                randomDelayCount++;
            }

            // Check price feed updates
            if (
                config.automatePriceFeeds &&
                linkBalance >= config.automationFee &&
                (block.timestamp >= status.lastUpdated + config.priceFeedUpdateInterval ||
                 status.lastGasPrice <= 0 ||
                 status.lastTokenPrice <= 0)
            ) {
                priceFeedChainIds[priceFeedCount] = currentChainId;
                priceFeedCount++;
            }
        }

        // Resize arrays to exact size
        assembly {
            mstore(statusChainIds, statusCount)
            mstore(randomDelayChainIds, randomDelayCount)
            mstore(priceFeedChainIds, priceFeedCount)
        }

        upkeepNeeded = statusCount > 0 || randomDelayCount > 0 || priceFeedCount > 0;
        performData = abi.encode(statusChainIds, randomDelayChainIds, priceFeedChainIds);
    }

    /// @notice Perform upkeep tasks for automated updates
    function performUpkeep(bytes calldata performData) external override nonReentrant whenNotPaused {
        if (automationUpkeepId == 0) revert AutomationNotRegistered();

        (uint16[] memory statusChainIds, uint16[] memory randomDelayChainIds, uint16[] memory priceFeedChainIds) = 
            abi.decode(performData, (uint16[], uint16[], uint16[]));

        bytes32[] memory statusRequestIds = new bytes32[](statusChainIds.length);
        uint256[] memory vrfRequestIds = new uint256[](randomDelayChainIds.length);
        bytes32[] memory priceFeedRequestIds = new bytes32[](priceFeedChainIds.length);

        // Perform status updates
        for (uint256 i = 0; i < statusChainIds.length; i++) {
            uint16 chainId = statusChainIds[i];
            ChainConfig storage config = chainConfigs[chainId];
            if (!config.active || !config.automateStatus) continue;
            statusRequestIds[i] = requestNetworkStatusUpdate(chainId, automationStatusJobId, config.automationFee);
        }

        // Perform random delay updates
        for (uint256 i = 0; i < randomDelayChainIds.length; i++) {
            uint16 chainId = randomDelayChainIds[i];
            ChainConfig storage config = chainConfigs[chainId];
            if (!config.active || !config.automateRandomDelay) continue;
            vrfRequestIds[i] = requestRandomRetryDelay(chainId);
        }

        // Perform price feed updates
        for (uint256 i = 0; i < priceFeedChainIds.length; i++) {
            uint16 chainId = priceFeedChainIds[i];
            ChainConfig storage config = chainConfigs[chainId];
            if (!config.active || !config.automatePriceFeeds) continue;
            priceFeedRequestIds[i] = requestPriceFeedUpdate(chainId, config.automationFee);
        }

        emit AutomationTasksPerformed(
            statusChainIds,
            statusRequestIds,
            randomDelayChainIds,
            vrfRequestIds,
            priceFeedChainIds,
            priceFeedRequestIds
        );
    }

    /// @notice Cancel a timed-out Chainlink Node request
    function cancelRequest(bytes32 requestId) external onlyOwner {
        RequestMetadata memory meta = requestMetadata[requestId];
        if (meta.chainId == 0) revert InvalidRequestId(requestId);
        if (block.timestamp <= meta.requestTime + requestTimeout) revert RequestTimedOut(requestId);

        delete requestMetadata[requestId];
        emit RequestCancelled(requestId);
    }

    /// @notice Update chain configuration
    function updateChainConfig(
        uint16 chainId,
        address gasPriceFeed,
        address tokenPriceFeed,
        bytes calldata trustedSender,
        bool active,
        bool automateStatus,
        bool automateRandomDelay,
        bool automatePriceFeeds,
        uint256 statusUpdateInterval,
        uint256 randomDelayUpdateInterval,
        uint256 priceFeedUpdateInterval,
        uint256 automationFee
    ) external onlyOwner {
        if (active && (gasPriceFeed == address(0) && tokenPriceFeed == address(0) && trustedSender.length == 0))
            revert InvalidConfig(gasPriceFeed, tokenPriceFeed, trustedSender);
        if (statusUpdateInterval > 0 && statusUpdateInterval < MIN_UPDATE_INTERVAL) revert InvalidUpdateInterval(statusUpdateInterval);
        if (randomDelayUpdateInterval > 0 && randomDelayUpdateInterval < MIN_UPDATE_INTERVAL) revert InvalidUpdateInterval(randomDelayUpdateInterval);
        if (priceFeedUpdateInterval > 0 && priceFeedUpdateInterval < MIN_UPDATE_INTERVAL) revert InvalidUpdateInterval(priceFeedUpdateInterval);
        if (automationFee == 0 && (automateStatus || automatePriceFeeds)) revert InvalidAutomationConfig(automationRegistrar, automationStatusJobId, automationPriceFeedJobId);

        uint8 gasPriceFeedDecimals = gasPriceFeed != address(0) ? AggregatorV3Interface(gasPriceFeed).decimals() : 0;
        uint8 tokenPriceFeedDecimals = tokenPriceFeed != address(0) ? AggregatorV3Interface(tokenPriceFeed).decimals() : 0;

        bool wasActive = chainConfigs[chainId].active;
        chainConfigs[chainId] = ChainConfig({
            gasPriceFeed: gasPriceFeed,
            gasPriceFeedDecimals: gasPriceFeedDecimals,
            tokenPriceFeed: tokenPriceFeed,
            tokenPriceFeedDecimals: tokenPriceFeedDecimals,
            trustedSender: trustedSender,
            active: active,
            automateStatus: automateStatus,
            automateRandomDelay: automateRandomDelay,
            automatePriceFeeds: automatePriceFeeds,
            statusUpdateInterval: statusUpdateInterval,
            randomDelayUpdateInterval: randomDelayUpdateInterval,
            priceFeedUpdateInterval: priceFeedUpdateInterval,
            automationFee: automationFee
        });

        // Update active chain IDs
        if (active && !wasActive) {
            for (uint256 i = 0; i < activeChainIds.length; i++) {
                if (activeChainIds[i] == chainId) revert ChainAlreadyConfigured(chainId);
            }
            activeChainIds.push(chainId);
            networkStatuses[chainId].randomRetryDelay = minRandomRetryDelay;
        } else if (!active && wasActive) {
            for (uint256 i = 0; i < activeChainIds.length; i++) {
                if (activeChainIds[i] == chainId) {
                    activeChainIds[i] = activeChainIds[activeChainIds.length - 1];
                    activeChainIds.pop();
                    delete networkStatuses[chainId];
                    break;
                }
            }
            if (chainConfigs[chainId].active) revert ChainNotFound(chainId); // Ensure removal
        }

        emit ChainConfigUpdated(
            chainId,
            gasPriceFeed,
            gasPriceFeedDecimals,
            tokenPriceFeed,
            tokenPriceFeedDecimals,
            trustedSender,
            active,
            automateStatus,
            automateRandomDelay,
            automatePriceFeeds,
            statusUpdateInterval,
            randomDelayUpdateInterval,
            priceFeedUpdateInterval,
            automationFee
        );
        emit ActiveChainIdsUpdated(activeChainIds);
    }

    /// @notice Update automation configuration
    function updateAutomationConfig(
        address _registrar,
        uint256 _upkeepId,
        bytes32 _statusJobId,
        bytes32 _priceFeedJobId
    ) external onlyOwner {
        require(_registrar != address(0), "Invalid registrar");
        require(_statusJobId != bytes32(0), "Invalid status job ID");
        require(_priceFeedJobId != bytes32(0), "Invalid price feed job ID");
        if (automationUpkeepId != 0 && _upkeepId == 0) revert AutomationNotRegistered();

        automationRegistrar = _registrar;
        automationUpkeepId = _upkeepId;
        automationStatusJobId = _statusJobId;
        automationPriceFeedJobId = _priceFeedJobId;
        emit AutomationConfigUpdated(_registrar, _upkeepId, _statusJobId, _priceFeedJobId);
    }

    /// @notice Update default prices
    function updateDefaultPrices(int256 _defaultGasPrice, int256 _defaultTokenPrice) external onlyOwner {
        require(_defaultGasPrice > 0 && _defaultTokenPrice > 0, "Invalid default prices");
        defaultGasPrice = _defaultGasPrice;
        defaultTokenPrice = _defaultTokenPrice;
        emit DefaultPricesUpdated(_defaultGasPrice, _defaultTokenPrice);
    }

    /// @notice Update heartbeat for a chain
    function updateHeartbeat(uint16 chainId, uint256 heartbeat) external onlyOwner {
        if (heartbeat < minHeartbeat || heartbeat > maxHeartbeat) revert InvalidHeartbeat(heartbeat);
        chainHeartbeats[chainId] = heartbeat;
        emit HeartbeatUpdated(chainId, heartbeat);
    }

    /// @notice Update heartbeat bounds
    function updateHeartbeatBounds(uint256 _minHeartbeat, uint256 _maxHeartbeat) external onlyOwner {
        if (_minHeartbeat == 0 || _maxHeartbeat < _minHeartbeat || _maxHeartbeat > 7 days) revert InvalidHeartbeatBounds(_minHeartbeat, _maxHeartbeat);
        minHeartbeat = _minHeartbeat;
        maxHeartbeat = _maxHeartbeat;
        emit HeartbeatBoundsUpdated(_minHeartbeat, _maxHeartbeat);
    }

    /// @notice Update maximum fallback retries
    function updateMaxFallbackRetries(uint8 _maxRetries) external onlyOwner {
        require(_maxRetries >= 1 && _maxRetries <= 5, "Invalid max retries");
        maxFallbackRetries = _maxRetries;
        emit MaxFallbackRetriesUpdated(_maxRetries);
    }

    /// @notice Update Chainlink configuration
    function updateChainlinkConfig(address _chainlinkToken, address _chainlinkOracle) external onlyOwner {
        require(_chainlinkToken != address(0), "Invalid LINK token");
        require(_chainlinkOracle != address(0), "Invalid Chainlink oracle");
        chainlinkToken = _chainlinkToken;
        chainlinkOracle = _chainlinkOracle;
        setChainlinkToken(_chainlinkToken);
        emit ChainlinkConfigUpdated(_chainlinkToken, _chainlinkOracle);
    }

    /// @notice Update VRF configuration
    function updateVrfConfig(
        address _vrfCoordinator,
        uint64 _subscriptionId,
        bytes32 _keyHash,
        uint32 _callbackGasLimit,
        uint16 _requestConfirmations
    ) external onlyOwner {
        require(_vrfCoordinator != address(0), "Invalid VRF coordinator");
        require(_subscriptionId != 0, "Invalid VRF subscription ID");
        require(_callbackGasLimit >= 20_000, "Invalid callback gas limit");
        require(_requestConfirmations >= 3 && _requestConfirmations <= 200, "Invalid request confirmations");

        vrfCoordinator = _vrfCoordinator;
        vrfSubscriptionId = _subscriptionId;
        vrfKeyHash = _keyHash;
        vrfCallbackGasLimit = _callbackGasLimit;
        vrfRequestConfirmations = _requestConfirmations;
        emit VrfConfigUpdated(_vrfCoordinator, _subscriptionId, _keyHash, _callbackGasLimit, _requestConfirmations);
    }

    /// @notice Update random retry delay bounds
    function updateRandomRetryDelayBounds(uint32 _minRandomRetryDelay, uint32 _maxRandomRetryDelay) external onlyOwner {
        if (_minRandomRetryDelay == 0 || _maxRandomRetryDelay < _minRandomRetryDelay || _maxRandomRetryDelay > maxRetryDelay)
            revert InvalidRandomRetryDelayBounds(_minRandomRetryDelay, _maxRandomRetryDelay);
        minRandomRetryDelay = _minRandomRetryDelay;
        maxRandomRetryDelay = _maxRandomRetryDelay;
        emit RandomRetryDelayBoundsUpdated(_minRandomRetryDelay, _maxRandomRetryDelay);
    }

    /// @notice Update request timeout
    function updateRequestTimeout(uint256 _timeout) external onlyOwner {
        require(_timeout >= 10 minutes && _timeout <= 1 days, "Invalid timeout");
        requestTimeout = _timeout;
        emit RequestTimeoutUpdated(_timeout);
    }

    /// @notice Toggle fallback to Chainlink price feeds
    function toggleFallbackPriceFeeds(bool enabled) external onlyOwner {
        useFallbackPriceFeeds = enabled;
        emit FallbackPriceFeedsToggled(enabled);
    }

    /// @notice Update maximum retry delay
    function updateMaxRetryDelay(uint256 _maxRetryDelay) external onlyOwner {
        require(_maxRetryDelay >= 1 hours && _maxRetryDelay <= 7 days, "Invalid max retry delay");
        maxRetryDelay = _maxRetryDelay;
        emit MaxRetryDelayUpdated(_maxRetryDelay);
    }

    /// @notice Update gas price bounds
    function updateGasPriceBounds(uint256 _minGasPrice, uint256 _maxGasPrice) external onlyOwner {
        require(_minGasPrice > 0 && _maxGasPrice > _minGasPrice, "Invalid gas price bounds");
        minGasPrice = _minGasPrice;
        maxGasPrice = _maxGasPrice;
        emit GasPriceBoundsUpdated(_minGasPrice, _maxGasPrice);
    }

    /// @notice Pause the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Authorize contract upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice Validate network status fields
    function _validateStatus(uint64 gasPrice, uint32 confirmationTime, uint8 congestionLevel, uint32 recommendedRetryDelay) private view {
        if (gasPrice < minGasPrice || gasPrice > maxGasPrice) revert InvalidGasPrice(gasPrice);
        if (confirmationTime < MIN_CONFIRMATION_TIME || confirmationTime > MAX_CONFIRMATION_TIME) revert InvalidConfirmationTime(confirmationTime);
        if (congestionLevel > MAX_CONGESTION_LEVEL) revert InvalidCongestionLevel(congestionLevel);
        if (recommendedRetryDelay > maxRetryDelay) revert InvalidConfirmationTime(recommendedRetryDelay);
    }

    /// @notice Adjust heartbeat dynamically based on congestion level
    function _adjustHeartbeat(uint16 chainId, uint8 congestionLevel) private {
        uint256 currentHeartbeat = chainHeartbeats[chainId] == 0 ? DEFAULT_HEARTBEAT : chainHeartbeats[chainId];
        uint256 newHeartbeat;

        if (congestionLevel >= 8) {
            newHeartbeat = minHeartbeat;
        } else if (congestionLevel <= 2) {
            newHeartbeat = maxHeartbeat;
        } else {
            uint256 range = maxHeartbeat - minHeartbeat;
            uint256 step = range / (MAX_CONGESTION_LEVEL - 2);
            newHeartbeat = maxHeartbeat - (congestionLevel - 2) * step;
        }

        if (newHeartbeat != currentHeartbeat) {
            chainHeartbeats[chainId] = newHeartbeat;
            emit HeartbeatUpdated(chainId, newHeartbeat);
        }
    }

    /// @notice Normalize price to 18 decimals
    function _normalizePrice(int256 price, uint8 decimals) private pure returns (int256) {
        if (decimals == NORMALIZED_DECIMALS) return price;
        if (decimals > NORMALIZED_DECIMALS) {
            return price / int256(10 ** (decimals - NORMALIZED_DECIMALS));
        } else {
            return price * int256(10 ** (NORMALIZED_DECIMALS - decimals));
        }
    }
}
