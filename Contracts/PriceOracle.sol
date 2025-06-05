// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol"; // Line 7
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol"; // Line 8
// Remove SafeMathUpgradeable import (not needed in Solidity 0.8.28) // Line 9
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol"; // Line 10, verify version
// Uniswap imports need npm packages or local files
import "./external/uniswap/v3/IUniswapV3Pool.sol";
import "./external/uniswap/v3/TickMath.sol";
import "./external/uniswap/v3/FullMath.sol";
import "./external/uniswap/v2/IUniswapV2Pair.sol";

/// @title PriceOracle
/// @notice Upgradeable price oracle for Sonic Blockchain with multiple data sources and advanced features
/// @dev Uses UUPS proxy, Chainlink VRF v2.5, and aggregates Chainlink feeds, Uniswap V3, SushiSwap, and PancakeSwap
contract PriceOracle is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    VRFConsumerBaseV2Plus
{
    using SafeMathUpgradeable for uint256;

    // Structs
    struct PriceFeedConfig {
        address feedAddress;
        uint8 decimals;
        bool isActive;
        uint256 heartbeat;
        uint256 weight;
        uint256 reliabilityScore;
        uint256 lastPrice;
        uint256 lastUpdated;
    }

    struct UniswapV3PoolConfig {
        address poolAddress;
        uint32 twapSeconds;
        bool isToken0Base;
        bool isActive;
        uint128 liquidity;
    }

    struct UniswapV2PoolConfig {
        address poolAddress;
        uint32 blockWindow;
        bool isToken0Base;
        bool isActive;
        uint128 liquidity;
        uint256 price0CumulativeLast;
        uint256 price1CumulativeLast;
        uint32 lastBlockTimestamp;
    }

    struct AssetConfig {
        uint8 primaryOracle; // 0: Chainlink, 1: Uniswap V3, 2: SushiSwap, 3: PancakeSwap
        uint256 maxPriceDeviation;
        bool useVRF;
        uint256 maxFeedDeviation;
        uint256 emaPrice;
        uint256 emaAlpha;
        uint256 volatilityIndex;
    }

    struct VRFRequest {
        address asset;
        uint256 requestId;
        bool isPending;
        uint256 price;
        uint256 timestamp;
    }

    // Storage
    mapping(address => AssetConfig) public assetConfigs;
    mapping(address => mapping(uint256 => PriceFeedConfig)) public priceFeeds;
    mapping(address => uint256) public priceFeedCount;
    mapping(address => mapping(uint256 => UniswapV3PoolConfig)) public uniswapV3Pools;
    mapping(address => mapping(uint256 => UniswapV2PoolConfig)) public sushiSwapPools;
    mapping(address => mapping(uint256 => UniswapV2PoolConfig)) public pancakeSwapPools;
    mapping(address => uint256) public uniswapV3PoolCount;
    mapping(address => uint256) public sushiSwapPoolCount;
    mapping(address => uint256) public pancakeSwapPoolCount;
    mapping(address => uint256) public emergencyPrices;
    mapping(address => bool) public emergencyOverrideActive;
    mapping(uint256 => VRFRequest) public vrfRequests;
    mapping(address => uint256) public pendingVRFRequestId; // Tracks VRF request per asset

    // Chainlink VRF configuration
    IVRFCoordinatorV2Plus public vrfCoordinator;
    uint64 public subscriptionId;
    bytes32 public keyHash;
    uint32 public callbackGasLimit;
    uint16 public requestConfirmations;
    uint32 public numWords;

    // Events
    event PriceFeedUpdated(address indexed asset, address feed, uint8 decimals, uint256 heartbeat, uint256 weight, uint256 reliabilityScore, uint256 index);
    event UniswapV3PoolAdded(address indexed asset, address pool, uint32 twapSeconds, bool isToken0Base, uint256 index);
    event UniswapV2PoolAdded(address indexed asset, address pool, uint32 blockWindow, bool isToken0Base, bool isSushiSwap, uint256 index);
    event UniswapV3PoolUpdated(address indexed asset, address pool, uint32 twapSeconds, uint128 liquidity, uint256 index);
    event UniswapV2PoolUpdated(address indexed asset, address pool, uint32 blockWindow, uint128 liquidity, bool isSushiSwap, uint256 index);
    event PoolDeactivated(address indexed asset, address pool, uint8 oracleType, uint256 index);
    event PriceFetched(address indexed asset, uint256 price, uint256 emaPrice, uint256 timestamp, uint8 oracleType);
    event TWAPWindowAdjusted(address indexed asset, address pool, uint32 oldWindow, uint32 newWindow, uint8 oracleType);
    event EmergencyPriceSet(address indexed asset, uint256 price);
    event EmergencyOverrideToggled(address indexed asset, bool isActive);
    event VRFRequestSent(uint256 requestId, address indexed asset);
    event VRFRequestFulfilled(uint256 requestId, address indexed asset, uint256 price, uint8 oracleType);
    event VRFConfigUpdated(address coordinator, uint64 subscriptionId, bytes32 keyHash);
    event VolatilityUpdated(address indexed asset, uint256 volatilityIndex);
    event EMASmoothingUpdated(address indexed asset, uint256 oldAlpha, uint256 newAlpha);
    event PoolStateUpdated(address indexed asset, address pool, uint8 oracleType, uint256 index, uint128 liquidity, uint256 timestamp);

    // Errors
    error ZeroAddress();
    error InvalidPriceFeed(address asset);
    error InvalidPool(address asset);
    error StalePrice(address asset);
    error InvalidPrice(address asset);
    error InvalidTWAPWindow();
    error InvalidBlockWindow();
    error InsufficientObservations(address pool);
    error InsufficientLiquidity(address pool);
    error NoValidPools(address asset);
    error PriceDeviationTooHigh(address asset);
    error FeedDeviationTooHigh(address asset);
    error ContractPaused();
    error VRFRequestPending(address asset);
    error VRFNotConfigured();
    error InvalidVRFRequest(uint256 requestId);
    error NoValidFeeds(address asset);
    error InvalidReliabilityScore();
    error InvalidVRFConfig();
    error PoolLimitReached(address asset);
    error InvalidEmergencyPrice(address asset);
    error ZeroValue();

    // Constants
    uint256 public constant DEFAULT_HEARTBEAT = 15 minutes; // Adjusted for better balance
    uint32 public constant MIN_TWAP_SECONDS = 5 minutes;
    uint32 public constant MAX_TWAP_SECONDS = 12 hours;
    uint32 public constant MIN_BLOCK_WINDOW = 20;
    uint32 public constant MAX_BLOCK_WINDOW = 512;
    uint256 public constant PRICE_PRECISION = 1e18;
    uint128 public constant MIN_LIQUIDITY_THRESHOLD = 1e15;
    uint16 public constant MAX_FEEDS_PER_ASSET = 5;
    uint16 public constant MAX_POOLS_PER_ASSET = 5;
    uint256 public constant BLOCK_TIME = 6;
    uint256 public constant DEFAULT_MAX_PRICE_DEVIATION = 5e16;
    uint256 public constant DEFAULT_MAX_FEED_DEVIATION = 2e16;
    uint256 public constant DEFAULT_EMA_ALPHA = 2e17;
    uint256 public constant MAX_RELIABILITY_SCORE = 100;
    uint256 public constant VOLATILITY_PRECISION = 1e18;
    uint32 public constant MIN_CALLBACK_GAS_LIMIT = 50_000;
    uint32 public constant MAX_CALLBACK_GAS_LIMIT = 500_000;
    uint16 public constant MIN_REQUEST_CONFIRMATIONS = 3;
    uint16 public constant MAX_REQUEST_CONFIRMATIONS = 20;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address _vrfCoordinator) VRFConsumerBaseV2Plus(_vrfCoordinator) {
        _disableInitializers();
    }

    /// @notice Authorizes contract upgrades
    /// @dev Required for UUPS proxy, only owner can upgrade
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @notice Initializes the contract
    /// @param initialOwner The initial owner address
    /// @param _vrfCoordinator Chainlink VRF Coordinator address
    /// @param _subscriptionId Chainlink VRF subscription ID
    /// @param _keyHash Chainlink VRF key hash
    /// @param _callbackGasLimit Gas limit for VRF callback
    /// @param _requestConfirmations Number of confirmations for VRF request
    function initialize(
        address initialOwner,
        address _vrfCoordinator,
        uint64 _subscriptionId,
        bytes32 _keyHash,
        uint32 _callbackGasLimit,
        uint16 _requestConfirmations
    ) external initializer {
        if (initialOwner == address(0) || _vrfCoordinator == address(0)) revert ZeroAddress();
        if (_callbackGasLimit < MIN_CALLBACK_GAS_LIMIT || _callbackGasLimit > MAX_CALLBACK_GAS_LIMIT) revert InvalidVRFConfig();
        if (_requestConfirmations < MIN_REQUEST_CONFIRMATIONS || _requestConfirmations > MAX_REQUEST_CONFIRMATIONS) revert InvalidVRFConfig();

        __Ownable_init(initialOwner);
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        vrfCoordinator = IVRFCoordinatorV2Plus(_vrfCoordinator);
        subscriptionId = _subscriptionId;
        keyHash = _keyHash;
        callbackGasLimit = _callbackGasLimit;
        requestConfirmations = _requestConfirmations;
        numWords = 1;
        emit VRFConfigUpdated(_vrfCoordinator, _subscriptionId, _keyHash);
    }

    /// @notice Updates VRF configuration
    /// @param _vrfCoordinator Chainlink VRF Coordinator address
    /// @param _subscriptionId Chainlink VRF subscription ID
    /// @param _keyHash Chainlink VRF key hash
    /// @param _callbackGasLimit Gas limit for VRF callback
    /// @param _requestConfirmations Number of confirmations for VRF request
    function updateVRFConfig(
        address _vrfCoordinator,
        uint64 _subscriptionId,
        bytes32 _keyHash,
        uint32 _callbackGasLimit,
        uint16 _requestConfirmations
    ) external onlyOwner {
        if (_vrfCoordinator == address(0)) revert ZeroAddress();
        if (_callbackGasLimit < MIN_CALLBACK_GAS_LIMIT || _callbackGasLimit > MAX_CALLBACK_GAS_LIMIT) revert InvalidVRFConfig();
        if (_requestConfirmations < MIN_REQUEST_CONFIRMATIONS || _requestConfirmations > MAX_REQUEST_CONFIRMATIONS) revert InvalidVRFConfig();

        vrfCoordinator = IVRFCoordinatorV2Plus(_vrfCoordinator);
        subscriptionId = _subscriptionId;
        keyHash = _keyHash;
        callbackGasLimit = _callbackGasLimit;
        requestConfirmations = _requestConfirmations;
        emit VRFConfigUpdated(_vrfCoordinator, _subscriptionId, _keyHash);
    }

    /// @notice Pauses the contract
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Adds or updates a Chainlink price feed
    /// @param asset The asset address
    /// @param feed The Chainlink price feed address
    /// @param decimals Decimals of the price feed
    /// @param heartbeat Maximum time before price is considered stale
    /// @param weight Weight for weighted median calculation
    /// @param reliabilityScore Reliability score for VRF selection (0-100)
    function setPriceFeed(
        address asset,
        address feed,
        uint8 decimals,
        uint256 heartbeat,
        uint256 weight,
        uint256 reliabilityScore
    ) external onlyOwner {
        if (asset == address(0) || feed == address(0)) revert ZeroAddress();
        if (reliabilityScore > MAX_RELIABILITY_SCORE) revert InvalidReliabilityScore();
        if (priceFeedCount[asset] >= MAX_FEEDS_PER_ASSET) revert PoolLimitReached(asset);

        uint256 index = priceFeedCount[asset]++;
        priceFeeds[asset][index] = PriceFeedConfig({
            feedAddress: feed,
            decimals: decimals,
            isActive: true,
            heartbeat: heartbeat == 0 ? DEFAULT_HEARTBEAT : heartbeat,
            weight: weight == 0 ? 1e18 : weight,
            reliabilityScore: reliabilityScore,
            lastPrice: 0,
            lastUpdated: 0
        });

        emit PriceFeedUpdated(asset, feed, decimals, heartbeat, weight, reliabilityScore, index);
    }

    /// @notice Deactivates a Chainlink price feed
    /// @param asset The asset address
    /// @param feedIndex Index of the price feed
    function deactivatePriceFeed(address asset, uint256 feedIndex) external onlyOwner {
        if (feedIndex >= priceFeedCount[asset]) revert InvalidPriceFeed(asset);
        priceFeeds[asset][feedIndex].isActive = false;
        emit PriceFeedUpdated(asset, priceFeeds[asset][feedIndex].feedAddress, priceFeeds[asset][feedIndex].decimals, priceFeeds[asset][feedIndex].heartbeat, 0, 0, feedIndex);
    }

    /// @notice Adds a Uniswap V3 pool
    /// @param asset The asset address
    /// @param poolAddress The Uniswap V3 pool address
    /// @param twapSeconds TWAP window in seconds
    /// @param isToken0Base Whether token0 is the base token
    function addUniswapV3Pool(
        address asset,
        address poolAddress,
        uint32 twapSeconds,
        bool isToken0Base
    ) external onlyOwner {
        if (asset == address(0) || poolAddress == address(0)) revert ZeroAddress();
        if (twapSeconds < MIN_TWAP_SECONDS || twapSeconds > MAX_TWAP_SECONDS) revert InvalidTWAPWindow();
        if (uniswapV3PoolCount[asset] >= MAX_POOLS_PER_ASSET) revert PoolLimitReached(asset);

        IUniswapV3Pool pool = IUniswapV3Pool(poolAddress);
        uint128 liquidity = pool.liquidity();
        if (liquidity < MIN_LIQUIDITY_THRESHOLD) revert InsufficientLiquidity(poolAddress);

        (, , , , uint16 observationCardinality, , ) = pool.slot0();
        uint16 requiredCardinality = calculateRequiredCardinality(twapSeconds);
        if (observationCardinality < requiredCardinality) {
            pool.increaseObservationCardinalityNext(requiredCardinality);
        }

        uint256 index = uniswapV3PoolCount[asset]++;
        uniswapV3Pools[asset][index] = UniswapV3PoolConfig({
            poolAddress: poolAddress,
            twapSeconds: twapSeconds,
            isToken0Base: isToken0Base,
            isActive: true,
            liquidity: liquidity
        });

        emit UniswapV3PoolAdded(asset, poolAddress, twapSeconds, isToken0Base, index);
    }

    /// @notice Adds a Uniswap V2-style pool (SushiSwap or PancakeSwap)
    /// @param asset The asset address
    /// @param poolAddress The pool address
    /// @param blockWindow Number of blocks for TWAP
    /// @param isToken0Base Whether token0 is the base token
    /// @param isSushiSwap Whether the pool is SushiSwap (true) or PancakeSwap (false)
    function addUniswapV2Pool(
        address asset,
        address poolAddress,
        uint32 blockWindow,
        bool isToken0Base,
        bool isSushiSwap
    ) external onlyOwner {
        if (asset == address(0) || poolAddress == address(0)) revert ZeroAddress();
        if (blockWindow < MIN_BLOCK_WINDOW || blockWindow > MAX_BLOCK_WINDOW) revert InvalidBlockWindow();

        IUniswapV2Pair pool = IUniswapV2Pair(poolAddress);
        (uint112 reserve0, uint112 reserve1, ) = pool.getReserves();
        uint128 liquidity = uint128(uint256(reserve0).mul(reserve1));
        if (liquidity < MIN_LIQUIDITY_THRESHOLD) revert InsufficientLiquidity(poolAddress);

        uint256 index;
        if (isSushiSwap) {
            if (sushiSwapPoolCount[asset] >= MAX_POOLS_PER_ASSET) revert PoolLimitReached(asset);
            index = sushiSwapPoolCount[asset]++;
            sushiSwapPools[asset][index] = UniswapV2PoolConfig({
                poolAddress: poolAddress,
                blockWindow: blockWindow,
                isToken0Base: isToken0Base,
                isActive: true,
                liquidity: liquidity,
                price0CumulativeLast: pool.price0CumulativeLast(),
                price1CumulativeLast: pool.price1CumulativeLast(),
                lastBlockTimestamp: uint32(block.timestamp)
            });
        } else {
            if (pancakeSwapPoolCount[asset] >= MAX_POOLS_PER_ASSET) revert PoolLimitReached(asset);
            index = pancakeSwapPoolCount[asset]++;
            pancakeSwapPools[asset][index] = UniswapV2PoolConfig({
                poolAddress: poolAddress,
                blockWindow: blockWindow,
                isToken0Base: isToken0Base,
                isActive: true,
                liquidity: liquidity,
                price0CumulativeLast: pool.price0CumulativeLast(),
                price1CumulativeLast: pool.price1CumulativeLast(),
                lastBlockTimestamp: uint32(block.timestamp)
            });
        }

        emit UniswapV2PoolAdded(asset, poolAddress, blockWindow, isToken0Base, isSushiSwap, index);
    }

    /// @notice Sets oracle preference and VRF usage
    /// @param asset The asset address
    /// @param oracleType Primary oracle type (0: Chainlink, 1: Uniswap V3, 2: SushiSwap, 3: PancakeSwap)
    /// @param maxPriceDeviation Maximum allowed deviation from secondary oracle
    /// @param maxFeedDeviation Maximum allowed deviation between Chainlink feeds
    /// @param useVRF Whether to use VRF for oracle selection
    /// @param emaAlpha EMA smoothing factor
    /// @param volatilityIndex Volatility index for dynamic heartbeat
    function setOraclePreference(
        address asset,
        uint8 oracleType,
        uint256 maxPriceDeviation,
        uint256 maxFeedDeviation,
        bool useVRF,
        uint256 emaAlpha,
        uint256 volatilityIndex
    ) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (oracleType > 3 || emaAlpha > 1e18) revert InvalidInput();

        AssetConfig storage config = assetConfigs[asset];
        emit EMASmoothingUpdated(asset, config.emaAlpha, emaAlpha == 0 ? DEFAULT_EMA_ALPHA : emaAlpha);
        if (config.volatilityIndex != volatilityIndex) {
            emit VolatilityUpdated(asset, volatilityIndex == 0 ? 1e18 : volatilityIndex);
        }

        config.primaryOracle = oracleType;
        config.maxPriceDeviation = maxPriceDeviation == 0 ? DEFAULT_MAX_PRICE_DEVIATION : maxPriceDeviation;
        config.maxFeedDeviation = maxFeedDeviation == 0 ? DEFAULT_MAX_FEED_DEVIATION : maxFeedDeviation;
        config.useVRF = useVRF;
        config.emaAlpha = emaAlpha == 0 ? DEFAULT_EMA_ALPHA : emaAlpha;
        config.volatilityIndex = volatilityIndex == 0 ? 1e18 : volatilityIndex;
    }

    /// @notice Sets emergency price override with deviation check
    /// @param asset The asset address
    /// @param price The emergency price
    function setEmergencyPrice(address asset, uint256 price) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        if (price == 0) revert ZeroValue();

        AssetConfig storage config = assetConfigs[asset];
        if (config.maxPriceDeviation > 0) {
            uint256 secondaryPrice = getSecondaryPrice(asset, config.primaryOracle);
            if (secondaryPrice > 0) {
                uint256 deviation = price > secondaryPrice
                    ? price.sub(secondaryPrice).mul(1e18).div(secondaryPrice)
                    : secondaryPrice.sub(price).mul(1e18).div(price);
                if (deviation > config.maxPriceDeviation) revert InvalidEmergencyPrice(asset);
            }
        }

        emergencyPrices[asset] = price;
        emergencyOverrideActive[asset] = true;
        emit EmergencyPriceSet(asset, price);
        emit EmergencyOverrideToggled(asset, true);
    }

    /// @notice Disables emergency price override
    /// @param asset The asset address
    function disableEmergencyOverride(address asset) external onlyOwner {
        if (asset == address(0)) revert ZeroAddress();
        emergencyOverrideActive[asset] = false;
        emit EmergencyOverrideToggled(asset, false);
    }

    /// @notice Deactivates a pool
    /// @param asset The asset address
    /// @param poolIndex Index of the pool
    /// @param oracleType Oracle type (1: Uniswap V3, 2: SushiSwap, 3: PancakeSwap)
    function deactivatePool(address asset, uint256 poolIndex, uint8 oracleType) external onlyOwner {
        if (oracleType == 1) {
            if (poolIndex >= uniswapV3PoolCount[asset]) revert InvalidPool(asset);
            uniswapV3Pools[asset][poolIndex].isActive = false;
            emit PoolDeactivated(asset, uniswapV3Pools[asset][poolIndex].poolAddress, 1, poolIndex);
        } else if (oracleType == 2) {
            if (poolIndex >= sushiSwapPoolCount[asset]) revert InvalidPool(asset);
            sushiSwapPools[asset][poolIndex].isActive = false;
            emit PoolDeactivated(asset, sushiSwapPools[asset][poolIndex].poolAddress, 2, poolIndex);
        } else if (oracleType == 3) {
            if (poolIndex >= pancakeSwapPoolCount[asset]) revert InvalidPool(asset);
            pancakeSwapPools[asset][poolIndex].isActive = false;
            emit PoolDeactivated(asset, pancakeSwapPools[asset][poolIndex].poolAddress, 3, poolIndex);
        } else {
            revert InvalidInput();
        }
    }

    /// @notice Updates TWAP window for a pool
    /// @param asset The asset address
    /// @param poolIndex Index of the pool
    /// @param oracleType Oracle type (1: Uniswap V3, 2: SushiSwap, 3: PancakeSwap)
    function updateTWAPWindow(address asset, uint256 poolIndex, uint8 oracleType) external nonReentrant whenNotPaused {
        if (oracleType == 1) {
            if (poolIndex >= uniswapV3PoolCount[asset]) revert InvalidPool(asset);
            UniswapV3PoolConfig storage poolConfig = uniswapV3Pools[asset][poolIndex];
            if (!poolConfig.isActive) revert InvalidPool(asset);

            IUniswapV3Pool pool = IUniswapV3Pool(poolConfig.poolAddress);
            uint128 liquidity = pool.liquidity();
            if (liquidity < MIN_LIQUIDITY_THRESHOLD) revert InsufficientLiquidity(poolConfig.poolAddress);

            uint32 newWindow = calculateDynamicTWAPWindow(liquidity);
            (, , , , uint16 observationCardinality, , ) = pool.slot0();
            uint16 requiredCardinality = calculateRequiredCardinality(newWindow);
            if (observationCardinality < requiredCardinality) {
                pool.increaseObservationCardinalityNext(requiredCardinality);
            }

            emit TWAPWindowAdjusted(asset, poolConfig.poolAddress, poolConfig.twapSeconds, newWindow, 1);
            poolConfig.twapSeconds = newWindow;
            poolConfig.liquidity = liquidity;
            emit UniswapV3PoolUpdated(asset, poolConfig.poolAddress, newWindow, liquidity, poolIndex);
            emit PoolStateUpdated(asset, poolConfig.poolAddress, 1, poolIndex, liquidity, block.timestamp);
        } else if (oracleType == 2 || oracleType == 3) {
            UniswapV2PoolConfig storage poolConfig = oracleType == 2
                ? sushiSwapPools[asset][poolIndex]
                : pancakeSwapPools[asset][poolIndex];
            if (poolIndex >= (oracleType == 2 ? sushiSwapPoolCount[asset] : pancakeSwapPoolCount[asset])) revert InvalidPool(asset);
            if (!poolConfig.isActive) revert InvalidPool(asset);

            IUniswapV2Pair pool = IUniswapV2Pair(poolConfig.poolAddress);
            (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast) = pool.getReserves();
            uint128 liquidity = uint128(uint256(reserve0).mul(reserve1));
            if (liquidity < MIN_LIQUIDITY_THRESHOLD) revert InsufficientLiquidity(poolConfig.poolAddress);

            uint32 newWindow = calculateDynamicBlockWindow(liquidity);
            poolConfig.price0CumulativeLast = pool.price0CumulativeLast();
            poolConfig.price1CumulativeLast = pool.price1CumulativeLast();
            poolConfig.lastBlockTimestamp = blockTimestampLast;
            poolConfig.blockWindow = newWindow;
            poolConfig.liquidity = liquidity;

            emit TWAPWindowAdjusted(asset, poolConfig.poolAddress, poolConfig.blockWindow, newWindow, oracleType);
            emit UniswapV2PoolUpdated(asset, poolConfig.poolAddress, newWindow, liquidity, oracleType == 2, poolIndex);
            emit PoolStateUpdated(asset, poolConfig.poolAddress, oracleType, poolIndex, liquidity, blockTimestampLast);
        } else {
            revert InvalidInput();
        }
    }

    /// @notice Gets the current EMA price for an asset
    /// @param asset The asset address
    /// @return The current EMA price
    function getCurrentPrice(address asset) external view returns (uint256) {
        return assetConfigs[asset].emaPrice;
    }

    /// @notice Checks if a VRF request is pending for an asset
    /// @param asset The asset address
    /// @return requestId The pending VRF request ID, or 0 if none
    function getPendingVRFRequest(address asset) external view returns (uint256) {
        return pendingVRFRequestId[asset];
    }

    /// @notice Requests price with optional VRF-based oracle selection
    /// @param asset The asset address
    /// @return price The EMA price, or 0 if VRF request is sent
    function getPrice(address asset) external nonReentrant whenNotPaused returns (uint256) {
    if (emergencyOverrideActive[asset]) {
        uint256 price = emergencyPrices[asset];
        uint256 emaPrice = updateEMA(asset, price);
        emit PriceFetched(asset, price, emaPrice, block.timestamp, 4);
        return emaPrice;
    }

    AssetConfig storage config = assetConfigs[asset];
    if (config.useVRF && address(vrfCoordinator) != address(0)) {
        if (pendingVRFRequestId[asset] != 0) revert VRFRequestPending(asset);
        uint256 requestId = vrfCoordinator.requestRandomWords(
            VRFV2PlusClient.RandomWordsRequest({
                keyHash: keyHash,
                subId: subscriptionId,
                requestConfirmations: requestConfirmations,
                callbackGasLimit: callbackGasLimit,
                numWords: numWords,
                extraArgs: VRFV2PlusClient._argsToBytes(
                    VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
                )
            })
        ); // Semicolon after function call
        vrfRequests[requestId] = VRFRequest({
            asset: asset,
            requestId: requestId,
            isPending: true,
            price: 0,
            timestamp: 0
        }); // Semicolon
        pendingVRFRequestId[asset] = requestId; // Semicolon
        emit VRFRequestSent(requestId, asset); // Semicolon
        return 0; // Indicate VRF request is pending
    }

    uint256 price = fetchPriceDeterministic(asset);
    uint256 emaPrice = updateEMA(asset, price);
    emit PriceFetched(asset, price, emaPrice, block.timestamp, config.primaryOracle);
    return emaPrice;
}

    /// @notice Fulfills VRF request with weighted oracle selection
    /// @param requestId The VRF request ID
    /// @param randomWords The random words provided by VRF
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
        VRFRequest storage request = vrfRequests[requestId];
        if (request.asset == address(0) || !request.isPending) revert InvalidVRFRequest(requestId);

        AssetConfig storage config = assetConfigs[request.asset];
        uint256 randomWord = randomWords[0];
        uint8 oracleType;

        bool[4] memory oracleAvailability = [
            priceFeedCount[request.asset] > 0,
            uniswapV3PoolCount[request.asset] > 0,
            sushiSwapPoolCount[request.asset] > 0,
            pancakeSwapPoolCount[request.asset] > 0
        ];
        uint256[4] memory oracleReliabilitySums;

        uint256 totalReliability = 0;
        if (oracleAvailability[0]) {
            for (uint256 i = 0; i < priceFeedCount[request.asset]; i++) {
                PriceFeedConfig memory feed = priceFeeds[request.asset][i];
                if (feed.isActive) {
                    oracleReliabilitySums[0] = oracleReliabilitySums[0].add(feed.reliabilityScore);
                }
            }
            totalReliability = totalReliability.add(oracleReliabilitySums[0]);
        }
        if (oracleAvailability[1]) oracleReliabilitySums[1] = 75;
        if (oracleAvailability[2]) oracleReliabilitySums[2] = 60;
        if (oracleAvailability[3]) oracleReliabilitySums[3] = 60;
        totalReliability = totalReliability
            .add(oracleAvailability[1] ? oracleReliabilitySums[1] : 0)
            .add(oracleAvailability[2] ? oracleReliabilitySums[2] : 0)
            .add(oracleAvailability[3] ? oracleReliabilitySums[3] : 0);

        if (totalReliability == 0) revert NoValidPools(request.asset);

        uint256 randomValue = randomWord % totalReliability;
        uint256 cumulativeReliability = 0;
        for (uint8 i = 0; i < 4; i++) {
            if (oracleAvailability[i]) {
                cumulativeReliability = cumulativeReliability.add(oracleReliabilitySums[i]);
                if (randomValue < cumulativeReliability) {
                    oracleType = i;
                    break;
                }
            }
        }

        uint256 price;
        try this.fetchPriceWithOracle(request.asset, oracleType) returns (uint256 _price) {
            price = _price;
        } catch {
            price = fetchPriceDeterministic(request.asset);
            oracleType = config.primaryOracle;
        }

        if (config.maxPriceDeviation > 0) {
            uint256 secondaryPrice = getSecondaryPrice(request.asset, oracleType);
            if (secondaryPrice > 0) {
                uint256 deviation = price > secondaryPrice
                    ? price.sub(secondaryPrice).mul(1e18).div(secondaryPrice)
                    : secondaryPrice.sub(price).mul(1e18).div(price);
                if (deviation > config.maxPriceDeviation) {
                    price = fetchPriceDeterministic(request.asset);
                    oracleType = config.primaryOracle;
                }
            }
        }

        price = updateEMA(request.asset, price);
        request.price = price;
        request.timestamp = block.timestamp;
        request.isPending = false;
        pendingVRFRequestId[request.asset] = 0;
        emit VRFRequestFulfilled(requestId, request.asset, price, oracleType);
        emit PriceFetched(request.asset, price, price, block.timestamp, oracleType);
    }

    /// @notice Fetches price using deterministic logic
    /// @param asset The asset address
    /// @return price The fetched price
    function fetchPriceDeterministic(address asset) internal nonReentrant returns (uint256) {
        AssetConfig storage config = assetConfigs[asset];
        uint8 oracleType = config.primaryOracle;
        uint256 price;

        if (oracleType == 0) {
            try this.getChainlinkPrice(asset) returns (uint256 _price) {
                price = _price;
            } catch {
                try this.getUniswapV3TWAP(asset) returns (uint256 _price) {
                    price = _price;
                } catch {
                    try this.getUniswapV2TWAP(asset, true) returns (uint256 _price) {
                        price = _price;
                    } catch {
                        price = getUniswapV2TWAP(asset, false);
                    }
                }
            }
        } else if (oracleType == 1) {
            try this.getUniswapV3TWAP(asset) returns (uint256 _price) {
                price = _price;
            } catch {
                try this.getUniswapV2TWAP(asset, true) returns (uint256 _price) {
                    price = _price;
                } catch {
                    price = getUniswapV2TWAP(asset, false);
                }
            }
        } else if (oracleType == 2) {
            try this.getUniswapV2TWAP(asset, true) returns (uint256 _price) {
                price = _price;
            } catch {
                price = getUniswapV2TWAP(asset, false);
            }
        } else {
            try this.getUniswapV2TWAP(asset, false) returns (uint256 _price) {
                price = _price;
            } catch {
                try this.getUniswapV3TWAP(asset) returns (uint256 _price) {
                    price = _price;
                } catch {
                    price = getChainlinkPrice(asset);
                }
            }
        }

        if (config.maxPriceDeviation > 0) {
            uint256 secondaryPrice = getSecondaryPrice(asset, oracleType);
            if (secondaryPrice > 0) {
                uint256 deviation = price > secondaryPrice
                    ? price.sub(secondaryPrice).mul(1e18).div(secondaryPrice)
                    : secondaryPrice.sub(price).mul(1e18).div(price);
                if (deviation > config.maxPriceDeviation) revert PriceDeviationTooHigh(asset);
            }
        }

        return price;
    }

    /// @notice Fetches price with specific oracle type
    /// @param asset The asset address
    /// @param oracleType Oracle type (0: Chainlink, 1: Uniswap V3, 2: SushiSwap, 3: PancakeSwap)
    /// @return price The fetched price
    function fetchPriceWithOracle(address asset, uint8 oracleType) external returns (uint256) {
        if (msg.sender != address(this)) revert InvalidInput();
        if (oracleType == 0) return getChainlinkPrice(asset);
        if (oracleType == 1) return getUniswapV3TWAP(asset);
        if (oracleType == 2) return getUniswapV2TWAP(asset, true);
        return getUniswapV2TWAP(asset, false);
    }

    /// @notice Gets aggregated Chainlink price
    /// @param asset The asset address
    /// @return price The weighted median price
    function getChainlinkPrice(address asset) public returns (uint256) {
        uint256 feedCount = priceFeedCount[asset];
        if (feedCount == 0) revert InvalidPriceFeed(asset);

        uint256 validPrices = 0;
        uint256 totalWeight = 0;
        uint256[] memory prices = new uint256[](feedCount);
        uint256[] memory weights = new uint256[](feedCount);

        for (uint256 i = 0; i < feedCount; i++) {
            PriceFeedConfig storage config = priceFeeds[asset][i];
            if (!config.isActive || config.feedAddress == address(0)) continue;

            AggregatorV3Interface feed = AggregatorV3Interface(config.feedAddress);
            try feed.latestRoundData() returns (
                uint80 roundId,
                int256 price,
                uint256 updatedAt,
                uint80 answeredInRound
            ) {
                uint256 heartbeat = calculateDynamicHeartbeat(asset);
                if (price <= 0 || answeredInRound < roundId || block.timestamp > updatedAt + heartbeat) continue;

                uint256 adjustedPrice = config.decimals == 18 ? uint256(price) : uint256(price).mul(10**(18 - config.decimals));
                prices[validPrices] = adjustedPrice;
                weights[validPrices] = config.weight;
                totalWeight = totalWeight.add(config.weight);
                config.lastPrice = adjustedPrice;
                config.lastUpdated = block.timestamp;
                validPrices++;
            } catch {
                continue;
            }
        }

        if (validPrices == 0) revert NoValidFeeds(asset);

        AssetConfig storage assetConfig = assetConfigs[asset];
        if (assetConfig.maxFeedDeviation > 0 && validPrices > 1) {
            uint256 medianPrice = calculateMedian(prices, validPrices);
            for (uint256 i = 0; i < validPrices; i++) {
                uint256 deviation = prices[i] > medianPrice
                    ? prices[i].sub(medianPrice).mul(1e18).div(medianPrice)
                    : medianPrice.sub(prices[i]).mul(1e18).div(prices[i]);
                if (deviation > assetConfig.maxFeedDeviation) revert FeedDeviationTooHigh(asset);
            }
        }

        return calculateWeightedMedian(prices, weights, validPrices, totalWeight);
    }

    /// @notice Gets Uniswap V3 TWAP
    /// @param asset The asset address
    /// @return price The median TWAP price
    function getUniswapV3TWAP(address asset) public returns (uint256) {
        uint256 poolCount = uniswapV3PoolCount[asset];
        if (poolCount == 0) revert InvalidPool(asset);

        uint256 validPrices = 0;
        uint256[] memory prices = new uint256[](poolCount);

        for (uint256 i = 0; i < poolCount; i++) {
            UniswapV3PoolConfig storage poolConfig = uniswapV3Pools[asset][i];
            if (!poolConfig.isActive || poolConfig.poolAddress == address(0)) continue;

            IUniswapV3Pool pool = IUniswapV3Pool(poolConfig.poolAddress);
            (, , , , uint16 observationCardinality, , ) = pool.slot0();
            uint16 requiredCardinality = calculateRequiredCardinality(poolConfig.twapSeconds);
            if (observationCardinality < requiredCardinality) {
                pool.increaseObservationCardinalityNext(requiredCardinality);
                continue;
            }

            uint32[] memory secondsAgo = new uint32[](2);
            secondsAgo[0] = poolConfig.twapSeconds;
            secondsAgo[1] = 0;

            try pool.observe(secondsAgo) returns (int56[] memory tickCumulatives, uint160[] memory) {
                if (tickCumulatives.length < 2) continue;

                int56 tickCumulativeDelta = tickCumulatives[1] - tickCumulatives[0];
                int24 arithmeticMeanTick = int24(tickCumulativeDelta / int56(uint56(poolConfig.twapSeconds)));
                prices[validPrices] = tickToPrice(arithmeticMeanTick, poolConfig.isToken0Base);
                validPrices++;
            } catch {
                continue;
            }
        }

        if (validPrices == 0) revert NoValidPools(asset);
        return calculateMedian(prices, validPrices);
    }

    /// @notice Gets Uniswap V2-style TWAP (SushiSwap or PancakeSwap)
    /// @param asset The asset address
    /// @param isSushiSwap Whether to use SushiSwap (true) or PancakeSwap (false)
    /// @return price The median TWAP price
    function getUniswapV2TWAP(address asset, bool isSushiSwap) public returns (uint256) {
        uint256 poolCount = isSushiSwap ? sushiSwapPoolCount[asset] : pancakeSwapPoolCount[asset];
        if (poolCount == 0) revert InvalidPool(asset);

        uint256 validPrices = 0;
        uint256[] memory prices = new uint256[](poolCount);

        for (uint256 i = 0; i < poolCount; i++) {
            UniswapV2PoolConfig storage poolConfig = isSushiSwap
                ? sushiSwapPools[asset][i]
                : pancakeSwapPools[asset][i];
            if (!poolConfig.isActive || poolConfig.poolAddress == address(0)) continue;

            IUniswapV2Pair pool = IUniswapV2Pair(poolConfig.poolAddress);
            (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast) = pool.getReserves();
            if (blockTimestampLast == 0) continue;

            uint256 price0Cumulative = pool.price0CumulativeLast();
            uint256 price1Cumulative = pool.price1CumulativeLast();
            uint256 timeElapsed = block.timestamp.sub(poolConfig.lastBlockTimestamp);

            if (timeElapsed < poolConfig.blockWindow * BLOCK_TIME) continue;

            uint256 price = poolConfig.isToken0Base
                ? calculateUniswapV2TWAP(price0Cumulative, poolConfig.price0CumulativeLast, timeElapsed)
                : calculateUniswapV2TWAP(price1Cumulative, poolConfig.price1CumulativeLast, timeElapsed);

            if (price > 0) {
                prices[validPrices] = price;
                validPrices++;
                poolConfig.price0CumulativeLast = price0Cumulative;
                poolConfig.price1CumulativeLast = price1Cumulative;
                poolConfig.lastBlockTimestamp = blockTimestampLast;
                emit PoolStateUpdated(asset, poolConfig.poolAddress, isSushiSwap ? 2 : 3, i, poolConfig.liquidity, blockTimestampLast);
            }
        }

        if (validPrices == 0) revert NoValidPools(asset);
        return calculateMedian(prices, validPrices);
    }

    /// @notice Gets secondary price for deviation check
    /// @param asset The asset address
    /// @param primaryOracle The primary oracle type
    /// @return price The secondary price, or 0 if none available
    function getSecondaryPrice(address asset, uint8 primaryOracle) internal returns (uint256) {
        for (uint8 i = 0; i < 4; i++) {
            if (i == primaryOracle) continue;
            if (i == 0 && priceFeedCount[asset] > 0) {
                try this.getChainlinkPrice(asset) returns (uint256 price) {
                    return price;
                } catch {
                    continue;
                }
            } else if (i == 1 && uniswapV3PoolCount[asset] > 0) {
                try this.getUniswapV3TWAP(asset) returns (uint256 price) {
                    return price;
                } catch {
                    continue;
                }
            } else if (i == 2 && sushiSwapPoolCount[asset] > 0) {
                try this.getUniswapV2TWAP(asset, true) returns (uint256 price) {
                    return price;
                } catch {
                    continue;
                }
            } else if (i == 3 && pancakeSwapPoolCount[asset] > 0) {
                try this.getUniswapV2TWAP(asset, false) returns (uint256 price) {
                    return price;
                } catch {
                    continue;
                }
            }
        }
        return 0;
    }

    /// @notice Updates EMA for price smoothing
    /// @param asset The asset address
    /// @param newPrice The new price to incorporate
    /// @return emaPrice The updated EMA price
    function updateEMA(address asset, uint256 newPrice) internal returns (uint256) {
        if (newPrice == 0) revert InvalidPrice(asset);
        AssetConfig storage config = assetConfigs[asset];
        if (config.emaPrice == 0) {
            uint256 secondaryPrice = getSecondaryPrice(asset, config.primaryOracle);
            if (secondaryPrice > 0 && config.maxPriceDeviation > 0) {
                uint256 deviation = newPrice > secondaryPrice
                    ? newPrice.sub(secondaryPrice).mul(1e18).div(secondaryPrice)
                    : secondaryPrice.sub(newPrice).mul(1e18).div(newPrice);
                if (deviation > config.maxPriceDeviation) revert InvalidPrice(asset);
            }
            config.emaPrice = newPrice;
            return newPrice;
        }
        config.emaPrice = config.emaPrice
            .mul(1e18 - config.emaAlpha)
            .add(newPrice.mul(config.emaAlpha))
            .div(1e18);
        return config.emaPrice;
    }

    /// @notice Calculates dynamic heartbeat based on volatility
    /// @param asset The asset address
    /// @return heartbeat The calculated heartbeat
    function calculateDynamicHeartbeat(address asset) internal view returns (uint256) {
        uint256 volatility = assetConfigs[asset].volatilityIndex;
        if (volatility == 0) volatility = 1e18;
        uint256 heartbeat = DEFAULT_HEARTBEAT.mul(1e18).div(volatility);
        return heartbeat < 5 minutes ? 5 minutes : heartbeat > 30 minutes ? 30 minutes : heartbeat;
    }

    /// @notice Calculates Uniswap V2 TWAP
    /// @param priceCumulativeEnd The ending cumulative price
    /// @param priceCumulativeStart The starting cumulative price
    /// @param timeElapsed Time elapsed between prices
    /// @return price The calculated TWAP
    function calculateUniswapV2TWAP(
        uint256 priceCumulativeEnd,
        uint256 priceCumulativeStart,
        uint256 timeElapsed
    ) internal pure returns (uint256) {
        if (priceCumulativeEnd < priceCumulativeStart) {
            priceCumulativeEnd += type(uint256).max;
        }
        uint256 priceCumulativeDelta = priceCumulativeEnd - priceCumulativeStart;
        if (timeElapsed == 0) revert InvalidInput();
        return FullMath.mulDiv(priceCumulativeDelta, PRICE_PRECISION, timeElapsed);
    }

    /// @notice Converts Uniswap V3 tick to price
    /// @param tick The Uniswap V3 tick
    /// @param isToken0Base Whether token0 is the base token
    /// @return price The converted price
    function tickToPrice(int24 tick, bool isToken0Base) internal pure returns (uint256) {
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        uint256 price;
        if (isToken0Base) {
            price = FullMath.mulDiv(
                uint256(sqrtPriceX96) * uint256(sqrtPriceX96),
                PRICE_PRECISION,
                1 << 192
            );
        } else {
            price = FullMath.mulDiv(
                1 << 192,
                PRICE_PRECISION,
                uint256(sqrtPriceX96) * uint256(sqrtPriceX96)
            );
        }
        if (price == 0) revert InvalidPrice(address(0));
        return price;
    }

    /// @notice Calculates weighted median price
    /// @param prices Array of prices
    /// @param weights Array of weights
    /// @param validCount Number of valid prices
    /// @param totalWeight Total weight of valid prices
    /// @return medianPrice The weighted median price
    function calculateWeightedMedian(
        uint256[] memory prices,
        uint256[] memory weights,
        uint256 validCount,
        uint256 totalWeight
    ) internal pure returns (uint256) {
        if (validCount == 0 || totalWeight == 0) revert InvalidInput();

        uint256[] memory sortedPrices = new uint256[](validCount);
        uint256[] memory sortedWeights = new uint256[](validCount);
        for (uint256 i = 0; i < validCount; i++) {
            sortedPrices[i] = prices[i];
            sortedWeights[i] = weights[i];
        }

        for (uint256 i = 1; i < validCount; i++) {
            uint256 keyPrice = sortedPrices[i];
            uint256 keyWeight = sortedWeights[i];
            uint256 j = i;
            while (j > 0 && sortedPrices[j - 1] > keyPrice) {
                sortedPrices[j] = sortedPrices[j - 1];
                sortedWeights[j] = sortedWeights[j - 1];
                j--;
            }
            sortedPrices[j] = keyPrice;
            sortedWeights[j] = keyWeight;
        }

        uint256 cumulativeWeight = 0;
        uint256 targetWeight = totalWeight.div(2);
        for (uint256 i = 0; i < validCount; i++) {
            cumulativeWeight = cumulativeWeight.add(sortedWeights[i]);
            if (cumulativeWeight >= targetWeight) {
                if (cumulativeWeight == targetWeight && i < validCount - 1) {
                    return (sortedPrices[i] + sortedPrices[i + 1]).div(2);
                }
                return sortedPrices[i];
            }
        }
        return sortedPrices[validCount - 1];
    }

    /// @notice Calculates median price
    /// @param prices Array of prices
    /// @param validCount Number of valid prices
    /// @return medianPrice The median price
    function calculateMedian(uint256[] memory prices, uint256 validCount) internal pure returns (uint256) {
        if (validCount == 0) revert InvalidInput();

        uint256[] memory sortedPrices = new uint256[](validCount);
        for (uint256 i = 0; i < validCount; i++) {
            sortedPrices[i] = prices[i];
        }

        for (uint256 i = 1; i < validCount; i++) {
            uint256 key = sortedPrices[i];
            uint256 j = i;
            while (j > 0 && sortedPrices[j - 1] > key) {
                sortedPrices[j] = sortedPrices[j - 1];
                j--;
            }
            sortedPrices[j] = key;
        }

        if (validCount % 2 == 0) {
            return (sortedPrices[validCount / 2 - 1] + sortedPrices[validCount / 2]) / 2;
        } else {
            return sortedPrices[validCount / 2];
        }
    }

    /// @notice Calculates required observation cardinality for Uniswap V3
    /// @param twapSeconds TWAP window in seconds
    /// @return cardinality The required observation cardinality
    function calculateRequiredCardinality(uint32 twapSeconds) internal pure returns (uint16) {
        return uint16(twapSeconds / 30) + 1;
    }

    /// @notice Calculates dynamic TWAP window based on liquidity
    /// @param liquidity The pool liquidity
    /// @return window The calculated TWAP window
    function calculateDynamicTWAPWindow(uint128 liquidity) internal pure returns (uint32) {
        if (liquidity < MIN_LIQUIDITY_THRESHOLD) return MAX_TWAP_SECONDS;
        if (liquidity > 1e18) return MIN_TWAP_SECONDS;
        uint256 liquidityFactor = uint256(liquidity).mul(1e18).div(1e18 - MIN_LIQUIDITY_THRESHOLD);
        uint32 window = uint32(MAX_TWAP_SECONDS - (MAX_TWAP_SECONDS - MIN_TWAP_SECONDS).mul(liquidityFactor).div(1e18));
        return window < MIN_TWAP_SECONDS ? MIN_TWAP_SECONDS : window;
    }

    /// @notice Calculates dynamic block window based on liquidity
    /// @param liquidity The pool liquidity
    /// @return window The calculated block window
    function calculateDynamicBlockWindow(uint128 liquidity) internal pure returns (uint32) {
        if (liquidity < MIN_LIQUIDITY_THRESHOLD) return MAX_BLOCK_WINDOW;
        if (liquidity > 1e18) return MIN_BLOCK_WINDOW;
        uint256 liquidityFactor = uint256(liquidity).mul(1e18).div(1e18 - MIN_LIQUIDITY_THRESHOLD);
        uint32 window = uint32(MAX_BLOCK_WINDOW - (MAX_BLOCK_WINDOW - MIN_BLOCK_WINDOW).mul(liquidityFactor).div(1e18));
        return window < MIN_BLOCK_WINDOW ? MIN_BLOCK_WINDOW : window;
    }

    /// @notice Gets price feed configuration
    /// @param asset The asset address
    /// @param index The feed index
    /// @return config The price feed configuration
    function getPriceFeedConfig(address asset, uint256 index) external view returns (PriceFeedConfig memory) {
        return priceFeeds[asset][index];
    }

    /// @notice Gets Uniswap V3 pool configuration
    /// @param asset The asset address
    /// @param index The pool index
    /// @return config The Uniswap V3 pool configuration
    function getUniswapV3PoolConfig(address asset, uint256 index) external view returns (UniswapV3PoolConfig memory) {
        return uniswapV3Pools[asset][index];
    }

    /// @notice Gets Uniswap V2 pool configuration
    /// @param asset The asset address
    /// @param index The pool index
    /// @param isSushiSwap Whether to fetch SushiSwap (true) or PancakeSwap (false)
    /// @return config The Uniswap V2 pool configuration
    function getUniswapV2PoolConfig(address asset, uint256 index, bool isSushiSwap) external view returns (UniswapV2PoolConfig memory) {
        return isSushiSwap ? sushiSwapPools[asset][index] : pancakeSwapPools[asset][index];
    }

    uint256[50] private __gap; // Increased for safety
}
