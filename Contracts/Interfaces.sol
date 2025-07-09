// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPriceOracle {
    function getPrice(address asset) external returns (uint256);
    function getPrice(address tokenA, address tokenB) external view returns (int256);
    function getCurrentPrice(address asset) external view returns (uint256);
    function getCurrentPairPrice(address baseToken, address quoteToken) external view returns (uint256 price, bool cachedStatus, uint256 timestamp);
    function assetConfigs(address pool) external view returns (
        uint256, address, address, uint256, uint256, uint256, uint256, uint256, uint256
    );
    function emergencyOverrideActive(address asset) external view returns (bool);
    // Functions from OrderBook.sol for compatibility
    function getSpotPrice(address tokenA, address tokenB) external view returns (uint256);
    function getIndexPrice(address tokenA, address tokenB) external view returns (uint256);
}

interface IChainlinkOracle {
    function decimals() external view returns (uint8);
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

interface IAMMPool {
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

    function initialize(
        ICommonStructs.InitParams memory params,
        address _retryOracle,
        bytes32 _oracleJobId,
        address _linkToken,
        address _orderBook
    ) external;

    function positions(uint256 positionId) external view returns (
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity,
        uint256 feeGrowthInside0LastX128,
        uint256 feeGrowthInside1LastX128,
        uint128 tokensOwed0,
        uint128 tokensOwed1
    );

    function getCurrentTick() external view returns (int24);
    function getOraclePrice() external returns (uint256);
    function tokenA() external view returns (address);
    function tokenB() external view returns (address);
    function positionCounter() external view returns (uint256);
    function addConcentratedLiquidityCrossChain(
        uint256 amountA,
        uint256 amountB,
        int24 tickLower,
        int24 tickUpper,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable;
    function addConcentratedLiquidityCrossChain(
        uint256 positionId,
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint16 srcChainId,
        address recipient
    ) external;
    function collectFeesInternal(uint256 positionId) external;
    function adjust(uint256 positionId, int24 tickLower, int24 tickUpper, uint256 liquidity) external;
    function exitFallbackPoolInternal(uint256 positionId) external;
    function compoundFallbackFeesInternal(uint256 positionId, uint256 tokensOwed0, uint256 tokensOwed1) external;
    function transferToken(address token, address recipient, uint256 amount) external;
    function MAX_BATCH_SIZE() external view returns (uint256);
    function MAX_RETRIES() external view returns (uint256);
    function authorizeAdjuster(uint256 positionId, address adjuster) external;
    function collectFees(uint256 positionId) external;
    function isInFallbackPool(uint256 positionId) external view returns (bool);
    function batchCrossChainMessages(uint16 dstChainId, bytes memory payload, bytes memory adapterParams) external payable;
    function exitFallbackPool(uint256 positionId) external;
    function trustedRemotePools(uint16 chainId) external view returns (bytes memory);
    function chainIdToAxelarChain(uint16 chainId) external view returns (string memory);
    function governance() external view returns (address);
    function emaVolatility() external view returns (uint256);
    function emaVol() external view returns (uint256);
    function getReserves() external view returns (uint64 reserveA, uint64 reserveB);
    function TICK_SPACING() external view returns (uint24);
    function getVolatilityThreshold() external view returns (uint256);
    function volatilityThreshold() external view returns (uint256);
    function updateVolatilityThreshold(uint256 newThreshold) external;
    function batchCrossChainMessages(
        uint16[] calldata dstChainIds,
        string[] calldata dstAxelarChains,
        bytes[] calldata payloads,
        bytes[] calldata adapterParams,
        uint256[] calldata timelocks
    ) external payable;
    function getTickSpacing() external view returns (uint24);
    function crossChainMessengers(uint8 messengerType) external view returns (address);
    function tokenBridge() external view returns (address);
    function tokenBridgeType(address token) external view returns (uint8);
    function failedMessageCount() external view returns (uint256);
    function setFailedMessage(uint256 messageId, ICommonStructs.FailedMessage memory message) external;
    function getFailedMessage(uint256 messageId) external view returns (ICommonStructs.FailedMessage memory);
    function deleteFailedMessage(uint256 messageId) external;
    function updateFailedMessage(uint256 messageId, uint256 retries, uint256 nextRetryTimestamp) external;
    function incrementFailedMessageCount() external;
    function chainTimelocks(uint16 chainId) external view returns (uint256);
    function MIN_TIMELOCK() external view returns (uint256);
    function MAX_TIMELOCK() external view returns (uint256);
    function RETRY_DELAY() external view returns (uint256);
    function paused() external view returns (bool);
    function chainPaused(uint16 chainId) external view returns (bool);
    function usedNonces(uint16 chainId, uint64 nonce) external view returns (bool);
    function setUsedNonces(uint16 chainId, uint64 nonce, bool used) external;
    function validatedMessages(bytes32 messageHash) external view returns (bool);
    function setValidatedMessages(bytes32 messageHash, bool validated) external;
    function wormholeTrustedSenders(uint16 chainId) external view returns (bytes32);
    function addLiquidityFromFees(uint256 positionId, uint256 amount0, uint256 amount1) external; // Added function
    function token0() external view returns (address);
    function token1() external view returns (address);
    function treasury() external view returns (address);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external returns (uint256);
    function getVolatility() external view returns (uint256);
    function adjustLiquidityRange(uint256 minPrice, uint256 maxPrice) external;
    function getConcentratedPrice() external view returns (uint256);
    function rebalanceReserves(uint16 chainId) external;

    event PositionCreated(uint256 indexed positionId, address indexed owner, int24 tickLower, int24 tickUpper, uint128 liquidity);
    event VolatilityThresholdUpdated(uint256 newThreshold);
    event CrossChainLiquiditySent(
        address indexed provider,
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock,
        uint256 positionId
    );
    event CrossChainSwap(
        address indexed user,
        address inputToken,
        uint256 amountIn,
        uint256 amountOut,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock,
        uint8 messengerType
    );
    event CrossChainLiquidityReceived(
        address indexed provider,
        uint256 amountA,
        uint256 amountB,
        uint16 srcChainId,
        uint64 nonce,
        uint8 messengerType
    );
    event FailedMessageStored(
        uint256 indexed messageId,
        uint16 dstChainId,
        string dstAxelarChain,
        uint256 timestamp,
        uint8 messengerType
    );
    event FailedMessageRetried(
        uint256 indexed messageId,
        uint16 dstChainId,
        uint256 retries,
        uint8 messengerType
    );
    event FailedMessageRetryScheduled(uint256 indexed messageId, uint256 nextRetryTimestamp);
    event BatchMessagesSent(uint16[] dstChainIds, uint8 messengerType, uint256 totalFee);
    event BatchRetryProcessed(uint256[] messageIds, uint256 successfulRetries, uint256 failedRetries);
}

interface IPositionManager {
    function mintPosition(uint256 positionId, address recipient) external;
    function feeDestinations(address owner) external view returns (address);
    function approve(address to, uint256 tokenId) external;
    function collectAndBridgeFees(
        uint256 positionId,
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable;
    function batchBridgeFees(
        uint256[] calldata positionIds,
        uint256 total0,
        uint256 total1,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable;
}

interface IPositionAdjuster {
    function adjustPosition(uint256 positionId, int24 newTickLower, int24 newTickUpper) external;
    function exitFallbackPool(uint256 positionId) external;
    function adjust(uint256 positionId, int24 tickLower, int24 tickUpper, uint256 liquidity) external;
}

interface ICommonStructs {
    struct InitParams {
        address tokenA;
        address tokenB;
        address treasury;
        address layerZeroEndpoint;
        address axelarGateway;
        address axelarGasService;
        address wormholeCore;
        address tokenBridge;
        address primaryPriceOracle;
        address[] fallbackPriceOracles;
        address governance;
        address positionManager;
        uint256 defaultTimelock;
        uint256 targetReserveRatio;
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
}

interface IConcentratedLiquidity {
    function addConcentratedLiquidity(address provider, int24 tickLower, int24 tickUpper, uint256 amountA, uint256 amountB)
        external
        returns (uint256 positionId);
    function removeConcentratedLiquidity(uint256 positionId, uint256 liquidity) external;
    function collectFees(uint256 positionId) external;
    function collectFeesInternal(uint256 positionId) external;
    function adjust(uint256 positionId, int24 tickLower, int24 tickUpper, uint256 liquidity) external;
    function swapConcentratedLiquidity(bool isTokenAInput, uint256 amountIn) external returns (uint256 amountOut);
}

interface ICrossChainModule {
    function addLiquidityCrossChain(address provider, uint256 amountA, uint256 amountB, uint16 dstChainId, bytes calldata adapterParams) external payable;
    function addConcentratedLiquidityCrossChain(address provider, uint256 amountA, uint256 amountB, int24 tickLower, int24 tickUpper, uint16 dstChainId, bytes calldata adapterParams) external payable;
    function swapCrossChain(address user, address inputToken, uint256 amountIn, uint256 minAmountOut, uint16 dstChainId, bytes calldata adapterParams) external payable returns (uint256);
    function receiveMessage(uint16 srcChainId, bytes calldata srcAddress, bytes calldata payload, bytes calldata additionalParams) external;
    function batchCrossChainMessages(uint16[] calldata dstChainIds, string[] calldata dstAxelarChains, bytes[] calldata payloads, bytes[] calldata adapterParams, uint256[] calldata timelocks) external payable;
    function retryFailedMessage(uint256 messageId) external payable;
    function retryFailedMessagesBatch(uint256[] calldata messageIds) external payable;
    function sendCrossChainMessage(
        uint16 dstChainId,
        string memory dstAxelarChain,
        bytes memory destinationAddress,
        bytes memory payload,
        bytes memory adapterParams,
        uint64 nonce,
        uint256 timelock,
        uint8 messengerType
    ) external payable;
    function bridgeTokens(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function validateCrossChainMessage(
        uint16 srcChainId,
        bytes memory srcAddress,
        bytes memory payload,
        bytes memory additionalParams
    ) external;
    function getNonce(uint16 chainId, uint8 messengerType) external view returns (uint64);
    // Functions from OrderBook.sol for compatibility
    function sendCrossChainOrder(address targetChain, bytes memory orderData) external;
    function receiveCrossChainOrder(bytes memory orderData) external;
    function getDynamicTimelock(uint16 chainId) external view returns (uint256);
    function getEstimatedCrossChainFee(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);
}

interface ILayerZeroEndpoint {
    function send(
        uint16 _dstChainId,
        bytes calldata _destination,
        bytes calldata _payload,
        address payable _refundAddress,
        address _zroPaymentAddress,
        bytes calldata _adapterParams
    ) external payable;
    function estimateFees(
        uint16 _dstChainId,
        address _destination,
        bytes calldata _payload,
        bool _payInZRO,
        bytes calldata _adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);
    function getInboundNonce(uint16 _srcChainId, bytes calldata _srcAddress) external view returns (uint64);
}

interface IAxelarGateway {
    function callContract(
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload
    ) external;
    function validateContractCall(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external view returns (bool valid);
}

interface IAxelarGasService {
    function payNativeGasForContractCall(
        bytes32 txHash,
        uint256 logIndex,
        address gasPayer
    ) external payable;
}

interface IWormhole {
    function publishMessage(
        bytes calldata payload,
        uint32 nonce,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);
    function parseAndVerifyVM(
        bytes calldata vaa
    ) external view returns (uint16 emitterChainId, bytes32 emitterAddress, uint64 sequence, bytes memory payload);
}

interface ICrossChainMessenger {
    function sendMessage(
        uint16 dstChainId,
        string calldata dstAxelarChain,
        bytes calldata destination,
        bytes calldata payload,
        bytes calldata adapterParams,
        address payable refundAddress
    ) external payable;

    function estimateFees(
        uint16 dstChainId,
        string calldata dstAxelarChain,
        address destination,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);
}

interface ITokenBridge {
    function burn(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function lock(address token, uint256 amount, address recipient, uint16 dstChainId) external;
    function mint(address token, uint256 amount, address recipient) external;
    function release(address token, uint256 amount, address recipient) external;
}

// New interfaces from OrderBook.sol
interface IGovernanceModule {
    // Placeholder for governance interface
}

interface IGovernanceToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface ICrossChainRetryOracle {
    struct NetworkStatus {
        bool bridgeOperational;
        bool retryRecommended;
        uint256 recommendedRetryDelay;
    }
    function getNetworkStatus(uint64 chainId) external view returns (NetworkStatus memory);
}

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
}