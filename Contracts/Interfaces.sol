// SPDX-License-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPriceOracle {
    function getPrice(address asset) external returns (uint256);
    function getPrice(address tokenA, address tokenB) external view returns (int256);
    function getCurrentPrice(address asset) external view returns (uint256);
    function getCurrentPairPrice(address baseToken, address quoteToken) external view returns (uint256, bool);
    function assetConfigs(address pool) external view returns (
        uint256, address, address, uint256, uint256, uint256, uint256, uint256, uint256
    );
    function emergencyOverrideActive(address asset) external view returns (bool);
}

interface IAMMPool {
    function positions(uint256 positionId) external view returns (
        address owner,
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity,
        uint256 feeGrowthInside0LastX128,
        uint256 feeGrowthInside1LastX128,
        uint256 tokensOwed0,
        uint256 tokensOwed1
    );
    
    function getcurrentTick() external view returns (int24);
    
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
    event PositionCreated(uint256 indexed positionId, address indexed owner, int24 tickLower, int24 tickUpper, uint256 liquidity);
    event VolatilityThresholdUpdated(uint256 newThreshold);
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
    function setFailedMessage(uint256 messageId, AMMPool.FailedMessage memory message) external;
    function getFailedMessage(uint256 messageId) external view returns (AMMPool.FailedMessage memory);
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
    function emitCrossChainLiquiditySent(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock,
        uint256 positionId
    ) external;
    function emitCrossChainSwap(
        address user,
        address inputToken,
        uint256 amountIn,
        uint256 amountOut,
        uint16 dstChainId,
        uint64 nonce,
        uint256 timelock,
        uint8 messengerType
    ) external;
    function emitCrossChainLiquidityReceived(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 srcChainId,
        uint64 nonce,
        uint8 messengerType
    ) external;
    function emitFailedMessageStored(
        uint256 messageId,
        uint16 dstChainId,
        bytes memory sender,
        uint256 timestamp,
        uint8 messengerType
    ) external;
    function emitFailedMessageRetried(
        uint256 messageId,
        uint16 dstChainId,
        uint256 retries,
        uint8 messengerType
    ) external;
    function emitFailedMessageRetryScheduled(uint256 messageId, uint256 nextRetryTimestamp) external;
    function emitBatchMessagesSent(uint16[] memory dstChainIds, uint8 messengerType, uint256 totalFee) external;
    function emitBatchRetryProcessed(uint256[] memory messageIds, uint256 successfulRetries, uint256 failedRetries) external;
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
        uint256 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint256 tokensOwed0;
        uint256 tokensOwed1;
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
        bytes calldata dstAddress,
        bytes calldata payload,
        bytes calldata adapterParams,
        address payable refundAddress
    ) external payable;
    function estimateFees(
        uint16 dstChainId,
        string calldata dstAxelarChain,
        address user,
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