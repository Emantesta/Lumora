// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@chainlink/contracts/src/v0.8/interfaces/KeeperCompatibleInterface.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "./AMMPool.sol";
import "./PositionManager.sol";
import "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import {UD60x18, ud} from "@prb/math/src/UD60x18.sol";

interface IPriceOracle {
    function getCurrentPairPrice(address tokenA, address tokenB) external view returns (uint256 price, bool isCached);
    function assetConfigs(address asset) external view returns (
        address tokenA,
        address tokenB,
        uint8 primaryOracle,
        uint256 maxPriceDeviation,
        uint256 maxFeedDeviation,
        bool useVRF,
        uint256 emaPrice,
        uint256 emaAlpha,
        uint256 volatilityIndex
    );
    function emergencyOverrideActive(address asset) external view returns (bool);
}

/// @title PositionAdjuster
/// @notice Automates liquidity position adjustments with Chainlink Keeper integration
/// @dev Enhanced with fee aggregation, multi-bridge support, and batch operations
contract PositionAdjuster is KeeperCompatibleInterface, ReentrancyGuardUpgradeable {
    AMMPool public immutable pool;
    PositionManager public immutable positionManager;
    address public immutable priceOracle;
    address[] public fallbackPriceOracles;
    mapping(address => Strategy[]) public strategies;
    mapping(address => bool) public pausedAssets;
    uint256 public maxAdjustmentsPerUpkeep = 10;
    uint256 public volumeWindow = 1 hours;
    mapping(address => mapping(uint256 => uint256)) public volumeData;
    mapping(uint256 => FailedCrossChainMessage) public failedMessages;
    uint256 public failedMessageCount;
    mapping(uint256 => uint256) public fallbackFees0;
    mapping(uint256 => uint256) public fallbackFees1;
    mapping(uint256 => uint256) public fallbackEntryTimestamp;
    uint256 public baseFallbackFeeRate = 20;
    uint256 public maxFallbackFeeRate = 100;
    uint256 public volatilityFeeMultiplier = 2;
    uint256 public durationFeeThreshold = 1 days;
    uint256 public constant MIN_GAS_PER_EXIT = 100_000;
    uint256 public constant FEE_AGGREGATION_THRESHOLD = 0.01 ether;
    mapping(uint8 => address) public tokenBridges; // Mapping of bridgeType to bridge address
    mapping(address => AggregatedFees) public aggregatedFees; // Aggregated fees per user

    enum StrategyType { Fixed, Volatility, Volume, Predictive }

    struct Strategy {
        uint256 positionId;
        StrategyType strategyType;
        uint24 rangeWidth;
        uint24 minPriceDeviation;
        uint24 volatilityThreshold;
        uint24 volumePercentile;
        uint24 twapPeriod;
        bool compoundFees;
        uint8 bridgeType; // Preferred bridge for fee bridging
    }

    struct FailedCrossChainMessage {
        uint256 positionId;
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 nextRetryTimestamp;
        bool fallbackActive;
        uint256 fee0;
        uint256 fee1;
    }

    struct AggregatedFees {
        uint256 total0;
        uint256 total1;
    }

    // Events
    event StrategyRegistered(address indexed owner, uint256 positionId, StrategyType strategyType, uint24 rangeWidth, bool compoundFees, uint8 bridgeType);
    event PositionAdjusted(uint256 indexed positionId, int24 newTickLower, int24 newTickUpper);
    event CrossChainAdjustmentSent(uint256 indexed positionId, uint16 dstChainId, int24 newTickLower, int24 newTickUpper, bool fallbackActive, uint256 fee0, uint256 fee1, uint8 bridgeType);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, uint256 positionId);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries);
    event FailedMessageRecovered(uint256 indexed messageId, uint16 dstChainId);
    event CachedPriceUsed(address indexed asset, uint256 price, uint256 timestamp);
    event AdjustmentsPaused(address indexed asset, uint256 timestamp);
    event AdjustmentsResumed(address indexed asset, uint256 timestamp);
    event FallbackFeesCollected(uint256 indexed positionId, uint256 amount0, uint256 amount1);
    event FallbackFeesCompounded(uint256 indexed positionId, uint256 amount0, uint256 amount1);
    event BatchFallbackPoolExited(uint256[] positionIds);
    event FallbackFeeConfigUpdated(uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier, uint256 durationThreshold);
    event FeesAggregated(address indexed owner, uint256 positionId, uint256 amount0, uint256 amount1);
    event TokenBridgeUpdated(uint8 bridgeType, address indexed newBridge);
    event BatchFeesBridged(address indexed owner, uint256[] positionIds, uint256 total0, uint256 total1, uint16 dstChainId, uint8 bridgeType);

    // Errors
    error InvalidStrategyType();
    error Unauthorized();
    error InvalidChainId(uint16 chainId);
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error RetryNotReady(uint256 messageId, uint256 nextRetryTimestamp);
    error InsufficientGas(uint256 required, uint256 available);
    error OracleFailure();
    error AssetPaused(address asset);
    error InsufficientLiquidity(uint256 liquidity);
    error InvalidBatchSize(uint256 size);
    error InvalidFeeConfig(uint256 baseFee, uint256 maxFee);
    error InvalidBridgeType(uint8 bridgeType);
    error InsufficientAggregatedFees();

    constructor(address _pool, address _positionManager, address _priceOracle, address[] memory _fallbackPriceOracles) {
        pool = AMMPool(_pool);
        positionManager = PositionManager(_positionManager);
        priceOracle = _priceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        __ReentrancyGuard_init();
    }

    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        Strategy[] memory userStrategies = strategies[msg.sender];
        uint256[] memory positionIds = new uint256[](maxAdjustmentsPerUpkeep);
        int24[] memory newTickLowers = new int24[](maxAdjustmentsPerUpkeep);
        int24[] memory newTickUppers = new int24[](maxAdjustmentsPerUpkeep);
        uint256 count;

        (uint256 reserveA, uint256 reserveB, , ) = pool.getReserves();
        uint256 currentPrice = (reserveB * 1e18) / reserveA;
        uint256 emaVolatility = pool.emaVolatility();

        for (uint256 i = 0; i < userStrategies.length && count < maxAdjustmentsPerUpkeep; i++) {
            Strategy memory strategy = userStrategies[i];
            (, int24 tickLower, int24 tickUpper, uint256 liquidity, bool fallbackActive, ) = pool.positions(strategy.positionId);
            if (liquidity == 0) continue;
            if (pausedAssets[address(pool)]) continue;

            bool isOutOfRange = currentPrice < _tickToPrice(tickLower) || currentPrice > _tickToPrice(tickUpper);
            bool isNearBoundary = _isNearBoundary(currentPrice, tickLower, tickUpper, strategy.minPriceDeviation);

            if (fallbackActive || isOutOfRange || isNearBoundary) {
                (int24 newTickLower, int24 newTickUpper) = _calculateNewTicks(
                    strategy,
                    currentPrice,
                    emaVolatility,
                    reserveA,
                    reserveB
                );
                positionIds[count] = strategy.positionId;
                newTickLowers[count] = newTickLower;
                newTickUppers[count] = newTickUpper;
                count++;
            }
        }

        upkeepNeeded = count > 0;
        performData = abi.encode(positionIds, newTickLowers, newTickUppers, count);
        return (upkeepNeeded, performData);
    }

    function performUpkeep(bytes calldata performData) external override nonReentrant {
        (uint256[] memory positionIds, int24[] memory newTickLowers, int24[] memory newTickUppers, uint256 count)
            = abi.decode(performData, (uint256[], int24[], int24[], uint256));

        batchExitFallbackPool(positionIds, count);

        for (uint256 i = 0; i < count; i++) {
            uint256 positionId = positionIds[i];
            (, int24 tickLower, int24 tickUpper, uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
            if (liquidity == 0) continue;
            if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

            _aggregateFees(positionId, owner);
            if (tickLower != newTickLowers[i] || tickUpper != newTickUppers[i]) {
                Strategy storage strategy = _getStrategy(positionId);
                if (strategy.compoundFees) {
                    compoundFallbackFees(positionId);
                } else {
                    collectFallbackFees(positionId);
                }
                pool.adjustPosition(positionId, newTickLowers[i], newTickUppers[i], liquidity);
                emit PositionAdjusted(positionId, newTickLowers[i], newTickUppers[i]);
            }
        }
    }

    function registerStrategy(
        uint256 positionId,
        StrategyType strategyType,
        uint24 rangeWidth,
        uint24 minPriceDeviation,
        uint24 volatilityThreshold,
        uint24 volumePercentile,
        uint24 twapPeriod,
        bool compoundFees,
        uint8 bridgeType
    ) external nonReentrant {
        if (uint8(strategyType) > uint8(StrategyType.Predictive)) revert InvalidStrategyType();
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType(bridgeType);
        pool.authorizeAdjuster(positionId, address(this));
        strategies[msg.sender].push(Strategy({
            positionId: positionId,
            strategyType: strategyType,
            rangeWidth: rangeWidth,
            minPriceDeviation: minPriceDeviation,
            volatilityThreshold: volatilityThreshold,
            volumePercentile: volumePercentile,
            twapPeriod: twapPeriod,
            compoundFees: compoundFees,
            bridgeType: bridgeType
        }));
        emit StrategyRegistered(msg.sender, positionId, strategyType, rangeWidth, compoundFees, bridgeType);
    }

    function performCrossChainAdjustment(
        uint256 positionId,
        int24 newTickLower,
        int24 newTickUpper,
        uint256 newLiquidity,
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant {
        if (pool.trustedRemotePools(dstChainId).length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType(bridgeType);
        (, , , uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

        _aggregateFees(positionId, owner);
        uint256 fee0 = fallbackFees0[positionId];
        uint256 fee1 = fallbackFees1[positionId];
        bytes memory payload = abi.encode(positionId, newTickLower, newTickUpper, newLiquidity, fallbackActive, fee0, fee1);
        string memory dstAxelarChain = pool.chainIdToAxelarChain(dstChainId);

        try pool.batchCrossChainMessages{value: msg.value}(dstChainId, payload, adapterParams) {
            Strategy storage strategy = _getStrategy(positionId);
            if (fallbackActive) {
                if (strategy.compoundFees) {
                    compoundFallbackFees(positionId);
                } else {
                    address destination = positionManager.feeDestinations(owner);
                    if (destination != address(0)) {
                        positionManager.collectAndBridgeFees{value: msg.value}(positionId, dstChainId, bridgeType, adapterParams);
                    } else {
                        collectFallbackFees(positionId);
                    }
                }
                pool.exitFallbackPool(positionId);
            }
            emit CrossChainAdjustmentSent(positionId, dstChainId, newTickLower, newTickUpper, fallbackActive, fee0, fee1, bridgeType);
        } catch {
            uint256 messageId = failedMessageCount++;
            failedMessages[messageId] = FailedCrossChainMessage({
                positionId: positionId,
                dstChainId: dstChainId,
                dstAxelarChain: dstAxelarChain,
                payload: payload,
                adapterParams: adapterParams,
                retries: 0,
                nextRetryTimestamp: block.timestamp + 1 hours,
                fallbackActive: fallbackActive,
                fee0: fee0,
                fee1: fee1
            });
            emit FailedMessageStored(messageId, dstChainId, positionId);
        }
    }

    function batchCrossChainAdjustments(
        uint256[] calldata positionIds,
        int24[] calldata newTickLowers,
        int24[] calldata newTickUppers,
        uint256[] calldata newLiquidities,
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable nonReentrant {
        uint256 count = positionIds.length;
        if (count == 0 || count > maxAdjustmentsPerUpkeep || count != newTickLowers.length || count != newLiquidities.length) revert InvalidBatchSize(count);
        if (pool.trustedRemotePools(dstChainId).length == 0) revert InvalidChainId(dstChainId);
        if (tokenBridges[bridgeType] == address(0)) revert InvalidBridgeType(bridgeType);

        uint256 totalFee0;
        uint256 totalFee1;
        bytes[] memory payloads = new bytes[](count);
        string memory dstAxelarChain = pool.chainIdToAxelarChain(dstChainId);

        for (uint256 i = 0; i < count; i++) {
            uint256 positionId = positionIds[i];
            (, , , uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
            if (liquidity == 0) revert InsufficientLiquidity(liquidity);
            if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

            _aggregateFees(positionId, owner);
            uint256 fee0 = fallbackFees0[positionId];
            uint256 fee1 = fallbackFees1[positionId];
            totalFee0 += fee0;
            totalFee1 += fee1;
            payloads[i] = abi.encode(positionId, newTickLowers[i], newTickUppers[i], newLiquidities[i], fallbackActive, fee0, fee1);
        }

        try pool.batchCrossChainMessages{value: msg.value}(dstChainId, payloads[0], adapterParams) {
            for (uint256 i = 0; i < count; i++) {
                uint256 positionId = positionIds[i];
                Strategy storage strategy = _getStrategy(positionId);
                (, , , , bool fallbackActive, address owner) = pool.positions(positionId);
                if (fallbackActive) {
                    if (strategy.compoundFees) {
                        compoundFallbackFees(positionId);
                    } else {
                        address destination = positionManager.feeDestinations(owner);
                        if (destination != address(0)) {
                            positionManager.collectAndBridgeFees{value: msg.value / count}(positionId, dstChainId, bridgeType, adapterParams);
                        } else {
                            collectFallbackFees(positionId);
                        }
                    }
                    pool.exitFallbackPool(positionId);
                }
                emit CrossChainAdjustmentSent(positionId, dstChainId, newTickLowers[i], newTickUppers[i], fallbackActive, fallbackFees0[positionId], fallbackFees1[positionId], bridgeType);
            }
            if (totalFee0 > FEE_AGGREGATION_THRESHOLD || totalFee1 > FEE_AGGREGATION_THRESHOLD) {
                positionManager.batchBridgeFees{value: msg.value / count}(positionIds, dstChainId, bridgeType, adapterParams);
                emit BatchFeesBridged(msg.sender, positionIds, totalFee0, totalFee1, dstChainId, bridgeType);
            }
        } catch {
            for (uint256 i = 0; i < count; i++) {
                uint256 messageId = failedMessageCount++;
                failedMessages[messageId] = FailedCrossChainMessage({
                    positionId: positionIds[i],
                    dstChainId: dstChainId,
                    dstAxelarChain: dstAxelarChain,
                    payload: payloads[i],
                    adapterParams: adapterParams,
                    retries: 0,
                    nextRetryTimestamp: block.timestamp + 1 hours,
                    fallbackActive: pool.inFallbackPool(positionIds[i]),
                    fee0: fallbackFees0[positionIds[i]],
                    fee1: fallbackFees1[positionIds[i]]
                });
                emit FailedMessageStored(messageId, dstChainId, positionIds[i]);
            }
        }
    }

    function retryFailedMessage(uint256 messageId) external payable nonReentrant {
        FailedCrossChainMessage storage message = failedMessages[messageId];
        if (message.retries >= pool.MAX_RETRIES()) revert MaxRetriesExceeded(messageId);
        if (message.nextRetryTimestamp == 0) revert MessageNotFailed(messageId);
        if (block.timestamp < message.nextRetryTimestamp) revert RetryNotReady(messageId, message.nextRetryTimestamp);
        if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

        unchecked {
            message.retries++;
            message.nextRetryTimestamp = block.timestamp + (1 hours * (2 ** message.retries));
        }

        try pool.batchCrossChainMessages{value: msg.value}(message.dstChainId, message.payload, message.adapterParams) {
            Strategy storage strategy = _getStrategy(message.positionId);
            if (message.fallbackActive) {
                if (strategy.compoundFees) {
                    compoundFallbackFees(message.positionId);
                } else {
                    (, , , , , address owner) = pool.positions(message.positionId);
                    address destination = positionManager.feeDestinations(owner);
                    if (destination != address(0)) {
                        positionManager.collectAndBridgeFees{value: msg.value}(message.positionId, message.dstChainId, strategy.bridgeType, message.adapterParams);
                    } else {
                        collectFallbackFees(message.positionId);
                    }
                }
                pool.exitFallbackPool(message.positionId);
            }
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries);
            delete failedMessages[messageId];
            failedMessageCount--;
            emit FailedMessageRecovered(messageId, message.dstChainId);
        } catch {
            emit FailedMessageStored(messageId, message.dstChainId, message.positionId);
        }
    }

    function collectFallbackFees(uint256 positionId) public nonReentrant {
        (, , , uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
        if (!fallbackActive) return;
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        if (msg.sender != owner && msg.sender != address(this)) revert Unauthorized();

        uint256 amount0 = fallbackFees0[positionId];
        uint256 amount1 = fallbackFees1[positionId];
        if (amount0 == 0 && amount1 == 0) return;

        if (amount0 > 0) {
            pool.transferToken(pool.tokenA(), owner, amount0);
            aggregatedFees[owner].total0 += amount0;
            fallbackFees0[positionId] = 0;
        }
        if (amount1 > 0) {
            pool.transferToken(pool.tokenB(), owner, amount1);
            aggregatedFees[owner].total1 += amount1;
            fallbackFees1[positionId] = 0;
        }

        emit FallbackFeesCollected(positionId, amount0, amount1);
        emit FeesAggregated(owner, positionId, amount0, amount1);
    }

    function compoundFallbackFees(uint256 positionId) public nonReentrant {
        (, int24 tickLower, int24 tickUpper, uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
        if (!fallbackActive) return;
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        if (msg.sender != owner && msg.sender != address(this)) revert Unauthorized();

        uint256 amount0 = fallbackFees0[positionId];
        uint256 amount1 = fallbackFees1[positionId];
        if (amount0 == 0 && amount1 == 0) return;

        uint256 additionalLiquidity = pool.getLiquidityForAmounts(tickLower, tickUpper, amount0, amount1);
        pool.adjustPosition(positionId, tickLower, tickUpper, liquidity + additionalLiquidity);

        aggregatedFees[owner].total0 += amount0;
        aggregatedFees[owner].total1 += amount1;
        fallbackFees0[positionId] = 0;
        fallbackFees1[positionId] = 0;

        emit FallbackFeesCompounded(positionId, amount0, amount1);
        emit FeesAggregated(owner, positionId, amount0, amount1);
    }

    function batchExitFallbackPool(uint256[] memory positionIds, uint256 count) public nonReentrant {
        if (count == 0 || count > maxAdjustmentsPerUpkeep || positionIds.length < count) revert InvalidBatchSize(count);
        if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

        uint256 requiredGas = count * MIN_GAS_PER_EXIT;
        if (gasleft() < requiredGas) revert InsufficientGas(requiredGas, gasleft());

        uint256[] memory validPositionIds = new uint256[](count);
        uint256 validCount = 0;

        for (uint256 i = 0; i < count; i++) {
            (, , , uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionIds[i]);
            if (liquidity == 0 || !fallbackActive) continue;
            _aggregateFees(positionIds[i], owner);
            validPositionIds[validCount] = positionIds[i];
            validCount++;
        }

        if (validCount > 0) {
            requiredGas = validCount * MIN_GAS_PER_EXIT;
            if (gasleft() < requiredGas) revert InsufficientGas(requiredGas, gasleft());

            uint256[] memory exitPositionIds = new uint256[](validCount);
            for (uint256 i = 0; i < validCount; i++) {
                exitPositionIds[i] = validPositionIds[i];
                pool.exitFallbackPool(validPositionIds[i]);
            }
            emit BatchFallbackPoolExited(exitPositionIds);
        }
    }

    function updateFallbackFeeConfig(
        uint256 newBaseFee,
        uint256 newMaxFee,
        uint256 newVolatilityMultiplier,
        uint256 newDurationThreshold
    ) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        if (newBaseFee > newMaxFee || newBaseFee < 10 || newMaxFee > 1000) revert InvalidFeeConfig(newBaseFee, newMaxFee);
        baseFallbackFeeRate = newBaseFee;
        maxFallbackFeeRate = newMaxFee;
        volatilityFeeMultiplier = newVolatilityMultiplier;
        durationFeeThreshold = newDurationThreshold;
        emit FallbackFeeConfigUpdated(newBaseFee, newMaxFee, newVolatilityMultiplier, newDurationThreshold);
    }

    function getDynamicFallbackFeeRate(uint256 positionId) public view returns (uint256) {
        uint256 feeRate = baseFallbackFeeRate;
        uint256 emaVolatility = pool.emaVolatility();
        uint256 volatilityAdjustment = (emaVolatility * volatilityFeeMultiplier) / 1e18;
        feeRate += volatilityAdjustment;

        uint256 entryTime = fallbackEntryTimestamp[positionId];
        if (entryTime > 0 && block.timestamp >= entryTime + durationFeeThreshold) {
            feeRate += baseFallbackFeeRate / 2;
        }

        return feeRate > maxFallbackFeeRate ? maxFallbackFeeRate : feeRate;
    }

    function _calculateNewTicks(
        Strategy memory strategy,
        uint256 currentPrice,
        uint256 emaVolatility,
        uint256 reserveA,
        uint256 reserveB
    ) internal view returns (int24 newTickLower, int24 newTickUpper) {
        uint24 tickSpacing = pool.TICK_SPACING();
        int24 currentTick = _priceToTick(currentPrice);
        uint24 rangeWidth;

        if (strategy.strategyType == StrategyType.Fixed) {
            rangeWidth = strategy.rangeWidth;
        } else if (strategy.strategyType == StrategyType.Volatility) {
            uint256 oracleVolatility = getOracleVolatility(address(pool));
            uint256 combinedVolatility = (emaVolatility + oracleVolatility) / 2;
            rangeWidth = combinedVolatility > (strategy.volatilityThreshold > 0 ? strategy.volatilityThreshold : pool.volatilityThreshold())
                ? 1000
                : 200;
        } else if (strategy.strategyType == StrategyType.Volume) {
            rangeWidth = _getVolumeBasedRange(strategy.volumePercentile, reserveA, reserveB);
        } else if (strategy.strategyType == StrategyType.Predictive) {
            rangeWidth = _getPredictiveRange(strategy.twapPeriod, currentPrice);
        }

        int24 rangeTicks;
        unchecked {
            rangeTicks = int24((rangeWidth * 100) / tickSpacing);
        }
        newTickLower = ((currentTick - rangeTicks) / int24(tickSpacing)) * int24(tickSpacing);
        newTickUpper = ((currentTick + rangeTicks) / int24(tickSpacing)) * int24(tickSpacing);

        if (newTickLower < TickMath.MIN_TICK) newTickLower = TickMath.MIN_TICK;
        if (newTickUpper > TickMath.MAX_TICK) newTickUpper = TickMath.MAX_TICK;
    }

    function _getVolumeBasedRange(uint24 volumePercentile, uint256 reserveA, uint256 reserveB) internal view returns (uint24) {
        uint256 currentWindow = block.timestamp / volumeWindow;
        uint256 totalVolume = volumeData[address(pool)][currentWindow];
        return volumePercentile > 80 ? 800 : 400;
    }

    function _getPredictiveRange(uint24 twapPeriod, uint256 currentPrice) internal view returns (uint24) {
        uint256 twapPrice = _getTWAP(twapPeriod);
        uint256 priceDiff = twapPrice > currentPrice ? twapPrice - currentPrice : currentPrice - twapPrice;
        return priceDiff > currentPrice / 100 ? 1000 : 500;
    }

    function _getTWAP(uint24 twapPeriod) internal view returns (uint256) {
        uint256 retryCount = 0;
        uint256 maxRetries = 3;

        while (retryCount < maxRetries) {
            try IPriceOracle(priceOracle).getCurrentPairPrice(address(pool.tokenA()), address(pool.tokenB())) returns (uint256 price, bool isCached) {
                (, address tokenA,,,,,,,) = IPriceOracle(priceOracle).assetConfigs(address(pool));
                bool isToken0Base = tokenA == address(pool.tokenA());
                price = isToken0Base ? price : 1e36 / price;
                if (isCached) {
                    emit CachedPriceUsed(address(pool), price, block.timestamp);
                }
                return price;
            } catch {
                retryCount++;
                if (retryCount == maxRetries) {
                    for (uint256 i = 0; i < fallbackPriceOracles.length; i++) {
                        try IPriceOracle(fallbackPriceOracles[i]).getCurrentPairPrice(address(pool.tokenA()), address(pool.tokenB())) returns (uint256 price, bool isCached) {
                            (, address tokenA,,,,,,,) = IPriceOracle(fallbackPriceOracles[i]).assetConfigs(address(pool));
                            bool isToken0Base = tokenA == address(pool.tokenA());
                            price = isToken0Base ? price : 1e36 / price;
                            if (isCached) {
                                emit CachedPriceUsed(address(pool), price, block.timestamp);
                            }
                            return price;
                        } catch {
                            continue;
                        }
                    }
                    revert OracleFailure();
                }
            }
        }
        revert OracleFailure();
    }

    function _isNearBoundary(uint256 currentPrice, int24 tickLower, int24 tickUpper, uint24 minPriceDeviation)
        internal
        view
        returns (bool)
    {
        uint256 lowerPrice = _tickToPrice(tickLower);
        uint256 upperPrice = _tickToPrice(tickUpper);
        uint256 deviation = (currentPrice * minPriceDeviation) / 10000;
        return currentPrice <= lowerPrice + deviation || currentPrice >= upperPrice - deviation;
    }

    function _tickToPrice(int24 tick) internal pure returns (uint256) {
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        UD60x18 price = ud(uint256(sqrtPriceX96) * uint256(sqrtPriceX96)).div(ud(1 << 192));
        return price.unwrap();
    }

    function _priceToTick(uint256 price) internal pure returns (int24) {
        UD60x18 sqrtPrice = ud(price).sqrt();
        uint160 sqrtPriceX96 = uint160(sqrtPrice.mul(ud(1 << 96)).unwrap());
        return TickMath.getTickAtSqrtRatio(sqrtPriceX96);
    }

    function _aggregateFees(uint256 positionId, address owner) internal {
        uint256 amount0 = fallbackFees0[positionId];
        uint256 amount1 = fallbackFees1[positionId];
        if (amount0 > 0 || amount1 > 0) {
            aggregatedFees[owner].total0 += amount0;
            aggregatedFees[owner].total1 += amount1;
            emit FeesAggregated(owner, positionId, amount0, amount1);
        }
    }

    function updateVolume(uint256 amountIn, uint256 amountOut, uint256 fee0, uint256 fee1, uint256 positionId) external {
        if (msg.sender != address(pool)) revert Unauthorized();
        uint256 currentWindow = block.timestamp / volumeWindow;
        bool fallbackActive = pool.inFallbackPool(positionId);
        if (fallbackActive && fallbackEntryTimestamp[positionId] == 0) {
            fallbackEntryTimestamp[positionId] = block.timestamp;
        }
        unchecked {
            volumeData[address(pool)][currentWindow] += amountIn + amountOut;
            if (fee0 > 0) {
                uint256 adjustedFee0 = (fee0 * getDynamicFallbackFeeRate(positionId)) / 10000;
                fallbackFees0[positionId] += adjustedFee0;
                aggregatedFees[msg.sender].total0 += adjustedFee0;
            }
            if (fee1 > 0) {
                uint256 adjustedFee1 = (fee1 * getDynamicFallbackFeeRate(positionId)) / 10000;
                fallbackFees1[positionId] += adjustedFee1;
                aggregatedFees[msg.sender].total1 += adjustedFee1;
            }
        }
        emit FeesAggregated(msg.sender, positionId, fee0, fee1);
    }

    function updateOracles(address newPrimaryOracle, address[] calldata newFallbackOracles) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        if (newPrimaryOracle == address(0)) revert InvalidAddress(newPrimaryOracle, "Invalid oracle");
        priceOracle = newPrimaryOracle;
        fallbackPriceOracles = newFallbackOracles;
    }

    function updateTokenBridge(uint8 bridgeType, address newBridge) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        if (newBridge == address(0)) revert InvalidAddress(newBridge, "Invalid bridge");
        tokenBridges[bridgeType] = newBridge;
        emit TokenBridgeUpdated(bridgeType, newBridge);
    }

    function pauseAdjustmentsForAsset(address asset) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        if (IPriceOracle(priceOracle).emergencyOverrideActive(asset)) {
            pausedAssets[asset] = true;
            emit AdjustmentsPaused(asset, block.timestamp);
        }
    }

    function resumeAdjustmentsForAsset(address asset) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        pausedAssets[asset] = false;
        emit AdjustmentsResumed(asset, block.timestamp);
    }

    function getPoolConstants() external view returns (uint256 maxRetries, uint256 tickSpacing) {
        maxRetries = pool.MAX_RETRIES();
        tickSpacing = pool.TICK_SPACING();
    }

    function getAggregatedFees(address owner) external view returns (uint256 total0, uint256 total1) {
        AggregatedFees memory fees = aggregatedFees[owner];
        return (fees.total0, fees.total1);
    }

    function _getStrategy(uint256 positionId) internal view returns (Strategy storage) {
        for (uint256 i = 0; i < strategies[msg.sender].length; i++) {
            if (strategies[msg.sender][i].positionId == positionId) {
                return strategies[msg.sender][i];
            }
        }
        revert Unauthorized();
    }
}
