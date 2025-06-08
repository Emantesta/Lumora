// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@chainlink/contracts/src/v0.8/interfaces/KeeperCompatibleInterface.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "./AMMPool.sol";
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
/// @notice Automates liquidity position adjustments for AMMPool with Chainlink Keeper integration
/// @dev Integrates with PriceOracle for TWAP, supports Fallback Pool, Cross-Chain, and multiple strategies
contract PositionAdjuster is KeeperCompatibleInterface, ReentrancyGuardUpgradeable {
    AMMPool public immutable pool;
    address public immutable priceOracle; // Primary price oracle
    address[] public fallbackPriceOracles; // Fallback oracles
    mapping(address => Strategy[]) public strategies;
    mapping(address => bool) public pausedAssets; // Assets paused due to emergency overrides
    uint256 public maxAdjustmentsPerUpkeep = 10; // Gas limit per upkeep
    uint256 public volumeWindow = 1 hours; // Volume tracking period
    mapping(address => mapping(uint256 => uint256)) public volumeData; // Pool => timestamp => volume
    mapping(uint256 => FailedCrossChainMessage) public failedMessages; // Cross-chain message retry storage
    uint256 public failedMessageCount; // Counter for failed messages
    mapping(uint256 => uint256) public fallbackFees0; // Accumulated fees for token0 in fallback pool
    mapping(uint256 => uint256) public fallbackFees1; // Accumulated fees for token1 in fallback pool
    mapping(uint256 => uint256) public fallbackEntryTimestamp; // Timestamp when position entered fallback pool
    uint256 public baseFallbackFeeRate = 20; // Base fee rate in basis points (0.2%)
    uint256 public maxFallbackFeeRate = 100; // Max fee rate in basis points (1%)
    uint256 public volatilityFeeMultiplier = 2; // Multiplier for volatility-based fees
    uint256 public durationFeeThreshold = 1 days; // Duration threshold for fee adjustment
    uint256 public constant MIN_GAS_PER_EXIT = 100_000; // Minimum gas required per exitFallbackPool call

    enum StrategyType { Fixed, Volatility, Volume, Predictive }

    struct Strategy {
        uint256 positionId; // NFT position ID
        StrategyType strategyType; // Strategy type
        uint24 rangeWidth; // Basis points (e.g., 500 = 5%)
        uint24 minPriceDeviation; // Trigger adjustment (basis points)
        uint24 volatilityThreshold; // Custom threshold for Volatility strategy
        uint24 volumePercentile; // Target volume percentile (e.g., 80%)
        uint24 twapPeriod; // TWAP period for Predictive strategy (seconds)
        bool compoundFees; // Whether to compound fees back into liquidity
    }

    struct FailedCrossChainMessage {
        uint256 positionId;
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 nextRetryTimestamp;
        bool fallbackActive; // Explicitly track fallback pool status
        uint256 fee0; // Accumulated token0 fees
        uint256 fee1; // Accumulated token1 fees
    }

    // Events
    event StrategyRegistered(address indexed owner, uint256 positionId, StrategyType strategyType, uint24 rangeWidth, bool compoundFees);
    event PositionAdjusted(uint256 indexed positionId, int24 newTickLower, int24 newTickUpper);
    event CrossChainAdjustmentSent(uint256 indexed positionId, uint16 dstChainId, int24 newTickLower, int24 newTickUpper, bool fallbackActive, uint256 fee0, uint256 fee1);
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

    constructor(address _pool, address _priceOracle, address[] memory _fallbackPriceOracles) {
        pool = AMMPool(_pool);
        priceOracle = _priceOracle;
        fallbackPriceOracles = _fallbackPriceOracles;
        __ReentrancyGuard_init();
    }

    /// @notice Checks if upkeep is needed for position adjustments
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        Strategy[] memory userStrategies = strategies[msg.sender];
        uint256[] memory positionIds = new uint256[](maxAdjustmentsPerUpkeep);
        int24[] memory newTickLowers = new int24[](maxAdjustmentsPerUpkeep);
        int24[] memory newTickUppers = new int24[](maxAdjustmentsPerUpkeep);
        uint256 count;

        // Cache reserves and volatility to save gas
        (uint256 reserveA, uint256 reserveB, , ) = pool.getReserves();
        uint256 currentPrice = (reserveB * 1e18) / reserveA;
        uint256 emaVolatility = pool.emaVolatility();

        for (uint256 i = 0; i < userStrategies.length && count < maxAdjustmentsPerUpkeep; i++) {
            Strategy memory strategy = userStrategies[i];
            (, int24 tickLower, int24 tickUpper, uint256 liquidity, bool fallbackActive, ) = pool.positions(strategy.positionId);
            if (liquidity == 0) continue; // Skip empty positions
            if (pausedAssets[address(pool)]) continue; // Skip paused assets

            bool isOutOfRange = currentPrice < _tickToPrice(tickLower) || currentPrice > _tickToPrice(tickUpper);
            bool isNearBoundary = _isNearBoundary(currentPrice, tickLower, tickUpper, strategy.minPriceDeviation);

            // Prioritize fallbackActive positions
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

    /// @notice Performs upkeep by adjusting positions
    function performUpkeep(bytes calldata performData) external override nonReentrant {
        (uint256[] memory positionIds, int24[] memory newTickLowers, int24[] memory newTickUppers, uint256 count)
            = abi.decode(performData, (uint256[], int24[], int24[], uint256));

        // Batch exit fallback pool with gas limit check
        batchExitFallbackPool(positionIds, count);

        for (uint256 i = 0; i < count; i++) {
            uint256 positionId = positionIds[i];
            (, int24 tickLower, int24 tickUpper, uint256 liquidity, bool fallbackActive, ) = pool.positions(positionId);
            if (liquidity == 0) continue;
            if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

            if (tickLower != newTickLowers[i] || tickUpper != newTickUppers[i]) {
                // Collect or compound fees based on strategy
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

    /// @notice Registers a new strategy for a position
    function registerStrategy(
        uint256 positionId,
        StrategyType strategyType,
        uint24 rangeWidth,
        uint24 minPriceDeviation,
        uint24 volatilityThreshold,
        uint24 volumePercentile,
        uint24 twapPeriod,
        bool compoundFees
    ) external nonReentrant {
        if (uint8(strategyType) > uint8(StrategyType.Predictive)) revert InvalidStrategyType();
        pool.authorizeAdjuster(positionId, address(this));
        strategies[msg.sender].push(Strategy({
            positionId: positionId,
            strategyType: strategyType,
            rangeWidth: rangeWidth,
            minPriceDeviation: minPriceDeviation,
            volatilityThreshold: volatilityThreshold,
            volumePercentile: volumePercentile,
            twapPeriod: twapPeriod,
            compoundFees: compoundFees
        }));
        emit StrategyRegistered(msg.sender, positionId, strategyType, rangeWidth, compoundFees);
    }

    /// @notice Performs a cross-chain position adjustment with fallback pool status and fees
    function performCrossChainAdjustment(
        uint256 positionId,
        int24 newTickLower,
        int24 newTickUpper,
        uint256 newLiquidity,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant {
        if (pool.trustedRemotePools(dstChainId).length == 0) revert InvalidChainId(dstChainId);
        (, , , uint256 liquidity, bool fallbackActive, ) = pool.positions(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

        // Include fallback fees and status in payload
        uint256 fee0 = fallbackFees0[positionId];
        uint256 fee1 = fallbackFees1[positionId];
        bytes memory payload = abi.encode(positionId, newTickLower, newTickUpper, newLiquidity, fallbackActive, fee0, fee1);
        string memory dstAxelarChain = pool.chainIdToAxelarChain(dstChainId);

        try pool.batchCrossChainMessages{value: msg.value}(dstChainId, payload, adapterParams) {
            // Handle fees based on strategy
            Strategy storage strategy = _getStrategy(positionId);
            if (fallbackActive) {
                if (strategy.compoundFees) {
                    compoundFallbackFees(positionId);
                } else {
                    collectFallbackFees(positionId);
                }
                pool.exitFallbackPool(positionId);
            }
            emit CrossChainAdjustmentSent(positionId, dstChainId, newTickLower, newTickUpper, fallbackActive, fee0, fee1);
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

    /// @notice Retries a failed cross-chain message
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
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries);
            if (message.fallbackActive) {
                Strategy storage strategy = _getStrategy(message.positionId);
                if (strategy.compoundFees) {
                    compoundFallbackFees(message.positionId);
                } else {
                    collectFallbackFees(message.positionId);
                }
                pool.exitFallbackPool(message.positionId);
            }
            delete failedMessages[messageId];
            failedMessageCount--;
            emit FailedMessageRecovered(messageId, message.dstChainId);
        } catch {
            emit FailedMessageStored(messageId, message.dstChainId, message.positionId);
        }
    }

    /// @notice Collects fees accumulated in the fallback pool for a position
    function collectFallbackFees(uint256 positionId) public nonReentrant {
        (, , , uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
        if (!fallbackActive) return;
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        if (msg.sender != owner && msg.sender != address(this)) revert Unauthorized();

        uint256 amount0 = fallbackFees0[positionId];
        uint256 amount1 = fallbackFees1[positionId];
        if (amount0 == 0 && amount1 == 0) return;

        // Transfer fees to the position owner
        if (amount0 > 0) {
            pool.transferToken(pool.tokenA(), owner, amount0);
            fallbackFees0[positionId] = 0;
        }
        if (amount1 > 0) {
            pool.transferToken(pool.tokenB(), owner, amount1);
            fallbackFees1[positionId] = 0;
        }

        emit FallbackFeesCollected(positionId, amount0, amount1);
    }

    /// @notice Compounds fees accumulated in the fallback pool back into liquidity
    function compoundFallbackFees(uint256 positionId) public nonReentrant {
        (, int24 tickLower, int24 tickUpper, uint256 liquidity, bool fallbackActive, address owner) = pool.positions(positionId);
        if (!fallbackActive) return;
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        if (msg.sender != owner && msg.sender != address(this)) revert Unauthorized();

        uint256 amount0 = fallbackFees0[positionId];
        uint256 amount1 = fallbackFees1[positionId];
        if (amount0 == 0 && amount1 == 0) return;

        // Re-add fees as liquidity to the concentrated pool
        uint256 additionalLiquidity = pool.getLiquidityForAmounts(tickLower, tickUpper, amount0, amount1);
        pool.adjustPosition(positionId, tickLower, tickUpper, liquidity + additionalLiquidity);

        // Reset fees
        fallbackFees0[positionId] = 0;
        fallbackFees1[positionId] = 0;

        emit FallbackFeesCompounded(positionId, amount0, amount1);
    }

    /// @notice Batches multiple exitFallbackPool calls with gas limit checks
    function batchExitFallbackPool(uint256[] memory positionIds, uint256 count) public nonReentrant {
        if (count == 0 || count > maxAdjustmentsPerUpkeep || positionIds.length < count) revert InvalidBatchSize(count);
        if (pausedAssets[address(pool)]) revert AssetPaused(address(pool));

        // Check gas availability
        uint256 requiredGas = count * MIN_GAS_PER_EXIT;
        if (gasleft() < requiredGas) revert InsufficientGas(requiredGas, gasleft());

        uint256[] memory validPositionIds = new uint256[](count);
        uint256 validCount = 0;

        for (uint256 i = 0; i < count; i++) {
            (, , , uint256 liquidity, bool fallbackActive, ) = pool.positions(positionIds[i]);
            if (liquidity == 0 || !fallbackActive) continue;
            validPositionIds[validCount] = positionIds[i];
            validCount++;
        }

        if (validCount > 0) {
            // Recheck gas for actual valid positions
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

    /// @notice Updates fallback pool fee configuration
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

    /// @notice Calculates dynamic fee rate for a position in the fallback pool
    function getDynamicFallbackFeeRate(uint256 positionId) public view returns (uint256) {
        uint256 feeRate = baseFallbackFeeRate;
        uint256 emaVolatility = pool.emaVolatility();
        uint256 volatilityAdjustment = (emaVolatility * volatilityFeeMultiplier) / 1e18;
        feeRate += volatilityAdjustment;

        // Adjust fee based on position duration in fallback pool
        uint256 entryTime = fallbackEntryTimestamp[positionId];
        if (entryTime > 0 && block.timestamp >= entryTime + durationFeeThreshold) {
            feeRate += baseFallbackFeeRate / 2; // Increase by 50% of base fee for long duration
        }

        return feeRate > maxFallbackFeeRate ? maxFallbackFeeRate : feeRate;
    }

    /// @notice Calculates new tick range based on strategy
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
                ? 1000 // ±10%
                : 200; // ±2%
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

    /// @notice Calculates volume-based range width
    function _getVolumeBasedRange(uint24 volumePercentile, uint256 reserveA, uint256 reserveB) internal view returns (uint24) {
        uint256 currentWindow = block.timestamp / volumeWindow;
        uint256 totalVolume = volumeData[address(pool)][currentWindow];
        return volumePercentile > 80 ? 800 : 400; // ±8% or ±4%
    }

    /// @notice Calculates predictive range based on TWAP
    function _getPredictiveRange(uint24 twapPeriod, uint256 currentPrice) internal view returns (uint24) {
        uint256 twapPrice = _getTWAP(twapPeriod);
        uint256 priceDiff = twapPrice > currentPrice ? twapPrice - currentPrice : currentPrice - twapPrice;
        return priceDiff > currentPrice / 100 ? 1000 : 500; // ±10% or ±5%
    }

    /// @notice Fetches TWAP from PriceOracle with failover
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

    /// @notice Checks if price is near position boundaries
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

    /// @notice Converts tick to price
    function _tickToPrice(int24 tick) internal pure returns (uint256) {
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        UD60x18 price = ud(uint256(sqrtPriceX96) * uint256(sqrtPriceX96)).div(ud(1 << 192));
        return price.unwrap();
    }

    /// @notice Converts price to tick
    function _priceToTick(uint256 price) internal pure returns (int24) {
        UD60x18 sqrtPrice = ud(price).sqrt();
        uint160 sqrtPriceX96 = uint160(sqrtPrice.mul(ud(1 << 96)).unwrap());
        return TickMath.getTickAtSqrtRatio(sqrtPriceX96);
    }

    /// @notice Updates volume data, fallback fees, and entry timestamp
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
            }
            if (fee1 > 0) {
                uint256 adjustedFee1 = (fee1 * getDynamicFallbackFeeRate(positionId)) / 10000;
                fallbackFees1[positionId] += adjustedFee1;
            }
        }
    }

    /// @notice Updates oracle addresses
    function updateOracles(address newPrimaryOracle, address[] calldata newFallbackOracles) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        if (newPrimaryOracle == address(0)) revert InvalidAddress(newPrimaryOracle, "Invalid oracle");
        priceOracle = newPrimaryOracle;
        fallbackPriceOracles = newFallbackOracles;
    }

    /// @notice Fetches volatility from PriceOracle
    function getOracleVolatility(address asset) public view returns (uint256) {
        (, , , , , , , , uint256 volatilityIndex) = IPriceOracle(priceOracle).assetConfigs(asset);
        return volatilityIndex == 0 ? 1e18 : volatilityIndex;
    }

    /// @notice Pauses adjustments for an asset if emergency override is active
    function pauseAdjustmentsForAsset(address asset) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        if (IPriceOracle(priceOracle).emergencyOverrideActive(asset)) {
            pausedAssets[asset] = true;
            emit AdjustmentsPaused(asset, block.timestamp);
        }
    }

    /// @notice Resumes adjustments for an asset
    function resumeAdjustmentsForAsset(address asset) external {
        if (msg.sender != pool.governance()) revert Unauthorized();
        pausedAssets[asset] = false;
        emit AdjustmentsResumed(asset, block.timestamp);
    }

    /// @notice Gets pool constants
    function getPoolConstants() external view returns (uint256 maxRetries, uint256 tickSpacing) {
        maxRetries = pool.MAX_RETRIES();
        tickSpacing = pool.TICK_SPACING();
    }

    /// @notice Helper to find a strategy for a position
    function _getStrategy(uint256 positionId) internal view returns (Strategy storage) {
        for (uint256 i = 0; i < strategies[msg.sender].length; i++) {
            if (strategies[msg.sender][i].positionId == positionId) {
                return strategies[msg.sender][i];
            }
        }
        revert Unauthorized();
    }
}
