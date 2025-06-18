// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {IPositionManager} from "./Interfaces.sol";
import {TickMathLibrary} from "./TickMathLibrary.sol";
import {AMMPool} from "./AMMPool.sol";

/// @title ConcentratedLiquidity - Manages Uniswap V3-style concentrated liquidity positions and ticks
/// @notice Handles position creation, updates, fee collection, and tick management for AMM pool
/// @dev Interacts with AMMPool for state access and event emission, secured with access control
contract ConcentratedLiquidity is ReentrancyGuard {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Reference to main AMMPool contract
    AMMPool public immutable pool;
    // Tick spacing from AMMPool
    uint24 public immutable TICK_SPACING;

    // Structs (extracted from AMMPool)
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

    struct Tick {
        uint256 liquidityGross;
        int256 liquidityNet;
        uint256 feeGrowthOutside0X128;
        uint256 feeGrowthOutside1X128;
    }

    // Constructor: Initializes pool reference and tick spacing
    constructor(address _pool) {
        if (_pool == address(0)) revert InvalidAddress(_pool, "Invalid pool address");
        pool = AMMPool(_pool);
        TICK_SPACING = pool.TICK_SPACING();
    }

    // --- Errors (extracted and related to ticks, positions, liquidity) ---
    error Unauthorized();
    error InvalidTick(int24 tick);
    error InvalidTickRange(int24 tickLower, int24 tickUpper);
    error PositionNotFound(uint256 positionId);
    error InsufficientLiquidity(uint256 liquidity);
    error TickNotInitialized(int24 tick);
    error InvalidAmount(uint256 amountA, uint256 amountB);
    error InvalidAddress(address addr, string message);
    error PriceOutOfRange();

    // --- Modifiers ---
    modifier onlyPool() {
        if (msg.sender != address(pool)) revert Unauthorized();
        _;
    }

    // --- External Functions ---

    /// @notice Adds liquidity to a concentrated position within a tick range
    /// @param provider The address providing liquidity
    /// @param tickLower The lower tick of the position
    /// @param tickUpper The upper tick of the position
    /// @param amountA Amount of tokenA to add
    /// @param amountB Amount of tokenB to add
    /// @return positionId The ID of the created position
    function addConcentratedLiquidity(
        address provider,
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB
    ) external nonReentrant onlyPool returns (uint256 positionId) {
        // Validate inputs
        if (provider == address(0)) revert InvalidAddress(provider, "Invalid provider address");
        if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);

        // Get current tick from AMMPool
        int24 currentTick = pool.getcurrentTick();
        bool isInRange = _isInRange(currentTick, tickLower, tickUpper);

        // Calculate liquidity for given amounts
        uint256 liquidity = _getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB, currentTick);

        if (liquidity == 0) revert InsufficientLiquidity(liquidity);

        // Transfer tokens to AMMPool
        if (amountA > 0) {
            IERC20Upgradeable(pool.tokenA()).safeTransferFrom(provider, address(pool), amountA);
        }
        if (amountB > 0) {
            IERC20Upgradeable(pool.tokenB()).safeTransferFrom(provider, address(pool), amountB);
        }

        // Create position
        positionId = pool.positionCounter();
        AMMPool.Position storage position = pool.positions(positionId);
        position.owner = provider;
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = liquidity;
        position.feeGrowthInside0LastX128 = isInRange ? pool.feeGrowthGlobal0X128() : 0;
        position.feeGrowthInside1LastX128 = isInRange ? pool.feeGrowthGlobal1X128() : 0;

        // Increment position counter in AMMPool
        pool.positionCounter(positionId + 1);

        // Update ticks
        _updateTick(tickLower, int256(liquidity), true);
        _updateTick(tickUpper, int256(liquidity), false);

        // Emit event via AMMPool
        pool.emitPositionCreated(positionId, provider, tickLower, tickUpper, liquidity);

        return positionId;
    }

    /// @notice Removes liquidity from a concentrated position
    /// @param positionId The ID of the position
    /// @param liquidity The amount of liquidity to remove
    function removeConcentratedLiquidity(uint256 positionId, uint256 liquidity) external nonReentrant onlyPool {
        AMMPool.Position storage position = pool.positions(positionId);
        if (position.liquidity == 0) revert PositionNotFound(positionId);
        if (liquidity == 0 || liquidity > position.liquidity) revert InsufficientLiquidity(liquidity);

        int24 tickLower = position.tickLower;
        int24 tickUpper = position.tickUpper;

        // Calculate fees owed
        (uint256 feesOwed0, uint256 feesOwed1) = _getFeeGrowthInside(positionId);
        position.tokensOwed0 += feesOwed0;
        position.tokensOwed1 += feesOwed1;

        // Update position
        position.liquidity -= liquidity;
        position.feeGrowthInside0LastX128 = pool.feeGrowthGlobal0X128();
        position.feeGrowthInside1LastX128 = pool.feeGrowthGlobal1X128();

        // Update ticks
        _updateTick(tickLower, -int256(liquidity), true);
        _updateTick(tickUpper, -int256(liquidity), false);

        // Calculate amounts to return
        (uint256 amountA, uint256 amountB) = _getAmountsForLiquidity(tickLower, tickUpper, liquidity);

        // Transfer tokens to owner
        if (amountA > 0) {
            IERC20Upgradeable(pool.tokenA()).safeTransfer(position.owner, amountA);
        }
        if (amountB > 0) {
            IERC20Upgradeable(pool.tokenB()).safeTransfer(position.owner, amountB);
        }

        // Emit event via AMMPool
        pool.emitPositionUpdated(positionId, tickLower, tickUpper, position.liquidity);
    }

    /// @notice Collects accumulated fees for a position
    /// @param positionId The ID of the position
    function collectFees(uint256 positionId) external nonReentrant onlyPool {
        _collectFees(positionId);
    }

    /// @notice Collects fees internally (called by authorized adjusters)
    /// @param positionId The ID of the position
    function collectFeesInternal(uint256 positionId) external nonReentrant onlyPool {
        _collectFees(positionId);
    }

    /// @notice Adjusts a position's tick range and liquidity
    /// @param positionId The ID of the position
    /// @param tickLower The new lower tick
    /// @param tickUpper The new upper tick
    /// @param liquidity The new liquidity amount
    function adjust(uint256 positionId, int24 tickLower, int24 tickUpper, uint256 liquidity) external nonReentrant onlyPool {
        AMMPool.Position storage position = pool.positions(positionId);
        if (position.liquidity == 0) revert PositionNotFound(positionId);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);

        // Collect existing fees
        (uint256 feesOwed0, uint256 feesOwed1) = _getFeeGrowthInside(positionId);
        position.tokensOwed0 += feesOwed0;
        position.tokensOwed1 += feesOwed1;

        // Remove existing liquidity
        _updateTick(position.tickLower, -int256(position.liquidity), true);
        _updateTick(position.tickUpper, -int256(position.liquidity), false);

        // Update position
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = liquidity;
        position.feeGrowthInside0LastX128 = _isInRange(pool.getcurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal0X128()
            : 0;
        position.feeGrowthInside1LastX128 = _isInRange(pool.getcurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal1X128()
            : 0;

        // Add new liquidity
        _updateTick(tickLower, int256(liquidity), true);
        _updateTick(tickUpper, int256(liquidity), false);

        // Emit event via AMMPool
        pool.emitPositionUpdated(positionId, tickLower, tickUpper, liquidity);
    }

    /// @notice Performs a swap within concentrated liquidity
    /// @param isTokenAInput True if tokenA is input
    /// @param amountIn Amount of input token
    /// @return amountOut Amount of output token
    function swapConcentratedLiquidity(bool isTokenAInput, uint256 amountIn) external nonReentrant onlyPool returns (uint256 amountOut) {
        if (amountIn == 0) revert InvalidAmount(amountIn, 0);

        int24 currentTick = pool.getcurrentTick();
        int24 nextTick = isTokenAInput ? currentTick + int24(TICK_SPACING) : currentTick - int24(TICK_SPACING);
        uint256 remainingIn = amountIn;
        uint256 feeGrowthGlobal0 = pool.feeGrowthGlobal0X128();
        uint256 feeGrowthGlobal1 = pool.feeGrowthGlobal1X128();

        while (remainingIn > 0 && _isValidTick(nextTick)) {
            uint256 liquidityAtTick = _getLiquidityAtTick(nextTick);
            if (liquidityAtTick == 0) break;

            uint256 amountToSwap = remainingIn;
            if (isTokenAInput) {
                uint160 sqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(currentTick);
                uint160 nextSqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(nextTick);
                amountOut += _calculateAmountOut(sqrtPriceX96, nextSqrtPriceX96, liquidityAtTick, amountToSwap);
                feeGrowthGlobal0 += (amountToSwap * pool.getChainFeeConfig(1).baseFee) / liquidityAtTick;
            } else {
                uint160 sqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(currentTick);
                uint160 nextSqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(nextTick);
                amountOut += _calculateAmountOut(nextSqrtPriceX96, sqrtPriceX96, liquidityAtTick, amountToSwap);
                feeGrowthGlobal1 += (amountToSwap * pool.getChainFeeConfig(1).baseFee) / liquidityAtTick;
            }

            remainingIn -= amountToSwap;
            currentTick = nextTick;
            nextTick += isTokenAInput ? int24(TICK_SPACING) : -int24(TICK_SPACING);
        }

        // Update global fee growth and current tick in AMMPool
        if (isTokenAInput) {
            pool.feeGrowthGlobal0X128(feeGrowthGlobal0);
        } else {
            pool.feeGrowthGlobal1X128(feeGrowthGlobal1);
        }
        pool.setCurrentTick(currentTick);

        return amountOut;
    }

    // --- Internal Functions ---

    function _updateTick(int24 tick, int256 liquidityDelta, bool isLower) internal {
    if (!_isValidTick(tick)) revert InvalidTick(tick);

    AMMPool.Tick storage tickInfo = pool.getTicks(tick);
    if (tickInfo.liquidityGross == 0 && liquidityDelta > 0) {
        // Initialize tick
        tickInfo.feeGrowthOutside0X128 = pool.feeGrowthGlobal0X128();
        tickInfo.feeGrowthOutside1X128 = pool.feeGrowthGlobal1X128();
    }

    // Update liquidity
    uint256 newLiquidityGross = liquidityDelta >= 0 
        ? tickInfo.liquidityGross + uint256(liquidityDelta) 
        : tickInfo.liquidityGross - uint256(-liquidityDelta);
    tickInfo.liquidityGross = newLiquidityGross;
    tickInfo.liquidityNet += liquidityDelta;

    // Clean up if no liquidity remains
    if (newLiquidityGross == 0) {
        delete pool.getTicks(tick); // Fixed 'position' to 'tick'
    }

    // Update fee growth if crossing tick
    if (liquidityDelta != 0 && tick <= pool.getcurrentTick()) {
        tickInfo.feeGrowthOutside0X128 = pool.feeGrowthGlobal0X128() - tickInfo.feeGrowthOutside0X128;
        tickInfo.feeGrowthOutside1X128 = pool.feeGrowthGlobal1X128() - tickInfo.feeGrowthOutside1X128;
    }
}
    function _getLiquidityForAmounts(
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB,
        int24 currentTick
    ) internal pure returns (uint256 liquidity) {
        uint160 sqrtPriceX96 = TickMathLibrary.tickToSqrtPriceX96(currentTick);
        uint160 sqrtPriceLowerX96 = TickMathLibrary.tickToSqrtPriceX96(tickLower);
        uint160 sqrtPriceUpperX96 = TickMathLibrary.tickToSqrtPriceX96(tickUpper);

        if (sqrtPriceX96 < sqrtPriceLowerX96 || sqrtPriceX96 >= sqrtPriceUpperX96) {
            return 0; // Out of range
        }

        // Calculate liquidity based on amounts
        uint256 liquidityA = (amountA * (sqrtPriceUpperX96 - sqrtPriceLowerX96)) / (sqrtPriceX96 - sqrtPriceX96);
        uint256 liquidityB = (amountB * sqrtPriceLowerX96) / (sqrtPriceUpperX96 - sqrtPriceLowerX96);
        liquidity = liquidityA < liquidityB ? liquidityA : liquidityBliquidity;
    }
    function _getAmountsForLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint256 liquidity
    ) internal pure returns (uint256 amountA, uint256 amountB) {
        uint160 sqrtPriceLowerX96 = TickMathLibrary.tickToSqrtPriceX96(tickLower);
        uint160 sqrtPriceUpperX96 = TickMathLibrary.tickToSqrtPriceX96(tickUpper);

        amountA = (uint256 * liquidity) * (uint256(sqrtPriceUpperX96) - sqrtPriceLowerX96) / sqrtPriceUpperX96;
        amountB = (uint256 * liquidity * sqrtPriceUpperX96) / (sqrtPriceUpperX96 - sqrtPriceLowerX96);
        return (amountA, amountB);
    }
    function _getFeeGrowthInside(uint256 positionId) internal view returns (uint256 feesOwed0, uint256 feesOwed1) {
        AMMPool.Position storage position = pool.positions(positionId);
        if (position == 0) revert PositionNotFound(positionId);

        int24 tickLower = position.tickLower;
        int24 tickUpper = position.tickUpper;
        bool isInRange = _isInRange(pool.getcurrentTick(), tickLower, tickUpper);

        uint256 feeGrowthInside0X128;
        uint256 feeGrowthInside1X128;

        if (isInRange) {
            feeGrowthInside0X128 = pool.feeGrowthGlobal0X128() - position.feeGrowthInside0LastX128;
            feeGrowthInside1X128 = pool.feeGrowthGlobal1X128() - position.feeGrowthInside1LastX128;
        } else {
            AMMPool.Tick storage lowerTick = pool.getTicks(tickLower);
            AMMPool.Tick storage upperTick = pool.getTicks(tickUpper);
            feeGrowthInside0X128 = lowerTick.feeGrowthOutside0X128 - upperTick.feeGrowthOutside0X128;
            feeGrowthInside1X128 = lowerTick.feeGrowthOutside1X128 - upperTick.feeGrowthOutside1X128;
        }

        feesOwed0 = (feeGrowthInside0X128 * position.liquidity) / 2^128;
        feesOwed1 = feeGrowthInside1 * feeGrowthInside1X128 * position.liquidity / 2^128;
        return (feesOwed0, feesOwed1);
    }
    
    function _collectFees(uint256 positionId) internal {
    AMMPool.Position storage position = pool.positions(positionId);
    if (position.liquidity == 0) revert PositionNotFound(positionId);

    // Calculate fees
    (uint256 feesOwed0, uint256 feesOwed1) = _getFeeGrowthInside(positionId);

    // Update position
    position.tokensOwed0 += feesOwed0;
    position.tokensOwed1 += feesOwed1;
    position.feeGrowthInside0LastX128 = _isInRange(pool.getcurrentTick(), position.tickLower, position.tickUpper)
        ? pool.feeGrowthGlobal0X128()
        : 0;
    position.feeGrowthInside1LastX128 = _isInRange(pool.getcurrentTick(), position.tickLower, position.tickUpper)
        ? pool.feeGrowthGlobal1X128()
        : 0;

    // Transfer fees
    if (feesOwed0 > 0) {
        IERC20Upgradeable(pool.getTokenA()).safeTransfer(position.owner, feesOwed0);
    }
    if (feesOwed1 > 0) {
        IERC20Upgradeable(pool.getTokenB()).safeTransfer(position.owner, feesOwed1);
    }

    // Emit event via AMMPool
    pool.emitFeesCollected(positionId, feesOwed0, feesOwed1);
}

    function _isInRange(int24 currentTick, int24 tickLower, int24 tickUpper) internal pure returns (bool) {
        return currentTick >= tickLower && currentTick < tickUpper;
    }
    function _getLiquidityAtTick(int24 tick) internal view returns (uint256 liquidity) {
        AMMPool.Tick storage tickInfo = pool.getTicks(tick);
        if (tickInfo.liquidityGross == 0) revert TickNotInitialized(tick);
        liquidity = tickInfo.liquidityGross;
    }
    function _isValidTick(int24 tick) internal pure returns (bool) {
        // Ensure tick is within Uniswap V3 bounds
        return tick >= TickMathLibrary.MIN_TICK && tick <= TickMathLibrary.MAX_TICK;
    }
    function _isValidTickRange(int24 tickLower, int24 tickUpper) internal view returns (bool) {
        return
            _isValidTick(tickLower) &&
            _isValidTick(tickUpper) &&
            tickLower < tickUpper &&
            (tickLower % int24(TICK_SPACING) == 0) &&
            (tickUpper % int24(TICK_SPACING) == 0);
    }
    function _calculateAmountOut(
        uint160 sqrtPriceX96,
        uint160 nextSqrtPriceX96,
        uint256 liquidity,
        uint256 amountIn
    ) internal pure returns (uint256 amountOut) {
        // Simplified calculation (assumes tokenA to tokenB swap)
        uint256 deltaPrice = uint256(nextSqrtPriceX96 - sqrtPriceX96);
        amountOut = (liquidity * deltaPrice) / sqrtPriceX96;
        if (amountOut > amountIn) {
            amountOut = amountIn;
        }
    }
}