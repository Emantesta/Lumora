// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@offchainlabs/upgrade-executor/node_modules/@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {FullMath} from "@uniswap/v3-core/contracts/libraries/FullMath.sol";
import {TickMath} from "@uniswap/v3-core/contracts/libraries/TickMath.sol";
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

    // Structs (aligned with AMMPool)
    struct Position {
        address owner;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity; // Changed to uint128 for Uniswap V3 compatibility
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint128 tokensOwed0; // Changed to uint128 for precision
        uint128 tokensOwed1; // Changed to uint128 for precision
    }

    struct Tick {
        uint128 liquidityGross; // Changed to uint128
        int128 liquidityNet; // Changed to int128
        uint256 feeGrowthOutside0X128;
        uint256 feeGrowthOutside1X128;
    }

    // Constructor: Initializes pool reference and tick spacing
    constructor(address _pool) {
        if (_pool == address(0)) revert InvalidAddress(_pool, "Invalid pool address");
        pool = AMMPool(_pool);
        TICK_SPACING = pool.TICK_SPACING();
    }

    // --- Errors ---
    error Unauthorized();
    error InvalidTick(int24 tick);
    error InvalidTickRange(int24 tickLower, int24 tickUpper);
    error PositionNotFound(uint256 positionId);
    error InsufficientLiquidity(uint128 liquidity);
    error TickNotInitialized(int24 tick);
    error InvalidAmount(uint256 amountA, uint256 amountB);
    error InvalidAddress(address addr, string message);
    error PriceOutOfRange();
    error Overflow();

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
        if (provider == address(0)) revert InvalidAddress(provider, "Invalid provider address");
        if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);

        int24 currentTick = pool.getCurrentTick();
        bool isInRange = _isInRange(currentTick, tickLower, tickUpper);

        // Calculate liquidity using Uniswap V3 exact math
        uint128 liquidity = _getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB, currentTick);
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
        AMMPool.Position memory position;
        position.owner = provider;
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = liquidity;
        position.feeGrowthInside0LastX128 = isInRange ? pool.feeGrowthGlobal0X128() : 0;
        position.feeGrowthInside1LastX128 = isInRange ? pool.feeGrowthGlobal1X128() : 0;
        pool.setPositionByLiquidity(positionId, position);
        // Increment position counter
        pool.incrementPositionCounter();

        // Update ticks
        _updateTick(tickLower, int128(liquidity), true);
        _updateTick(tickUpper, int128(liquidity), false);

        // Emit event
        pool.emitPositionCreated(positionId, provider, tickLower, tickUpper, liquidity);

        return positionId;
    }

    /// @notice Removes liquidity from a concentrated position
    /// @param positionId The ID of the position
    /// @param liquidity The amount of liquidity to remove
    function removeConcentratedLiquidity(uint256 positionId, uint128 liquidity) external nonReentrant onlyPool {
        // Fetch position data into memory
        (
            address owner,
            int24 tickLower,
            int24 tickUpper,
            uint128 currentLiquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        ) = pool.positions(positionId);
        if (currentLiquidity == 0) revert PositionNotFound(positionId);
        if (liquidity == 0 || liquidity > currentLiquidity) revert InsufficientLiquidity(liquidity);

        (uint128 feesOwed0, uint128 feesOwed1) = _getFeeGrowthInside(positionId);

        // Create a memory struct to update position
        AMMPool.Position memory position;
        position.owner = owner;
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = currentLiquidity - liquidity;
        position.feeGrowthInside0LastX128 = _isInRange(pool.getCurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal0X128()
            : 0;
        position.feeGrowthInside1LastX128 = _isInRange(pool.getCurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal1X128()
            : 0;
        position.tokensOwed0 = tokensOwed0 + feesOwed0;
        position.tokensOwed1 = tokensOwed1 + feesOwed1;
        pool.setPositionByLiquidity(positionId, position);

        _updateTick(tickLower, -int128(liquidity), true);
        _updateTick(tickUpper, -int128(liquidity), false);

        (uint256 amountA, uint256 amountB) = _getAmountsForLiquidity(tickLower, tickUpper, liquidity);

        if (amountA > 0) {
            IERC20Upgradeable(pool.tokenA()).safeTransfer(owner, amountA);
        }
        if (amountB > 0) {
            IERC20Upgradeable(pool.tokenB()).safeTransfer(owner, amountB);
        }

        pool.emitPositionUpdated(positionId, tickLower, tickUpper, position.liquidity);
    }

    /// @notice Collects accumulated fees for a position
    /// @param positionId The ID of the position
    function collectFees(uint256 positionId) external nonReentrant onlyPool {
        _collectFees(positionId);
    }

    /// @notice Collects fees internally
    /// @param positionId The ID of the position
    function collectFeesInternal(uint256 positionId) external nonReentrant onlyPool {
        _collectFees(positionId);
    }

    /// @notice Adjusts a position's tick range and liquidity
    /// @param positionId The ID of the position
    /// @param tickLower The new lower tick
    /// @param tickUpper The new upper tick
    /// @param liquidity The new liquidity amount
    function adjust(uint256 positionId, int24 tickLower, int24 tickUpper, uint128 liquidity) external nonReentrant onlyPool {
        (
            address owner,
            int24 oldTickLower,
            int24 oldTickUpper,
            uint128 currentLiquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        ) = pool.positions(positionId);
        if (currentLiquidity == 0) revert PositionNotFound(positionId);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);

        (uint128 feesOwed0, uint128 feesOwed1) = _getFeeGrowthInside(positionId);

        _updateTick(oldTickLower, -int128(currentLiquidity), true);
        _updateTick(oldTickUpper, -int128(currentLiquidity), false);

        AMMPool.Position memory position;
        position.owner = owner;
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = liquidity;
        position.feeGrowthInside0LastX128 = _isInRange(pool.getCurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal0X128()
            : 0;
        position.feeGrowthInside1LastX128 = _isInRange(pool.getCurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal1X128()
            : 0;
        position.tokensOwed0 = tokensOwed0 + feesOwed0;
        position.tokensOwed1 = tokensOwed1 + feesOwed1;
        pool.setPositionByLiquidity(positionId, position);

        _updateTick(tickLower, int128(liquidity), true);
        _updateTick(tickUpper, int128(liquidity), false);

        pool.emitPositionUpdated(positionId, tickLower, tickUpper, liquidity);
    }

    /// @notice Performs a swap within concentrated liquidity
    /// @param isTokenAInput True if tokenA is input
    /// @param amountIn Amount of input token
    /// @return amountOut Amount of output token
    function swapConcentratedLiquidity(bool isTokenAInput, uint256 amountIn) external nonReentrant onlyPool returns (uint256 amountOut) {
        if (amountIn == 0) revert InvalidAmount(amountIn, 0);

        int24 currentTick = pool.getCurrentTick();
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(currentTick);
        uint256 remainingIn = amountIn;
        uint256 feeGrowthGlobal0 = pool.feeGrowthGlobal0X128();
        uint256 feeGrowthGlobal1 = pool.feeGrowthGlobal1X128();

        while (remainingIn > 0) {
            int24 nextTick = _findNextInitializedTick(currentTick, isTokenAInput);
            // Fetch tick data into memory
            AMMPool.Tick memory tickInfo = pool.getTicks(nextTick);
            if (tickInfo.liquidityGross == 0) revert TickNotInitialized(nextTick);

            uint128 liquidity = tickInfo.liquidityGross;

            uint256 amountUsed;
            if (isTokenAInput) {
                (amountOut, amountUsed) = _calculateSwapAmounts(
                    sqrtPriceX96,
                    TickMath.getSqrtRatioAtTick(nextTick),
                    liquidity,
                    remainingIn,
                    true
                );
                (uint256 baseFee, , ) = pool.getChainFeeConfig(1);
                feeGrowthGlobal0 += FullMath.mulDiv(
                    amountUsed,
                    baseFee,
                    1 << 128
                );
            } else {
                (amountOut, amountUsed) = _calculateSwapAmounts(
                    TickMath.getSqrtRatioAtTick(nextTick),
                    sqrtPriceX96,
                    liquidity,
                    remainingIn,
                    false
                );
                (uint256 baseFee, , ) = pool.getChainFeeConfig(1);
                feeGrowthGlobal1 += FullMath.mulDiv(
                    amountUsed,
                    baseFee,
                    1 << 128
                );
            }

            remainingIn -= amountUsed;
            sqrtPriceX96 = TickMath.getSqrtRatioAtTick(nextTick);
            currentTick = nextTick;

            if (remainingIn == 0 || sqrtPriceX96 <= TickMath.MIN_SQRT_RATIO || sqrtPriceX96 >= TickMath.MAX_SQRT_RATIO) {
                break;
            }
        }

        if (isTokenAInput) {
            pool.setFeeGrowthGlobal0X128(feeGrowthGlobal0);
        } else {
            pool.setFeeGrowthGlobal1X128(feeGrowthGlobal1);
        }
        pool.setCurrentTick(currentTick);

        return amountOut;
    }

    /// @notice Public wrapper to get fee growth inside for a position
    /// @param positionId The ID of the position
    /// @return feesOwed0 Fees owed in token0
    /// @return feesOwed1 Fees owed in token1
    function getFeeGrowthInside(uint256 positionId) external view onlyPool returns (uint128 feesOwed0, uint128 feesOwed1) {
        (
            address owner,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            ,
            ,
            ,
        ) = pool.positions(positionId);
        if (liquidity == 0) revert PositionNotFound(positionId);
        return _getFeeGrowthInside(positionId);
    }

    function getLiquidityForAmounts(
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB,
        int24 currentTick
    ) external view returns (uint128 liquidity) {
        if (msg.sender != address(pool)) revert Unauthorized();
        return _getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB, currentTick);
    }


    // --- Internal Functions ---

    /// @notice Updates tick state
    function _updateTick(int24 tick, int128 liquidityDelta, bool isLower) internal {
        if (!_isValidTick(tick)) revert InvalidTick(tick);

        // Fetch tick data into memory
        (uint128 liquidityGross, int128 liquidityNet, uint256 feeGrowthOutside0X128, uint256 feeGrowthOutside1X128) = pool.ticks(tick);
        AMMPool.Tick memory tickInfo = AMMPool.Tick({
            liquidityGross: liquidityGross,
            liquidityNet: liquidityNet,
            feeGrowthOutside0X128: feeGrowthOutside0X128,
            feeGrowthOutside1X128: feeGrowthOutside1X128
        });

        if (tickInfo.liquidityGross == 0 && liquidityDelta > 0) {
            tickInfo.feeGrowthOutside0X128 = pool.feeGrowthGlobal0X128();
            tickInfo.feeGrowthOutside1X128 = pool.feeGrowthGlobal1X128();
        }

        uint128 newLiquidityGross = liquidityDelta >= 0
            ? tickInfo.liquidityGross + uint128(liquidityDelta)
            : tickInfo.liquidityGross - uint128(-liquidityDelta);
        if (liquidityDelta < 0 && newLiquidityGross > tickInfo.liquidityGross) revert Overflow();
        tickInfo.liquidityGross = newLiquidityGross;
        tickInfo.liquidityNet = liquidityDelta >= 0
            ? tickInfo.liquidityNet + liquidityDelta
            : tickInfo.liquidityNet - int128(uint128(-liquidityDelta));

        if (newLiquidityGross == 0) {
            pool.deleteTick(tick); // Use new function instead of delete
        } else {
            pool.setTick(tick, tickInfo); // Write updated tick back to storage
        }

        int24 currentTick = pool.getCurrentTick();
        if (liquidityDelta != 0 && ((isLower && tick <= currentTick) || (!isLower && tick > currentTick))) {
            tickInfo.feeGrowthOutside0X128 = pool.feeGrowthGlobal0X128() - tickInfo.feeGrowthOutside0X128;
            tickInfo.feeGrowthOutside1X128 = pool.feeGrowthGlobal1X128() - tickInfo.feeGrowthOutside1X128;
            pool.setTick(tick, tickInfo); // Write updated fee growth
        }
    }

    /// @notice Calculates liquidity for given amounts
    function _getLiquidityForAmounts(
        int24 tickLower,
        int24 tickUpper,
        uint256 amountA,
        uint256 amountB,
        int24 currentTick
    ) internal pure returns (uint128 liquidity) {
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(currentTick);
        uint160 sqrtPriceLowerX96 = TickMath.getSqrtRatioAtTick(tickLower);
        uint160 sqrtPriceUpperX96 = TickMath.getSqrtRatioAtTick(tickUpper);

        if (sqrtPriceX96 < sqrtPriceLowerX96 || sqrtPriceX96 > sqrtPriceUpperX96) {
            return 0; // Out of range
        }

        // Uniswap V3 liquidity calculations
        if (amountA > 0) {
            // Calculate liquidity based on token0
            uint256 temp = FullMath.mulDiv(
                amountA,
                FullMath.mulDiv(sqrtPriceUpperX96, sqrtPriceX96, 1 << 96),
                sqrtPriceUpperX96 - sqrtPriceX96
            );
            liquidity = temp > type(uint128).max ? type(uint128).max : uint128(temp);
        }
        if (amountB > 0) {
            // Calculate liquidity based on token1
            uint256 temp = FullMath.mulDiv(
                amountB,
                1 << 96,
                sqrtPriceUpperX96 - sqrtPriceLowerX96
            );
            liquidity = liquidity == 0 || temp < liquidity ? (temp > type(uint128).max ? type(uint128).max : uint128(temp)) : liquidity;
        }
    }

    /// @notice Calculates amounts for given liquidity
    function _getAmountsForLiquidity(
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity
    ) internal pure returns (uint256 amount0, uint256 amount1) {
        uint160 sqrtPriceLowerX96 = TickMath.getSqrtRatioAtTick(tickLower);
        uint160 sqrtPriceUpperX96 = TickMath.getSqrtRatioAtTick(tickUpper);
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(TickMath.getTickAtSqrtRatio(sqrtPriceUpperX96));

        // Uniswap V3 amount calculations
        if (sqrtPriceX96 <= sqrtPriceLowerX96) {
            // Only token1 provided
            amount1 = FullMath.mulDiv(
                liquidity,
                sqrtPriceUpperX96 - sqrtPriceLowerX96,
                1 << 96
            );
        } else if (sqrtPriceX96 < sqrtPriceUpperX96) {
            // Both tokens provided
            amount0 = FullMath.mulDiv(
                liquidity,
                FullMath.mulDiv(sqrtPriceUpperX96, sqrtPriceX96, 1 << 96),
                sqrtPriceUpperX96 - sqrtPriceX96
            );
            amount1 = FullMath.mulDiv(
                liquidity,
                sqrtPriceUpperX96 - sqrtPriceX96,
                1 << 96
            );
        } else {
            // Only token0 provided
            amount0 = FullMath.mulDiv(
                liquidity,
                FullMath.mulDiv(sqrtPriceUpperX96, sqrtPriceLowerX96, 1 << 96),
                sqrtPriceUpperX96 - sqrtPriceLowerX96
            );
        }
    }

    /// @notice Calculates fees accrued by a position
    function _getFeeGrowthInside(uint256 positionId) internal view returns (uint128 feesOwed0, uint128 feesOwed1) {
        (
            address owner,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            ,
        ) = pool.positions(positionId);
        if (liquidity == 0) revert PositionNotFound(positionId);

        int24 currentTick = pool.getCurrentTick();
        bool isInRange = _isInRange(currentTick, tickLower, tickUpper);

        uint256 feeGrowthInside0X128;
        uint256 feeGrowthInside1X128;

        // Fetch tick data into memory
        AMMPool.Tick memory lowerTick = pool.getTicks(tickLower);
        AMMPool.Tick memory upperTick = pool.getTicks(tickUpper);

        if (isInRange) {
            feeGrowthInside0X128 = pool.feeGrowthGlobal0X128() - lowerTick.feeGrowthOutside0X128 - upperTick.feeGrowthOutside0X128;
            feeGrowthInside1X128 = pool.feeGrowthGlobal1X128() - lowerTick.feeGrowthOutside1X128 - upperTick.feeGrowthOutside1X128;
        } else {
            feeGrowthInside0X128 = lowerTick.feeGrowthOutside0X128 - upperTick.feeGrowthOutside0X128;
            feeGrowthInside1X128 = lowerTick.feeGrowthOutside1X128 - upperTick.feeGrowthOutside1X128;
        }

        feesOwed0 = uint128(FullMath.mulDiv(
            feeGrowthInside0X128 - feeGrowthInside0LastX128,
            liquidity,
            1 << 128
        ));
        feesOwed1 = uint128(FullMath.mulDiv(
            feeGrowthInside1X128 - feeGrowthInside1LastX128,
            liquidity,
            1 << 128
        ));
    }

    /// @notice Collects fees for a position
    function _collectFees(uint256 positionId) internal {
        // Fetch position data into memory
        (
            address owner,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        ) = pool.positions(positionId);
        if (liquidity == 0 && tokensOwed0 == 0 && tokensOwed1 == 0) revert PositionNotFound(positionId);

        // Calculate fees
        (uint128 feesOwed0, uint128 feesOwed1) = _getFeeGrowthInside(positionId);

        // Update position in memory
        AMMPool.Position memory position;
        position.owner = owner;
        position.tickLower = tickLower;
        position.tickUpper = tickUpper;
        position.liquidity = liquidity;
        position.feeGrowthInside0LastX128 = _isInRange(pool.getCurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal0X128()
            : 0;
        position.feeGrowthInside1LastX128 = _isInRange(pool.getCurrentTick(), tickLower, tickUpper)
            ? pool.feeGrowthGlobal1X128()
            : 0;
        position.tokensOwed0 = tokensOwed0 + feesOwed0;
        position.tokensOwed1 = tokensOwed1 + feesOwed1;

        // Write back to storage
        pool.setPositionByLiquidity(positionId, position);

        // Transfer fees
        if (position.tokensOwed0 > 0) {
            IERC20Upgradeable(pool.tokenA()).safeTransfer(position.owner, position.tokensOwed0);
            position.tokensOwed0 = 0;
        }
        if (position.tokensOwed1 > 0) {
            IERC20Upgradeable(pool.tokenB()).safeTransfer(position.owner, position.tokensOwed1);
            position.tokensOwed1 = 0;
        }

        // Update storage after transferring fees
        pool.setPositionByLiquidity(positionId, position);

        // Emit event
        pool.emitFeesCollected(positionId, feesOwed0, feesOwed1);
    }

    /// @notice Calculates swap amounts for a tick range
    function _calculateSwapAmounts(
        uint160 sqrtPriceX96,
        uint160 nextSqrtPriceX96,
        uint128 liquidity,
        uint256 amountIn,
        bool isToken0Input
    ) internal pure returns (uint256 amountOut, uint256 amountUsed) {
        uint256 deltaPrice;
        if (isToken0Input) {
            // token0 -> token1 (price decreases)
            deltaPrice = sqrtPriceX96 > nextSqrtPriceX96 
                ? sqrtPriceX96 - nextSqrtPriceX96 
                : nextSqrtPriceX96 - sqrtPriceX96;
            amountOut = FullMath.mulDiv(liquidity, deltaPrice, 1 << 96);
            amountUsed = FullMath.mulDiv(
                liquidity,
                FullMath.mulDiv(1 << 96, 1, sqrtPriceX96) - FullMath.mulDiv(1 << 96, 1, nextSqrtPriceX96),
                1
            );
        } else {
            // token1 -> token0 (price increases)
            deltaPrice = nextSqrtPriceX96 > sqrtPriceX96 
                ? nextSqrtPriceX96 - sqrtPriceX96 
                : sqrtPriceX96 - nextSqrtPriceX96;
            amountOut = FullMath.mulDiv(liquidity, deltaPrice, 1 << 96);
            amountUsed = FullMath.mulDiv(liquidity, deltaPrice, sqrtPriceX96);
        }
        if (amountUsed > amountIn) {
            amountUsed = amountIn;
            amountOut = isToken0Input
                ? FullMath.mulDiv(amountUsed, deltaPrice, 1 << 96)
                : FullMath.mulDiv(amountUsed, deltaPrice, sqrtPriceX96);
        }
    }

    /// @notice Finds the next initialized tick
    function _findNextInitializedTick(int24 currentTick, bool isToken0Input) internal view returns (int24 nextTick) {
        nextTick = isToken0Input ? currentTick + int24(TICK_SPACING) : currentTick - int24(TICK_SPACING);
        while (_isValidTick(nextTick)) {
            AMMPool.Tick memory tickInfo = pool.getTicks(nextTick);
            if (tickInfo.liquidityGross > 0) {
                return nextTick;
            }
            nextTick += isToken0Input ? int24(TICK_SPACING) : -int24(TICK_SPACING);
        }
        revert TickNotInitialized(nextTick);
    }

    /// @notice Checks if tick is in range
    function _isInRange(int24 currentTick, int24 tickLower, int24 tickUpper) internal pure returns (bool) {
        return currentTick >= tickLower && currentTick < tickUpper;
    }

    /// @notice Gets liquidity at a tick
    function _getLiquidityAtTick(int24 tick) internal view returns (uint128 liquidity) {
        AMMPool.Tick memory tickInfo = pool.getTicks(tick);
        if (tickInfo.liquidityGross == 0) revert TickNotInitialized(tick);
        liquidity = tickInfo.liquidityGross;
    }

    /// @notice Validates tick
    function _isValidTick(int24 tick) internal pure returns (bool) {
        return tick >= TickMath.MIN_TICK && tick <= TickMath.MAX_TICK;
    }

    /// @notice Validates tick range
    function _isValidTickRange(int24 tickLower, int24 tickUpper) internal view returns (bool) {
        return
            _isValidTick(tickLower) &&
            _isValidTick(tickUpper) &&
            tickLower < tickUpper &&
            (tickLower % int24(TICK_SPACING) == 0) &&
            (tickUpper % int24(TICK_SPACING) == 0);
    }
}