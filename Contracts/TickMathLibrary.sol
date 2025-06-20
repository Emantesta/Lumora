// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TickMath} from "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import {FullMath} from "@uniswap/v3-core/contracts/libraries/FullMath.sol";
import {AMMPool} from "./AMMPool.sol";
import {DynamicFeeLibrary} from "./DynamicFeeLibrary.sol";

/// @title TickMathLibrary - Library for tick-related calculations
/// @notice Extends Uniswap's TickMath with precise V3 math for price and amount calculations
/// @dev Used by AMMPool for tick-based pricing and swap computations
library TickMathLibrary {
    // Custom errors
    error InvalidTick(int24 tick);
    error InvalidSqrtPriceX96(uint160 sqrtPriceX96);
    error InsufficientLiquidity(uint256 amountIn, uint256 reserveOut);
    error ZeroAmount();
    error InvalidToken(address token);
    error Overflow();

    /// @notice Converts a tick to a sqrt price (Q64.96 format)
    /// @param tick The tick value
    /// @return sqrtPriceX96 The sqrt price in Q64.96 format
    function tickToSqrtPriceX96(int24 tick) 
        internal 
        pure 
        returns (uint160 sqrtPriceX96) 
    {
        if (tick < TickMath.MIN_TICK || tick > TickMath.MAX_TICK) 
            revert InvalidTick(tick);
        return TickMath.getSqrtRatioAtTick(tick);
    }

    /// @notice Converts a sqrt price (Q64.96 format) to a tick
    /// @param sqrtPriceX96 The sqrt price in Q64.96 format
    /// @return tick The tick value
    function sqrtPriceX96ToTick(uint160 sqrtPriceX96) 
        internal 
        pure 
        returns (int24 tick) 
    {
        if (sqrtPriceX96 < TickMath.MIN_SQRT_RATIO || sqrtPriceX96 > TickMath.MAX_SQRT_RATIO) 
            revert InvalidSqrtPriceX96(sqrtPriceX96);
        return TickMath.getTickAtSqrtRatio(sqrtPriceX96);
    }

    /// @notice Calculates the next sqrt price after a swap using Uniswap V3's exact math
    /// @param pool The AMMPool contract instance
    /// @param sqrtPriceX96 The current sqrt price
    /// @param isTokenAInput True if tokenA is the input token
    /// @param amountIn The input amount
    /// @return nextSqrtPriceX96 The next sqrt price
    function calculateNextPrice(
        AMMPool pool,
        uint160 sqrtPriceX96,
        bool isTokenAInput,
        uint256 amountIn
    ) 
        internal 
        view 
        returns (uint160 nextSqrtPriceX96) 
    {
        if (amountIn == 0) revert ZeroAmount();
        if (sqrtPriceX96 < TickMath.MIN_SQRT_RATIO || sqrtPriceX96 > TickMath.MAX_SQRT_RATIO) 
            revert InvalidSqrtPriceX96(sqrtPriceX96);

        // Fetch liquidity from pool
        uint128 liquidity = uint128(pool.getLiquidity());
        if (liquidity == 0) revert InsufficientLiquidity(amountIn, 0);

        // Apply dynamic fee
        uint256 fee = pool.getDynamicFee(1); // ChainId 1
        uint256 amountInWithFee = FullMath.mulDiv(amountIn, 10000 - fee, 10000);
        if (amountInWithFee == 0) revert ZeroAmount();

        // Uniswap V3 exact price update: Δ(1/sqrtPrice) = amountIn / liquidity
        if (isTokenAInput) {
            // For token0 -> token1 (price decreases)
            // Δ(1/sqrtPrice) = amountIn / liquidity
            uint256 delta = FullMath.mulDiv(amountInWithFee, 1 << 96, liquidity);
            uint256 inverseSqrtPrice = FullMath.mulDiv(1 << 192, 1, sqrtPriceX96);
            
            // Check for underflow
            if (inverseSqrtPrice < delta) revert Overflow();
            
            inverseSqrtPrice -= delta;
            
            // Convert back to sqrtPriceX96
            nextSqrtPriceX96 = uint160(FullMath.mulDiv(1 << 192, 1, inverseSqrtPrice));
        } else {
            // For token1 -> token0 (price increases)
            // ΔsqrtPrice = (amountIn * sqrtPrice) / liquidity
            uint256 delta = FullMath.mulDiv(amountInWithFee, sqrtPriceX96, liquidity);
            
            // Check for overflow
            if (uint256(sqrtPriceX96) + delta > type(uint160).max) revert Overflow();
            
            nextSqrtPriceX96 = uint160(uint256(sqrtPriceX96) + delta);
        }

        // Enforce price bounds
        if (nextSqrtPriceX96 < TickMath.MIN_SQRT_RATIO) 
            nextSqrtPriceX96 = TickMath.MIN_SQRT_RATIO;
        if (nextSqrtPriceX96 > TickMath.MAX_SQRT_RATIO) 
            nextSqrtPriceX96 = TickMath.MAX_SQRT_RATIO;

        return nextSqrtPriceX96;
    }

    /// @notice Calculates the output amount for a swap using Uniswap V3's exact math
    /// @param pool The AMMPool instance
    /// @param sqrtPriceX96 The current sqrt price
    /// @param inputToken The input token address
    /// @param amountIn The input amount
    /// @return amountOut The output amount
    function calculateAmountOut(
        AMMPool pool,
        uint160 sqrtPriceX96,
        address inputToken,
        uint256 amountIn
    ) 
        internal 
        view 
        returns (uint256 amountOut) 
    {
        if (amountIn == 0) revert ZeroAmount();
        if (sqrtPriceX96 < TickMath.MIN_SQRT_RATIO || sqrtPriceX96 > TickMath.MAX_SQRT_RATIO) 
            revert InvalidSqrtPriceX96(sqrtPriceX96);
        if (inputToken != pool.tokenA() && inputToken != pool.tokenB()) 
            revert InvalidToken(inputToken);

        bool isTokenAInput = inputToken == pool.tokenA();
        uint128 liquidity = uint128(pool.getLiquidity());
        if (liquidity == 0) revert InsufficientLiquidity(amountIn, 0);

        // Apply dynamic fee
        uint256 fee = pool.getDynamicFee(1); // ChainId 1
        uint256 amountInWithFee = FullMath.mulDiv(amountIn, 10000 - fee, 10000);
        if (amountInWithFee == 0) revert ZeroAmount();

        // Calculate next sqrt price
        uint160 nextSqrtPriceX96 = calculateNextPrice(pool, sqrtPriceX96, isTokenAInput, amountIn);

        // Calculate amount out using Uniswap V3's exact formula
        if (isTokenAInput) {
            // token0 -> token1: use Δ(1/sqrtPrice) to calculate amountOut
            uint256 deltaPrice = FullMath.mulDiv(1 << 192, 1, sqrtPriceX96) - 
                                FullMath.mulDiv(1 << 192, 1, nextSqrtPriceX96);
            amountOut = FullMath.mulDiv(deltaPrice, liquidity, 1 << 96);
        } else {
            // token1 -> token0: use ΔsqrtPrice to calculate amountOut
            uint256 deltaPrice = uint256(nextSqrtPriceX96) - uint256(sqrtPriceX96);
            amountOut = FullMath.mulDiv(deltaPrice, liquidity, 1 << 96);
        }

        // Verify output amount against reserves
        (uint64 reserveA, uint64 reserveB) = pool.getReserves();
        uint256 reserveOut = isTokenAInput ? reserveB : reserveA;
        if (amountOut > reserveOut) 
            revert InsufficientLiquidity(amountIn, reserveOut);

        return amountOut;
    }
}