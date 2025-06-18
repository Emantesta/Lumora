// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPriceOracle} from "./Interfaces.sol";
import {UD60x18, ud} from "@prb/math/src/UD60x18.sol";
import {AMMPool} from "./AMMPool.sol";

/// @title DynamicFeeLibrary - Library for dynamic fee and volatility calculations
/// @notice Provides functions for calculating dynamic fees, updating volatility, and validating prices
/// @dev Used by AMMPool to manage fee and volatility state
library DynamicFeeLibrary {
    // Struct for fee configuration
    struct FeeConfig {
        uint256 baseFee;
        uint256 maxFee;
        uint256 volatilityMultiplier;
    }

    // Struct to encapsulate AMMPool state
    struct State {
        mapping(uint16 => FeeConfig) chainFees;
        uint256 emaVolatility;
        uint256 emaPeriod;
        uint256 volatilityThreshold;
        uint256 lastPrice;
        uint256[] priceHistory;
        uint256 priceHistoryIndex;
        bool useConstantSum;
        uint256 priceDeviationThreshold;
        address primaryPriceOracle;
        address[] fallbackPriceOracles;
    }

    // Custom errors
    error InvalidFeeRange(uint256 baseFee, uint256 maxFee);
    error InvalidPrice(uint256 expected, uint256 actual);
    error OracleFailure();
    error NegativeOraclePrice(int256 price);
    error InvalidToken(address token);
    error InvalidAddress(address addr, string message);

    /// @notice Calculates the dynamic fee based on volatility
    /// @param state The AMMPool state
    /// @param chainId The chain ID
    /// @return fee The calculated fee
    function getDynamicFee(State storage state, uint16 chainId) 
        internal 
        view 
        returns (uint256 fee) 
    {
        FeeConfig storage config = state.chainFees[chainId];
        if (config.maxFee == 0 || config.baseFee > config.maxFee) 
            revert InvalidFeeRange(config.baseFee, config.maxFee);
        
        uint256 volatility = state.emaVolatility;
        fee = config.baseFee + ((volatility * config.volatilityMultiplier) / 1e18);
        return fee > config.maxFee ? config.maxFee : fee;
    }

    /// @notice Updates volatility based on EMA and price history
    /// @param state The AMMPool state
    /// @param pool The AMMPool contract instance
    /// @param tokenA The address of tokenA
    /// @param tokenB The address of tokenB
    function updateVolatility(State storage state, AMMPool pool, address tokenA, address tokenB) 
        internal 
    {
        // Get current price from AMMPool wrapper
        uint256 newPrice = pool.getOraclePrice();
        
        // Update price history
        if (state.priceHistory.length == 0) {
            state.priceHistory = new uint256[](pool.PRICE_HISTORY_SIZE());
        }
        
        state.priceHistory[state.priceHistoryIndex] = newPrice;
        state.priceHistoryIndex = (state.priceHistoryIndex + 1) % pool.PRICE_HISTORY_SIZE();
        state.lastPrice = newPrice;

        // Calculate volatility
        uint256 volatility;
        if (state.priceHistory.length > 1) {
            uint256 sum;
            uint256 count;
            for (uint256 i = 1; i < state.priceHistory.length && i <= pool.VOLATILITY_WINDOW(); i++) {
                uint256 prevIndex = (state.priceHistoryIndex + state.priceHistory.length - i) % state.priceHistory.length;
                uint256 currIndex = (prevIndex + 1) % state.priceHistory.length;
                uint256 priceDiff = state.priceHistory[currIndex] > state.priceHistory[prevIndex]
                    ? state.priceHistory[currIndex] - state.priceHistory[prevIndex]
                    : state.priceHistory[prevIndex] - state.priceHistory[currIndex];
                sum += priceDiff;
                count++;
            }
            volatility = count > 0 ? sum / count : 0;
        }

        // Update EMA volatility
        uint256 newEmaVol = ((volatility * 2) / (state.emaPeriod + 1)) + 
                            (state.emaVolatility * (state.emaPeriod - 1) / (state.emaPeriod + 1));
        state.emaVolatility = newEmaVol;

        // Update useConstantSum based on volatility
        state.useConstantSum = state.emaVolatility < state.volatilityThreshold;
    }

    /// @notice Validates swap price against oracle price
    /// @param state The AMMPool state
    /// @param inputToken The input token address
    /// @param amountIn The input amount
    /// @param amountOut The output amount
    /// @param tokenA The address of tokenA
    /// @param tokenB The address of tokenB
    function validatePrice(
        State storage state,
        address inputToken,
        uint256 amountIn,
        uint256 amountOut,
        address tokenA,
        address tokenB
    ) 
        internal 
        view 
    {
        if (inputToken != tokenA && inputToken != tokenB) revert InvalidToken(inputToken);
        uint256 expectedPrice = pool.getOraclePrice();
        uint256 actualPrice = (amountOut * 1e18) / amountIn;
        
        if (actualPrice > expectedPrice + state.priceDeviationThreshold || 
            actualPrice < expectedPrice - state.priceDeviationThreshold) 
            revert InvalidPrice(expectedPrice, actualPrice);
    }
}