// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@offchainlabs/upgrade-executor/node_modules/@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {AMMPool} from "./AMMPool.sol";
import {TickMath} from "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import {TickMathLibrary} from "./TickMathLibrary.sol";

/// @title FallbackPool - Manages the fallback pool for out-of-range positions
/// @notice Handles liquidity for positions outside the current tick range, swaps, and fee compounding
/// @dev Interacts with AMMPool for state and token transfers
contract FallbackPool is ReentrancyGuard {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable reference to AMMPool
    AMMPool public immutable pool;

    // Struct for fallback pool reserves
    struct FallbackReserves {
        uint256 reserveA;
        uint256 reserveB;
        uint128 totalLiquidity;
    }

    // State variables
    FallbackReserves public fallbackReserves;
    mapping(address => uint128) public fallbackLiquidityBalance;
    mapping(uint256 => bool) public inFallbackPool;

    // Custom errors
    error Unauthorized();
    error InsufficientLiquidity(uint256 liquidity);
    error PositionNotInFallback(uint256 positionId);
    error InsufficientReserve(uint256 amountOut, uint256 reserve);
    error InvalidToken(address token);
    error LiquidityOverflow();
    error TotalLiquidityOverflow();
    error UserLiquidityBalanceOverflow();

    // Events
    event FallbackPoolEntered(uint256 indexed positionId, uint256 liquidity);
    event FallbackPoolExited(uint256 indexed positionId, uint256 liquidity);

    /// @notice Constructor to initialize the pool address
    /// @param _pool The address of the AMMPool contract
    constructor(address _pool) {
        if (_pool == address(0)) revert Unauthorized();
        pool = AMMPool(_pool);
    }

    // Modifiers
    modifier onlyPool() {
        if (msg.sender != address(pool)) revert Unauthorized();
        _;
    }

    modifier onlyPositionOwner(uint256 positionId) {
        (address owner,,,,,) = pool.getPosition(positionId);
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyPositionAdjuster() {
        if (msg.sender != pool.positionAdjuster()) revert Unauthorized();
        _;
    }

    /// @notice Checks if a position is out of range and moves it to the fallback pool
    /// @param positionId The ID of the position to check
    function checkAndMoveToFallback(uint256 positionId) external onlyPool {
        if (inFallbackPool[positionId]) return;

        (address owner, int24 tickLower, int24 tickUpper, uint128 liquidity,,) = pool.getPosition(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);

        int24 currentTick = pool.getCurrentTick();
        if (currentTick < tickLower || currentTick >= tickUpper) {
            inFallbackPool[positionId] = true;

            uint256 totalLiquidity = pool.getLiquidity();
            (uint64 reserveA, uint64 reserveB) = pool.getReserves();

            uint256 amountA = (liquidity * reserveA) / totalLiquidity;
            uint256 amountB = (liquidity * reserveB) / totalLiquidity;

            // Check for uint128 overflow
            if (liquidity > type(uint128).max) revert LiquidityOverflow();
            if (fallbackReserves.totalLiquidity + liquidity < fallbackReserves.totalLiquidity)
                revert TotalLiquidityOverflow();
            if (fallbackLiquidityBalance[owner] + liquidity < fallbackLiquidityBalance[owner])
                revert UserLiquidityBalanceOverflow();

            fallbackReserves.reserveA += amountA;
            fallbackReserves.reserveB += amountB;
            fallbackReserves.totalLiquidity += liquidity;
            fallbackLiquidityBalance[owner] += liquidity;

            emit FallbackPoolEntered(positionId, liquidity);
        }
    }

    /// @notice Allows a position owner to exit the fallback pool
    /// @param positionId The ID of the position to exit
    function exitFallbackPool(uint256 positionId) external nonReentrant onlyPositionOwner(positionId) {
        _exitFallbackPool(positionId);

        (address owner, , , uint128 liquidity,,) = pool.getPosition(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
    }

    /// @notice Internal function to exit the fallback pool for a position
    /// @param positionId The ID of the position to exit
    function exitFallbackPoolInternal(uint256 positionId) external onlyPositionAdjuster {
        _exitFallbackPool(positionId);
    }

    /// @notice Internal logic to exit the fallback pool
    /// @param positionId The ID of the position to exit
    function _exitFallbackPool(uint256 positionId) internal {
        if (!inFallbackPool[positionId]) revert PositionNotInFallback(positionId);

        (address owner, , , uint128 liquidity,,) = pool.getPosition(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);

        uint256 amountA = (liquidity * fallbackReserves.reserveA) / fallbackReserves.totalLiquidity;
        uint256 amountB = (liquidity * fallbackReserves.reserveB) / fallbackReserves.totalLiquidity;

        inFallbackPool[positionId] = false;
        fallbackReserves.reserveA -= amountA;
        fallbackReserves.reserveB -= amountB;
        fallbackReserves.totalLiquidity -= liquidity;
        fallbackLiquidityBalance[owner] -= liquidity;

        IERC20Upgradeable(pool.tokenA()).safeTransfer(owner, amountA);
        IERC20Upgradeable(pool.tokenB()).safeTransfer(owner, amountB);

        emit FallbackPoolExited(positionId, liquidity);
    }

    /// @notice Compounds fees for a position in the fallback pool
    /// @param positionId The ID of the position
    /// @param tokensOwed0 Amount of token0 to compound
    /// @param tokensOwed1 Amount of token1 to compound
    function compoundFallbackFeesInternal(uint256 positionId, uint256 tokensOwed0, uint256 tokensOwed1)
        external
        onlyPositionAdjuster
    {
        if (!inFallbackPool[positionId]) revert PositionNotInFallback(positionId);

        (address owner, , , uint128 liquidity,,) = pool.getPosition(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);

        // Calculate additional liquidity from fees
        uint256 additionalLiquidity;
        if (tokensOwed0 > 0 && tokensOwed1 > 0) {
            additionalLiquidity = (tokensOwed0 + tokensOwed1) / 2; // Simplified constant-sum approach
        } else if (tokensOwed0 > 0) {
            additionalLiquidity = tokensOwed0;
        } else if (tokensOwed1 > 0) {
            additionalLiquidity = tokensOwed1;
        }

        if (additionalLiquidity > 0) {
            // Check for uint128 overflow
            if (additionalLiquidity > type(uint128).max) revert LiquidityOverflow();
            uint128 additionalLiquidity128 = uint128(additionalLiquidity);

            // Check for totalLiquidity and user balance overflow
            if (fallbackReserves.totalLiquidity + additionalLiquidity128 < fallbackReserves.totalLiquidity)
                revert TotalLiquidityOverflow();
            if (fallbackLiquidityBalance[owner] + additionalLiquidity128 < fallbackLiquidityBalance[owner])
                revert UserLiquidityBalanceOverflow();

            fallbackReserves.reserveA += tokensOwed0;
            fallbackReserves.reserveB += tokensOwed1;
            fallbackReserves.totalLiquidity += additionalLiquidity128;
            fallbackLiquidityBalance[owner] += additionalLiquidity128;
        }
    }

    /// @notice Executes a swap in the fallback pool
    /// @param isTokenAInput True if tokenA is the input token
    /// @param amountIn The input amount
    /// @return amountOut The output amount
    function swapFallbackPool(bool isTokenAInput, uint256 amountIn) external onlyPool returns (uint256 amountOut) {
        // Determine input token
        address inputToken = isTokenAInput ? pool.tokenA() : pool.tokenB();

        // Get current tick and convert to sqrtPriceX96
        int24 currentTick = pool.getCurrentTick();
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(currentTick);

        // Calculate output amount using TickMathLibrary
        amountOut = TickMathLibrary.calculateAmountOut(pool, sqrtPriceX96, inputToken, amountIn);

        // Additional reserve check for safety
        (uint256 reserveIn, uint256 reserveOut) = isTokenAInput
            ? (fallbackReserves.reserveA, fallbackReserves.reserveB)
            : (fallbackReserves.reserveB, fallbackReserves.reserveA);
        if (amountOut > reserveOut) revert InsufficientReserve(amountOut, reserveOut);

        // Update reserves
        updateFallbackReserves(isTokenAInput, amountIn, amountOut);

        return amountOut;
    }

    /// @notice Updates fallback pool reserves after a swap
    /// @param isTokenAInput True if tokenA is the input token
    /// @param amountIn The input amount
    /// @param amountOut The output amount
    function updateFallbackReserves(bool isTokenAInput, uint256 amountIn, uint256 amountOut) public onlyPool {
        if (isTokenAInput) {
            fallbackReserves.reserveA += amountIn;
            fallbackReserves.reserveB -= amountOut;
        } else {
            fallbackReserves.reserveB += amountIn;
            fallbackReserves.reserveA -= amountOut;
        }
    }

    /// @notice Transfers tokens from the fallback pool
    /// @param token The token to transfer
    /// @param recipient The recipient address
    /// @param amount The amount to transfer
    function transferToken(address token, address recipient, uint256 amount) external onlyPositionAdjuster {
        if (token != pool.tokenA() && token != pool.tokenB()) revert InvalidToken(token);
        IERC20Upgradeable(token).safeTransfer(recipient, amount);
    }

    /// @notice Retrieves the current reserves and total liquidity of the fallback pool
    /// @return reserveA The reserve amount of tokenA
    /// @return reserveB The reserve amount of tokenB
    /// @return totalLiquidity The total liquidity in the fallback pool
    function getFallbackReserves()
        external
        view
        returns (uint256 reserveA, uint256 reserveB, uint128 totalLiquidity)
    {
        return (fallbackReserves.reserveA, fallbackReserves.reserveB, fallbackReserves.totalLiquidity);
    }
}