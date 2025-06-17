// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {AMMPool} from "./AMMPool.sol";

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
        uint256 totalLiquidity;
    }

    // State variables
    FallbackReserves public fallbackReserves;
    mapping(address => uint256) public fallbackLiquidityBalance;
    mapping(uint256 => bool) public inFallbackPool;

    // Custom errors
    error Unauthorized();
    error InsufficientLiquidity(uint256 liquidity);
    error PositionNotInFallback(uint256 positionId);
    error InsufficientReserve(uint256 amountOut, uint256 reserve);
    error InvalidToken(address token);

    // Events
    event FallbackPoolEntered(uint256 indexed positionId, uint256 liquidity);
    event FallbackPoolExited(uint256 indexed positionId, uint256 liquidity);

    // Constructor
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
        
        (address owner, int24 tickLower, int24 tickUpper, uint256 liquidity,,) = pool.getPosition(positionId);
        if (liquidity == 0) revert InsufficientLiquidity(liquidity);
        
        int24 currentTick = pool.getcurrentTick();
        if (currentTick < tickLower || currentTick >= tickUpper) {
            inFallbackPool[positionId] = true;
            
            uint256 totalLiquidity = pool.totalLiquidity();
            (uint64 reserveA, uint64 reserveB) = pool.getReserves();
            
            uint256 amountA = (liquidity * reserveA) / totalLiquidity;
            uint256 amountB = (liquidity * reserveB) / totalLiquidity;
            
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
        
        (address owner, , , uint256 liquidity,,) = pool.getPosition(positionId);
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
        
        (address owner, , , uint256 liquidity,,) = pool.getPosition(positionId);
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
            fallbackReserves.reserveA += tokensOwed0;
            fallbackReserves.reserveB += tokensOwed1;
            fallbackReserves.totalLiquidity += additionalLiquidity;
            fallbackLiquidityBalance[owner] += additionalLiquidity;
        }
    }

    /// @notice Executes a swap in the fallback pool
    /// @param isTokenAInput True if tokenA is the input token
    /// @param amountIn The input amount
    /// @return amountOut The output amount
    function swapFallbackPool(bool isTokenAInput, uint256 amountIn) external onlyPool returns (uint256 amountOut) {
        (uint256 reserveIn, uint256 reserveOut) = isTokenAInput
            ? (fallbackReserves.reserveA, fallbackReserves.reserveB)
            : (fallbackReserves.reserveB, fallbackReserves.reserveA);
        
        // Simplified constant-product formula
        amountOut = (reserveOut * amountIn) / (reserveIn + amountIn);
        
        if (amountOut > reserveOut) revert InsufficientReserve(amountOut, reserveOut);
        
        updateFallbackReserves(isTokenAInput, amountIn, amountOut);
        
        return amountOut;
    }

    /// @notice Updates fallback pool reserves after a swap
    /// @param isTokenAInput True if tokenA is the input token
    /// @param amountIn The input amount
    /// @param amountOut The output amount
    function updateFallbackReserves(bool isTokenAInput, uint256 amountIn, uint256 amountOut) external onlyPool {
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
}