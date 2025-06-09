// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPriceOracle {
    function getPrice(address asset) external returns (uint256);
    function getCurrentPrice(address asset) external view returns (uint256);
    function getCurrentPairPrice(address baseToken, address quoteToken) external view returns (uint256, bool);
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
    function collectFees(uint256 positionId) external;
    function inFallbackPool(uint256 positionId) external view returns (bool);
    function exitFallbackPool(uint256 positionId) external;
    function emaVolatility() external view returns (uint256);
    function getReserves() external view returns (uint64 reserveA, uint64 reserveB);
    function TICK_SPACING() external view returns (int24);
    event PositionCreated(uint256 indexed positionId, address indexed owner, int24 tickLower, int24 tickUpper, uint256 liquidity);
}

interface IPositionManager {
    function mintPosition(uint256 positionId, address recipient) external;
}

interface IPositionAdjuster {
    function adjustPosition(uint256 positionId, int24 newTickLower, int24 newTickUpper) external;
    function exitFallbackPool(uint256 positionId) external;
}