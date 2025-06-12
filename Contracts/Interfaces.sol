// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPriceOracle {
    function getPrice(address asset) external returns (uint256);
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
    function inFallbackPool(uint256 positionId) external view returns (bool);
    function batchCrossChainMessages(uint16 dstChainId, bytes memory payload, bytes memory adapterParams) external payable;
    function exitFallbackPool(uint256 positionId) external;
    function trustedRemotePools(uint16 chainId) external view returns (bytes memory);
    function chainIdToAxelarChain(uint16 chainId) external view returns (string memory);
    function governance() external view returns (address);
    function emaVolatility() external view returns (uint256);
    function emaVol() external view returns (uint256);
    function volatilityThreshold() external view returns (uint24);
    function getReserves() external view returns (uint64 reserveA, uint64 reserveB);
    function TICK_SPACING() external view returns (uint24);
    event PositionCreated(uint256 indexed positionId, address indexed owner, int24 tickLower, int24 tickUpper, uint256 liquidity);
}

interface IPositionManager {
    /// @notice Mints a new position for a recipient
    /// @param positionId The ID of the position to mint
    /// @param recipient The address to receive the position
    function mintPosition(uint256 positionId, address recipient) external;

    /// @notice Returns the fee destination address for a given owner
    /// @param owner The address of the position owner
    /// @return destination The address where fees should be sent
    function feeDestinations(address owner) external view returns (address);

    /// @notice Collects and bridges fees for a position to a destination chain
    /// @param positionId The ID of the position
    /// @param dstChainId The destination chain ID
    /// @param bridgeType The type of bridge to use
    /// @param adapterParams Additional parameters for the bridge
    function collectAndBridgeFees(
        uint256 positionId,
        uint16 dstChainId,
        uint8 bridgeType,
        bytes calldata adapterParams
    ) external payable;

    /// @notice Bridges fees for multiple positions in a batch
    /// @param positionIds Array of position IDs
    /// @param total0 Total fees in token0
    /// @param total1 Total fees in token1
    /// @param bridgeType The type of bridge to use
    /// @param adapterParams Additional parameters for the bridge
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