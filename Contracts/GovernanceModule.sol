// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {AMMPool} from "./AMMPool.sol";

/// @title GovernanceModule - Manages governance proposals and configuration updates for the AMM pool
/// @notice Handles governance proposals, fee configurations, and reserve rebalancing
/// @dev Interacts with AMMPool for state management and emits governance-related events
contract GovernanceModule is ReentrancyGuard {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable reference to AMMPool
    AMMPool public immutable pool;

    // Governance address
    address public governance;

    // Governance proposal struct
    struct GovernanceProposal {
        address target;
        bytes data;
        uint256 proposedAt;
        bool executed;
    }

    // State variables
    mapping(uint256 => GovernanceProposal) public governanceProposals;
    uint256 public proposalCount;

    // Custom errors
    error Unauthorized();
    error InvalidAmplificationFactor(uint256 A);
    error InvalidFeeRange(uint256 baseFee, uint256 maxFee);
    error ProposalNotFound(uint256 proposalId);
    error ProposalNotReady(uint256 proposalId);
    error ProposalAlreadyExecuted(uint256 proposalId);
    error GovernanceProposalFailed();
    error InvalidAddress(address addr, string message);
    error InvalidTimelock(uint256 timelock);
    error InvalidReserveRatio(uint256 ratio);
    error InvalidPrice(uint256 expected, uint256 actual);
    error InvalidToken(address token);
    error InsufficientReserve(uint256 amountOut, uint256 reserveOut);

    // Events
    event GovernanceProposalCreated(uint256 indexed proposalId, address target, bytes data, uint256 proposedAt);
    event GovernanceProposalExecuted(uint256 indexed proposalId);
    event AmplificationFactorUpdated(uint256 newA);
    event PositionAdjusterUpdated(address indexed newAdjuster);
    event FeesUpdated(uint64 indexed chainId, uint256 baseFee, uint256 maxFee, uint256 lpFeeShare, uint256 treasuryFeeShare);
    event PositionManagerUpdated(address indexed newPositionManager);
    event VolatilityThresholdUpdated(uint256 newThreshold);
    event TrustedRemotePoolAdded(uint64 indexed chainId, bytes poolAddress);
    event TokenBridgeUpdated(address indexed newTokenBridge);
    event TokenBridgeTypeUpdated(address indexed token, uint8 bridgeType);
    event TargetReserveRatioUpdated(uint256 newRatio);
    event PriceOracleUpdated(address indexed primaryOracle, address[] fallbackOracles);
    event EmaPeriodUpdated(uint256 newPeriod);
    event CrossChainMessengerUpdated(uint8 indexed messengerType, address indexed newMessenger);
    event AxelarGasServiceUpdated(address indexed newGasService);
    event ChainIdMappingUpdated(uint64 chainId, string axelarChain);
    event WormholeTrustedSenderUpdated(uint64 chainId, bytes32 senderAddress);
    event GovernanceUpdated(address indexed newGovernance);

    // Constructor
    constructor(address _pool) {
        if (_pool == address(0)) revert InvalidAddress(_pool, "Invalid pool address");
        pool = AMMPool(_pool);
        governance = pool.governance(); // Initialize governance from AMMPool
    }

    // Modifiers
    modifier onlyGovernance() {
        if (msg.sender != governance) revert Unauthorized();
        _;
    }

    modifier onlyPool() {
        if (msg.sender != address(pool)) revert Unauthorized();
        _;
    }

    /// @notice Proposes a governance change
    /// @param target The target contract address
    /// @param data The call data for the proposal
    /// @return proposalId The ID of the created proposal
    function proposeGovernanceChange(address target, bytes calldata data) 
        external 
        onlyGovernance 
        returns (uint256 proposalId) 
    {
        proposalId = proposalCount++;
        governanceProposals[proposalId] = GovernanceProposal({
            target: target,
            data: data,
            proposedAt: block.timestamp,
            executed: false
        });
        emit GovernanceProposalCreated(proposalId, target, data, block.timestamp);
        return proposalId;
    }

    /// @notice Executes a governance proposal after the timelock period
    /// @param proposalId The ID of the proposal to execute
    function executeGovernanceProposal(uint256 proposalId) 
        external 
        onlyGovernance 
        nonReentrant 
    {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted(proposalId);
        if (block.timestamp < proposal.proposedAt + pool.GOVERNANCE_TIMELOCK()) 
            revert ProposalNotReady(proposalId);

        proposal.executed = true;
        (bool success, ) = proposal.target.call(proposal.data);
        if (!success) revert GovernanceProposalFailed();
        
        emit GovernanceProposalExecuted(proposalId);
    }

    /// @notice Rebalances reserves across chains
    /// @param chainId The target chain ID
    function rebalanceReserves(uint16 chainId) 
        external 
        onlyGovernance 
        nonReentrant 
    {
        pool.rebalanceReserves(chainId);
    }

    /// @notice Updates the amplification factor for dynamic curves
    /// @param newA The new amplification factor
    function updateAmplificationFactor(uint256 newA) 
        external 
        onlyGovernance 
    {
        if (newA < pool.MIN_AMPLIFICATION() || newA > pool.MAX_AMPLIFICATION()) 
            revert InvalidAmplificationFactor(newA);
        pool.setAmplificationFactor(newA);
        emit AmplificationFactorUpdated(newA);
    }

    /// @notice Updates the position adjuster address
    /// @param newAdjuster The new position adjuster address
    function updatePositionAdjuster(address newAdjuster) 
        external 
        onlyGovernance 
    {
        if (newAdjuster == address(0)) revert InvalidAddress(newAdjuster, "Invalid adjuster address");
        pool.setPositionAdjuster(newAdjuster);
        emit PositionAdjusterUpdated(newAdjuster);
    }

    /// @notice Updates fee configuration for a chain
    /// @param chainId The chain ID
    /// @param baseFee The base fee
    /// @param maxFee The maximum fee
    /// @param volatilityMultiplier The volatility multiplier
    function updateFeeConfig(
        uint16 chainId,
        uint256 baseFee,
        uint256 maxFee,
        uint256 volatilityMultiplier
    ) 
        external 
        onlyGovernance 
    {
        if (baseFee > maxFee || maxFee == 0) revert InvalidFeeRange(baseFee, maxFee);
        pool.setChainFeeConfig(chainId, baseFee, maxFee, volatilityMultiplier);
        emit FeesUpdated(chainId, baseFee, maxFee, pool.lpFeeShare(), pool.treasuryFeeShare());
    }

    /// @notice Updates the position manager address
    /// @param newPositionManager The new position manager address
    function updatePositionManager(address newPositionManager) 
        external 
        onlyGovernance 
    {
        if (newPositionManager == address(0)) 
            revert InvalidAddress(newPositionManager, "Invalid position manager address");
        pool.setPositionManager(newPositionManager);
        emit PositionManagerUpdated(newPositionManager);
    }

    /// @notice Updates the volatility threshold
    /// @param newThreshold The new volatility threshold
    function updateVolatilityThreshold(uint256 newThreshold) 
        external 
        onlyGovernance 
    {
        pool.setVolatilityThreshold(newThreshold);
        emit VolatilityThresholdUpdated(newThreshold);
    }

    /// @notice Updates the trusted remote pool address for a chain
    /// @param chainId The chain ID
    /// @param poolAddress The trusted pool address
    function updateTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) 
        external 
        onlyGovernance 
    {
        pool.setTrustedRemotePool(chainId, poolAddress);
        emit TrustedRemotePoolAdded(chainId, poolAddress);
    }

    /// @notice Updates the token bridge address
    /// @param newTokenBridge The new token bridge address
    function updateTokenBridge(address newTokenBridge) 
        external 
        onlyGovernance 
    {
        if (newTokenBridge == address(0)) 
            revert InvalidAddress(newTokenBridge, "Invalid token bridge address");
        pool.setTokenBridge(newTokenBridge);
        emit TokenBridgeUpdated(newTokenBridge);
    }

    /// @notice Updates the token bridge type for a token
    /// @param token The token address
    /// @param bridgeType The bridge type
    function updateTokenBridgeType(address token, uint8 bridgeType) 
        external 
        onlyGovernance 
    {
        if (token != pool.tokenA() && token != pool.tokenB()) revert InvalidToken(token);
        pool.setTokenBridgeType(token, bridgeType);
        emit TokenBridgeTypeUpdated(token, bridgeType);
    }

    /// @notice Updates the target reserve ratio
    /// @param newRatio The new target reserve ratio
    function updateTargetReserveRatio(uint256 newRatio) 
        external 
        onlyGovernance 
    {
        if (newRatio == 0) revert InvalidReserveRatio(newRatio);
        pool.setTargetReserveRatio(newRatio);
        emit TargetReserveRatioUpdated(newRatio);
    }

    /// @notice Updates the price oracle configuration
    /// @param newPrimaryOracle The new primary oracle address
    /// @param newFallbackOracles The new fallback oracle addresses
    function updatePriceOracle(address newPrimaryOracle, address[] calldata newFallbackOracles) 
        external 
        onlyGovernance 
    {
        if (newPrimaryOracle == address(0)) 
            revert InvalidAddress(newPrimaryOracle, "Invalid primary oracle address");
        bool hasValidFallback;
        for (uint256 i = 0; i < newFallbackOracles.length; i++) {
            if (newFallbackOracles[i] != address(0)) {
                hasValidFallback = true;
                break;
            }
        }
        if (!hasValidFallback) revert InvalidAddress(address(0), "No valid fallback oracle");
        pool.setPriceOracle(newPrimaryOracle, newFallbackOracles);
        emit PriceOracleUpdated(newPrimaryOracle, newFallbackOracles);
    }

    /// @notice Updates the EMA period for volatility calculations
    /// @param newPeriod The new EMA period
    function updateEmaPeriod(uint256 newPeriod) 
        external 
        onlyGovernance 
    {
        if (newPeriod == 0) revert InvalidTimelock(newPeriod);
        pool.setEmaPeriod(newPeriod);
        emit EmaPeriodUpdated(newPeriod);
    }

    /// @notice Updates the cross-chain messenger address
    /// @param messengerType The messenger type
    /// @param newMessenger The new messenger address
    function updateCrossChainMessenger(uint8 messengerType, address newMessenger) 
        external 
        onlyGovernance 
    {
        if (newMessenger == address(0)) 
            revert InvalidAddress(newMessenger, "Invalid messenger address");
        pool.setCrossChainMessenger(messengerType, newMessenger);
        emit CrossChainMessengerUpdated(messengerType, newMessenger);
    }

    /// @notice Updates the Axelar gas service address
    /// @param newGasService The new gas service address
    function updateAxelarGasService(address newGasService) 
        external 
        onlyGovernance 
    {
        if (newGasService == address(0)) 
            revert InvalidAddress(newGasService, "Invalid gas service address");
        pool.setAxelarGasService(newGasService);
        emit AxelarGasServiceUpdated(newGasService);
    }

    function updateVolatility() external onlyGovernance {
        pool.updateVolatility();
    }

    /// @notice Updates the chain ID to Axelar chain mapping
    /// @param chainId The chain ID
    /// @param axelarChain The Axelar chain name
    function updateChainIdMapping(uint16 chainId, string calldata axelarChain) 
        external 
        onlyGovernance 
    {
        pool.setChainIdMapping(chainId, axelarChain);
        emit ChainIdMappingUpdated(chainId, axelarChain);
    }

    /// @notice Updates the Wormhole trusted sender address
    /// @param chainId The chain ID
    /// @param senderAddress The trusted sender address
    function updateWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) 
        external 
        onlyGovernance 
    {
        pool.setWormholeTrustedSender(chainId, senderAddress);
        emit WormholeTrustedSenderUpdated(chainId, senderAddress);
    }

    /// @notice Updates the governance address
    /// @param newGovernance The new governance address
    function updateGovernance(address newGovernance) 
        external 
        onlyGovernance 
    {
        if (newGovernance == address(0)) 
            revert InvalidAddress(newGovernance, "Invalid governance address");
        governance = newGovernance;
        pool.setGovernance(newGovernance);
        emit GovernanceUpdated(newGovernance);
    }


    /// @notice Executes a constant-sum swap calculation
    /// @param amountIn The input amount
    /// @param reserveIn The input reserve
    /// @param reserveOut The output reserve
    /// @return amountOut The output amount
    function swapConstantSum(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) 
        external 
        view 
        onlyPool 
        returns (uint256 amountOut) 
    {
        // Simplified constant-sum formula
        amountOut = amountIn * reserveOut / (reserveIn + amountIn);
        if (amountOut > reserveOut) revert InsufficientReserve(amountOut, reserveOut);
        return amountOut;
    }
}