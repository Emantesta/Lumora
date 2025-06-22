// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {GovernorUpgradeable} from "@openzeppelin/contracts-upgradeable/governance/GovernorUpgradeable.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";
import {CCIPReceiver} from "@chainlink/contracts-ccip/src/v0.8/ccip/applications/CCIPReceiver.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {KeeperCompatibleInterface} from "@chainlink/contracts/src/v0.8/interfaces/KeeperCompatibleInterface.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

// Interface for PriceOracle (unchanged)
interface IPriceOracle {
    function getCurrentPairPrice(address pool, address token) external view returns (uint256 price, uint256 timestamp);
}

// Interface for CrossChainRetryOracle (unchanged)
interface ICrossChainRetryOracle {
    struct NetworkStatus {
        bool bridgeOperational;
        bool retryRecommended;
        uint32 randomRetryDelay;
        uint256 lastUpdated;
    }
    function getNetworkStatus(uint64 chainId) external view returns (NetworkStatus memory);
    function activeChainIds() external view returns (uint64[] memory);
}

// Interface for AMMPool (unchanged)
interface IAMMPool {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getCurrentFee(uint64 chainId) external view returns (uint256);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function setPriceOracle(address primaryOracle, address[] calldata fallbackOracles) external;
    function setChainFeeConfig(uint16 chainId, uint256 baseFee, uint256 maxFee, uint256 volatilityMultiplier) external;
    function setTrustedRemotePool(uint16 chainId, bytes calldata poolAddress) external;
    function setTokenBridge(address tokenBridge) external;
    function setTokenBridgeType(address token, uint8 bridgeType) external;
    function setTargetReserveRatio(uint256 newRatio) external;
}

// Interface for Uniswap V2 Callee (unchanged)
interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

// Interface for lending protocol (updated)
interface ILendingProtocol {
    function getHealthFactor(address user, address asset) external view returns (uint256);
    function liquidate(address user, address collateralAsset, address debtAsset, uint256 debtToCover) external;
    function swapCollateral(address user, address fromAsset, address toAsset, uint256 amount) external;
    function getAllUsersWithDebt() external view returns (address[] memory);
}

// Interface for external exchange (unchanged)
interface IExternalExchange {
    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn, uint64 destChainId) external returns (uint256 amountOut);
    function getDynamicFee(address tokenIn, address tokenOut) external view returns (uint256 fee);
}

// Interface for Private Mempool Service (unchanged)
interface IPrivateMempool {
    function submitPrivateTx(bytes calldata txData, uint256 maxPriorityFee, uint256 maxFeePerGas) external payable returns (bytes32 txHash);
}

/// @title FlashSwapArbitrage
/// @notice Contract for arbitrage, liquidations, and collateral swapping with DAO governance and Chainlink automation
/// @dev Integrates Chainlink Keepers, multiple oracles, private mempools, and enhanced security
contract FlashSwapArbitrage is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable,
    CCIPReceiver,
    IUniswapV2Callee,
    KeeperCompatibleInterface
{
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    // Immutable addresses
    address public immutable ammPool;
    address public immutable lendingProtocol;
    address public immutable tokenA; // token0 in AMMPool
    address public immutable tokenB; // token1 in AMMPool

    // External contracts
    GovernorUpgradeable public governor;
    AggregatorV3Interface[] public priceFeeds; // Chainlink Price Feeds
    ICrossChainRetryOracle public retryOracle;
    address public externalExchange;
    LinkTokenInterface public linkToken;
    address public keeperRegistry;
    address public privateMempool; // e.g., Flashbots or Eden Network

    // Storage
    mapping(uint64 => address) public crossChainAMMPools;
    mapping(address => bool) public supportedTokens;
    mapping(address => uint256) public minHealthFactor;
    mapping(bytes32 => uint256) public retryTimestamps; // Track retry attempts
    uint256 public gasReserve; // ETH reserve for gas funding
    uint256 public linkReserve; // LINK reserve for Chainlink operations
    uint256 public constant PRICE_PRECISION = 1e18;
    uint256 public constant MIN_HEALTH_FACTOR = 1e18; // 1.0 in 18 decimals
    uint256 public constant MAX_FEE_BASIS_POINTS = 10000; // 100%
    uint256 public constant MIN_GAS_RESERVE = 0.01 ether; // Minimum ETH for gas
    uint256 public constant MIN_LINK_RESERVE = 1 ether; // Minimum LINK for Chainlink
    uint256 public constant MAX_RETRIES = 3; // Max retry attempts
    uint256 public constant MAX_USERS = 50; // Limit users processed in one call
    uint256 public minProfitThreshold; // Minimum profit for arbitrage
    uint256 public healthFactorThreshold; // Health factor threshold for liquidations

    // Custom errors
    error UnauthorizedCaller(address caller);
    error InvalidBorrowedAmount(uint256 amount0, uint256 amount1);
    error InsufficientRepayment(uint256 received, uint256 required);
    error InvalidExchangeAddress(address exchange);
    error TradeFailed(uint256 amountReceived, uint256 amountExpected);
    error InvalidCallbackData();
    error InsufficientBalance(address token, uint256 balance, uint256 required);
    error InvalidChainId(uint64 chainId);
    error NoValidOraclePrice(address asset);
    error RetryOracleError(uint64 chainId);
    error LiquidationNotRequired(address user);
    error InvalidTokenPair(address tokenA, address tokenB);
    error CrossChainNotConfigured(uint64 chainId);
    error InsufficientProfit(uint256 profit, uint256 minProfit);
    error HealthFactorBelowThreshold(uint256 healthFactor, uint256 minHealthFactor);
    error InvalidFee(uint256 fee);
    error DivisionByZero();
    error InvalidOracleArray();
    error BatchSizeMismatch(uint256 expected, uint256 provided);
    error InvalidGovernorAddress(address governor);
    error InsufficientGasReserve(uint256 reserve, uint256 required);
    error InsufficientLinkReserve(uint256 reserve, uint256 required);
    error MaxRetriesExceeded(bytes32 txId);
    error InvalidPrivateMempool(address mempool);
    error InvalidKeeperRegistry(address registry);
    error InvalidLinkToken(address token);

    // Events (unchanged)
    event FlashSwapInitiated(address indexed sender, uint256 amount0Out, uint256 amount1Out, uint64 chainId);
    event FlashSwapCompleted(address indexed sender, uint256 amountIn, uint256 amountOut, uint256 profit, uint64 chainId);
    event ProfitWithdrawn(address indexed token, address indexed recipient, uint256 amount);
    event LiquidationTriggered(address indexed user, address collateralAsset, address debtAsset, uint256 debtCovered);
    event BatchLiquidationTriggered(uint256 userCount, uint256 totalDebtCovered);
    event CollateralSwapped(address indexed user, address fromAsset, address toAsset, uint256 amount);
    event BatchCollateralSwapped(uint256 userCount, uint256 totalAmount);
    event CrossChainPoolUpdated(uint64 indexed chainId, address pool);
    event PriceFeedsUpdated(uint256 feedCount);
    event RetryOracleUpdated(address indexed retryOracle);
    event ExternalExchangeUpdated(address indexed exchange);
    event SupportedTokenUpdated(address indexed token, bool supported);
    event MinHealthFactorUpdated(address indexed user, uint256 minHealthFactor);
    event CrossChainMessageReceived(uint64 indexed sourceChainId, bytes32 indexed messageId);
    event AssetsRecovered(address indexed token, uint256 amount, address indexed recipient);
    event BatchProposalCreated(uint256[] proposalIds);
    event GovernorUpdated(address indexed newGovernor);
    event GasReserveUpdated(uint256 newReserve);
    event LinkReserveUpdated(uint256 newReserve);
    event PrivateMempoolUpdated(address indexed mempool);
    event KeeperRegistryUpdated(address indexed registry);
    event LinkTokenUpdated(address indexed token);
    event RetryAttempted(bytes32 indexed txId, uint256 attempt);
    event AutomationTriggered(bytes32 indexed taskId, string taskType);
    event MinProfitThresholdUpdated(uint256 newThreshold);
    event HealthFactorThresholdUpdated(uint256 newThreshold);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _ammPool,
        address _lendingProtocol,
        address _tokenA,
        address _tokenB,
        address _router
    ) CCIPReceiver(_router) {
        require(_ammPool != address(0), "Invalid AMM pool address");
        require(_lendingProtocol != address(0), "Invalid lending protocol address");
        require(_tokenA != address(0) && _tokenB != address(0), "Invalid token addresses");
        require(_tokenA != _tokenB, "Tokens must be different");

        address poolToken0 = IAMMPool(_ammPool).token0();
        address poolToken1 = IAMMPool(_ammPool).token1();
        require(
            (_tokenA == poolToken0 && _tokenB == poolToken1) || (_tokenA == poolToken1 && _tokenB == poolToken0),
            "Invalid token pair for AMM pool"
        );

        ammPool = _ammPool;
        lendingProtocol = _lendingProtocol;
        tokenA = _tokenA;
        tokenB = _tokenB;
        _disableInitializers();
    }

    /// @notice Initializes the contract
    function initialize(
        address _governor,
        address[] calldata _priceFeeds,
        address _retryOracle,
        address _externalExchange,
        address _router,
        address _linkToken,
        address _keeperRegistry,
        address _privateMempool
    ) external initializer {
        require(_governor != address(0), "Invalid governor address");
        require(_priceFeeds.length > 0, "Invalid oracle array");
        require(_retryOracle != address(0), "Invalid retry oracle address");
        require(_externalExchange != address(0), "Invalid exchange address");
        require(_router != address(0), "Invalid router address");
        require(_linkToken != address(0), "Invalid LINK token address");
        require(_keeperRegistry != address(0), "Invalid keeper registry address");
        require(_privateMempool != address(0), "Invalid private mempool address");

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __AccessControl_init();

        governor = GovernorUpgradeable(_governor);
        for (uint256 i = 0; i < _priceFeeds.length; i++) {
            require(_priceFeeds[i] != address(0), "Invalid feed address");
            priceFeeds.push(AggregatorV3Interface(_priceFeeds[i]));
        }
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        externalExchange = _externalExchange;
        linkToken = LinkTokenInterface(_linkToken);
        keeperRegistry = _keeperRegistry;
        privateMempool = _privateMempool;

        supportedTokens[tokenA] = true;
        supportedTokens[tokenB] = true;
        minProfitThreshold = 1e16; // 0.01 ETH equivalent
        healthFactorThreshold = MIN_HEALTH_FACTOR;

        _grantRole(DEFAULT_ADMIN_ROLE, _governor);
        _grantRole(GOVERNOR_ROLE, _governor);
        _grantRole(KEEPER_ROLE, _keeperRegistry);

        emit GovernorUpdated(_governor);
        emit PriceFeedsUpdated(_priceFeeds.length);
        emit RetryOracleUpdated(_retryOracle);
        emit ExternalExchangeUpdated(_externalExchange);
        emit LinkTokenUpdated(_linkToken);
        emit KeeperRegistryUpdated(_keeperRegistry);
        emit PrivateMempoolUpdated(_privateMempool);
        emit SupportedTokenUpdated(tokenA, true);
        emit SupportedTokenUpdated(tokenB, true);
        emit MinProfitThresholdUpdated(minProfitThreshold);
        emit HealthFactorThresholdUpdated(healthFactorThreshold);
    }

    /// @notice Authorizes contract upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(GOVERNOR_ROLE) {}

    /// @notice Funds gas reserve with ETH
    function fundGasReserve() external payable {
        gasReserve += msg.value;
        emit GasReserveUpdated(gasReserve);
    }

    /// @notice Funds LINK reserve for Chainlink operations
    function fundLinkReserve(uint256 amount) external {
        IERC20(address(linkToken)).safeTransferFrom(msg.sender, address(this), amount);
        linkReserve += amount;
        emit LinkReserveUpdated(linkReserve);
    }

    /// @notice Gets users with undercollateralized positions from the lending protocol
    /// @return users Array of user addresses eligible for liquidation or collateral swap
    function _getUsers() internal view returns (address[] memory users) {
        // Fetch all users with debt from the lending protocol
        address[] memory allUsers = ILendingProtocol(lendingProtocol).getAllUsersWithDebt();
        uint256 eligibleCount = 0;

        // First pass: count eligible users to size the array
        for (uint256 i = 0; i < allUsers.length && eligibleCount < MAX_USERS; i++) {
            if (allUsers[i] == address(0)) continue;
            // Check health factor for tokenA and tokenB
            try ILendingProtocol(lendingProtocol).getHealthFactor(allUsers[i], tokenA) returns (uint256 healthFactorA) {
                uint256 minHF = minHealthFactor[allUsers[i]] > 0 ? minHealthFactor[allUsers[i]] : healthFactorThreshold;
                if (healthFactorA < minHF) {
                    eligibleCount++;
                    continue;
                }
            } catch {
                // Skip if health factor call fails
            }
            try ILendingProtocol(lendingProtocol).getHealthFactor(allUsers[i], tokenB) returns (uint256 healthFactorB) {
                uint256 minHF = minHealthFactor[allUsers[i]] > 0 ? minHealthFactor[allUsers[i]] : healthFactorThreshold;
                if (healthFactorB < minHF) {
                    eligibleCount++;
                }
            } catch {
                // Skip if health factor call fails
            }
        }

        // Second pass: populate the users array
        users = new address[](eligibleCount);
        uint256 index = 0;
        for (uint256 i = 0; i < allUsers.length && index < eligibleCount; i++) {
            if (allUsers[i] == address(0)) continue;
            bool isEligible = false;
            try ILendingProtocol(lendingProtocol).getHealthFactor(allUsers[i], tokenA) returns (uint256 healthFactorA) {
                uint256 minHF = minHealthFactor[allUsers[i]] > 0 ? minHealthFactor[allUsers[i]] : healthFactorThreshold;
                if (healthFactorA < minHF) {
                    isEligible = true;
                }
            } catch {}
            if (!isEligible) {
                try ILendingProtocol(lendingProtocol).getHealthFactor(allUsers[i], tokenB) returns (uint256 healthFactorB) {
                    uint256 minHF = minHealthFactor[allUsers[i]] > 0 ? minHealthFactor[allUsers[i]] : healthFactorThreshold;
                    if (healthFactorB < minHF) {
                        isEligible = true;
                    }
                } catch {}
            }
            if (isEligible) {
                users[index] = allUsers[i];
                index++;
            }
        }

        return users;
    }

    /// @notice Checks if upkeep is needed for Chainlink Keepers
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        upkeepNeeded = false;
        // Check for arbitrage opportunities
        (uint256 poolPrice, ) = getOraclePrice(ammPool, tokenA);
        (uint256 externalPrice, ) = getOraclePrice(externalExchange, tokenA);
        uint256 priceDiff = poolPrice > externalPrice ? poolPrice - externalPrice : externalPrice - poolPrice;
        if (priceDiff * PRICE_PRECISION / poolPrice > minProfitThreshold) {
            upkeepNeeded = true;
            performData = abi.encode("arbitrage", uint64(0), poolPrice, externalPrice);
            return (upkeepNeeded, performData);
        }

        // Check for liquidations and collateral swaps
        address[] memory users = _getUsers();
        for (uint256 i = 0; i < users.length; i++) {
            try ILendingProtocol(lendingProtocol).getHealthFactor(users[i], tokenA) returns (uint256 healthFactor) {
                uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
                if (healthFactor < minHF) {
                    upkeepNeeded = true;
                    // Assume debtToCover is calculated off-chain or via a separate call
                    performData = abi.encode("liquidation", users[i], tokenA, tokenB, uint256(0));
                    return (upkeepNeeded, performData);
                }
            } catch {}
            try ILendingProtocol(lendingProtocol).getHealthFactor(users[i], tokenB) returns (uint256 healthFactor) {
                uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
                if (healthFactor < minHF) {
                    upkeepNeeded = true;
                    // Assume amount is calculated off-chain or via a separate call
                    performData = abi.encode("collateral", users[i], tokenB, tokenA, uint256(0));
                    return (upkeepNeeded, performData);
                }
            } catch {}
        }

        return (upkeepNeeded, performData);
    }

    /// @notice Performs upkeep tasks
    function performUpkeep(bytes calldata performData) external override onlyRole(KEEPER_ROLE) {
        (string memory taskType, bytes memory data) = abi.decode(performData, (string, bytes));
        bytes32 taskId = keccak256(abi.encode(taskType, data, block.timestamp));

        if (keccak256(abi.encodePacked(taskType)) == keccak256(abi.encodePacked("arbitrage"))) {
            (uint64 chainId, uint256 poolPrice, uint256 externalPrice) = abi.decode(data, (uint64, uint256, uint256));
            _executeArbitrage(chainId, poolPrice, externalPrice);
        } else if (keccak256(abi.encodeWithSelector(taskType) == keccak256("liquidation"))) {
            (address user, address collateralAsset, address debtAsset, uint256 debtToCover) = abi.decode(
                data, (address, address, address, uint256)
            );
            _executeLiquidation(user, collateralAsset, debtAsset, debtToCover);
        } else if (keccak256(abi.encodeWithSignature(taskType)) == keccak256("collateral")) {
            (address user, address fromAsset, address toAsset, uint256 amount) = abi.decode(
                data, (address, address, address, uint256)
            );
            _executeCollateralSwap(user, fromAsset, toAsset, amount);
        }

        emit AutomationTriggered(taskId, taskType);
    }

    /// @notice Executes arbitrage via flash swap
    function _executeArbitrage(uint64 chainIdchainId, uint256 poolPrice, uint256 externalPrice) internal {
        uint256 amountOut = poolPrice > externalPrice ? 1e18 : 1e18; // Simplified amount calculation
        bytes memory data = abi.encode(address(this), minProfitThreshold, chainId, poolPrice);
        address targetPool = chainId == 0 ? ammPool : crossChainAMMPools[chainId];
        _submitPrivateSwap(targetPool, amountOut, data);
    }

    /// @notice Executes liquidation
    function _executeLiquidation(
        address user,
        address collateralAsset,
        address debtAsset,
        uint256 debtToCover
    ) internal {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        if (linkReserve < MIN_LINK_RESERVE) revert InsufficientLinkReserve(linkReserve, MIN_LINK_RESERVE);

        IERC20(debtAsset).safeApprove(lendingProtocol, debtToCover);
        ILendingProtocol(lendingProtocol).liquidate(user, collateralAsset, debtAsset, debtToCover);
        IERC20(debtAsset).safeApprove(lendingProtocol, 0);
        emit LiquidationTriggered(user, collateralAsset, debtAsset, debtToCover);
    }

    /// @notice Executes collateral swap
    function _executeCollateralSwap(
        address user,
        address fromAsset,
        address toAsset,
        uint256 amount
    ) internal {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        if (linkReserve < MIN_LINK_RESERVE) revert InsufficientLinkReserve(linkReserve, MIN_LINK_RESERVE);

        IERC20(fromAsset).safeApprove(lendingProtocol, amount);
        ILendingProtocol(lendingProtocol).swapCollateral(user, fromAsset, toAsset, amount);
        IERC20(fromAsset).safeApprove(lendingProtocol, 0);
        emit CollateralSwapped(user, fromAsset, toAsset, amount);
    }

    /// @notice Submits swap to private mempool
    function _submitPrivateSwap(
        address targetPool,
        uint256 amount0Out,
        uint256 amount1Out,
        bytes memory data
    ) internal {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        bytes memory txData = abi.encodeWithSelector(
            IAMMPool.swap.selector,
            amount0Out,
            amount1Out,
            address(this),
            data
        );
        uint256 maxPriorityFee = 2 gwei; // Configurable
        uint256 maxFeePerGas = 50 gwei; // Configurable
        IPrivateMempool(privateMempool).submitPrivateTx{value: gasReserve / 100}(txData, maxPriorityFee, maxFeePerGas);
        gasReserve -= gasReserve / 100;
        emit GasReserveUpdated(gasReserve);
    }

    /// @notice Proposes batch governance actions
    function proposeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata calldatas,
        string memory description
    ) external onlyRole(GOVERNOR_ROLE) returns (uint256[] memory proposalIds) {
        require(
            targets.length == values.length && targets.length == calldatas.length,
            "Batch size mismatch"
        );
        proposalIds = new uint256[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            proposalIds[i] = governor.propose(
                _singleArray(targets[i]),
                _singleArray(values[i]),
                _singleArray(calldatas[i]),
                string(abi.encodePacked(description, " #", i))
            );
        }
        emit BatchProposalCreated(proposalIds);
    }

    /// @notice Helper to create single-element arrays
    function _singleArray(uint256 value) internal pure returns (uint256[] memory) {
        uint256[] memory arr = new uint256[](1);
        arr[0] = value;
        return arr;
    }

    function _singleArray(address value) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = value;
        return arr;
    }

    function _singleArray(bytes memory value) internal pure returns (bytes[] memory) {
        bytes[] memory arr = new bytes[](1);
        arr[0] = value;
        return arr;
    }

    /// @notice Updates cross-chain AMM pool
    function updateCrossChainPool(uint64 chainId, address pool) external onlyRole(GOVERNOR_ROLE) {
        require(chainId != 0, "Invalid chain ID");
        require(pool != address(0), "Invalid pool address");
        crossChainAMMPools[chainId] = pool;
        emit CrossChainPoolUpdated(chainId, pool);
    }

    /// @notice Updates price feeds
    function updatePriceOracles(address[] calldata _feeds) external onlyRole(GOVERNOR_ROLE) {
        require(_feeds.length > 0, "Invalid oracle array");
        delete priceFeeds;
        for (uint256 i = 0; i < _feeds.length; i++) {
            require(_feeds[i] != address(0), "Invalid oracle address");
            priceFeeds.push(AggregatorV3Interface(_feeds[i]));
        }
        emit PriceFeedsUpdated(_feeds.length);
    }

    /// @notice Updates retry oracle
    function updateRetryOracle(address _retryOracle) external onlyRole(GOVERNOR_ROLE) {
        require(_retryOracle != address(0), "Invalid retry oracle address");
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        emit RetryOracleUpdated(_retryOracle);
    }

    /// @notice Updates external exchange
    function updateExternalExchange(address _externalExchange) external onlyRole(GOVERNOR_ROLE) {
        require(_externalExchange != address(0), "Invalid exchange address");
        externalExchange = _externalExchange;
        emit ExternalExchangeUpdated(_externalExchange);
    }

    /// @notice Updates supported token
    function updateSupportedToken(address token, bool supported) external onlyRole(GOVERNOR_ROLE) {
        require(token != address(0), "Invalid token address");
        supportedTokens[token] = supported;
        emit SupportedTokenUpdated(token, supported);
    }

    /// @notice Updates minimum health factor
    function updateMinHealthFactor(address user, uint256 _minHealthFactor) external onlyRole(GOVERNOR_ROLE) {
        require(user != address(0), "Invalid user address");
        require(_minHealthFactor >= MIN_HEALTH_FACTOR, "Health factor too low");
        minHealthFactor[user] = _minHealthFactor;
        emit MinHealthFactorUpdated(user, _minHealthFactor);
    }

    /// @notice Updates governor
    function updateGovernor(address _governor) external onlyRole(GOVERNOR_ROLE) {
        require(_governor != address(0), "Invalid governor address");
        governor = GovernorUpgradeable(_governor);
        _grantRole(GOVERNOR_ROLE, _governor);
        _revokeRole(GOVERNOR_ROLE, msg.sender);
        emit GovernorUpdated(_governor);
    }

    /// @notice Updates private mempool
    function updatePrivateMempool(address _mempool) external onlyRole(GOVERNOR_ROLE) {
        require(_mempool != address(0), "Invalid private mempool address");
        privateMempool = _mempool;
        emit PrivateMempoolUpdated(_mempool);
    }

    /// @notice Updates keeper registry
    function updateKeeperRegistry(address _registry) external onlyRole(GOVERNOR_ROLE) {
        require(_registry != address(0), "invalid keeper registry address");
        keeperRegistry = _registry;
        _grantRole(KEEPER_KEEPER_ROLE, _registry);
        emit KeeperRegistryUpdated(_registry);
    }

    /// @notice Updates LINK token
    function updateLinkToken(address _token) external onlyRole(GOVERNOR_ROLE) {
        require(_token != address(0), "invalid LINK token address");
        linkToken = linkTokenInterface(_token);
        emit LinkTokenUpdated(_token);
    }

    /// @notice Updates minimum profit threshold
    function updateMinProfitThreshold(uint256 _threshold) external onlyRole(GOVERNOR_ROLE) {
        require(_threshold > 0, "Invalid threshold");
        minProfitThreshold = _threshold;
        emit MinProfitThresholdUpdated(_threshold);
    }

    /// @notice Updates health factor threshold
    function updateHealthFactorThreshold(uint256 _threshold) external onlyRole(GOVERNOR_ROLE) {
        require(_threshold >= MIN_HEALTH_FACTOR, "Invalid threshold");
        healthFactorThreshold = _threshold;
        emit HealthFactorThresholdUpdated(_threshold);
    }

    /// @notice Gets price from multiple Chainlink feeds
    function getOraclePrice(address asset, address token) internal view returns (uint256 price, uint256 timestamp) {
        uint256 validPrices = 0;
        uint256 totalPrice = 0;
        uint256 latestTimestamp = 0;

        for (uint256 i = 0; i < priceFeeds.length; i++) {
            try priceFeeds[i].latestRoundData() returns (
                uint80,
                int256 _price,
                uint256,
                uint256 _timestamp,
                uint80
            ) {
                if (_price > 0) {
                    totalPrice += uint256(_price);
                    validPrices++;
                    if (_timestamp > latestTimestamp) {
                        latestTimestamp = _timestamp;
                    }
                }
            } catch {
                continue;
            }
        }

        if (validPrices == 0) revert NoValidOraclePrice(asset);
        return (totalPrice / validPrices, latestTimestamp);
    }

    /// @notice Initiates a flash swap for arbitrage with retry logic
    function initiateFlashSwap(
        uint64 chainId,
        uint256 amount0Out,
        uint256 amount1Out,
        uint256 minProfit
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        if (amount0Out == 0 && amount1Out == 0) revert InvalidBorrowedAmount(amount0Out, amount1Out);
        if (amount0Out > 0 && amount1Out > 0) revert InvalidBorrowedAmount(amount0Out, amount1Out);
        if (chainId != 0 && crossChainAMMPools[chainId] == address(0)) revert CrossChainNotConfigured(chainId);

        bytes32 txId = keccak256(abi.encode(msg.sender, chainId, amount0Out, amount1Out, block.timestamp));
        if (retryTimestamps[txId] > MAX_RETRIES) revert MaxRetriesExceeded(txId);

        if (chainId != 0) {
            ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(chainId);
            if (!status.bridgeOperational || status.retryRecommended) {
                retryTimestamps[txId]++;
                emit RetryAttempted(txId, retryTimestamps[txId]);
                uint256 retryDelay = status.randomRetryDelay;
                require(block.timestamp >= status.lastUpdated + retryDelay, "Retry delay not met");
            }
        }

        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        if (linkReserve < MIN_LINK_RESERVE) revert InsufficientLinkReserve(linkReserve, MIN_LINK_RESERVE);

        address asset = chainId == 0 ? ammPool : crossChainAMMPools[chainId];
        (uint256 price, ) = getOraclePrice(asset, amount1Out > 0 ? tokenB : tokenA);
        if (price == 0) revert NoValidOraclePrice(asset);

        bytes memory data = abi.encode(msg.sender, minProfit, chainId, price, txId);
        address targetPool = chainId == 0 ? ammPool : crossChainAMMPools[chainId];
        _submitPrivateSwap(targetPool, amount0Out, amount1Out, data);
        emit FlashSwapInitiated(msg.sender, amount0Out, amount1Out, chainId);
    }

    /// @notice Callback for flash swap
    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external override nonReentrant whenNotPaused {
        address targetPool = crossChainAMMPools[uint64(0)] == msg.sender ? crossChainAMMPools[uint64(0)] : ammPool;
        if (msg.sender != targetPool) revert UnauthorizedCaller(msg.sender);
        if (amount0 == 0 && amount1 == 0) revert InvalidBorrowedAmount(amount0, amount1);
        if (amount0 > 0 && amount1 > 0) revert InvalidBorrowedAmount(amount0, amount1);
        if (data.length == 0) revert InvalidCallbackData();

        (address initiator, uint256 minProfit, uint64 chainId, uint256 oraclePrice, bytes32 txId) = abi.decode(
            data, (address, uint256, uint64, uint256, bytes32)
        );
        if (!hasRole(OPERATOR_ROLE, initiator)) revert UnauthorizedCaller(initiator);

        bool isTokenAInput = amount1 > 0;
        address inputToken = isTokenAInput ? tokenA : tokenB;
        address outputToken = isTokenAInput ? tokenB : tokenA;
        uint256 amountOut = isTokenAInput ? amount1 : amount0;

        targetPool = chainId == 0 ? ammPool : crossChainAMMPools[chainId];
        uint256 poolFee = IAMMPool(targetPool).getCurrentFee(chainId == 0 ? 1 : chainId);
        uint256 exchangeFee = IExternalExchange(externalExchange).getDynamicFee(outputToken, inputToken);
        uint256 totalFee = poolFee + exchangeFee;
        if (totalFee > MAX_FEE_BASIS_POINTS) revert InvalidFee(totalFee);

        uint256 reserveIn = IERC20(inputToken).balanceOf(targetPool);
        uint256 reserveOut = IERC20(outputToken).balanceOf(targetPool);
        if (reserveOut <= amountOut) revert DivisionByZero();
        uint256 amountIn = (amountOut * reserveIn) / (reserveOut - amountOut);
        uint256 amountInWithFee = (amountIn * (MAX_FEE_BASIS_POINTS + exchangeFee - poolFee)) / MAX_FEE_BASIS_POINTS;

        uint256 amountReceived = _executeTrade(outputToken, inputToken, amountOut, chainId);
        if (amountReceived < amountInWithFee + minProfit)
            revert InsufficientRepayment(amountReceived, amountInWithFee + minProfit);

        IERC20(inputToken).safeTransfer(targetPool, amountInWithFee);
        uint256 profit = amountReceived - amountInWithFee;
        retryTimestamps[txId] = 0; // Reset retry counter on success
        emit FlashSwapCompleted(sender, amountInWithFee, amountReceived, profit, chainId);
    }

    /// @notice Executes a trade on the external exchange
    function _executeTrade(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint64 chainId
    ) internal returns (uint256 amountOut) {
        uint256 balance = IERC20(tokenIn).balanceOf(address(this));
        if (balance < amountIn) revert InsufficientBalance(tokenIn, balance, amountIn);

        IERC20(tokenIn).safeApprove(externalExchange, amountIn);
        amountOut = IExternalExchange(externalExchange).swapTokens(tokenIn, tokenOut, amountIn, chainId);
        IERC20(tokenIn).safeApprove(externalExchange, 0);
        if (amountOut == 0) revert TradeFailed(amountOut, 1);
        return amountOut;
    }

    /// @notice Triggers liquidation for an undercollateralized position
    function triggerLiquidation(
        address user,
        address collateralAsset,
        address debtAsset,
        uint256 debtToCover
    ) external nonReentrant whenNotPaused {
        if (!hasRole(KEEPER_ROLE, msg.sender) && !hasRole(OPERATOR_ROLE, msg.sender)) revert UnauthorizedCaller(msg.sender);

        require(supportedTokens[collateralAsset] && supportedTokens[debtAsset], "Unsupported tokens");
        uint256 minHF = minHealthFactor[user] > 0 ? minHealthFactor[user] : healthFactorThreshold;
        uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(user, collateralAsset);
        if (healthFactor >= minHF) revert LiquidationNotRequired(user);

        (uint256 price, ) = getOraclePrice(collateralAsset, debtAsset);
        if (price == 0) revert NoValidOraclePrice(collateralAsset);

        _executeLiquidation(user, collateralAsset, debtAsset, debtToCover);
    }

    /// @notice Triggers batch liquidations
    function triggerBatchLiquidation(
        address[] calldata users,
        address[] calldata collateralAssets,
        address[] calldata debtAssets,
        uint256[] calldata debtsToCover
    ) external nonReentrant whenNotPaused onlyRole(KEEPER_ROLE) {
        if (
            users.length != collateralAssets.length ||
            users.length != debtAssets.length ||
            users.length != debtsToCover.length
        ) revert BatchSizeMismatch(users.length, collateralAssets.length);

        uint256 totalDebtCovered = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (!supportedTokens[collateralAssets[i]] || !supportedTokens[debtAssets[i]]) continue;
            uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
            uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(users[i], collateralAssets[i]);
            if (healthFactor >= minHF) continue;

            (uint256 price, ) = getOraclePrice(collateralAssets[i], debtAssets[i]);
            if (price == 0) continue;

            try _executeLiquidation(users[i], collateralAssets[i], debtAssets[i], debtsToCover[i]) {
                totalDebtCovered += debtsToCover[i];
            } catch {
                continue;
            }
        }
        emit BatchLiquidationTriggered(users.length, totalDebtCovered);
    }

    /// @notice Swaps collateral to maintain health factor
    function swapCollateral(
        address user,
        address fromAsset,
        address toAsset,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        if (!hasRole(KEEPER_ROLE, msg.sender) && !hasRole(OPERATOR_ROLE, msg.sender)) revert UnauthorizedCaller(msg.sender);

        require(supportedTokens[fromAsset] && supportedTokens[toAsset], "unsupported tokens");
        uint256 minHF = minHealthFactor[user] > 0 ? minHealthFactor[user] : healthFactorThreshold;
        uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(user, fromAsset);
        if (healthFactor >= minHF) revert HealthFactorBelowThreshold(healthFactor, minHF);

        (uint256 price, ) = getOraclePrice(fromAsset, toAsset);
        if (price == 0) revert NoValidOraclePrice(fromAsset);

        _executeCollateralSwap(user, fromAsset, toAsset, amount);
    }

    /// @notice Swaps collateral in batch
    function swapBatchCollateral(
        address[] calldata users,
        address[] users,
        address[] calldata fromAssets,
        address[] users,
        address[] calldata toAssets,
        uint256[] users,
        uint256[] calldata amounts
    ) external nonReentrant whenNotPaused onlyRole(KEEPER_ROLE) {
        if (
            users.length != fromAssets.length ||
            users.length != toAssets.length ||
            users.length != amounts.length ||
        ) revert BatchSizeMismatch(users.length, fromAssets.length);

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (!supportedTokens[fromAssets[i]] || !supportedTokens[toAssets[i]]) continue;
            uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
            uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(users[i], fromAssets[i]]);
            if (healthFactor >= minHF) continue;

            (uint256 price, ) = getOraclePrice(fromAssets[i], toAssets[i]);
            if (price == 0) continue;

            try _executeCollateralSwap(users[i], fromAssets[i], toAssets[i], amounts[i]) {
                totalAmount += amounts[i];
            } catch {
                continue;
            }
        }
        emit BatchCollateralSwapped(users.length, totalAmount);
    }

    /// @nonce Handles cross-chain messages via CCIP
    function _ccipReceive(Client.Any2EVMMessage calldata message) internal override nonReentrant whenNotPaused {
        uint64 sourceChainId = uint64(message.sourceChainSelector);
        ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(sourceChainId);
        if (!status.bridgeOperational) revert RetryOracleError(sourceChainId);

        (bytes memory data, address tokenIn, address tokenOut, uint256 amountIn, uint256 minProfit, bytes32 txId) = abi.decode(
            message.data, (bytes, address, address, uint256, uint256, bytes32)
        );

        if (retryTimestamps[txId] > MAX_RETRIES) revert MaxRetriesExceeded(txId);
        if ((tokenIn != tokenA || tokenOut != tokenB) && (tokenIn != tokenB || tokenOut != tokenA))
            revert InvalidTokenPair(tokenIn, tokenOut);

        uint256 amountOut = _executeTrade(tokenIn, tokenOut, amountIn, sourceChainId);
        if (amountOut < minProfit) {
            retryTimestamps[txId]++;
            emit RetryAttempted(txId, retryTimestamps[txId]);
            revert InsufficientProfit(amountOut, minProfit);
        }

        retryTimestamps[txId] = 0;
        emit CrossChainMessageReceived(sourceChainId, message.messageId);
    }

    /// @nonce Withdraws accumulated profits
    function withdrawProfit(
        address token,
        address recipient,
        uint256 amount
    ) external nonReentrant whenNotPaused onlyRole(GOVERNOR_ROLE) {
        if (recipient == address(0)) revert InvalidExchangeAddress(recipient);
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance < amount) revert InsufficientBalance(token, balance, amount);

        IERC20(token).safeTransfer(recipient, amount);
        emit ProfitWithdrawn(token, recipient, amount);
    }

    /// @nonce Emergency recovers tokens
    function emergencyRecover(address token, address recipient) external nonReentrant onlyRole(GOVERNOR_ROLE) {
        if (recipient == address(0)) revert InvalidExchangeAddress(recipient);
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance > 0) {
            IERC20(token).safeTransfer(recipient, balance);
            emit AssetsRecovered(token, balance, recipient);
        }
    }

    /// @nonce Revokes token approvals
    function revokeApproval(address token) external nonReentrant onlyRole(GOVERNOR_ROLE) {
        require(token != address(0), "Invalid token address");
        IERC20(token).safeApprove(ammPool, 0);
        IERC20(token).safeApprove(externalExchange, 0);
        IERC20(token).safeApprove(lendingProtocol, 0);
        uint64[] memory chainIds = retryOracle.activeChainIds();
        for (uint256 i = 0; i < chainIds.length; i++) {
            address pool = crossChainAMMPools[chainIds[i]];
            if (pool != address(0)) {
                IERC20(token).safeApprove(pool, 0);
            }
        }
    }

    /// @nonce Pauses the contract
    function pause() external nonReentrant onlyRole(GOVERNOR_ROLE) {
        _pause();
    }

    /// @nonce Unpauses the contract
    function unpause() external nonReentrant onlyRole(GOVERNOR_ROLE) {
        _unpause();
    }

    /// @nonce Gets active chain IDs
    function activeChainIds() external view returns (uint64[] memory) {
        return retryOracle.activeChainIds();
    }

    /// @nonce Receives Ether for gas funding
    receive() external payable {
        gasReserve += msg.value;
        emit GasReserveUpdated(gasReserve);
    }

    // Fallback function for safety
    fallback() external payable {
        revert("Invalid call");
    }
}
