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
import {Client} from "@chainlink/contracts/src/v0.8/ccip/libraries/Client.sol";
import {CCIPReceiver} from "@chainlink/contracts/src/v0.8/ccip/applications/CCIPReceiver.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {KeeperCompatibleInterface} from "@chainlink/contracts/src/v0.8/interfaces/KeeperCompatibleInterface.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

// Uniswap V3 Interfaces
import {ISwapRouter} from "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";
import {IUniswapV3Pool} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {IUniswapV3Factory} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol";
import {OracleLibrary} from "@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol";

// SushiSwap Interfaces
interface ISushiSwapRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory amounts);
}

interface ISushiSwapPair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

// Aave V3 Interfaces
interface IAavePool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    );
    function liquidationCall(
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external;
}

interface IAaveIncentivesController {
    function getRewardsBalance(address[] calldata assets, address user) external view returns (uint256);
    function claimRewards(address[] calldata assets, uint256 amount, address to) external returns (uint256);
}

interface IAaveProtocolDataProvider {
    function getReserveConfigurationData(address asset) external view returns (
        uint256 decimals,
        uint256 ltv,
        uint256 liquidationThreshold,
        uint256 liquidationBonus,
        uint256 reserveFactor,
        bool usageAsCollateralEnabled,
        bool borrowingEnabled,
        bool stableBorrowingEnabled,
        bool isActive,
        bool isFrozen
    );
}

// AMMPool Interface
interface IAMMPool {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint64 reserveA, uint64 reserveB);
    function getDynamicFee(uint16 chainId) external view returns (uint256 fee);
    function swap(
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient
    ) external returns (uint256 amountOut);
    function swapCrossChain(
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable returns (uint256 amountOut);
}

// Existing Interfaces
interface IPriceOracle {
    function getCurrentPairPrice(address pool, address token) external view returns (uint256 price, uint256 timestamp);
}

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

interface ILendingProtocol {
    function getAllUsersWithDebt() external view returns (address[] memory);
    function swapCollateral(address user, address fromAsset, address toAsset, uint256 amount) external;
}

interface IExternalExchange {
    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn, uint64 destChainId) external returns (uint256 amountOut);
    function getDynamicFee(address tokenIn, address tokenOut) external view returns (uint256 fee);
}

interface IPrivateMempool {
    function submitPrivateTx(bytes calldata txData, uint256 maxPriorityFee, uint256 maxFeePerGas) external payable returns (bytes32 txHash);
}

/// @title FlashSwapArbitrage
/// @notice Contract for arbitrage, liquidations, and collateral swapping with Uniswap V3, SushiSwap, Aave flash loans, AMM pool, MEV mitigation, and Chainlink automation
/// @dev Integrates Uniswap V3, SushiSwap, Aave V3, AMM pool, Chainlink Keepers, private mempools, dynamic liquidation bonuses, and enhanced security
contract FlashSwapArbitrage is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable,
    CCIPReceiver,
    KeeperCompatibleInterface
{
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    // Immutable addresses
    address public immutable uniswapV3Factory;
    address public immutable uniswapV3SwapRouter;
    address public immutable sushiSwapRouter;
    address public immutable sushiSwapPair; // Pair for tokenA/tokenB
    address public immutable lendingProtocol; // Aave Pool
    address public immutable tokenA;
    address public immutable tokenB;
    address public immutable aaveDataProvider;
    address public immutable aaveIncentivesController;
    address public immutable ammPool; // AMM Pool

    // External contracts
    GovernorUpgradeable public governor;
    AggregatorV3Interface[] public priceFeeds; // Chainlink Price Feeds
    ICrossChainRetryOracle public retryOracle;
    address public externalExchange;
    LinkTokenInterface public linkToken;
    address public keeperRegistry;
    address public privateMempool; // e.g., Flashbots

    // Storage
    mapping(uint64 => address) public crossChainAMMPools;
    mapping(address => bool) public supportedTokens;
    mapping(address => uint256) public minHealthFactor;
    mapping(bytes32 => uint256) public retryTimestamps; // Track retry attempts
    uint256 public gasReserve; // ETH reserve for gas funding
    uint256 public linkReserve; // LINK reserve for Chainlink operations
    uint256[] public uniswapFeeTiers; // Supported Uniswap V3 fee tiers (e.g., 500, 3000, 10000)
    uint256 public constant PRICE_PRECISION = 1e18;
    uint256 public constant MIN_HEALTH_FACTOR = 1e18; // 1.0 in 18 decimals
    uint256 public constant MAX_FEE_BASIS_POINTS = 10000; // 100%
    uint256 public constant MIN_GAS_RESERVE = 0.01 ether; // Minimum ETH for gas
    uint256 public constant MIN_LINK_RESERVE = 1 ether; // Minimum LINK for Chainlink
    uint256 public constant MAX_RETRIES = 3; // Max retry attempts
    uint256 public constant MAX_USERS = 50; // Limit users processed in one call
    uint256 public minProfitThreshold; // Minimum profit for arbitrage
    uint256 public healthFactorThreshold; // Health factor threshold for liquidations
    uint256 public dynamicBonusThreshold; // Threshold for dynamic liquidation bonus
    uint256 public maxLiquidationBonus; // Maximum liquidation bonus percentage
    uint256 public minLiquidationBonus; // Minimum liquidation bonus percentage
    mapping(address => uint256) public userLiquidationBonuses; // Dynamic bonuses per user

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
    error InvalidAaveDataProvider(address provider);
    error InvalidAaveIncentivesController(address controller);
    error FlashLoanFailed(address asset, uint256 amount);
    error InvalidLiquidationBonus(uint256 bonus);
    error InvalidFeeTier(uint256 feeTier);
    error NoLiquidityInPool(address pool);
    error InvalidSushiSwapPair(address pair);
    error InvalidAMMPoolAddress(address pool);
    error AMMPoolSwapFailed(uint256 amountOut, uint256 minAmountOut);
    error AMMPoolInsufficientReserves(uint256 reserveA, uint256 reserveB);

    // Events
    event FlashSwapInitiated(address indexed sender, uint256 amountIn, uint256 amountOutMin, uint64 chainId, uint24 feeTier, bool isSushiSwap, bool isAMMPool);
    event FlashSwapCompleted(address indexed sender, uint256 amountIn, uint256 amountOut, uint256 profit, uint64 chainId);
    event ProfitWithdrawn(address indexed token, address indexed recipient, uint256 amount);
    event LiquidationTriggered(address indexed user, address collateralAsset, address debtAsset, uint256 debtCovered, uint256 bonus);
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
    event DynamicBonusThresholdUpdated(uint256 newThreshold);
    event LiquidationBonusUpdated(address indexed user, uint256 bonus);
    event FlashLoanExecuted(address indexed asset, uint256 amount, uint256 premium);
    event RewardsClaimed(address indexed user, uint256 amount);
    event FeeTiersUpdated(uint256[] feeTiers);
    event AMMPoolUpdated(address indexed pool);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _uniswapV3Factory,
        address _uniswapV3SwapRouter,
        address _sushiSwapRouter,
        address _sushiSwapPair,
        address _lendingProtocol,
        address _tokenA,
        address _tokenB,
        address _router,
        address _aaveDataProvider,
        address _aaveIncentivesController,
        address _ammPool
    ) CCIPReceiver(_router) {
        require(_uniswapV3Factory != address(0), "Invalid Uniswap V3 factory address");
        require(_uniswapV3SwapRouter != address(0), "Invalid Uniswap V3 router address");
        require(_sushiSwapRouter != address(0), "Invalid SushiSwap router address");
        require(_sushiSwapPair != address(0), "Invalid SushiSwap pair address");
        require(_lendingProtocol != address(0), "Invalid lending protocol address");
        require(_tokenA != address(0) && _tokenB != address(0), "Invalid token addresses");
        require(_tokenA != _tokenB, "Tokens must be different");
        require(_aaveDataProvider != address(0), "Invalid Aave data provider address");
        require(_aaveIncentivesController != address(0), "Invalid Aave incentives controller address");
        require(_ammPool != address(0), "Invalid AMM pool address");

        address pairToken0 = ISushiSwapPair(_sushiSwapPair).token0();
        address pairToken1 = ISushiSwapPair(_sushiSwapPair).token1();
        require(
            (_tokenA == pairToken0 && _tokenB == pairToken1) || (_tokenA == pairToken1 && _tokenB == pairToken0),
            "Invalid token pair for SushiSwap"
        );

        address ammToken0 = IAMMPool(_ammPool).token0();
        address ammToken1 = IAMMPool(_ammPool).token1();
        require(
            (_tokenA == ammToken0 && _tokenB == ammToken1) || (_tokenA == ammToken1 && _tokenB == ammToken0),
            "Invalid token pair for AMM pool"
        );

        uniswapV3Factory = _uniswapV3Factory;
        uniswapV3SwapRouter = _uniswapV3SwapRouter;
        sushiSwapRouter = _sushiSwapRouter;
        sushiSwapPair = _sushiSwapPair;
        lendingProtocol = _lendingProtocol;
        tokenA = _tokenA;
        tokenB = _tokenB;
        aaveDataProvider = _aaveDataProvider;
        aaveIncentivesController = _aaveIncentivesController;
        ammPool = _ammPool;
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
        address _privateMempool,
        uint256[] calldata _feeTiers
    ) external initializer {
        require(_governor != address(0), "Invalid governor address");
        require(_priceFeeds.length > 0, "Invalid oracle array");
        require(_retryOracle != address(0), "Invalid retry oracle address");
        require(_externalExchange != address(0), "Invalid exchange address");
        require(_router != address(0), "Invalid router address");
        require(_linkToken != address(0), "Invalid LINK token address");
        require(_keeperRegistry != address(0), "Invalid keeper registry address");
        require(_privateMempool != address(0), "Invalid private mempool address");
        require(_feeTiers.length > 0, "Invalid fee tiers");

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
        for (uint256 i = 0; i < _feeTiers.length; i++) {
            require(_feeTiers[i] == 500 || _feeTiers[i] == 3000 || _feeTiers[i] == 10000, "Invalid fee tier");
            uniswapFeeTiers.push(_feeTiers[i]);
        }

        supportedTokens[tokenA] = true;
        supportedTokens[tokenB] = true;
        minProfitThreshold = 1e16; // 0.01 ETH equivalent
        healthFactorThreshold = MIN_HEALTH_FACTOR;
        dynamicBonusThreshold = 0.9e18; // 0.9 health factor
        maxLiquidationBonus = 10800; // 8% max bonus
        minLiquidationBonus = 10500; // 5% min bonus

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
        emit DynamicBonusThresholdUpdated(dynamicBonusThreshold);
        emit FeeTiersUpdated(_feeTiers);
        emit AMMPoolUpdated(ammPool);
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

    /// @notice Gets users with undercollateralized positions from Aave
    function _getUsers() internal view returns (address[] memory users) {
        address[] memory allUsers = ILendingProtocol(lendingProtocol).getAllUsersWithDebt();
        uint256 eligibleCount = 0;

        for (uint256 i = 0; i < allUsers.length && eligibleCount < MAX_USERS; i++) {
            if (allUsers[i] == address(0)) continue;
            try IAavePool(lendingProtocol).getUserAccountData(allUsers[i]) returns (
                uint256,
                uint256,
                uint256,
                uint256,
                uint256,
                uint256 healthFactor
            ) {
                uint256 minHF = minHealthFactor[allUsers[i]] > 0 ? minHealthFactor[allUsers[i]] : healthFactorThreshold;
                if (healthFactor < minHF) {
                    eligibleCount++;
                }
            } catch {
                continue;
            }
        }

        users = new address[](eligibleCount);
        uint256 index = 0;
        for (uint256 i = 0; i < allUsers.length && index < eligibleCount; i++) {
            if (allUsers[i] == address(0)) continue;
            try IAavePool(lendingProtocol).getUserAccountData(allUsers[i]) returns (
                uint256,
                uint256,
                uint256,
                uint256,
                uint256,
                uint256 healthFactor
            ) {
                uint256 minHF = minHealthFactor[allUsers[i]] > 0 ? minHealthFactor[allUsers[i]] : healthFactorThreshold;
                if (healthFactor < minHF) {
                    users[index] = allUsers[i];
                    index++;
                }
            } catch {
                continue;
            }
        }

        return users;
    }

    /// @notice Calculates dynamic liquidation bonus based on health factor
    function _calculateDynamicBonus(address user) internal view returns (uint256 bonus) {
        (, , , , , uint256 healthFactor) = IAavePool(lendingProtocol).getUserAccountData(user);
        if (healthFactor < dynamicBonusThreshold) {
            uint256 bonusRange = maxLiquidationBonus - minLiquidationBonus;
            uint256 bonusIncrement = bonusRange * (MIN_HEALTH_FACTOR - healthFactor) / MIN_HEALTH_FACTOR;
            bonus = minLiquidationBonus + bonusIncrement;
        } else {
            bonus = minLiquidationBonus;
        }
        return bonus;
    }

    /// @notice Updates dynamic liquidation bonus for a user
    function updateUserLiquidationBonus(address user) external onlyRole(GOVERNOR_ROLE) {
        uint256 bonus = _calculateDynamicBonus(user);
        userLiquidationBonuses[user] = bonus;
        emit LiquidationBonusUpdated(user, bonus);
    }

    /// @notice Selects the best Uniswap V3 pool based on liquidity
    function _selectBestUniswapV3Pool(address tokenIn, address tokenOut) internal view returns (address pool, uint24 feeTier) {
        uint128 highestLiquidity = 0;
        for (uint256 i = 0; i < uniswapFeeTiers.length; i++) {
            address poolAddress = IUniswapV3Factory(uniswapV3Factory).getPool(tokenIn, tokenOut, uint24(uniswapFeeTiers[i]));
            if (poolAddress == address(0)) continue;
            (uint128 liquidity, , , , , , ) = IUniswapV3Pool(poolAddress).slot0();
            if (liquidity > highestLiquidity) {
                highestLiquidity = liquidity;
                pool = poolAddress;
                feeTier = uint24(uniswapFeeTiers[i]);
            }
        }
        if (pool == address(0)) revert NoLiquidityInPool(address(0));
    }

    /// @notice Gets Uniswap V3 TWAP price
    function _getUniswapV3Price(address pool, address tokenIn) internal view returns (uint256 price, uint256 timestamp) {
        (uint32[] memory secondsAgos, int24[] memory tickCumulatives, ) = OracleLibrary.consult(pool, 300); // 5-minute TWAP
        int24 tick = int24((tickCumulatives[1] - tickCumulatives[0]) / int32(secondsAgos[1] - secondsAgos[0]));
        price = OracleLibrary.getQuoteAtTick(tick, 1e18, tokenIn, tokenIn == tokenA ? tokenB : tokenA);
        timestamp = block.timestamp;
    }

    /// @notice Gets SushiSwap pool price
    function _getSushiSwapPrice(address pair, address tokenIn) internal view returns (uint256 price, uint256 timestamp) {
        (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast) = ISushiSwapPair(pair).getReserves();
        address token0 = ISushiSwapPair(pair).token0();
        uint256 reserveIn = tokenIn == token0 ? reserve0 : reserve1;
        uint256 reserveOut = tokenIn == token0 ? reserve1 : reserve0;
        if (reserveOut == 0) revert DivisionByZero();
        price = (reserveIn * PRICE_PRECISION) / reserveOut;
        timestamp = blockTimestampLast;
    }

    /// @notice Gets AMM pool price
    function _getAMMPoolPrice(address pool, address tokenIn) internal view returns (uint256 price, uint256 timestamp) {
        (uint64 reserveA, uint64 reserveB) = IAMMPool(pool).getReserves();
        address token0 = IAMMPool(pool).token0();
        uint256 reserveIn = tokenIn == token0 ? reserveA : reserveB;
        uint256 reserveOut = tokenIn == token0 ? reserveB : reserveA;
        if (reserveOut == 0) revert DivisionByZero();
        price = (reserveIn * PRICE_PRECISION) / reserveOut;
        timestamp = block.timestamp;
    }

    /// @notice Checks if upkeep is needed for Chainlink Keepers
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        upkeepNeeded = false;

        // Check for arbitrage opportunities (Uniswap V3, SushiSwap, AMM Pool)
        (address uniswapPool, uint24 feeTier) = _selectBestUniswapV3Pool(tokenA, tokenB);
        (uint256 uniswapPrice, ) = _getUniswapV3Price(uniswapPool, tokenA);
        (uint256 sushiPrice, ) = _getSushiSwapPrice(sushiSwapPair, tokenA);
        (uint256 ammPrice, ) = _getAMMPoolPrice(ammPool, tokenA);
        (uint256 externalPrice, ) = getOraclePrice(externalExchange, tokenA);

        uint256 maxPrice = uniswapPrice;
        if (sushiPrice > maxPrice) maxPrice = sushiPrice;
        if (ammPrice > maxPrice) maxPrice = ammPrice;
        if (externalPrice > maxPrice) maxPrice = externalPrice;

        uint256 minPrice = uniswapPrice;
        if (sushiPrice < minPrice) minPrice = sushiPrice;
        if (ammPrice < minPrice) minPrice = ammPrice;
        if (externalPrice < minPrice) minPrice = externalPrice;

        uint256 priceDiff = maxPrice - minPrice;

        if (priceDiff * PRICE_PRECISION / maxPrice > minProfitThreshold) {
            upkeepNeeded = true;
            bool isSushiSwap = sushiPrice == minPrice;
            bool isAMMPool = ammPrice == minPrice;
            performData = abi.encode("arbitrage", uint64(0), maxPrice, minPrice, feeTier, isSushiSwap, isAMMPool);
            return (upkeepNeeded, performData);
        }

        // Check for liquidations and collateral swaps
        address[] memory users = _getUsers();
        for (uint256 i = 0; i < users.length; i++) {
            try IAavePool(lendingProtocol).getUserAccountData(users[i]) returns (
                uint256,
                uint256,
                uint256,
                uint256,
                uint256,
                uint256 healthFactor
            ) {
                uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
                if (healthFactor < minHF) {
                    upkeepNeeded = true;
                    performData = abi.encode("liquidation", users[i], tokenA, tokenB, false);
                    return (upkeepNeeded, performData);
                }
            } catch {
                continue;
            }
        }

        return (upkeepNeeded, performData);
    }

    /// @notice Performs upkeep tasks
    function performUpkeep(bytes calldata performData) external override onlyRole(KEEPER_ROLE) whenNotPaused {
        (string memory taskType, bytes memory data) = abi.decode(performData, (string, bytes));
        bytes32 taskId = keccak256(abi.encode(taskType, data, block.timestamp));

        if (keccak256(abi.encodePacked(taskType)) == keccak256(abi.encodePacked("arbitrage"))) {
            (uint64 chainId, uint256 poolPrice, uint256 externalPrice, uint24 feeTier, bool isSushiSwap, bool isAMMPool) = abi.decode(
                data,
                (uint64, uint256, uint256, uint24, bool, bool)
            );
            _executeArbitrage(chainId, poolPrice, externalPrice, feeTier, isSushiSwap, isAMMPool);
        } else if (keccak256(abi.encodePacked(taskType)) == keccak256(abi.encodePacked("liquidation"))) {
            (address user, address collateralAsset, address debtAsset, bool receiveAToken) = abi.decode(
                data,
                (address, address, address, bool)
            );
            _executeFlashLoanLiquidation(user, collateralAsset, debtAsset, receiveAToken);
        } else if (keccak256(abi.encodePacked(taskType)) == keccak256(abi.encodePacked("collateral"))) {
            (address user, address fromAsset, address toAsset, uint256 amount) = abi.decode(
                data,
                (address, address, address, uint256)
            );
            _executeCollateralSwap(user, fromAsset, toAsset, amount);
        }

        emit AutomationTriggered(taskId, taskType);
    }

    /// @notice Executes arbitrage via Uniswap V3, SushiSwap, or AMM Pool
    function _executeArbitrage(uint64 chainId, uint256 poolPrice, uint256 externalPrice, uint24 feeTier, bool isSushiSwap, bool isAMMPool) internal {
        uint256 amountIn = 1e18; // Simplified amount
        bytes memory data = abi.encode(address(this), minProfitThreshold, chainId, poolPrice, feeTier, isSushiSwap, isAMMPool);
        if (isSushiSwap) {
            _submitSushiSwapFlashSwap(amountIn, data);
        } else if (isAMMPool) {
            _submitAMMPoolSwap(tokenA, tokenB, amountIn, data, chainId);
        } else {
            _submitUniswapV3Swap(tokenA, tokenB, amountIn, data, feeTier);
        }
    }

    /// @notice Initiates flash loan for liquidation
    function _executeFlashLoanLiquidation(
        address user,
        address collateralAsset,
        address debtAsset,
        bool receiveAToken
    ) internal nonReentrant {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        if (linkReserve < MIN_LINK_RESERVE) revert InsufficientLinkReserve(linkReserve, MIN_LINK_RESERVE);

        (, uint256 totalDebtBase, , , , ) = IAavePool(lendingProtocol).getUserAccountData(user);
        uint256 debtToCover = totalDebtBase; // Cover all debt
        uint256 bonus = userLiquidationBonuses[user] > 0 ? userLiquidationBonuses[user] : minLiquidationBonus;

        bytes memory params = abi.encode(user, collateralAsset, debtAsset, debtToCover, bonus, receiveAToken);
        IERC20(debtAsset).safeApprove(lendingProtocol, debtToCover);

        try IAavePool(lendingProtocol).flashLoanSimple(
            address(this),
            debtAsset,
            debtToCover,
            params,
            0 // referralCode
        ) {
            emit FlashLoanExecuted(debtAsset, debtToCover, 0);
        } catch {
            revert FlashLoanFailed(debtAsset, debtToCover);
        }
    }

    /// @notice Aave flash loan callback
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == lendingProtocol, "Unauthorized");
        require(initiator == address(this), "Invalid initiator");

        (address user, address collateralAsset, address debtAsset, uint256 debtToCover, uint256 bonus, bool receiveAToken) = abi.decode(
            params,
            (address, address, address, uint256, uint256, bool)
        );

        IAavePool(lendingProtocol).liquidationCall(collateralAsset, debtAsset, user, debtToCover, receiveAToken);
        uint256 totalRepay = amount + premium;
        IERC20(asset).safeApprove(lendingProtocol, totalRepay);
        emit LiquidationTriggered(user, collateralAsset, debtAsset, debtToCover, bonus);
        emit FlashLoanExecuted(asset, amount, premium);

        return true;
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

    /// @notice Submits Uniswap V3 swap to private mempool
    function _submitUniswapV3Swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        bytes memory data,
        uint24 feeTier
    ) internal {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: feeTier,
            recipient: address(this),
            deadline: block.timestamp + 15,
            amountIn: amountIn,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });
        bytes memory txData = abi.encodeWithSelector(ISwapRouter.exactInputSingle.selector, params);
        uint256 maxPriorityFee = 2 gwei;
        uint256 maxFeePerGas = 50 gwei;
        IPrivateMempool(privateMempool).submitPrivateTx{value: gasReserve / 100}(txData, maxPriorityFee, maxFeePerGas);
        gasReserve -= gasReserve / 100;
        emit GasReserveUpdated(gasReserve);
    }

    /// @notice Submits SushiSwap flash swap to private mempool
    function _submitSushiSwapFlashSwap(
        uint256 amountIn,
        bytes memory data
    ) internal {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        (uint256 amount0Out, uint256 amount1Out) = tokenA == ISushiSwapPair(sushiSwapPair).token0()
            ? (amountIn, uint256(0))
            : (uint256(0), amountIn);
        bytes memory txData = abi.encodeWithSelector(
            ISushiSwapPair.swap.selector,
            amount0Out,
            amount1Out,
            address(this),
            data
        );
        uint256 maxPriorityFee = 2 gwei;
        uint256 maxFeePerGas = 50 gwei;
        IPrivateMempool(privateMempool).submitPrivateTx{value: gasReserve / 256}(txData, maxPriorityFee, maxFeePerGas);
        gasReserve -= gasReserve / 256;
        emit GasReserveUpdated(gasReserve);
    }

    /// @notice Submits AMM pool swap
    function _submitAMMPoolSwap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        bytes memory data,
        uint64 chainId
    ) internal {
        if (gasReserve < MIN_GAS_RESERVE) revert InsufficientGasReserve(gasReserve, MIN_GAS_RESERVE);
        IERC20(tokenIn).safeApprove(ammPool, amountIn);
        if (chainId == 0) {
            uint256 amountOut = IAMMPool(ammPool).swap(tokenIn, amountIn, 0, address(this));
            (address initiator, uint256 minProfit, , , , , ) = abi.decode(
                data,
                (address, uint256, uint64, uint256, uint24, bool, bool)
            );
            if (amountOut < amountIn + minProfit) revert AMMPoolSwapFailed(amountOut, amountIn + minProfit);
            uint256 profit = amountOut - amountIn;
            emit FlashSwapCompleted(initiator, amountIn, amountOut, profit, chainId);
        } else {
            bytes memory adapterParams = "";
            IAMMPool(ammPool).swapCrossChain{value: gasReserve / 256}(tokenIn, amountIn, 0, uint16(chainId), adapterParams);
            gasReserve -= gasReserve / 256;
            emit GasReserveUpdated(gasReserve);
        }
        IERC20(tokenIn).safeApprove(ammPool, 0);
    }

    /// @notice Uniswap V3 swap callback
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        (address uniswapPool, uint24 feeTier) = _selectBestUniswapV3Pool(tokenA, tokenB);
        require(msg.sender == uniswapPool, "Unauthorized");
        if (data.length == 0) revert InvalidCallbackData();

        (address initiator, uint256 minProfit, uint64 chainId, uint256 oraclePrice, uint24 feeTierCallback, bool isSushiSwap, bool isAMMPool) = abi.decode(
            data,
            (address, uint256, uint64, uint256, uint24, bool, bool)
        );
        require(!isSushiSwap && !isAMMPool, "Invalid protocol for Uniswap callback");
        require(feeTier == feeTierCallback, "Fee tier mismatch");
        require(hasRole(OPERATOR_ROLE, initiator), "Invalid initiator");

        bool isTokenAIn = amount0Delta > 0;
        address tokenIn = isTokenAIn ? tokenA : tokenB;
        address tokenOut = isTokenAIn ? tokenB : tokenA;
        uint256 amountIn = uint256(isTokenAIn ? amount0Delta : amount1Delta);

        uint256 exchangeFee = IExternalExchange(externalExchange).getDynamicFee(tokenOut, tokenIn);
        uint256 totalFee = feeTier + exchangeFee;
        if (totalFee > MAX_FEE_BASIS_POINTS) revert InvalidFee(totalFee);

        uint256 amountOut = _executeTrade(tokenOut, tokenIn, amountIn, chainId);
        if (amountOut < amountIn + minProfit)
            revert InsufficientRepayment(amountOut, amountIn + minProfit);

        IERC20(tokenIn).safeTransfer(uniswapPool, amountIn);
        uint256 profit = amountOut - amountIn;
        emit FlashSwapCompleted(initiator, amountIn, amountOut, profit, chainId);
    }

    /// @notice SushiSwap flash swap callback
    function sushiSwapCall(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external {
        require(msg.sender == sushiSwapPair, "Unauthorized");
        require(sender == address(this), "Invalid sender");
        if (amount0 == 0 && amount1 == 0) revert InvalidBorrowedAmount(amount0, amount1);
        if (amount0 > 0 && amount1 > 0) revert InvalidBorrowedAmount(amount0, amount1);
        if (data.length == 0) revert InvalidCallbackData();

        (address initiator, uint256 minProfit, uint64 chainId, uint256 oraclePrice, uint24 _feeTier, bool isSushiSwap, bool isAMMPool) = abi.decode(
            data,
            (address, uint256, uint64, uint256, uint24, bool, bool)
        );
        require(isSushiSwap && !isAMMPool, "Invalid protocol for SushiSwap callback");
        require(hasRole(OPERATOR_ROLE, initiator), "Invalid initiator");

        bool isTokenAOut = amount0 > 0;
        address tokenOut = isTokenAOut ? tokenA : tokenB;
        address tokenIn = isTokenAOut ? tokenB : tokenA;
        uint256 amountOut = amount0 > 0 ? amount0 : amount1;

        (uint112 reserve0, uint112 reserve1, ) = ISushiSwapPair(sushiSwapPair).getReserves();
        uint256 reserveIn = tokenIn == ISushiSwapPair(sushiSwapPair).token0() ? reserve0 : reserve1;
        uint256 reserveOut = tokenIn == ISushiSwapPair(sushiSwapPair).token0() ? reserve1 : reserve0;
        if (reserveOut <= amountOut) revert DivisionByZero();
        uint256 amountInWithFee = (amountOut * reserveIn) / (reserveOut - amountOut);
        amountInWithFee = (amountInWithFee * 1000) / 997; // SushiSwap 0.3% fee

        uint256 exchangeFee = IExternalExchange(externalExchange).getDynamicFee(tokenOut, tokenIn);
        uint256 totalFee = 300 + exchangeFee; // SushiSwap base fee (0.3%)
        if (totalFee > MAX_FEE_BASIS_POINTS) revert InvalidFee(totalFee);

        uint256 amountReceived = _executeTrade(tokenOut, tokenIn, amountOut, chainId);
        if (amountReceived < amountInWithFee + minProfit)
            revert InsufficientRepayment(amountReceived, amountInWithFee + minProfit);

        IERC20(tokenIn).safeTransfer(sushiSwapPair, amountInWithFee);
        uint256 profit = amountReceived - amountInWithFee;
        emit FlashSwapCompleted(initiator, amountInWithFee, amountReceived, profit, chainId);
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

    function _singleArray(uint256 value) private pure returns (uint256[] memory) {
        uint256[] memory arr = new uint256[](1);
        arr[0] = value;
        return arr;
    }

    function _singleArray(address value) private pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = value;
        return arr;
    }

    function _singleArray(bytes memory value) private pure returns (bytes[] memory) {
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
    function updatePriceOracles(address[] calldata feeds) external onlyRole(GOVERNOR_ROLE) {
        require(feeds.length > 0, "Invalid oracle array");
        delete priceFeeds;
        for (uint256 i = 0; i < feeds.length; i++) {
            require(feeds[i] != address(0), "Invalid oracle address");
            priceFeeds.push(AggregatorV3Interface(feeds[i]));
        }
        emit PriceFeedsUpdated(feeds.length);
    }

    /// @notice Updates retry oracle
    function updateRetryOracle(address _retryOracle) external onlyRole(GOVERNOR_ROLE) {
        require(_retryOracle != address(0), "Invalid retry oracle address");
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        emit RetryOracleUpdated(_retryOracle);
    }

    /// @notice Updates external exchange address
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
        require(_mempool != address(0), "Invalid mempool address");
        privateMempool = _mempool;
        emit PrivateMempoolUpdated(_mempool);
    }

    /// @notice Updates keeper registry
    function updateKeeperRegistry(address _registry) external onlyRole(GOVERNOR_ROLE) {
        require(_registry != address(0), "Invalid keeper registry address");
        keeperRegistry = _registry;
        _grantRole(KEEPER_ROLE, _registry);
        emit KeeperRegistryUpdated(_registry);
    }

    /// @notice Updates LINK token
    function updateLinkToken(address _token) external onlyRole(GOVERNOR_ROLE) {
        require(_token != address(0), "Invalid LINK token address");
        linkToken = LinkTokenInterface(_token);
        emit LinkTokenUpdated(_token);
    }

    /// @notice Updates minimum profit threshold
    function updateMinProfitThreshold(uint256 _threshold) external onlyRole(GOVERNOR_ROLE) {
        require(_threshold != 0, "Invalid threshold");
        minProfitThreshold = _threshold;
        emit MinProfitThresholdUpdated(_threshold);
    }

    /// @notice Updates health factor threshold
    function updateHealthFactorThreshold(uint256 _threshold) external onlyRole(GOVERNOR_ROLE) {
        require(_threshold >= MIN_HEALTH_FACTOR, "Invalid threshold");
        healthFactorThreshold = _threshold;
        emit HealthFactorThresholdUpdated(_threshold);
    }

    /// @notice Updates dynamic liquidation bonus threshold
    function updateDynamicBonusThreshold(uint256 _threshold) external onlyRole(GOVERNOR_ROLE) {
        require(_threshold <= MIN_HEALTH_FACTOR, "Invalid threshold");
        dynamicBonusThreshold = _threshold;
        emit DynamicBonusThresholdUpdated(_threshold);
    }

    /// @notice Updates Uniswap fee tiers
    function updateFeeTiers(uint256[] calldata _feeTiers) external onlyRole(GOVERNOR_ROLE) {
        require(_feeTiers.length > 0, "Invalid fee tiers");
        delete uniswapFeeTiers;
        for (uint256 i = 0; i < _feeTiers.length; i++) {
            require(_feeTiers[i] == 500 || _feeTiers[i] == 3000 || _feeTiers[i] == 10000, "Invalid fee tier");
            uniswapFeeTiers.push(_feeTiers[i]);
        }
        emit FeeTiersUpdated(_feeTiers);
    }

    /// @notice Gets price from multiple Chainlink feeds
    function getOraclePrice(address _asset, address token) internal view returns (uint256 price, uint256 timestamp) {
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
                if (_price > 0 && _timestamp > block.timestamp - 3600) {
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

        if (validPrices == 0) revert NoValidOraclePrice(_asset);
        require(validPrices >= 2, "Insufficient valid prices");
        return (totalPrice / validPrices, latestTimestamp);
    }

    /// @notice Initiates a flash swap for arbitrage
    function initiateFlashSwap(
        uint64 chainId,
        uint256 amountIn,
        uint256 amountOutMin,
        uint24 feeTier,
        bool useSushiSwap,
        bool useAMMPool
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        if (amountIn == 0) revert InvalidBorrowedAmount(amountIn, 0);
        if (chainId != 0 && crossChainAMMPools[chainId] == address(0)) revert CrossChainNotConfigured(chainId);
        if (useSushiSwap && useAMMPool) revert InvalidOperation("Cannot use both SushiSwap and AMM pool");

        if (!useSushiSwap && !useAMMPool) {
            bool validFeeTier = false;
            for (uint256 i = 0; i < uniswapFeeTiers.length; i++) {
                if (uniswapFeeTiers[i] == feeTier) {
                    validFeeTier = true;
                    break;
                }
            }
            require(validFeeTier, "Invalid fee tier");
        }

        bytes32 txId = keccak256(abi.encodePacked(msg.sender, chainId, amountIn, amountOutMin, feeTier, useSushiSwap, useAMMPool, block.timestamp));
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

        address pool = useSushiSwap ? sushiSwapPair : useAMMPool ? ammPool : IUniswapV3Factory(uniswapV3Factory).getPool(tokenA, tokenB, feeTier);
        (uint256 price, ) = useSushiSwap ? _getSushiSwapPrice(sushiSwapPair, tokenA) : useAMMPool ? _getAMMPoolPrice(ammPool, tokenA) : _getUniswapV3Price(pool, tokenA);
        if (price == 0) revert NoValidOraclePrice(pool);

        bytes memory data = abi.encode(msg.sender, amountOutMin, chainId, price, feeTier, useSushiSwap, useAMMPool);
        if (useSushiSwap) {
            _submitSushiSwapFlashSwap(amountIn, data);
        } else if (useAMMPool) {
            _submitAMMPoolSwap(tokenA, tokenB, amountIn, data, chainId);
        } else {
            _submitUniswapV3Swap(tokenA, tokenB, amountIn, data, feeTier);
        }
        emit FlashSwapInitiated(msg.sender, amountIn, amountOutMin, chainId, feeTier, useSushiSwap, useAMMPool);
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
        bool receiveAToken
    ) external nonReentrant whenNotPaused {
        if (!hasRole(KEEPER_ROLE, msg.sender) && !hasRole(OPERATOR_ROLE, msg.sender)) revert UnauthorizedCaller(msg.sender);

        require(supportedTokens[collateralAsset] && supportedTokens[debtAsset], "Unsupported tokens");
        (, , , , , uint256 healthFactor) = IAavePool(lendingProtocol).getUserAccountData(user);
        uint256 minHF = minHealthFactor[user] > 0 ? minHealthFactor[user] : healthFactorThreshold;
        if (healthFactor >= minHF) revert LiquidationNotRequired(user);

        (uint256 price, ) = getOraclePrice(collateralAsset, debtAsset);
        if (price == 0) revert NoValidOraclePrice(collateralAsset);

        _executeFlashLoanLiquidation(user, collateralAsset, debtAsset, receiveAToken);
    }

    /// @notice Triggers batch liquidations
    function triggerBatchLiquidation(
        address[] calldata users,
        address[] calldata collateralAssets,
        address[] calldata debtAssets,
        bool[] calldata receiveATokens
    ) external nonReentrant whenNotPaused onlyRole(KEEPER_ROLE) {
        if (
            users.length != collateralAssets.length ||
            users.length != debtAssets.length ||
            users.length != receiveATokens.length
        ) revert BatchSizeMismatch(users.length, collateralAssets.length);

        uint256 totalDebtCovered = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (!supportedTokens[collateralAssets[i]] || !supportedTokens[debtAssets[i]]) continue;
            (, , , , , uint256 healthFactor) = IAavePool(lendingProtocol).getUserAccountData(users[i]);
            uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
            if (healthFactor >= minHF) continue;

            (uint256 price, ) = getOraclePrice(collateralAssets[i], debtAssets[i]);
            if (price == 0) continue;

            try this._executeFlashLoanLiquidation(users[i], collateralAssets[i], debtAssets[i], receiveATokens[i]) {
                (, uint256 debtCovered, , , , ) = IAavePool(lendingProtocol).getUserAccountData(users[i]);
                totalDebtCovered += debtCovered;
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

        require(supportedTokens[fromAsset] && supportedTokens[toAsset], "Unsupported tokens");
        (, , , , , uint256 healthFactor) = IAavePool(lendingProtocol).getUserAccountData(user);
        uint256 minHF = minHealthFactor[user] > 0 ? minHealthFactor[user] : healthFactorThreshold;
        if (healthFactor >= minHF) revert HealthFactorBelowThreshold(healthFactor, minHF);

        (uint256 price, ) = getOraclePrice(fromAsset, toAsset);
        if (price == 0) revert NoValidOraclePrice(fromAsset);

        _executeCollateralSwap(user, fromAsset, toAsset, amount);
    }

    /// @notice Swaps collateral in batch
    function swapBatchCollateral(
        address[] calldata users,
        address[] calldata fromAssets,
        address[] calldata toAssets,
        uint256[] calldata amounts
    ) external nonReentrant whenNotPaused onlyRole(KEEPER_ROLE) {
        if (
            users.length != fromAssets.length ||
            users.length != toAssets.length ||
            users.length != amounts.length
        ) revert BatchSizeMismatch(users.length, fromAssets.length);

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (!supportedTokens[fromAssets[i]] || !supportedTokens[toAssets[i]]) continue;
            (, , , , , uint256 healthFactor) = IAavePool(lendingProtocol).getUserAccountData(users[i]);
            uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : healthFactorThreshold;
            if (healthFactor >= minHF) continue;

            (uint256 price, ) = getOraclePrice(fromAssets[i], toAssets[i]);
            if (price == 0) continue;

            try this._executeCollateralSwap(users[i], fromAssets[i], toAssets[i], amounts[i]) {
                totalAmount += amounts[i];
            } catch {
                continue;
            }
        }
        emit BatchCollateralSwapped(users.length, totalAmount);
    }

    /// @notice Claims Aave rewards
    function claimRewards(address[] calldata assets, uint256 amount, address to) external onlyRole(GOVERNOR_ROLE) {
        uint256 claimed = IAaveIncentivesController(aaveIncentivesController).claimRewards(assets, amount, to);
        emit RewardsClaimed(to, claimed);
    }

    /// @notice Handles cross-chain messages via CCIP
    function _ccipReceive(Client.Any2EVMMessage calldata message) internal override nonReentrant whenNotPaused {
        uint64 sourceChainId = uint64(message.sourceChainSelector);
        ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(sourceChainId);
        if (!status.bridgeOperational) revert RetryOracleError(sourceChainId);

        (bytes memory data, address tokenIn, address tokenOut, uint256 amountIn, uint256 minProfit, bytes32 txId) = abi.decode(
            message.data,
            (bytes, address, address, uint256, uint256, bytes32)
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

    /// @notice Withdraws accumulated profits
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

    /// @notice Emergency recovers tokens
    function emergencyRecover(address token, address recipient) external nonReentrant onlyRole(GOVERNOR_ROLE) {
        if (recipient == address(0)) revert InvalidExchangeAddress(recipient);
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance > 0) {
            IERC20(token).safeTransfer(recipient, balance);
            emit AssetsRecovered(token, balance, recipient);
        }
    }

    /// @notice Revokes token approvals
    function revokeApproval(address token) external nonReentrant onlyRole(GOVERNOR_ROLE) {
        require(token != address(0), "Invalid token address");
        IERC20(token).safeApprove(uniswapV3SwapRouter, 0);
        IERC20(token).safeApprove(sushiSwapRouter, 0);
        IERC20(token).safeApprove(sushiSwapPair, 0);
        IERC20(token).safeApprove(externalExchange, 0);
        IERC20(token).safeApprove(lendingProtocol, 0);
        IERC20(token).safeApprove(ammPool, 0);
        uint64[] memory chainIds = retryOracle.activeChainIds();
        for (uint256 i = 0; i < chainIds.length; i++) {
            address pool = crossChainAMMPools[chainIds[i]];
            if (pool != address(0)) {
                IERC20(token).safeApprove(pool, 0);
            }
        }
    }

    /// @notice Pauses the contract
    function pause() external nonReentrant onlyRole(GOVERNOR_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external nonReentrant onlyRole(GOVERNOR_ROLE) {
        _unpause();
    }

    /// @notice Gets active chain IDs
    function activeChainIds() external view returns (uint64[] memory) {
        return retryOracle.activeChainIds();
    }

    /// @notice Receives Ether for gas funding
    receive() external payable {
        gasReserve += msg.value;
        emit GasReserveUpdated(gasReserve);
    }

    // Fallback function for safety
    fallback() external payable {
        revert("Invalid call");
    }
}
