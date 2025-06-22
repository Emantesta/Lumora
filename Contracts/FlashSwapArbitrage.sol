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
import {GovernorSettingsUpgradeable} from "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorSettingsUpgradeable.sol";
import {GovernorCountingSimpleUpgradeable} from "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorCountingSimpleUpgradeable.sol";
import {GovernorVotesUpgradeable} from "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorVotesUpgradeable.sol";
import {GovernorTimelockControlUpgradeable} from "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorTimelockControlUpgradeable.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";
import {CCIPReceiver} from "@chainlink/contracts-ccip/src/v0.8/ccip/applications/CCIPReceiver.sol";

// Interface for PriceOracle
interface IPriceOracle {
    function getCurrentPairPrice(address pool, address token) external view returns (uint256 price, uint256 timestamp);
}

// Interface for CrossChainRetryOracle
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

// Interface for AMMPool
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

// Interface for Uniswap V2 Callee
interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

// Interface for lending protocol (e.g., Aave-like)
interface ILendingProtocol {
    function getHealthFactor(address user, address asset) external view returns (uint256);
    function liquidate(address user, address collateralAsset, address debtAsset, uint256 debtToCover) external;
    function swapCollateral(address user, address fromAsset, address toAsset, uint256 amount) external;
}

// Interface for external exchange (e.g., SushiSwap)
interface IExternalExchange {
    function swapTokens(address tokenIn, address tokenOut, uint256 amountIn, uint64 destChainId) external returns (uint256 amountOut);
    function getDynamicFee(address tokenIn, address tokenOut) external view returns (uint256 fee);
}

/// @title FlashSwapArbitrage
/// @notice Contract for arbitrage, liquidations, and collateral swapping with DAO governance
/// @dev Integrates with OpenZeppelin Governor for decentralized governance and role-based access
contract FlashSwapArbitrage is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable,
    CCIPReceiver,
    IUniswapV2Callee
{
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");

    // Immutable addresses
    address public immutable ammPool;
    address public immutable lendingProtocol;
    address public immutable tokenA; // token0 in AMMPool
    address public immutable tokenB; // token1 in AMMPool

    // External contracts
    GovernorUpgradeable public governor;
    IPriceOracle[] public priceOracles;
    ICrossChainRetryOracle public retryOracle;
    address public externalExchange;

    // Storage
    mapping(uint64 => address) public crossChainAMMPools;
    mapping(address => bool) public supportedTokens;
    mapping(address => uint256) public minHealthFactor;
    uint256 public constant PRICE_PRECISION = 1e18;
    uint256 public constant MIN_HEALTH_FACTOR = 1e18; // 1.0 in 18 decimals
    uint256 public constant MAX_FEE_BASIS_POINTS = 10000; // 100%

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
    error RetryOrphanError(uint64 chainId);
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

    // Events
    event FlashSwapInitiated(address indexed sender, uint256 amount0Out, uint256 amount1Out, uint64 chainId);
    event FlashSwapCompleted(address indexed sender, uint256 amountIn, uint256 amountOut, uint256 profit, uint64 chainId);
    event ProfitWithdrawn(address indexed token, address indexed recipient, uint256 amount);
    event LiquidationTriggered(address indexed user, address collateralAsset, address debtAsset, uint256 debtCovered);
    event BatchLiquidationTriggered(uint256 userCount, uint256 totalDebtCovered);
    event CollateralSwapped(address indexed user, address fromAsset, address toAsset, uint256 amount);
    event BatchCollateralSwapped(uint256 userCount, uint256 totalAmount);
    event CrossChainPoolUpdated(uint64 indexed chainId, address pool);
    event PriceOraclesUpdated(uint256 oracleCount);
    event RetryOracleUpdated(address indexed retryOracle);
    event ExternalExchangeUpdated(address indexed exchange);
    event SupportedTokenUpdated(address indexed token, bool supported);
    event MinHealthFactorUpdated(address indexed user, uint256 minHealthFactor);
    event CrossChainMessageReceived(uint64 indexed sourceChainId, bytes32 indexed messageId);
    event AssetsRecovered(address indexed token, uint256 amount, address indexed recipient);
    event BatchProposalCreated(uint256[] proposalIds);
    event GovernorUpdated(address indexed newGovernor);

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
    /// @param _governor The Governor contract address
    /// @param _priceOracles Array of PriceOracle contract addresses
    /// @param _retryOracle The CrossChainRetryOracle contract address
    /// @param _externalExchange The external exchange address
    /// @param _router The CCIP router address
    function initialize(
        address _governor,
        address[] calldata _priceOracles,
        address _retryOracle,
        address _externalExchange,
        address _router
    ) external initializer {
        require(_governor != address(0), "Invalid governor address");
        require(_priceOracles.length > 0, "Invalid oracle array");
        require(_retryOracle != address(0), "Invalid retry oracle address");
        require(_externalExchange != address(0), "Invalid exchange address");
        require(_router != address(0), "Invalid router address");

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __AccessControl_init();

        governor = GovernorUpgradeable(_governor);
        for (uint256 i = 0; i < _priceOracles.length; i++) {
            require(_priceOracles[i] != address(0), "Invalid oracle address");
            priceOracles.push(IPriceOracle(_priceOracles[i]));
        }
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        externalExchange = _externalExchange;

        supportedTokens[tokenA] = true;
        supportedTokens[tokenB] = true;

        _grantRole(DEFAULT_ADMIN_ROLE, _governor);
        _grantRole(GOVERNOR_ROLE, _governor);

        emit GovernorUpdated(_governor);
        emit PriceOraclesUpdated(_priceOracles.length);
        emit RetryOracleUpdated(_retryOracle);
        emit ExternalExchangeUpdated(_externalExchange);
        emit SupportedTokenUpdated(tokenA, true);
        emit SupportedTokenUpdated(tokenB, true);
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(GOVERNOR_ROLE) {}

    /// @notice Proposes batch governance actions
    /// @param targets Array of target contract addresses
    /// @param values Array of ether values
    /// @param calldatas Array of encoded function calls
    /// @param description Proposal description
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

    /// @notice Helper to create single-element arrays for Governor propose
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

    /// @notice Updates the cross-chain AMM pool
    /// @param chainId The chain ID
    /// @param pool The AMM pool address
    function updateCrossChainPool(uint64 chainId, address pool) external onlyRole(GOVERNOR_ROLE) {
        require(chainId != 0, "Invalid chain ID");
        require(pool != address(0), "Invalid pool address");
        crossChainAMMPools[chainId] = pool;
        emit CrossChainPoolUpdated(chainId, pool);
    }

    /// @notice Updates the price oracles
    /// @param _priceOracles Array of new PriceOracle addresses
    function updatePriceOracles(address[] calldata _priceOracles) external onlyRole(GOVERNOR_ROLE) {
        require(_priceOracles.length > 0, "Invalid oracle array");
        delete priceOracles;
        address[] memory fallbackOracles = new address[](_priceOracles.length - 1);
        for (uint256 i = 0; i < _priceOracles.length; i++) {
            require(_priceOracles[i] != address(0), "Invalid oracle address");
            priceOracles.push(IPriceOracle(_priceOracles[i]));
            if (i > 0) {
                fallbackOracles[i - 1] = _priceOracles[i];
            }
        }
        IAMMPool(ammPool).setPriceOracle(_priceOracles[0], fallbackOracles);
        emit PriceOraclesUpdated(_priceOracles.length);
    }

    /// @notice Updates the retry oracle
    /// @param _retryOracle The new CrossChainRetryOracle address
    function updateRetryOracle(address _retryOracle) external onlyRole(GOVERNOR_ROLE) {
        require(_retryOracle != address(0), "Invalid retry oracle address");
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        emit RetryOracleUpdated(_retryOracle);
    }

    /// @notice Updates the external exchange
    /// @param _externalExchange The new external exchange address
    function updateExternalExchange(address _externalExchange) external onlyRole(GOVERNOR_ROLE) {
        require(_externalExchange != address(0), "Invalid exchange address");
        externalExchange = _externalExchange;
        emit ExternalExchangeUpdated(_externalExchange);
    }

    /// @notice Updates the supported token status
    /// @param token The token address
    /// @param supported Whether the token is supported
    function updateSupportedToken(address token, bool supported) external onlyRole(GOVERNOR_ROLE) {
        require(token != address(0), "Invalid token address");
        supportedTokens[token] = supported;
        emit SupportedTokenUpdated(token, supported);
    }

    /// @notice Updates the minimum health factor
    /// @param user The user address
    /// @param _minHealthFactor The minimum health factor
    function updateMinHealthFactor(address user, uint256 _minHealthFactor) external onlyRole(GOVERNOR_ROLE) {
        require(user != address(0), "Invalid user address");
        require(_minHealthFactor >= MIN_HEALTH_FACTOR, "Health factor too low");
        minHealthFactor[user] = _minHealthFactor;
        emit MinHealthFactorUpdated(user, _minHealthFactor);
    }

    /// @notice Updates the governor
    /// @param _governor The new Governor address
    function updateGovernor(address _governor) external onlyRole(GOVERNOR_ROLE) {
        require(_governor != address(0), "Invalid governor address");
        governor = GovernorUpgradeable(_governor);
        _grantRole(GOVERNOR_ROLE, _governor);
        _revokeRole(GOVERNOR_ROLE, msg.sender);
        emit GovernorUpdated(_governor);
    }

    /// @notice Grants operator role to an address
    /// @param operator The operator address
    function grantOperatorRole(address operator) external onlyRole(GOVERNOR_ROLE) {
        require(operator != address(0), "Invalid operator address");
        _grantRole(OPERATOR_ROLE, operator);
    }

    /// @notice Revokes operator role from an address
    /// @param operator The operator address
    function revokeOperatorRole(address operator) external onlyRole(GOVERNOR_ROLE) {
        require(operator != address(0), "Invalid operator address");
        _revokeRole(OPERATOR_ROLE, operator);
    }

    /// @notice Gets price from multiple oracles with fallback
    /// @param asset The asset address
    /// @param token The token address
    /// @return price The aggregated price
    /// @return timestamp The latest timestamp
    function getOraclePrice(address asset, address token) internal view returns (uint256 price, uint256 timestamp) {
        uint256 validPrices = 0;
        uint256 totalPrice = 0;
        uint256 latestTimestamp = 0;

        for (uint256 i = 0; i < priceOracles.length; i++) {
            try priceOracles[i].getCurrentPairPrice(asset, token) returns (uint256 _price, uint256 _timestamp) {
                if (_price > 0) {
                    totalPrice += _price;
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

    /// @notice Initiates a flash swap for arbitrage
    /// @param chainId The destination chain ID (0 for local chain)
    /// @param amount0Out The amount of tokenA to borrow
    /// @param amount1Out The amount of tokenB to borrow
    /// @param minProfit The minimum profit required
    function initiateFlashSwap(
        uint64 chainId,
        uint256 amount0Out,
        uint256 amount1Out,
        uint256 minProfit
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        if (amount0Out == 0 && amount1Out == 0) revert InvalidBorrowedAmount(amount0Out, amount1Out);
        if (amount0Out > 0 && amount1Out > 0) revert InvalidBorrowedAmount(amount0Out, amount1Out);
        if (chainId != 0 && crossChainAMMPools[chainId] == address(0)) revert CrossChainNotConfigured(chainId);

        if (chainId != 0) {
            ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(chainId);
            if (!status.bridgeOperational || status.retryRecommended) {
                uint32 retryDelay = status.randomRetryDelay;
                require(block.timestamp >= status.lastUpdated + retryDelay, "Retry delay not met");
            }
        }

        address asset = chainId == 0 ? ammPool : crossChainAMMPools[chainId];
        (uint256 price, ) = getOraclePrice(asset, amount1Out > 0 ? tokenB : tokenA);
        if (price == 0) revert NoValidOraclePrice(asset);

        bytes memory data = abi.encode(msg.sender, minProfit, chainId, price);
        address targetPool = chainId == 0 ? ammPool : crossChainAMMPools[chainId];
        IAMMPool(targetPool).swap(amount0Out, amount1Out, address(this), data);
        emit FlashSwapInitiated(msg.sender, amount0Out, amount1Out, chainId);
    }

    /// @notice Callback for flash swap
    /// @param sender The sender of the flash swap
    /// @param amount0 The amount of token0 borrowed
    /// @param amount1 The amount of token1 borrowed
    /// @param data The callback data
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

        (address initiator, uint256 minProfit, uint64 chainId, uint256 oraclePrice) = abi.decode(
            data,
            (address, uint256, uint64, uint256)
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
        emit FlashSwapCompleted(sender, amountInWithFee, amountOut, profit, chainId);
    }

    /// @notice Executes a trade on the external exchange
    /// @param tokenIn The input token
    /// @param tokenOut The output token
    /// @param amountIn The input amount
    /// @param chainId The destination chain ID
    /// @return amountOut The output amount
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
    /// @param user The user to liquidate
    /// @param collateralAsset The collateral asset
    /// @param debtAsset The debt asset
    /// @param debtToCover The amount of debt to cover
    function triggerLiquidation(
        address user,
        address collateralAsset,
        address debtAsset,
        uint256 debtToCover
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        require(supportedTokens[collateralAsset] && supportedTokens[debtAsset], "Unsupported tokens");
        uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(user, collateralAsset);
        if (healthFactor >= minHealthFactor[user] || healthFactor >= MIN_HEALTH_FACTOR)
            revert LiquidationNotRequired(user);

        (uint256 price, ) = getOraclePrice(collateralAsset, debtAsset);
        if (price == 0) revert NoValidOraclePrice(collateralAsset);

        IERC20(debtAsset).safeApprove(lendingProtocol, debtToCover);
        ILendingProtocol(lendingProtocol).liquidate(user, collateralAsset, debtAsset, debtToCover);
        IERC20(debtAsset).safeApprove(lendingProtocol, 0);
        emit LiquidationTriggered(user, collateralAsset, debtAsset, debtToCover);
    }

    /// @notice Triggers batch liquidations
    /// @param users Array of users to liquidate
    /// @param collateralAssets Array of collateral assets
    /// @param debtAssets Array of debt assets
    /// @param debtsToCover Array of debt amounts to cover
    function triggerBatchLiquidation(
        address[] calldata users,
        address[] calldata collateralAssets,
        address[] calldata debtAssets,
        uint256[] calldata debtsToCover
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        if (
            users.length != collateralAssets.length ||
            users.length != debtAssets.length ||
            users.length != debtsToCover.length
        ) revert BatchSizeMismatch(users.length, collateralAssets.length);

        uint256 totalDebtCovered = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (!supportedTokens[collateralAssets[i]] || !supportedTokens[debtAssets[i]]) continue;
            uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(users[i], collateralAssets[i]);
            if (healthFactor >= minHealthFactor[users[i]] && healthFactor >= MIN_HEALTH_FACTOR) continue;

            (uint256 price, ) = getOraclePrice(collateralAssets[i], debtAssets[i]);
            if (price == 0) continue;

            IERC20(debtAssets[i]).safeApprove(lendingProtocol, debtsToCover[i]);
            try
                ILendingProtocol(lendingProtocol).liquidate(
                    users[i],
                    collateralAssets[i],
                    debtAssets[i],
                    debtsToCover[i]
                )
            {
                totalDebtCovered += debtsToCover[i];
                emit LiquidationTriggered(users[i], collateralAssets[i], debtAssets[i], debtsToCover[i]);
            } catch {
                continue;
            } finally {
                IERC20(debtAssets[i]).safeApprove(lendingProtocol, 0);
            }
        }
        emit BatchLiquidationTriggered(users.length, totalDebtCovered);
    }

    /// @notice Swaps collateral to maintain health factor
    /// @param user The user address
    /// @param fromAsset The source asset
    /// @param toAsset The target asset
    /// @param amount The amount to swap
    function swapCollateral(
        address user,
        address fromAsset,
        address toAsset,
        uint256 amount
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        require(supportedTokens[fromAsset] && supportedTokens[toAsset], "Unsupported tokens");
        uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(user, fromAsset);
        uint256 minHF = minHealthFactor[user] > 0 ? minHealthFactor[user] : MIN_HEALTH_FACTOR;
        if (healthFactor >= minHF) revert HealthFactorBelowThreshold(healthFactor, minHF);

        (uint256 price, ) = getOraclePrice(fromAsset, toAsset);
        if (price == 0) revert NoValidOraclePrice(fromAsset);

        IERC20(fromAsset).safeApprove(lendingProtocol, amount);
        ILendingProtocol(lendingProtocol).swapCollateral(user, fromAsset, toAsset, amount);
        IERC20(fromAsset).safeApprove(lendingProtocol, 0);
        emit CollateralSwapped(user, fromAsset, toAsset, amount);
    }

    /// @notice Swaps collateral in batch
    /// @param users Array of user addresses
    /// @param fromAssets Array of source assets
    /// @param toAssets Array of target assets
    /// @param amounts Array of amounts to swap
    function swapBatchCollateral(
        address[] calldata users,
        address[] calldata fromAssets,
        address[] calldata toAssets,
        uint256[] calldata amounts
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        if (
            users.length != fromAssets.length ||
            users.length != toAssets.length ||
            users.length != amounts.length
        ) revert BatchSizeMismatch(users.length, fromAssets.length);

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (!supportedTokens[fromAssets[i]] || !supportedTokens[toAssets[i]]) continue;
            uint256 healthFactor = ILendingProtocol(lendingProtocol).getHealthFactor(users[i], fromAssets[i]);
            uint256 minHF = minHealthFactor[users[i]] > 0 ? minHealthFactor[users[i]] : MIN_HEALTH_FACTOR;
            if (healthFactor >= minHF) continue;

            (uint256 price, ) = getOraclePrice(fromAssets[i], toAssets[i]);
            if (price == 0) continue;

            IERC20(fromAssets[i]).safeApprove(lendingProtocol, amounts[i]);
            try
                ILendingProtocol(lendingProtocol).swapCollateral(users[i], fromAssets[i], toAssets[i], amounts[i])
            {
                totalAmount += amounts[i];
                emit CollateralSwapped(users[i], fromAssets[i], toAssets[i], amounts[i]);
            } catch {
                continue;
            } finally {
                IERC20(fromAssets[i]).safeApprove(lendingProtocol, 0);
            }
        }
        emit BatchCollateralSwapped(users.length, totalAmount);
    }

    /// @notice Handles cross-chain messages via CCIP
    /// @param message The CCIP message
    function _ccipReceive(Client.Any2EVMMessage memory message) internal override nonReentrant whenNotPaused {
        uint64 sourceChainId = uint64(message.sourceChainSelector);
        ICrossChainRetryOracle.NetworkStatus memory status = retryOracle.getNetworkStatus(sourceChainId);
        if (!status.bridgeOperational) revert RetryOracleError(sourceChainId);

        (bytes memory data, address tokenIn, address tokenOut, uint256 amountIn, uint256 minProfit) = abi.decode(
            message.data,
            (bytes, address, address, uint256, uint256)
        );

        if ((tokenIn != tokenA || tokenOut != tokenB) && (tokenIn != tokenB || tokenOut != tokenA))
            revert InvalidTokenPair(tokenIn, tokenOut);

        uint256 amountOut = _executeTrade(tokenIn, tokenOut, amountIn, sourceChainId);
        if (amountOut < minProfit) revert InsufficientProfit(amountOut, minProfit);

        emit CrossChainMessageReceived(sourceChainId, message.messageId);
    }

    /// @notice Withdraws accumulated profits
    /// @param token The token to withdraw
    /// @param recipient The recipient address
    /// @param amount The amount to withdraw
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
    /// @param token The token to recover
    /// @param recipient The recipient address
    function emergencyRecover(address token, address recipient) external nonReentrant onlyRole(GOVERNOR_ROLE) {
        if (recipient == address(0)) revert InvalidExchangeAddress(recipient);
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance > 0) {
            IERC20(token).safeTransfer(recipient, balance);
            emit AssetsRecovered(token, balance, recipient);
        }
    }

    /// @notice Revokes token approvals for specified contracts
    /// @param token The token to revoke approvals for
    function revokeApproval(address token) external onlyRole(GOVERNOR_ROLE) {
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

    /// @notice Pauses the contract
    function pause() external onlyRole(GOVERNOR_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyRole(GOVERNOR_ROLE) {
        _unpause();
    }

    /// @notice Gets active chain IDs from retry oracle
    /// @return chainIds The active chain IDs
    function activeChainIds() public view returns (uint64[] memory chainIds) {
        return retryOracle.activeChainIds();
    }

    /// @notice Receives tokens for gas fees
    receive() external payable {}
}
