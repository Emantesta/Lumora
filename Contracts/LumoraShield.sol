a// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

// Interface for LayerZero (compatible with AMMPool)
interface ILayerZeroEndpoint {
    function send(
        uint16 _dstChainId,
        bytes calldata _destination,
        bytes calldata _payload,
        address payable _refundAddress,
        address _zroPaymentAddress,
        bytes calldata _adapterParams
    ) external payable;
}

// Interface for Lumora DAO (governance)
interface ILumoraDAO {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function GOVERNANCE_ROLE() external view returns (bytes32);
}

// Interface for AMMPool (from AMMPool.sol)
interface IAMMPool {
    function getReserves() external view returns (uint64 reserveA, uint64 reserveB);
    function getCrossChainReserves() external view returns (uint128 reserveA, uint128 reserveB);
    function tokenA() external view returns (address);
    function tokenB() external view returns (address);
    function totalLiquidity() external view returns (uint256);
    function getDynamicFee(uint16 chainId) external view returns (uint256);
    function getPriceOracle() external view returns (address);
    function getFallbackPriceOracles() external view returns (address[] memory);
    function getVolatilityThreshold() external view returns (uint256);
}

/// @title LumoraShield
/// @notice A decentralized insurance protocol providing price protection, impermanent loss coverage, and parametric insurance for DeFi users.
/// @dev Extends ERC721 for policy NFTs and ReentrancyGuard for security. Integrates with AMMPool for liquidity data, LayerZero for cross-chain operations, and Chainlink for price feeds.
/// @custom:security This contract handles user funds and cross-chain operations. Ensure proper testing, audits, and governance controls before deployment.
contract LumoraShield is ReentrancyGuard, ERC721 {
    using SafeERC20Upgradeable for IERC20;

    // Dependencies
    ILumoraDAO public immutable dao; // DAO for governance
    IERC20 public immutable shieldToken; // SHIELD governance and reward token
    IERC20 public immutable usdc; // USDC for stablecoin payments
    address public immutable treasury; // Protocol treasury for fees
    ILayerZeroEndpoint public immutable layerZeroEndpoint; // Cross-chain bridge endpoint
    IAMMPool public immutable ammPool; // AMM pool contract for liquidity operations
    mapping(address => AggregatorV3Interface) public chainlinkOracles; // Asset => Chainlink price feed

    // Constants
    uint256 public constant MAX_VOLATILITY_THRESHOLD = 20 * 1e18; // 20% volatility triggers circuit breaker
    uint256 public constant PREMIUM_DISCOUNT = 20; // 20% discount for SHIELD payments
    uint256 public constant BASE_RATE = 1e16; // Base premium rate (0.01)
    uint256 public constant REWARD_RATE = 1e14; // SHIELD rewards per block per ETH staked
    uint256 public constant MIN_LIQUIDITY_THRESHOLD = 1e18; // Minimum pool liquidity for premium calculation
    uint256 public constant VOLATILITY_WINDOW = 7 days; // 7-day window for volatility calculation
    uint256 public constant PRICE_HISTORY_INTERVAL = 1 hours; // Price recorded every hour
    uint256 public constant MAX_RETRY_ATTEMPTS = 3; // Max retries for cross-chain investment
    uint256 private constant PRICE_HISTORY_SIZE = VOLATILITY_WINDOW / PRICE_HISTORY_INTERVAL; // 168 slots

    // Configurable Fees
    uint256 public treasuryFee = 5; // 5% fee on premiums, configurable
    uint256 public marketplaceFee = 25; // 2.5% fee on NFT trades, configurable

    // Structs
    struct InsurancePolicy {
        address user;
        address asset;
        uint16 chainId; // Changed to uint16 to match AMMPool
        uint256 coverageAmount;
        uint256 coverageThreshold;
        uint256 coveragePercentage;
        uint256 premiumPaid;
        uint256 expiry;
        bool active;
    }

    struct ILPolicy {
        address user;
        address pool;
        uint16 chainId; // Changed to uint16 to match AMMPool
        uint256 lpTokenAmount;
        uint256 coveragePercentage;
        uint256 premiumPaid;
        uint256 expiry;
        bool active;
    }

    struct ParametricPolicy {
        address user;
        address protocol;
        uint16 chainId; // Changed to uint16 to match AMMPool
        uint256 coverageAmount;
        uint256 premiumPaid;
        uint256 expiry;
        bool active;
    }

    struct RiskPool {
        uint256 totalBalance;
        uint256 totalStaked;
        uint256 investedBalance;
        uint256 totalClaims; // Track historical claims
        mapping(address => uint256) stakes;
        mapping(address => uint256) lastRewardBlock;
    }

    struct PriceHistory {
        uint256[168] prices; // Fixed-size array for gas efficiency
        uint256[168] timestamps; // Fixed-size array for gas efficiency
        uint256 lastIndex;
    }

    struct CrossChainInvestment {
        uint256 amount;
        uint256 retryCount;
        bool pending;
        bytes payload;
        uint16 dstChainId;
        bytes adapterParams;
    }

    // State Variables
    mapping(uint16 => mapping(address => RiskPool)) public crossChainRiskPools; // Changed to uint16
    mapping(uint256 => InsurancePolicy) public policies;
    mapping(uint256 => ILPolicy) public impermanentLossPolicies;
    mapping(uint256 => ParametricPolicy) public parametricPolicies;
    mapping(address => PriceHistory) public priceHistories; // Asset => Price history for volatility
    mapping(uint256 => CrossChainInvestment) public pendingInvestments; // Investment ID => CrossChainInvestment
    uint256 public policyCounter;
    uint256 public impermanentLossPolicyCounter;
    uint256 public parametricPolicyCounter;
    uint256 public investmentCounter;
    bool public circuitBreakerActive;
    mapping(address => bool) public supportedProtocols;

    // Tiered Reward Thresholds
    uint256 public constant TIER_1_THRESHOLD = 10 ether; // Stakes >= 10 ETH
    uint256 public constant TIER_2_THRESHOLD = 50 ether; // Stakes >= 50 ETH
    uint256 public constant TIER_1_MULTIPLIER = 12; // 1.2x rewards
    uint256 public constant TIER_2_MULTIPLIER = 15; // 1.5x rewards

    // Errors (aligned with AMMPool)
    error InvalidAddress(address addr, string message);
    error InvalidAmount(uint256 amount, uint256 expected);
    error CircuitBreakerActive();
    error Unauthorized();
    error AssetNotSupported(address asset);
    error InvalidCoveragePercentage(uint256 percentage);
    error InvalidDuration(uint256 duration);
    error VolatilityTooHigh(uint256 volatility);
    error InsufficientPoolFunds(uint256 available, uint256 required);
    error PolicyNotActive(uint256 policyId);
    error NotPolicyOwner(uint256 policyId);
    error PriceAboveThreshold(uint256 currentPrice, uint256 threshold);
    error InvalidPoolSupply();
    error MaxRetriesExceeded(uint256 investmentId);
    error InvestmentNotPending(uint256 investmentId);
    error InvalidFee(uint256 fee);
    error InvalidPrice(uint256 price);
    error StalePrice(uint256 timestamp);
    error OracleFailure();

    // Events (aligned with AMMPool where applicable)
    event PolicyPurchased(uint256 indexed policyId, address indexed user, address indexed asset, uint256 coverageAmount);
    event ILPolicyPurchased(uint256 indexed policyId, address indexed user, address indexed pool, uint256 lpTokenAmount);
    event ParametricPolicyPurchased(uint256 indexed policyId, address indexed user, address indexed protocol);
    event ClaimPayout(uint256 indexed policyId, address indexed user, address indexed asset, uint256 payout);
    event ILClaimPayout(uint256 indexed policyId, address indexed user, address indexed pool, uint256 payout);
    event ParametricClaimPayout(uint256 indexed policyId, address indexed user, address indexed protocol, uint256 payout);
    event RiskPoolStaked(address indexed provider, address indexed asset, uint256 amount);
    event RiskPoolWithdrawn(address indexed provider, address indexed asset, uint256 amount);
    event RewardsClaimed(address indexed provider, address indexed asset, uint256 reward);
    event CircuitBreakerToggled(bool active);
    event SupportedProtocolAdded(address indexed protocol);
    event PolicyTraded(uint256 indexed policyId, address indexed seller, address indexed buyer, uint256 price);
    event PoolInvested(uint16 indexed chainId, address indexed asset, uint256 amount);
    event TreasuryFeeCollected(address indexed asset, uint256 amount);
    event CrossChainInvestment(uint256 indexed investmentId, uint16 indexed chainId, address indexed asset, uint256 amount, uint16 dstChainId);
    event CrossChainInvestmentConfirmed(uint256 indexed investmentId, bool success);
    event TreasuryFeeUpdated(uint256 newFee);
    event MarketplaceFeeUpdated(uint256 newFee);
    event PriceHistoryUpdated(address indexed asset, uint256 price, uint256 timestamp);

    /**
     * @dev Constructor to initialize the contract with dependencies, including AMMPool.
     * @param _daoAddress Address of the governance DAO contract.
     * @param _shieldTokenAddress Address of the SHIELD token contract.
     * @param _usdcAddress Address of the USDC token contract.
     * @param _treasury Address of the treasury for collecting fees.
     * @param _layerZeroEndpoint Address of the LayerZero endpoint for cross-chain operations.
     * @param _ammPool Address of the AMMPool contract.
     */
    constructor(
        address _daoAddress,
        address _shieldTokenAddress,
        address _usdcAddress,
        address _treasury,
        address _layerZeroEndpoint,
        address _ammPool
    ) ERC721("LumoraShieldPolicy", "LSP") {
        if (_daoAddress == address(0)) revert InvalidAddress(_daoAddress, "Invalid DAO address");
        if (_shieldTokenAddress == address(0)) revert InvalidAddress(_shieldTokenAddress, "Invalid SHIELD token address");
        if (_usdcAddress == address(0)) revert InvalidAddress(_usdcAddress, "Invalid USDC address");
        if (_treasury == address(0)) revert InvalidAddress(_treasury, "Invalid treasury address");
        if (_layerZeroEndpoint == address(0)) revert InvalidAddress(_layerZeroEndpoint, "Invalid LayerZero endpoint");
        if (_ammPool == address(0)) revert InvalidAddress(_ammPool, "Invalid AMM pool address");

        dao = ILumoraDAO(_daoAddress);
        shieldToken = IERC20(_shieldTokenAddress);
        usdc = IERC20(_usdcAddress);
        treasury = _treasury;
        layerZeroEndpoint = ILayerZeroEndpoint(_layerZeroEndpoint);
        ammPool = IAMMPool(_ammPool);
        circuitBreakerActive = false;
    }

    /**
     * @dev Sets the Chainlink oracle for an asset and initializes price history.
     * @param asset The asset to set the oracle for.
     * @param oracle The Chainlink price feed address.
     */
    function setChainlinkOracle(address asset, address oracle) external {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        if (asset == address(0)) revert InvalidAddress(asset, "Invalid asset address");
        if (oracle == address(0)) revert InvalidAddress(oracle, "Invalid oracle address");
        chainlinkOracles[asset] = AggregatorV3Interface(oracle);
        // Initialize price history with zeroed arrays
        priceHistories[asset].lastIndex = 0;
        _updatePriceHistory(asset);
    }

    /**
     * @dev Updates the treasury fee percentage.
     * @param newFee The new fee percentage (0-20).
     */
    function setTreasuryFee(uint256 newFee) external {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        if (newFee > 20) revert InvalidFee(newFee);
        treasuryFee = newFee;
        emit TreasuryFeeUpdated(newFee);
    }

    /**
     * @dev Updates the marketplace fee percentage for NFT trades.
     * @param newFee The new fee percentage (0-50, representing 0-5%).
     */
    function setMarketplaceFee(uint256 newFee) external {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        if (newFee > 50) revert InvalidFee(newFee);
        marketplaceFee = newFee;
        emit MarketplaceFeeUpdated(newFee);
    }

    /**
     * @dev Purchases price protection insurance for an asset.
     * @param chainId The target chain ID.
     * @param asset The asset to insure.
     * @param coverageAmount The amount to cover.
     * @param coverageThreshold The price threshold for triggering a claim.
     * @param coveragePercentage The percentage of loss to cover (10-100).
     * @param duration The policy duration (1-365 days).
     * @param payWithShield Whether to pay with SHIELD tokens.
     * @param payWithUSDC Whether to pay with USDC.
     */
    function purchasePriceProtection(
        uint16 chainId,
        address asset,
        uint256 coverageAmount,
        uint256 coverageThreshold,
        uint256 coveragePercentage,
        uint256 duration,
        bool payWithShield,
        bool payWithUSDC
    ) external payable nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (address(chainlinkOracles[asset]) == address(0) && asset != ammPool.tokenA() && asset != ammPool.tokenB()) revert AssetNotSupported(asset);
        if (coveragePercentage < 10 || coveragePercentage > 100) revert InvalidCoveragePercentage(coveragePercentage);
        if (duration < 1 days || duration > 365 days) revert InvalidDuration(duration);
        if (coverageAmount == 0) revert InvalidAmount(coverageAmount, 0);

        _updatePriceHistory(asset);
        uint256 volatility = _getVolatility(asset, chainId);
        if (volatility >= MAX_VOLATILITY_THRESHOLD) revert VolatilityTooHigh(volatility);

        uint256 premium = calculatePremium(coverageAmount, coveragePercentage, volatility, duration, chainId, asset);
        uint256 treasuryFeeAmount = premium * treasuryFee / 100;
        uint256 netPremium = premium - treasuryFeeAmount;

        _handlePayment(payWithShield, payWithUSDC, premium, treasuryFeeAmount, chainId, asset);

        policyCounter++;
        policies[policyCounter] = InsurancePolicy(
            msg.sender,
            asset,
            chainId,
            coverageAmount,
            coverageThreshold,
            coveragePercentage,
            premium,
            block.timestamp + duration,
            true
        );
        _mint(msg.sender, policyCounter);

        emit PolicyPurchased(policyCounter, msg.sender, asset, coverageAmount);
    }

    /**
     * @dev Purchases impermanent loss protection for a liquidity pool.
     * @param chainId The target chain ID.
     * @param pool The liquidity pool address (must be AMMPool).
     * @param lpTokenAmount The amount of LP tokens to cover.
     * @param coveragePercentage The percentage of loss to cover (10-100).
     * @param duration The policy duration (1-365 days).
     * @param payWithShield Whether to pay with SHIELD tokens.
     * @param payWithUSDC Whether to pay with USDC.
     */
    function purchaseILProtection(
        uint16 chainId,
        address pool,
        uint256 lpTokenAmount,
        uint256 coveragePercentage,
        uint256 duration,
        bool payWithShield,
        bool payWithUSDC
    ) external payable nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (pool != address(ammPool)) revert InvalidAddress(pool, "Only AMMPool supported");
        if (coveragePercentage < 10 || coveragePercentage > 100) revert InvalidCoveragePercentage(coveragePercentage);
        if (duration < 1 days || duration > 365 days) revert InvalidDuration(duration);
        if (lpTokenAmount == 0) revert InvalidAmount(lpTokenAmount, 0);

        address token0 = ammPool.tokenA();
        address token1 = ammPool.tokenB();
        _updatePriceHistory(token0);
        _updatePriceHistory(token1);
        uint256 volatility0 = _getVolatility(token0, chainId);
        uint256 volatility1 = _getVolatility(token1, chainId);
        uint256 avgVolatility = (volatility0 + volatility1) / 2;

        uint256 premium = calculatePremium(lpTokenAmount, coveragePercentage, avgVolatility, duration, chainId, pool);
        uint256 treasuryFeeAmount = premium * treasuryFee / 100;
        uint256 netPremium = premium - treasuryFeeAmount;

        _handlePayment(payWithShield, payWithUSDC, premium, treasuryFeeAmount, chainId, pool);

        impermanentLossPolicyCounter++;
        impermanentLossPolicies[impermanentLossPolicyCounter] = ILPolicy(
            msg.sender,
            pool,
            chainId,
            lpTokenAmount,
            coveragePercentage,
            premium,
            block.timestamp + duration,
            true
        );
        _mint(msg.sender, impermanentLossPolicyCounter);

        emit ILPolicyPurchased(impermanentLossPolicyCounter, msg.sender, pool, lpTokenAmount);
    }

    /**
     * @dev Purchases parametric insurance for a protocol.
     * @param chainId The target chain ID.
     * @param protocol The protocol to insure.
     * @param coverageAmount The amount to cover.
     * @param duration The policy duration (1-365 days).
     * @param payWithShield Whether to pay with SHIELD tokens.
     * @param payWithUSDC Whether to pay with USDC.
     */
    function purchaseParametricProtection(
        uint16 chainId,
        address protocol,
        uint256 coverageAmount,
        uint256 duration,
        bool payWithShield,
        bool payWithUSDC
    ) external payable nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (!supportedProtocols[protocol]) revert InvalidAddress(protocol, "Protocol not supported");
        if (duration < 1 days || duration > 365 days) revert InvalidDuration(duration);
        if (coverageAmount == 0) revert InvalidAmount(coverageAmount, 0);

        uint256 premium = calculatePremium(coverageAmount, 100, 1e18, duration, chainId, protocol);
        uint256 treasuryFeeAmount = premium * treasuryFee / 100;
        uint256 netPremium = premium - treasuryFeeAmount;

        _handlePayment(payWithShield, payWithUSDC, premium, treasuryFeeAmount, chainId, protocol);

        parametricPolicyCounter++;
        parametricPolicies[parametricPolicyCounter] = ParametricPolicy(
            msg.sender,
            protocol,
            chainId,
            coverageAmount,
            premium,
            block.timestamp + duration,
            true
        );
        _mint(msg.sender, parametricPolicyCounter);

        emit ParametricPolicyPurchased(parametricPolicyCounter, msg.sender, protocol);
    }

    /**
     * @dev Claims payout for a price protection policy.
     * @param policyId The ID of the policy to claim.
     */
    function claim(uint256 policyId) external nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        InsurancePolicy storage policy = policies[policyId];
        if (policy.user != msg.sender) revert NotPolicyOwner(policyId);
        if (!policy.active || block.timestamp > policy.expiry) revert PolicyNotActive(policyId);

        _updatePriceHistory(policy.asset);
        uint256 currentPrice = _getPrice(policy.asset, policy.chainId);
        if (currentPrice >= policy.coverageThreshold) revert PriceAboveThreshold(currentPrice, policy.coverageThreshold);

        uint256 effectiveCoverage = policy.coverageAmount * policy.coveragePercentage / 100;
        uint256 payout = effectiveCoverage * (policy.coverageThreshold - currentPrice) / 1e18;
        RiskPool storage pool = crossChainRiskPools[policy.chainId][policy.asset];
        if (pool.totalBalance < payout) revert InsufficientPoolFunds(pool.totalBalance, payout);

        pool.totalBalance -= payout;
        pool.totalClaims += payout;
        policy.active = false;
        payable(msg.sender).transfer(payout);

        emit ClaimPayout(policyId, msg.sender, policy.asset, payout);
    }

    /**
     * @dev Claims payout for an impermanent loss policy.
     * @param policyId The ID of the policy to claim.
     */
    function claimIL(uint256 policyId) external nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        ILPolicy storage policy = impermanentLossPolicies[policyId];
        if (policy.user != msg.sender) revert NotPolicyOwner(policyId);
        if (!policy.active || block.timestamp > policy.expiry) revert PolicyNotActive(policyId);
        if (policy.pool != address(ammPool)) revert InvalidAddress(policy.pool, "Only AMMPool supported");

        (uint64 reserveA, uint64 reserveB) = ammPool.getReserves();
        address token0 = ammPool.tokenA();
        address token1 = ammPool.tokenB();
        _updatePriceHistory(token0);
        _updatePriceHistory(token1);
        uint256 price0 = _getPrice(token0, policy.chainId);
        uint256 price1 = _getPrice(token1, policy.chainId);
        uint256 ilLoss = calculateImpermanentLoss(policy.lpTokenAmount, reserveA, reserveB, price0, price1, policy.pool);

        uint256 payout = ilLoss * policy.coveragePercentage / 100;
        RiskPool storage pool = crossChainRiskPools[policy.chainId][policy.pool];
        if (pool.totalBalance < payout) revert InsufficientPoolFunds(pool.totalBalance, payout);

        pool.totalBalance -= payout;
        pool.totalClaims += payout;
        policy.active = false;
        payable(msg.sender).transfer(payout);

        emit ILClaimPayout(policyId, msg.sender, policy.pool, payout);
    }

    /**
     * @dev Triggers a parametric payout for a protocol failure.
     * @param policyId The ID of the parametric policy.
     * @param protocol The protocol address.
     * @param lossAmount The payout amount.
     */
    function triggerParametricPayout(uint256 policyId, address protocol, uint256 lossAmount) external nonReentrant {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        ParametricPolicy storage policy = parametricPolicies[policyId];
        if (policy.protocol != protocol) revert InvalidAddress(protocol, "Invalid protocol");
        if (!policy.active || block.timestamp > policy.expiry) revert PolicyNotActive(policyId);
        RiskPool storage pool = crossChainRiskPools[policy.chainId][protocol];
        if (pool.totalBalance < lossAmount) revert InsufficientPoolFunds(pool.totalBalance, lossAmount);

        pool.totalBalance -= lossAmount;
        pool.totalClaims += lossAmount;
        policy.active = false;
        payable(policy.user).transfer(lossAmount);

        emit ParametricClaimPayout(policyId, policy.user, protocol, lossAmount);
    }

    /**
     * @dev Stakes funds in a risk pool.
     * @param chainId The target chain ID.
     * @param asset The asset or protocol to stake for.
     */
    function stake(uint16 chainId, address asset) external payable nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (address(chainlinkOracles[asset]) == address(0) && !supportedProtocols[asset] && asset != address(ammPool)) revert AssetNotSupported(asset);
        if (msg.value == 0) revert InvalidAmount(msg.value, 0);

        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        _claimRewards(msg.sender, chainId, asset);
        pool.stakes[msg.sender] += msg.value;
        pool.totalStaked += msg.value;
        pool.totalBalance += msg.value;
        pool.lastRewardBlock[msg.sender] = block.number;

        emit RiskPoolStaked(msg.sender, asset, msg.value);
    }

    /**
     * @dev Withdraws staked funds from a risk pool.
     * @param chainId The target chain ID.
     * @param asset The asset or protocol.
     * @param amount The amount to withdraw.
     */
    function withdraw(uint16 chainId, address asset, uint256 amount) external nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        if (pool.stakes[msg.sender] < amount) revert InvalidAmount(amount, pool.stakes[msg.sender]);

        _claimRewards(msg.sender, chainId, asset);
        pool.stakes[msg.sender] -= amount;
        pool.totalStaked -= amount;
        pool.totalBalance -= amount;
        payable(msg.sender).transfer(amount);

        emit RiskPoolWithdrawn(msg.sender, asset, amount);
    }

    /**
     * @dev Claims SHIELD token rewards for staking.
     * @param chainId The target chain ID.
     * @param asset The asset or protocol.
     */
    function claimRewards(uint16 chainId, address asset) external nonReentrant {
        _claimRewards(msg.sender, chainId, asset);
    }

    /**
     * @dev Trades a policy NFT to a new owner.
     * @param policyId The ID of the policy NFT.
     * @param price The sale price.
     * @param buyer The address of the buyer.
     */
    function tradePolicy(uint256 policyId, uint256 price, address buyer) external payable nonReentrant {
        if (circuitBreakerActive) revert CircuitBreakerActive();
        if (ownerOf(policyId) != msg.sender) revert NotPolicyOwner(policyId);
        if (buyer == address(0)) revert InvalidAddress(buyer, "Invalid buyer address");
        if (msg.value < price) revert InvalidAmount(msg.value, price);

        uint256 fee = price * marketplaceFee / 1000;
        payable(treasury).transfer(fee);
        _transfer(msg.sender, buyer, policyId);
        payable(msg.sender).transfer(price - fee);
        if (msg.value > price) {
            payable(msg.sender).transfer(msg.value - price);
        }
        emit PolicyTraded(policyId, msg.sender, buyer, price);
    }

    /**
     * @dev Invests risk pool funds in a cross-chain protocol via LayerZero.
     * @param chainId The source chain ID.
     * @param asset The asset to invest.
     * @param amount The investment amount.
     * @param dstChainId The destination chain ID.
     * @param adapterParams LayerZero adapter parameters.
     */
    function investPool(
        uint16 chainId,
        address asset,
        uint256 amount,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        if (pool.totalBalance < amount) revert InsufficientPoolFunds(pool.totalBalance, amount);
        if (pool.totalBalance - pool.investedBalance < amount) revert InsufficientPoolFunds(pool.totalBalance - pool.investedBalance, amount);

        pool.totalBalance -= amount;
        pool.investedBalance += amount;

        investmentCounter++;
        bytes memory payload = abi.encode(asset, amount, investmentCounter);
        pendingInvestments[investmentCounter] = CrossChainInvestment(
            amount,
            0,
            true,
            payload,
            dstChainId,
            adapterParams
        );

        try layerZeroEndpoint.send{value: msg.value}(
            dstChainId,
            abi.encodePacked(address(this)),
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        ) {
            emit PoolInvested(chainId, asset, amount);
            emit CrossChainInvestment(investmentCounter, chainId, asset, amount, dstChainId);
        } catch {
            _retryInvestment(investmentCounter, chainId, asset);
        }
    }

    /**
     * @dev Retries a failed cross-chain investment.
     * @param investmentId The ID of the investment to retry.
     */
    function retryInvestment(uint256 investmentId) external payable nonReentrant {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        CrossChainInvestment storage investment = pendingInvestments[investmentId];
        if (!investment.pending) revert InvestmentNotPending(investmentId);
        if (investment.retryCount >= MAX_RETRY_ATTEMPTS) revert MaxRetriesExceeded(investmentId);

        _retryInvestment(investmentId, investment.payload);
    }

    /**
     * @dev Confirms a cross-chain investment (called by LayerZero).
     * @param investmentId The ID of the investment.
     * @param success Whether the investment was successful.
     */
    function confirmInvestment(uint256 investmentId, bool success) external nonReentrant {
        if (msg.sender != address(layerZeroEndpoint)) revert Unauthorized();
        CrossChainInvestment storage investment = pendingInvestments[investmentId];
        if (!investment.pending) revert InvestmentNotPending(investmentId);

        (address asset, uint256 amount,) = abi.decode(investment.payload, (address, uint256, uint256));
        RiskPool storage pool = crossChainRiskPools[investmentId][asset];

        if (!success && investment.retryCount < MAX_RETRY_ATTEMPTS) {
            _retryInvestment(investmentId, investment.payload);
        } else {
            if (!success) {
                pool.totalBalance += investment.amount;
                pool.investedBalance -= investment.amount;
            }
            delete pendingInvestments[investmentId];
            emit CrossChainInvestmentConfirmed(investmentId, success);
        }
    }

    /**
     * @dev Toggles the circuit breaker to pause or resume operations.
     * @param active Whether to activate the circuit breaker.
     */
    function toggleCircuitBreaker(bool active) external {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        circuitBreakerActive = active;
        emit CircuitBreakerToggled(active);
    }

    /**
     * @dev Adds a supported protocol for insurance.
     * @param protocol The protocol address.
     */
    function addSupportedProtocol(address protocol) external {
        if (!dao.hasRole(dao.GOVERNANCE_ROLE(), msg.sender)) revert Unauthorized();
        if (protocol == address(0)) revert InvalidAddress(protocol, "Invalid protocol address");
        if (supportedProtocols[protocol]) revert InvalidAddress(protocol, "Protocol already supported");
        supportedProtocols[protocol] = true;
        emit SupportedProtocolAdded(protocol);
    }

    /**
     * @dev Calculates the premium for an insurance policy.
     * @param coverageAmount The amount to cover.
     * @param coveragePercentage The percentage of loss to cover.
     * @param volatility Volatility factor.
     * @param duration The policy duration.
     * @param chainId The target chain ID.
     * @param asset The asset or protocol.
     * @return The premium amount in wei.
     */
    function calculatePremium(
        uint256 coverageAmount,
        uint256 coveragePercentage,
        uint256 volatility,
        uint256 duration,
        uint16 chainId,
        address asset
    ) public view returns (uint256) {
        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        uint256 liquidityFactor = pool.totalBalance > MIN_LIQUIDITY_THRESHOLD
            ? MIN_LIQUIDITY_THRESHOLD * 1e18 / pool.totalBalance
            : 1e18;
        uint256 claimsFactor = pool.totalClaims > 0
            ? (pool.totalClaims * 1e18 / pool.totalBalance) + 1e18
            : 1e18;
        uint256 dynamicFee = ammPool.getDynamicFee(chainId);

        return (coverageAmount * coveragePercentage * volatility * duration * BASE_RATE * claimsFactor * dynamicFee) /
            (100 * 1e18 * 365 days * liquidityFactor * 1e4);
    }

    /**
     * @dev Calculates impermanent loss for a liquidity pool position.
     * @param lpTokenAmount The amount of LP tokens.
     * @param reserve0 Reserve of token0 in the pool.
     * @param reserve1 Reserve of token1 in the pool.
     * @param price0 Price of token0.
     * @param price1 Price of token1.
     * @param pool The pool address.
     * @return The impermanent loss in wei.
     */
    function calculateImpermanentLoss(
        uint256 lpTokenAmount,
        uint256 reserve0,
        uint256 reserve1,
        uint256 price0,
        uint256 price1,
        address pool
    ) public view returns (uint256) {
        if (pool != address(ammPool)) revert InvalidAddress(pool, "Only AMMPool supported");
        uint256 totalSupply = ammPool.totalLiquidity();
        if (totalSupply == 0) revert InvalidPoolSupply();

        uint256 share = lpTokenAmount * 1e18 / totalSupply;
        uint256 amount0 = reserve0 * share / 1e18;
        uint256 amount1 = reserve1 * share / 1e18;

        uint256 pooledValue = (amount0 * price0 + amount1 * price1) / 1e18;

        uint256 k = amount0 * amount1;
        uint256 currentPriceRatio = (price0 * 1e18) / price1;
        uint256 optimalAmount0 = sqrt(k * currentPriceRatio / 1e18);
        uint256 optimalAmount1 = k / optimalAmount0;
        uint256 holdValue = (optimalAmount0 * price0 + optimalAmount1 * price1) / 1e18;

        return holdValue > pooledValue ? holdValue - pooledValue : 0;
    }

    /**
     * @dev Retrieves the latest price for an asset, preferring AMMPool's oracle.
     * @param asset The asset address.
     * @param chainId The chain ID.
     * @return The latest price in wei.
     */
    function _getPrice(address asset, uint16 chainId) internal view returns (uint256) {
        // Try AMMPool's primary oracle first
        address primaryOracle = ammPool.getPriceOracle();
        if (primaryOracle != address(0) && (asset == ammPool.tokenA() || asset == ammPool.tokenB())) {
            try IPriceOracle(primaryOracle).getPrice(ammPool.tokenA(), ammPool.tokenB()) returns (int256 price) {
                if (price <= 0) revert InvalidPrice(uint256(price));
                return uint256(price);
            } catch {
                // Fallback to AMMPool's fallback oracles
                address[] memory fallbackOracles = ammPool.getFallbackPriceOracles();
                for (uint256 i = 0; i < fallbackOracles.length; i++) {
                    if (fallbackOracles[i] != address(0)) {
                        try IPriceOracle(fallbackOracles[i]).getPrice(ammPool.tokenA(), ammPool.tokenB()) returns (int256 price) {
                            if (price <= 0) revert InvalidPrice(uint256(price));
                            return uint256(price);
                        } catch {}
                    }
                }
            }
        }

        // Fallback to Chainlink oracle
        AggregatorV3Interface oracle = chainlinkOracles[asset];
        if (address(oracle) == address(0)) revert AssetNotSupported(asset);
        (, int256 price,, uint256 updatedAt,) = oracle.latestRoundData();
        if (price <= 0) revert InvalidPrice(uint256(price));
        if (block.timestamp > updatedAt + 1 hours) revert StalePrice(updatedAt);
        return uint256(price);
    }

    /**
     * @dev Calculates annualized volatility based on price history or AMMPool volatility.
     * @param asset The asset address.
     * @param chainId The chain ID.
     * @return The annualized volatility.
     */
    function _getVolatility(address asset, uint16 chainId) internal view returns (uint256) {
        // Use AMMPool's volatility if available for pool tokens
        if (asset == ammPool.tokenA() || asset == ammPool.tokenB()) {
            uint256 volatility = ammPool.getVolatilityThreshold();
            if (volatility > 0) {
                return volatility;
            }
        }

        // Fallback to Chainlink-based volatility
        PriceHistory storage history = priceHistories[asset];
        if (address(chainlinkOracles[asset]) == address(0)) revert AssetNotSupported(asset);
        if (history.prices[0] == 0) return 10 * 1e16; // Default volatility

        uint256 sumReturns = 0;
        uint256 sumReturnsSquared = 0;
        uint256 count = 0;

        for (uint256 i = 1; i < PRICE_HISTORY_SIZE; i++) {
            if (history.prices[i] != 0 && history.prices[i-1] != 0) {
                uint256 returnValue = (history.prices[i] * 1e18) / history.prices[i-1];
                sumReturns += returnValue;
                sumReturnsSquared += returnValue * returnValue / 1e18;
                count++;
            }
        }

        if (count == 0) return 10 * 1e16; // Default volatility

        uint256 meanReturns = sumReturns / count;
        uint256 variance = (sumReturnsSquared / count - (meanReturns * meanReturns / 1e18)) * 1e18;
        uint256 dailyVolatility = sqrt(variance);
        return dailyVolatility * sqrt(365 * 24); // Annualize
    }

    /**
     * @dev Updates the price history for an asset using Chainlink or AMMPool data.
     * @param asset The asset address.
     */
    function _updatePriceHistory(address asset) internal {
        PriceHistory storage history = priceHistories[asset];
        uint256 price;

        // Try AMMPool's oracle for pool tokens
        if (asset == ammPool.tokenA() || asset == ammPool.tokenB()) {
            try this._getPrice(asset, 0) returns (uint256 oraclePrice) {
                price = oraclePrice;
            } catch {
                return; // Skip update if oracle fails
            }
        } else {
            AggregatorV3Interface oracle = chainlinkOracles[asset];
            if (address(oracle) == address(0)) revert AssetNotSupported(asset);
            (, int256 oraclePrice,, uint256 updatedAt,) = oracle.latestRoundData();
            if (oraclePrice <= 0 || block.timestamp > updatedAt + 1 hours) revert InvalidPrice(uint256(oraclePrice));
            price = uint256(oraclePrice);
        }

        uint256 lastTimestamp = history.timestamps[history.lastIndex];
        if (block.timestamp < lastTimestamp + PRICE_HISTORY_INTERVAL) return;

        history.lastIndex = (history.lastIndex + 1) % PRICE_HISTORY_SIZE;
        history.prices[history.lastIndex] = price;
        history.timestamps[history.lastIndex] = block.timestamp;

        emit PriceHistoryUpdated(asset, price, block.timestamp);
    }

    /**
     * @dev Handles payment for premiums in ETH, USDC, or SHIELD.
     * @param payWithShield Whether to pay with SHIELD tokens.
     * @param payWithUSDC Whether to pay with USDC.
     * @param premium The premium amount.
     * @param treasuryFeeAmount The treasury fee portion.
     * @param chainId The target chain ID.
     * @param asset The asset or protocol.
     */
    function _handlePayment(
        bool payWithShield,
        bool payWithUSDC,
        uint256 premium,
        uint256 treasuryFeeAmount,
        uint16 chainId,
        address asset
    ) internal {
        uint256 netPremium = premium - treasuryFeeAmount;
        if (payWithUSDC) {
            uint256 premiumUSD = premium * _getPrice(address(0), chainId) / 1e18;
            uint256 treasuryFeeUSD = premiumUSD * treasuryFee / 100;
            usdc.safeTransferFrom(msg.sender, treasury, treasuryFeeUSD);
            usdc.safeTransferFrom(msg.sender, address(this), premiumUSD - treasuryFeeUSD);
            emit TreasuryFeeCollected(address(usdc), treasuryFeeUSD);
        } else if (payWithShield) {
            uint256 discountedPremium = premium * (100 - PREMIUM_DISCOUNT) / 100;
            uint256 discountedTreasuryFee = discountedPremium * treasuryFee / 100;
            shieldToken.safeTransferFrom(msg.sender, treasury, discountedTreasuryFee);
            shieldToken.safeTransferFrom(msg.sender, address(this), discountedPremium - discountedTreasuryFee);
            emit TreasuryFeeCollected(address(shieldToken), discountedTreasuryFee);
        } else {
            if (msg.value < premium) revert InvalidAmount(msg.value, premium);
            payable(treasury).transfer(treasuryFeeAmount);
            crossChainRiskPools[chainId][asset].totalBalance += netPremium;
            if (msg.value > premium) {
                payable(msg.sender).transfer(msg.value - premium);
            }
            emit TreasuryFeeCollected(address(0), treasuryFeeAmount);
        }
    }

    /**
     * @dev Claims rewards for a staker with tiered multipliers.
     * @param provider The staker's address.
     * @param chainId The chain ID.
     * @param asset The asset or protocol.
     */
    function _claimRewards(address provider, uint16 chainId, address asset) internal {
        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        uint256 blocksSinceLast = block.number - pool.lastRewardBlock[provider];
        uint256 baseReward = pool.stakes[provider] * blocksSinceLast * REWARD_RATE / 1e18;

        uint256 multiplier = 10; // 1.0x default
        if (pool.stakes[provider] >= TIER_2_THRESHOLD) {
            multiplier = TIER_2_MULTIPLIER; // 1.5x
        } else if (pool.stakes[provider] >= TIER_1_THRESHOLD) {
            multiplier = TIER_1_MULTIPLIER; // 1.2x
        }
        uint256 reward = baseReward * multiplier / 10;

        if (reward > 0) {
            pool.lastRewardBlock[provider] = block.number;
            shieldToken.safeTransfer(provider, reward);
            emit RewardsClaimed(provider, asset, reward);
        }
    }

    /**
     * @dev Retries a failed cross-chain investment.
     * @param investmentId The ID of the investment.
     * @param payload The encoded investment data.
     */
    function _retryInvestment(uint256 investmentId, bytes memory payload) private {
        CrossChainInvestment storage investment = pendingInvestments[investmentId];
        (address asset, uint256 amount,) = abi.decode(payload, (address, uint256, uint256));
        investment.retryCount++;
        RiskPool storage pool = crossChainRiskPools[investmentId][asset];

        try layerZeroEndpoint.send{value: msg.value}(
            investment.dstChainId,
            abi.encodePacked(address(this)),
            payload,
            payable(msg.sender),
            address(0),
            investment.adapterParams
        ) {
            emit CrossChainInvestment(investmentId, investmentId, asset, amount, investment.dstChainId);
        } catch {
            if (investment.retryCount >= MAX_RETRY_ATTEMPTS) {
                pool.totalBalance += investment.amount;
                pool.investedBalance -= investment.amount;
                delete pendingInvestments[investmentId];
                emit CrossChainInvestmentConfirmed(investmentId, false);
            }
        }
    }

    /**
     * @dev Overrides ERC721 _update to handle policy ownership changes.
     * @param to The new owner's address.
     * @param tokenId The policy NFT ID.
     * @param auth The authorized address (unused).
     * @return The previous owner's address.
     */
    function _update(address to, uint256 tokenId, address /* auth */) internal override returns (address) {
        if (to == address(0)) revert InvalidAddress(to, "Cannot transfer to zero address");
        address previousOwner = super._update(to, tokenId, address(0));
        if (policies[tokenId].user != address(0)) {
            policies[tokenId].user = to;
        } else if (impermanentLossPolicies[tokenId].user != address(0)) {
            impermanentLossPolicies[tokenId].user = to;
        } else if (parametricPolicies[tokenId].user != address(0)) {
            parametricPolicies[tokenId].user = to;
        }
        return previousOwner;
    }

    /**
     * @dev Calculates the square root of a number using the Babylonian method.
     * @param y The input number.
     * @return z The square root.
     */
    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
        return z;
    }

    // View functions
    function getPolicy(uint256 policyId) external view returns (InsurancePolicy memory) {
        return policies[policyId];
    }

    function getILPolicy(uint256 policyId) external view returns (ILPolicy memory) {
        return impermanentLossPolicies[policyId];
    }

    function getParametricPolicy(uint256 policyId) external view returns (ParametricPolicy memory) {
        return parametricPolicies[policyId];
    }

    function getRiskPool(uint16 chainId, address asset) external view returns (uint256 totalBalance, uint256 totalStaked, uint256 investedBalance, uint256 totalClaims) {
        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        return (pool.totalBalance, pool.totalStaked, pool.investedBalance, pool.totalClaims);
    }

    function estimateRewards(address provider, uint16 chainId, address asset) external view returns (uint256) {
        RiskPool storage pool = crossChainRiskPools[chainId][asset];
        uint256 blocksSinceLast = block.number - pool.lastRewardBlock[provider];
        uint256 baseReward = pool.stakes[provider] * blocksSinceLast * REWARD_RATE / 1e18;

        uint256 multiplier = 10; // 1.0x default
        if (pool.stakes[provider] >= TIER_2_THRESHOLD) {
            multiplier = TIER_2_MULTIPLIER; // 1.5x
        } else if (pool.stakes[provider] >= TIER_1_THRESHOLD) {
            multiplier = TIER_1_MULTIPLIER; // 1.2x
        }
        return baseReward * multiplier / 10;
    }

    function getPriceHistory(address asset) external view returns (uint256[] memory prices, uint256[] memory timestamps) {
        PriceHistory storage history = priceHistories[asset];
        prices = new uint256[](PRICE_HISTORY_SIZE);
        timestamps = new uint256[](PRICE_HISTORY_SIZE);
        for (uint256 i = 0; i < PRICE_HISTORY_SIZE; i++) {
            prices[i] = history.prices[i];
            timestamps[i] = history.timestamps[i];
        }
        return (prices, timestamps);
    }
}

// Placeholder IPriceOracle interface (from AMMPool.sol)
interface IPriceOracle {
    function getPrice(address tokenA, address tokenB) external view returns (int256);
}
