// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

// Interface for Band Protocol (fallback oracle)
interface IBandProtocol {
    function getReferenceData(string memory pair) external view returns (uint256, uint256);
}

// Interface for CrossChainModule
interface ICrossChainModule {
    function addLiquidityCrossChain(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable;

    function swapCrossChain(
        address user,
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable returns (uint256);

    function receiveMessage(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external;

    function getEstimatedCrossChainFee(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);
}

// Interface for OrderBook
interface IOrderBook {
    struct FeeTier {
        uint256 orderSizeThreshold;
        uint256 feeRateBps;
    }

    struct SignedOrder {
        bool isBuy;
        bool isMarket;
        bool isStopLoss;
        uint96 price;
        uint96 triggerPrice;
        uint96 amount;
        address tokenA;
        address tokenB;
        uint64 expiryTimestamp;
        bool useConcentratedLiquidity;
        address user;
        bytes signature;
    }

    function getAggregatedPrice(address tokenA, address tokenB) external view returns (uint256);
    function placeOrder(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp,
        bool useConcentratedLiquidity
    ) external returns (uint256);
    function placePerpetualOrder(
        address tokenA,
        address tokenB,
        uint256 amount,
        bool isBuy,
        uint256 leverage,
        uint256 margin
    ) external returns (uint256);
    function placeOrderCrossChain(
        bool isBuy,
        bool isMarket,
        bool isStopLoss,
        uint96 price,
        uint96 triggerPrice,
        uint96 amount,
        address tokenA,
        address tokenB,
        uint64 expiryTimestamp,
        bool useConcentratedLiquidity,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable returns (uint256);
    function placeOrderWithSignature(SignedOrder calldata signedOrder) external returns (uint256);
    function applyFunding(uint256 orderId) external;
    function liquidatePosition(uint256 orderId) external;
    function setLiquidityRange(uint256 amountA, uint256 amountB) external;
    function getFeeTiers() external view returns (FeeTier[] memory);
    function createProposal(
        string memory description,
        ProposalType proposalType,
        bytes memory data
    ) external;
    enum ProposalType { ParameterChange, ProtocolUpgrade }
}

// Custom errors
error InvalidExpiry();
error InvalidAmount();
error InvalidPremium();
error NotOptionOwner();
error OptionExercised();
error OptionExpired();
error NotInTheMoney();
error TransferFailed();
error InvalidPrice();
error StalePrice();
error NotSameChain();
error Unauthorized();
error InvalidProtocol();
error MessageFailed();
error InvalidBarrier();
error BarrierNotMet();
error FundingRateNotPaid();
error InvalidOptionType();
error InvalidAdapterParams();
error InsufficientFee(uint256 provided, uint256 required);
error ChainPausedError(uint16 chainId);
error OrderBookError(string message);
error InvalidSignature();
error InvalidFeeTier();
error ProposalFailed(string reason);
error InvalidObservationInterval();
error ObservationLimitExceeded();
error InvalidObservationCount();
error FundingRateTooHigh();
error StorageLimitExceeded();

// @title CryptoOptions - Upgradeable options trading contract for DEX with OrderBook integration
// @notice Supports standard, barrier, binary, perpetual, stop-loss, Asian, and Lookback options with cross-chain and AMM integration
// @dev Integrates with OrderBook for trade execution, pricing, and liquidity provision
// @custom:version 1.5.1
contract CryptoOptions is Initializable, UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    // @notice Enum for option types
    enum OptionType {
        Standard,
        BarrierKnockIn,
        BarrierKnockOut,
        Binary,
        Perpetual,
        AsianAveragePrice,
        AsianAverageStrike,
        LookbackFixedStrike,
        LookbackFloatingStrike
    }

    // @notice Struct for an option contract
    struct Option {
        address buyer; // Option owner
        address underlyingToken; // e.g., wBTC, ETH
        address quoteToken; // Quote token (e.g., USDC)
        uint96 strikePrice; // in 18 decimals
        uint96 premium; // in USDC (6 decimals)
        uint64 expiry; // timestamp (0 for perpetual options)
        uint128 amount; // underlying token amount (18 decimals)
        bool isCall; // true for call, false for put
        bool isAmerican; // true for American-style (ignored for perpetual/binary)
        bool exercised; // true if exercised
        uint32 chainId; // for non-Cosmos chains
        string cosmosChainId; // for Cosmos chains
        OptionType optionType; // Option type
        uint96 barrierPrice; // Barrier price for barrier options (18 decimals)
        uint96 payout; // Fixed payout for binary options (6 decimals)
        uint64 lastFundingPayment; // Last funding rate payment timestamp
        uint96 fundingRateBps; // Funding rate in basis points
        uint256 orderBookId; // OrderBook order ID
        uint96 triggerPrice; // Trigger price for stop-loss (18 decimals)
        uint64 observationInterval; // Interval for price observations
        uint8 observationCount; // Number of price observations
        uint96 maxPrice; // Max price observed (18 decimals)
        uint96 minPrice; // Min price observed (18 decimals)
    }

    // State variables
    mapping(uint256 => Option) public options;
    mapping(uint256 => mapping(uint256 => uint96)) public priceObservations; // optionId => observationIndex => price (18 decimals)
    mapping(uint256 => mapping(uint256 => uint64)) public observationTimestamps; // optionId => observationIndex => timestamp
    uint256 public optionCounter;
    IERC20 public usdc;
    IOrderBook public orderBook;
    IBandProtocol public bandOracle;
    ICrossChainModule public crossChainModule;
    mapping(address => AggregatorV3Interface) public chainlinkOracles;
    mapping(address => uint256[]) public userOptions;
    mapping(address => bool) public kycVerified;
    uint256 public feeBps = 5; // Default 0.05% fee (5 basis points)
    uint256 public constant BPS_DENOMINATOR = 10000; // Basis points
    uint256 public timeout = 1 hours; // Timeout for in-flight messages
    uint256 public fundingInterval = 8 hours; // Funding rate payment interval
    uint256 public constant MAX_OBSERVATIONS = 100; // Max price observations per option
    uint256 public constant MIN_OBSERVATION_INTERVAL = 1 hours; // Minimum interval
    uint256 public constant MAX_FUNDING_RATE_BPS = 1000; // Max 10% funding rate
    uint256 public collectedFundingFees;

    // Events
    event OptionCreated(
        uint256 indexed optionId,
        address indexed buyer,
        address underlyingToken,
        address quoteToken,
        uint256 strikePrice,
        uint256 premium,
        uint256 expiry,
        bool isCall,
        bool isAmerican,
        uint256 chainId,
        string cosmosChainId,
        OptionType optionType,
        uint256 barrierPrice,
        uint256 payout,
        uint256 fundingRateBps,
        uint256 orderBookId,
        uint256 triggerPrice,
        uint64 observationInterval,
        uint8 observationCount
    );
    event OptionExercised(uint256 indexed optionId, address indexed buyer, uint256 profit);
    event FeeCollected(address indexed recipient, uint256 fee);
    event LiquidityRewardDeposited(address indexed token, uint256 amount);
    event Paused(address indexed owner);
    event Unpaused(address indexed owner);
    event CrossChainModuleUpdated(address indexed crossChainModule);
    event OrderBookUpdated(address indexed orderBook);
    event FundingRatePaid(uint256 indexed optionId, address indexed buyer, uint256 amount);
    event CrossChainMessageSent(uint256 indexed optionId, uint16 dstChainId, bytes payload, uint256 nativeFee);
    event CrossChainMessageReceived(uint256 indexed optionId, uint16 srcChainId, bytes payload);
    event LiquidityProvided(address indexed provider, address tokenA, address tokenB, uint256 amountA, uint256 amountB);
    event ParameterProposed(string paramName, uint256 value);
    event PriceObservationRecorded(uint256 indexed optionId, uint256 index, uint96 price, uint64 timestamp);
    event LookbackPriceUpdated(uint256 indexed optionId, uint96 maxPrice, uint96 minPrice);
    event FeeBpsUpdated(uint256 newFeeBps);
    event TimeoutUpdated(uint256 newTimeout);
    event FundingIntervalUpdated(uint256 newFundingInterval);

    // @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // @notice Initialize the contract
    // @param _usdc USDC token address
    // @param _orderBook OrderBook contract address
    // @param _bandOracle Band Protocol oracle address
    // @param _crossChainModule CrossChainModule address
    function initialize(
        address _usdc,
        address _orderBook,
        address _bandOracle,
        address _crossChainModule
    ) external initializer {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        __Pausable_init();
        usdc = IERC20(_usdc);
        orderBook = IOrderBook(_orderBook);
        bandOracle = IBandProtocol(_bandOracle);
        crossChainModule = ICrossChainModule(_crossChainModule);
    }

    // @notice Authorize upgrades
    // @param newImplementation New implementation address
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // @notice Create a new option
    // @param _underlyingToken Underlying token address (e.g., wBTC, ETH)
    // @param _quoteToken Quote token address (e.g., USDC)
    // @param _strikePrice Strike price (18 decimals)
    // @param _premium Premium (USDC, 6 decimals)
    // @param _expiry Expiry timestamp (0 for perpetual)
    // @param _amount Underlying token amount (18 decimals)
    // @param _isCall True for call, false for put
    // @param _isAmerican True for American-style
    // @param _chainId Chain ID for non-Cosmos chains
    // @param _cosmosChainId Cosmos chain ID
    // @param _optionType Type of option
    // @param _barrierPrice Barrier price (18 decimals)
    // @param _payout Payout for binary options (6 decimals)
    // @param _fundingRateBps Funding rate in basis points
    // @param _leverage Leverage for perpetual options
    // @param _margin Margin for perpetual options
    // @param _triggerPrice Trigger price for stop-loss (18 decimals)
    // @param _observationInterval Observation interval for Asian options
    // @param _observationCount Number of observations for Asian options
    // @return optionId The ID of the created option
    function createOption(
        address _underlyingToken,
        address _quoteToken,
        uint96 _strikePrice,
        uint96 _premium,
        uint64 _expiry,
        uint128 _amount,
        bool _isCall,
        bool _isAmerican,
        uint32 _chainId,
        string calldata _cosmosChainId,
        OptionType _optionType,
        uint96 _barrierPrice,
        uint96 _payout,
        uint96 _fundingRateBps,
        uint256 _leverage,
        uint256 _margin,
        uint96 _triggerPrice,
        uint64 _observationInterval,
        uint8 _observationCount
    ) public nonReentrant whenNotPaused returns (uint256) {
        if (!kycVerified[msg.sender]) revert Unauthorized();
        if (_optionType != OptionType.Perpetual && _expiry <= block.timestamp) revert InvalidExpiry();
        if (_amount == 0) revert InvalidAmount();
        if (_premium == 0) revert InvalidPremium();
        if (_optionType == OptionType.BarrierKnockIn || _optionType == OptionType.BarrierKnockOut) {
            if (_barrierPrice == 0) revert InvalidBarrier();
        }
        if (_optionType == OptionType.Binary && _payout == 0) revert InvalidPremium();
        if (_optionType == OptionType.Perpetual) {
            if (_fundingRateBps == 0 || _leverage == 0 || _margin == 0) revert InvalidPremium();
            if (_fundingRateBps > MAX_FUNDING_RATE_BPS) revert FundingRateTooHigh();
        }
        if (_optionType == OptionType.AsianAveragePrice || _optionType == OptionType.AsianAverageStrike) {
            if (_observationInterval < MIN_OBSERVATION_INTERVAL) revert InvalidObservationInterval();
            if (_observationCount == 0 || _observationCount > MAX_OBSERVATIONS) revert InvalidObservationCount();
        }

        uint256 fee = getDynamicFee(_premium);
        uint256 netPremium = _premium - fee;
        if (!usdc.transferFrom(msg.sender, address(this), _premium)) revert TransferFailed();

        uint256 optionId = optionCounter++;
        uint256 orderBookId;

        if (_optionType == OptionType.Perpetual) {
            orderBookId = orderBook.placePerpetualOrder(_underlyingToken, _quoteToken, _amount, _isCall, _leverage, _margin);
        } else if (_triggerPrice > 0) {
            orderBookId = orderBook.placeOrder(
                _isCall,
                false,
                true,
                _strikePrice,
                _triggerPrice,
                uint96(_amount),
                _underlyingToken,
                _quoteToken,
                _expiry,
                false
            );
        }

        uint96 maxPrice = 0;
        uint96 minPrice = type(uint96).max;
        if (_optionType == OptionType.LookbackFixedStrike || _optionType == OptionType.LookbackFloatingStrike) {
            (uint256 price, bool isValid) = getAssetPrice(_underlyingToken, _quoteToken);
            if (isValid) {
                maxPrice = uint96(price);
                minPrice = uint96(price);
            }
        }

        options[optionId] = Option({
            buyer: msg.sender,
            underlyingToken: _underlyingToken,
            quoteToken: _quoteToken,
            strikePrice: _strikePrice,
            premium: uint96(netPremium),
            expiry: _optionType == OptionType.Perpetual ? 0 : _expiry,
            amount: _amount,
            isCall: _isCall,
            isAmerican: _optionType == OptionType.Perpetual ? true : _isAmerican,
            exercised: false,
            chainId: _chainId,
            cosmosChainId: _cosmosChainId,
            optionType: _optionType,
            barrierPrice: _barrierPrice,
            payout: _payout,
            lastFundingPayment: _optionType == OptionType.Perpetual ? uint64(block.timestamp) : 0,
            fundingRateBps: _fundingRateBps,
            orderBookId: orderBookId,
            triggerPrice: _triggerPrice,
            observationInterval: _observationInterval,
            observationCount: _observationCount,
            maxPrice: maxPrice,
            minPrice: minPrice
        });

        if (_optionType == OptionType.AsianAveragePrice || _optionType == OptionType.AsianAverageStrike) {
            (uint256 price, bool isValid) = getAssetPrice(_underlyingToken, _quoteToken);
            if (isValid) {
                priceObservations[optionId][0] = uint96(price);
                observationTimestamps[optionId][0] = uint64(block.timestamp);
                emit PriceObservationRecorded(optionId, 0, uint96(price), uint64(block.timestamp));
            }
        }

        userOptions[msg.sender].push(optionId);

        emit OptionCreated(
            optionId,
            msg.sender,
            _underlyingToken,
            _quoteToken,
            _strikePrice,
            netPremium,
            _optionType == OptionType.Perpetual ? 0 : _expiry,
            _isCall,
            _isAmerican,
            _chainId,
            _cosmosChainId,
            _optionType,
            _barrierPrice,
            _payout,
            _fundingRateBps,
            orderBookId,
            _triggerPrice,
            _observationInterval,
            _observationCount
        );
        emit FeeCollected(owner(), fee);

        return optionId;
    }

    // @notice Create an option using a signed order
    // @param _signedOrder Signed order data from OrderBook
    // @param _optionType Type of option
    // @param _barrierPrice Barrier price (18 decimals)
    // @param _payout Payout for binary options (6 decimals)
    // @param _fundingRateBps Funding rate in basis points
    // @param _leverage Leverage for perpetual options
    // @param _margin Margin for perpetual options
    // @param _observationInterval Observation interval for Asian options
    // @param _observationCount Number of observations for Asian options
    // @return optionId The ID of the created option
    function createOptionWithSignature(
        IOrderBook.SignedOrder calldata _signedOrder,
        OptionType _optionType,
        uint96 _barrierPrice,
        uint96 _payout,
        uint96 _fundingRateBps,
        uint256 _leverage,
        uint256 _margin,
        uint64 _observationInterval,
        uint8 _observationCount
    ) public nonReentrant whenNotPaused returns (uint256) {
        if (!kycVerified[msg.sender]) revert Unauthorized();
        if (_signedOrder.user != msg.sender) revert Unauthorized();
        if (_signedOrder.amount == 0) revert InvalidAmount();
        if (_optionType == OptionType.Perpetual) {
            if (_fundingRateBps == 0 || _leverage == 0 || _margin == 0) revert InvalidPremium();
            if (_fundingRateBps > MAX_FUNDING_RATE_BPS) revert FundingRateTooHigh();
        }
        if (_optionType == OptionType.AsianAveragePrice || _optionType == OptionType.AsianAverageStrike) {
            if (_observationInterval < MIN_OBSERVATION_INTERVAL) revert InvalidObservationInterval();
            if (_observationCount == 0 || _observationCount > MAX_OBSERVATIONS) revert InvalidObservationCount();
        }

        uint256 fee = getDynamicFee(uint256(_signedOrder.amount));
        uint256 netPremium = uint256(_signedOrder.amount) - fee;
        if (!usdc.transferFrom(msg.sender, address(this), _signedOrder.amount)) revert TransferFailed();

        uint256 orderBookId = orderBook.placeOrderWithSignature(_signedOrder);
        return createOption(
            _signedOrder.tokenA,
            _signedOrder.tokenB,
            _signedOrder.price,
            uint96(_signedOrder.amount),
            _signedOrder.expiryTimestamp,
            uint128(_signedOrder.amount),
            _signedOrder.isBuy,
            _signedOrder.isMarket,
            uint32(block.chainid),
            "",
            _optionType,
            _barrierPrice,
            _payout,
            _fundingRateBps,
            _leverage,
            _margin,
            _signedOrder.triggerPrice,
            _observationInterval,
            _observationCount
        );
    }

    // @notice Create a stop-loss option
    // @param _underlyingToken Underlying token address
    // @param _quoteToken Quote token address
    // @param _strikePrice Strike price (18 decimals)
    // @param _premium Premium (USDC, 6 decimals)
    // @param _expiry Expiry timestamp
    // @param _amount Underlying token amount (18 decimals)
    // @param _isCall True for call, false for put
    // @param _isAmerican True for American-style
    // @param _chainId Chain ID
    // @param _cosmosChainId Cosmos chain ID
    // @param _optionType Type of option
    // @param _barrierPrice Barrier price (18 decimals)
    // @param _payout Payout for binary options (6 decimals)
    // @param _fundingRateBps Funding rate in basis points
    // @param _triggerPrice Trigger price for stop-loss (18 decimals)
    // @param _leverage Leverage for perpetual options
    // @param _margin Margin for perpetual options
    // @param _observationInterval Observation interval for Asian options
    // @param _observationCount Number of observations for Asian options
    // @return optionId The ID of the created option
    function createStopLossOption(
        address _underlyingToken,
        address _quoteToken,
        uint96 _strikePrice,
        uint96 _premium,
        uint64 _expiry,
        uint128 _amount,
        bool _isCall,
        bool _isAmerican,
        uint32 _chainId,
        string calldata _cosmosChainId,
        OptionType _optionType,
        uint96 _barrierPrice,
        uint96 _payout,
        uint96 _fundingRateBps,
        uint96 _triggerPrice,
        uint256 _leverage,
        uint256 _margin,
        uint64 _observationInterval,
        uint8 _observationCount
    ) public nonReentrant whenNotPaused returns (uint256) {
        if (_triggerPrice == 0) revert InvalidBarrier();
        return createOption(
            _underlyingToken,
            _quoteToken,
            _strikePrice,
            _premium,
            _expiry,
            _amount,
            _isCall,
            _isAmerican,
            _chainId,
            _cosmosChainId,
            _optionType,
            _barrierPrice,
            _payout,
            _fundingRateBps,
            _leverage,
            _margin,
            _triggerPrice,
            _observationInterval,
            _observationCount
        );
    }

    // @notice Create a cross-chain option with OrderBook integration
    // @param _underlyingToken Underlying token address
    // @param _quoteToken Quote token address
    // @param _strikePrice Strike price (18 decimals)
    // @param _premium Premium (USDC, 6 decimals)
    // @param _expiry Expiry timestamp
    // @param _amount Underlying token amount (18 decimals)
    // @param _isCall True for call, false for put
    // @param _isAmerican True for American-style
    // @param _dstChainId Destination chain ID
    // @param _cosmosChainId Cosmos chain ID
    // @param _optionType Type of option
    // @param _barrierPrice Barrier price (18 decimals)
    // @param _payout Payout for binary options (6 decimals)
    // @param _fundingRateBps Funding rate in basis points
    // @param _triggerPrice Trigger price for stop-loss (18 decimals)
    // @param _adapterParams Adapter parameters for cross-chain
    // @param _leverage Leverage for perpetual options
    // @param _margin Margin for perpetual options
    // @param _observationInterval Observation interval for Asian options
    // @param _observationCount Number of observations for Asian options
    function createCrossChainOptionWithOrderBook(
        address _underlyingToken,
        address _quoteToken,
        uint96 _strikePrice,
        uint96 _premium,
        uint64 _expiry,
        uint128 _amount,
        bool _isCall,
        bool _isAmerican,
        uint16 _dstChainId,
        string calldata _cosmosChainId,
        OptionType _optionType,
        uint96 _barrierPrice,
        uint96 _payout,
        uint96 _fundingRateBps,
        uint96 _triggerPrice,
        bytes calldata _adapterParams,
        uint256 _leverage,
        uint256 _margin,
        uint64 _observationInterval,
        uint8 _observationCount
    ) public payable nonReentrant whenNotPaused {
        if (!kycVerified[msg.sender]) revert Unauthorized();
        if (_dstChainId == block.chainid && bytes(_cosmosChainId).length == 0) revert NotSameChain();
        uint256 optionId = createOption(
            _underlyingToken,
            _quoteToken,
            _strikePrice,
            _premium,
            _expiry,
            _amount,
            _isCall,
            _isAmerican,
            uint32(_dstChainId),
            _cosmosChainId,
            _optionType,
            _barrierPrice,
            _payout,
            _fundingRateBps,
            _leverage,
            _margin,
            _triggerPrice,
            _observationInterval,
            _observationCount
        );

        uint256 orderBookId = orderBook.placeOrderCrossChain(
            _isCall,
            true,
            _triggerPrice > 0,
            _strikePrice,
            _triggerPrice,
            uint96(_amount),
            _underlyingToken,
            _quoteToken,
            _expiry,
            false,
            _dstChainId,
            _adapterParams
        );

        bytes memory payload = abi.encode(
            optionId,
            _premium,
            _dstChainId,
            _cosmosChainId,
            _optionType,
            _barrierPrice,
            _payout,
            _fundingRateBps,
            _leverage,
            _margin,
            _triggerPrice,
            _observationInterval,
            _observationCount
        );
        (uint256 nativeFee, ) = crossChainModule.getEstimatedCrossChainFee(_dstChainId, payload, _adapterParams);
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        crossChainModule.receiveMessage(_dstChainId, abi.encode(address(this)), payload, _adapterParams);
        if (msg.value > nativeFee) {
            (bool success, ) = msg.sender.call{value: msg.value - nativeFee}("");
            if (!success) revert TransferFailed();
        }
        emit CrossChainMessageSent(optionId, _dstChainId, payload, nativeFee);
    }

    // @notice Record price observation for Asian options
    // @param _optionId Option ID
    function recordPriceObservation(uint256 _optionId) public nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender && msg.sender != owner()) revert NotOptionOwner();
        if (option.optionType != OptionType.AsianAveragePrice && option.optionType != OptionType.AsianAverageStrike) revert InvalidOptionType();
        if (option.exercised) revert OptionExercised();
        if (block.timestamp > option.expiry) revert OptionExpired();

        uint256 currentIndex;
        uint256 count = option.observationCount;
        for (uint256 i = 0; i < count; ) {
            if (observationTimestamps[_optionId][i] == 0) {
                currentIndex = i;
                break;
            }
            if (i == count - 1) revert ObservationLimitExceeded();
            unchecked { i++; }
        }

        if (currentIndex > 0 && block.timestamp < observationTimestamps[_optionId][currentIndex - 1] + option.observationInterval) {
            revert InvalidObservationInterval();
        }

        (uint256 price, bool isValid) = getAssetPrice(option.underlyingToken, option.quoteToken);
        if (!isValid) revert InvalidPrice();

        priceObservations[_optionId][currentIndex] = uint96(price);
        observationTimestamps[_optionId][currentIndex] = uint64(block.timestamp);
        emit PriceObservationRecorded(_optionId, currentIndex, uint96(price), uint64(block.timestamp));
    }

    // @notice Update max/min prices for Lookback options
    // @param _optionId Option ID
    function updateLookbackPrices(uint256 _optionId) public nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender && msg.sender != owner()) revert NotOptionOwner();
        if (option.optionType != OptionType.LookbackFixedStrike && option.optionType != OptionType.LookbackFloatingStrike) revert InvalidOptionType();
        if (option.exercised) revert OptionExercised();
        if (block.timestamp > option.expiry && option.expiry != 0) revert OptionExpired();

        (uint256 price, bool isValid) = getAssetPrice(option.underlyingToken, option.quoteToken);
        if (!isValid) revert InvalidPrice();

        if (uint96(price) > option.maxPrice) {
            option.maxPrice = uint96(price);
        }
        if (uint96(price) < option.minPrice) {
            option.minPrice = uint96(price);
        }
        emit LookbackPriceUpdated(_optionId, option.maxPrice, option.minPrice);
    }

    // @notice Provide liquidity to OrderBook AMM pool
    // @param _tokenA First token address
    // @param _tokenB Second token address
    // @param _amountA Amount of token A (18 decimals)
    // @param _amountB Amount of token B (18 decimals)
    function provideLiquidity(address _tokenA, address _tokenB, uint256 _amountA, uint256 _amountB) public nonReentrant whenNotPaused {
        if (_amountA == 0 || _amountB == 0) revert InvalidAmount();
        if (!IERC20(_tokenA).transferFrom(msg.sender, address(orderBook), _amountA)) revert TransferFailed();
        if (!IERC20(_tokenB).transferFrom(msg.sender, address(orderBook), _amountB)) revert TransferFailed();
        orderBook.setLiquidityRange(_amountA, _amountB);
        emit LiquidityProvided(msg.sender, _tokenA, _tokenB, _amountA, _amountB);
    }

    // @notice Propose parameter change via OrderBook governance
    // @param _paramName Parameter name
    // @param _value New value
    function proposeParameterChange(string memory _paramName, uint256 _value) public onlyOwner {
        orderBook.createProposal(
            string(abi.encodePacked("Update CryptoOptions ", _paramName)),
            IOrderBook.ProposalType.ParameterChange,
            abi.encode(_paramName, _value)
        );
        emit ParameterProposed(_paramName, _value);
    }

    // @notice Pay funding rate for perpetual options
    // @param _optionId Option ID
    function payFundingRate(uint256 _optionId) public nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender) revert NotOptionOwner();
        if (option.optionType != OptionType.Perpetual) revert InvalidOptionType();
        if (option.exercised) revert OptionExercised();
        if (block.timestamp < option.lastFundingPayment + fundingInterval) revert FundingRateNotPaid();

        uint256 fundingAmount = (option.premium * option.fundingRateBps) / BPS_DENOMINATOR;
        if (!usdc.transferFrom(msg.sender, address(this), fundingAmount)) revert TransferFailed();

        option.lastFundingPayment = uint64(block.timestamp);
        collectedFundingFees += fundingAmount;

        orderBook.applyFunding(option.orderBookId);
        emit FundingRatePaid(_optionId, msg.sender, fundingAmount);
    }

    // @notice Exercise an option
    // @param _optionId Option ID
    function exerciseOption(uint256 _optionId) public payable nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender) revert NotOptionOwner();
        if (option.exercised) revert OptionExercised();
        if (option.optionType != OptionType.Perpetual && block.timestamp > option.expiry) revert OptionExpired();
        if (option.optionType != OptionType.Perpetual && !option.isAmerican && block.timestamp != option.expiry) revert OptionExpired();
        if (option.optionType == OptionType.Perpetual && block.timestamp >= option.lastFundingPayment + fundingInterval) revert FundingRateNotPaid();

        if (option.optionType == OptionType.BarrierKnockIn || option.optionType == OptionType.BarrierKnockOut) {
            (uint256 price, bool isValid) = getAssetPrice(option.underlyingToken, option.quoteToken);
            if (!isValid) revert InvalidPrice();
            if (option.optionType == OptionType.BarrierKnockIn && price < option.barrierPrice) revert BarrierNotMet();
            if (option.optionType == OptionType.BarrierKnockOut && price >= option.barrierPrice) revert BarrierNotMet();
        }

        uint256 price;
        bool isValid;
        if (option.optionType == OptionType.AsianAveragePrice || option.optionType == OptionType.AsianAverageStrike) {
            price = calculateAveragePrice(_optionId);
            isValid = price > 0;
        } else if (option.optionType == OptionType.LookbackFixedStrike || option.optionType == OptionType.LookbackFloatingStrike) {
            price = option.isCall ? option.maxPrice : option.minPrice;
            isValid = price > 0;
        } else {
            (price, isValid) = getAssetPrice(option.underlyingToken, option.quoteToken);
        }
        if (!isValid) revert InvalidPrice();

        uint256 profit;
        if (option.optionType == OptionType.Binary) {
            if (option.isCall && price <= option.strikePrice) revert NotInTheMoney();
            if (!option.isCall && price >= option.strikePrice) revert NotInTheMoney();
            profit = option.payout;
        } else if (option.optionType == OptionType.AsianAverageStrike) {
            uint96 effectiveStrike = uint96(price);
            if (option.isCall && price <= effectiveStrike) revert NotInTheMoney();
            if (!option.isCall && price >= effectiveStrike) revert NotInTheMoney();
            profit = option.isCall
                ? (price - effectiveStrike) * option.amount / 1e18
                : (effectiveStrike - price) * option.amount / 1e18;
        } else if (option.optionType == OptionType.LookbackFloatingStrike) {
            uint96 effectiveStrike = option.isCall ? option.minPrice : option.maxPrice;
            if (option.isCall && price <= effectiveStrike) revert NotInTheMoney();
            if (!option.isCall && price >= effectiveStrike) revert NotInTheMoney();
            profit = option.isCall
                ? (price - effectiveStrike) * option.amount / 1e18
                : (effectiveStrike - price) * option.amount / 1e18;
        } else {
            if (option.isCall && price <= option.strikePrice) revert NotInTheMoney();
            if (!option.isCall && price >= option.strikePrice) revert NotInTheMoney();
            profit = option.isCall
                ? (price - option.strikePrice) * option.amount / 1e18
                : (option.strikePrice - price) * option.amount / 1e18;
        }

        if (option.optionType == OptionType.Perpetual) {
            orderBook.liquidatePosition(option.orderBookId);
        } else {
            orderBook.placeOrder(
                option.isCall,
                true,
                option.triggerPrice > 0,
                option.strikePrice,
                option.triggerPrice,
                uint96(option.amount),
                option.underlyingToken,
                option.quoteToken,
                0,
                false
            );
        }

        if (bytes(option.cosmosChainId).length > 0 || option.chainId != block.chainid) {
            bytes memory adapterParams = new bytes(0);
            (uint256 nativeFee, ) = crossChainModule.getEstimatedCrossChainFee(uint16(option.chainId), "", adapterParams);
            if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

            uint256 amountOut = crossChainModule.swapCrossChain{value: nativeFee}(
                msg.sender,
                address(usdc),
                profit,
                profit,
                uint16(option.chainId),
                adapterParams
            );
            if (amountOut < profit) revert TransferFailed();
            if (msg.value > nativeFee) {
                (bool success, ) = msg.sender.call{value: msg.value - nativeFee}("");
                if (!success) revert TransferFailed();
            }
        } else {
            if (!usdc.transfer(msg.sender, profit)) revert TransferFailed();
        }

        option.exercised = true;
        emit OptionExercised(_optionId, msg.sender, profit);
    }

    // @notice Refund expired, unexercised options
    // @param _optionId Option ID
    function refundExpiredOption(uint256 _optionId) public payable nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender) revert NotOptionOwner();
        if (option.optionType != OptionType.Perpetual && block.timestamp <= option.expiry) revert OptionExpired();
        if (option.exercised) revert OptionExercised();

        uint256 refund = option.premium;
        option.exercised = true;

        if (option.optionType == OptionType.Perpetual) {
            orderBook.liquidatePosition(option.orderBookId);
        }

        if (bytes(option.cosmosChainId).length > 0 || option.chainId != block.chainid) {
            bytes memory adapterParams = new bytes(0);
            (uint256 nativeFee, ) = crossChainModule.getEstimatedCrossChainFee(uint16(option.chainId), "", adapterParams);
            if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

            uint256 amountOut = crossChainModule.swapCrossChain{value: nativeFee}(
                msg.sender,
                address(usdc),
                refund,
                refund,
                uint16(option.chainId),
                adapterParams
            );
            if (amountOut < refund) revert TransferFailed();
            if (msg.value > nativeFee) {
                (bool success, ) = msg.sender.call{value: msg.value - nativeFee}("");
                if (!success) revert TransferFailed();
            }
        } else {
            if (!usdc.transfer(msg.sender, refund)) revert TransferFailed();
        }
    }

    // @notice Receive cross-chain messages
    // @param _srcChainId Source chain ID
    // @param _srcAddress Source address
    // @param _payload Message payload
    // @param _additionalParams Additional parameters
    function receiveCrossChainMessage(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        bytes calldata _payload,
        bytes calldata _additionalParams
    ) external nonReentrant whenNotPaused {
        if (msg.sender != address(crossChainModule)) revert Unauthorized();
        (uint256 optionId, , , , , , , , , , , , ) = abi.decode(
            _payload,
            (uint256, uint96, uint16, string, OptionType, uint96, uint96, uint96, uint256, uint256, uint96, uint64, uint8)
        );
        crossChainModule.receiveMessage(_srcChainId, _srcAddress, _payload, _additionalParams);
        emit CrossChainMessageReceived(optionId, _srcChainId, _payload);
    }

    // @notice Get dynamic fee based on OrderBook fee tiers
    // @param _premium Premium amount (6 decimals)
    // @return fee The calculated fee (6 decimals)
    function getDynamicFee(uint256 _premium) public view returns (uint256) {
        IOrderBook.FeeTier[] memory tiers = orderBook.getFeeTiers();
        if (tiers.length == 0) revert InvalidFeeTier();
        uint256 feeRate = tiers[0].feeRateBps;
        uint256 len = tiers.length;
        for (uint256 i = 1; i < len; ) {
            if (_premium >= tiers[i].orderSizeThreshold) {
                feeRate = tiers[i].feeRateBps;
            }
            unchecked { i++; }
        }
        return (_premium * feeRate) / BPS_DENOMINATOR;
    }

    // @notice Calculate average price for Asian options
    // @param _optionId Option ID
    // @return averagePrice The calculated average price (18 decimals)
    function calculateAveragePrice(uint256 _optionId) internal view returns (uint256) {
        Option storage option = options[_optionId];
        if (option.optionType != OptionType.AsianAveragePrice && option.optionType != OptionType.AsianAverageStrike) {
            return 0;
        }

        uint256 totalPrice;
        uint256 validObservations;
        uint256 count = option.observationCount;
        for (uint256 i = 0; i < count; ) {
            if (observationTimestamps[_optionId][i] > 0) {
                totalPrice += priceObservations[_optionId][i];
                validObservations++;
            }
            unchecked { i++; }
        }
        return validObservations == 0 ? 0 : totalPrice / validObservations;
    }

    // @notice Get asset price from OrderBook, Chainlink, or Band
    // @param _underlyingToken Underlying token
    // @param _quoteToken Quote token
    // @return price The asset price (18 decimals)
    // @return isValid Whether the price is valid
    function getAssetPrice(address _underlyingToken, address _quoteToken) internal view returns (uint256 price, bool isValid) {
        uint256 obPrice = orderBook.getAggregatedPrice(_underlyingToken, _quoteToken);
        if (obPrice > 0 && obPrice < type(uint96).max) {
            return (obPrice * 1e12, true); // Normalize to 18 decimals (assuming 6 decimals)
        }

        AggregatorV3Interface oracle = chainlinkOracles[_underlyingToken];
        if (address(oracle) != address(0)) {
            (, int256 answer, , uint256 updatedAt, ) = oracle.latestRoundData();
            if (answer > 0 && block.timestamp <= updatedAt + timeout && uint256(answer) < type(uint96).max) {
                return (uint256(answer) * 1e10, true); // Normalize to 18 decimals (assuming 8 decimals)
            }
        }

        (uint256 bandPrice, bool bandValid) = getBandPrice(_underlyingToken);
        if (bandValid && bandPrice < type(uint96).max) {
            return (bandPrice * 1e12, true); // Normalize to 18 decimals (assuming 6 decimals)
        }

        return (0, false);
    }

    // @notice Get price from Band Protocol
    // @param _token Token address
    // @return price The asset price (18 decimals)
    // @return isValid Whether the price is valid
    function getBandPrice(address _token) internal view returns (uint256 price, bool isValid) {
        string memory pair = getTokenPair(_token);
        if (bytes(pair).length == 0) return (0, false);
        (uint256 rate, uint256 updatedAt) = bandOracle.getReferenceData(pair);
        if (rate > 0 && block.timestamp <= updatedAt + timeout) {
            return (rate, true);
        }
        return (0, false);
    }

    // @notice Map token to price feed pair
    // @param _token Token address
    // @return pair The price feed pair
    function getTokenPair(address _token) internal pure returns (string memory) {
        if (_token = "0x2260FAC5E1a373473335eF271974C34F6fB7A693") return "BTC/USD";
        if (_token = "0x2170Ed0881dB1171A4A0d5A0A0B8c4860A9fB6F7") return "ETH/USD";
        if (_token = "0x1234567890abcdef1234567890abcdef12345678") return "BRETT/USD";
        return "";
    }

    // @notice Deposit liquidity rewards for AMM pools
    // @param _token Token address
    // @param _amount Amount to deposit (18 decimals)
    function depositLiquidityReward(address _token, uint256 _amount) public onlyOwner whenNotPaused {
        if (!IERC20(_token).transferFrom(msg.sender, address(this), _amount)) revert TransferFailed();
        emit LiquidityRewardDeposited(_token, _amount);
    }

    // @notice Distribute collected funding fees to liquidity providers
    // @param _recipient Recipient address
    // @param _amount Amount to distribute (6 decimals)
    function distributeFundingFees(address _recipient, uint256 _amount) public onlyOwner whenNotPaused {
        if (_amount > collectedFundingFees) revert InvalidAmount();
        if (!usdc.transfer(_recipient, _amount)) revert TransferFailed();
        collectedFundingFees -= _amount;
    }

    // @notice Set Chainlink oracle for a token
    // @param _token Token address
    // @param _oracle Oracle address
    function setChainlinkOracle(address _token, address _oracle) public onlyOwner {
        chainlinkOracles[_token] = AggregatorV3Interface(_oracle);
    }

    // @notice Set KYC status for a user
    // @param _user User address
    // @param _status KYC status
    function setKycVerified(address _user, bool _status) public onlyOwner {
        kycVerified[_user] = _status;
    }

    // @notice Update OrderBook address
    // @param _newOrderBook New OrderBook address
    function updateOrderBook(address _newOrderBook) public onlyOwner {
        if (_newOrderBook == address(0)) revert InvalidProtocol();
        orderBook = IOrderBook(_newOrderBook);
        emit OrderBookUpdated(_newOrderBook);
    }

    // @notice Update CrossChainModule address
    // @param _newCrossChainModule New CrossChainModule address
    function updateCrossChainModule(address _newCrossChainModule) public onlyOwner {
        if (_newCrossChainModule == address(0)) revert InvalidProtocol();
        crossChainModule = ICrossChainModule(_newCrossChainModule);
        emit CrossChainModuleUpdated(_newCrossChainModule);
    }

    // @notice Update fee in basis points
    // @param _newFeeBps New fee in basis points
    function updateFeeBps(uint256 _newFeeBps) public onlyOwner {
        if (_newFeeBps > 1000) revert InvalidAmount(); // Max 10%
        feeBps = _newFeeBps;
        emit FeeBpsUpdated(_newFeeBps);
    }

    // @notice Update timeout for price staleness
    // @param _newTimeout New timeout in seconds
    function updateTimeout(uint256 _newTimeout) public onlyOwner {
        if (_newTimeout < 30 minutes || _newTimeout > 24 hours) revert InvalidAmount();
        timeout = _newTimeout;
        emit TimeoutUpdated(_newTimeout);
    }

    // @notice Update funding interval for perpetual options
    // @param _newFundingInterval New funding interval in seconds
    function updateFundingInterval(uint256 _newFundingInterval) public onlyOwner {
        if (_newFundingInterval < 1 hours || _newFundingInterval > 24 hours) revert InvalidAmount();
        fundingInterval = _newFundingInterval;
        emit FundingIntervalUpdated(_newFundingInterval);
    }

    // @notice Pause contract operations
    function pause() public onlyOwner {
        _pause();
        emit Paused(msg.sender);
    }

    // @notice Unpause contract operations
    function unpause() public onlyOwner {
        _unpause();
        emit Unpaused(msg.sender);
    }

    // @notice Get user's options
    // @param _user User address
    // @return Array of option IDs
    function getUserOptions(address _user) public view returns (uint256[] memory) {
        return userOptions[_user];
    }
}
