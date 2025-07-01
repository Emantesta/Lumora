// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.2/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.2/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.2/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import "@chainlink/contracts@1.2.0/src/v0.8/interfaces/AggregatorV3Interface.sol";

// Interface for Band Protocol (fallback oracle)
interface IBandProtocol {
    function getReferenceData(string memory pair) external view returns (uint256, uint256);
}

// Interface for CLOB-AMM DEX (e.g., Osmosis-compatible)
interface ICLobAmmDex {
    function getPrice(address token, uint256 amount) external view returns (uint256);
    function executeTrade(address token, uint256 amount, bool isBuy) external returns (bool);
}

// Interface for Injective Protocol
interface IInjectiveProtocol {
    function getOrderBookPrice(address token) external view returns (uint256);
    function executeOrder(address token, uint256 amount, bool isBuy, uint256 chainId, string calldata cosmosChainId) external returns (bool);
}

// Interface for cross-chain protocols (CCIP, LayerZero, Wormhole, Axelar)
interface ICrossChainProtocol {
    function transferToken(address token, address recipient, uint256 amount, uint256 chainId) external returns (bytes32);
    function sendMessage(address receiver, bytes calldata data, uint256 chainId) external returns (bytes32);
    function receiveToken(address token, uint256 amount, bytes32 messageId) external;
}

// Interface for Cosmos IBC
interface IIbcProtocol {
    function sendPacket(bytes32 channelId, bytes calldata data, uint64 timeoutTimestamp) external returns (bytes32);
    function transferToken(address token, address recipient, uint256 amount, string calldata destinationChain) external returns (bytes32);
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
error InvalidChannel();
error InvalidBarrier();
error BarrierNotMet();
error FundingRateNotPaid();
error InvalidOptionType();

// @title CryptoOptions - Upgradeable options trading contract on Sonic Blockchain
// @notice Supports standard, barrier, binary, and perpetual options with cross-chain messaging
// @dev Uses IBC and Injective for Cosmos chains, CCIP as primary for non-Cosmos, with LayerZero, Wormhole, Axelar as fallbacks
// @custom:version 1.1.0
contract CryptoOptions is Initializable, UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    // @notice Enum for option types
    enum OptionType { Standard, BarrierKnockIn, BarrierKnockOut, Binary, Perpetual }

    // @notice Struct for an option contract
    struct Option {
        address buyer; // Option owner
        address underlyingToken; // e.g., wBTC, ETH, $ავ

        uint96 strikePrice; // in USDC (6 decimals)
        uint96 premium; // in USDC
        uint64 expiry; // timestamp (0 for perpetual options)
        uint128 amount; // underlying token amount (e.g., 0.1 BTC in wei)
        bool isCall; // true for call, false for put
        bool isAmerican; // true for American-style (ignored for perpetual/binary)
        bool exercised; // true if exercised
        uint32 chainId; // for non-Cosmos chains
        string cosmosChainId; // for Cosmos chains
        OptionType optionType; // Option type
        uint96 barrierPrice; // Barrier price for barrier options (0 if not applicable)
        uint96 payout; // Fixed payout for binary options (0 if not applicable)
        uint64 lastFundingPayment; // Last funding rate payment timestamp for perpetual options
        uint96 fundingRateBps; // Funding rate in basis points for perpetual options
    }

    // State variables
    mapping(uint256 => Option) public options; //彼此

    uint256 public optionCounter; // Tracks option IDs
    IERC20 public usdc; // USDC for premiums/settlement
    ICLobAmmDex public dex; // CLOB-AMM DEX (Osmosis-compatible)
    IBandProtocol public bandOracle; // Fallback oracle
    IInjectiveProtocol public injective; // Injective Protocol
    mapping(address => AggregatorV3Interface) public chainlinkOracles; // Token to Chainlink feed
    mapping(address => uint256[]) public userOptions; // User-owned options
    mapping(address => bool) public kycVerified; // KYC status
    mapping(uint256 => address) public protocolPriority; // Protocol priority (0: IBC, 1: Injective, 2: CCIP, 3: LayerZero, 4: Wormhole, 5: Axelar)
    bytes32 public ibcChannel; // IBC channel for Cosmos chains
    uint256 public constant FEE_BPS = 5; // 0.05% fee (5 basis points)
    uint256 public constant BPS_DENOMINATOR = 10000; // Basis points
    uint256 public constant TIMEOUT = 1 hours; // Timeout for in-flight messages
    uint256 public constant FUNDING_INTERVAL = 8 hours; // Funding rate payment interval
    uint256 public collectedFundingFees; // Accumulated funding fees for perpetual options

    // Events
    event OptionCreated(
        uint256 indexed optionId,
        address indexed buyer,
        address underlyingToken,
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
        uint256 fundingRateBps
    );
    event OptionExercised(uint256 indexed optionId, address indexed buyer, uint256 profit);
    event FeeCollected(address indexed recipient, uint256 fee);
    event LiquidityRewardDeposited(address indexed token, uint256 amount);
    event Paused(address indexed owner);
    event Unpaused(address indexed owner);
    event ProtocolUpdated(uint256 indexed priority, address indexed protocol);
    event IbcChannelUpdated(bytes32 indexed channelId);
    event InjectiveUpdated(address indexed injective);
    event FundingRatePaid(uint256 indexed optionId, address indexed buyer, uint256 amount);

    // @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // @notice Initialize the contract
    function initialize(
        address _usdc,
        address _ibc,
        address _injective,
        address _ccip,
        address _layerZero,
        address _wormhole,
        address _axelar,
        address _dex,
        address _bandOracle,
        bytes32 _ibcChannel
    ) external initializer {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        __Pausable_init();
        usdc = IERC20(_usdc);
        protocolPriority[0] = _ibc;
        protocolPriority[1] = _injective;
        protocolPriority[2] = _ccip;
        protocolPriority[3] = _layerZero;
        protocolPriority[4] = _wormhole;
        protocolPriority[5] = _axelar;
        dex = ICLobAmmDex(_dex);
        bandOracle = IBandProtocol(_bandOracle);
        injective = IInjectiveProtocol(_injective);
        ibcChannel = _ibcChannel;
    }

    // @notice Authorize upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // @notice Create a new option
    function createOption(
        address _underlyingToken,
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
        uint96 _fundingRateBps
    ) public nonReentrant whenNotPaused returns (uint256) {
        if (_optionType != OptionType.Perpetual && _expiry <= block.timestamp) revert InvalidExpiry();
        if (_amount == 0) revert InvalidAmount();
        if (_premium == 0) revert InvalidPremium();
        if (_optionType == OptionType.BarrierKnockIn || _optionType == OptionType.BarrierKnockOut) {
            if (_barrierPrice == 0) revert InvalidBarrier();
        }
        if (_optionType == OptionType.Binary && _payout == 0) revert InvalidPremium();
        if (_optionType == OptionType.Perpetual && _fundingRateBps == 0) revert InvalidPremium();
        if (!kycVerified[msg.sender] && _chainId == block.chainid && bytes(_cosmosChainId).length == 0) revert Unauthorized();

        // Transfer premium with fee
        uint256 fee = (_premium * FEE_BPS) / BPS_DENOMINATOR;
        uint256 netPremium = _premium - fee;
        if (!usdc.transferFrom(msg.sender, address(this), _premium)) revert TransferFailed();

        // Create option
        optionCounter++;
        options[optionCounter] = Option({
            buyer: msg.sender,
            underlyingToken: _underlyingToken,
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
            fundingRateBps: _fundingRateBps
        });

        userOptions[msg.sender].push(optionCounter);

        emit OptionCreated(
            optionCounter,
            msg.sender,
            _underlyingToken,
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
            _fundingRateBps
        );
        emit FeeCollected(owner(), fee);

        return optionCounter;
    }

    // @notice Pay funding rate for perpetual options
    function payFundingRate(uint256 _optionId) public nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender) revert NotOptionOwner();
        if (option.optionType != OptionType.Perpetual) revert InvalidOptionType();
        if (option.exercised) revert OptionExercised();
        if (block.timestamp < option.lastFundingPayment + FUNDING_INTERVAL) revert FundingRateNotPaid();

        uint256 fundingAmount = (option.premium * option.fundingRateBps) / BPS_DENOMINATOR;
        if (!usdc.transferFrom(msg.sender, address(this), fundingAmount)) revert TransferFailed();

        option.lastFundingPayment = uint64(block.timestamp);
        collectedFundingFees += fundingAmount;

        emit FundingRatePaid(_optionId, msg.sender, fundingAmount);
    }

    // @notice Exercise an option
    function exerciseOption(uint256 _optionId) public nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender) revert NotOptionOwner();
        if (option.exercised) revert OptionExercised();
        if (option.optionType != OptionType.Perpetual && block.timestamp > option.expiry) revert OptionExpired();
        if (option.optionType != OptionType.Perpetual && !option.isAmerican && block.timestamp != option.expiry) revert OptionExpired();
        if (option.optionType == OptionType.Perpetual && block.timestamp >= option.lastFundingPayment + FUNDING_INTERVAL) revert FundingRateNotPaid();

        // Check barrier conditions for barrier options
        if (option.optionType == OptionType.BarrierKnockIn || option.optionType == OptionType.BarrierKnockOut) {
            (uint256 price, bool isValid) = getAssetPrice(option.underlyingToken);
            if (!isValid) revert InvalidPrice();
            if (option.optionType == OptionType.BarrierKnockIn && price < option.barrierPrice) revert BarrierNotMet();
            if (option.optionType == OptionType.BarrierKnockOut && price >= option.barrierPrice) revert BarrierNotMet();
        }

        // Get price for standard, barrier, or perpetual options
        (uint256 price, bool isValid) = getAssetPrice(option.underlyingToken);
        if (!isValid) revert InvalidPrice();

        uint256 profit;
        if (option.optionType == OptionType.Binary) {
            if (option.isCall && price <= option.strikePrice) revert NotInTheMoney();
            if (!option.isCall && price >= option.strikePrice) revert NotInTheMoney();
            profit = option.payout;
        } else {
            if (option.isCall && price <= option.strikePrice) revert NotInTheMoney();
            if (!option.isCall && price >= option.strikePrice) revert NotInTheMoney();
            profit = option.isCall
                ? (price - option.strikePrice) * option.amount / 1e6
                : (option.strikePrice - price) * option.amount / 1e6;
        }

        // Execute trade on Injective for Cosmos chains, else DEX
        bool tradeSuccess;
        if (bytes(option.cosmosChainId).length > 0) {
            tradeSuccess = injective.executeOrder(option.underlyingToken, option.amount, option.isCall, option.chainId, option.cosmosChainId);
        } else {
            tradeSuccess = dex.executeTrade(option.underlyingToken, option.amount, option.isCall);
        }
        if (!tradeSuccess) revert TransferFailed();

        // Settle profit via cross-chain protocol
        if (bytes(option.cosmosChainId).length > 0) {
            if (!tryIbcTransfer(address(usdc), msg.sender, profit, option.cosmosChainId)) revert TransferFailed();
        } else {
            if (!tryCrossChainTransfer(address(usdc), msg.sender, profit, option.chainId)) revert TransferFailed();
        }

        option.exercised = true;
        emit OptionExercised(_optionId, msg.sender, profit);
    }

    // @notice Create a cross-chain option
    function createCrossChainOption(
        address _underlyingToken,
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
        uint96 _fundingRateBps
    ) public nonReentrant whenNotPaused {
        if (_chainId == block.chainid && bytes(_cosmosChainId).length == 0) revert NotSameChain();
        uint256 optionId = createOption(
            _underlyingToken,
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
            _fundingRateBps
        );
        bytes memory data = abi.encode(optionId, _premium, _chainId, _cosmosChainId, _optionType, _barrierPrice, _payout, _fundingRateBps);
        if (bytes(_cosmosChainId).length > 0) {
            if (!tryIbcMessage(address(this), data, _cosmosChainId)) revert MessageFailed();
        } else {
            if (!tryCrossChainMessage(address(this), data, _chainId)) revert MessageFailed();
        }
    }

    // @notice Refund expired, unexercised options
    function refundExpiredOption(uint256 _optionId) public nonReentrant whenNotPaused {
        Option storage option = options[_optionId];
        if (option.buyer != msg.sender) revert NotOptionOwner();
        if (option.optionType != OptionType.Perpetual && block.timestamp <= option.expiry) revert OptionExpired();
        if (option.exercised) revert OptionExercised();

        uint256 refund = option.premium;
        option.exercised = true;
        if (bytes(option.cosmosChainId).length > 0) {
            if (!tryIbcTransfer(address(usdc), msg.sender, refund, option.cosmosChainId)) revert TransferFailed();
        } else {
            if (!tryCrossChainTransfer(address(usdc), msg.sender, refund, option.chainId)) revert TransferFailed();
        }
    }

    // @notice Try IBC transfer for Cosmos chains
    function tryIbcTransfer(
        address _token,
        address _recipient,
        uint256 _amount,
        string memory _destinationChain
    ) internal returns (bool) {
        address ibc = protocolPriority[0];
        if (ibc == address(0)) return false;
        try IIbcProtocol(ibc).transferToken(_token, _recipient, _amount, _destinationChain) returns (bytes32) {
            return true;
        } catch {
            return false;
        }
    }

    // @notice Try IBC message for Cosmos chains
    function tryIbcMessage(
        address _receiver,
        bytes memory _data,
        string memory _destinationChain
    ) internal returns (bool) {
        address ibc = protocolPriority[0];
        if (ibc == address(0)) return false;
        try IIbcProtocol(ibc).sendPacket(ibcChannel, _data, uint64(block.timestamp + TIMEOUT)) returns (bytes32) {
            return true;
        } catch {
            return false;
        }
    }

    // @notice Try cross-chain transfer with protocol fallback (non-Cosmos)
    function tryCrossChainTransfer(
        address _token,
        address _recipient,
        uint256 _amount,
        uint256 _chainId
    ) internal returns (bool) {
        for (uint256 i = 2; i < 6; i++) {
            address protocol = protocolPriority[i];
            if (protocol == address(0)) continue;
            try ICrossChainProtocol(protocol).transferToken(_token, _recipient, _amount, _chainId) returns (bytes32) {
                return true;
            } catch {
                continue;
            }
        }
        return false;
    }

    // @notice Try cross-chain message with protocol fallback (non-Cosmos)
    function tryCrossChainMessage(
        address _receiver,
        bytes memory _data,
        uint256 _chainId
    ) internal returns (bool) {
        for (uint256 i = 2; i < 6; i++) {
            address protocol = protocolPriority[i];
            if (protocol == address(0)) continue;
            try ICrossChainProtocol(protocol).sendMessage(_receiver, _data, _chainId) returns (bytes32) {
                return true;
            } catch {
                continue;
            }
        }
        return false;
    }

    // @notice Get asset price from Injective, Chainlink, or Band
    function getAssetPrice(address _token) internal view returns (uint256 price, bool isValid) {
        // Try Injective first
        address inj = protocolPriority[1];
        if (inj != address(0)) {
            try IInjectiveProtocol(inj).getOrderBookPrice(_token) returns (uint256 injPrice) {
                if (injPrice > 0) return (injPrice, true);
            } catch {
                // Fallback to Chainlink or Band
            }
        }
        // Chainlink
        AggregatorV3Interface oracle = chainlinkOracles[_token];
        if (address(oracle) != address(0)) {
            (, int256 answer, , uint256 updatedAt, ) = oracle.latestRoundData();
            if (answer > 0 && block.timestamp <= updatedAt + 1 hours) {
                return (uint256(answer), true);
            }
        }
        // Band
        return getBandPrice(_token);
    }

    // @notice Get price from Band Protocol
    function getBandPrice(address _token) internal view returns (uint256 price, bool isValid) {
        string memory pair = getTokenPair(_token);
        if (bytes(pair).length == 0) return (0, false);
        (uint256 rate, uint256 updatedAt) = bandOracle.getReferenceData(pair);
        if (rate > 0 && block.timestamp <= updatedAt + 1 hours) {
            return (rate, true);
        }
        return (0, false);
    }

    // @notice Map token to price feed pair
    function getTokenPair(address _token) internal pure returns (string memory) {
        if (_token == 0x2260FAC5E1a373473335eF271974C34F6fB7A693) return "BTC/USD";
        if (_token == 0x2170Ed0881dB1171A4A0d5A0A0B8c4860A9fB6F7) return "ETH/USD";
        if (_token == 0x1234567890abcdef1234567890abcdef12345678) return "BRETT/USD";
        return "";
    }

    // @notice Deposit liquidity rewards for AMM pools
    function depositLiquidityReward(address _token, uint256 _amount) public onlyOwner whenNotPaused {
        if (!IERC20(_token).transferFrom(msg.sender, address(dex), _amount)) revert TransferFailed();
        emit LiquidityRewardDeposited(_token, _amount);
    }

    // @notice Distribute collected funding fees to liquidity providers
    function distributeFundingFees(address _recipient, uint256 _amount) public onlyOwner whenNotPaused {
        if (_amount > collectedFundingFees) revert InvalidAmount();
        if (!usdc.transfer(_recipient, _amount)) revert TransferFailed();
        collectedFundingFees -= _amount;
    }

    // @notice Set Chainlink oracle for a token
    function setChainlinkOracle(address _token, address _oracle) public onlyOwner {
        chainlinkOracles[_token] = AggregatorV3Interface(_oracle);
    }

    // @notice Set KYC status for a user
    function setKycVerified(address _user, bool _status) public onlyOwner {
        kycVerified[_user] = _status;
    }

    // @notice Update DEX address
    function updateDexAddress(address _newDex) public onlyOwner {
        dex = ICLobAmmDex(_newDex);
    }

    // @notice Update cross-chain protocol
    function updateProtocol(uint256 _priority, address _protocol) public onlyOwner {
        if (_priority > 5) revert InvalidProtocol();
        protocolPriority[_priority] = _protocol;
        emit ProtocolUpdated(_priority, _protocol);
    }

    // @notice Update IBC channel
    function updateIbcChannel(bytes32 _channelId) public onlyOwner {
        if (_channelId == bytes32(0)) revert InvalidChannel();
        ibcChannel = _channelId;
        emit IbcChannelUpdated(_channelId);
    }

    // @notice Update Injective Protocol address
    function updateInjective(address _injective) public onlyOwner {
        injective = IInjectiveProtocol(_injective);
        emit InjectiveUpdated(_injective);
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
    function getUserOptions(address _user) public view returns (uint256[] memory) {
        return userOptions[_user];
    }
}
