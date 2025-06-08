// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AMMPool.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

/// @title PoolFactory - An upgradeable factory for deploying AMM pools with CREATE2
/// @notice Creates and manages AMM pools with deterministic addresses, cross-chain support, and enhanced governance
/// @dev Uses UUPS upgradeability, ReentrancyGuard, and Chainlink or PriceOracle for secure pool deployment
contract PoolFactory is Initializable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using AddressUpgradeable for address;

    /// @notice Mapping to store pool addresses for token pairs (token0 => token1 => pool)
    mapping(address => mapping(address => address)) public getPool;

    /// @notice Tracks all created pools
    address[] public allPools;

    /// @notice Global pause status
    bool public paused;

    /// @notice Chain-specific pause status
    mapping(uint16 => bool) public chainPaused;

    /// @notice Cross-chain messenger addresses (0 = LayerZero, 1 = Axelar, 2 = Wormhole)
    mapping(uint8 => address) public crossChainMessengers;

    /// @notice Axelar gas service for gas payments
    address public axelarGasService;

    /// @notice Chain ID to Axelar chain name mapping
    mapping(uint16 => string) public chainIdToAxelarChain;

    /// @notice Axelar chain name to chain ID mapping
    mapping(string => uint16) public axelarChainToChainId;

    /// @notice Wormhole trusted sender addresses
    mapping(uint16 => bytes32) public wormholeTrustedSenders;

    /// @notice Treasury address for fee collection
    address public treasury;

    /// @notice Token bridge address for cross-chain token transfers
    address public tokenBridge;

    /// @notice Default timelock duration for cross-chain operations (in seconds)
    uint256 public defaultTimelock;

    /// @notice Default target reserve ratio (in 1e18 precision)
    uint256 public defaultTargetReserveRatio;

    /// @notice Trusted remote factory addresses by chain ID
    mapping(uint16 => bytes) public trustedRemoteFactories;

    /// @notice Nonces for cross-chain sync to prevent replays
    mapping(uint16 => mapping(uint64 => bool)) public usedNonces;

    /// @notice Failed cross-chain messages for retry
    struct FailedMessage {
        uint16 dstChainId;
        string dstAxelarChain;
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 timestamp;
        uint256 nextRetryTimestamp;
        uint8 messengerType; // 0 = LayerZero, 1 = Axelar, 2 = Wormhole
    }
    mapping(uint256 => FailedMessage) public failedMessages;
    uint256 public failedMessageCount;

    /// @notice Governance proposals
    struct GovernanceProposal {
        address target;
        bytes data;
        address proposer;
        uint256 proposedAt;
        bool executed;
        uint256 votesFor;
        uint256 votesAgainst;
        bool votingClosed;
        bool cancelled;
        uint256 snapshotSupply;
        uint256 impactLevel; // 1=low, 2=medium, 3=high
    }
    mapping(uint256 => GovernanceProposal) public governanceProposals;
    mapping(uint256 => GovernanceProposal) public executedProposals;
    uint256 public proposalCount;

    /// @notice Tracks votes for proposals
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    /// @notice Tracks last proposal submission time per address
    mapping(address => uint256) public lastProposalTime;

    /// @notice Proposal submission cooldown period (in seconds)
    uint256 public proposalCooldown;

    /// @notice Proposal submission fee (in native tokens)
    uint256 public proposalFee;

    /// @notice Delegated voting power with expiration
    struct Delegation {
        address delegate;
        uint256 expiry;
    }
    mapping(address => Delegation) public voteDelegate;

    /// @notice Governance token for voting power
    address public governanceToken;

    /// @notice Total supply of governance token for percentage-based quorum
    uint256 public governanceTokenTotalSupply;

    /// @notice Voting period for proposals (in seconds)
    uint256 public votingPeriod;

    /// @notice Minimum voting power required to propose
    uint256 public minimumProposalPower;

    /// @notice Quorum threshold as a percentage of total supply (in 1e18 precision)
    uint256 public quorumThreshold;

    /// @notice Available oracles per chain
    mapping(uint16 => address[]) public chainOracles;

    /// @notice Available relayers per chain
    mapping(uint16 => address[]) public chainRelayers;

    /// @notice Selected oracle/relayer per chain
    mapping(uint16 => address) public selectedOracle;
    mapping(uint16 => address) public selectedRelayer;

    /// @notice Chain-specific timelocks for reorg protection
    mapping(uint16 => uint256) public timelocks;

    /// @notice Governance timelock delay
    uint256 public governanceTimelock;

    /// @notice Configurable constants
    uint32 public minTimelock;
    uint32 public maxTimelock;
    uint32 public maxRetries;
    uint32 public maxBatchSize;
    uint32 public minGasLimit;
    uint32 public maxOracleStaleness;

    /// @notice Whitelist of allowed governance target addresses
    mapping(address => bool) public governanceTargetWhitelist;

    /// @notice Multi-signature committee\ for critical actions
    mapping(address => bool) public committeeMembers;
    uint256 public committeeMemberCount;
    uint256 public constant MIN_COMMITTEE_APPROVALS = 3;

    /// @notice Pending upgrades for multi-step approval
    struct PendingUpgrade {
        address newImplementation;
        uint256 proposedAt;
        uint256 approvals;
        mapping(address => bool) approvedBy;
    }
    mapping(uint256 => PendingUpgrade) public pendingUpgrades;
    uint256 public upgradeProposalCount;

    /// @notice Fallback oracles per chain
    mapping(uint16 => address[]) public fallbackOracles;

    /// @notice Oracle override flag for emergency use
    bool public oracleOverride;

    /// @notice Circuit breaker for cross-chain operations
    bool public crossChainCircuitBreaker;

    /// @notice Emergency flag proposals
    struct EmergencyFlagProposal {
        bool oracleOverride;
        bool circuitBreaker;
        uint256 proposedAt;
    }
    mapping(uint256 => Emergency FrankProposal) public emergencyFlagProposals;
    uint256 public emergencyFlagProposalCount;

    /// @notice Mapping for pair-to-asset resolution
    mapping(address => mapping(address => address)) public pairToAsset; // tokenA => tokenB => asset

    /// @notice Oracle health status
    struct OracleHealth {
        bool isHealthy;
        uint256 lastChecked;
        uint256 failureCount;
        uint256 lastPrice;
    }
    mapping(address => OracleHealth) public oracleHealth;

    /// @notice Maximum allowed oracle failures before failover
    uint256 public maxOracleFailures;

    /// @notice Minimum time between oracle health checks
    uint256 public oracleHealthCheckInterval;

    /// @notice Position manager address
    address public positionManager;

    /// @notice Storage gap for future upgrades
    uint256[89] private __gap; // Adjusted from 90 to 89 for new positionManager variable

    /// @custom: Errors
    error InvalidTokenAddress(string reason);
    error IdenticalTokens();
    error PoolAlreadyExists();
    error ContractPaused();
    error ChainPausedError(uint16 chainId);
    error InvalidAddress(address addr, string reason);
    error InvalidTimelock(uint256 timelock, uint256 min, uint256 max);
    error InvalidReserveRatio();
    error InvalidOracle(address oracle, string reason);
    error ProposalNotFound(uint256 proposalId);
    error ProposalNotReady(uint256 proposalId, string reason);
    error ProposalAlreadyExecuted();
    error ProposalCancelled();
    error InvalidAdapterParams(string reason);
    error InsufficientFee(uint256 provided, uint256 required);
    error MaxRetriesExceeded();
    error MessageNotExists(uint256 messageId);
    error InsufficientVotingPower(uint256 power, uint256 required);
    error AlreadyVoted();
    error VotingClosedError();
    error BatchSizeExceeded(uint256 size, uint256 max);
    error InvalidSalt();
    error QuorumNotMet(uint256 totalVotes, uint256 quorumRequired);
    error InvalidGasLimit(uint256 gasLimit, uint256 minGasLimit);
    error InvalidNonce();
    error InvalidOracleRelayer(address oracle, address relayer);
    error InvalidAmount(string reason);
    error StaleOracleData(uint256 updatedAt, uint256 currentTimestamp);
    error UnauthorizedCaller(address caller);
    error InvalidDelegate(address delegate);
    error FailedExternalCall(string reason);
    error InvalidTarget(address target);
    error UpgradeNotApproved(uint256 upgradeId);
    error DelegationExpired(address delegate);
    error NoOracleAvailable();
    error ProposalCooldownActive(uint256 nextProposalTime);
    error InsufficientProposalFee(uint256 provided, uint256 required);
    error InvalidCommitteeMember(address member);
    error InvalidPayload();
    error CircuitBreakerTriggered();
    error InvalidTokenContract(address token, string reason);
    error OraclePrecisionMismatch(uint8 primaryDecimals, uint8 fallbackDecimals);
    error InvalidTokenPair(address oracle, address tokenA, address tokenB);
    error EmergencyFlagPending(uint256 proposalId);
    error InvalidMessengerType(uint8 messengerType);
    error MessengerNotSet(uint8 messengerType);
    error OracleHealthCheckFailed(address oracle, string reason);
    error NoValidOracleFound();

    /// @notice Events
    event PoolCreated(
        address indexed tokenA,
        address indexed tokenB,
        address pool,
        address primaryPriceOracle,
        address[] fallbackPriceOracles,
        uint16 chainId,
        bytes32 salt
    );
    event BatchPoolsCreated(uint256 poolCount, uint16 chainId);
    event PauseToggled(bool paused);
    event ChainPaused(uint16 indexed chainId, address indexed caller);
    event ChainUnpaused(uint16 indexed chainId, address indexed caller);
    event TreasuryUpdated(address indexed newTreasury);
    event TokenBridgeUpdated(address indexed newTokenBridge);
    event CrossChainMessengerUpdated(uint8 indexed messengerType, address indexed newMessenger);
    event AxelarGasServiceUpdated(address indexed newGasService);
    event ChainIdMappingUpdated(uint16 chainId, string axelarChain);
    event WormholeTrustedSenderUpdated(uint16 chainId, bytes32 senderAddress);
    event DefaultTimelockUpdated(uint256 newTimelock);
    event DefaultTargetReserveRatioUpdated(uint256 newRatio);
    event TrustedRemoteFactoryAdded(uint16 indexed chainId, bytes factoryAddress);
    event GovernanceProposalCreated(
        uint256 indexed proposalId,
        address target,
        bytes data,
        address proposer,
        uint256 proposedAt,
        uint256 snapshotSupply,
        uint256 impactLevel
    );
    event GovernanceProposalExecuted(uint256 indexed proposalId);
    event GovernanceProposalCancelled(uint256 indexed proposalId);
    event Voted(uint256 indexed proposalId, address indexed voter, bool inFavor, uint256 votingPower);
    event BatchVoted(address indexed voter, uint256[] proposalIds, bool[] inFavor, uint256 votingPower);
    event VotingClosed(uint256 indexed proposalId);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes payload, uint8 messengerType);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries, uint8 messengerType);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event CrossChainSyncSent(uint16 indexed chainId, bytes payload, uint8 messengerType);
    event CrossChainPoolUpdated(uint16 indexed srcChainId, address tokenA, address tokenB, address pool);
    event VotingParametersUpdated(uint256 votingPeriod, uint256 minimumProposalPower, uint256 quorumThreshold);
    event GovernanceTokenUpdated(address indexed newGovernanceToken);
    event OracleRelayerUpdated(uint16 indexed chainId, address oracle, address relayer);
    event TimelockUpdated(uint16 indexed chainId, uint256 timelock);
    event VoteDelegated(address indexed delegator, address indexed delegate, uint256 expiry);
    event DelegationRevoked(address indexed delegator, address indexed delegate);
    event MinTimelockUpdated(uint256 minTimelock);
    event MaxTimelockUpdated(uint256 maxTimelock);
    event MaxRetriesUpdated(uint256 maxRetries);
    event MaxBatchSizeUpdated(uint256 maxBatchSize);
    event MinGasLimitUpdated(uint256 minGasLimit);
    event MaxOracleStalenessUpdated(uint256 maxOracleStaleness);
    event GovernanceTargetWhitelisted(address indexed target);
    event UpgradeProposed(uint256 indexed upgradeId, address newImplementation, uint256 proposedAt);
    event UpgradeApproved(uint256 indexed upgradeId, address approver);
    event UpgradeExecuted(uint256 indexed upgradeId, address newImplementation);
    event FailedMessageCleared(uint256 indexed messageId);
    event GovernanceProposalCleared(uint256 indexed proposalId);
    event CommitteeMemberAdded(address indexed member);
    event CommitteeMemberRemoved(address indexed member);
    event GovernanceTokenSupplyUpdated(uint256 newSupply);
    event OracleOverrideToggled(bool enabled);
    event CircuitBreakerToggled(bool enabled);
    event FallbackOraclesUpdated(uint16 indexed chainId, address[] oracles);
    event ProposalCooldownUpdated(uint256 newCooldown);
    event ProposalFeeUpdated(uint256 newFee);
    event EmergencyFlagProposed(uint256 indexed proposalId, bool oracleOverride, bool circuitBreaker, uint256 proposedAt);
    event OracleValidationFailed(address indexed oracle, string reason);
    event PairAssetSet(address indexed tokenA, address indexed tokenB, address asset);
    event OracleHealthUpdated(address indexed oracle, bool isHealthy, uint256 failureCount);
    event OracleFailover(address indexed failedOracle, address indexed newOracle);
    event OracleConfigUpdated(uint256 maxOracleFailures, uint256 oracleHealthCheckInterval);
    event PositionManagerUpdated(address indexed newPositionManager);

    /// @notice Modifier to check if the contract is not paused
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    /// @notice Modifier to check if a specific chain is not paused
    modifier whenChainNotPaused(uint16 chainId) {
        if (chainPaused[chainId]) revert ChainPausedError(chainId);
        _;
    }

    /// @notice Modifier to restrict to governance-approved calls
    modifier onlyGovernance() {
        if (msg.sender != address(this)) revert UnauthorizedCaller(msg.sender);
        _;
    }

    /// @notice Modifier to restrict to committee members
    modifier onlyCommittee() {
        if (!committeeMembers[msg.sender]) revert UnauthorizedCaller(msg.sender);
        _;
    }

    /// @notice Modifier to check circuit breaker
    modifier whenCircuitBreakerNotTriggered() {
        if (crossChainCircuitBreaker) revert CircuitBreakerTriggered();
        _;
    }

    /// @notice Disable constructor for upgradeable contracts
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the factory
    function initialize(
        address _layerZeroEndpoint,
        address _axelarGateway,
        address _axelarGasService,
        address _wormholeCore,
        address _treasury,
        address _tokenBridge,
        address _governanceToken,
        address _positionManager,
        uint256 _defaultTimelock,
        uint256 _defaultTargetReserveRatio,
        uint256 _votingPeriod,
        uint256 _minimumProposalPower,
        uint256 _quorumThreshold,
        uint256 _maxOracleStaleness,
        address[] calldata _initialCommittee
    ) external initializer {
        if (crossChainMessengers[0] != address(0)) revert InvalidAmount("Contract already initialized");
        if (
            _layerZeroEndpoint == address(0) ||
            _axelarGateway == address(0) ||
            _axelarGasService == address(0) ||
            _wormholeCore == address(0) ||
            _treasury == address(0) ||
            _tokenBridge == address(0) ||
            _governanceToken == address(0) ||
            _positionManager == address(0)
        ) revert InvalidAddress(address(0), "Zero address not allowed");
        if (_defaultTimelock < 10800 || _defaultTimelock > 48 * 3600)
            revert InvalidTimelock(_defaultTimelock, 10800, 48 * 3600);
        if (_defaultTargetReserveRatio == 0) revert InvalidReserveRatio();
        if (_votingPeriod == 0 || _minimumProposalPower == 0 || _quorumThreshold == 0 || _quorumThreshold > 1e18)
            revert InvalidAmount("Invalid voting parameters");
        if (_maxOracleStaleness == 0) revert InvalidAmount("Invalid oracle staleness");
        if (_initialCommittee.length < MIN_COMMITTEE_APPROVALS) revert InvalidAmount("Insufficient committee members");

        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        crossChainMessengers[0] = _layerZeroEndpoint; // LayerZero
        crossChainMessengers[1] = _axelarGateway; // Axelar
        crossChainMessengers[2] = _wormholeCore; // Wormhole
        axelarGasService = _axelarGasService;
        treasury = _treasury;
        tokenBridge = _tokenBridge;
        governanceToken = _governanceToken;
        positionManager = _positionManager;
        governanceTokenTotalSupply = IERC20Upgradeable(_governanceToken).totalSupply();
        defaultTimelock = _defaultTimelთ
        defaultTargetReserveRatio = _defaultTargetReserveRatio;
        votingPeriod = _votingPeriod;
        minimumProposalPower = _minimumProposalPower;
        quorumThreshold = _quorumThreshold;
        governanceTimelock = 15 * 3600;
        minTimelock = 10800;
        maxTimelock = 48 * 3600;
        maxRetries = 3;
        maxBatchSize = 10;
        minGasLimit = 200_000;
        maxOracleStaleness = _maxOracleStaleness;
        proposalCooldown = 1 days;
        proposalFee = 0.01 ether;
        maxOracleFailures = 3;
        oracleHealthCheckInterval = 1 hours;

        for (uint256 i = 0; i < _initialCommittee.length; i++) {
            if (_initialCommittee[i] == address(0)) revert InvalidAddress(_initialCommittee[i], "Invalid committee member");
            committeeMembers[_initialCommittee[i]] = true;
            emit CommitteeMemberAdded(_initialCommittee[i]);
        }
        committeeMemberCount = _initialCommittee.length;

        governanceTargetWhitelist[address(this)] = true;
        emit GovernanceTargetWhitelisted(address(this));

        emit MinTimelockUpdated(minTimelock);
        emit MaxTimelockUpdated(maxTimelock);
        emit MaxRetriesUpdated(maxRetries);
        emit MaxBatchSizeUpdated(maxBatchSize);
        emit MinGasLimitUpdated(minGasLimit);
        emit MaxOracleStalenessUpdated(maxOracleStaleness);
        emit ProposalCooldownUpdated(proposalCooldown);
        emit ProposalFeeUpdated(proposalFee);
        emit OracleConfigUpdated(maxOracleFailures, oracleHealthCheckInterval);
        emit PositionManagerUpdated(_positionManager);
    }

    /// @notice Updates oracle configuration parameters
    function updateOracleConfig(uint256 _maxOracleFailures, uint256 _oracleHealthCheckInterval) external onlyGovernance {
        if (_maxOracleFailures == 0 || _oracleHealthCheckInterval < 1 hours)
            revert InvalidAmount("Invalid oracle config parameters");
        maxOracleFailures = _maxOracleFailures;
        oracleHealthCheckInterval = _oracleHealthCheckInterval;
        emit OracleConfigUpdated(_maxOracleFailures, _oracleHealthCheckInterval);
    }

    /// @notice Checks oracle health and updates status
    function checkOracleHealth(address oracle, uint16 chainId, address tokenA, address tokenB) public returns (bool) {
        if (oracle == address(0)) revert InvalidAddress(oracle, "Zero address");
        OracleHealth storage health = oracleHealth[oracle];
        if (block.timestamp < health.lastChecked + oracleHealthCheckInterval) return health.isHealthy;

        bool isHealthy;
        address asset = pairToAsset[tokenA][tokenB];
        try IChainlinkOracle(oracle).latestRoundData() returns (
            uint80 roundId,
            int256 answer,
            uint256,
            uint256 updatedAt,
            uint80 answeredInRound
        ) {
            if (answer <= 0 || updatedAt == 0 || updatedAt > block.timestamp || answeredInRound != roundId) {
                isHealthy = false;
            } else {
                if (asset != address(0)) {
                    try IPriceOracle(oracle).getCurrentPrice(asset) returns (uint256 price) {
                        uint8 decimals = IChainlinkOracle(oracle).decimals();
                        uint256 scaledAnswer = (uint256(answer) * 1e18) / (10 ** decimals);
                        isHealthy = price > 0 && scaledAnswer == price;
                    } catch {
                        isHealthy = false;
                    }
                } else {
                    try IPriceOracle(oracle).getCurrentPairPrice(tokenA, tokenB) returns (uint256 price, bool) {
                        isHealthy = price > 0;
                        health.lastPrice = price;
                    } catch {
                        isHealthy = false;
                    }
                }
            }
            health.lastPrice = (uint256(answer) * 1e18) / (10 ** IChainlinkOracle(oracle).decimals());
        } catch {
            try IPriceOracle(oracle).getCurrentPairPrice(tokenA, tokenB) returns (uint256 price, bool) {
                isHealthy = price > 0;
                health.lastPrice = price;
            } catch {
                try IPriceOracle(oracle).getCurrentPrice(asset) returns (uint256 price) {
                    isHealthy = price > 0;
                    health.lastPrice = price;
                } catch {
                    isHealthy = false;
                }
            }
        }

        if (!isHealthy) {
            health.failureCount++;
            if (health.failureCount >= maxOracleFailures) {
                health.isHealthy = false;
            }
        } else {
            health.failureCount = 0;
            health.isHealthy = true;
        }
        health.lastChecked = block.timestamp;
        emit OracleHealthUpdated(oracle, health.isHealthy, health.failureCount);
        return health.isHealthy;
    }

    /// @notice Approves a proposed upgrade
    function approveUpgrade(uint256 upgradeId) external onlyCommittee {
        PendingUpgrade storage upgrade = pendingUpgrades[upgradeId];
        if (upgrade.newImplementation == address(0)) revert ProposalNotFound(upgradeId);
        if (upgrade.approvedBy[msg.sender]) revert AlreadyVoted();
        upgrade.approvedBy[msg.sender] = true;
        unchecked {
            upgrade.approvals++;
        }
        emit UpgradeApproved(upgradeId, msg.sender);
    }

    /// @notice Sets the asset for a token pair
    function setPairAsset(address tokenA, address tokenB, address asset) external onlyOwner {
        if (tokenA == address(0) || tokenB == address(0) || asset == address(0))
            revert InvalidAddress(address(0), "Zero address not allowed");
        pairToAsset[tokenA][tokenB] = asset;
        pairToAsset[tokenB][tokenA] = asset;
        emit PairAssetSet(tokenA, tokenB, asset);
    }

    /// @notice Updates the position manager
    function updatePositionManager(address newPositionManager) external onlyGovernance {
        if (newPositionManager == address(0)) revert InvalidAddress(newPositionManager, "Invalid position manager");
        positionManager = newPositionManager;
        emit PositionManagerUpdated(newPositionManager);
    }

    /// @notice Creates a new AMM pool for a token pair using CREATE2
    function createPool(
        address tokenA,
        address tokenB,
        address primaryPriceOracle,
        uint16 chainId,
        bytes calldata adapterParams,
        bytes32 customSalt
    ) external payable whenNotPaused whenChainNotPaused(chainId) whenCircuitBreakerNotTriggered nonReentrant returns (address pool) {
        _validateAdapterParams(adapterParams);
        _validateTokens(tokenA, tokenB);
        address selectedOracle = _validateOracles(primaryPriceOracle, chainId, tokenA, tokenB);
        pool = _createSinglePool(tokenA, tokenB, selectedOracle, chainId, adapterParams, customSalt);
    }

    /// @notice Creates multiple AMM pools in a single transaction
    function batchCreatePools(
        address[2][] calldata tokens,
        address[] calldata primaryPriceOracles,
        uint16[] calldata chainIds,
        bytes[] calldata adapterParams,
        bytes32[] calldata customSalts
    ) external payable whenNotPaused whenCircuitBreakerNotTriggered nonReentrant returns (address[] memory pools) {
        uint256 length = tokens.length;
        if (length == 0 || length > maxBatchSize) revert BatchSizeExceeded(length, maxBatchSize);
        if (
            length != primaryPriceOracles.length ||
            length != chainIds.length ||
            length != adapterParams.length ||
            length != customSalts.length
        ) revert InvalidAmount("Array length mismatch");

        pools = new address[](length);
        uint256 gasLeft = gasleft();
        for (uint256 i = 0; i < length; i++) {
            if (gasleft() < minGasLimit) revert InvalidGasLimit(gasleft(), minGasLimit);
            if (!chainPaused[chainIds[i]]) {
                _validateAdapterParams(adapterParams[i]);
                _validateTokens(tokens[i][0], tokens[i][1]);
                address selectedOracle = _validateOracles(primaryPriceOracles[i], chainIds[i], tokens[i][0], tokens[i][1]);
                pools[i] = _createSinglePool(
                    tokens[i][0],
                    tokens[i][1],
                    selectedOracle,
                    chainIds[i],
                    adapterParams[i],
                    customSalts[i]
                );
            }
        }
        emit BatchPoolsCreated(length, chainIds[0]);
    }

    /// @notice Predicts the deterministic address for a pool
    function predictPoolAddress(
        address tokenA,
        address tokenB,
        uint16 chainId,
        bytes32 customSalt
    ) external view returns (address pool) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        bytes32 salt = customSalt == bytes32(0) ? keccak256(abi.encodePacked(token0, token1, chainId)) : customSalt;
        pool = address(
            uint160(
                uint(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            salt,
                            keccak256(abi.encodePacked(type(AMMPool).creationCode))
                        )
                    )
                )
            )
        );
    }

    /// @notice Gets the estimated cross-chain fee
    function getEstimatedCrossChainFee(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) public view returns (uint256 nativeFee, uint256 zroFee) {
        string memory dstAxelarChain = chainIdToAxelarChain[dstChainId];
        for (uint8 i = 0; i < 3; i++) {
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            try ICrossChainMessenger(messenger).estimateFees(dstChainId, dstAxelarChain, address(this), payload, adapterParams)
                returns (uint256 _nativeFee, uint256 _zroFee) {
                return (_nativeFee, _zroFee);
            } catch {
                continue;
            }
        }
        revert MessengerNotSet(0);
    }

    /// @notice Retries a failed cross-chain message with exponential backoff
    function retryFailedMessage(uint256 messageId) external payable whenCircuitBreakerNotTriggered nonReentrant {
        if (msg.value < proposalFee) revert InsufficientProposalFee(msg.value, proposalFee);
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotExists(messageId);
        if (message.retries >= maxRetries) revert MaxRetriesExceeded();
        if (block.timestamp < message.nextRetryTimestamp) revert ProposalNotReady(messageId, "Retry timelock not elapsed");

        address messenger = crossChainMessengers[message.messengerType];
        if (messenger == address(0)) revert MessengerNotSet(message.messengerType);

        (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
            message.dstChainId,
            message.dstAxelarChain,
            address(this),
            message.payload,
            message.adapterParams
        );
        if (msg.value < nativeFee + proposalFee) revert InsufficientFee(msg.value, nativeFee + proposalFee);

        unchecked {
            message.retries++;
            message.timestamp = block.timestamp;
            message.nextRetryTimestamp = block.timestamp + (2 ** message.retries) * 1 hours;
        }

        try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
            message.dstChainId,
            message.dstAxelarChain,
            abi.encodePacked(trustedRemoteFactories[message.dstChainId], address(this)),
            message.payload,
            message.adapterParams,
            payable(msg.sender)
        ) {
            if (msg.value > nativeFee + proposalFee) {
                AddressUpgradeable.sendValue(payable(msg.sender), msg.value - nativeFee - proposalFee);
            }
            AddressUpgradeable.sendValue(payable(treasury), proposalFee);
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries, message.messengerType);
            delete failedMessages[messageId];
            emit FailedMessageCleared(messageId);
        } catch {
            AddressUpgradeable.sendValue(payable(treasury), proposalFee);
            emit FailedMessageStored(messageId, message.dstChainId, message.payload, message.messengerType);
        }
    }

    /// @notice Recovers a failed cross-chain message after max retries
    function recoverFailedMessage(uint256 messageId, address recipient) external onlyGovernance nonReentrant {
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotExists(messageId);
        if (message.retries < maxRetries) revert ProposalNotReady(messageId, "Max retries not reached");
        if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient");

        if (msg.value > 0) {
            AddressUpgradeable.sendValue(payable(recipient), msg.value);
        }

        emit FailedMessageRecovered(messageId, recipient);
        delete failedMessages[messageId];
        emit FailedMessageCleared(messageId);
    }

    /// @notice Synchronizes pool data with a remote chain
    function syncCrossChainPools(
        uint16 chainId,
        bytes calldata adapterParams,
        uint64 nonce
    ) external whenCircuitBreakerNotTriggered nonReentrant {
        if (trustedRemoteFactories[chainId].length == 0) revert InvalidAddress(address(0), "No trusted factory");
        if (usedNonces[chainId][nonce]) revert InvalidNonce();
        _validateAdapterParams(adapterParams);

        usedNonces[chainId][nonce] = true;
        bytes memory payload = abi.encode(allPools, block.timestamp, nonce);
        string memory dstAxelarChain = chainIdToAxelarChain[chainId];
        bytes memory destinationAddress = abi.encodePacked(trustedRemoteFactories[chainId], address(this));

        bool success;
        uint8 successfulMessengerType;
        for (uint8 i = 0; i < 3; i++) {
            address messenger = crossChainMessengers[i];
            if (messenger == address(0)) continue;
            (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
                chainId,
                dstAxelarChain,
                address(this),
                payload,
                adapterParams
            );
            if (msg.value < nativeFee) continue;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                chainId,
                dstAxelarChain,
                destinationAddress,
                payload,
                adapterParams,
                payable(msg.sender)
            ) {
                if (msg.value > nativeFee) {
                    AddressUpgradeable.sendValue(payable(msg.sender), msg.value - nativeFee);
                }
                success = true;
                successfulMessengerType = i;
                break;
            } catch {
                continue;
            }
        }
        if (success) {
            emit CrossChainSyncSent(chainId, payload, successfulMessengerType);
        } else {
            unchecked {
                failedMessages[failedMessageCount] = FailedMessage({
                    dstChainId: chainId,
                    dstAxelarChain: dstAxelarChain,
                    payload: payload,
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    nextRetryTimestamp: block.timestamp + 1 hours,
                    messengerType: 0
                });
                emit FailedMessageStored(failedMessageCount, chainId, payload, 0);
                failedMessageCount++;
            }
        }
    }

    /// @notice Receives cross-chain pool updates
    function receiveCrossChainPoolUpdate(
        uint16 srcChainId,
        string calldata srcAxelarChain,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external whenCircuitBreakerNotTriggered nonReentrant {
        uint8 messengerType;
        if (msg.sender == crossChainMessengers[0]) {
            messengerType = 0; // LayerZero
        } else if (msg.sender == crossChainMessengers[1]) {
            messengerType = 1; // Axelar
        } else if (msg.sender == crossChainMessengers[2]) {
            messengerType = 2; // Wormhole
        } else {
            revert UnauthorizedCaller(msg.sender);
        }

        if (trustedRemoteFactories[srcChainId].length == 0) revert InvalidAddress(address(0), "Invalid trusted factory");
        if (keccak256(srcAddress) != keccak256(abi.encodePacked(trustedRemoteFactories[srcChainId], address(this))))
            revert InvalidAddress(address(0), "Invalid source address");

        (address[] memory pools, uint256 timestamp, uint64 nonce) = abi.decode(payload, (address[], uint256, uint64));
        if (usedNonces[srcChainId][nonce]) revert InvalidNonce();
        if (pools.length == 0) revert InvalidPayload();

        usedNonces[srcChainId][nonce] = true;
        for (uint256 i = 0; i < pools.length; i++) {
            try this.decodePayload(pools[i]) returns (address tokenA, address tokenB, address pool) {
                (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
                if (getPool[token0][token1] == address(0)) {
                    _updatePoolStorage(token0, token1, pool);
                    emit CrossChainPoolUpdated(srcChainId, token0, token1, pool);
                }
            } catch {
                continue;
            }
        }
    }

    /// @notice Helper function to decode payload
    function decodePayload(bytes calldata poolData) external pure returns (address tokenA, address tokenB, address pool) {
        (tokenA, tokenB, pool) = abi.decode(poolData, (address, address, address));
    }

    /// @notice Gets all created pools with pagination
    function getAllPools(uint256 start, uint256 end) external view returns (address[] memory pools) {
        if (end > allPools.length || start > end) revert InvalidAmount("Invalid pagination range");
        uint256 length = end - start;
        pools = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            pools[i] = allPools[start + i];
        }
    }

    /// @notice Gets the number of pools created
    function allPoolsLength() external view returns (uint256) {
        return allPools.length;
    }

    /// @notice Validates if a pool exists for a token pair
    function poolExists(address tokenA, address tokenB) external view returns (bool exists) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return getPool[token0][token1] != address(0);
    }

    /// @notice Delegates voting power to another address with optional expiry
    function delegateVote(address delegate, uint256 expiry) external {
        if (delegate == address(0) || delegate == msg.sender) revert InvalidDelegate(delegate);
        if (expiry != 0 && expiry < block.timestamp) revert InvalidAmount("Invalid expiry");
        voteDelegate[msg.sender] = Delegation({delegate: delegate, expiry: expiry});
        emit VoteDelegated(msg.sender, delegate, expiry);
    }

    /// @notice Revokes vote delegation
    function revokeDelegation() external {
        Delegation memory delegation = voteDelegate[msg.sender];
        if (delegation.delegate == address(0)) revert InvalidDelegate(address(0));
        delete voteDelegate[msg.sender];
        emit DelegationRevoked(msg.sender, delegation.delegate);
    }

    /// @notice Proposes a governance update
    function proposeGovernanceUpdate(address target, bytes calldata data, uint256 impactLevel) external payable returns (uint256) {
        if (msg.value < proposalFee) revert InsufficientProposalFee(msg.value, proposalFee);
        if (!governanceTargetWhitelist[target]) revert InvalidTarget(target);
        if (block.timestamp < lastProposalTime[msg.sender] + proposalCooldown)
            revert ProposalCooldownActive(lastProposalTime[msg.sender] + proposalCooldown);
        if (impactLevel < 1 || impactLevel > 3) revert InvalidAmount("Invalid impact level");

        address voter = _getVoter(msg.sender);
        uint256 power = IERC20Upgradeable(governanceToken).balanceOf(voter);
        if (power < minimumProposalPower) revert InsufficientVotingPower(power, minimumProposalPower);

        uint256 proposalId;
        unchecked {
            proposalId = proposalCount++;
        }
        governanceProposals[proposalId] = GovernanceProposal({
            target: target,
            data: data,
            proposer: msg.sender,
            proposedAt: block.timestamp,
            executed: false,
            votesFor: 0,
            votesAgainst: 0,
            votingClosed: false,
            cancelled: false,
            snapshotSupply: governanceTokenTotalSupply,
            impactLevel: impactLevel
        });
        lastProposalTime[msg.sender] = block.timestamp;
        AddressUpgradeable.sendValue(payable(treasury), msg.value);
        emit GovernanceProposalCreated(proposalId, target, data, msg.sender, block.timestamp, governanceTokenTotalSupply, impactLevel);
        return proposalId;
    }

    /// @notice Cancels a governance proposal
    function cancelGovernanceProposal(uint256 proposalId) external {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (msg.sender != proposal.proposer && !committeeMembers[msg.sender]) revert UnauthorizedCaller(msg.sender);
        if (proposal.executed || proposal.cancelled) revert ProposalNotReady(proposalId, "Already executed or canceled");
        if (block.timestamp > proposal.proposedAt + votingPeriod) revert ProposalNotReady(proposalId, "Voting period ended");

        proposal.cancelled = true;
        if (proposalFee > 0) {
            AddressUpgradeable.sendValue(payable(proposal.proposer), proposalFee / 2);
        }
        emit GovernanceProposalCancelled(proposalId);
    }

    /// @notice Votes on a governance proposal
    function vote(uint256 proposalId, bool inFavor) external {
        _vote(proposalId, inFavor, _getVoter(msg.sender));
    }

    /// @notice Batch votes on multiple proposals
    function batchVote(uint256[] calldata proposalIds, bool[] calldata inFavor) external {
        if (proposalIds.length == 0 || proposalIds.length > maxBatchSize)
            revert BatchSizeExceeded(proposalIds.length, maxBatchSize);
        if (proposalIds.length != inFavor.length) revert InvalidAmount("Array length mismatch");
        address voter = _getVoter(msg.sender);
        uint256 power = IERC20Upgradeable(governanceToken).balanceOf(voter);
        uint256 gasLeft = gasleft();
        if (power == 0) revert InsufficientVotingPower(power, 0);

        for (uint256 i = 0; i < proposalIds.length; i++) {
            if (gasleft() < minGasLimit) revert InvalidGasLimit(gasleft(), minGasLimit);
            _vote(proposalIds[i], inFavor[i], voter);
        }
        emit BatchVoted(msg.sender, proposalIds, inFavor, power);
    }

    /// @notice Executes a governance proposal after timelock and voting
    function executeGovernanceProposal(uint256 proposalId) external nonReentrant {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (proposal.executed) revert ProposalAlreadyExecuted();
        if (proposal.cancelled) revert ProposalCancelled();
        if (block.timestamp < proposal.proposedAt + votingPeriod)
            revert ProposalNotReady(proposalId, "Voting period not ended");
        if (!proposal.votingClosed) {
            proposal.votingClosed = true;
            emit VotingClosed(proposalId);
        }

        uint256 totalVotes = proposal.votesFor + proposal.votesAgainst;
        uint256 quorumRequired = (proposal.snapshotSupply * quorumThreshold) / 1e18;
        if (totalVotes < quorumRequired) revert QuorumNotMet(totalVotes, quorumRequired);
        if (proposal.votesFor <= proposal.votesAgainst) revert ProposalNotReady(proposalId, "Insufficient votes in favor");

        uint256 requiredTimelock = governanceTimelock * proposal.impactLevel;
        if (requiredTimelock > maxTimelock) requiredTimelock = maxTimelock;
        if (block.timestamp < proposal.proposedAt + votingPeriod + requiredTimelock)
            revert ProposalNotReady(proposalId, "Timelock not elapsed");

        proposal.executed = true;
        executedProposals[proposalId] = proposal;
        (bool success, bytes memory reason) = proposal.target.call{gas: 500_000}(proposal.data);
        if (!success) {
            string memory revertReason = reason.length > 0 ? string(reason) : "Unknown error";
            revert FailedExternalCall(revertReason);
        }
        emit GovernanceProposalExecuted(proposalId);

        delete governanceProposals[proposalId];
        emit GovernanceProposalCleared(proposalId);
    }

    /// @notice Updates voting parameters
    function updateVotingParameters(
        uint256 _votingPeriod,
        uint256 _minimumProposalPower,
        uint256 _quorumThreshold
    ) external onlyGovernance {
        if (_votingPeriod == 0 || _minimumProposalPower == 0 || _quorumThreshold == 0 || _quorumThreshold > 1e18)
            revert InvalidAmount("Invalid voting parameters");
        votingPeriod = _votingPeriod;
        minimumProposalPower = _minimumProposalPower;
        quorumThreshold = _quorumThreshold;
        emit VotingParametersUpdated(_votingPeriod, _minimumProposalPower, _quorumThreshold);
    }

    /// @notice Updates configuration parameters
    function updateConfig(
        uint256 _minTimelock,
        uint256 _maxTimelock,
        uint256 _maxRetries,
        uint256 _maxBatchSize,
        uint256 _minGasLimit,
        uint256 _maxOracleStaleness
    ) external onlyGovernance {
        if (_minTimelock == 0 || _maxTimelock < _minTimelock || _maxRetries == 0 || _maxBatchSize == 0 || _minGasLimit == 0 || _maxOracleStaleness == 0)
            revert InvalidAmount("Invalid config parameters");
        minTimelock = uint32(_minTimelock);
        maxTimelock Pray
        maxTimelock = uint32(_maxTimelock);
        maxRetries = uint32(_maxRetries);
        maxBatchSize = uint32(_maxBatchSize);
        minGasLimit = uint32(_minGasLimit);
        maxOracleStaleness = uint32(_maxOracleStaleness);
        emit MinTimelockUpdated(_minTimelock);
        emit MaxTimelockUpdated(_maxTimelock);
        emit MaxRetriesUpdated(_maxRetries);
        emit MaxBatchSizeUpdated(_maxBatchSize);
        emit MinGasLimitUpdated(_minGasLimit);
        emit MaxOracleStalenessUpdated(_maxOracleStaleness);
    }

    /// @notice Updates governance token
    function updateGovernanceToken(address _governanceToken) external onlyGovernance {
        if (_governanceToken == address(0)) revert InvalidAddress(_governanceToken, "Invalid governance token");
        governanceToken = _governanceToken;
        governanceTokenTotalSupply = IERC20Upgradeable(_governanceToken).totalSupply();
        emit GovernanceTokenUpdated(_governanceToken);
        emit GovernanceTokenSupplyUpdated(governanceTokenTotalSupply);
    }

    /// @notice Updates oracle and relayer for a chain
    function updateOracleRelayer(uint16 chainId, address oracle, address relayer) external onlyGovernance {
        if (oracle == address(0) || relayer == address(0)) revert InvalidOracleRelayer(oracle, relayer);
        chainOracles[chainId].push(oracle);
        chainRelayers[chainId].push(relayer);
        selectedOracle[chainId] = oracle;
        selectedRelayer[chainId] = relayer;
        emit OracleRelayerUpdated(chainId, oracle, relayer);
    }

    /// @notice Selects an existing oracle/relayer pair
    function selectOracleRelayer(uint16 chainId, uint256 index) external onlyGovernance {
        if (index >= chainOracles[chainId].length || index >= chainRelayers[chainId].length)
            revert InvalidOracleRelayer(address(0), address(0));
        selectedOracle[chainId] = chainOracles[chainId][index];
        selectedRelayer[chainId] = chainRelayers[chainId][index];
        emit OracleRelayerUpdated(chainId, selectedOracle[chainId], selectedRelayer[chainId]);
    }

    /// @notice Updates timelock for a chain
    function updateTimelock(uint16 chainId, uint256 timelock) external onlyGovernance {
        if (timelock < minTimelock || timelock > maxTimelock) revert InvalidTimelock(timelock, minTimelock, maxTimelock);
        timelocks[chainId] = timelock;
        emit TimelockUpdated(chainId, timelock);
    }

    /// @notice Updates governance timelock
    function updateGovernanceTimelock(uint256 _governanceTimelock) external onlyGovernance {
        if (_governanceTimelock < minTimelock) revert InvalidTimelock(_governanceTimelock, minTimelock, maxTimelock);
        governanceTimelock = _governanceTimelock;
        emit DefaultTimelockUpdated(_governanceTimelock);
    }

    /// @notice Updates cross-chain messenger
   癒
    function updateCrossChainMessenger(uint8 messengerType, address newMessenger) external onlyGovernance {
        if (messengerType > 2) revert InvalidMessengerType(messengerType);
        if (newMessenger == Candy) revert InvalidAddress(newMessenger, "Invalid messenger address");
        crossChainMessengers[messengerType] = newMessenger;
        emit CrossChainMessengerUpdated(messengerType, newMessenger);
    }

    /// @notice Updates Axelar gas service
    function updateAxelarGasService(address newGasService) external onlyGovernance {
        if (newGasService == address(0)) revert InvalidAddress(newGasService, "Invalid gas service address");
        axelarGasService = newGasService;
        emit AxelarGasServiceUpdated(newGasService);
    }

    /// @notice Updates chain ID to Axelar chain mapping
    function updateChainIdMapping(uint16 chainId, string calldata axelarChain) external onlyGovernance {
        chainIdToAxelarChain[chainId] = axelarChain;
        axelarChainToChainId[axelarChain] = chainId;
        emit ChainIdMappingUpdated(chainId, axelarChain);
    }

    /// @notice Updates wormhole trusted sender
    function updateWormholeTrustedSender(uint16 chainId, bytes32 senderAddress) external onlyGovernance {
        wormholeTrustedSenders[chainId] = senderAddress;
        emit WormholeTrustedSenderUpdated(chainId, senderAddress);
    }

    /// @notice Updates token bridge address
    function updateTokenBridge(address newBridge) external onlyGovernance {
        if (newBridge == address(0)) revert InvalidAddress(newBridge, "Invalid token bridge");
        tokenBridge = newBridge;
        emit TokenBridgeUpdated(newBridge);
    }

    /// @notice Pauses the contract
    function pause() external onlyGovernance {
        if (paused) revert ContractPaused();
        paused = true;
        emit PauseToggled(true);
    }

    /// @notice Unpauses the contract
    function unpause() external onlyGovernance {
        if (!paused) revert UnauthorizedCaller(msg.sender);
        paused = false;
        emit PauseToggled(false);
    }

    /// @notice Pauses a specific chain
    function pauseChain(uint16 chainId) external onlyGovernance {
        if (chainPaused[chainId]) revert ChainPaused(chainId);
        chainPaused[chainId] = true;
        emit ChainPaused(chainId, msg.sender);
    }

    /// @notice Unpauses a specific chain
    function unpauseChain(uint16 chainId) external onlyGovernance {
        if (!chainPaused[chainId]) revert UnauthorizedCaller(msg.sender);
        chainPaused[chainId] = false;
        emit ChainUnpaused(chainId, msg.sender);
    }

    /// @notice Updates treasury address
    function updateTreasury(address _treasury) external onlyGovernance {
        if (_treasury == address(0)) revert InvalidAddress(_treasury, "Invalid treasury");
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /// @notice Updates default timelock
    function updateDefaultTimelock(uint256 _defaultTimelock) external onlyGovernance {
        if (_defaultTimelock < minTimelock || _defaultTimelock > maxTimelock)
            revert InvalidTimelock(_defaultTimelock, minTimelock, maxTimelock);
        defaultTimelock = _defaultTimelock;
        emit DefaultTimelockUpdated(_defaultTimelock);
    }

    /// @notice Updates default target reserve ratio
    function updateDefaultTargetReserveRatio(uint256 _defaultTargetReserveRatio) external onlyGovernance {
        if (_defaultTargetReserveRatio == 0) revert InvalidReserveRatio();
        defaultTargetReserveRatio = _defaultTargetReserveRatio;
        emit DefaultTargetReserveRatioUpdated(_defaultTargetReserveRatio);
    }

    /// @notice Adds a trusted remote factory for a chain
    function addTrustedRemoteFactory(uint16 chainId, bytes calldata factoryAddress) external onlyGovernance {
        if (factoryAddress.length == 0) revert InvalidAddress(address(0), "Invalid factory address");
        trustedRemoteFactories[chainId] = factoryAddress;
        emit TrustedRemoteFactoryAdded(chainId, factoryAddress);
    }

    /// @notice Removes a trusted remote factory for a chain
    function removeTrustedRemoteFactory(uint16 chainId) external onlyGovernance {
        if (trustedRemoteFactories[chainId].length == 0) revert InvalidAddress(address(0), "No factory set");
        delete trustedRemoteFactories[chainId];
        emit TrustedRemoteFactoryAdded(chainId, bytes(""));
    }

    /// @notice Updates proposal cooldown period
    function updateProposalCooldown(uint256 _proposalCooldown) external onlyGovernance {
        if (_proposalCooldown < 1 hours) revert InvalidAmount("Cooldown too short");
        proposalCooldown = _proposalCooldown;
        emit ProposalCooldownUpdated(_proposalCooldown);
    }

    /// @notice Updates proposal fee
    function updateProposalFee(uint256 _proposalFee) external onlyGovernance {
        proposalFee = _proposalFee;
        emit ProposalFeeUpdated(_proposalFee);
    }

    /// @notice Adds a committee member
    function addCommitteeMember(address member) external onlyGovernance {
        if (member == address(0)) revert InvalidCommitteeMember(member);
        if (committeeMembers[member]) revert InvalidCommitteeMember(member);
        committeeMembers[member] = true;
        unchecked {
            committeeMemberCount++;
        }
        emit CommitteeMemberAdded(member);
    }

    /// @notice Removes a committee member
    function removeCommitteeMember(address member) external onlyGovernance {
        if (!committeeMembers[member]) revert InvalidCommitteeMember(member);
        if (committeeMemberCount <= MIN_COMMITTEE_APPROVALS) revert InvalidAmount("Cannot reduce below minimum approvals");
        delete committeeMembers[member];
        unchecked {
            committeeMemberCount--;
        }
        emit CommitteeMemberRemoved(member);
    }

    /// @notice Whitelists a governance target address
    function whitelistGovernanceTarget(address target) external onlyGovernance {
        if (target == address(0)) revert InvalidAddress(target, "Invalid target");
        governanceTargetWhitelist[target] = true;
        emit GovernanceTargetWhitelisted(target);
    }

    /// @notice Removes a governance target from whitelist
    function removeGovernanceTarget(address target) external onlyGovernance {
        if (!governanceTargetWhitelist[target]) revert InvalidAddress(target, "Not whitelisted");
        delete governanceTargetWhitelist[target];
        emit GovernanceTargetWhitelisted(address(0));
    }

    /// @notice Updates fallback oracles for a chain
    function updateFallbackOracles(uint16 chainId, address[] calldata oracles) external onlyGovernance {
        for (uint256 i = 0; i < oracles.length; i++) {
            if (oracles[i] == address(0)) revert InvalidOracle(oracles[i], "Invalid oracle address");
            try IChainlinkOracle(oracles[i]).latestRoundData() returns (
                uint80,
                int256 answer,
                uint256,
                uint256 updatedAt,
                uint80
            ) {
                if (answer <= 0 || block.timestamp > updatedAt + maxOracleStaleness)
                    revert InvalidOracle(oracles[i], "Untrusted oracle");
            } catch {
                try IPriceOracle(oracles[i]).getCurrentPrice(address(0)) returns (uint256 price) {
                    if (price == 0) revert InvalidOracle(oracles[i], "Untrusted oracle");
                } catch {
                    revert InvalidOracle(oracles[i], "Not a valid oracle");
                }
            }
        }
        fallbackOracles[chainId] = oracles;
        emit FallbackOraclesUpdated(chainId, oracles);
    }

    /// @notice Toggles oracle override flag
    function toggleOracleOverride(bool enable) external onlyGovernance {
        oracleOverride = enable;
        emit OracleOverrideToggled(enable);
    }

    /// @notice Toggles cross-chain circuit breaker
    function toggleCircuitBreaker(bool enable) external onlyGovernance {
        crossChainCircuitBreaker = enable;
        emit CircuitBreakerToggled(enable);
    }

    /// @notice Proposes an emergency flag change
    function proposeEmergencyFlag(bool _oracleOverride, bool _circuitBreaker) external onlyCommittee returns (uint256) {
        uint256 proposalId;
        unchecked {
            proposalId = emergencyFlagProposalCount++;
        }
        emergencyFlagProposals[proposalId] = EmergencyFlagProposal({
            oracleOverride: _oracleOverride,
            circuitBreaker: _circuitBreaker,
            proposedAt: block.timestamp
        });
        emit EmergencyFlagProposed(proposalId, _oracleOverride, _circuitBreaker, block.timestamp);
        return proposalId;
    }

    /// @notice Executes an emergency flag proposal
    function executeEmergencyFlag(uint256 proposalId) external onlyGovernance {
        EmergencyFlagProposal storage proposal = emergencyFlagProposals[proposalId];
        if (proposal.proposedAt == 0) revert ProposalNotFound(proposalId);
        if (block.timestamp < proposal.proposedAt + governanceTimelock)
            revert ProposalNotReady(proposalId, "Timelock not elapsed");

        oracleOverride = proposal.oracleOverride;
        crossChainCircuitBreaker = proposal.circuitBreaker;
        emit OracleOverrideToggled(proposal.oracleOverride);
        emit CircuitBreakerToggled(proposal.circuitBreaker);
        delete emergencyFlagPro>nals[proposalId];
    }

    /// @notice Internal function to validate token addresses
    function _validateTokens(address tokenA, address tokenB) internal view {
        if (tokenA == address(0) || tokenB == address(0)) revert InvalidTokenAddress("Zero address");
        if (tokenA == tokenB) revert IdenticalTokens();
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        if (getPool[token0][token1] != address(0)) revert PoolAlreadyExists();
        try IERC20Upgradeable(tokenA).totalSupply() returns (uint256) {} catch {
            revert InvalidTokenContract(tokenA, "Not a valid ERC20 token");
        }
        try IERC20Upgradeable(tokenB).totalSupply() returns (uint256) {} catch {
            revert InvalidTokenContract(tokenB, "Not a valid ERC20 token");
        }
    }

    /// @notice Internal function to validate oracles with automatic failover
    function _validateOracles(address primaryPriceOracle, uint16 chainId, address tokenA, address tokenB) internal returns (address selectedOracle) {
        if (primaryPriceOracle == address(0)) revert InvalidOracle(primaryPriceOracle, "Zero address");
        if (!oracleOverride && selectedOracle[chainId] != address(0) && primaryPriceOracle != selectedOracle[chainId])
            revert InvalidOracle(primaryPriceOracle, "Not selected oracle");

        // Check primary oracle health
        if (checkOracleHealth(primaryPriceOracle, chainId, tokenA, tokenB)) {
            // Verify precision compatibility with fallback oracles
            uint8 primaryDecimals = _getOracleDecimals(primaryPriceOracle);
            address[] memory fallbackOraclesList = fallbackOracles[chainId];
            for (uint256 i = 0; i < fallbackOraclesList.length; i++) {
                if (fallbackOraclesList[i] != address(0)) {
                    uint8 fallbackDecimals = _getOracleDecimals(fallbackOraclesList[i]);
                    if (fallbackDecimals != primaryDecimals)
                        revert OraclePrecisionMismatch(primaryDecimals, fallbackDecimals);
                }
            }
            return primaryPriceOracle;
        }

        // Primary oracle failed, attempt failover
        emit OracleValidationFailed(primaryPriceOracle, "Primary oracle unhealthy");
        address[] memory fallbackOraclesList = fallbackOracles[chainId];
        if (fallbackOraclesList.length == 0) revert NoValidOracleFound();

        for (uint256 i = 0; i < fallbackOraclesList.length; i++) {
            if (fallbackOraclesList[i] == address(0)) continue;
            if (checkOracleHealth(fallbackOraclesList[i], chainId, tokenA, tokenB)) {
                emit OracleFailover(primaryPriceOracle, fallbackOraclesList[i]);
                selectedOracle[chainId] = fallbackOraclesList[i];
                return fallbackOraclesList[i];
            }
            emit OracleValidationFailed(fallbackOraclesList[i], "Fallback oracle unhealthy");
        }

        revert NoValidOracleFound();
    }

    /// @notice Internal function to get oracle decimals
    function _getOracleDecimals(address oracle) internal view returns (uint8) {
        try IChainlinkOracle(oracle).decimals() returns (uint8 decimals) {
            return decimals;
        } catch {
            return 18; // Default to 18 for non-Chainlink oracles
        }
    }

    /// @notice Internal function to validate adapter parameters
    function _validateAdapterParams(bytes calldata adapterParams) internal pure {
        if (adapterParams.length > 0) {
            try abi.decode(adapterParams, (uint256)) returns (uint256 gasLimit) {
                if (gasLimit < 200_000) revert InvalidAdapterParams("Gas limit too low");
            } catch {
                revert InvalidAdapterParams("Invalid adapter params format");
            }
        }
    }

    /// @notice Internal function to create a single pool
    function _createSinglePool(
        address tokenA,
        address tokenB,
        address primaryPriceOracle,
        uint16 chainId,
        bytes calldata adapterParams,
        bytes32 customSalt
    ) internal returns (address pool) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        bytes32 salt = customSalt == bytes32(0) ? keccak256(abi.encodePacked(token0, token1, chainId)) : customSalt;
        if (salt == bytes32(0)) revert InvalidSalt();

        pool = address(new AMMPool{salt: salt}());
        AMMPool(pool).initialize(
            token0,
            token1,
            treasury,
            crossChainMessengers[0], // LayerZero
            crossChainMessengers[1], // Axelar
            axelarGasService,
            crossChainMessengers[2], // Wormhole
            tokenBridge,
            primaryPriceOracle,
            fallbackOracles[chainId],
            address(this), // Governance
            positionManager,
            defaultTimelock,
            defaultTargetReserveRatio
        );

        getPool[token0][token1] = pool;
        allPools.push(pool);
        emit PoolCreated(token0, token1, pool, primaryPriceOracle, fallbackOracles[chainId], chainId, salt);

        // Notify cross-chain if applicable
        if (trustedRemoteFactories[chainId].length > 0 && adapterParams.length > 0) {
            bytes memory payload = abi.encode(token0, token1, pool);
            string memory dstAxelarChain = chainIdToAxelarChain[chainId];
            bytes memory destinationAddress = abi.encodePacked(trustedRemoteFactories[chainId], address(this));
            bool success;
            uint8 successfulMessengerType;

            for (uint8 i = 0; i < 3; i++) {
                address messenger = crossChainMessengers[i];
                if (messenger == address(0)) continue;
                (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
                    chainId,
                    dstAxelarChain,
                    address(this),
                    payload,
                    adapterParams
                );
                if (msg.value < nativeFee) continue;
                try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                    chainId,
                    dstAxelarChain,
                    destinationAddress,
                    payload,
                    adapterParams,
                    payable(msg.sender)
                ) {
                    if (msg.value > nativeFee) {
                        AddressUpgradeable.sendValue(payable(msg.sender), msg.value - nativeFee);
                    }
                    success = true;
                    successfulMessengerType = i;
                    break;
                } catch {
                    continue;
                }
            }
            if (!success) {
                unchecked {
                    failedMessages[failedMessageCount] = FailedMessage({
                        dstChainId: chainId,
                        dstAxelarChain: dstAxelarChain,
                        payload: payload,
                        adapterParams: adapterParams,
                        retries: 0,
                        timestamp: block.timestamp,
                        nextRetryTimestamp: block.timestamp + 1 hours,
                        messengerType: 0
                    });
                    emit FailedMessageStored(failedMessageCount, chainId, payload, 0);
                    failedMessageCount++;
                }
            } else {
                emit CrossChainSyncSent(chainId, payload, successfulMessengerType);
            }
        }
    }

    /// @notice Internal function to update pool storage
    function _updatePoolStorage(address token0, address token1, address pool) internal {
        if (getPool[token0][token1] == address(0)) {
            getPool[token0][token1] = pool;
            allPools.push(pool);
        }
    }

    /// @notice Internal function to get the effective voter address
    function _getVoter(address user) internal view returns (address voter) {
        Delegation memory delegation = voteDelegate[user];
        if (delegation.delegate != address(0) && (delegation.expiry == 0 || delegation.expiry > block.timestamp)) {
            voter = delegation.delegate;
        } else {
            voter = user;
        }
    }

    /// @notice Internal function to handle voting logic
    function _vote(uint256 proposalId, bool inFavor, address voter) internal {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (proposal.executed || proposal.cancelled) revert ProposalNotReady(proposalId, "Already executed or cancelled");
        if (block.timestamp > proposal.proposedAt + votingPeriod) revert VotingClosedError();
        if (hasVoted[proposalId][voter]) revert AlreadyVoted();

        uint256 power = IERC20Upgradeable(governanceToken).balanceOf(voter);
        if (power == 0) revert InsufficientVotingPower(power, 0);

        hasVoted[proposalId][voter] = true;
        if (inFavor) {
            proposal.votesFor += power;
        } else {
            proposal.votesAgainst += power;
        }
        emit Voted(proposalId, voter, inFavor, power);
    }

    /// @notice Fallback function to accept native tokens
    receive() external payable {}

    /// @notice Withdraws stuck native tokens
    function withdrawNative(address payable recipient, uint256 amount) external onlyGovernance {
        if (recipient == address(0)) revert InvalidAddress(recipient, "Invalid recipient");
        if (amount > address(this).balance) revert InvalidAmount("Insufficient balance");
        AddressUpgradeable.sendValue(recipient, amount);
    }

    /// @notice Withdraws stuck ERC20 tokens
    function withdrawERC20(address token, address recipient, uint256 amount) external onlyGovernance {
        if (token == address(0) || recipient == address(0)) revert InvalidAddress(address(0), "Invalid address");
        try IERC20Upgradeable(token).transfer(recipient, amount) returns (bool success) {
            if (!success) revert FailedExternalCall("Transfer failed");
        } catch {
            revert InvalidTokenContract(token, "Not a valid ERC20 token");
        }
    }
}
