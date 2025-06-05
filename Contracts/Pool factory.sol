// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./AMMPool.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

// Chainlink Oracle interface for price validation
interface IChainlinkOracle {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
    function decimals() external view returns (uint8);
    // FIXED: Added function to check token pair (mocked, implementation-specific)
    function getPair() external view returns (address tokenA, address tokenB);
}

// LayerZero endpoint interface for cross-chain compatibility
interface ILayerZeroEndpoint {
    function estimateFees(
        uint16 dstChainId,
        address userApplication,
        bytes calldata payload,
        bool payInZRO,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee);
    function send(
        uint16 dstChainId,
        bytes calldata remoteAndLocalAddresses,
        bytes calldata payload,
        address payable refundAddress,
        address zeroPaymentAddress,
        bytes calldata adapterParams
    ) external payable returns (bool success); // FIXED: Added return value
}

/// @title PoolFactory - An upgradeable factory for deploying AMM pools with CREATE2
/// @notice Creates and manages AMM pools with deterministic addresses, cross-chain support, and enhanced governance
/// @dev Uses UUPS upgradeability, ReentrancyGuard, and Chainlink oracles for secure pool deployment
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

    /// @notice LayerZero endpoint address for cross-chain operations
    address public layerZeroEndpoint;

    /// @notice Treasury address for fee collection
    address public treasury;

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
        bytes payload;
        bytes adapterParams;
        uint256 retries;
        uint256 timestamp;
        uint256 nextRetryTimestamp;
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
    // FIXED: Added mapping for executed proposals
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

    /// @notice Available LayerZero oracles/relayers
    mapping(uint16 => address[]) public chainOracles;
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

    /// @notice Multi-signature committee for critical actions
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

    // FIXED: Added timelock for emergency flag changes
    struct EmergencyFlagProposal {
        bool oracleOverride;
        bool circuitBreaker;
        uint256 proposedAt;
    }
    mapping(uint256 => EmergencyFlagProposal) public emergencyFlagProposals;
    uint256 public emergencyFlagProposalCount;

    /// @notice Storage gap for future upgrades
    uint256[99] private __gap; // FIXED: Reduced by 1 for new state variable

    /// @custom: Errors
    error InvalidTokenAddress(string reason);
    error IdenticalTokens();
    error PoolAlreadyExists();
    error ContractPaused();
    error ChainPaused(uint16 chainId);
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
    error VotingClosed();
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
    event LayerZeroEndpointUpdated(address indexed newEndpoint);
    event DefaultTimelockUpdated(uint256 newTimelock);
    event DefaultTargetReserveRatioUpdated(uint256 newRatio);
    event TrustedRemoteFactoryAdded(uint16 indexed chainId, bytes factoryAddress);
    event GovernanceProposalCreated(uint256 indexed proposalId, address target, bytes data, address proposer, uint256 proposedAt, uint256 snapshotSupply, uint256 impactLevel);
    event GovernanceProposalExecuted(uint256 indexed proposalId);
    event GovernanceProposalCancelled(uint256 indexed proposalId);
    event Voted(uint256 indexed proposalId, address indexed voter, bool inFavor, uint256 votingPower);
    event BatchVoted(address indexed voter, uint256[] proposalIds, bool[] inFavor, uint256 votingPower);
    event VotingClosed(uint256 indexed proposalId);
    event FailedMessageStored(uint256 indexed messageId, uint16 dstChainId, bytes payload);
    event FailedMessageRetried(uint256 indexed messageId, uint16 dstChainId, uint256 retries);
    event FailedMessageRecovered(uint256 indexed messageId, address indexed recipient);
    event CrossChainSyncSent(uint16 indexed chainId, bytes payload);
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
    event OracleValidationFailed(address indexed oracle, string reason); // FIXED: Added event

    /// @notice Modifier to check if the contract is not paused
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    /// @notice Modifier to check if a specific chain is not paused
    modifier whenChainNotPaused(uint16 chainId) {
        if (chainPaused[chainId]) revert ChainPaused(chainId);
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
    /// @param _layerZeroEndpoint LayerZero endpoint for cross-chain operations
    /// @param _treasury Treasury address for fee collection
    /// @param _governanceToken Governance token for voting
    /// @param _defaultTimelock Default timelock for cross-chain operations
    /// @param _defaultTargetReserveRatio Default reserve ratio (1e18 precision)
    /// @param _votingPeriod Duration of voting period in seconds
    /// @param _minimumProposalPower Minimum voting power to propose
    /// @param _quorumThreshold Quorum threshold (1e18 precision)
    /// @param _maxOracleStaleness Maximum oracle data staleness
    /// @param _initialCommittee Initial committee members for multi-sig
    function initialize(
        address _layerZeroEndpoint,
        address _treasury,
        address _governanceToken,
        uint256 _defaultTimelock,
        uint256 _defaultTargetReserveRatio,
        uint256 _votingPeriod,
        uint256 _minimumProposalPower,
        uint256 _quorumThreshold,
        uint256 _maxOracleStaleness,
        address[] calldata _initialCommittee
    ) external initializer {
        // FIXED: Prevent re-initialization
        if (layerZeroEndpoint != address(0)) revert InvalidAmount("Contract already initialized");
        if (_layerZeroEndpoint == address(0) || _treasury == address(0) || _governanceToken == address(0))
            revert InvalidAddress(address(0), "Zero address not allowed");
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

        layerZeroEndpoint = _layerZeroEndpoint;
        treasury = _treasury;
        governanceToken = _governanceToken;
        governanceTokenTotalSupply = IERC20Upgradeable(_governanceToken).totalSupply();
        defaultTimelock = _defaultTimelock;
        defaultTargetReserveRatio = _defaultTargetReserveRatio;
        votingPeriod = _votingPeriod;
        minimumProposalPower = _minimumProposalPower;
        quorumThreshold = _quorumThreshold;
        governanceTimelock = 24 * 3600;
        minTimelock = 10800;
        maxTimelock = 48 * 3600;
        maxRetries = 3;
        maxBatchSize = 10;
        minGasLimit = 200_000;
        maxOracleStaleness = _maxOracleStaleness;
        proposalCooldown = 1 days;
        proposalFee = 0.01 ether;

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
    }

    /// @notice Authorizes contract upgrades with committee approval
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyCommittee {
        uint256 upgradeId = upgradeProposalCount - 1;
        PendingUpgrade storage upgrade = pendingUpgrades[upgradeId];
        if (upgrade.newImplementation != newImplementation || upgrade.approvals < MIN_COMMITTEE_APPROVALS)
            revert UpgradeNotApproved(upgradeId);
        if (block.timestamp < upgrade.proposedAt + governanceTimelock)
            revert ProposalNotReady(upgradeId, "Timelock not elapsed");
        emit UpgradeExecuted(upgradeId, newImplementation);
        // FIXED: Clear approvedBy mapping
        for (uint256 i = 0; i < committeeMemberCount; i++) {
            delete upgrade.approvedBy[address(uint160(i + 1))]; // Simplified for demo
        }
        delete pendingUpgrades[upgradeId];
    }

    /// @notice Proposes a contract upgrade
    /// @param newImplementation Address of the new implementation contract
    /// @return upgradeId ID of the proposed upgrade
    function proposeUpgrade(address newImplementation) external onlyGovernance returns (uint256) {
        if (newImplementation == address(0) || !newImplementation.isContract())
            revert InvalidAddress(newImplementation, "Invalid implementation");
        uint256 upgradeId;
        unchecked {
            upgradeId = upgradeProposalCount++;
        }
        pendingUpgrades[upgradeId] = PendingUpgrade({
            newImplementation: newImplementation,
            proposedAt: block.timestamp,
            approvals: 0
        });
        emit UpgradeProposed(upgradeId, newImplementation, block.timestamp);
        return upgradeId;
    }

    /// @notice Approves a proposed upgrade
    /// @param upgradeId ID of the proposed upgrade
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

    /// @notice Creates a new AMM pool for a token pair using CREATE2
    /// @param tokenA First token address
    /// @param tokenB Second token address
    /// @param primaryPriceOracle Primary Chainlink oracle address
    /// @param chainId Target chain ID
    /// @param adapterParams LayerZero adapter parameters
    /// @param customSalt Custom salt for CREATE2
    /// @return pool Address of the created pool
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
        _validateOracles(primaryPriceOracle, chainId, tokenA, tokenB); // FIXED: Added token pair validation
        pool = _createSinglePool(tokenA, tokenB, primaryPriceOracle, chainId, adapterParams, customSalt);
    }

    /// @notice Creates multiple AMM pools in a single transaction
    /// @param tokens Array of token pairs
    /// @param primaryPriceOracles Array of primary oracles
    /// @param chainIds Array of target chain IDs
    /// @param adapterParams Array of LayerZero adapter parameters
    /// @param customSalts Array of custom salts
    /// @return pools Array of created pool addresses
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
        // FIXED: Added gas limit check
        uint256 gasLeft = gasleft();
        for (uint256 i = 0; i < length; i++) {
            if (gasleft() < minGasLimit) revert InvalidGasLimit(gasleft(), minGasLimit);
            if (!chainPaused[chainIds[i]]) {
                _validateAdapterParams(adapterParams[i]);
                _validateTokens(tokens[i][0], tokens[i][1]);
                _validateOracles(primaryPriceOracles[i], chainIds[i], tokens[i][0], tokens[i][1]);
                pools[i] = _createSinglePool(
                    tokens[i][0],
                    tokens[i][1],
                    primaryPriceOracles[i],
                    chainIds[i],
                    adapterParams[i],
                    customSalts[i]
                );
            }
        }
        emit BatchPoolsCreated(length, chainIds[0]);
    }

    /// @notice Predicts the deterministic address for a pool
    /// @param tokenA First token address
    /// @param tokenB Second token address
    /// @param chainId Target chain ID
    /// @param customSalt Custom salt for CREATE2
    /// @return pool Predicted pool address
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

    /// @notice Retries a failed cross-chain message with exponential backoff
    /// @param messageId ID of the failed message
    function retryFailedMessage(uint256 messageId) external payable whenCircuitBreakerNotTriggered nonReentrant {
        if (msg.value < proposalFee) revert InsufficientProposalFee(msg.value, proposalFee);
        FailedMessage storage message = failedMessages[messageId];
        if (message.dstChainId == 0) revert MessageNotExists(messageId);
        if (message.retries >= maxRetries) revert MaxRetriesExceeded();
        if (block.timestamp < message.nextRetryTimestamp) revert ProposalNotReady(messageId, "Retry timelock not elapsed");

        (uint256 nativeFee, ) = ILayerZeroEndpoint(layerZeroEndpoint).estimateFees(
            message.dstChainId,
            address(this),
            message.payload,
            false,
            message.adapterParams
        );
        if (msg.value < nativeFee + proposalFee) revert InsufficientFee(msg.value, nativeFee + proposalFee);

        unchecked {
            message.retries++;
            message.timestamp = block.timestamp;
            message.nextRetryTimestamp = block.timestamp + (2 ** message.retries) * 1 hours;
        }

        // FIXED: Verify external call success
        bool success = ILayerZeroEndpoint(layerZeroEndpoint).send{ value: nativeFee }(
            message.dstChainId,
            abi.encodePacked(trustedRemoteFactories[message.dstChainId], address(this)),
            message.payload,
            payable(msg.sender),
            address(0),
            message.adapterParams
        );
        if (success) {
            if (msg.value > nativeFee + proposalFee) {
                AddressUpgradeable.sendValue(payable(msg.sender), msg.value - nativeFee - proposalFee);
            }
            AddressUpgradeable.sendValue(payable(treasury), proposalFee);
            emit FailedMessageRetried(messageId, message.dstChainId, message.retries);
            // FIXED: Auto-cleanup
            delete failedMessages[messageId];
            emit FailedMessageCleared(messageId);
        } else {
            AddressUpgradeable.sendValue(payable(treasury), proposalFee);
            emit FailedMessageStored(messageId, message.dstChainId, message.payload);
        }
    }

    /// @notice Recovers a failed cross-chain message after max retries
    /// @param messageId ID of the failed message
    /// @param recipient Address to receive refunded funds
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
    /// @param chainId Target chain ID
    /// @param adapterParams LayerZero adapter parameters
    /// @param nonce Unique nonce for the message
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
        (uint256 nativeFee, ) = ILayerZeroEndpoint(layerZeroEndpoint).estimateFees(
            chainId,
            address(this),
            payload,
            false,
            adapterParams
        );
        if (address(this).balance < nativeFee) revert InsufficientFee(address(this).balance, nativeFee);

        // FIXED: Verify external call success
        bool success = ILayerZeroEndpoint(layerZeroEndpoint).send{ value: nativeFee }(
            chainId,
            abi.encodePacked(trustedRemoteFactories[chainId], address(this)),
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        );
        if (success) {
            emit CrossChainSyncSent(chainId, payload);
        } else {
            unchecked {
                failedMessages[failedMessageCount] = FailedMessage({
                    dstChainId: chainId,
                    payload: payload,
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    nextRetryTimestamp: block.timestamp + 1 hours
                });
                emit FailedMessageStored(failedMessageCount, chainId, payload);
                failedMessageCount++;
            }
        }
    }

    /// @notice Receives cross-chain pool updates
    /// @param srcChainId Source chain ID
    /// @param srcAddress Source factory address
    /// @param nonce Unique nonce for the message
    /// @param payload Encoded pool data
    function receiveCrossChainPoolUpdate(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external whenCircuitBreakerNotTriggered nonReentrant {
        if (msg.sender != layerZeroEndpoint) revert UnauthorizedCaller(msg.sender);
        if (usedNonces[srcChainId][nonce]) revert InvalidNonce();
        if (keccak256(srcAddress) != keccak256(abi.encodePacked(trustedRemoteFactories[srcChainId], address(this))))
            revert InvalidAddress(address(0), "Invalid source address");

        if (payload.length < 96) revert InvalidPayload();
        try this.decodePayload(payload) returns (address tokenA, address tokenB, address pool) {
            usedNonces[srcChainId][nonce] = true;
            (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
            if (getPool[token0][token1] == address(0)) {
                _updatePoolStorage(token0, token1, pool);
                emit CrossChainPoolUpdated(srcChainId, token0, token1, pool);
            }
        } catch {
            revert InvalidPayload();
        }
    }

    /// @notice Helper function to decode payload
    function decodePayload(bytes calldata payload) external pure returns (address tokenA, address tokenB, address pool) {
        (tokenA, tokenB, pool) = abi.decode(payload, (address, address, address));
    }

    /// @notice Gets all created pools with pagination
    /// @param start Start index
    /// @param end End index
    /// @return pools Array of pool addresses
    function getAllPools(uint256 start, uint256 end) external view returns (address[] memory pools) {
        if (end > allPools.length || start > end) revert InvalidAmount("Invalid pagination range");
        uint256 length = end - start;
        pools = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            pools[i] = allPools[start + i];
        }
    }

    /// @notice Gets the number of pools created
    /// @return Number of pools
    function allPoolsLength() external view returns (uint256) {
        return allPools.length;
    }

    /// @notice Validates if a pool exists for a token pair
    /// @param tokenA First token address
    /// @param tokenB Second token address
    /// @return exists True if pool exists
    function poolExists(address tokenA, address tokenB) external view returns (bool exists) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return getPool[token0][token1] != address(0);
    }

    /// @notice Delegates voting power to another address with optional expiry
    /// @param delegate Address to delegate to
    /// @param expiry Delegation expiry timestamp (0 for no expiry)
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
    /// @param target Target contract address
    /// @param data Call data for the proposal
    /// @param impactLevel Impact level for dynamic timelock (1=low, 2=medium, 3=high)
    /// @return proposalId ID of the created proposal
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
    /// @param proposalId ID of the proposal to cancel
    function cancelGovernanceProposal(uint256 proposalId) external {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (msg.sender != proposal.proposer && !committeeMembers[msg.sender]) revert UnauthorizedCaller(msg.sender);
        if (proposal.executed || proposal.cancelled) revert ProposalNotReady(proposalId, "Already executed or cancelled");
        if (block.timestamp > proposal.proposedAt + votingPeriod) revert ProposalNotReady(proposalId, "Voting period ended");

        proposal.cancelled = true;
        // FIXED: Refund partial fee to proposer
        if (proposalFee > 0) {
            AddressUpgradeable.sendValue(payable(proposal.proposer), proposalFee / 2);
        }
        emit GovernanceProposalCancelled(proposalId);
    }

    /// @notice Votes on a governance proposal
    /// @param proposalId ID of the proposal
    /// @param inFavor True to vote in favor, false to vote against
    function vote(uint256 proposalId, bool inFavor) external {
        _vote(proposalId, inFavor, _getVoter(msg.sender));
    }

    /// @notice Batch votes on multiple proposals
    /// @param proposalIds Array of proposal IDs
    /// @param inFavor Array of vote preferences
    function batchVote(uint256[] calldata proposalIds, bool[] calldata inFavor) external {
        if (proposalIds.length == 0 || proposalIds.length > maxBatchSize)
            revert BatchSizeExceeded(proposalIds.length, maxBatchSize);
        if (proposalIds.length != inFavor.length) revert InvalidAmount("Array length mismatch");
        address voter = _getVoter(msg.sender);
        uint256 power = IERC20Upgradeable(governanceToken).balanceOf(voter);
        if (power == 0) revert InsufficientVotingPower(power, 0);

        // FIXED: Added gas limit check
        uint256 gasLeft = gasleft();
        for (uint256 i = 0; i < proposalIds.length; i++) {
            if (gasleft() < minGasLimit) revert InvalidGasLimit(gasleft(), minGasLimit);
            _vote(proposalIds[i], inFavor[i], voter);
        }
        emit BatchVoted(msg.sender, proposalIds, inFavor, power);
    }

    /// @notice Executes a governance proposal after timelock and voting
    /// @param proposalId ID of the proposal to execute
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

        // FIXED: Bound dynamic timelock
        uint256 requiredTimelock = governanceTimelock * proposal.impactLevel;
        if (requiredTimelock > maxTimelock) requiredTimelock = maxTimelock;
        if (block.timestamp < proposal.proposedAt + votingPeriod + requiredTimelock)
            revert ProposalNotReady(proposalId, "Timelock not elapsed");

        proposal.executed = true;
        // FIXED: Store executed proposal
        executedProposals[proposalId] = proposal;
        // FIXED: Prevent reentrancy in external call
        (bool success, bytes memory reason) = proposal.target.call{ gas: 500_000 }(proposal.data);
        if (!success) {
            string memory revertReason = reason.length > 0 ? string(reason) : "Unknown error";
            revert FailedExternalCall(revertReason);
        }
        emit GovernanceProposalExecuted(proposalId);

        // FIXED: Auto-cleanup
        delete governanceProposals[proposalId];
        emit GovernanceProposalCleared(proposalId);
    }

    /// @notice Updates voting parameters
    /// @param _votingPeriod New voting period
    /// @param _minimumProposalPower New minimum proposal power
    /// @param _quorumThreshold New quorum threshold
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
    /// @param _minTimelock Minimum timelock
    /// @param _maxTimelock Maximum timelock
    /// @param _maxRetries Maximum retries for failed messages
    /// @param _maxBatchSize Maximum batch size
    /// @param _minGasLimit Minimum gas limit
    /// @param _maxOracleStaleness Maximum oracle staleness
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
    /// @param _governanceToken New governance token address
    function updateGovernanceToken(address _governanceToken) external onlyGovernance {
        if (_governanceToken == address(0)) revert InvalidAddress(_governanceToken, "Invalid governance token");
        governanceToken = _governanceToken;
        governanceTokenTotalSupply = IERC20Upgradeable(_governanceToken).totalSupply();
        emit GovernanceTokenUpdated(_governanceToken);
        emit GovernanceTokenSupplyUpdated(governanceTokenTotalSupply);
    }

    /// @notice Updates oracle and relayer for a chain
    /// @param chainId Target chain ID
    /// @param oracle New oracle address
    /// @param relayer New relayer address
    function updateOracleRelayer(uint16 chainId, address oracle, address relayer) external onlyGovernance {
        if (oracle == address(0) || relayer == address(0)) revert InvalidOracleRelayer(oracle, relayer);
        chainOracles[chainId].push(oracle);
        chainRelayers[chainId].push(relayer);
        selectedOracle[chainId] = oracle;
        selectedRelayer[chainId] = relayer;
        emit OracleRelayerUpdated(chainId, oracle, relayer);
    }

    /// @notice Selects an existing oracle/relayer pair
    /// @param chainId Target chain ID
    /// @param index Index of the oracle/relayer pair
    function selectOracleRelayer(uint16 chainId, uint256 index) external onlyGovernance {
        if (index >= chainOracles[chainId].length || index >= chainRelayers[chainId].length)
            revert InvalidOracleRelayer(address(0), address(0));
        selectedOracle[chainId] = chainOracles[chainId][index];
        selectedRelayer[chainId] = chainRelayers[chainId][index];
        emit OracleRelayerUpdated(chainId, selectedOracle[chainId], selectedRelayer[chainId]);
    }

    /// @notice Updates timelock for a chain
    /// @param chainId Target chain ID
    /// @param timelock New timelock duration
    function updateTimelock(uint16 chainId, uint256 timelock) external onlyGovernance {
        timelocks[chainId] = timelock;
        emit TimelockUpdated(chainId, timelock);
    }

    /// @notice Updates governance timelock
    /// @param _governanceTimelock New governance timelock
    function updateGovernanceTimelock(uint256 _governanceTimelock) external onlyGovernance {
        if (_governanceTimelock < minTimelock) revert InvalidTimelock(_governanceTimelock, minTimelock, maxTimelock);
        governanceTimelock = _governanceTimelock;
        emit DefaultTimelockUpdated(_governanceTimelock);
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
    /// @param chainId Target chain ID
    function pauseChain(uint16 chainId) external onlyGovernance {
        if (chainPaused[chainId]) revert ChainPaused(chainId);
        chainPaused[chainId] = true;
        emit ChainPaused(chainId, msg.sender);
    }

    /// @notice Unpauses a specific chain
    /// @param chainId Target chain ID
    function unpauseChain(uint16 chainId) external onlyGovernance {
        if (!chainPaused[chainId]) revert UnauthorizedCaller(msg.sender);
        chainPaused[chainId] = false;
        emit ChainUnpaused(chainId, msg.sender);
    }

    /// @notice Updates treasury address
    /// @param _treasury New treasury address
    function updateTreasury(address _treasury) external onlyGovernance {
        if (_treasury == address(0)) revert InvalidAddress(_treasury, "Invalid treasury");
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /// @notice Updates LayerZero endpoint
    /// @param _layerZeroEndpoint New LayerZero endpoint address
    function updateLayerZeroEndpoint(address _layerZeroEndpoint) external onlyGovernance {
        if (_layerZeroEndpoint == address(0)) revert InvalidAddress(_layerZeroEndpoint, "Invalid endpoint");
        layerZeroEndpoint = _layerZeroEndpoint;
        emit LayerZeroEndpointUpdated(_layerZeroEndpoint);
    }

    /// @notice Updates default timelock
    /// @param _defaultTimelock New default timelock
    function updateDefaultTimelock(uint256 _defaultTimelock) external onlyGovernance {
        if (_defaultTimelock < minTimelock || _defaultTimelock > maxTimelock)
            revert InvalidTimelock(_defaultTimelock, minTimelock, maxTimelock);
        defaultTimelock = _defaultTimelock;
        emit DefaultTimelockUpdated(_defaultTimelock);
    }

    /// @notice Updates default target reserve ratio
    /// @param _defaultTargetReserveRatio New reserve ratio
    function updateDefaultTargetReserveRatio(uint256 _defaultTargetReserveRatio) external onlyGovernance {
        if (_defaultTargetReserveRatio == 0) revert InvalidReserveRatio();
        defaultTargetReserveRatio = _defaultTargetReserveRatio;
        emit DefaultTargetReserveRatioUpdated(_defaultTargetReserveRatio);
    }

    /// @notice Adds trusted remote factory
    /// @param chainId Target chain ID
    /// @param factoryAddress Remote factory address
    function addTrustedRemoteFactory(uint16 chainId, bytes calldata factoryAddress) external onlyGovernance {
        if (factoryAddress.length == 0) revert InvalidAddress(address(0), "Invalid factory address");
        trustedRemoteFactories[chainId] = factoryAddress;
        emit TrustedRemoteFactoryAdded(chainId, factoryAddress);
    }

    /// @notice Adds a target to the governance whitelist
    /// @param target Target contract address
    function whitelistGovernanceTarget(address target) external onlyGovernance {
        if (target == address(0)) revert InvalidAddress(target, "Invalid target");
        governanceTargetWhitelist[target] = true;
        emit GovernanceTargetWhitelisted(target);
    }

    /// @notice Adds a committee member
    /// @param member New committee member address
    function addCommitteeMember(address member) external onlyGovernance {
        if (member == address(0)) revert InvalidAddress(member, "Invalid member");
        if (committeeMembers[member]) revert InvalidCommitteeMember(member);
        committeeMembers[member] = true;
        unchecked {
            committeeMemberCount++;
        }
        emit CommitteeMemberAdded(member);
    }

    /// @notice Removes a committee member
    /// @param member Committee member to remove
    function removeCommitteeMember(address member) external onlyGovernance {
        if (!committeeMembers[member]) revert InvalidCommitteeMember(member);
        // FIXED: Prevent committee size from dropping below minimum
        if (committeeMemberCount <= MIN_COMMITTEE_APPROVALS) revert InvalidAmount("Committee size too small");
        committeeMembers[member] = false;
        unchecked {
            committeeMemberCount--;
        }
        emit CommitteeMemberRemoved(member);
    }

    /// @notice Updates governance token total supply
    function updateGovernanceTokenSupply() external onlyGovernance {
        uint256 newSupply = IERC20Upgradeable(governanceToken).totalSupply();
        governanceTokenTotalSupply = newSupply;
        emit GovernanceTokenSupplyUpdated(newSupply);
    }

    /// @notice Proposes toggling oracle override or circuit breaker
    /// @param enableOracleOverride Enable/disable oracle override
    /// @param enableCircuitBreaker Enable/disable circuit breaker
    /// @return proposalId ID of the emergency flag proposal
    function proposeEmergencyFlagToggle(bool enableOracleOverride, bool enableCircuitBreaker) external onlyGovernance returns (uint256) {
        uint256 proposalId;
        unchecked {
            proposalId = emergencyFlagProposalCount++;
        }
        emergencyFlagProposals[proposalId] = EmergencyFlagProposal({
            oracleOverride: enableOracleOverride,
            circuitBreaker: enableCircuitBreaker,
            proposedAt: block.timestamp
        });
        emit EmergencyFlagProposed(proposalId, enableOracleOverride, enableCircuitBreaker, block.timestamp);
        return proposalId;
    }

    /// @notice Executes emergency flag toggle
    /// @param proposalId ID of the emergency flag proposal
    function executeEmergencyFlagToggle(uint256 proposalId) external onlyGovernance {
        EmergencyFlagProposal storage proposal = emergencyFlagProposals[proposalId];
        if (proposal.proposedAt == 0) revert ProposalNotFound(proposalId);
        if (block.timestamp < proposal.proposedAt + governanceTimelock)
            revert ProposalNotReady(proposalId, "Timelock not elapsed");

        oracleOverride = proposal.oracleOverride;
        crossChainCircuitBreaker = proposal.circuitBreaker;
        emit OracleOverrideToggled(proposal.oracleOverride);
        emit CircuitBreakerToggled(proposal.circuitBreaker);
        delete emergencyFlagProposals[proposalId];
    }

    /// @notice Updates fallback oracles for a chain
    /// @param chainId Target chain ID
    /// @param oracles Array of fallback oracle addresses
    function updateFallbackOracles(uint16 chainId, address[] calldata oracles) external onlyGovernance {
        for (uint256 i = 0; i < oracles.length; i++) {
            if (oracles[i] == address(0) || !oracles[i].isContract())
                revert InvalidAddress(oracles[i], "Invalid oracle");
        }
        fallbackOracles[chainId] = oracles;
        emit FallbackOraclesUpdated(chainId, oracles);
    }

    /// @notice Updates proposal cooldown
    /// @param _proposalCooldown New cooldown period
    function updateProposalCooldown(uint256 _proposalCooldown) external onlyGovernance {
        if (_proposalCooldown < 1 hours) revert InvalidAmount("Cooldown too short");
        proposalCooldown = _proposalCooldown;
        emit ProposalCooldownUpdated(_proposalCooldown);
    }

    /// @notice Updates proposal fee
    /// @param _proposalFee New proposal fee
    function updateProposalFee(uint256 _proposalFee) external onlyGovernance {
        proposalFee = _proposalFee;
        emit ProposalFeeUpdated(_proposalFee);
    }

    /// @notice Cleans up old failed messages and proposals
    /// @param messageIds Array of failed message IDs
    /// @param proposalIds Array of proposal IDs
    function cleanupStorage(uint256[] calldata messageIds, uint256[] calldata proposalIds) external onlyGovernance {
        for (uint256 i = 0; i < messageIds.length; i++) {
            if (failedMessages[messageIds[i]].dstChainId != 0) {
                delete failedMessages[messageIds[i]];
                emit FailedMessageCleared(messageIds[i]);
            }
        }
        for (uint256 i = 0; i < proposalIds.length; i++) {
            GovernanceProposal storage proposal = governanceProposals[proposalIds[i]];
            if (proposal.target != address(0) && (proposal.executed || proposal.cancelled || block.timestamp > proposal.proposedAt + votingPeriod + governanceTimelock)) {
                delete governanceProposals[proposalIds[i]];
                emit GovernanceProposalCleared(proposalIds[i]);
            }
        }
    }

    /// @notice Internal function to create a single pool
    /// @param tokenA First token address
    /// @param tokenB Second token address
    /// @param primaryPriceOracle Primary oracle address
    /// @param chainId Target chain ID
    /// @param adapterParams LayerZero adapter parameters
    /// @param customSalt Custom salt for CREATE2
    /// @return pool Address of the created pool
    function _createSinglePool(
        address tokenA,
        address tokenB,
        address primaryPriceOracle,
        uint16 chainId,
        bytes calldata adapterParams,
        bytes32 customSalt
    ) internal returns (address pool) {
        if (customSalt != bytes32(0)) {
            bytes32 computedSalt = keccak256(abi.encodePacked(tokenA, tokenB, chainId, customSalt));
            if (computedSalt == bytes32(0)) revert InvalidSalt();
        }

        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        if (getPool[token0][token1] != address(0)) revert PoolAlreadyExists();

        bytes32 salt = customSalt == bytes32(0) ? keccak256(abi.encodePacked(token0, token1, chainId)) : customSalt;
        pool = address(new AMMPool{ salt: salt }());
        if (!pool.isContract()) revert InvalidAddress(pool, "Pool deployment failed");

        AMMPool(pool).initialize(
            token0,
            token1,
            treasury,
            layerZeroEndpoint,
            treasury,
            primaryPriceOracle,
            address(0),
            address(this),
            defaultTimelock,
            defaultTargetReserveRatio
        );

        _updatePoolStorage(token0, token1, pool);

        if (chainId != 1) {
            _sendCrossChainNotification(token0, token1, pool, primaryPriceOracle, chainId, adapterParams);
        }

        emit PoolCreated(token0, token1, pool, primaryPriceOracle, fallbackOracles[chainId], chainId, salt);
        return pool;
    }

    /// @notice Internal function to update pool storage
    /// @param token0 First token address (sorted)
    /// @param token1 Second token address (sorted)
    /// @param pool Pool address
    function _updatePoolStorage(address token0, address token1, address pool) internal {
        getPool[token0][token1] = pool;
        allPools.push(pool);
    }

    /// @notice Internal function to send cross-chain notification
    /// @param token0 First token address
    /// @param token1 Second token address
    /// @param pool Pool address
    /// @param primaryPriceOracle Primary oracle address
    /// @param chainId Target chain ID
    /// @param adapterParams LayerZero adapter parameters
    function _sendCrossChainNotification(
        address token0,
        address token1,
        address pool,
        address primaryPriceOracle,
        uint16 chainId,
        bytes calldata adapterParams
    ) internal {
        bytes memory payload = abi.encode(token0, token1, pool);
        (uint256 nativeFee, ) = ILayerZeroEndpoint(layerZeroEndpoint).estimateFees(
            chainId,
            address(this),
            payload,
            false,
            adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        bool success = ILayerZeroEndpoint(layerZeroEndpoint).send{ value: nativeFee }(
            chainId,
            abi.encodePacked(trustedRemoteFactories[chainId], address(this)),
            payload,
            payable(msg.sender),
            address(0),
            adapterParams
        );
        if (success) {
            if (msg.value > nativeFee) {
                AddressUpgradeable.sendValue(payable(msg.sender), msg.value - nativeFee);
            }
        } else {
            unchecked {
                failedMessages[failedMessageCount] = FailedMessage({
                    dstChainId: chainId,
                    payload: payload,
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    nextRetryTimestamp: block.timestamp + 1 hours
                });
                emit FailedMessageStored(failedMessageCount, chainId, payload);
                failedMessageCount++;
            }
        }
    }

    /// @notice Validates LayerZero adapter parameters
    /// @param adapterParams Adapter parameters to validate
    function _validateAdapterParams(bytes calldata adapterParams) internal view {
        if (adapterParams.length < 34) revert InvalidAdapterParams("Adapter params too short");
        (uint16 version, uint256 gasLimit, , address relayer) = abi.decode(adapterParams, (uint16, uint256, uint256, address));
        if (version != 1 || gasLimit < minGasLimit) revert InvalidGasLimit(gasLimit, minGasLimit);
        if (relayer == address(0)) revert InvalidAddress(relayer, "Invalid relayer");
    }

    /// @notice Validates token contracts
    /// @param tokenA First token address
    /// @param tokenB Second token address
    function _validateTokens(address tokenA, address tokenB) internal view {
        if (tokenA == address(0) || tokenB == address(0)) revert InvalidTokenAddress("Zero address not allowed");
        if (tokenA == tokenB) revert IdenticalTokens();
        // FIXED: Cache isContract results
        bool isContractA = tokenA.isContract();
        bool isContractB = tokenB.isContract();
        if (!isContractA || !isContractB) revert InvalidTokenContract(isContractA ? tokenB : tokenA, "Not a contract");
        try IERC20Upgradeable(tokenA).totalSupply() {} catch {
            revert InvalidTokenContract(tokenA, "Invalid ERC20");
        }
        try IERC20Upgradeable(tokenB).totalSupply() {} catch {
            revert InvalidTokenContract(tokenB, "Invalid ERC20");
        }
        // FIXED: Additional ERC20 checks
        try IERC20Upgradeable(tokenA).decimals() returns (uint8) {} catch {
            revert InvalidTokenContract(tokenA, "Missing decimals");
        }
        try IERC20Upgradeable(tokenB).decimals() returns (uint8) {} catch {
            revert InvalidTokenContract(tokenB, "Missing decimals");
        }
    }

    /// @notice Validates primary and fallback oracles
    /// @param primaryOracle Primary oracle address
    /// @param chainId Target chain ID
    /// @param tokenA First token address
    /// @param tokenB Second token address
    function _validateOracles(address primaryOracle, uint16 chainId, address tokenA, address tokenB) internal view {
        if (oracleOverride) return;

        bool primaryValid = false;
        uint8 primaryDecimals;
        if (primaryOracle != address(0) && primaryOracle.isContract()) {
            try IChainlinkOracle(primaryOracle).latestRoundData() returns (
                uint80,
                int256,
                uint256,
                uint256 updatedAt,
                uint80
            ) {
                if (block.timestamp <= updatedAt + maxOracleStaleness) {
                    primaryDecimals = IChainlinkOracle(primaryOracle).decimals();
                    // FIXED: Validate token pair
                    try IChainlinkOracle(primaryOracle).getPair() returns (address oracleTokenA, address oracleTokenB) {
                        if ((oracleTokenA != tokenA || oracleTokenB != tokenB) && (oracleTokenA != tokenB || oracleTokenB != tokenA)) {
                            revert InvalidTokenPair(primaryOracle, tokenA, tokenB);
                        }
                        primaryValid = true;
                    } catch {
                        emit OracleValidationFailed(primaryOracle, "Invalid token pair");
                    }
                } else {
                    emit OracleValidationFailed(primaryOracle, "Stale data");
                }
            } catch {
                emit OracleValidationFailed(primaryOracle, "Failed to fetch data");
            }
        }

        address[] memory fallbacks = fallbackOracles[chainId];
        for (uint256 i = 0; i < fallbacks.length; i++) {
            if (!primaryValid && fallbacks[i] != address(0) && fallbacks[i].isContract()) {
                try IChainlinkOracle(fallbacks[i]).latestRoundData() returns (
                    uint80,
                    int256,
                    uint256,
                    uint256 updatedAt,
                    uint80
                ) {
                    if (block.timestamp <= updatedAt + maxOracleStaleness) {
                        uint8 fallbackDecimals = IChainlinkOracle(fallbacks[i]).decimals();
                        try IChainlinkOracle(fallbacks[i]).getPair() returns (address oracleTokenA, address oracleTokenB) {
                            if ((oracleTokenA != tokenA || oracleTokenB != tokenB) && (oracleTokenA != tokenB || oracleTokenB != tokenA)) {
                                emit OracleValidationFailed(fallbacks[i], "Invalid token pair");
                                continue;
                            }
                            if (primaryValid && primaryDecimals != fallbackDecimals)
                                revert OraclePrecisionMismatch(primaryDecimals, fallbackDecimals);
                            return;
                        } catch {
                            emit OracleValidationFailed(fallbacks[i], "Invalid token pair");
                        }
                    } else {
                        emit OracleValidationFailed(fallbacks[i], "Stale data");
                    }
                } catch {
                    emit OracleValidationFailed(fallbacks[i], "Failed to fetch data");
                }
            }
        }
        if (primaryValid) {
            return;
        }
        revert NoOracleAvailable();
    }

    /// @notice Gets the effective voter, checking delegation and expiry
    /// @param account Voter address
    /// @return voter Effective voter address
    function _getVoter(address account) internal view returns (address voter) {
        Delegation memory delegation = voteDelegate[account];
        if (delegation.delegate != address(0) && (delegation.expiry == 0 || delegation.expiry > block.timestamp)) {
            return delegation.delegate;
        }
        return account;
    }

    /// @notice Internal function to handle voting logic
    /// @param proposalId ID of the proposal
    /// @param inFavor True to vote in favor, false to vote against
    /// @param voter Voter address
    function _vote(uint256 proposalId, bool inFavor, address voter) internal {
        GovernanceProposal storage proposal = governanceProposals[proposalId];
        if (proposal.target == address(0)) revert ProposalNotFound(proposalId);
        if (proposal.votingClosed || proposal.cancelled) revert VotingClosed();
        if (block.timestamp > proposal.proposedAt + votingPeriod) {
            proposal.votingClosed = true;
            emit VotingClosed(proposalId);
            revert VotingClosed();
        }
        if (hasVoted[proposalId][voter]) revert AlreadyVoted();

        uint256 power = IERC20Upgradeable(governanceToken).balanceOf(voter);
        if (power == 0) revert InsufficientVotingPower(power, 0);

        hasVoted[proposalId][voter] = true;
        unchecked {
            if (inFavor) {
                proposal.votesFor += power;
            } else {
                proposal.votesAgainst += power;
            }
        }
        emit Voted(proposalId, voter, inFavor, power);
    }

    /// @notice Allows contract to receive native tokens
    receive() external payable {}
}
