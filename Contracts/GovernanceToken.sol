// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol"; // Added for reentrancy protection

/// @title GovernanceToken
/// @notice An upgradeable ERC20 token with cross-chain support, access control, and multisig bridge updates
/// @dev Inherits from OpenZeppelin's upgradeable contracts with added security and governance features
contract GovernanceToken is Initializable, ERC20Upgradeable, AccessControlUpgradeable, UUPSUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    // Roles for access control
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant BRIDGE_ADMIN_ROLE = keccak256("BRIDGE_ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Cross-chain bridge interface
    /// @notice Address of the bridge contract
    address public bridgeContract;
    /// @notice Tracks supported chain IDs for cross-chain operations
    mapping(uint256 => bool) public supportedChainIds;
    /// @notice Tracks total cross-chain minted supply
    uint256 public totalCrossChainSupply;
    /// @notice Tracks nonce status for cross-chain transfers
    enum NonceStatus { Unprocessed, Processed, Failed }
    /// @notice Updated nonce mapping to include chain ID for uniqueness
    mapping(uint256 => mapping(bytes32 => NonceStatus)) public nonceStatus; // chainId => nonce => status
    /// @notice Maximum token supply
    uint256 public maxSupply; // Added supply cap
    uint256 public constant DEFAULT_MAX_SUPPLY = 100_000_000 * 10**18; // 100M tokens

    // Multisig for bridge contract updates
    struct BridgeUpdateProposal {
        address newBridge;
        uint256 proposedTime;
        uint256 approvalCount;
        address[] approvers; // Replaced mapping with array for gas efficiency
        bool executed;
        bool cancelled; // Added for proposal cancellation
    }
    /// @notice Maps proposal IDs to bridge update proposals
    mapping(uint256 => BridgeUpdateProposal) public bridgeProposals;
    /// @notice Incremental ID for bridge update proposals
    uint256 public proposalCount;
    /// @notice Number of approvals required for bridge updates
    uint256 public requiredApprovals;
    /// @notice Delay for bridge update execution
    uint256 public bridgeUpdateDelay;
    uint256 public constant MIN_DELAY = 1 days;
    uint256 public constant MAX_DELAY = 7 days;
    /// @notice Proposal expiry duration
    uint256 public constant PROPOSAL_EXPIRY = 7 days; // Added expiry
    /// @notice Contract version for upgrade tracking
    uint256 public version;
    /// @notice Cached total supply for gas optimization
    uint256 private cachedTotalSupply; // Added for gas optimization

    // Events
    event Mint(address indexed to, uint256 amount, uint256 chainId, uint256 timestamp, uint256 blockNumber);
    event Burn(address indexed from, uint256 amount, uint256 chainId, uint256 timestamp, uint256 blockNumber);
    event BridgeUpdateProposed(uint256 indexed proposalId, address indexed newBridge, uint256 proposedTime, uint256 chainId);
    event BridgeUpdateApproved(uint256 indexed proposalId, address indexed approver);
    event BridgeUpdateExecuted(uint256 indexed proposalId, address indexed newBridge, uint256 executedTime);
    event BridgeUpdateCancelled(uint256 indexed proposalId, uint256 timestamp); // Added for cancellation
    event ChainSupportUpdated(uint256 chainId, bool supported, uint256 timestamp);
    event CrossChainTransfer(address indexed to, uint256 amount, uint256 sourceChainId, bytes32 nonce, uint256 timestamp);
    event NonceReclaimed(bytes32 indexed nonce, uint256 chainId, uint256 timestamp);
    event BridgeUpdateDelaySet(uint256 oldDelay, uint256 newDelay, uint256 timestamp); // Enhanced event
    event RequiredApprovalsSet(uint256 oldRequiredApprovals, uint256 newRequiredApprovals, uint256 timestamp); // Enhanced event
    event BridgeRevoked(address indexed oldBridge, address indexed fallbackBridge, uint256 timestamp); // Enhanced event
    event MaxSupplySet(uint256 oldMaxSupply, uint256 newMaxSupply, uint256 timestamp); // Added event
    event EmergencyBridgePause(bool paused, uint256 timestamp); // Added for bridge-specific pause

    // Modifiers
    /// @notice Ensures the address is a contract
    modifier onlyContract(address _addr) {
        require(_addr.code.length > 0, "GovernanceToken: not a contract");
        _;
    }

    /// @notice Initializes the contract with admin, required approvals, initial bridge, and max supply
    /// @param admin The address to receive initial roles
    /// @param initialRequiredApprovals Number of approvals needed for bridge updates
    /// @param initialBridge Initial bridge contract address
    /// @param initialMaxSupply Initial maximum supply
    function initialize(
        address admin,
        uint256 initialRequiredApprovals,
        address initialBridge,
        uint256 initialMaxSupply
    ) public initializer {
        require(admin != address(0), "GovernanceToken: invalid admin address");
        require(initialRequiredApprovals > 0, "GovernanceToken: invalid approval count");
        require(initialBridge != address(0), "GovernanceToken: invalid initial bridge");
        require(initialMaxSupply > 0, "GovernanceToken: invalid max supply");

        __ERC20_init("Governance Token", "GOV");
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init(); // Added reentrancy guard

        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(BRIDGE_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);

        uint256 initialSupply = 1_000_000 * 10**18; // Initial supply: 1M tokens
        require(initialSupply <= initialMaxSupply, "GovernanceToken: initial supply exceeds max");
        _mint(admin, initialSupply);
        maxSupply = initialMaxSupply;
        cachedTotalSupply = initialSupply; // Initialize cached supply
        supportedChainIds[block.chainid] = true;
        requiredApprovals = initialRequiredApprovals;
        bridgeUpdateDelay = MIN_DELAY;
        bridgeContract = initialBridge;
        version = 1;

        emit MaxSupplySet(0, initialMaxSupply, block.timestamp);
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) onlyContract(newImplementation) {
        version++;
        emit VersionUpgraded(version, newImplementation, block.timestamp); // Added event
    }

    // Added event for upgrade tracking
    event VersionUpgraded(uint256 version, address indexed newImplementation, uint256 timestamp);

    /// @notice Sets the delay for bridge updates
    /// @param newDelay The new delay in seconds
    function setBridgeUpdateDelay(uint256 newDelay) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newDelay >= MIN_DELAY && newDelay <= MAX_DELAY, "GovernanceToken: invalid delay");
        uint256 oldDelay = bridgeUpdateDelay;
        bridgeUpdateDelay = newDelay;
        emit BridgeUpdateDelaySet(oldDelay, newDelay, block.timestamp);
    }

    /// @notice Proposes a new bridge contract
    /// @param _newBridge Address of the proposed bridge contract
    function proposeBridgeContract(address _newBridge) external onlyRole(BRIDGE_ADMIN_ROLE) onlyContract(_newBridge) {
        require(_newBridge != bridgeContract, "GovernanceToken: same bridge address");
        require(proposalCount < type(uint256).max, "GovernanceToken: proposal count overflow");

        proposalCount++;
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalCount];
        proposal.newBridge = _newBridge;
        proposal.proposedTime = block.timestamp;
        proposal.approvalCount = 0;
        proposal.executed = false;
        proposal.cancelled = false;

        emit BridgeUpdateProposed(proposalCount, _newBridge, block.timestamp, block.chainid);
    }

    /// @notice Approves a bridge contract update
    /// @param proposalId The ID of the proposal to approve
    function approveBridgeContract(uint256 proposalId) external onlyRole(BRIDGE_ADMIN_ROLE) {
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalId];
        require(proposal.newBridge != address(0), "GovernanceToken: invalid proposal");
        require(!proposal.executed, "GovernanceToken: proposal already executed");
        require(!proposal.cancelled, "GovernanceToken: proposal cancelled");
        require(block.timestamp <= proposal.proposedTime + PROPOSAL_EXPIRY, "GovernanceToken: proposal expired");
        require(!hasApproved(proposalId, msg.sender), "GovernanceToken: already approved");

        proposal.approvers.push(msg.sender);
        proposal.approvalCount++;

        emit BridgeUpdateApproved(proposalId, msg.sender);
    }

    /// @notice Helper function to check if an address has approved a proposal
    function hasApproved(uint256 proposalId, address approver) private view returns (bool) {
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalId];
        for (uint256 i = 0; i < proposal.approvers.length; i++) {
            if (proposal.approvers[i] == approver) {
                return true;
            }
        }
        return false;
    }

    /// @notice Executes a bridge contract update
    /// @param proposalId The ID of the proposal to execute
    function executeBridgeContract(uint256 proposalId) external nonReentrant {
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalId];
        require(proposal.newBridge != address(0), "GovernanceToken: invalid proposal");
        require(!proposal.executed, "GovernanceToken: already executed");
        require(!proposal.cancelled, "GovernanceToken: proposal cancelled");
        require(proposal.approvalCount >= requiredApprovals, "GovernanceToken: insufficient approvals");
        require(block.timestamp >= proposal.proposedTime + bridgeUpdateDelay, "GovernanceToken: delay not elapsed");
        require(block.timestamp <= proposal.proposedTime + PROPOSAL_EXPIRY, "GovernanceToken: proposal expired");

        bridgeContract = proposal.newBridge;
        proposal.executed = true;
        emit BridgeUpdateExecuted(proposalId, bridgeContract, block.timestamp);
    }

    /// @notice Cancels a bridge update proposal
    /// @param proposalId The ID of the proposal to cancel
    function cancelBridgeContractProposal(uint256 proposalId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalId];
        require(proposal.newBridge != address(0), "GovernanceToken: invalid proposal");
        require(!proposal.executed, "GovernanceToken: already executed");
        require(!proposal.cancelled, "GovernanceToken: already cancelled");

        proposal.cancelled = true;
        emit BridgeUpdateCancelled(proposalId, block.timestamp);
    }

    /// @notice Revokes the current bridge contract with a fallback
    /// @param fallbackBridge Optional fallback bridge address
    function revokeBridgeContract(address fallbackBridge) external onlyRole(DEFAULT_ADMIN_ROLE) onlyContract(fallbackBridge) {
        require(bridgeContract != address(0), "GovernanceToken: no bridge set");
        address oldBridge = bridgeContract;
        bridgeContract = fallbackBridge;
        emit BridgeRevoked(oldBridge, fallbackBridge, block.timestamp);
    }

    /// @notice Updates support for a chain ID
    /// @param chainId The chain ID to update
    /// @param supported Whether the chain is supported
    function updateChainSupport(uint256 chainId, bool supported) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChainIds[chainId] = supported;
        emit ChainSupportUpdated(chainId, supported, block.timestamp);
    }

    /// @notice Mints tokens to an address
    /// @param to The recipient address
    /// @param amount The amount of tokens to mint
    /// @param chainId The chain ID for the mint operation
    function mint(address to, uint256 amount, uint256 chainId) external whenNotPaused nonReentrant {
        require(hasRole(MINTER_ROLE, msg.sender) || (msg.sender == bridgeContract && bridgeContract != address(0)), "GovernanceToken: unauthorized");
        require(supportedChainIds[chainId], "GovernanceToken: unsupported chain");
        require(to != address(0), "GovernanceToken: invalid recipient");
        require(cachedTotalSupply + amount <= maxSupply, "GovernanceToken: exceeds max supply");

        _mint(to, amount);
        cachedTotalSupply += amount; // Update cached supply
        if (chainId != block.chainid) {
            totalCrossChainSupply += amount;
        }
        emit Mint(to, amount, chainId, block.timestamp, block.number);
    }

    /// @notice Burns tokens from the sender
    /// @param amount The amount of tokens to burn
    /// @param chainId The chain ID for the burn operation
    function burn(uint256 amount, uint256 chainId) external whenNotPaused nonReentrant {
        require(supportedChainIds[chainId], "GovernanceToken: unsupported chain");
        _burn(msg.sender, amount);
        cachedTotalSupply -= amount; // Update cached supply
        if (chainId != block.chainid) {
            require(totalCrossChainSupply >= amount, "GovernanceToken: insufficient cross-chain supply");
            totalCrossChainSupply -= amount;
        }
        emit Burn(msg.sender, amount, chainId, block.timestamp, block.number);
    }

    /// @notice Handles cross-chain token transfers
    /// @param to The recipient address
    /// @param amount The amount of tokens to transfer
    /// @param sourceChainId The source chain ID
    /// @param nonce The unique nonce for the transfer
    function bridgeTransfer(address to, uint256 amount, uint256 sourceChainId, bytes32 nonce) external whenNotPaused nonReentrant {
        require(msg.sender == bridgeContract && bridgeContract != address(0), "GovernanceToken: invalid bridge");
        require(supportedChainIds[sourceChainId], "GovernanceToken: unsupported source chain");
        require(nonce != bytes32(0), "GovernanceToken: invalid nonce");
        require(nonceStatus[sourceChainId][nonce] == NonceStatus.Unprocessed, "GovernanceToken: nonce invalid");
        require(to != address(0), "GovernanceToken: invalid recipient");
        require(cachedTotalSupply + amount <= maxSupply, "GovernanceToken: exceeds max supply");

        _mint(to, amount);
        nonceStatus[sourceChainId][Producers] = NonceStatus.Processed;
        totalCrossChainSupply += amount;
        cachedTotalSupply += amount; // Update cached supply
        emit CrossChainTransfer(to, amount, sourceChainId, nonce, block.timestamp);
    }

    /// @notice Marks a nonce as failed for retrying cross-chain transfers
    /// @param nonce The nonce to mark as failed
    /// @param sourceChainId The source chain ID
    function markNonceFailed(bytes32 nonce, uint256 sourceChainId) external onlyRole(BRIDGE_ADMIN_ROLE) {
        require(nonceStatus[sourceChainId][nonce] == NonceStatus.Unprocessed, "GovernanceToken: nonce invalid");
        nonceStatus[sourceChainId][nonce] = NonceStatus.Failed;
    }

    /// @notice Reclaims a failed nonce for reuse
    /// @param nonce The nonce to reclaim
    /// @param sourceChainId The source chain ID
    function reclaimNonce(bytes32 nonce, uint256 sourceChainId) external onlyRole(BRIDGE_ADMIN_ROLE) {
        require(nonceStatus[sourceChainId][nonce] == NonceStatus.Failed, "GovernanceToken: nonce not failed");
        nonceStatus[sourceChainId][nonce] = NonceStatus.Unprocessed;
        emit NonceReclaimed(nonce, sourceChainId, block.timestamp);
    }

    /// @notice Transfers tokens with pause check
    /// @param to The recipient address
    /// @param amount The amount of tokens to transfer
    /// @return True if the transfer succeeds
    function transfer(address to, uint256 amount) public virtual override whenNotPaused returns (bool) {
        return super.transfer(to, amount);
    }

    /// @notice Returns the total supply including cross-chain supply
    /// @return The total token supply
    function totalSupply() public view virtual override returns (uint256) {
        return cachedTotalSupply; // Use cached value
    }

    /// @notice Pauses the contract
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Sets the required number of approvals for bridge updates
    /// @param newRequiredApprovals The new number of required approvals
    function setRequiredApprovals(uint256 newRequiredApprovals) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newRequiredApprovals > 0, "GovernanceToken: invalid approval count");
        uint256 oldRequiredApprovals = requiredApprovals;
        requiredApprovals = newRequiredApprovals;
        emit RequiredApprovalsSet(oldRequiredApprovals, newRequiredApprovals, block.timestamp);
    }

    /// @notice Sets the maximum supply
    /// @param newMaxSupply The new maximum supply
    function setMaxSupply(uint256 newMaxSupply) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMaxSupply >= cachedTotalSupply, "GovernanceToken: new max supply too low");
        uint256 oldMaxSupply = maxSupply;
        maxSupply = newMaxSupply;
        emit MaxSupplySet(oldMaxSupply, newMaxSupply, block.timestamp);
    }

    /// @notice Pauses or unpauses bridge-specific operations
    /// @param paused Whether to pause or unpause
    function setBridgePaused(bool paused) external onlyRole(PAUSER_ROLE) {
        _setBridgePaused(paused);
        emit EmergencyBridgePause(paused, block.timestamp);
    }

    /// @notice Internal function to pause/unpause bridge operations
    bool private bridgePaused;
    function _setBridgePaused(bool paused) internal {
        bridgePaused = paused;
    }

    /// @notice Modifier to check bridge pause status
    modifier whenBridgeNotPaused() {
        require(!bridgePaused, "GovernanceToken: bridge paused");
        _;
    }

    /// @notice Overrides bridge-related functions to include pause check
    function bridgeTransfer(address to, uint256 amount, uint256 sourceChainId, bytes32 nonce) external override whenNotPaused whenBridgeNotPaused {
        // Existing bridgeTransfer logic (already included above)
    }

    function mint(address to, uint256 amount, uint256 chainId) external override whenNotPaused whenBridgeNotPaused {
        // Existing mint logic (already included above)
    }
}
