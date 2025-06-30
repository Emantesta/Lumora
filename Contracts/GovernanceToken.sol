// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

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
    address public bridgeContract;
    mapping(uint256 => bool) public supportedChainIds;
    uint256 public totalCrossChainSupply;
    enum NonceStatus { Unprocessed, Processed, Failed }
    mapping(uint256 => mapping(bytes32 => NonceStatus)) public nonceStatus;
    uint256 public maxSupply;
    uint256 public constant DEFAULT_MAX_SUPPLY = 100_000_000 * 10**18;

    // Multisig for bridge contract updates
    struct BridgeUpdateProposal {
        address newBridge;
        uint256 proposedTime;
        uint256 approvalCount;
        address[] approvers;
        bool executed;
        bool cancelled;
    }
    mapping(uint256 => BridgeUpdateProposal) public bridgeProposals;
    uint256 public proposalCount;
    uint256 public requiredApprovals;
    uint256 public bridgeUpdateDelay;
    uint256 public constant MIN_DELAY = 1 days;
    uint256 public constant MAX_DELAY = 7 days;
    uint256 public constant PROPOSAL_EXPIRY = 7 days;
    uint256 public version;
    uint256 private cachedTotalSupply;

    // Events
    event Mint(address indexed to, uint256 amount, uint256 chainId, uint256 timestamp, uint256 blockNumber);
    event Burn(address indexed from, uint256 amount, uint256 chainId, uint256 timestamp, uint256 blockNumber);
    event BridgeUpdateProposed(uint256 indexed proposalId, address indexed newBridge, uint256 proposedTime, uint256 chainId);
    event BridgeUpdateApproved(uint256 indexed proposalId, address indexed approver);
    event BridgeUpdateExecuted(uint256 indexed proposalId, address indexed newBridge, uint256 executedTime);
    event BridgeUpdateCancelled(uint256 indexed proposalId, uint256 timestamp);
    event ChainSupportUpdated(uint256 chainId, bool supported, uint256 timestamp);
    event CrossChainTransfer(address indexed to, uint256 amount, uint256 sourceChainId, bytes32 nonce, uint256 timestamp);
    event NonceReclaimed(bytes32 indexed nonce, uint256 chainId, uint256 timestamp);
    event BridgeUpdateDelaySet(uint256 oldDelay, uint256 newDelay, uint256 timestamp);
    event RequiredApprovalsSet(uint256 oldRequiredApprovals, uint256 newRequiredApprovals, uint256 timestamp);
    event BridgeRevoked(address indexed oldBridge, address indexed fallbackBridge, uint256 timestamp);
    event MaxSupplySet(uint256 oldMaxSupply, uint256 newMaxSupply, uint256 timestamp);
    event EmergencyBridgePause(bool paused, uint256 timestamp);
    event VersionUpgraded(uint256 version, address indexed newImplementation, uint256 timestamp);

    // Modifiers
    modifier onlyContract(address _addr) {
        require(_addr.code.length > 0, "GovernanceToken: not a contract");
        _;
    }

    bool private bridgePaused;
    modifier whenBridgeNotPaused() {
        require(!bridgePaused, "GovernanceToken: bridge paused");
        _;
    }

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
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(BRIDGE_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);

        uint256 initialSupply = 1_000_000 * 10**18;
        require(initialSupply <= initialMaxSupply, "GovernanceToken: initial supply exceeds max");
        _mint(admin, initialSupply);
        maxSupply = initialMaxSupply;
        cachedTotalSupply = initialSupply;
        supportedChainIds[block.chainid] = true;
        requiredApprovals = initialRequiredApprovals;
        bridgeUpdateDelay = MIN_DELAY;
        bridgeContract = initialBridge;
        version = 1;

        emit MaxSupplySet(0, initialMaxSupply, block.timestamp);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) onlyContract(newImplementation) {
        version++;
        emit VersionUpgraded(version, newImplementation, block.timestamp);
    }

    function setBridgeUpdateDelay(uint256 newDelay) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newDelay >= MIN_DELAY && newDelay <= MAX_DELAY, "GovernanceToken: invalid delay");
        uint256 oldDelay = bridgeUpdateDelay;
        bridgeUpdateDelay = newDelay;
        emit BridgeUpdateDelaySet(oldDelay, newDelay, block.timestamp);
    }

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

    function hasApproved(uint256 proposalId, address approver) private view returns (bool) {
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalId];
        for (uint256 i = 0; i < proposal.approvers.length; i++) {
            if (proposal.approvers[i] == approver) {
                return true;
            }
        }
        return false;
    }

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

    function cancelBridgeContractProposal(uint256 proposalId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        BridgeUpdateProposal storage proposal = bridgeProposals[proposalId];
        require(proposal.newBridge != address(0), "GovernanceToken: invalid proposal");
        require(!proposal.executed, "GovernanceToken: already executed");
        require(!proposal.cancelled, "GovernanceToken: already cancelled");

        proposal.cancelled = true;
        emit BridgeUpdateCancelled(proposalId, block.timestamp);
    }

    function revokeBridgeContract(address fallbackBridge) external onlyRole(DEFAULT_ADMIN_ROLE) onlyContract(fallbackBridge) {
        require(bridgeContract != address(0), "GovernanceToken: no bridge set");
        address oldBridge = bridgeContract;
        bridgeContract = fallbackBridge;
        emit BridgeRevoked(oldBridge, fallbackBridge, block.timestamp);
    }

    function updateChainSupport(uint256 chainId, bool supported) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedChainIds[chainId] = supported;
        emit ChainSupportUpdated(chainId, supported, block.timestamp);
    }

    function mint(address to, uint256 amount, uint256 chainId) external whenNotPaused whenBridgeNotPaused nonReentrant {
        require(hasRole(MINTER_ROLE, msg.sender) || (msg.sender == bridgeContract && bridgeContract != address(0)), "GovernanceToken: unauthorized");
        require(supportedChainIds[chainId], "GovernanceToken: unsupported chain");
        require(to != address(0), "GovernanceToken: invalid recipient");
        require(cachedTotalSupply + amount <= maxSupply, "GovernanceToken: exceeds max supply");

        _mint(to, amount);
        cachedTotalSupply += amount;
        if (chainId != block.chainid) {
            totalCrossChainSupply += amount;
        }
        emit Mint(to, amount, chainId, block.timestamp, block.number);
    }

    function burn(uint256 amount, uint256 chainId) external whenNotPaused nonReentrant {
        require(supportedChainIds[chainId], "GovernanceToken: unsupported chain");
        _burn(msg.sender, amount);
        cachedTotalSupply -= amount;
        if (chainId != block.chainid) {
            require(totalCrossChainSupply >= amount, "GovernanceToken: insufficient cross-chain supply");
            totalCrossChainSupply -= amount;
        }
        emit Burn(msg.sender, amount, chainId, block.timestamp, block.number);
    }

    function bridgeTransfer(address to, uint256 amount, uint256 sourceChainId, bytes32 nonce) external whenNotPaused whenBridgeNotPaused nonReentrant {
        require(msg.sender == bridgeContract && bridgeContract != address(0), "GovernanceToken: invalid bridge");
        require(supportedChainIds[sourceChainId], "GovernanceToken: unsupported source chain");
        require(nonce != bytes32(0), "GovernanceToken: invalid nonce");
        require(nonceStatus[sourceChainId][nonce] == NonceStatus.Unprocessed, "GovernanceToken: nonce invalid");
        require(to != address(0), "GovernanceToken: invalid recipient");
        require(cachedTotalSupply + amount <= maxSupply, "GovernanceToken: exceeds max supply");

        _mint(to, amount);
        nonceStatus[sourceChainId][nonce] = NonceStatus.Processed;
        totalCrossChainSupply += amount;
        cachedTotalSupply += amount;
        emit CrossChainTransfer(to, amount, sourceChainId, nonce, block.timestamp);
    }

    function markNonceFailed(bytes32 nonce, uint256 sourceChainId) external onlyRole(BRIDGE_ADMIN_ROLE) {
        require(nonceStatus[sourceChainId][nonce] == NonceStatus.Unprocessed, "GovernanceToken: nonce invalid");
        nonceStatus[sourceChainId][nonce] = NonceStatus.Failed;
    }

    function reclaimNonce(bytes32 nonce, uint256 sourceChainId) external onlyRole(BRIDGE_ADMIN_ROLE) {
        require(nonceStatus[sourceChainId][nonce] == NonceStatus.Failed, "GovernanceToken: nonce not failed");
        nonceStatus[sourceChainId][nonce] = NonceStatus.Unprocessed;
        emit NonceReclaimed(nonce, sourceChainId, block.timestamp);
    }

    function transfer(address to, uint256 amount) public virtual override whenNotPaused returns (bool) {
        return super.transfer(to, amount);
    }

    function totalSupply() public view virtual override returns (uint256) {
        return cachedTotalSupply;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function setRequiredApprovals(uint256 newRequiredApprovals) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newRequiredApprovals > 0, "GovernanceToken: invalid approval count");
        uint256 oldRequiredApprovals = requiredApprovals;
        requiredApprovals = newRequiredApprovals;
        emit RequiredApprovalsSet(oldRequiredApprovals, newRequiredApprovals, block.timestamp);
    }

    function setMaxSupply(uint256 newMaxSupply) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newMaxSupply >= cachedTotalSupply, "GovernanceToken: new max supply too low");
        uint256 oldMaxSupply = maxSupply;
        maxSupply = newMaxSupply;
        emit MaxSupplySet(oldMaxSupply, newMaxSupply, block.timestamp);
    }

    function setBridgePaused(bool paused) external onlyRole(PAUSER_ROLE) {
        _setBridgePaused(paused);
        emit EmergencyBridgePause(paused, block.timestamp);
    }

    function _setBridgePaused(bool paused) internal {
        bridgePaused = paused;
    }
}