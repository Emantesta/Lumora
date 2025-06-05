// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/**
 * @title DebtToken
 * @dev Upgradeable ERC20 token representing user debt in a lending protocol
 * @notice Tracks debt for a specific asset, minted when borrowing and burned upon repayment.
 *         Only the owner (LendingPool) can mint/burn tokens. Supports pausing, upgrades with a timelock,
 *         and reentrancy protection for future-proofing.
 */
contract DebtToken is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    /// @notice Address of the underlying asset (e.g., USDC) associated with this debt token
    address public underlyingAsset;

    /// @notice Delay for contract upgrades (in seconds)
    uint256 public upgradeDelay;
    /// @notice Timestamp when the proposed upgrade can be executed
    uint256 public upgradeProposalTime;
    /// @notice Proposed new implementation address for the upgrade
    address public proposedImplementation;

    /// @notice Emitted when debt tokens are minted
    event DebtMinted(address indexed user, address indexed underlyingAsset, uint256 amount);
    /// @notice Emitted when debt tokens are burned
    event DebtRepaid(address indexed user, address indexed underlyingAsset, uint256 amount);
    /// @notice Emitted when an upgrade is proposed
    event UpgradeProposed(address indexed newImplementation, uint256 proposalTime);
    /// @notice Emitted when debt tokens are minted in batch
    event BatchDebtMinted(address[] recipients, uint256[] amounts);
    /// @notice Emitted when debt tokens are burned in batch
    event BatchDebtRepaid(address[] accounts, uint256[] amounts);

    /**
     * @dev Constructor is replaced by initializer for upgradeable contracts
     * @param name_ Token name (e.g., "Debt USDC")
     * @param symbol_ Token symbol (e.g., "dUSDC")
     * @param _underlyingAsset Address of the underlying asset (e.g., USDC)
     * @param _upgradeDelay Delay for upgrades in seconds (min 1 hour, max 30 days)
     */
    function initialize(string memory name_, string memory symbol_, address _underlyingAsset, uint256 _upgradeDelay) public initializer {
        require(_underlyingAsset != address(0), "Invalid underlying asset address");
        require(_upgradeDelay >= 1 hours && _upgradeDelay <= 30 days, "Invalid upgrade delay");
        __ERC20_init(name_, symbol_);
        underlyingAsset = _underlyingAsset;
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        upgradeDelay = _upgradeDelay;
    }

    /**
     * @notice Mints debt tokens to a user, representing new debt
     * @dev Only callable by the owner (LendingPool) when not paused, with reentrancy protection
     * @param to Address receiving the debt tokens
     * @param amount Amount of debt tokens to mint, in wei
     */
    function mint(address to, uint256 amount) external onlyOwner whenNotPaused nonReentrant {
        require(to != address(0), "Invalid address");
        require(amount > 0, "Amount must be greater than zero");
        _mint(to, amount);
        emit DebtMinted(to, underlyingAsset, amount);
    }

    /**
     * @notice Burns debt tokens from a user, representing debt repayment
     * @dev Only callable by the owner (LendingPool) when not paused, with reentrancy protection
     * @param from Address from which to burn debt tokens
     * @param amount Amount of debt tokens to burn, in wei
     */
    function burn(address from, uint256 amount) external onlyOwner whenNotPaused nonReentrant {
        require(from != address(0), "Invalid address");
        require(amount > 0, "Amount must be greater than zero");
        _burn(from, amount);
        emit DebtRepaid(from, underlyingAsset, amount);
    }

    /**
     * @notice Mints debt tokens to multiple users in a single transaction
     * @dev Only callable by the owner (LendingPool) when not paused, with reentrancy protection
     * @param recipients Array of addresses receiving the debt tokens
     * @param amounts Array of amounts to mint for each recipient
     */
    function batchMint(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner whenNotPaused nonReentrant {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        require(recipients.length > 0, "Empty arrays");
        require(recipients.length <= 100, "Batch size too large");
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid address");
            require(amounts[i] > 0, "Amount must be greater than zero");
            _mint(recipients[i], amounts[i]);
        }
        emit BatchDebtMinted(recipients, amounts);
    }

    /**
     * @notice Burns debt tokens from multiple users in a single transaction
     * @dev Only callable by the owner (LendingPool) when not paused, with reentrancy protection
     * @param accounts Array of addresses from which to burn debt tokens
     * @param amounts Array of amounts to burn for each account
     */
    function batchBurn(address[] calldata accounts, uint256[] calldata amounts) external onlyOwner whenNotPaused nonReentrant {
        require(accounts.length == amounts.length, "Arrays length mismatch");
        require(accounts.length > 0, "Empty arrays");
        require(accounts.length <= 100, "Batch size too large");
        for (uint256 i = 0; i < accounts.length; i++) {
            require(accounts[i] != address(0), "Invalid address");
            require(amounts[i] > 0, "Amount must be greater than zero");
            _burn(accounts[i], amounts[i]);
        }
        emit BatchDebtRepaid(accounts, amounts);
    }

    /**
     * @notice Pauses minting and burning operations
     * @dev Only callable by the owner
     */
    function pause() external onlyOwner {
        _pause();
        emit Paused(msg.sender);
    }

    /**
     * @notice Unpauses minting and burning operations
     * @dev Only callable by the owner
     */
    function unpause() external onlyOwner {
        _unpause();
        emit Unpaused(msg.sender);
    }

    /**
     * @notice Proposes a new implementation for the contract upgrade
     * @dev Only callable by the owner. The upgrade can only be executed after the timelock period (upgradeDelay) has passed.
     * @param newImplementation Address of the new contract implementation
     */
    function proposeUpgrade(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid implementation address");
        upgradeProposalTime = block.timestamp + upgradeDelay;
        proposedImplementation = newImplementation;
        emit UpgradeProposed(newImplementation, upgradeProposalTime);
    }

    /**
     * @dev Authorizes the upgrade to the proposed implementation after the timelock period
     * @param newImplementation Address of the new contract implementation
     * @notice Only callable by the owner. The newImplementation must match the proposedImplementation, and the timelock must have elapsed.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        require(newImplementation == proposedImplementation, "Invalid implementation");
        require(block.timestamp >= upgradeProposalTime, "Timelock not elapsed");
        require(upgradeProposalTime > 0, "No upgrade proposed");
        upgradeProposalTime = 0;
        proposedImplementation = address(0);
    }

    /**
     * @notice Returns the proposed implementation address
     * @return Address of the proposed implementation
     */
    function getProposedImplementation() external view returns (address) {
        return proposedImplementation;
    }

    /**
     * @notice Returns the timestamp when the proposed upgrade can be executed
     * @return Timestamp of the proposed upgrade
     */
    function getUpgradeProposalTime() external view returns (uint256) {
        return upgradeProposalTime;
    }

    /**
     * @notice Disables token transfers
     * @dev Debt tokens are non-transferable to ensure protocol integrity
     */
    function transfer(address, uint256) public virtual override returns (bool) {
        revert("DebtToken: Transfers are disabled");
    }

    /**
     * @notice Disables token transfers
     * @dev Debt tokens are non-transferable to ensure protocol integrity
     */
    function transferFrom(address, address, uint256) public virtual override returns (bool) {
        revert("DebtToken: Transfers are disabled");
    }
}
