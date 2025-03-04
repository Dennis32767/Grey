// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GreyStone is ERC20, Ownable, Pausable, ReentrancyGuard, AccessControl {
    using ECDSA for bytes32; // Use ECDSA library for secure signature verification

    // Roles
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 private constant MINER_ROLE = keccak256("MINER_ROLE");
    bytes32 private constant REWARD_MANAGER_ROLE = keccak256("REWARD_MANAGER_ROLE");

    // Token supply constants
    uint256 private constant INITIAL_SUPPLY = 700000000 * 1e18; // 700,000,000 GREY tokens

    // Step reward constants
    uint256 private constant DAILY_STEP_GOAL = 10000; // 10,000 steps per day
    uint256 private constant MAX_STEPS = 100000; // Maximum steps per day
    uint256 public rewardPerDay = 10 * 1e18; // 10 GREY tokens per day for meeting the goal

    // Burning fee
    uint256 private constant BURN_FEE = 1 * 1e18; // 1 GREY token as a burning fee

    // User data struct
    struct UserData {
        uint256 dailySteps;
        uint256 lastUpdateBlock; // Use block number instead of timestamp
        uint256 nonce;
    }

    // State variables
    mapping(address => UserData) public userData; // Tracks user data
    uint256 public totalMined; // Total GREY tokens mined via rewards
    uint256 public pauseTimelock; // Timelock duration for pausing/unpausing
    uint256 public roleChangeTimelock; // Timelock duration for role changes
    uint256 public blocksPerDay; // Number of blocks per day (default: 5760 blocks ≈ 1 day)

    // Off-chain metadata URI
    string private _contractMetadataURI; // URI for contract metadata (off-chain)

    // Events
    event StepsLogged(address indexed user, uint256 steps);
    event RewardEarned(address indexed user, uint256 amount);
    event MinerRoleGranted(address indexed account);
    event MinerRoleRevoked(address indexed account);
    event OperatorRoleGranted(address indexed account);
    event OperatorRoleRevoked(address indexed account);
    event RewardManagerRoleGranted(address indexed account);
    event RewardManagerRoleRevoked(address indexed account);
    event ContractPaused();
    event ContractUnpaused();
    event TokensBurned(address indexed burner, uint256 amount);
    event PauseTimelockUpdated(uint256 newTimelock);
    event RoleChangeTimelockUpdated(uint256 newTimelock);
    event RewardPerDayUpdated(uint256 newReward);
    event ContractMetadataUpdated(string newMetadataURI);
    event BlocksPerDayUpdated(uint256 newBlocksPerDay);

    constructor() ERC20("GreyStone", "GREY") {
        // Mint initial supply to the deployer
        _mint(msg.sender, INITIAL_SUPPLY);

        // Grant roles to the deployer
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
        _setupRole(OPERATOR_ROLE, msg.sender);
        _setupRole(MINER_ROLE, msg.sender);
        _setupRole(REWARD_MANAGER_ROLE, msg.sender);

        // Initialize timelocks (e.g., 1 day in blocks, assuming ~15 seconds per block)
        blocksPerDay = 5760; // 5760 blocks ≈ 1 day
        pauseTimelock = block.number + blocksPerDay;
        roleChangeTimelock = block.number + blocksPerDay;
    }

    /**
     * @dev Log steps with signature verification and nonce.
     * @param steps The number of steps logged by the user.
     * @param blockNumber The block number of the step logging.
     * @param signature The signature verifying the step data.
     */
    function logSteps(uint256 steps, uint256 blockNumber, bytes memory signature) external nonReentrant whenNotPaused {
        // Validate inputs
        require(steps != 0 && steps <= MAX_STEPS, "Invalid steps");
        require(block.number >= blockNumber - 240, "Invalid block number"); // 240 blocks ≈ 1 hour
        require(block.number <= blockNumber + 240, "Invalid block number"); // 240 blocks ≈ 1 hour
        require(verifySignature(msg.sender, steps, blockNumber, userData[msg.sender].nonce, signature), "Invalid signature");
        require(block.number > userData[msg.sender].lastUpdateBlock + blocksPerDay, "Steps already logged"); // 1 day cooldown

        // Update user data
        userData[msg.sender].dailySteps = steps;
        userData[msg.sender].lastUpdateBlock = blockNumber;
        userData[msg.sender].nonce++; // Increment nonce to prevent replay attacks

        // Reward user if they meet the daily step goal
        if (steps >= DAILY_STEP_GOAL) {
            _mint(msg.sender, rewardPerDay); // Reward the user with GREY tokens
            totalMined += rewardPerDay;
            emit RewardEarned(msg.sender, rewardPerDay);
        }

        emit StepsLogged(msg.sender, steps);
    }

    /**
     * @dev Verify the signature for step data.
     * @param user The address of the user.
     * @param steps The number of steps.
     * @param blockNumber The block number of the step logging.
     * @param nonce The nonce for replay protection.
     * @param signature The signature to verify.
     * @return bool True if the signature is valid, false otherwise.
     */
    function verifySignature(
        address user,
        uint256 steps,
        uint256 blockNumber,
        uint256 nonce,
        bytes memory signature
    ) private pure returns (bool) {
        // Ensure the signature length is 65 bytes
        if (signature.length != 65) {
            return false;
        }

        // Create the message hash
        bytes32 messageHash = keccak256(abi.encodePacked(user, steps, blockNumber, nonce));
        // Convert the message hash to an Ethereum signed message hash
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        // Recover the signer's address from the signature
        try ethSignedMessageHash.recover(signature) returns (address recoveredSigner) {
            // Ensure the recovered signer is not address(0) and matches the expected user
            return (recoveredSigner != address(0) && recoveredSigner == user);
        } catch {
            revert("Signature recovery failed"); // Add error message for failed recovery
        }
    }

    /**
     * @dev Set the number of blocks per day (only DEFAULT_ADMIN_ROLE).
     * @param newBlocksPerDay The new number of blocks per day.
     */
    function setBlocksPerDay(uint256 newBlocksPerDay) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(newBlocksPerDay != blocksPerDay, "No change in value");
        blocksPerDay = newBlocksPerDay;
        emit BlocksPerDayUpdated(newBlocksPerDay);
    }

    /**
     * @dev Grant MINER_ROLE to an account (only DEFAULT_ADMIN_ROLE or OPERATOR_ROLE).
     * @param account The address to grant the role to.
     */
    function grantMinerRole(address account) external nonReentrant {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(OPERATOR_ROLE, msg.sender),
            "Unauthorized"
        );
        require(account != address(0), "Invalid account");
        require(block.number >= roleChangeTimelock, "Timelock not expired");

        _grantRole(MINER_ROLE, account);
        emit MinerRoleGranted(account);
    }

    /**
     * @dev Revoke MINER_ROLE from an account (only DEFAULT_ADMIN_ROLE or OPERATOR_ROLE).
     * @param account The address to revoke the role from.
     */
    function revokeMinerRole(address account) external nonReentrant {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(OPERATOR_ROLE, msg.sender),
            "Unauthorized"
        );
        require(account != address(0), "Invalid account");
        require(block.number >= roleChangeTimelock, "Timelock not expired");

        revokeRole(MINER_ROLE, account);
        emit MinerRoleRevoked(account);
    }

    /**
     * @dev Grant OPERATOR_ROLE to an account (only DEFAULT_ADMIN_ROLE).
     * @param account The address to grant the role to.
     */
    function grantOperatorRole(address account) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(account != address(0), "Invalid account");
        require(block.number >= roleChangeTimelock, "Timelock not expired");

        grantRole(OPERATOR_ROLE, account);
        emit OperatorRoleGranted(account);
    }

    /**
     * @dev Revoke OPERATOR_ROLE from an account (only DEFAULT_ADMIN_ROLE).
     * @param account The address to revoke the role from.
     */
    function revokeOperatorRole(address account) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(account != address(0), "Invalid account");
        require(block.number >= roleChangeTimelock, "Timelock not expired");

        revokeRole(OPERATOR_ROLE, account);
        emit OperatorRoleRevoked(account);
    }

    /**
     * @dev Grant REWARD_MANAGER_ROLE to an account (only DEFAULT_ADMIN_ROLE).
     * @param account The address to grant the role to.
     */
    function grantRewardManagerRole(address account) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(account != address(0), "Invalid account");
        require(block.number >= roleChangeTimelock, "Timelock not expired");

        grantRole(REWARD_MANAGER_ROLE, account);
        emit RewardManagerRoleGranted(account);
    }

    /**
     * @dev Revoke REWARD_MANAGER_ROLE from an account (only DEFAULT_ADMIN_ROLE).
     * @param account The address to revoke the role from.
     */
    function revokeRewardManagerRole(address account) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(account != address(0), "Invalid account");
        require(block.number >= roleChangeTimelock, "Timelock not expired");

        revokeRole(REWARD_MANAGER_ROLE, account);
        emit RewardManagerRoleRevoked(account);
    }

    /**
     * @dev Set reward per day (only REWARD_MANAGER_ROLE).
     * @param reward The new reward amount per day.
     */
    function setRewardPerDay(uint256 reward) external nonReentrant {
        require(hasRole(REWARD_MANAGER_ROLE, msg.sender), "Unauthorized");
        require(reward != rewardPerDay, "No change in value");
        rewardPerDay = reward;
        emit RewardPerDayUpdated(reward);
    }

    /**
     * @dev Set pause timelock duration (only DEFAULT_ADMIN_ROLE).
     * @param timelock The new timelock duration.
     */
    function setPauseTimelock(uint256 timelock) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(timelock != pauseTimelock, "No change in value");
        pauseTimelock = timelock;
        emit PauseTimelockUpdated(timelock);
    }

    /**
     * @dev Set role change timelock duration (only DEFAULT_ADMIN_ROLE).
     * @param timelock The new timelock duration.
     */
    function setRoleChangeTimelock(uint256 timelock) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(timelock != roleChangeTimelock, "No change in value");
        roleChangeTimelock = timelock;
        emit RoleChangeTimelockUpdated(timelock);
    }

    /**
     * @dev Pause the contract with timelock (only DEFAULT_ADMIN_ROLE).
     */
    function pause() external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(!paused(), "Already paused");
        require(block.number >= pauseTimelock, "Timelock not expired");

        _pause();
        emit ContractPaused();
    }

    /**
     * @dev Unpause the contract with timelock (only DEFAULT_ADMIN_ROLE).
     */
    function unpause() external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        require(paused(), "Not paused");
        require(block.number >= pauseTimelock, "Timelock not expired");

        _unpause();
        emit ContractUnpaused();
    }

    /**
     * @dev Burn tokens with a fee (anyone can burn their own tokens).
     * @param amount The amount of tokens to burn.
     */
    function burn(uint256 amount) external nonReentrant whenNotPaused {
        require(amount != 0, "Invalid amount");
        require(balanceOf(msg.sender) >= amount + BURN_FEE, "Insufficient balance");

        _burn(msg.sender, amount);
        _burn(msg.sender, BURN_FEE); // Burn the fee
        emit TokensBurned(msg.sender, amount);
    }

    /**
     * @dev Renounce ownership to ensure no further changes can be made (optional).
     */
    function renounceOwnership() public override onlyOwner nonReentrant {
        _transferOwnership(address(0));
    }

    /**
     * @dev Set the contract metadata URI (only DEFAULT_ADMIN_ROLE).
     * @param metadataURI The new metadata URI.
     */
    function setContractMetadataURI(string memory metadataURI) external nonReentrant {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Unauthorized");
        _contractMetadataURI = metadataURI;
        emit ContractMetadataUpdated(metadataURI);
    }

    /**
     * @dev Get the contract metadata URI.
     * @return string The metadata URI.
     */
    function getContractMetadataURI() external view returns (string memory) {
        return _contractMetadataURI;
    }

    /**
     * @dev Ensure the contract is not a honeypot by allowing transfers and approvals.
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
    }

    /**
     * @dev Additional safeguard: Prevent unexpected behavior during pauses/unpauses.
     */
    function _requireNotPaused() internal view virtual override {
        require(!paused(), "Contract paused");
    }
}