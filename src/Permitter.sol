// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IValidationHook} from "./interfaces/IValidationHook.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {IPolicyEngine} from "./interfaces/IPolicyEngine.sol";

/// @title Permitter
/// @notice Validation hook for CCA auctions with sanctions, purchase limits, and allowlist
/// enforcement
/// @dev Implements IValidationHook and integrates with Chainlink ACE Policy Engine and CCID
contract Permitter is IValidationHook, Initializable {
  // ========== STRUCTS ==========

  /// @notice Configuration for initializing a Permitter
  struct Config {
    address identityRegistry;
    address policyEngine;
    bytes32 merkleRoot;
    uint256 perUserLimit;
    uint256 globalCap;
    bool requireSanctionsCheck;
    bool requireAllowlist;
  }

  // ========== STORAGE ==========

  /// @notice The authorized auction/CCA contract (set once via authorizeCCA)
  address public auction;

  /// @notice The owner/admin of this permitter
  address public owner;

  /// @notice Chainlink CCID Identity Registry
  IIdentityRegistry public identityRegistry;

  /// @notice Chainlink ACE Policy Engine
  IPolicyEngine public policyEngine;

  /// @notice Merkle root for allowlist verification
  bytes32 public merkleRoot;

  /// @notice Per-user purchase limit in tokens
  uint256 public perUserLimit;

  /// @notice Global purchase cap in tokens
  uint256 public globalCap;

  /// @notice Whether sanctions check is required
  bool public requireSanctionsCheck;

  /// @notice Whether allowlist is required
  bool public requireAllowlist;

  /// @notice Whether the permitter is paused
  bool public paused;

  /// @notice Total tokens committed for this auction
  uint256 public totalCommitted;

  /// @notice Tokens committed per CCID
  mapping(bytes32 ccid => uint256 amount) public committedByCCID;

  /// @notice Tokens committed per address (fallback if no CCID)
  mapping(address user => uint256 amount) public committedByAddress;

  // ========== ERRORS ==========

  /// @notice Thrown when caller is not the owner
  error Unauthorized();

  /// @notice Thrown when validate() is called before a CCA has been authorized
  error CCANotConfigured();

  /// @notice Thrown when caller is not the authorized CCA
  error UnauthorizedCCA();

  /// @notice Thrown when attempting to authorize a CCA after one is already set
  error CCAAlreadyAuthorized();

  /// @notice Thrown when the permitter is paused
  error Paused();

  /// @notice Thrown when bidder has no CCID registered
  error NoCCIDFound(address bidder);

  /// @notice Thrown when bidder is not on the allowlist
  error NotOnAllowlist(address user);

  /// @notice Thrown when bidder's CCID fails sanctions check
  error SanctionsFailed(address user, bytes32 ccid);

  /// @notice Thrown when bid would exceed individual CCID limit
  /// @param ccid The CCID that would exceed its limit
  /// @param requested The requested bid amount
  /// @param remaining The remaining allocation for this CCID
  error IndividualLimitExceeded(bytes32 ccid, uint256 requested, uint256 remaining);

  /// @notice Thrown when bid would exceed global sale cap
  /// @param requested The requested bid amount
  /// @param remaining The remaining global allocation
  error GlobalCapExceeded(uint256 requested, uint256 remaining);

  /// @notice Thrown when CCID registry lookup fails
  error CCIDLookupFailed(address bidder);

  /// @notice Thrown when a zero address is provided
  error ZeroAddress();

  // ========== EVENTS ==========

  /// @notice Emitted when permitter is initialized
  event Initialized(address indexed owner, uint256 perUserLimit, uint256 globalCap);

  /// @notice Emitted when a CCA is authorized
  event CCAAuthorized(address indexed cca);

  /// @notice Emitted when per-user limit is updated
  event PerUserLimitUpdated(uint256 oldLimit, uint256 newLimit);

  /// @notice Emitted when global cap is updated
  event GlobalCapUpdated(uint256 oldCap, uint256 newCap);

  /// @notice Emitted when merkle root is updated
  event MerkleRootUpdated(bytes32 oldRoot, bytes32 newRoot);

  /// @notice Emitted when paused state changes
  event PausedStateChanged(bool isPaused);

  /// @notice Emitted when ownership is transferred
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  // ========== MODIFIERS ==========

  modifier onlyOwner() {
    if (msg.sender != owner) revert Unauthorized();
    _;
  }

  modifier whenNotPaused() {
    if (paused) revert Paused();
    _;
  }

  // ========== INITIALIZATION ==========

  /// @notice Initializes the permitter (called by factory)
  /// @param _owner The owner of this permitter
  /// @param config The configuration from the factory
  function initialize(address _owner, Config calldata config) external initializer {
    if (_owner == address(0)) revert ZeroAddress();

    owner = _owner;
    identityRegistry = IIdentityRegistry(config.identityRegistry);
    policyEngine = IPolicyEngine(config.policyEngine);
    merkleRoot = config.merkleRoot;
    perUserLimit = config.perUserLimit;
    globalCap = config.globalCap;
    requireSanctionsCheck = config.requireSanctionsCheck;
    requireAllowlist = config.requireAllowlist;

    emit Initialized(_owner, config.perUserLimit, config.globalCap);
  }

  /// @notice Authorizes a CCA contract to call validate()
  /// @dev Can only be called once by the owner. Subsequent calls revert.
  /// @param cca The CCA contract address to authorize
  function authorizeCCA(address cca) external onlyOwner {
    if (cca == address(0)) revert ZeroAddress();
    if (auction != address(0)) revert CCAAlreadyAuthorized();

    auction = cca;
    emit CCAAuthorized(cca);
  }

  // ========== VALIDATION HOOK ==========

  /// @notice Validates a bid according to configured policies
  /// @dev Called by the CCA. Reverts if validation fails.
  /// @param amount The bid amount in tokens
  /// @param bidOwner The beneficial owner of the bid (used for CCID lookup)
  /// @param hookData Merkle proof if allowlist is required
  function validate(uint256, uint128 amount, address bidOwner, address, bytes calldata hookData)
    external
    override
    whenNotPaused
  {
    // 1. Verify CCA is authorized
    if (auction == address(0)) revert CCANotConfigured();

    // 2. Verify caller is the authorized CCA
    if (msg.sender != auction) revert UnauthorizedCCA();

    // 3. Check allowlist if required
    if (requireAllowlist) _checkAllowlist(bidOwner, hookData);

    // 4. Get the user's CCID (fresh lookup every call)
    bytes32 ccid = _getCCID(bidOwner);

    // 5. Check sanctions via Policy Engine if required
    if (requireSanctionsCheck) _checkSanctions(bidOwner, ccid);

    // 6. Check per-user limit
    _checkPerUserLimit(bidOwner, ccid, uint256(amount));

    // 7. Check global cap
    _checkGlobalCap(uint256(amount));

    // 8. Update state (only if all checks pass)
    _recordCommitment(bidOwner, ccid, uint256(amount));
  }

  // ========== INTERNAL FUNCTIONS ==========

  /// @notice Gets the CCID for a user from the identity registry
  /// @dev Fresh lookup every call to catch revocations
  function _getCCID(address user) internal view returns (bytes32) {
    if (address(identityRegistry) == address(0)) return bytes32(0);
    return identityRegistry.getIdentity(user);
  }

  /// @notice Checks if user is on the allowlist via Merkle proof
  function _checkAllowlist(address user, bytes calldata hookData) internal view {
    if (merkleRoot == bytes32(0)) {
      // No merkle root set, allowlist is effectively disabled
      return;
    }

    // Decode the merkle proof from hookData
    bytes32[] memory proof = abi.decode(hookData, (bytes32[]));

    // Compute the leaf
    bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(user))));

    // Verify the proof
    if (!MerkleProof.verify(proof, merkleRoot, leaf)) revert NotOnAllowlist(user);
  }

  /// @notice Checks sanctions status via Policy Engine
  function _checkSanctions(address user, bytes32 ccid) internal view {
    // If no CCID and sanctions required, revert with distinct error
    if (ccid == bytes32(0)) revert NoCCIDFound(user);

    // If no policy engine configured, skip
    if (address(policyEngine) == address(0)) return;

    // Build payload for policy engine
    IPolicyEngine.Payload memory payload = IPolicyEngine.Payload({
      selector: this.validate.selector,
      sender: user,
      calldata_: abi.encode(ccid),
      context: ""
    });

    // Check policy - this will revert if policy rejects
    IPolicyEngine.PolicyResult result = policyEngine.check(payload);
    if (result == IPolicyEngine.PolicyResult.None) revert SanctionsFailed(user, ccid);
  }

  /// @notice Checks if bid would exceed per-user limit
  function _checkPerUserLimit(address user, bytes32 ccid, uint256 amount) internal view {
    if (perUserLimit == 0) return; // No limit set

    uint256 currentTotal = _getUserTotal(user, ccid);
    uint256 remaining = perUserLimit > currentTotal ? perUserLimit - currentTotal : 0;

    if (currentTotal + amount > perUserLimit) {
      revert IndividualLimitExceeded(ccid, amount, remaining);
    }
  }

  /// @notice Gets the total committed tokens for a user
  function _getUserTotal(address user, bytes32 ccid) internal view returns (uint256) {
    if (ccid != bytes32(0)) return committedByCCID[ccid];
    return committedByAddress[user];
  }

  /// @notice Checks if bid would exceed global cap
  function _checkGlobalCap(uint256 amount) internal view {
    if (globalCap == 0) return; // No cap set

    uint256 remaining = globalCap > totalCommitted ? globalCap - totalCommitted : 0;

    if (totalCommitted + amount > globalCap) {
      revert GlobalCapExceeded(amount, remaining);
    }
  }

  /// @notice Records a commitment
  function _recordCommitment(address user, bytes32 ccid, uint256 amount) internal {
    if (ccid != bytes32(0)) {
      committedByCCID[ccid] += amount;
    } else {
      committedByAddress[user] += amount;
    }
    totalCommitted += amount;
  }

  // ========== VIEW FUNCTIONS ==========

  /// @notice Checks if an address is eligible to bid (basic checks)
  /// @dev Fast check: CCID exists and under limits. Does not run full policy evaluation.
  /// @param bidder The address to check
  /// @return eligible True if basic eligibility checks pass
  function checkEligibility(address bidder) external view returns (bool eligible) {
    // Check if CCID exists (if sanctions check required)
    if (requireSanctionsCheck) {
      bytes32 ccid = _getCCID(bidder);
      if (ccid == bytes32(0)) return false;
    }

    // Check individual limit
    if (perUserLimit > 0) {
      bytes32 ccid = _getCCID(bidder);
      uint256 current = _getUserTotal(bidder, ccid);
      if (current >= perUserLimit) return false;
    }

    // Check global cap
    if (globalCap > 0 && totalCommitted >= globalCap) return false;

    return true;
  }

  /// @notice Gets remaining purchase capacity for a user in tokens
  /// @param user The user address
  /// @return remaining The remaining capacity in tokens
  function getRemainingUserCapacity(address user) external view returns (uint256 remaining) {
    if (perUserLimit == 0) return type(uint256).max;

    bytes32 ccid = _getCCID(user);
    uint256 current = _getUserTotal(user, ccid);

    if (current >= perUserLimit) return 0;
    return perUserLimit - current;
  }

  /// @notice Gets remaining global capacity in tokens
  /// @return remaining The remaining capacity in tokens
  function getRemainingGlobalCapacity() external view returns (uint256 remaining) {
    if (globalCap == 0) return type(uint256).max;
    if (totalCommitted >= globalCap) return 0;
    return globalCap - totalCommitted;
  }

  /// @notice Gets total committed tokens for a user
  /// @param user The user address
  /// @return total The total committed tokens
  function getUserCommitted(address user) external view returns (uint256 total) {
    bytes32 ccid = _getCCID(user);
    return _getUserTotal(user, ccid);
  }

  // ========== ADMIN FUNCTIONS ==========

  /// @notice Updates the per-user limit
  /// @param newLimit New limit in tokens
  function setPerUserLimit(uint256 newLimit) external onlyOwner {
    emit PerUserLimitUpdated(perUserLimit, newLimit);
    perUserLimit = newLimit;
  }

  /// @notice Updates the global cap
  /// @param newCap New cap in tokens
  function setGlobalCap(uint256 newCap) external onlyOwner {
    emit GlobalCapUpdated(globalCap, newCap);
    globalCap = newCap;
  }

  /// @notice Updates the merkle root for allowlist
  /// @param newRoot New merkle root
  function setMerkleRoot(bytes32 newRoot) external onlyOwner {
    emit MerkleRootUpdated(merkleRoot, newRoot);
    merkleRoot = newRoot;
  }

  /// @notice Pauses or unpauses the permitter
  /// @param _paused New paused state
  function setPaused(bool _paused) external onlyOwner {
    paused = _paused;
    emit PausedStateChanged(_paused);
  }

  /// @notice Transfers ownership
  /// @param newOwner New owner address
  function transferOwnership(address newOwner) external onlyOwner {
    if (newOwner == address(0)) revert ZeroAddress();
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}
