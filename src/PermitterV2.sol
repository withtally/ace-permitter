// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IValidationHook} from "./interfaces/IValidationHook.sol";
import {IPermitter} from "./interfaces/IPermitter.sol";

/// @title PermitterV2
/// @notice Validation hook for CCA auctions using EIP-712 signed permits
/// @dev Implements IValidationHook and uses off-chain KYC signatures for validation
contract PermitterV2 is IPermitter, IValidationHook, EIP712 {
  // ========== CONSTANTS ==========

  /// @notice EIP-712 typehash for Permit struct
  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  // ========== STORAGE ==========

  /// @notice Address authorized to sign permits (Tally backend)
  address public trustedSigner;

  /// @notice Maximum total ETH that can be raised in the auction
  uint256 public maxTotalEth;

  /// @notice Maximum tokens any single bidder can purchase
  uint256 public maxTokensPerBidder;

  /// @notice Track per-address cumulative bid totals
  mapping(address bidder => uint256 amount) public cumulativeBids;

  /// @notice Total ETH raised across all bidders
  uint256 public totalEthRaised;

  /// @notice Owner who can update caps and pause
  address public owner;

  /// @notice Whether validations are paused
  bool public paused;

  // ========== MODIFIERS ==========

  modifier onlyOwner() {
    if (msg.sender != owner) revert Unauthorized();
    _;
  }

  modifier whenNotPaused() {
    if (paused) revert ContractPaused();
    _;
  }

  // ========== CONSTRUCTOR ==========

  /// @notice Creates a new Permitter instance
  /// @param _trustedSigner Address authorized to sign permits
  /// @param _maxTotalEth Maximum total ETH that can be raised
  /// @param _maxTokensPerBidder Maximum tokens per bidder
  /// @param _owner Owner address
  constructor(
    address _trustedSigner,
    uint256 _maxTotalEth,
    uint256 _maxTokensPerBidder,
    address _owner
  ) EIP712("Permitter", "1") {
    if (_trustedSigner == address(0)) revert ZeroAddress();
    if (_owner == address(0)) revert ZeroAddress();

    trustedSigner = _trustedSigner;
    maxTotalEth = _maxTotalEth;
    maxTokensPerBidder = _maxTokensPerBidder;
    owner = _owner;
  }

  // ========== VALIDATION HOOK ==========

  /// @notice Validates a bid using EIP-712 signed permit
  /// @param amount Currency amount being bid (in wei)
  /// @param bidOwner Address receiving purchased tokens (the buyer)
  /// @param hookData ABI-encoded (Permit, signature) for validation
  /// @dev Reverts if validation fails
  function validate(uint256, uint128 amount, address bidOwner, address, bytes calldata hookData)
    external
    override
    whenNotPaused
  {
    // Decode permit data
    (Permit memory permit, bytes memory signature) = abi.decode(hookData, (Permit, bytes));

    // Check time window
    if (block.timestamp > permit.expiry) {
      revert SignatureExpired(permit.expiry, block.timestamp);
    }

    // Verify EIP-712 signature
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    bytes32 digest = _hashTypedDataV4(structHash);
    address recovered = ECDSA.recover(digest, signature);

    if (recovered != trustedSigner) revert InvalidSignature(trustedSigner, recovered);

    // Check permit is for this bidder
    if (permit.bidder != bidOwner) revert InvalidSignature(bidOwner, permit.bidder);

    // Check individual cap (cumulative)
    uint256 newCumulative = cumulativeBids[bidOwner] + uint256(amount);
    if (newCumulative > permit.maxBidAmount) {
      revert ExceedsPersonalCap(uint256(amount), permit.maxBidAmount, cumulativeBids[bidOwner]);
    }

    // Also check against global per-bidder cap
    if (maxTokensPerBidder > 0 && newCumulative > maxTokensPerBidder) {
      revert ExceedsPersonalCap(uint256(amount), maxTokensPerBidder, cumulativeBids[bidOwner]);
    }

    // Check global cap
    uint256 newTotalEth = totalEthRaised + uint256(amount);
    if (maxTotalEth > 0 && newTotalEth > maxTotalEth) {
      revert ExceedsTotalCap(uint256(amount), maxTotalEth, totalEthRaised);
    }

    // Update state
    cumulativeBids[bidOwner] = newCumulative;
    totalEthRaised = newTotalEth;

    // Emit event for monitoring
    uint256 remainingPersonal =
      permit.maxBidAmount > newCumulative ? permit.maxBidAmount - newCumulative : 0;
    uint256 remainingTotal =
      maxTotalEth > newTotalEth ? maxTotalEth - newTotalEth : type(uint256).max;

    emit PermitVerified(bidOwner, uint256(amount), remainingPersonal, remainingTotal);
  }

  // ========== ADMIN FUNCTIONS ==========

  /// @inheritdoc IPermitter
  function updateMaxTotalEth(uint256 newMaxTotalEth) external override onlyOwner {
    uint256 oldCap = maxTotalEth;
    maxTotalEth = newMaxTotalEth;
    emit CapUpdated(CapType.TOTAL_ETH, oldCap, newMaxTotalEth);
  }

  /// @inheritdoc IPermitter
  function updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external override onlyOwner {
    uint256 oldCap = maxTokensPerBidder;
    maxTokensPerBidder = newMaxTokensPerBidder;
    emit CapUpdated(CapType.TOKENS_PER_BIDDER, oldCap, newMaxTokensPerBidder);
  }

  /// @inheritdoc IPermitter
  function updateTrustedSigner(address newSigner) external override onlyOwner {
    if (newSigner == address(0)) revert ZeroAddress();
    address oldSigner = trustedSigner;
    trustedSigner = newSigner;
    emit SignerUpdated(oldSigner, newSigner);
  }

  /// @inheritdoc IPermitter
  function pause() external override onlyOwner {
    paused = true;
    emit Paused(msg.sender);
  }

  /// @inheritdoc IPermitter
  function unpause() external override onlyOwner {
    paused = false;
    emit Unpaused(msg.sender);
  }

  // ========== VIEW FUNCTIONS ==========

  /// @inheritdoc IPermitter
  function getBidAmount(address bidder) external view override returns (uint256 cumulativeBid) {
    return cumulativeBids[bidder];
  }

  /// @inheritdoc IPermitter
  function getTotalEthRaised() external view override returns (uint256) {
    return totalEthRaised;
  }

  /// @notice Returns the EIP-712 domain separator
  /// @return The domain separator
  function DOMAIN_SEPARATOR() external view returns (bytes32) {
    return _domainSeparatorV4();
  }
}
