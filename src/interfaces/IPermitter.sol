// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IPermitter
/// @notice Interface for KYC-based bid validation in CCA auctions
/// @dev Uses EIP-712 signed permits from trusted signer for KYC verification
interface IPermitter {
  // ========== STRUCTS ==========

  /// @notice Permit structure signed by trusted signer
  /// @param bidder Address authorized to bid
  /// @param maxBidAmount Maximum tokens this bidder can purchase (cumulative)
  /// @param expiry Timestamp when permit expires
  struct Permit {
    address bidder;
    uint256 maxBidAmount;
    uint256 expiry;
  }

  // ========== ENUMS ==========

  /// @notice Types of caps that can be updated
  enum CapType {
    TOTAL_ETH,
    TOKENS_PER_BIDDER
  }

  // ========== ERRORS ==========

  /// @notice Thrown when contract is paused
  error ContractPaused();

  /// @notice Thrown when signature has expired
  /// @param expiry The permit expiry timestamp
  /// @param currentTime The current block timestamp
  error SignatureExpired(uint256 expiry, uint256 currentTime);

  /// @notice Thrown when signature is invalid or from wrong signer
  /// @param expected The expected signer/bidder
  /// @param recovered The recovered address
  error InvalidSignature(address expected, address recovered);

  /// @notice Thrown when bid exceeds personal cap
  /// @param requested The requested bid amount
  /// @param cap The personal cap
  /// @param alreadyBid The amount already bid
  error ExceedsPersonalCap(uint256 requested, uint256 cap, uint256 alreadyBid);

  /// @notice Thrown when bid exceeds total cap
  /// @param requested The requested amount
  /// @param cap The total cap
  /// @param alreadyRaised The amount already raised
  error ExceedsTotalCap(uint256 requested, uint256 cap, uint256 alreadyRaised);

  /// @notice Thrown when caller is not authorized
  error Unauthorized();

  /// @notice Thrown when a zero address is provided
  error ZeroAddress();

  // ========== EVENTS ==========

  /// @notice Emitted when a permit is verified and bid is validated
  /// @param bidder The address that placed the bid
  /// @param bidAmount The amount bid
  /// @param remainingPersonalCap Remaining capacity under personal cap
  /// @param remainingTotalCap Remaining capacity under total cap
  event PermitVerified(
    address indexed bidder,
    uint256 bidAmount,
    uint256 remainingPersonalCap,
    uint256 remainingTotalCap
  );

  /// @notice Emitted when a cap is updated
  /// @param capType The type of cap updated
  /// @param oldCap The previous cap value
  /// @param newCap The new cap value
  event CapUpdated(CapType indexed capType, uint256 oldCap, uint256 newCap);

  /// @notice Emitted when trusted signer is updated
  /// @param oldSigner The previous signer address
  /// @param newSigner The new signer address
  event SignerUpdated(address indexed oldSigner, address indexed newSigner);

  /// @notice Emitted when contract is paused
  /// @param by The address that paused
  event Paused(address indexed by);

  /// @notice Emitted when contract is unpaused
  /// @param by The address that unpaused
  event Unpaused(address indexed by);

  // ========== FUNCTIONS ==========

  /// @notice Update the maximum total ETH cap (owner only)
  /// @param newMaxTotalEth New ETH cap
  function updateMaxTotalEth(uint256 newMaxTotalEth) external;

  /// @notice Update the maximum tokens per bidder cap (owner only)
  /// @param newMaxTokensPerBidder New per-bidder cap
  function updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external;

  /// @notice Update the trusted signer address (owner only)
  /// @dev Use this to rotate keys if signing key is compromised
  /// @param newSigner New trusted signer address
  function updateTrustedSigner(address newSigner) external;

  /// @notice Emergency pause all bid validations (owner only)
  function pause() external;

  /// @notice Resume bid validations (owner only)
  function unpause() external;

  /// @notice Get cumulative bid amount for an address
  /// @param bidder Address to query
  /// @return cumulativeBid Total tokens bid by this address
  function getBidAmount(address bidder) external view returns (uint256 cumulativeBid);

  /// @notice Get total ETH raised across all bidders
  /// @return totalEthRaised Cumulative ETH raised
  function getTotalEthRaised() external view returns (uint256 totalEthRaised);

  /// @notice Get the trusted signer address
  /// @return The trusted signer address
  function trustedSigner() external view returns (address);

  /// @notice Get the maximum total ETH cap
  /// @return The max total ETH cap
  function maxTotalEth() external view returns (uint256);

  /// @notice Get the maximum tokens per bidder
  /// @return The max tokens per bidder
  function maxTokensPerBidder() external view returns (uint256);

  /// @notice Get the owner address
  /// @return The owner address
  function owner() external view returns (address);

  /// @notice Check if contract is paused
  /// @return True if paused
  function paused() external view returns (bool);
}
