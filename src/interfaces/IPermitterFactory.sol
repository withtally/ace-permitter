// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IPermitterFactory
/// @notice Factory interface for deploying Permitter instances
/// @dev Deploys isolated Permitter instances for each auction using CREATE2
interface IPermitterFactory {
  // ========== EVENTS ==========

  /// @notice Emitted when a new Permitter is created
  /// @param permitter The address of the new permitter
  /// @param owner The owner of the permitter
  /// @param trustedSigner The trusted signer address
  /// @param maxTotalEth Maximum total ETH that can be raised
  /// @param maxTokensPerBidder Maximum tokens per bidder
  event PermitterCreated(
    address indexed permitter,
    address indexed owner,
    address indexed trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder
  );

  // ========== ERRORS ==========

  /// @notice Thrown when a zero address is provided
  error ZeroAddress();

  // ========== FUNCTIONS ==========

  /// @notice Create a new Permitter instance for an auction
  /// @param trustedSigner Address authorized to sign permits (Tally backend)
  /// @param maxTotalEth Maximum total ETH that can be raised in the auction
  /// @param maxTokensPerBidder Maximum tokens any single bidder can purchase
  /// @param _owner Address that can update caps and pause (auction creator)
  /// @return permitter Address of deployed Permitter contract
  function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address _owner
  ) external returns (address permitter);

  /// @notice Create a new Permitter with deterministic address
  /// @param trustedSigner Address authorized to sign permits
  /// @param maxTotalEth Maximum total ETH that can be raised
  /// @param maxTokensPerBidder Maximum tokens per bidder
  /// @param _owner Owner address
  /// @param salt Salt for deterministic deployment
  /// @return permitter Address of deployed Permitter contract
  function createPermitterDeterministic(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address _owner,
    bytes32 salt
  ) external returns (address permitter);

  /// @notice Predict the address of a Permitter before deployment
  /// @param salt Salt for deterministic deployment
  /// @return predicted The predicted address
  function predictPermitterAddress(bytes32 salt) external view returns (address predicted);

  /// @notice Get the implementation address
  /// @return The implementation contract address
  function implementation() external view returns (address);

  /// @notice Check if an address is a valid permitter deployed by this factory
  /// @param permitter Address to check
  /// @return True if valid permitter
  function isPermitter(address permitter) external view returns (bool);
}
