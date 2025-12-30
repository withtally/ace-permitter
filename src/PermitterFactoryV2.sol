// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IPermitterFactory} from "./interfaces/IPermitterFactory.sol";
import {PermitterV2} from "./PermitterV2.sol";

/// @title PermitterFactoryV2
/// @notice Factory for creating PermitterV2 validation hooks for CCA auctions
/// @dev Uses CREATE2 for deterministic addresses across chains
contract PermitterFactoryV2 is IPermitterFactory {
  // ========== STORAGE ==========

  /// @notice Registry of deployed permitters
  mapping(address permitter => bool isValid) private _isPermitter;

  /// @notice Permitters created by each address
  mapping(address creator => address[] permitters) internal _permittersByCreator;

  // ========== EXTERNAL FUNCTIONS ==========

  /// @inheritdoc IPermitterFactory
  function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address _owner
  ) external override returns (address permitter) {
    if (trustedSigner == address(0)) revert ZeroAddress();
    if (_owner == address(0)) revert ZeroAddress();

    // Deploy new Permitter
    permitter = address(new PermitterV2(trustedSigner, maxTotalEth, maxTokensPerBidder, _owner));

    // Register the permitter
    _isPermitter[permitter] = true;
    _permittersByCreator[msg.sender].push(permitter);

    emit PermitterCreated(permitter, _owner, trustedSigner, maxTotalEth, maxTokensPerBidder);
  }

  /// @inheritdoc IPermitterFactory
  function createPermitterDeterministic(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address _owner,
    bytes32 salt
  ) external override returns (address permitter) {
    if (trustedSigner == address(0)) revert ZeroAddress();
    if (_owner == address(0)) revert ZeroAddress();

    // Get bytecode with constructor args
    bytes memory bytecode =
      _getCreationBytecode(trustedSigner, maxTotalEth, maxTokensPerBidder, _owner);

    // Deploy with CREATE2
    permitter = Create2.deploy(0, salt, bytecode);

    // Register the permitter
    _isPermitter[permitter] = true;
    _permittersByCreator[msg.sender].push(permitter);

    emit PermitterCreated(permitter, _owner, trustedSigner, maxTotalEth, maxTokensPerBidder);
  }

  /// @inheritdoc IPermitterFactory
  function predictPermitterAddress(bytes32) external pure override returns (address) {
    // For prediction, we need placeholder values since we don't have the actual params
    // This is a simplified version - in practice you'd need to pass the full params
    revert("Use predictPermitterAddressWithParams");
  }

  /// @notice Predict permitter address with full constructor parameters
  /// @param trustedSigner Trusted signer address
  /// @param maxTotalEth Max total ETH cap
  /// @param maxTokensPerBidder Max tokens per bidder
  /// @param _owner Owner address
  /// @param salt Salt for CREATE2
  /// @return predicted The predicted address
  function predictPermitterAddressWithParams(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address _owner,
    bytes32 salt
  ) external view returns (address predicted) {
    bytes memory bytecode =
      _getCreationBytecode(trustedSigner, maxTotalEth, maxTokensPerBidder, _owner);
    return Create2.computeAddress(salt, keccak256(bytecode));
  }

  /// @inheritdoc IPermitterFactory
  function implementation() external pure override returns (address) {
    // No implementation contract - we deploy full contracts, not proxies
    return address(0);
  }

  /// @inheritdoc IPermitterFactory
  function isPermitter(address permitter) external view override returns (bool) {
    return _isPermitter[permitter];
  }

  /// @notice Gets all permitters created by an address
  /// @param creator The creator address
  /// @return permitters Array of permitter addresses
  function getPermittersByCreator(address creator)
    external
    view
    returns (address[] memory permitters)
  {
    return _permittersByCreator[creator];
  }

  // ========== INTERNAL FUNCTIONS ==========

  /// @notice Get creation bytecode with constructor arguments
  function _getCreationBytecode(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address _owner
  ) internal pure returns (bytes memory) {
    return abi.encodePacked(
      type(PermitterV2).creationCode,
      abi.encode(trustedSigner, maxTotalEth, maxTokensPerBidder, _owner)
    );
  }
}
