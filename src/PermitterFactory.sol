// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Permitter} from "./Permitter.sol";

/// @title PermitterFactory
/// @notice Factory for creating Permitter validation hooks for CCA auctions
/// @dev Uses EIP-1167 minimal proxies for gas-efficient deployment
contract PermitterFactory {
  using Clones for address;

  // ========== STORAGE ==========

  /// @notice The Permitter implementation contract
  address public immutable IMPLEMENTATION;

  /// @notice Registry of deployed permitters
  mapping(address permitter => bool isValid) public isPermitter;

  /// @notice Permitters created by each address
  mapping(address creator => address[] permitters) internal _permittersByCreator;

  // ========== EVENTS ==========

  /// @notice Emitted when a new Permitter is created
  /// @param permitter The address of the new permitter
  /// @param creator The address that created the permitter
  event PermitterCreated(address indexed permitter, address indexed creator);

  // ========== CONSTRUCTOR ==========

  /// @notice Deploys the factory and creates the Permitter implementation
  constructor() {
    IMPLEMENTATION = address(new Permitter());
  }

  // ========== EXTERNAL FUNCTIONS ==========

  /// @notice Creates a new Permitter
  /// @dev The permitter is created without an authorized CCA. Call authorizeCCA on the
  ///      permitter after creation to set the auction contract.
  /// @param config The configuration for the permitter
  /// @return permitter The address of the new permitter
  // slither-disable-next-line reentrancy-benign,reentrancy-events
  function createPermitter(Permitter.Config calldata config) external returns (address permitter) {
    // Clone the implementation
    permitter = IMPLEMENTATION.clone();

    // Initialize the clone (msg.sender becomes owner)
    Permitter(permitter).initialize(msg.sender, config);

    // Register the permitter
    isPermitter[permitter] = true;
    _permittersByCreator[msg.sender].push(permitter);

    emit PermitterCreated(permitter, msg.sender);
  }

  /// @notice Creates a permitter with deterministic address
  /// @dev The permitter is created without an authorized CCA. Call authorizeCCA on the
  ///      permitter after creation to set the auction contract.
  /// @param config The configuration for the permitter
  /// @param salt The salt for deterministic deployment
  /// @return permitter The address of the new permitter
  // slither-disable-next-line reentrancy-benign,reentrancy-events
  function createPermitterDeterministic(Permitter.Config calldata config, bytes32 salt)
    external
    returns (address permitter)
  {
    permitter = IMPLEMENTATION.cloneDeterministic(salt);
    Permitter(permitter).initialize(msg.sender, config);
    isPermitter[permitter] = true;
    _permittersByCreator[msg.sender].push(permitter);

    emit PermitterCreated(permitter, msg.sender);
  }

  /// @notice Predicts the address of a deterministic permitter
  /// @param salt The salt that would be used for deployment
  /// @return predicted The predicted address
  function predictPermitterAddress(bytes32 salt) external view returns (address predicted) {
    return IMPLEMENTATION.predictDeterministicAddress(salt);
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
}
