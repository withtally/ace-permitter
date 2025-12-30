// SPDX-License-Identifier: MIT
// slither-disable-start reentrancy-benign

pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {PermitterFactoryV2} from "src/PermitterFactoryV2.sol";
import {PermitterV2} from "src/PermitterV2.sol";

/// @title DeployV2
/// @notice Deployment script for PermitterFactoryV2
/// @dev Deploys factory with CREATE2 for deterministic addresses across chains
contract DeployV2 is Script {
  function run() public returns (PermitterFactoryV2 factory) {
    vm.broadcast();
    factory = new PermitterFactoryV2();

    console2.log("PermitterFactoryV2 deployed at:", address(factory));
  }

  /// @notice Deploy factory with CREATE2 for deterministic address
  /// @param salt Salt for CREATE2 deployment
  function runDeterministic(bytes32 salt) public returns (PermitterFactoryV2 factory) {
    vm.broadcast();
    factory = new PermitterFactoryV2{salt: salt}();

    console2.log("PermitterFactoryV2 deployed at:", address(factory));
    console2.log("Salt used:", vm.toString(salt));
  }
}

/// @title DeployPermitter
/// @notice Deployment script for creating a Permitter via factory
contract DeployPermitter is Script {
  /// @notice Deploy a new Permitter instance
  /// @param factoryAddr Address of PermitterFactoryV2
  /// @param trustedSigner Address authorized to sign permits
  /// @param maxTotalEth Maximum total ETH cap
  /// @param maxTokensPerBidder Maximum tokens per bidder
  /// @param owner Owner address
  function run(
    address factoryAddr,
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner
  ) public returns (address permitter) {
    PermitterFactoryV2 factory = PermitterFactoryV2(factoryAddr);

    vm.broadcast();
    permitter = factory.createPermitter(trustedSigner, maxTotalEth, maxTokensPerBidder, owner);

    console2.log("Permitter deployed at:", permitter);
    console2.log("Trusted signer:", trustedSigner);
    console2.log("Max total ETH:", maxTotalEth);
    console2.log("Max tokens per bidder:", maxTokensPerBidder);
    console2.log("Owner:", owner);
  }

  /// @notice Deploy a Permitter with deterministic address
  function runDeterministic(
    address factoryAddr,
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    bytes32 salt
  ) public returns (address permitter) {
    PermitterFactoryV2 factory = PermitterFactoryV2(factoryAddr);

    // Log predicted address first
    address predicted = factory.predictPermitterAddressWithParams(
      trustedSigner, maxTotalEth, maxTokensPerBidder, owner, salt
    );
    console2.log("Predicted permitter address:", predicted);

    vm.broadcast();
    permitter = factory.createPermitterDeterministic(
      trustedSigner, maxTotalEth, maxTokensPerBidder, owner, salt
    );

    console2.log("Permitter deployed at:", permitter);
    require(permitter == predicted, "Address mismatch");
  }
}
