// SPDX-License-Identifier: MIT
// slither-disable-start reentrancy-benign

pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";
import {Permitter} from "src/Permitter.sol";

/// @title DeployPermitter
/// @notice Deployment script for creating and configuring a Permitter via factory
/// @dev Configuration via environment variables:
///   FACTORY (required)        - PermitterFactory address
///   IDENTITY_REGISTRY         - Chainlink CCID registry (default: address(0))
///   POLICY_ENGINE             - Chainlink ACE Policy Engine (default: address(0))
///   MERKLE_ROOT               - Allowlist root (default: bytes32(0))
///   PER_USER_LIMIT            - Per-user token limit in wei (default: 0 = no limit)
///   GLOBAL_CAP                - Total cap in wei (default: 0 = no limit)
///   REQUIRE_SANCTIONS         - Enable sanctions check (default: false)
///   REQUIRE_ALLOWLIST         - Enable allowlist (default: false)
///   CCA                       - CCA address to authorize after deploy (optional)
///   SALT                      - Salt for deterministic deployment (optional)
contract DeployPermitter is Script {
  function run() public returns (Permitter permitter) {
    // Required: factory address
    address factoryAddr = vm.envAddress("FACTORY");
    PermitterFactory factory = PermitterFactory(factoryAddr);

    // Optional config with defaults
    address identityRegistry = vm.envOr("IDENTITY_REGISTRY", address(0));
    address policyEngine = vm.envOr("POLICY_ENGINE", address(0));
    bytes32 merkleRoot = vm.envOr("MERKLE_ROOT", bytes32(0));
    uint256 perUserLimit = vm.envOr("PER_USER_LIMIT", uint256(0));
    uint256 globalCap = vm.envOr("GLOBAL_CAP", uint256(0));
    bool requireSanctions = vm.envOr("REQUIRE_SANCTIONS", false);
    bool requireAllowlist = vm.envOr("REQUIRE_ALLOWLIST", false);

    // Optional: CCA to authorize
    address cca = vm.envOr("CCA", address(0));

    // Optional: salt for deterministic deployment
    bytes32 salt = vm.envOr("SALT", bytes32(0));

    // Build config
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: identityRegistry,
      policyEngine: policyEngine,
      merkleRoot: merkleRoot,
      perUserLimit: perUserLimit,
      globalCap: globalCap,
      requireSanctionsCheck: requireSanctions,
      requireAllowlist: requireAllowlist
    });

    // Deploy permitter
    vm.startBroadcast();

    address permitterAddr;
    if (salt != bytes32(0)) {
      permitterAddr = factory.createPermitterDeterministic(config, salt);
      console2.log("Permitter deployed deterministically at:", permitterAddr);
    } else {
      permitterAddr = factory.createPermitter(config);
      console2.log("Permitter deployed at:", permitterAddr);
    }
    permitter = Permitter(permitterAddr);

    // Authorize CCA if provided
    if (cca != address(0)) {
      permitter.authorizeCCA(cca);
      console2.log("CCA authorized:", cca);
    }

    vm.stopBroadcast();

    // Log configuration
    console2.log("--- Configuration ---");
    console2.log("Factory:", factoryAddr);
    console2.log("Identity Registry:", identityRegistry);
    console2.log("Policy Engine:", policyEngine);
    console2.log("Merkle Root:", vm.toString(merkleRoot));
    console2.log("Per User Limit:", perUserLimit);
    console2.log("Global Cap:", globalCap);
    console2.log("Require Sanctions:", requireSanctions);
    console2.log("Require Allowlist:", requireAllowlist);
  }
}
