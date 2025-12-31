// SPDX-License-Identifier: MIT
// slither-disable-start reentrancy-benign

pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";

/// @title DeployFactory
/// @notice Deployment script for PermitterFactory
contract DeployFactory is Script {
  function run() public returns (PermitterFactory factory) {
    vm.broadcast();
    factory = new PermitterFactory();

    console2.log("PermitterFactory deployed at:", address(factory));
    console2.log("Permitter implementation at:", factory.IMPLEMENTATION());
  }
}
