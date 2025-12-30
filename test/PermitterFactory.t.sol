// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "src/Permitter.sol";
import {PermitterFactory} from "src/PermitterFactory.sol";

contract PermitterFactoryTest is Test {
  address private OWNER;
  address private SIGNER;

  function setUp() public {
    OWNER = makeAddr("owner");
    SIGNER = makeAddr("signer");
  }

  function test_CreatePermitter_PredictsAddress() public {
    PermitterFactory factory = new PermitterFactory();
    uint256 maxTotalEth = 100 ether;
    uint256 maxTokensPerBidder = 1_000 ether;
    bytes32 salt = keccak256(abi.encode(SIGNER, maxTotalEth, maxTokensPerBidder, OWNER));

    address predicted = factory.predictPermitterAddress(
      SIGNER,
      maxTotalEth,
      maxTokensPerBidder,
      OWNER,
      salt
    );
    address deployed =
      factory.createPermitter(SIGNER, maxTotalEth, maxTokensPerBidder, OWNER);

    assertEq(deployed, predicted);

    Permitter permitter = Permitter(deployed);
    assertEq(permitter.trustedSigner(), SIGNER);
    assertEq(permitter.maxTotalEth(), maxTotalEth);
    assertEq(permitter.maxTokensPerBidder(), maxTokensPerBidder);
    assertEq(permitter.owner(), OWNER);
  }

  function test_CreatePermitterWithSalt_PredictsAddress() public {
    PermitterFactory factory = new PermitterFactory();
    uint256 maxTotalEth = 50 ether;
    uint256 maxTokensPerBidder = 250 ether;
    bytes32 salt = keccak256("custom-salt");

    address predicted = factory.predictPermitterAddress(
      SIGNER,
      maxTotalEth,
      maxTokensPerBidder,
      OWNER,
      salt
    );
    address deployed =
      factory.createPermitterWithSalt(SIGNER, maxTotalEth, maxTokensPerBidder, OWNER, salt);

    assertEq(deployed, predicted);
  }
}
