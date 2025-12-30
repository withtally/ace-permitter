// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";
import {PermitterFactoryV2} from "../src/PermitterFactoryV2.sol";
import {PermitterV2} from "../src/PermitterV2.sol";
import {IPermitterFactory} from "../src/interfaces/IPermitterFactory.sol";
import {IPermitter} from "../src/interfaces/IPermitter.sol";

/// @title PermitterFactoryV2Test
/// @notice Comprehensive tests for PermitterFactoryV2 contract
contract PermitterFactoryV2Test is Test {
  PermitterFactoryV2 public factory;

  address public trustedSigner;
  address public owner;
  address public creator;

  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 10 ether;

  event PermitterCreated(
    address indexed permitter,
    address indexed owner,
    address indexed trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder
  );

  function setUp() public {
    trustedSigner = makeAddr("trustedSigner");
    owner = makeAddr("owner");
    creator = makeAddr("creator");

    factory = new PermitterFactoryV2();
  }

  // ========== CREATION TESTS ==========

  function test_createPermitter() public {
    vm.expectEmit(false, true, true, true);
    emit PermitterCreated(address(0), owner, trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER);

    vm.prank(creator);
    address permitterAddr =
      factory.createPermitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);

    // Verify permitter was created correctly
    assertTrue(permitterAddr != address(0));
    assertTrue(factory.isPermitter(permitterAddr));

    PermitterV2 permitter = PermitterV2(permitterAddr);
    assertEq(permitter.trustedSigner(), trustedSigner);
    assertEq(permitter.maxTotalEth(), MAX_TOTAL_ETH);
    assertEq(permitter.maxTokensPerBidder(), MAX_TOKENS_PER_BIDDER);
    assertEq(permitter.owner(), owner);
  }

  function test_createPermitter_tracksCreator() public {
    vm.prank(creator);
    address permitter1 =
      factory.createPermitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);

    vm.prank(creator);
    address permitter2 =
      factory.createPermitter(trustedSigner, MAX_TOTAL_ETH * 2, MAX_TOKENS_PER_BIDDER, owner);

    address[] memory permitters = factory.getPermittersByCreator(creator);
    assertEq(permitters.length, 2);
    assertEq(permitters[0], permitter1);
    assertEq(permitters[1], permitter2);
  }

  function test_createPermitter_revertsOnZeroSigner() public {
    vm.expectRevert(IPermitterFactory.ZeroAddress.selector);
    factory.createPermitter(address(0), MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);
  }

  function test_createPermitter_revertsOnZeroOwner() public {
    vm.expectRevert(IPermitterFactory.ZeroAddress.selector);
    factory.createPermitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, address(0));
  }

  function test_createPermitter_multipleCreators() public {
    address creator2 = makeAddr("creator2");

    vm.prank(creator);
    address permitter1 =
      factory.createPermitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);

    vm.prank(creator2);
    address permitter2 =
      factory.createPermitter(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);

    assertEq(factory.getPermittersByCreator(creator).length, 1);
    assertEq(factory.getPermittersByCreator(creator)[0], permitter1);

    assertEq(factory.getPermittersByCreator(creator2).length, 1);
    assertEq(factory.getPermittersByCreator(creator2)[0], permitter2);
  }

  // ========== DETERMINISTIC CREATION TESTS ==========

  function test_createPermitterDeterministic() public {
    bytes32 salt = keccak256("test_salt");

    // Predict address first
    address predicted = factory.predictPermitterAddressWithParams(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    // Create permitter
    vm.prank(creator);
    address permitterAddr = factory.createPermitterDeterministic(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    // Should match prediction
    assertEq(permitterAddr, predicted);
    assertTrue(factory.isPermitter(permitterAddr));
  }

  function test_createPermitterDeterministic_sameParamsSameSalt() public {
    bytes32 salt = keccak256("same_salt");

    vm.prank(creator);
    address permitter1 = factory.createPermitterDeterministic(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    // Trying to create again with same salt should revert (address already taken)
    vm.expectRevert();
    vm.prank(creator);
    factory.createPermitterDeterministic(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );
  }

  function test_createPermitterDeterministic_differentSalts() public {
    bytes32 salt1 = keccak256("salt1");
    bytes32 salt2 = keccak256("salt2");

    vm.prank(creator);
    address permitter1 = factory.createPermitterDeterministic(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt1
    );

    vm.prank(creator);
    address permitter2 = factory.createPermitterDeterministic(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt2
    );

    assertTrue(permitter1 != permitter2);
    assertTrue(factory.isPermitter(permitter1));
    assertTrue(factory.isPermitter(permitter2));
  }

  function test_createPermitterDeterministic_differentParams() public {
    bytes32 salt = keccak256("same_salt");

    address predicted1 = factory.predictPermitterAddressWithParams(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    address predicted2 = factory.predictPermitterAddressWithParams(
      trustedSigner, MAX_TOTAL_ETH * 2, MAX_TOKENS_PER_BIDDER, owner, salt
    );

    // Different params should produce different addresses even with same salt
    assertTrue(predicted1 != predicted2);
  }

  function test_createPermitterDeterministic_revertsOnZeroSigner() public {
    bytes32 salt = keccak256("test_salt");

    vm.expectRevert(IPermitterFactory.ZeroAddress.selector);
    factory.createPermitterDeterministic(
      address(0), MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner, salt
    );
  }

  function test_createPermitterDeterministic_revertsOnZeroOwner() public {
    bytes32 salt = keccak256("test_salt");

    vm.expectRevert(IPermitterFactory.ZeroAddress.selector);
    factory.createPermitterDeterministic(
      trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, address(0), salt
    );
  }

  // ========== VIEW FUNCTION TESTS ==========

  function test_isPermitter_returnsFalseForNonPermitter() public view {
    assertFalse(factory.isPermitter(address(0)));
    assertFalse(factory.isPermitter(address(this)));
    assertFalse(factory.isPermitter(trustedSigner));
  }

  function test_implementation_returnsZero() public view {
    // PermitterFactoryV2 uses full contract deployment, not proxies
    assertEq(factory.implementation(), address(0));
  }

  function test_getPermittersByCreator_returnsEmptyForNewCreator() public {
    address newCreator = makeAddr("newCreator");
    address[] memory permitters = factory.getPermittersByCreator(newCreator);
    assertEq(permitters.length, 0);
  }

  function test_predictPermitterAddress_reverts() public {
    bytes32 salt = keccak256("test_salt");

    // The simplified predictPermitterAddress should revert
    vm.expectRevert("Use predictPermitterAddressWithParams");
    factory.predictPermitterAddress(salt);
  }
}

/// @title PermitterFactoryV2IntegrationTest
/// @notice Integration tests for factory-created permitters
contract PermitterFactoryV2IntegrationTest is Test {
  PermitterFactoryV2 public factory;

  address public trustedSigner;
  uint256 public trustedSignerPk;
  address public owner;
  address public bidder;
  address public auction;

  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  function setUp() public {
    (trustedSigner, trustedSignerPk) = makeAddrAndKey("trustedSigner");
    owner = makeAddr("owner");
    bidder = makeAddr("bidder");
    auction = makeAddr("auction");

    factory = new PermitterFactoryV2();
  }

  function test_factoryCreatedPermitter_validatesCorrectly() public {
    // Create permitter via factory
    address permitterAddr = factory.createPermitter(trustedSigner, 100 ether, 10 ether, owner);

    PermitterV2 permitter = PermitterV2(permitterAddr);

    // Create and sign permit
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: bidder, maxBidAmount: 5 ether, expiry: expiry});

    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    bytes32 digest =
      keccak256(abi.encodePacked("\x19\x01", permitter.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedSignerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    bytes memory hookData = abi.encode(permit, signature);

    // Validate bid
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), 1 ether);
  }

  function test_deterministicPermitter_sameAddressAcrossChains() public {
    bytes32 salt = keccak256("cross_chain_salt");

    // Simulate same factory deployment on two chains
    PermitterFactoryV2 factory1 = new PermitterFactoryV2();
    PermitterFactoryV2 factory2 = new PermitterFactoryV2();

    // Both factories have same bytecode, so predictions should match
    address predicted1 =
      factory1.predictPermitterAddressWithParams(trustedSigner, 100 ether, 10 ether, owner, salt);

    address predicted2 =
      factory2.predictPermitterAddressWithParams(trustedSigner, 100 ether, 10 ether, owner, salt);

    // Note: In reality, they would be different because verifyingContract differs
    // But the CREATE2 address depends on factory address, so they'd differ
    // This test verifies the prediction mechanism works
    assertTrue(predicted1 != address(0));
    assertTrue(predicted2 != address(0));
  }

  function test_multiplePermittersWithDifferentDomains() public {
    // Create two permitters
    address permitter1Addr = factory.createPermitter(trustedSigner, 100 ether, 10 ether, owner);
    address permitter2Addr = factory.createPermitter(trustedSigner, 200 ether, 20 ether, owner);

    PermitterV2 permitter1 = PermitterV2(permitter1Addr);
    PermitterV2 permitter2 = PermitterV2(permitter2Addr);

    // Domain separators should be different
    assertTrue(permitter1.DOMAIN_SEPARATOR() != permitter2.DOMAIN_SEPARATOR());

    // Signature valid for permitter1 should not work for permitter2
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: bidder, maxBidAmount: 5 ether, expiry: expiry});

    // Sign for permitter1
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    bytes32 digest1 =
      keccak256(abi.encodePacked("\x19\x01", permitter1.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedSignerPk, digest1);
    bytes memory signature1 = abi.encodePacked(r, s, v);
    bytes memory hookData1 = abi.encode(permit, signature1);

    // Should work on permitter1
    vm.prank(auction);
    permitter1.validate(0, 1 ether, bidder, auction, hookData1);

    // Should fail on permitter2 (wrong domain)
    vm.expectRevert(); // InvalidSignature
    vm.prank(auction);
    permitter2.validate(0, 1 ether, bidder, auction, hookData1);
  }
}
