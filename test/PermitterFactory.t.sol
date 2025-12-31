// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PermitterFactory} from "../src/PermitterFactory.sol";
import {Permitter} from "../src/Permitter.sol";

contract PermitterFactoryTest is Test {
  PermitterFactory factory;
  address creator = makeAddr("creator");

  function setUp() public {
    factory = new PermitterFactory();
  }

  function _defaultConfig() internal pure returns (Permitter.Config memory) {
    return Permitter.Config({
      identityRegistry: address(0),
      policyEngine: address(0),
      merkleRoot: bytes32(0),
      perUserLimit: 10_000e18,
      globalCap: 50_000_000e18,
      requireSanctionsCheck: false,
      requireAllowlist: false
    });
  }
}

contract Constructor is PermitterFactoryTest {
  function test_DeploysImplementation() public view {
    assertNotEq(factory.IMPLEMENTATION(), address(0));
  }

  function test_ImplementationIsPermitter() public view {
    Permitter impl = Permitter(factory.IMPLEMENTATION());
    // Implementation should exist and be a Permitter
    assertEq(impl.owner(), address(0)); // Not initialized
  }
}

contract CreatePermitter is PermitterFactoryTest {
  function test_CreatesPermitter() public {
    vm.prank(creator);
    address permitter = factory.createPermitter(_defaultConfig());

    assertNotEq(permitter, address(0));
    assertTrue(factory.isPermitter(permitter));
  }

  function test_InitializesPermitterCorrectly() public {
    Permitter.Config memory config = _defaultConfig();
    config.perUserLimit = 5000e18;
    config.globalCap = 1_000_000e18;

    vm.prank(creator);
    address permitterAddr = factory.createPermitter(config);
    Permitter permitter = Permitter(permitterAddr);

    assertEq(permitter.owner(), creator);
    assertEq(permitter.auction(), address(0)); // Not authorized yet
    assertEq(permitter.perUserLimit(), 5000e18);
    assertEq(permitter.globalCap(), 1_000_000e18);
  }

  function test_EmitsPermitterCreatedEvent() public {
    vm.prank(creator);
    vm.expectEmit(false, true, false, false);
    emit PermitterFactory.PermitterCreated(address(0), creator);
    factory.createPermitter(_defaultConfig());
  }

  function test_RegistersInPermittersByCreator() public {
    vm.prank(creator);
    address permitter1 = factory.createPermitter(_defaultConfig());
    vm.prank(creator);
    address permitter2 = factory.createPermitter(_defaultConfig());

    address[] memory permitters = factory.getPermittersByCreator(creator);
    assertEq(permitters.length, 2);
    assertEq(permitters[0], permitter1);
    assertEq(permitters[1], permitter2);
  }
}

contract CreatePermitterDeterministic is PermitterFactoryTest {
  function test_CreatesDeterministicPermitter() public {
    bytes32 salt = keccak256("test-salt");

    address predicted = factory.predictPermitterAddress(salt);

    vm.prank(creator);
    address permitter = factory.createPermitterDeterministic(_defaultConfig(), salt);

    assertEq(permitter, predicted);
    assertTrue(factory.isPermitter(permitter));
  }

  function test_SameSaltSameAddress() public view {
    bytes32 salt = keccak256("test-salt");

    address predicted1 = factory.predictPermitterAddress(salt);
    address predicted2 = factory.predictPermitterAddress(salt);

    assertEq(predicted1, predicted2);
  }

  function test_DifferentSaltDifferentAddress() public view {
    bytes32 salt1 = keccak256("test-salt-1");
    bytes32 salt2 = keccak256("test-salt-2");

    address predicted1 = factory.predictPermitterAddress(salt1);
    address predicted2 = factory.predictPermitterAddress(salt2);

    assertNotEq(predicted1, predicted2);
  }
}

contract GetPermittersByCreator is PermitterFactoryTest {
  function test_ReturnsEmptyArrayForNewCreator() public {
    address unknown = makeAddr("unknown");
    address[] memory permitters = factory.getPermittersByCreator(unknown);
    assertEq(permitters.length, 0);
  }

  function test_ReturnsCorrectPermitters() public {
    vm.startPrank(creator);
    address p1 = factory.createPermitter(_defaultConfig());
    address p2 = factory.createPermitter(_defaultConfig());
    address p3 = factory.createPermitter(_defaultConfig());
    vm.stopPrank();

    address[] memory permitters = factory.getPermittersByCreator(creator);
    assertEq(permitters.length, 3);
    assertEq(permitters[0], p1);
    assertEq(permitters[1], p2);
    assertEq(permitters[2], p3);
  }
}

contract AuthorizeCCAAfterCreate is PermitterFactoryTest {
  function test_OwnerCanAuthorizeCCA() public {
    vm.prank(creator);
    address permitterAddr = factory.createPermitter(_defaultConfig());
    Permitter permitter = Permitter(permitterAddr);

    address cca = makeAddr("cca");

    vm.prank(creator);
    permitter.authorizeCCA(cca);

    assertEq(permitter.auction(), cca);
  }

  function test_NonOwnerCannotAuthorizeCCA() public {
    vm.prank(creator);
    address permitterAddr = factory.createPermitter(_defaultConfig());
    Permitter permitter = Permitter(permitterAddr);

    address cca = makeAddr("cca");
    address notOwner = makeAddr("notOwner");

    vm.prank(notOwner);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.authorizeCCA(cca);
  }
}
