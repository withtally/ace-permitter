// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "../src/Permitter.sol";
import {PermitterFactory} from "../src/PermitterFactory.sol";
import {MockCCA} from "./mocks/MockCCA.sol";
import {MockIdentityRegistry} from "./mocks/MockIdentityRegistry.sol";
import {MockPolicyEngine} from "./mocks/MockPolicyEngine.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract PermitterTest is Test {
  PermitterFactory factory;
  Permitter permitter;
  MockCCA cca;
  MockIdentityRegistry identityRegistry;
  MockPolicyEngine policyEngine;

  address owner = makeAddr("owner");
  address bidder1 = makeAddr("bidder1");
  address bidder2 = makeAddr("bidder2");
  bytes32 ccid1 = keccak256("ccid1");
  bytes32 ccid2 = keccak256("ccid2");

  // Default test values (token-denominated)
  uint256 constant PER_USER_LIMIT = 10_000e18; // 10,000 tokens
  uint256 constant GLOBAL_CAP = 50_000_000e18; // 50M tokens

  function setUp() public virtual {
    factory = new PermitterFactory();
    identityRegistry = new MockIdentityRegistry();
    policyEngine = new MockPolicyEngine();

    // Create a permitter through the factory
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: PER_USER_LIMIT,
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    address permitterAddr = factory.createPermitter(config);
    permitter = Permitter(permitterAddr);

    // Create CCA with the permitter
    cca = new MockCCA(permitterAddr);

    // Register CCIDs
    identityRegistry.registerIdentity(bidder1, ccid1);
    identityRegistry.registerIdentity(bidder2, ccid2);
  }

  function _createPermitterAndAuthorizeCCA() internal returns (Permitter) {
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: PER_USER_LIMIT,
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));

    // Authorize the CCA
    vm.prank(owner);
    p.authorizeCCA(address(cca));

    return p;
  }
}

// ========== INITIALIZATION TESTS ==========

contract Initialize is PermitterTest {
  function test_InitializesCorrectly() public view {
    assertEq(permitter.owner(), owner);
    assertEq(permitter.perUserLimit(), PER_USER_LIMIT);
    assertEq(permitter.globalCap(), GLOBAL_CAP);
    assertTrue(permitter.requireSanctionsCheck());
    assertFalse(permitter.requireAllowlist());
    assertFalse(permitter.paused());
    assertEq(permitter.auction(), address(0)); // Not authorized yet
  }

  function test_RevertIf_ReinitializeAttempted() public {
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(0),
      policyEngine: address(0),
      merkleRoot: bytes32(0),
      perUserLimit: 0,
      globalCap: 0,
      requireSanctionsCheck: false,
      requireAllowlist: false
    });

    vm.expectRevert();
    permitter.initialize(owner, config);
  }

  function test_RevertIf_ZeroOwner() public {
    // Deploy a fresh Permitter (not through factory)
    Permitter freshPermitter = new Permitter();

    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(0),
      policyEngine: address(0),
      merkleRoot: bytes32(0),
      perUserLimit: 0,
      globalCap: 0,
      requireSanctionsCheck: false,
      requireAllowlist: false
    });

    vm.expectRevert(Permitter.ZeroAddress.selector);
    freshPermitter.initialize(address(0), config);
  }
}

// ========== CCA AUTHORIZATION TESTS ==========

contract AuthorizeCCA is PermitterTest {
  function test_AuthorizesCCA() public {
    vm.prank(owner);
    permitter.authorizeCCA(address(cca));

    assertEq(permitter.auction(), address(cca));
  }

  function test_EmitsCCAAuthorizedEvent() public {
    vm.prank(owner);
    vm.expectEmit(true, true, true, true);
    emit Permitter.CCAAuthorized(address(cca));
    permitter.authorizeCCA(address(cca));
  }

  function test_RevertIf_NotOwner() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.authorizeCCA(address(cca));
  }

  function test_RevertIf_ZeroAddress() public {
    vm.prank(owner);
    vm.expectRevert(Permitter.ZeroAddress.selector);
    permitter.authorizeCCA(address(0));
  }

  function test_RevertIf_AlreadyAuthorized() public {
    vm.prank(owner);
    permitter.authorizeCCA(address(cca));

    vm.prank(owner);
    vm.expectRevert(Permitter.CCAAlreadyAuthorized.selector);
    permitter.authorizeCCA(makeAddr("anotherCCA"));
  }
}

// ========== VALIDATION TESTS ==========

contract Validate is PermitterTest {
  function setUp() public override {
    super.setUp();
    permitter = _createPermitterAndAuthorizeCCA();
    cca.setValidationHook(address(permitter));
  }

  function test_ValidatesSuccessfulBid() public {
    uint128 amount = 1000e18;

    vm.prank(bidder1);
    cca.submitBid(1e18, amount, bidder1, "");

    // Check state was updated
    assertEq(permitter.getUserCommitted(bidder1), 1000e18);
    assertEq(permitter.totalCommitted(), 1000e18);
  }

  function test_RevertIf_CCANotConfigured() public {
    // Create a permitter without authorizing CCA
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: PER_USER_LIMIT,
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter unconfiguredPermitter = Permitter(factory.createPermitter(config));
    cca.setValidationHook(address(unconfiguredPermitter));

    vm.prank(bidder1);
    vm.expectRevert(Permitter.CCANotConfigured.selector);
    cca.submitBid(1e18, 1000e18, bidder1, "");
  }

  function test_RevertIf_UnauthorizedCCA() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.UnauthorizedCCA.selector);
    permitter.validate(1e18, 1000e18, bidder1, bidder1, "");
  }

  function test_RevertIf_Paused() public {
    vm.prank(owner);
    permitter.setPaused(true);

    vm.prank(bidder1);
    vm.expectRevert(Permitter.Paused.selector);
    cca.submitBid(1e18, 1000e18, bidder1, "");
  }
}

// ========== SANCTIONS TESTS ==========

contract SanctionsCheck is PermitterTest {
  function setUp() public override {
    super.setUp();
    permitter = _createPermitterAndAuthorizeCCA();
    cca.setValidationHook(address(permitter));
  }

  function test_PassesWhenNotSanctioned() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 1000e18, bidder1, "");
    assertEq(permitter.getUserCommitted(bidder1), 1000e18);
  }

  function test_RevertIf_NoCCID() public {
    address noCcidBidder = makeAddr("noCcidBidder");
    // Don't register CCID for this bidder

    vm.prank(noCcidBidder);
    vm.expectRevert(abi.encodeWithSelector(Permitter.NoCCIDFound.selector, noCcidBidder));
    cca.submitBid(1e18, 1000e18, noCcidBidder, "");
  }

  function test_RevertIf_Sanctioned() public {
    // Block the CCID
    policyEngine.setAllowAll(false);
    policyEngine.blockCCID(ccid1);

    vm.prank(bidder1);
    vm.expectRevert(abi.encodeWithSelector(Permitter.SanctionsFailed.selector, bidder1, ccid1));
    cca.submitBid(1e18, 1000e18, bidder1, "");
  }

  function test_SkipsSanctionsWhenNotRequired() public {
    // Create permitter without sanctions check
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: PER_USER_LIMIT,
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: false, // Disabled
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    p.authorizeCCA(address(cca));
    cca.setValidationHook(address(p));

    // Bidder without CCID should pass
    address noCcidBidder = makeAddr("noCcidBidder");
    vm.prank(noCcidBidder);
    cca.submitBid(1e18, 1000e18, noCcidBidder, "");

    assertEq(p.getUserCommitted(noCcidBidder), 1000e18);
  }
}

// ========== PER-USER LIMIT TESTS ==========

contract PerUserLimit is PermitterTest {
  function setUp() public override {
    super.setUp();
    permitter = _createPermitterAndAuthorizeCCA();
    cca.setValidationHook(address(permitter));
  }

  function test_AllowsBidWithinLimit() public {
    uint128 amount = 5000e18; // Under 10k limit

    vm.prank(bidder1);
    cca.submitBid(1e18, amount, bidder1, "");

    assertEq(permitter.getUserCommitted(bidder1), 5000e18);
    assertEq(permitter.getRemainingUserCapacity(bidder1), 5000e18);
  }

  function test_AllowsMultipleBidsUpToLimit() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 4000e18, bidder1, "");

    vm.prank(bidder1);
    cca.submitBid(1e18, 4000e18, bidder1, "");

    vm.prank(bidder1);
    cca.submitBid(1e18, 2000e18, bidder1, ""); // Exactly at limit

    assertEq(permitter.getUserCommitted(bidder1), 10_000e18);
    assertEq(permitter.getRemainingUserCapacity(bidder1), 0);
  }

  function test_RevertIf_ExceedsLimit() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 8000e18, bidder1, "");

    vm.prank(bidder1);
    vm.expectRevert(
      abi.encodeWithSelector(Permitter.IndividualLimitExceeded.selector, ccid1, 3000e18, 2000e18)
    );
    cca.submitBid(1e18, 3000e18, bidder1, "");
  }

  function test_TracksByCCIDNotAddress() public {
    // Register second address for same CCID
    address bidder1Alt = makeAddr("bidder1Alt");
    identityRegistry.registerIdentity(bidder1Alt, ccid1);

    // Bid from first address
    vm.prank(bidder1);
    cca.submitBid(1e18, 6000e18, bidder1, "");

    // Bid from second address should share the same limit
    vm.prank(bidder1Alt);
    cca.submitBid(1e18, 3000e18, bidder1Alt, "");

    // Total should be accumulated
    assertEq(permitter.getUserCommitted(bidder1), 9000e18);
    assertEq(permitter.getUserCommitted(bidder1Alt), 9000e18);

    // Third bid should exceed limit
    vm.prank(bidder1);
    vm.expectRevert(
      abi.encodeWithSelector(Permitter.IndividualLimitExceeded.selector, ccid1, 2000e18, 1000e18)
    );
    cca.submitBid(1e18, 2000e18, bidder1, "");
  }

  function test_NoLimitWhenZero() public {
    // Create permitter with no per-user limit
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: 0, // No limit
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    p.authorizeCCA(address(cca));
    cca.setValidationHook(address(p));

    // Should allow very large bid
    vm.prank(bidder1);
    cca.submitBid(1e18, 1_000_000e18, bidder1, "");

    assertEq(p.getRemainingUserCapacity(bidder1), type(uint256).max);
  }
}

// ========== GLOBAL CAP TESTS ==========

contract GlobalCap is PermitterTest {
  function setUp() public override {
    super.setUp();

    // Create permitter with smaller global cap for testing
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: 100_000e18, // Higher user limit
      globalCap: 20_000e18, // 20k global cap
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    permitter = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    permitter.authorizeCCA(address(cca));
    cca.setValidationHook(address(permitter));
  }

  function test_AllowsBidWithinGlobalCap() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 10_000e18, bidder1, "");

    assertEq(permitter.totalCommitted(), 10_000e18);
    assertEq(permitter.getRemainingGlobalCapacity(), 10_000e18);
  }

  function test_AllowsMultipleUsersBidsUpToCap() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 10_000e18, bidder1, "");

    vm.prank(bidder2);
    cca.submitBid(1e18, 10_000e18, bidder2, "");

    assertEq(permitter.totalCommitted(), 20_000e18);
    assertEq(permitter.getRemainingGlobalCapacity(), 0);
  }

  function test_RevertIf_ExceedsGlobalCap() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 15_000e18, bidder1, "");

    vm.prank(bidder2);
    vm.expectRevert(
      abi.encodeWithSelector(Permitter.GlobalCapExceeded.selector, 10_000e18, 5000e18)
    );
    cca.submitBid(1e18, 10_000e18, bidder2, "");
  }

  function test_NoCapWhenZero() public {
    // Create permitter with no global cap
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: 0,
      globalCap: 0, // No cap
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    p.authorizeCCA(address(cca));
    cca.setValidationHook(address(p));

    // Should allow very large bid
    vm.prank(bidder1);
    cca.submitBid(1e18, 1_000_000_000e18, bidder1, "");

    assertEq(p.getRemainingGlobalCapacity(), type(uint256).max);
  }
}

// ========== ALLOWLIST TESTS ==========

contract AllowlistCheck is PermitterTest {
  bytes32 testMerkleRoot;
  bytes32[] proof1;

  function setUp() public override {
    super.setUp();

    // Build a simple merkle tree with bidder1 and bidder2
    bytes32 leaf1 = keccak256(bytes.concat(keccak256(abi.encode(bidder1))));
    bytes32 leaf2 = keccak256(bytes.concat(keccak256(abi.encode(bidder2))));

    // Simple 2-leaf tree: root = hash(leaf1, leaf2)
    if (leaf1 < leaf2) {
      testMerkleRoot = keccak256(bytes.concat(leaf1, leaf2));
      proof1 = new bytes32[](1);
      proof1[0] = leaf2;
    } else {
      testMerkleRoot = keccak256(bytes.concat(leaf2, leaf1));
      proof1 = new bytes32[](1);
      proof1[0] = leaf2;
    }

    // Create permitter with allowlist
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: testMerkleRoot,
      perUserLimit: PER_USER_LIMIT,
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: true,
      requireAllowlist: true
    });

    vm.prank(owner);
    permitter = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    permitter.authorizeCCA(address(cca));
    cca.setValidationHook(address(permitter));
  }

  function test_PassesWithValidProof() public {
    vm.prank(bidder1);
    cca.submitBid(1e18, 1000e18, bidder1, abi.encode(proof1));

    assertEq(permitter.getUserCommitted(bidder1), 1000e18);
  }

  function test_RevertIf_NotOnAllowlist() public {
    address notAllowed = makeAddr("notAllowed");
    identityRegistry.registerIdentity(notAllowed, keccak256("notAllowedCcid"));

    // Empty proof
    bytes32[] memory emptyProof = new bytes32[](0);

    vm.prank(notAllowed);
    vm.expectRevert(abi.encodeWithSelector(Permitter.NotOnAllowlist.selector, notAllowed));
    cca.submitBid(1e18, 1000e18, notAllowed, abi.encode(emptyProof));
  }

  function test_RevertIf_InvalidProof() public {
    bytes32[] memory wrongProof = new bytes32[](1);
    wrongProof[0] = keccak256("wrong");

    vm.prank(bidder1);
    vm.expectRevert(abi.encodeWithSelector(Permitter.NotOnAllowlist.selector, bidder1));
    cca.submitBid(1e18, 1000e18, bidder1, abi.encode(wrongProof));
  }

  function test_SkipsAllowlistWhenNoMerkleRoot() public {
    // Create permitter with allowlist required but no merkle root
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0), // No merkle root
      perUserLimit: PER_USER_LIMIT,
      globalCap: GLOBAL_CAP,
      requireSanctionsCheck: true,
      requireAllowlist: true
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    p.authorizeCCA(address(cca));
    cca.setValidationHook(address(p));

    // Should pass without proof
    vm.prank(bidder1);
    cca.submitBid(1e18, 1000e18, bidder1, "");

    assertEq(p.getUserCommitted(bidder1), 1000e18);
  }
}

// ========== CHECK ELIGIBILITY TESTS ==========

contract CheckEligibility is PermitterTest {
  function setUp() public override {
    super.setUp();
    permitter = _createPermitterAndAuthorizeCCA();
    cca.setValidationHook(address(permitter));
  }

  function test_ReturnsTrueForEligibleBidder() public view {
    assertTrue(permitter.checkEligibility(bidder1));
  }

  function test_ReturnsFalseIfNoCCID() public {
    address noCcidBidder = makeAddr("noCcidBidder");
    assertFalse(permitter.checkEligibility(noCcidBidder));
  }

  function test_ReturnsFalseIfAtLimit() public {
    // Use up the entire limit
    vm.prank(bidder1);
    cca.submitBid(1e18, uint128(PER_USER_LIMIT), bidder1, "");

    assertFalse(permitter.checkEligibility(bidder1));
  }

  function test_ReturnsFalseIfGlobalCapReached() public {
    // Create permitter with small global cap
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: type(uint256).max,
      globalCap: 1000e18,
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    p.authorizeCCA(address(cca));
    cca.setValidationHook(address(p));

    // Fill up global cap
    vm.prank(bidder1);
    cca.submitBid(1e18, 1000e18, bidder1, "");

    // bidder2 should now be ineligible
    assertFalse(p.checkEligibility(bidder2));
  }
}

// ========== ADMIN TESTS ==========

contract AdminFunctions is PermitterTest {
  function setUp() public override {
    super.setUp();
    permitter = _createPermitterAndAuthorizeCCA();
  }

  function test_SetPerUserLimit() public {
    vm.prank(owner);
    permitter.setPerUserLimit(20_000e18);

    assertEq(permitter.perUserLimit(), 20_000e18);
  }

  function test_SetPerUserLimit_EmitsEvent() public {
    vm.prank(owner);
    vm.expectEmit(true, true, true, true);
    emit Permitter.PerUserLimitUpdated(PER_USER_LIMIT, 20_000e18);
    permitter.setPerUserLimit(20_000e18);
  }

  function test_SetPerUserLimit_RevertIf_NotOwner() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.setPerUserLimit(20_000e18);
  }

  function test_SetGlobalCap() public {
    vm.prank(owner);
    permitter.setGlobalCap(100_000_000e18);

    assertEq(permitter.globalCap(), 100_000_000e18);
  }

  function test_SetMerkleRoot() public {
    bytes32 newRoot = keccak256("new-root");

    vm.prank(owner);
    permitter.setMerkleRoot(newRoot);

    assertEq(permitter.merkleRoot(), newRoot);
  }

  function test_SetPaused() public {
    vm.prank(owner);
    permitter.setPaused(true);

    assertTrue(permitter.paused());

    vm.prank(owner);
    permitter.setPaused(false);

    assertFalse(permitter.paused());
  }

  function test_TransferOwnership() public {
    address newOwner = makeAddr("newOwner");

    vm.prank(owner);
    permitter.transferOwnership(newOwner);

    assertEq(permitter.owner(), newOwner);
  }

  function test_TransferOwnership_RevertIf_ZeroAddress() public {
    vm.prank(owner);
    vm.expectRevert(Permitter.ZeroAddress.selector);
    permitter.transferOwnership(address(0));
  }

  function test_SetGlobalCap_RevertIf_NotOwner() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.setGlobalCap(100_000_000e18);
  }

  function test_SetMerkleRoot_RevertIf_NotOwner() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.setMerkleRoot(keccak256("new-root"));
  }

  function test_SetPaused_RevertIf_NotOwner() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.setPaused(true);
  }

  function test_TransferOwnership_RevertIf_NotOwner() public {
    vm.prank(bidder1);
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.transferOwnership(bidder1);
  }
}

// ========== FUZZ TESTS ==========

contract FuzzTests is PermitterTest {
  function setUp() public override {
    super.setUp();
    permitter = _createPermitterAndAuthorizeCCA();
    cca.setValidationHook(address(permitter));
  }

  function testFuzz_MultiplePurchasesAccumulate(uint128[5] memory amounts) public {
    uint256 total = 0;

    for (uint256 i = 0; i < 5; i++) {
      // Bound to keep under per-user limit
      uint128 amount = uint128(bound(amounts[i], 0, 1000e18));
      if (amount == 0) continue;

      uint256 amountTokens = uint256(amount);
      if (total + amountTokens > PER_USER_LIMIT) break;

      vm.prank(bidder1);
      cca.submitBid(1e18, amount, bidder1, "");
      total += amountTokens;
    }

    assertEq(permitter.getUserCommitted(bidder1), total);
  }

  function testFuzz_GlobalCapEnforced(uint128 amount1, uint128 amount2) public {
    // Create permitter with smaller global cap
    Permitter.Config memory config = Permitter.Config({
      identityRegistry: address(identityRegistry),
      policyEngine: address(policyEngine),
      merkleRoot: bytes32(0),
      perUserLimit: type(uint256).max,
      globalCap: 100_000e18,
      requireSanctionsCheck: true,
      requireAllowlist: false
    });

    vm.prank(owner);
    Permitter p = Permitter(factory.createPermitter(config));
    vm.prank(owner);
    p.authorizeCCA(address(cca));
    cca.setValidationHook(address(p));

    amount1 = uint128(bound(amount1, 1, 50_000e18));
    amount2 = uint128(bound(amount2, 1, 50_000e18));

    vm.prank(bidder1);
    cca.submitBid(1e18, amount1, bidder1, "");

    if (uint256(amount1) + uint256(amount2) <= 100_000e18) {
      vm.prank(bidder2);
      cca.submitBid(1e18, amount2, bidder2, "");
      assertEq(p.totalCommitted(), uint256(amount1) + uint256(amount2));
    } else {
      uint256 remaining = 100_000e18 - uint256(amount1);
      vm.prank(bidder2);
      vm.expectRevert(
        abi.encodeWithSelector(Permitter.GlobalCapExceeded.selector, uint256(amount2), remaining)
      );
      cca.submitBid(1e18, amount2, bidder2, "");
    }
  }
}
