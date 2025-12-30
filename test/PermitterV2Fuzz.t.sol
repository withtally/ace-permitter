// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";
import {PermitterV2} from "../src/PermitterV2.sol";
import {IPermitter} from "../src/interfaces/IPermitter.sol";

/// @title PermitterV2FuzzTest
/// @notice Fuzz tests for PermitterV2 contract
contract PermitterV2FuzzTest is Test {
  PermitterV2 public permitter;

  address public trustedSigner;
  uint256 public trustedSignerPk;
  address public owner;
  address public auction;

  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  function setUp() public {
    (trustedSigner, trustedSignerPk) = makeAddrAndKey("trustedSigner");
    owner = makeAddr("owner");
    auction = makeAddr("auction");

    permitter = new PermitterV2(trustedSigner, 1000 ether, 100 ether, owner);
  }

  function _signPermit(IPermitter.Permit memory permit, uint256 signerPk)
    internal
    view
    returns (bytes memory)
  {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));

    bytes32 digest =
      keccak256(abi.encodePacked("\x19\x01", permitter.DOMAIN_SEPARATOR(), structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
    return abi.encodePacked(r, s, v);
  }

  // ========== SIGNATURE VERIFICATION FUZZ TESTS ==========

  /// @notice Fuzz test: Only signatures from trustedSigner should pass
  function testFuzz_signatureVerification_onlyTrustedSignerPasses(
    address randomBidder,
    uint256 randomAmount,
    uint256 randomExpiry,
    uint256 randomSignerPk
  ) public {
    // Bound inputs to reasonable ranges
    vm.assume(randomBidder != address(0));
    vm.assume(randomAmount > 0 && randomAmount <= 100 ether);
    vm.assume(randomExpiry > block.timestamp && randomExpiry < block.timestamp + 365 days);
    vm.assume(randomSignerPk != 0 && randomSignerPk < type(uint256).max / 2);
    vm.assume(randomSignerPk != trustedSignerPk);

    IPermitter.Permit memory permit = IPermitter.Permit({
      bidder: randomBidder, maxBidAmount: randomAmount * 2, expiry: randomExpiry
    });

    // Sign with random key (not trusted signer)
    bytes memory signature = _signPermitWithKey(permit, randomSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    // Should revert with InvalidSignature
    vm.expectRevert();
    vm.prank(auction);
    permitter.validate(0, uint128(randomAmount), randomBidder, auction, hookData);
  }

  function _signPermitWithKey(IPermitter.Permit memory permit, uint256 signerPk)
    internal
    view
    returns (bytes memory)
  {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));

    bytes32 digest =
      keccak256(abi.encodePacked("\x19\x01", permitter.DOMAIN_SEPARATOR(), structHash));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
    return abi.encodePacked(r, s, v);
  }

  /// @notice Fuzz test: Valid signatures from trusted signer should pass
  function testFuzz_signatureVerification_trustedSignerPasses(
    uint256 bidderSeed,
    uint128 randomAmount,
    uint256 randomExpiry
  ) public {
    // Create a valid bidder address from seed (never zero)
    address randomBidder = address(uint160(bound(bidderSeed, 1, type(uint160).max)));

    // Bound amount to valid range
    randomAmount = uint128(bound(randomAmount, 1, 100 ether));

    // Bound expiry to future (at least current timestamp)
    randomExpiry = bound(randomExpiry, block.timestamp, block.timestamp + 365 days);

    // maxBid must be >= amount
    uint256 randomMaxBid = bound(randomAmount, randomAmount, 100 ether);

    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: randomBidder, maxBidAmount: randomMaxBid, expiry: randomExpiry});

    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    // Should succeed
    vm.prank(auction);
    permitter.validate(0, randomAmount, randomBidder, auction, hookData);

    assertEq(permitter.getBidAmount(randomBidder), uint256(randomAmount));
  }

  // ========== CAP INVARIANT FUZZ TESTS ==========

  /// @notice Fuzz test: Cumulative bids never exceed personal cap
  function testFuzz_capInvariant_cumulativeNeverExceedsCap(uint256 seed, uint8 numBids) public {
    // Bound number of bids to 1-10
    numBids = uint8(bound(numBids, 1, 10));

    address bidder = makeAddr("testBidder");
    uint256 personalCap = 50 ether;
    uint256 expiry = block.timestamp + 1 hours;

    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: bidder, maxBidAmount: personalCap, expiry: expiry});
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    uint256 totalBid = 0;

    for (uint256 i = 0; i < numBids; i++) {
      // Generate deterministic amount from seed
      uint128 amount = uint128(bound(uint256(keccak256(abi.encode(seed, i))), 1, 10 ether));

      if (totalBid + amount <= personalCap) {
        vm.prank(auction);
        permitter.validate(0, amount, bidder, auction, hookData);
        totalBid += amount;
      } else {
        vm.expectRevert();
        vm.prank(auction);
        permitter.validate(0, amount, bidder, auction, hookData);
      }
    }

    // Invariant: cumulative bids never exceed cap
    assertLe(permitter.getBidAmount(bidder), personalCap);
  }

  /// @notice Fuzz test: Total raised never exceeds global cap
  function testFuzz_capInvariant_totalNeverExceedsGlobalCap(uint256 seed, uint8 numBidders) public {
    numBidders = uint8(bound(numBidders, 1, 5));

    // Create permitter with small global cap for testing
    PermitterV2 smallCapPermitter = new PermitterV2(trustedSigner, 50 ether, 100 ether, owner);

    uint256 expiry = block.timestamp + 1 hours;
    uint256 totalRaised = 0;

    for (uint256 i = 0; i < numBidders; i++) {
      address bidder = address(uint160(uint256(keccak256(abi.encode(seed, i)))));
      uint128 amount =
        uint128(bound(uint256(keccak256(abi.encode(seed, i, "amount"))), 1 ether, 20 ether));

      if (bidder == address(0)) continue;

      IPermitter.Permit memory permit =
        IPermitter.Permit({bidder: bidder, maxBidAmount: 100 ether, expiry: expiry});

      bytes32 structHash =
        keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
      bytes32 digest =
        keccak256(abi.encodePacked("\x19\x01", smallCapPermitter.DOMAIN_SEPARATOR(), structHash));
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedSignerPk, digest);
      bytes memory signature = abi.encodePacked(r, s, v);
      bytes memory hookData = abi.encode(permit, signature);

      if (totalRaised + amount <= 50 ether) {
        vm.prank(auction);
        smallCapPermitter.validate(0, amount, bidder, auction, hookData);
        totalRaised += amount;
      } else {
        vm.expectRevert();
        vm.prank(auction);
        smallCapPermitter.validate(0, amount, bidder, auction, hookData);
      }
    }

    // Invariant: total raised never exceeds global cap
    assertLe(smallCapPermitter.getTotalEthRaised(), 50 ether);
  }

  // ========== EXPIRY FUZZ TESTS ==========

  /// @notice Fuzz test: Expired permits always fail
  function testFuzz_expiredPermits_alwaysFail(
    uint256 bidderSeed,
    uint128 randomAmount,
    uint256 pastExpiry
  ) public {
    // Create valid bidder from seed
    address randomBidder = address(uint160(bound(bidderSeed, 1, type(uint160).max)));

    // Bound amount to valid range
    randomAmount = uint128(bound(randomAmount, 1, 10 ether));

    // Bound pastExpiry to be in the past (0 to block.timestamp - 1)
    // If block.timestamp is 0, skip (shouldn't happen in practice)
    if (block.timestamp == 0) return;
    pastExpiry = bound(pastExpiry, 0, block.timestamp - 1);

    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: randomBidder, maxBidAmount: randomAmount * 2, expiry: pastExpiry});

    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, pastExpiry, block.timestamp)
    );
    vm.prank(auction);
    permitter.validate(0, randomAmount, randomBidder, auction, hookData);
  }

  /// @notice Fuzz test: Valid expiry permits succeed (when all other conditions met)
  function testFuzz_validExpiry_succeeds(
    address randomBidder,
    uint128 randomAmount,
    uint256 futureExpiry
  ) public {
    vm.assume(randomBidder != address(0));
    vm.assume(randomAmount > 0 && randomAmount <= 10 ether);
    vm.assume(futureExpiry >= block.timestamp && futureExpiry < block.timestamp + 365 days);

    IPermitter.Permit memory permit = IPermitter.Permit({
      bidder: randomBidder, maxBidAmount: randomAmount * 2, expiry: futureExpiry
    });

    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    vm.prank(auction);
    permitter.validate(0, randomAmount, randomBidder, auction, hookData);

    assertEq(permitter.getBidAmount(randomBidder), uint256(randomAmount));
  }

  // ========== BIDDER MISMATCH FUZZ TESTS ==========

  /// @notice Fuzz test: Permit for different bidder always fails
  function testFuzz_bidderMismatch_alwaysFails(
    address permitBidder,
    address actualBidder,
    uint128 amount
  ) public {
    vm.assume(permitBidder != address(0));
    vm.assume(actualBidder != address(0));
    vm.assume(permitBidder != actualBidder);
    vm.assume(amount > 0 && amount <= 10 ether);

    uint256 expiry = block.timestamp + 1 hours;

    IPermitter.Permit memory permit =
      IPermitter.Permit({bidder: permitBidder, maxBidAmount: amount * 2, expiry: expiry});

    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, actualBidder, permitBidder)
    );
    vm.prank(auction);
    permitter.validate(0, amount, actualBidder, auction, hookData);
  }

  // ========== STATE CONSISTENCY FUZZ TESTS ==========

  /// @notice Fuzz test: State is consistent after multiple operations
  function testFuzz_stateConsistency_afterMultipleOps(uint256 seed, uint8 numBidders) public {
    numBidders = uint8(bound(numBidders, 1, 5));

    uint256 expiry = block.timestamp + 1 hours;
    uint256 expectedTotal = 0;

    for (uint256 i = 0; i < numBidders; i++) {
      address bidder = address(uint160(uint256(keccak256(abi.encode(seed, i)))));
      uint128 amount =
        uint128(bound(uint256(keccak256(abi.encode(seed, i, "amount"))), 1 ether, 10 ether));

      if (bidder == address(0)) continue;

      // Skip if would exceed caps
      uint256 currentBid = permitter.getBidAmount(bidder);
      if (currentBid + amount > 100 ether) continue;
      if (expectedTotal + amount > 1000 ether) continue;

      IPermitter.Permit memory permit =
        IPermitter.Permit({bidder: bidder, maxBidAmount: 100 ether, expiry: expiry});
      bytes memory signature = _signPermit(permit, trustedSignerPk);
      bytes memory hookData = abi.encode(permit, signature);

      uint256 bidderBefore = permitter.getBidAmount(bidder);
      uint256 totalBefore = permitter.getTotalEthRaised();

      vm.prank(auction);
      permitter.validate(0, amount, bidder, auction, hookData);

      // State consistency checks
      assertEq(permitter.getBidAmount(bidder), bidderBefore + amount);
      assertEq(permitter.getTotalEthRaised(), totalBefore + amount);

      expectedTotal += amount;
    }

    // Final consistency check
    assertEq(permitter.getTotalEthRaised(), expectedTotal);
  }
}

/// @title PermitterV2AdminFuzzTest
/// @notice Fuzz tests for admin functions
contract PermitterV2AdminFuzzTest is Test {
  PermitterV2 public permitter;

  address public trustedSigner;
  address public owner;

  function setUp() public {
    trustedSigner = makeAddr("trustedSigner");
    owner = makeAddr("owner");

    permitter = new PermitterV2(trustedSigner, 100 ether, 10 ether, owner);
  }

  /// @notice Fuzz test: Only owner can update caps
  function testFuzz_onlyOwner_canUpdateCaps(address caller, uint256 newCap) public {
    vm.assume(caller != owner);

    vm.prank(caller);
    vm.expectRevert(IPermitter.Unauthorized.selector);
    permitter.updateMaxTotalEth(newCap);

    vm.prank(caller);
    vm.expectRevert(IPermitter.Unauthorized.selector);
    permitter.updateMaxTokensPerBidder(newCap);
  }

  /// @notice Fuzz test: Owner can set any cap value
  function testFuzz_owner_canSetAnyCap(uint256 newMaxTotal, uint256 newMaxPerBidder) public {
    vm.prank(owner);
    permitter.updateMaxTotalEth(newMaxTotal);
    assertEq(permitter.maxTotalEth(), newMaxTotal);

    vm.prank(owner);
    permitter.updateMaxTokensPerBidder(newMaxPerBidder);
    assertEq(permitter.maxTokensPerBidder(), newMaxPerBidder);
  }

  /// @notice Fuzz test: Only owner can update signer
  function testFuzz_onlyOwner_canUpdateSigner(address caller, address newSigner) public {
    vm.assume(caller != owner);
    vm.assume(newSigner != address(0));

    vm.prank(caller);
    vm.expectRevert(IPermitter.Unauthorized.selector);
    permitter.updateTrustedSigner(newSigner);
  }

  /// @notice Fuzz test: Owner can set any valid signer
  function testFuzz_owner_canSetAnySigner(address newSigner) public {
    vm.assume(newSigner != address(0));

    vm.prank(owner);
    permitter.updateTrustedSigner(newSigner);
    assertEq(permitter.trustedSigner(), newSigner);
  }

  /// @notice Fuzz test: Only owner can pause/unpause
  function testFuzz_onlyOwner_canPause(address caller) public {
    vm.assume(caller != owner);

    vm.prank(caller);
    vm.expectRevert(IPermitter.Unauthorized.selector);
    permitter.pause();

    vm.prank(owner);
    permitter.pause();

    vm.prank(caller);
    vm.expectRevert(IPermitter.Unauthorized.selector);
    permitter.unpause();
  }
}
