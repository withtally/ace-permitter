// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";
import {PermitterV2} from "../src/PermitterV2.sol";
import {IPermitter} from "../src/interfaces/IPermitter.sol";

/// @title PermitterV2Test
/// @notice Comprehensive tests for PermitterV2 contract
contract PermitterV2Test is Test {
  PermitterV2 public permitter;

  address public trustedSigner;
  uint256 public trustedSignerPk;
  address public owner;
  address public bidder;
  address public anotherBidder;
  address public auction;

  uint256 public constant MAX_TOTAL_ETH = 100 ether;
  uint256 public constant MAX_TOKENS_PER_BIDDER = 10 ether;

  bytes32 public constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");

  event PermitVerified(
    address indexed bidder,
    uint256 bidAmount,
    uint256 remainingPersonalCap,
    uint256 remainingTotalCap
  );

  event CapUpdated(IPermitter.CapType indexed capType, uint256 oldCap, uint256 newCap);
  event SignerUpdated(address indexed oldSigner, address indexed newSigner);
  event Paused(address indexed by);
  event Unpaused(address indexed by);

  function setUp() public {
    // Create accounts
    (trustedSigner, trustedSignerPk) = makeAddrAndKey("trustedSigner");
    owner = makeAddr("owner");
    bidder = makeAddr("bidder");
    anotherBidder = makeAddr("anotherBidder");
    auction = makeAddr("auction");

    // Deploy permitter
    permitter = new PermitterV2(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);
  }

  // ========== HELPER FUNCTIONS ==========

  function _createPermit(address _bidder, uint256 maxBidAmount, uint256 expiry)
    internal
    view
    returns (IPermitter.Permit memory)
  {
    return IPermitter.Permit({bidder: _bidder, maxBidAmount: maxBidAmount, expiry: expiry});
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

  function _encodeHookData(IPermitter.Permit memory permit, bytes memory signature)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encode(permit, signature);
  }

  // ========== INITIALIZATION TESTS ==========

  function test_initialization() public view {
    assertEq(permitter.trustedSigner(), trustedSigner);
    assertEq(permitter.maxTotalEth(), MAX_TOTAL_ETH);
    assertEq(permitter.maxTokensPerBidder(), MAX_TOKENS_PER_BIDDER);
    assertEq(permitter.owner(), owner);
    assertEq(permitter.paused(), false);
    assertEq(permitter.totalEthRaised(), 0);
  }

  function test_constructor_revertsOnZeroSigner() public {
    vm.expectRevert(IPermitter.ZeroAddress.selector);
    new PermitterV2(address(0), MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, owner);
  }

  function test_constructor_revertsOnZeroOwner() public {
    vm.expectRevert(IPermitter.ZeroAddress.selector);
    new PermitterV2(trustedSigner, MAX_TOTAL_ETH, MAX_TOKENS_PER_BIDDER, address(0));
  }

  // ========== VALIDATION TESTS ==========

  function test_validate_successWithValidPermit() public {
    uint256 bidAmount = 1 ether;
    uint256 expiry = block.timestamp + 1 hours;

    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    vm.expectEmit(true, false, false, true);
    emit PermitVerified(bidder, bidAmount, 4 ether, MAX_TOTAL_ETH - bidAmount);

    vm.prank(auction);
    permitter.validate(0, uint128(bidAmount), bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), bidAmount);
    assertEq(permitter.getTotalEthRaised(), bidAmount);
  }

  function test_validate_multipleBidsFromSameBidder() public {
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    // First bid
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);

    // Second bid
    vm.prank(auction);
    permitter.validate(0, 2 ether, bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), 3 ether);
    assertEq(permitter.getTotalEthRaised(), 3 ether);
  }

  function test_validate_revertsWhenPaused() public {
    vm.prank(owner);
    permitter.pause();

    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, block.timestamp + 1 hours);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    vm.expectRevert(IPermitter.ContractPaused.selector);
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);
  }

  function test_validate_revertsOnExpiredPermit() public {
    uint256 expiry = block.timestamp - 1; // Already expired

    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);
  }

  function test_validate_revertsOnInvalidSignature() public {
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);

    // Sign with wrong key
    (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
    bytes memory signature = _signPermit(permit, wrongPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    vm.expectRevert(); // InvalidSignature
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);
  }

  function test_validate_revertsOnWrongBidder() public {
    uint256 expiry = block.timestamp + 1 hours;

    // Permit is for bidder, but anotherBidder is trying to use it
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.InvalidSignature.selector, anotherBidder, bidder)
    );
    vm.prank(auction);
    permitter.validate(0, 1 ether, anotherBidder, auction, hookData);
  }

  function test_validate_revertsOnExceedsPersonalCap() public {
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    // First bid uses up 4 ether of the 5 ether cap
    vm.prank(auction);
    permitter.validate(0, 4 ether, bidder, auction, hookData);

    // Second bid tries to use 2 more ether, exceeding the 5 ether cap
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsPersonalCap.selector, 2 ether, 5 ether, 4 ether)
    );
    vm.prank(auction);
    permitter.validate(0, 2 ether, bidder, auction, hookData);
  }

  function test_validate_revertsOnExceedsGlobalCap() public {
    // Create permitter with small global cap
    PermitterV2 smallCapPermitter =
      new PermitterV2(trustedSigner, 5 ether, MAX_TOKENS_PER_BIDDER, owner);

    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 10 ether, expiry);

    // Need to sign for the new permitter's domain
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    bytes32 digest =
      keccak256(abi.encodePacked("\x19\x01", smallCapPermitter.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedSignerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    bytes memory hookData = _encodeHookData(permit, signature);

    // First bid uses up 4 ether of the 5 ether global cap
    vm.prank(auction);
    smallCapPermitter.validate(0, 4 ether, bidder, auction, hookData);

    // Second bid tries to use 2 more ether, exceeding the 5 ether global cap
    vm.expectRevert(
      abi.encodeWithSelector(IPermitter.ExceedsTotalCap.selector, 2 ether, 5 ether, 4 ether)
    );
    vm.prank(auction);
    smallCapPermitter.validate(0, 2 ether, bidder, auction, hookData);
  }

  function test_validate_respectsGlobalPerBidderCap() public {
    uint256 expiry = block.timestamp + 1 hours;
    // Permit allows 20 ether but global per-bidder cap is 10 ether
    IPermitter.Permit memory permit = _createPermit(bidder, 20 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    // First bid uses 8 ether
    vm.prank(auction);
    permitter.validate(0, 8 ether, bidder, auction, hookData);

    // Second bid tries 5 more ether, which would exceed 10 ether per-bidder cap
    vm.expectRevert(
      abi.encodeWithSelector(
        IPermitter.ExceedsPersonalCap.selector, 5 ether, MAX_TOKENS_PER_BIDDER, 8 ether
      )
    );
    vm.prank(auction);
    permitter.validate(0, 5 ether, bidder, auction, hookData);
  }

  // ========== ADMIN FUNCTION TESTS ==========

  function test_updateMaxTotalEth() public {
    uint256 newCap = 200 ether;

    vm.expectEmit(true, false, false, true);
    emit CapUpdated(IPermitter.CapType.TOTAL_ETH, MAX_TOTAL_ETH, newCap);

    vm.prank(owner);
    permitter.updateMaxTotalEth(newCap);

    assertEq(permitter.maxTotalEth(), newCap);
  }

  function test_updateMaxTotalEth_revertsForNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateMaxTotalEth(200 ether);
  }

  function test_updateMaxTokensPerBidder() public {
    uint256 newCap = 20 ether;

    vm.expectEmit(true, false, false, true);
    emit CapUpdated(IPermitter.CapType.TOKENS_PER_BIDDER, MAX_TOKENS_PER_BIDDER, newCap);

    vm.prank(owner);
    permitter.updateMaxTokensPerBidder(newCap);

    assertEq(permitter.maxTokensPerBidder(), newCap);
  }

  function test_updateMaxTokensPerBidder_revertsForNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateMaxTokensPerBidder(20 ether);
  }

  function test_updateTrustedSigner() public {
    address newSigner = makeAddr("newSigner");

    vm.expectEmit(true, true, false, false);
    emit SignerUpdated(trustedSigner, newSigner);

    vm.prank(owner);
    permitter.updateTrustedSigner(newSigner);

    assertEq(permitter.trustedSigner(), newSigner);
  }

  function test_updateTrustedSigner_revertsForZeroAddress() public {
    vm.expectRevert(IPermitter.ZeroAddress.selector);
    vm.prank(owner);
    permitter.updateTrustedSigner(address(0));
  }

  function test_updateTrustedSigner_revertsForNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.updateTrustedSigner(makeAddr("newSigner"));
  }

  function test_updateTrustedSigner_invalidatesOldSignatures() public {
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    // Update signer
    (address newSigner, uint256 newSignerPk) = makeAddrAndKey("newSigner");
    vm.prank(owner);
    permitter.updateTrustedSigner(newSigner);

    // Old signature should no longer work
    vm.expectRevert(); // InvalidSignature
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);

    // New signature should work
    bytes memory newSignature = _signPermitWithSigner(permit, newSignerPk);
    bytes memory newHookData = _encodeHookData(permit, newSignature);

    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, newHookData);
  }

  function _signPermitWithSigner(IPermitter.Permit memory permit, uint256 signerPk)
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

  function test_pause() public {
    vm.expectEmit(true, false, false, false);
    emit Paused(owner);

    vm.prank(owner);
    permitter.pause();

    assertTrue(permitter.paused());
  }

  function test_pause_revertsForNonOwner() public {
    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.pause();
  }

  function test_unpause() public {
    vm.prank(owner);
    permitter.pause();

    vm.expectEmit(true, false, false, false);
    emit Unpaused(owner);

    vm.prank(owner);
    permitter.unpause();

    assertFalse(permitter.paused());
  }

  function test_unpause_revertsForNonOwner() public {
    vm.prank(owner);
    permitter.pause();

    vm.expectRevert(IPermitter.Unauthorized.selector);
    vm.prank(bidder);
    permitter.unpause();
  }

  // ========== VIEW FUNCTION TESTS ==========

  function test_getBidAmount() public {
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = _encodeHookData(permit, signature);

    assertEq(permitter.getBidAmount(bidder), 0);

    vm.prank(auction);
    permitter.validate(0, 2 ether, bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), 2 ether);
  }

  function test_getTotalEthRaised() public {
    assertEq(permitter.getTotalEthRaised(), 0);

    uint256 expiry = block.timestamp + 1 hours;

    // Bidder 1
    IPermitter.Permit memory permit1 = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature1 = _signPermit(permit1, trustedSignerPk);
    bytes memory hookData1 = _encodeHookData(permit1, signature1);

    vm.prank(auction);
    permitter.validate(0, 2 ether, bidder, auction, hookData1);

    // Bidder 2
    IPermitter.Permit memory permit2 = _createPermit(anotherBidder, 5 ether, expiry);
    bytes memory signature2 = _signPermit(permit2, trustedSignerPk);
    bytes memory hookData2 = _encodeHookData(permit2, signature2);

    vm.prank(auction);
    permitter.validate(0, 3 ether, anotherBidder, auction, hookData2);

    assertEq(permitter.getTotalEthRaised(), 5 ether);
  }

  function test_DOMAIN_SEPARATOR() public view {
    bytes32 domainSeparator = permitter.DOMAIN_SEPARATOR();
    assertTrue(domainSeparator != bytes32(0));
  }
}

/// @title PermitterV2EdgeCasesTest
/// @notice Edge case tests for PermitterV2
contract PermitterV2EdgeCasesTest is Test {
  PermitterV2 public permitter;

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

    // Deploy with zero caps (unlimited)
    permitter = new PermitterV2(trustedSigner, 0, 0, owner);
  }

  function _createPermit(address _bidder, uint256 maxBidAmount, uint256 expiry)
    internal
    pure
    returns (IPermitter.Permit memory)
  {
    return IPermitter.Permit({bidder: _bidder, maxBidAmount: maxBidAmount, expiry: expiry});
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

  function test_zeroCaps_noGlobalLimits() public {
    // With zero caps, only permit cap should apply
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 1000 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    // Should succeed with large bid since global caps are 0 (unlimited)
    vm.prank(auction);
    permitter.validate(0, 500 ether, bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), 500 ether);
  }

  function test_exactCapMatch() public {
    // Deploy with specific caps
    PermitterV2 cappedPermitter = new PermitterV2(trustedSigner, 10 ether, 5 ether, owner);

    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);

    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    bytes32 digest =
      keccak256(abi.encodePacked("\x19\x01", cappedPermitter.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(trustedSignerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);
    bytes memory hookData = abi.encode(permit, signature);

    // Bid exactly at cap should succeed
    vm.prank(auction);
    cappedPermitter.validate(0, 5 ether, bidder, auction, hookData);

    assertEq(cappedPermitter.getBidAmount(bidder), 5 ether);
  }

  function test_expiryAtExactTimestamp() public {
    uint256 expiry = block.timestamp; // Expires exactly now

    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    // Should succeed since block.timestamp == expiry (not > expiry)
    vm.prank(auction);
    permitter.validate(0, 1 ether, bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), 1 ether);
  }

  function test_zeroBidAmount() public {
    uint256 expiry = block.timestamp + 1 hours;
    IPermitter.Permit memory permit = _createPermit(bidder, 5 ether, expiry);
    bytes memory signature = _signPermit(permit, trustedSignerPk);
    bytes memory hookData = abi.encode(permit, signature);

    // Zero bid should succeed (though it's a bit pointless)
    vm.prank(auction);
    permitter.validate(0, 0, bidder, auction, hookData);

    assertEq(permitter.getBidAmount(bidder), 0);
  }
}
