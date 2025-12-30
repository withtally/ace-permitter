// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "src/Permitter.sol";

contract PermitterTest is Test {
  uint256 private constant SIGNER_KEY = 0xA11CE;
  uint256 private constant OTHER_SIGNER_KEY = 0xB0B;

  address private SIGNER;
  address private OTHER_SIGNER;
  address private OWNER;
  address private BIDDER;
  address private OTHER_BIDDER;

  Permitter private permitter;

  function setUp() public {
    SIGNER = vm.addr(SIGNER_KEY);
    OTHER_SIGNER = vm.addr(OTHER_SIGNER_KEY);
    OWNER = makeAddr("owner");
    BIDDER = makeAddr("bidder");
    OTHER_BIDDER = makeAddr("otherBidder");

    permitter = new Permitter(SIGNER, 100 ether, 1_000 ether, OWNER);
    vm.deal(address(this), 1_000 ether);
  }

  function test_ValidateBid_SucceedsWithValidPermit() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 500 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    bool valid = permitter.validateBid{value: 10 ether}(BIDDER, 100 ether, permitData);

    assertTrue(valid);
    assertEq(permitter.getBidAmount(BIDDER), 100 ether);
    assertEq(permitter.getTotalEthRaised(), 10 ether);
  }

  function test_RevertIf_SignatureExpired() public {
    uint256 expiry = block.timestamp - 1;
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 100 ether,
      expiry: expiry
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(Permitter.SignatureExpired.selector, expiry, block.timestamp)
    );
    permitter.validateBid{value: 1 ether}(BIDDER, 10 ether, permitData);
  }

  function test_RevertIf_InvalidSignature() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 100 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(OTHER_SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(Permitter.InvalidSignature.selector, SIGNER, OTHER_SIGNER)
    );
    permitter.validateBid{value: 1 ether}(BIDDER, 10 ether, permitData);
  }

  function test_RevertIf_BidderMismatch() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: OTHER_BIDDER,
      maxBidAmount: 100 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(Permitter.InvalidSignature.selector, BIDDER, OTHER_BIDDER)
    );
    permitter.validateBid{value: 1 ether}(BIDDER, 10 ether, permitData);
  }

  function test_RevertIf_PersonalCapExceeded() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 50 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(
        Permitter.ExceedsPersonalCap.selector,
        60 ether,
        50 ether,
        0
      )
    );
    permitter.validateBid{value: 1 ether}(BIDDER, 60 ether, permitData);
  }

  function test_RevertIf_MaxTokensPerBidderExceeded() public {
    vm.prank(OWNER);
    permitter.updateMaxTokensPerBidder(40 ether);

    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 100 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(
        Permitter.ExceedsPersonalCap.selector,
        50 ether,
        40 ether,
        0
      )
    );
    permitter.validateBid{value: 1 ether}(BIDDER, 50 ether, permitData);
  }

  function test_RevertIf_TotalCapExceeded() public {
    vm.prank(OWNER);
    permitter.updateMaxTotalEth(1 ether);

    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 100 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(
      abi.encodeWithSelector(Permitter.ExceedsTotalCap.selector, 2 ether, 1 ether, 0)
    );
    permitter.validateBid{value: 2 ether}(BIDDER, 10 ether, permitData);
  }

  function test_RevertIf_Paused() public {
    vm.prank(OWNER);
    permitter.pause();

    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 100 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.expectRevert(Permitter.ContractPaused.selector);
    permitter.validateBid{value: 1 ether}(BIDDER, 10 ether, permitData);
  }

  function test_UpdateCapsAndSigner() public {
    vm.startPrank(OWNER);
    permitter.updateMaxTotalEth(200 ether);
    permitter.updateMaxTokensPerBidder(2_000 ether);
    permitter.updateTrustedSigner(OTHER_SIGNER);
    vm.stopPrank();

    assertEq(permitter.maxTotalEth(), 200 ether);
    assertEq(permitter.maxTokensPerBidder(), 2_000 ether);
    assertEq(permitter.trustedSigner(), OTHER_SIGNER);

    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 100 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(OTHER_SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    bool valid = permitter.validateBid{value: 1 ether}(BIDDER, 10 ether, permitData);
    assertTrue(valid);
  }

  function test_RevertIf_Unauthorized() public {
    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.updateMaxTotalEth(200 ether);

    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.updateMaxTokensPerBidder(2_000 ether);

    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.updateTrustedSigner(OTHER_SIGNER);

    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.pause();

    vm.expectRevert(Permitter.Unauthorized.selector);
    permitter.unpause();
  }

  function _signPermit(uint256 signerKey, Permitter.Permit memory permit)
    internal
    returns (bytes memory)
  {
    bytes32 digest = _hashPermit(permit);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
    return abi.encodePacked(r, s, v);
  }

  function _hashPermit(Permitter.Permit memory permit) internal view returns (bytes32) {
    bytes32 domainTypehash = keccak256(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 permitTypehash =
      keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");
    bytes32 domainSeparator = keccak256(
      abi.encode(
        domainTypehash,
        keccak256(bytes("Permitter")),
        keccak256(bytes("1")),
        block.chainid,
        address(permitter)
      )
    );
    bytes32 structHash =
      keccak256(abi.encode(permitTypehash, permit.bidder, permit.maxBidAmount, permit.expiry));
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
  }
}
