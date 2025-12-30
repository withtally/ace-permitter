// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "src/Permitter.sol";

contract PermitterFuzzTest is Test {
  uint256 private constant SIGNER_KEY = 0xA11CE;
  uint256 private constant MAX_TOKENS = 1_000 ether;
  uint256 private constant MAX_TOTAL_ETH = 100 ether;

  address private SIGNER;
  address private OWNER;

  Permitter private permitter;

  function setUp() public {
    SIGNER = vm.addr(SIGNER_KEY);
    OWNER = makeAddr("owner");
    permitter = new Permitter(SIGNER, MAX_TOTAL_ETH, MAX_TOKENS, OWNER);
    vm.deal(address(this), 1_000_000 ether);
  }

  function testFuzz_RevertIf_InvalidSignature(
    address bidder,
    uint256 bidAmount,
    uint256 expiry,
    bytes memory randomSignature
  ) public {
    uint256 validExpiry = bound(expiry, block.timestamp + 1, block.timestamp + 7 days);
    uint256 safeBidAmount = bound(bidAmount, 1, MAX_TOKENS);

    Permitter.Permit memory permit = Permitter.Permit({
      bidder: bidder,
      maxBidAmount: MAX_TOKENS,
      expiry: validExpiry
    });

    if (randomSignature.length == 65) {
      bytes32 digest = _hashPermit(permit);
      address recovered = _recoverNoRevert(digest, randomSignature);
      vm.assume(recovered != SIGNER);
    }

    bytes memory permitData = abi.encode(permit, randomSignature);
    vm.expectRevert();
    permitter.validateBid{value: 1 ether}(bidder, safeBidAmount, permitData);
  }

  function testFuzz_CumulativeBidsNeverExceedCap(
    uint256[] memory bidAmounts,
    uint256[] memory ethAmounts
  ) public {
    uint256 length = bidAmounts.length;
    if (ethAmounts.length < length) {
      length = ethAmounts.length;
    }
    if (length == 0) {
      return;
    }
    if (length > 16) {
      length = 16;
    }

    address bidder = makeAddr("bidder");
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: bidder,
      maxBidAmount: MAX_TOKENS,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    uint256 remainingTokens = MAX_TOKENS;
    uint256 remainingEth = MAX_TOTAL_ETH;

    for (uint256 i = 0; i < length; i++) {
      uint256 bidAmount = bound(bidAmounts[i], 0, remainingTokens);
      uint256 ethAmount = bound(ethAmounts[i], 0, remainingEth);

      permitter.validateBid{value: ethAmount}(bidder, bidAmount, permitData);

      remainingTokens -= bidAmount;
      remainingEth -= ethAmount;
    }

    assertLe(permitter.getBidAmount(bidder), MAX_TOKENS);
    assertLe(permitter.getTotalEthRaised(), MAX_TOTAL_ETH);
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

  function _recoverNoRevert(bytes32 digest, bytes memory signature)
    internal
    pure
    returns (address)
  {
    if (signature.length != 65) {
      return address(0);
    }

    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
      r := mload(add(signature, 0x20))
      s := mload(add(signature, 0x40))
      v := byte(0, mload(add(signature, 0x60)))
    }

    if (v < 27) {
      v += 27;
    }
    if (v != 27 && v != 28) {
      return address(0);
    }

    return ecrecover(digest, v, r, s);
  }
}
