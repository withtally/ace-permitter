// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IPermitter, Permitter} from "src/Permitter.sol";

contract MockCCA {
  IPermitter public immutable hook;
  uint256 public totalBidAmount;
  mapping(address => uint256) public bids;

  constructor(IPermitter hook_) {
    hook = hook_;
  }

  function placeBid(uint256 bidAmount, bytes calldata permitData) external payable {
    bool ok = hook.validateBid{value: msg.value}(msg.sender, bidAmount, permitData);
    require(ok, "VALIDATION_FAILED");

    bids[msg.sender] += bidAmount;
    totalBidAmount += bidAmount;
  }
}

contract CCAPlusPermitterTest is Test {
  uint256 private constant SIGNER_KEY = 0xA11CE;

  address private SIGNER;
  address private OWNER;
  address private BIDDER;

  Permitter private permitter;
  MockCCA private cca;

  function setUp() public {
    SIGNER = vm.addr(SIGNER_KEY);
    OWNER = makeAddr("owner");
    BIDDER = makeAddr("bidder");

    permitter = new Permitter(SIGNER, 100 ether, 1_000 ether, OWNER);
    cca = new MockCCA(permitter);

    vm.deal(BIDDER, 100 ether);
  }

  function test_FullBidFlow() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 500 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.prank(BIDDER);
    cca.placeBid{value: 10 ether}(100 ether, permitData);

    assertEq(cca.bids(BIDDER), 100 ether);
    assertEq(cca.totalBidAmount(), 100 ether);
    assertEq(permitter.getBidAmount(BIDDER), 100 ether);
    assertEq(permitter.getTotalEthRaised(), 10 ether);
  }

  function test_MultipleBidsFromSameUser() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 300 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.startPrank(BIDDER);
    cca.placeBid{value: 5 ether}(100 ether, permitData);
    cca.placeBid{value: 7 ether}(150 ether, permitData);
    vm.stopPrank();

    assertEq(cca.bids(BIDDER), 250 ether);
    assertEq(cca.totalBidAmount(), 250 ether);
    assertEq(permitter.getBidAmount(BIDDER), 250 ether);
    assertEq(permitter.getTotalEthRaised(), 12 ether);
  }

  function test_RevertIf_BidRejectedDoesNotAffectCCA() public {
    Permitter.Permit memory permit = Permitter.Permit({
      bidder: BIDDER,
      maxBidAmount: 50 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permit);
    bytes memory permitData = abi.encode(permit, signature);

    vm.prank(BIDDER);
    vm.expectRevert(
      abi.encodeWithSelector(Permitter.ExceedsPersonalCap.selector, 60 ether, 50 ether, 0)
    );
    cca.placeBid{value: 1 ether}(60 ether, permitData);

    assertEq(cca.bids(BIDDER), 0);
    assertEq(cca.totalBidAmount(), 0);
    assertEq(permitter.getBidAmount(BIDDER), 0);
    assertEq(permitter.getTotalEthRaised(), 0);
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
