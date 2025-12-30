// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Permitter} from "src/Permitter.sol";

contract MainnetForkTest is Test {
  uint256 private constant SIGNER_KEY = 0xA11CE;

  function testFork_PermitterValidationOnMainnet() public {
    string memory rpcUrl = vm.envOr("MAINNET_RPC_URL", string(""));
    if (bytes(rpcUrl).length == 0) {
      vm.skip(true);
    }

    uint256 forkBlock = vm.envOr("MAINNET_FORK_BLOCK", uint256(18_000_000));
    vm.createSelectFork(rpcUrl, forkBlock);

    address signer = vm.addr(SIGNER_KEY);
    address owner = makeAddr("owner");
    address bidder = makeAddr("bidder");

    Permitter permitter = new Permitter(signer, 100 ether, 1_000 ether, owner);

    Permitter.Permit memory permit = Permitter.Permit({
      bidder: bidder,
      maxBidAmount: 500 ether,
      expiry: block.timestamp + 1 days
    });
    bytes memory signature = _signPermit(SIGNER_KEY, permitter, permit);
    bytes memory permitData = abi.encode(permit, signature);

    bool valid = permitter.validateBid{value: 1 ether}(bidder, 100 ether, permitData);
    assertTrue(valid);
  }

  function testFork_RealCCAAddressHasCode() public {
    string memory rpcUrl = vm.envOr("MAINNET_RPC_URL", string(""));
    address ccaAddress = vm.envOr("MAINNET_CCA_ADDRESS", address(0));
    if (bytes(rpcUrl).length == 0 || ccaAddress == address(0)) {
      vm.skip(true);
    }

    uint256 forkBlock = vm.envOr("MAINNET_FORK_BLOCK", uint256(18_000_000));
    vm.createSelectFork(rpcUrl, forkBlock);

    assertGt(ccaAddress.code.length, 0);
  }

  function _signPermit(uint256 signerKey, Permitter permitter, Permitter.Permit memory permit)
    internal
    returns (bytes memory)
  {
    bytes32 digest = _hashPermit(permitter, permit);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
    return abi.encodePacked(r, s, v);
  }

  function _hashPermit(Permitter permitter, Permitter.Permit memory permit)
    internal
    view
    returns (bytes32)
  {
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
