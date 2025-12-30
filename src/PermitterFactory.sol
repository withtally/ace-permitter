// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Permitter} from "src/Permitter.sol";

interface IPermitterFactory {
  function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner
  ) external returns (address permitter);

  function createPermitterWithSalt(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    bytes32 salt
  ) external returns (address permitter);

  function predictPermitterAddress(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    bytes32 salt
  ) external view returns (address);

  event PermitterCreated(
    address indexed permitter,
    address indexed owner,
    address indexed trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder
  );
}

contract PermitterFactory is IPermitterFactory {
  function createPermitter(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner
  ) external returns (address permitter) {
    bytes32 salt = _salt(trustedSigner, maxTotalEth, maxTokensPerBidder, owner);
    permitter =
      address(new Permitter{salt: salt}(trustedSigner, maxTotalEth, maxTokensPerBidder, owner));

    emit PermitterCreated(permitter, owner, trustedSigner, maxTotalEth, maxTokensPerBidder);
  }

  function createPermitterWithSalt(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    bytes32 salt
  ) external returns (address permitter) {
    permitter =
      address(new Permitter{salt: salt}(trustedSigner, maxTotalEth, maxTokensPerBidder, owner));

    emit PermitterCreated(permitter, owner, trustedSigner, maxTotalEth, maxTokensPerBidder);
  }

  function predictPermitterAddress(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner,
    bytes32 salt
  ) external view returns (address) {
    bytes32 initCodeHash = keccak256(
      abi.encodePacked(
        type(Permitter).creationCode,
        abi.encode(trustedSigner, maxTotalEth, maxTokensPerBidder, owner)
      )
    );
    bytes32 rawAddress = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash));
    return address(uint160(uint256(rawAddress)));
  }

  function _salt(
    address trustedSigner,
    uint256 maxTotalEth,
    uint256 maxTokensPerBidder,
    address owner
  ) internal pure returns (bytes32) {
    return keccak256(abi.encode(trustedSigner, maxTotalEth, maxTokensPerBidder, owner));
  }
}
