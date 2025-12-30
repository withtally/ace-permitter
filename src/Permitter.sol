// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

interface IPermitter {
  function validateBid(
    address bidder,
    uint256 bidAmount,
    bytes calldata permitData
  ) external payable returns (bool valid);

  function updateMaxTotalEth(uint256 newMaxTotalEth) external;

  function updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external;

  function updateTrustedSigner(address newSigner) external;

  function pause() external;

  function unpause() external;

  function getBidAmount(address bidder) external view returns (uint256 cumulativeBid);

  function getTotalEthRaised() external view returns (uint256 totalEthRaised);
}

library ECDSA {
  error InvalidSignatureLength(uint256 length);
  error InvalidSignatureVValue(uint8 v);

  function _recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
    if (signature.length != 65) {
      revert InvalidSignatureLength(signature.length);
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
      revert InvalidSignatureVValue(v);
    }

    return ecrecover(digest, v, r, s);
  }
}

contract Permitter is IPermitter {
  struct Permit {
    address bidder;
    uint256 maxBidAmount;
    uint256 expiry;
  }

  enum CapType {
    TOTAL_ETH,
    TOKENS_PER_BIDDER
  }

  error ContractPaused();
  error SignatureExpired(uint256 expiry, uint256 currentTime);
  error InvalidSignature(address expected, address recovered);
  error ExceedsPersonalCap(uint256 requested, uint256 cap, uint256 alreadyBid);
  error ExceedsTotalCap(uint256 requested, uint256 cap, uint256 alreadyRaised);
  error BidTooEarly(uint256 currentTime, uint256 validFrom);
  error Unauthorized();

  event PermitVerified(
    address indexed bidder,
    uint256 bidAmount,
    uint256 remainingPersonalCap,
    uint256 remainingTotalCap
  );

  event CapUpdated(CapType indexed capType, uint256 oldCap, uint256 newCap);

  event SignerUpdated(address indexed oldSigner, address indexed newSigner);

  event Paused(address indexed by);
  event Unpaused(address indexed by);

  bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
  );
  bytes32 private constant PERMIT_TYPEHASH =
    keccak256("Permit(address bidder,uint256 maxBidAmount,uint256 expiry)");
  bytes32 private constant NAME_HASH = keccak256(bytes("Permitter"));
  bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

  address public trustedSigner;
  uint256 public maxTotalEth;
  uint256 public maxTokensPerBidder;
  mapping(address => uint256) public cumulativeBids;
  uint256 public totalEthRaised;
  address public owner;
  bool public paused;

  modifier onlyOwner() {
    if (msg.sender != owner) {
      revert Unauthorized();
    }
    _;
  }

  constructor(
    address trustedSigner_,
    uint256 maxTotalEth_,
    uint256 maxTokensPerBidder_,
    address owner_
  ) {
    trustedSigner = trustedSigner_;
    maxTotalEth = maxTotalEth_;
    maxTokensPerBidder = maxTokensPerBidder_;
    owner = owner_;
  }

  function validateBid(
    address bidder,
    uint256 bidAmount,
    bytes calldata permitData
  ) external payable returns (bool valid) {
    if (paused) {
      revert ContractPaused();
    }

    (Permit memory permit, bytes memory signature) = abi.decode(permitData, (Permit, bytes));

    if (block.timestamp > permit.expiry) {
      revert SignatureExpired(permit.expiry, block.timestamp);
    }

    address recovered = _recoverSigner(permit, signature);
    if (recovered != trustedSigner) {
      revert InvalidSignature(trustedSigner, recovered);
    }

    if (permit.bidder != bidder) {
      revert InvalidSignature(bidder, permit.bidder);
    }

    uint256 previousCumulative = cumulativeBids[bidder];
    uint256 newCumulative = previousCumulative + bidAmount;
    uint256 personalCap = permit.maxBidAmount;
    if (maxTokensPerBidder < personalCap) {
      personalCap = maxTokensPerBidder;
    }
    if (newCumulative > personalCap) {
      revert ExceedsPersonalCap(bidAmount, personalCap, previousCumulative);
    }

    uint256 newTotalEth = totalEthRaised + msg.value;
    if (newTotalEth > maxTotalEth) {
      revert ExceedsTotalCap(msg.value, maxTotalEth, totalEthRaised);
    }

    cumulativeBids[bidder] = newCumulative;
    totalEthRaised = newTotalEth;

    emit PermitVerified(
      bidder,
      bidAmount,
      personalCap - newCumulative,
      maxTotalEth - newTotalEth
    );

    return true;
  }

  function updateMaxTotalEth(uint256 newMaxTotalEth) external onlyOwner {
    uint256 oldCap = maxTotalEth;
    maxTotalEth = newMaxTotalEth;
    emit CapUpdated(CapType.TOTAL_ETH, oldCap, newMaxTotalEth);
  }

  function updateMaxTokensPerBidder(uint256 newMaxTokensPerBidder) external onlyOwner {
    uint256 oldCap = maxTokensPerBidder;
    maxTokensPerBidder = newMaxTokensPerBidder;
    emit CapUpdated(CapType.TOKENS_PER_BIDDER, oldCap, newMaxTokensPerBidder);
  }

  function updateTrustedSigner(address newSigner) external onlyOwner {
    address oldSigner = trustedSigner;
    trustedSigner = newSigner;
    emit SignerUpdated(oldSigner, newSigner);
  }

  function pause() external onlyOwner {
    paused = true;
    emit Paused(msg.sender);
  }

  function unpause() external onlyOwner {
    paused = false;
    emit Unpaused(msg.sender);
  }

  function getBidAmount(address bidder) external view returns (uint256 cumulativeBid) {
    return cumulativeBids[bidder];
  }

  function getTotalEthRaised() external view returns (uint256 totalEthRaised_) {
    return totalEthRaised;
  }

  function _domainSeparator() internal view returns (bytes32) {
    return keccak256(
      abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))
    );
  }

  function _hashPermit(Permit memory permit) internal view returns (bytes32) {
    bytes32 structHash =
      keccak256(abi.encode(PERMIT_TYPEHASH, permit.bidder, permit.maxBidAmount, permit.expiry));
    return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
  }

  function _recoverSigner(Permit memory permit, bytes memory signature)
    internal
    view
    returns (address)
  {
    return ECDSA._recover(_hashPermit(permit), signature);
  }
}
