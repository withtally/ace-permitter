# KYC and Permissions Registry Technical Specification

## Overview

The Permissions Registry is a smart contract system that enforces eligibility rules for token sales conducted via Uniswap's Continuous Clearing Auction (CCA). It validates that bidders have completed KYC, are not sanctioned, and are within their allocation limits.

### Core Design Principles

- **Simple** - Prefer out-of-the-box components and patterns where possible
- **Flexible** - Easy to change policies for future sales with different business logic
- **Modular** - Stateless policies with state managed in the hook contract
- **Immutable** - No upgrade mechanisms; deploy new hooks for fixes

---

## Architecture

### Contract Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CCA Auction                              │
│                    (Uniswap Contract)                            │
└─────────────────────┬───────────────────────────────────────────┘
                      │ calls validate()
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PermissionsHook                             │
│  - Implements IValidationHook                                    │
│  - Extends PolicyProtected                                       │
│  - Deploys PolicyEngine in constructor                           │
│  - Manages state: committed amounts per CCID, global total       │
│  - Single authorized CCA (set once, immutable)                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │ runPolicyWithContext()
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PolicyEngine                                │
│  (Chainlink ACE - deployed per hook)                             │
│  - Whitelisted policies only                                     │
│  - Attached post-deployment by admin                             │
└─────────────────────┬───────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌───────────┐  ┌─────────────┐  ┌─────────────┐
│ Sanctions │  │ Individual  │  │  Global     │
│  Policy   │  │ Limit       │  │  Cap        │
│ (shared)  │  │ Policy      │  │  Policy     │
│           │  │ (shared)    │  │  (shared)   │
└───────────┘  └─────────────┘  └─────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│              Chainlink CCID Registry                             │
│  (Sumsub integration - resolves address → CCID)                  │
└─────────────────────────────────────────────────────────────────┘
```

### Deployment Flow

1. **Tally deploys canonical policies** (one-time setup):
   - SanctionsPolicy (Chainlink's pre-built)
   - IndividualLimitPolicy (custom, stateless)
   - GlobalCapPolicy (custom, stateless)

2. **Per-sale deployment** (Tally deploys on behalf of issuer):
   - Deploy `PermissionsHook` with constructor parameters:
     - `policyEngineImpl`: Address of PolicyEngine implementation (or deploy internally)
     - `individualLimit`: uint256 - max tokens per CCID
     - `globalCap`: uint256 - max tokens for entire sale
     - `admin`: address - single admin EOA with full control
   - Hook constructor deploys its own PolicyEngine instance
   - Admin attaches policies via `attachPolicy()` calls
   - Admin authorizes CCA via `authorizeCCA()` (single call, immutable thereafter)

3. **CCA references the hook** at auction creation

---

## Contract Specifications

### PermissionsHook

The main entry point implementing Uniswap's validation interface.

#### Inheritance

```solidity
contract PermissionsHook is IValidationHook, PolicyProtected
```

#### State Variables

```solidity
/// @notice The PolicyEngine instance for this hook (deployed in constructor)
PolicyEngine public immutable policyEngine;

/// @notice Maximum tokens a single CCID can commit across all bids
uint256 public immutable individualLimit;

/// @notice Maximum tokens that can be committed globally for this sale
uint256 public immutable globalCap;

/// @notice Admin address with policy attachment and CCA authorization rights
address public immutable admin;

/// @notice The single authorized CCA contract (set once, immutable)
address public authorizedCCA;

/// @notice Total tokens committed across all bidders
uint256 public globalCommitted;

/// @notice Tokens committed per CCID
mapping(bytes32 => uint256) public committedByCCID;

/// @notice Address of the Chainlink CCID registry
address public immutable ccidRegistry;
```

#### Constructor

```solidity
/// @notice Deploys a new PermissionsHook with its own PolicyEngine
/// @param _individualLimit Maximum tokens per CCID
/// @param _globalCap Maximum tokens for the entire sale
/// @param _admin Admin address for policy attachment and CCA authorization
/// @param _ccidRegistry Address of the Chainlink CCID registry
constructor(
    uint256 _individualLimit,
    uint256 _globalCap,
    address _admin,
    address _ccidRegistry
)
```

#### External Functions

```solidity
/// @notice Validates a bid and commits the amount if valid
/// @dev Called by the CCA. Reverts if validation fails.
/// @dev MUST revert if the bid is invalid (per IValidationHook spec)
/// @param maxPrice The maximum price the bidder is willing to pay (unused)
/// @param amount The bid amount in sale tokens
/// @param owner The beneficial owner of the bid (used for CCID lookup)
/// @param sender The transaction sender (unused)
/// @param hookData Additional validation data (ignored in current implementation)
function validate(
    uint256 maxPrice,
    uint128 amount,
    address owner,
    address sender,
    bytes calldata hookData
) external;

/// @notice Authorizes a CCA contract to call validate()
/// @dev Can only be called once. Subsequent calls revert.
/// @param cca The CCA contract address to authorize
function authorizeCCA(address cca) external;

/// @notice Attaches a policy to the PolicyEngine
/// @dev Only callable by admin
/// @param policy The policy contract address
/// @param selector The function selector to protect
function attachPolicy(address policy, bytes4 selector) external;

/// @notice Checks if an address is eligible to bid (basic checks)
/// @dev Fast check: CCID exists and under limits. Does not run full policy evaluation.
/// @param bidder The address to check
/// @return eligible True if basic eligibility checks pass
function checkEligibility(address bidder) external view returns (bool eligible);

/// @notice Performs full eligibility check including PolicyEngine evaluation
/// @dev More gas intensive than checkEligibility
/// @param bidder The address to check
/// @param amount The proposed bid amount
/// @return eligible True if full validation would pass
function fullCheck(address bidder, uint256 amount) external view returns (bool eligible);
```

#### Error Definitions

```solidity
/// @notice Thrown when validate() is called before a CCA has been authorized
error CCANotConfigured();

/// @notice Thrown when caller is not the authorized CCA
error UnauthorizedCCA();

/// @notice Thrown when caller is not the admin
error UnauthorizedAdmin();

/// @notice Thrown when attempting to authorize a CCA after one is already set
error CCAAlreadyAuthorized();

/// @notice Thrown when bidder has no CCID registered
error NoCCIDFound(address bidder);

/// @notice Thrown when bidder's CCID fails sanctions check
error SanctionsFailed(bytes32 ccid);

/// @notice Thrown when bid would exceed individual CCID limit
/// @param ccid The CCID that would exceed its limit
/// @param requested The requested bid amount
/// @param remaining The remaining allocation for this CCID
error IndividualLimitExceeded(bytes32 ccid, uint256 requested, uint256 remaining);

/// @notice Thrown when bid would exceed global sale cap
/// @param requested The requested bid amount
/// @param remaining The remaining global allocation
error GlobalCapExceeded(uint256 requested, uint256 remaining);

/// @notice Thrown when CCID registry lookup fails
error CCIDLookupFailed(address bidder);
```

#### Validation Logic

The `validate()` function performs the following steps atomically:

1. **Verify CCA is authorized** - revert with `CCANotConfigured()` if `authorizedCCA == address(0)`
2. **Verify caller is the authorized CCA** - revert with `UnauthorizedCCA()` if `msg.sender != authorizedCCA`
3. **Resolve owner address to CCID** via Chainlink CCID registry (fresh lookup every call)
4. **Fail-closed on lookup failure** - revert if CCID registry is unavailable
5. **Run PolicyEngine checks** via `runPolicyWithContext`:
   - SanctionsPolicy: Verify CCID is not sanctioned
   - IndividualLimitPolicy: Verify `committedByCCID[ccid] + amount <= individualLimit`
   - GlobalCapPolicy: Verify `globalCommitted + amount <= globalCap`
6. **Update state** (only if all checks pass):
   - `committedByCCID[ccid] += amount`
   - `globalCommitted += amount`
7. **Revert with detailed error** if any check fails

**Important**: State updates rely on transaction atomicity. If the CCA transaction reverts after `validate()` succeeds, the hook's state changes are also rolled back.

---

### IndividualLimitPolicy

Stateless policy that checks CCID allocation limits.

```solidity
/// @notice Policy that enforces per-CCID purchase limits
/// @dev Stateless - receives state via context from PermissionsHook
contract IndividualLimitPolicy is IPolicy {

    /// @notice Evaluates whether a bid is within the CCID's individual limit
    /// @param context Encoded (bytes32 ccid, uint256 amount, uint256 committed, uint256 limit)
    /// @return True if bid is within limits
    function evaluate(bytes calldata context) external pure returns (bool);
}
```

#### Context Encoding

```solidity
struct IndividualLimitContext {
    bytes32 ccid;           // The bidder's CCID
    uint256 amount;         // The bid amount
    uint256 committed;      // Currently committed amount for this CCID
    uint256 limit;          // The individual limit for this sale
}
```

---

### GlobalCapPolicy

Stateless policy that checks global sale cap.

```solidity
/// @notice Policy that enforces global sale cap
/// @dev Stateless - receives state via context from PermissionsHook
contract GlobalCapPolicy is IPolicy {

    /// @notice Evaluates whether a bid is within the global cap
    /// @param context Encoded (uint256 amount, uint256 globalCommitted, uint256 globalCap)
    /// @return True if bid is within global cap
    function evaluate(bytes calldata context) external pure returns (bool);
}
```

#### Context Encoding

```solidity
struct GlobalCapContext {
    uint256 amount;          // The bid amount
    uint256 globalCommitted; // Currently committed global amount
    uint256 globalCap;       // The global cap for this sale
}
```

---

### SanctionsPolicy

Uses Chainlink's pre-built SanctionsPolicy that integrates with the CCID registry and Sumsub's sanctions attestations.

---

## Business Logic Summary

| Rule | Implementation | Behavior |
|------|---------------|----------|
| Sanctions check | SanctionsPolicy via Chainlink ACE | Accept any non-revoked CCID (trust initial KYC) |
| Individual limit | IndividualLimitPolicy | Per-sale, tracks committed bids, no restoration on cancellation |
| Global cap | GlobalCapPolicy | Per-sale parameter, rejects bids that would exceed cap entirely |
| Multi-wallet CCID | Track by CCID directly | All wallets under same CCID share one limit pool |
| CCID lookup | Fresh every bid | Fail-closed if registry unavailable |
| Policy failures | Atomic revert | Full transaction reverts with detailed error |

---

## Access Control

| Action | Who | Constraints |
|--------|-----|-------------|
| Deploy hook | Tally (protocol) | On behalf of issuer |
| Attach policies | Admin (single EOA) | Post-deployment, whitelisted policies only |
| Authorize CCA | Admin | Single call only, immutable thereafter |
| Update limits | N/A | Immutable at deployment |
| Pause/unpause | N/A | No pause mechanism |
| Upgrade | N/A | Immutable contracts, deploy new for fixes |

---

## Error Handling

### Error Detail Level

Full error details are exposed on-chain to help with UX:
- Specific error type (no CCID, sanctions, individual limit, global cap)
- Remaining allocation amounts where applicable
- CCID identifier for debugging

### Oracle Failures

- **CCID registry unavailable**: Fail-closed (reject all bids)
- **Stale data**: Not checked - trust initial KYC attestation

---

## View Functions for Frontend Integration

### checkEligibility(address bidder)

Fast, low-gas check for basic eligibility:
- Verifies CCID exists for bidder
- Verifies CCID is under individual limit
- Verifies global cap not reached
- Does NOT run full PolicyEngine evaluation

### fullCheck(address bidder, uint256 amount)

Complete validation simulation:
- Runs full PolicyEngine evaluation
- Includes sanctions check
- Returns whether a bid of `amount` would succeed
- Higher gas cost

---

## Events

Minimal event emission - rely on transaction traces for debugging:

```solidity
/// @notice Emitted when a CCA is authorized
event CCAAuthorized(address indexed cca);

/// @notice Emitted when a policy is attached
event PolicyAttached(address indexed policy, bytes4 indexed selector);
```

---

## Gas Considerations

- **Simple nested mapping** for tracking: `mapping(bytes32 => uint256)`
- **Fresh CCID lookup every bid**: Higher gas but ensures correctness
- **Minimal events**: Reduces gas, use traces for debugging
- **Optimization deferred**: Start simple, optimize if gas becomes prohibitive

---

## Security Considerations

### Trust Model

- **Single admin EOA**: Full control over policy attachment and CCA authorization
- **No timelock**: Policy changes are immediate
- **No escape hatches**: Minimal attack surface, no emergency withdrawal or circuit breakers
- **Immutable contracts**: No proxy pattern, deploy new hooks for fixes

### Invariants

1. `globalCommitted <= globalCap` (enforced by revert on exceed)
2. `committedByCCID[ccid] <= individualLimit` for all CCIDs
3. Once `authorizedCCA` is set, it cannot be changed
4. Limits are permanent once committed (no restoration on bid cancellation)

### Attack Vectors Mitigated

- **Front-running**: First-come-first-served based on transaction ordering (accepted tradeoff)
- **CCID transfer gaming**: Limits follow CCID, allowing legitimate wallet migration
- **Oracle manipulation**: Trust Chainlink/Sumsub attestation, fail-closed on unavailability

---

## Integration Points

### Uniswap CCA

Implements `IValidationHook` interface:

```solidity
interface IValidationHook {
    function validate(
        uint256 maxPrice,
        uint128 amount,
        address owner,
        address sender,
        bytes calldata hookData
    ) external;
}
```

### Chainlink ACE

- Extends `PolicyProtected` for policy execution
- Deploys `PolicyEngine` per hook instance
- Uses `runPolicyWithContext` modifier for stateless policy evaluation

### Chainlink CCID Registry

- Fresh lookup: `address → bytes32 CCID`
- Interface TBD based on final Chainlink ACE CCID specification

---

## Deployment Checklist

1. [ ] Deploy canonical policies (SanctionsPolicy, IndividualLimitPolicy, GlobalCapPolicy)
2. [ ] For each sale:
   - [ ] Deploy PermissionsHook with sale-specific parameters
   - [ ] Attach SanctionsPolicy
   - [ ] Attach IndividualLimitPolicy
   - [ ] Attach GlobalCapPolicy
   - [ ] Authorize CCA contract
3. [ ] Configure CCA to use the hook address
4. [ ] Verify via checkEligibility/fullCheck before sale starts

---

## Future Considerations (Out of Scope for MVP)

- Multi-platform support (Balancer LBP integration)
- Pending bids with KYC deadline
- Bid restoration on cancellation
- USD-denominated limits with price oracle
- Upgradeable proxy pattern
- On-chain hook registry for discoverability
- Time-bound validation windows
