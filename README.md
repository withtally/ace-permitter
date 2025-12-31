# Permitter

> **Warning:** This code has not been audited. Use at your own risk.

A smart contract system that enforces eligibility rules for token sales conducted via Uniswap's Continuous Clearing Auction (CCA). It validates that bidders have completed KYC, are not sanctioned, and are within their allocation limits.

## Overview

Permitter is a validation hook for CCA auctions that integrates with:
- **Chainlink CCID Identity Registry** - Maps wallet addresses to verified identities (CCIDs)
- **Chainlink ACE Policy Engine** - Enforces sanctions policies
- **Merkle-based allowlists** - Optional per-sale participant whitelisting

### Design Principles

- **Simple** - Prefer out-of-the-box components and patterns
- **Flexible** - Easy to configure different policies per sale
- **Modular** - Stateless policies with state managed in the hook
- **Immutable** - No upgrade mechanisms; deploy new hooks for fixes

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CCA Auction                             │
│                    (Uniswap Contract)                           │
└─────────────────────┬───────────────────────────────────────────┘
                      │ calls validate()
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Permitter                                │
│  - Implements IValidationHook                                   │
│  - Manages state: committed amounts per CCID, global total      │
│  - Configurable sanctions, allowlist, and limit enforcement     │
└─────────────────────┬───────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌───────────────┐  ┌─────────────┐  ┌─────────────┐
│   Chainlink   │  │  Chainlink  │  │   Merkle    │
│    Policy     │  │   Identity  │  │  Allowlist  │
│    Engine     │  │   Registry  │  │             │
└───────────────┘  └─────────────┘  └─────────────┘
```

## Contracts

### Permitter

The main validation hook implementing Uniswap's `IValidationHook` interface.

**Key Features:**
- Token-denominated per-user and global purchase limits
- Optional sanctions checking via Chainlink ACE
- Optional Merkle-based allowlist verification
- Dual tracking by CCID (primary) and address (fallback)
- Pausable by owner

**Configuration:**

| Parameter | Description |
|-----------|-------------|
| `identityRegistry` | Chainlink CCID registry address |
| `policyEngine` | Chainlink ACE Policy Engine address |
| `merkleRoot` | Root hash for allowlist verification |
| `perUserLimit` | Maximum tokens per CCID (0 = unlimited) |
| `globalCap` | Maximum tokens for entire sale (0 = unlimited) |
| `requireSanctionsCheck` | Whether to enforce sanctions |
| `requireAllowlist` | Whether to require allowlist membership |

### PermitterFactory

Factory contract for gas-efficient deployment using EIP-1167 minimal proxies.

**Functions:**
- `createPermitter(config)` - Deploy a new Permitter
- `createPermitterDeterministic(config, salt)` - Deploy at predictable address
- `predictPermitterAddress(salt)` - Predict deployment address
- `getPermittersByCreator(address)` - Query permitters by creator

## Validation Flow

When `validate()` is called by the CCA:

1. Verify CCA is authorized and caller is the authorized CCA
2. Check paused state
3. Verify allowlist membership (if enabled) via Merkle proof
4. Resolve bidder address to CCID via Identity Registry
5. Check sanctions via Policy Engine (if enabled)
6. Verify bid doesn't exceed per-user limit
7. Verify bid doesn't exceed global cap
8. Record commitment if all checks pass

If any check fails, the transaction reverts with a descriptive error.

## Usage

### Installation

```bash
forge install
```

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Deploy

**1. Deploy the Factory (one-time)**

```bash
forge script script/DeployFactory.s.sol --rpc-url $RPC_URL --broadcast
```

**2. Create a Permitter**

```bash
FACTORY=0x... \
IDENTITY_REGISTRY=0x... \
POLICY_ENGINE=0x... \
PER_USER_LIMIT=1000000000000000000000 \
GLOBAL_CAP=100000000000000000000000 \
REQUIRE_SANCTIONS=true \
forge script script/DeployPermitter.s.sol --rpc-url $RPC_URL --broadcast
```

**Environment Variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `FACTORY` | Yes | PermitterFactory address |
| `IDENTITY_REGISTRY` | No | Chainlink CCID registry |
| `POLICY_ENGINE` | No | Chainlink ACE Policy Engine |
| `MERKLE_ROOT` | No | Allowlist Merkle root |
| `PER_USER_LIMIT` | No | Per-user limit in wei (0 = unlimited) |
| `GLOBAL_CAP` | No | Global cap in wei (0 = unlimited) |
| `REQUIRE_SANCTIONS` | No | Enable sanctions check |
| `REQUIRE_ALLOWLIST` | No | Enable allowlist |
| `CCA` | No | CCA address to authorize immediately |
| `SALT` | No | Salt for deterministic deployment |

**3. Authorize the CCA**

If not authorized during deployment:

```solidity
permitter.authorizeCCA(ccaAddress);
```

## View Functions

For frontend integration:

- `checkEligibility(address)` - Fast check if user can participate
- `getRemainingUserCapacity(address)` - Tokens remaining for user
- `getRemainingGlobalCapacity()` - Tokens remaining globally
- `getUserCommitted(address)` - Tokens already committed by user

## Admin Functions

Owner-only functions for managing the permitter:

- `setPerUserLimit(uint256)` - Update per-user limit
- `setGlobalCap(uint256)` - Update global cap
- `setMerkleRoot(bytes32)` - Update allowlist
- `setPaused(bool)` - Pause/unpause validation
- `transferOwnership(address)` - Transfer ownership

## Errors

| Error | Description |
|-------|-------------|
| `Unauthorized()` | Caller is not owner |
| `CCANotConfigured()` | No CCA authorized yet |
| `UnauthorizedCCA()` | Caller is not the authorized CCA |
| `CCAAlreadyAuthorized()` | CCA already set |
| `Paused()` | Contract is paused |
| `NoCCIDFound(address)` | Bidder has no CCID |
| `NotOnAllowlist(address)` | Bidder not on allowlist |
| `SanctionsFailed(address, bytes32)` | CCID is sanctioned |
| `IndividualLimitExceeded(bytes32, uint256, uint256)` | Per-user limit exceeded |
| `GlobalCapExceeded(uint256, uint256)` | Global cap exceeded |

## Security

### Trust Model

- Single owner EOA with full control over configuration
- Authorized CCA is immutable once set
- Fail-closed on registry unavailability

### Invariants

1. `totalCommitted <= globalCap`
2. `committedByCCID[ccid] <= perUserLimit` for all CCIDs
3. Once `auction` is set, it cannot be changed
4. Limits follow CCID, allowing wallet migration

## Development

This project uses the [ScopeLift Foundry Template](https://github.com/ScopeLift/foundry-template).

### Profiles

- `default` - Production settings
- `lite` - Optimizer off for faster compilation
- `ci` - Deep fuzz/invariant testing

### Code Quality

```bash
# Format code
scopelint fmt

# Check formatting and best practices
scopelint check
```

## License

MIT
