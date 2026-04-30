# wBOB Contracts

> *The lock that can only be opened by three voices in agreement, none of which are "Bob"'s.*

Foundry source for the **wBOB Bridge** on Gnosis Chain — the contracts
that mint **Wrapped Dobbscoin (wBOB)** when native (BOB) is locked on
the Dobbscoin L1, and burn it when (BOB) is released back.

These contracts are deployed and live. The bridge they back ships at
[`bridge.subgenius.finance`](https://bridge.subgenius.finance/). The
service code that drives them lives in
[`dobbscoin/wbob-bridge`](https://github.com/dobbscoin/wbob-bridge).

---

## What's in the box

```
src/
  WBob.sol                 ERC-20 — wrapped (BOB), 8 decimals, role-gated mint/burn
  BridgeController.sol     3-of-5 EIP-712 mint authorization + burn-to-release accounting
  BridgeExecutorModule.sol Safe module that lets the automated executor call only
                            executeMint / pause / unpause — never admin

test/
  ...                      Unit tests + 1000-run fuzz + invariant suite at depth 100

script/
  Deploy.s.sol             End-to-end deployment script
```

---

## The 3-of-5 invariant

The load-bearing piece. Five EOAs are registered as authorized signers
on `BridgeController`. To mint wBOB, an off-chain caller must present a
`MintAuthorization` (EIP-712 typed data — depositId, recipient, amount,
sourceChainId, deadline) along with **at least 3 valid signatures** from
**distinct** signers. The contract:

1. Verifies signatures and dedupes signers in `_countValidSignatures`.
2. Bails early once it hits the threshold (gas savings on the happy path).
3. Marks `processedDeposits[depositId] = true` — **forever, no clearing**.
4. Mints the corresponding wBOB.

There is no admin escape hatch on `executeMint`. There is no oracle
that can pause it mid-call. The `mintNonce` admin lever exists only to
**invalidate outstanding authorizations** in an emergency (force every
watcher to re-sign with the new nonce); it cannot fabricate or
fast-forward a mint.

In Conspiracy terms: this is a vault that opens only when three of five
strangers — none of them "Bob" — agree it should. Even the Safe that
holds admin can't reach in and grab.

---

## Trust model — Tier B

| Privilege | Who holds it |
|---|---|
| `DEFAULT_ADMIN_ROLE` (pause, role mgmt, signer rotation, mintNonce bump) | **Gnosis Safe** (multi-owner, threshold-governed) |
| `BRIDGE_EXECUTOR_ROLE` on wBOB (callable mint/burn target) | `BridgeController` only |
| `executeMint`, `pause`, `unpause` automation | `BridgeExecutorModule` (Safe module — constrained surface) |
| Authorization signers (3-of-5) | Five independent watcher EOAs, no admin power |

**No hot wallet ever holds `DEFAULT_ADMIN_ROLE`.** This is the single
most important invariant in the whole repo.

---

## Key design decisions

- **8 decimals on wBOB** to match Dobbscoin satoshi precision (so 1 BOB
  = 100,000,000 raw on both chains, no awkward rescaling).
- **EIP-712 typed mints**, not raw signature concatenation, so wallets
  can display human-readable mint authorizations and signers don't
  blind-sign opaque hashes.
- **Signer dedup in `_countValidSignatures`** — a single key can't
  count multiple times. The 3-of-5 threshold is on **distinct keys**.
- **Early exit at THRESHOLD** in the signature loop — no work done past
  3 valid signatures, even if the caller submits all 5.
- **`processedDeposits[depositId]` is one-way.** Set on first mint,
  never cleared. Replay protection survives signer key rotation, admin
  changes, even a Safe takeover.
- **`withdrawalNonces[address]` monotonically increases per user** so
  burn requests can't be replayed against a single account.
- **`mintNonce` (admin-incrementable)** is the emergency-stop on
  outstanding authorizations: bumping it invalidates every signature
  in flight.

---

## Deployed addresses (Gnosis Chain, chainId 100)

| Contract | Address | Status |
|---|---|---|
| wBOB ERC-20 | [`0x13550ae65f22A36f60A50d625B70b58666488263`](https://gnosisscan.io/address/0x13550ae65f22A36f60A50d625B70b58666488263) | Source-verified on Gnosisscan |
| BridgeController | [`0x20a9A6D5FB3615a79603a6Ed74A3d26FB11aB872`](https://gnosisscan.io/address/0x20a9A6D5FB3615a79603a6Ed74A3d26FB11aB872) | Source-verified |
| BridgeExecutorModule | [`0xd5ebf9EC7971B18A6b1e7f05Ee0BF96BE72e3410`](https://gnosisscan.io/address/0xd5ebf9EC7971B18A6b1e7f05Ee0BF96BE72e3410) | Source-verified |

---

## Build, test, deploy

Solidity **0.8.27**, Foundry **1.6.0-nightly**, OpenZeppelin **v5.3.0**.

```bash
forge install
forge build

# Unit + fuzz (1000 runs each)
forge test --no-match-path 'test/invariants/*' -v

# Invariant suite (500 runs × depth 100)
forge test --match-path 'test/invariants/*' -v

# All
forge test -v
```

### Deploy

```bash
cp .env.example .env
# fill in DEPLOYER_PRIVATE_KEY, SAFE_ADDRESS, WATCHER_1..5, RPC_URL, etc.
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL --broadcast --chain-id 100
```

---

## Foundry nightly STATICCALL quirk (developer note)

In the nightly Foundry used here, `vm.prank` and `vm.expectRevert` are
**consumed by STATICCALL** (i.e. view-function calls), not just
state-changing calls. If you read a role constant or build a signature
inside an `expectRevert`-bracketed line, the prank/expectation is
spent on the read, not the call you cared about.

```solidity
// WRONG — prank consumed by BRIDGE_EXECUTOR_ROLE() STATICCALL
vm.prank(admin);
wBOB.grantRole(wBOB.BRIDGE_EXECUTOR_ROLE(), executor);

// CORRECT
bytes32 role = wBOB.BRIDGE_EXECUTOR_ROLE();
vm.prank(admin);
wBOB.grantRole(role, executor);
```

```solidity
// WRONG — expectRevert consumed by _buildSigs() which calls
// getMintAuthorizationDigest() (a view)
vm.expectRevert(...);
bridge.executeMint(auth, _buildSigs(auth, indices));

// CORRECT
bytes[] memory sigs = _buildSigs(auth, indices);
vm.expectRevert(...);
bridge.executeMint(auth, sigs);
```

If a test fails with a confusing "expected revert but call succeeded"
or "next call's caller is wrong", check this first.

---

## Audit status

**Unaudited** as of this writing. Test coverage is broad (unit + 1000-run
fuzz + invariant runs at depth 100), but no third-party security audit
has been completed. A formal audit is on the roadmap.

**NOT FINANCIAL ADVISORS. NOT FINANCIAL ADVICE.** Read the code. Verify
the deployments on Gnosisscan. Trust 3-of-5 watchers only as much as
you trust three strangers to disagree with each other when it matters.

---

## Related repos

- [`dobbscoin/wbob-bridge`](https://github.com/dobbscoin/wbob-bridge) — the bridge service stack (backend, watcher, portal, ops)
- [`dobbscoin/dobbscoin-source`](https://github.com/dobbscoin/dobbscoin-source) — the Dobbscoin L1 daemon (Bitcoin Core 0.10 fork, scrypt PoW, since Jan 2014)

---

> *Eternal salvation, or triple your money back.*

— Praise "Bob".
