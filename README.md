# Keyfall

[![Built on QoreChain](https://build.qorechain.io/badge/keyfall.svg)](https://build.qorechain.io/p/keyfall)

**Prove what a leaked key can still do.**

Keyfall measures a QoreChain contract's **leak surface**: every state change an attacker
holding only the classical (ECDSA) keys can cause. Paste an address. Keyfall forks testnet,
plays the attacker, and reports every function that still moves value or changes control,
each with a working replay. Clean reports are signed with ML-DSA-87 and anchored on-chain.

> Status: early build for *Build Before Q-Day* (QoreChain). The architecture below is the plan;
> the **Verified so far** section lists what actually works today.

## Why

Many contracts claim "a leaked ECDSA key can't drain this." Until now nothing checked that
claim except a real attacker. Keyfall turns the Q-Day Drill into a test you run on every deploy.

## How it works (planned)

On one fork, each call sequence runs in two worlds:

| | Q-Day world | Honest world |
|---|---|---|
| Caller | privileged accounts, classical key only | same accounts |
| PQC Verify (`0x…0a01`) | always rejects (ML-DSA-87 can't be forged) | accepts valid authorizations |

A **finding** is anything that succeeds in the Q-Day world and moves value or changes control.

Attack classes:
1. **Unguarded paths** — value/control functions with no PQC check.
2. **Replayed PQC authorizations** — every PQC-signed call the contract ever received is
   resubmitted by the attacker. Missing nonce, domain separation or deadline turns a real
   post-quantum signature into a weapon. This bug class exists only on chains with on-chain PQC.
3. **Sequences** — up to 3 calls that are harmless alone.

Severity is a rule over the state diff, not a model: value out = Critical, control change =
High, griefing = Medium. Every finding ships with a minimal replay, so there are no false positives.

```
address ─► Resolver ─► Harness generator ─► forge (fork + fuzz) ─► Classifier ─► Report ─► Attestor
```

## Verified so far

- `scripts/probe-precompile.mjs` calls the testnet PQC Verify precompile with `eth_call`
  (no transaction): a FIPS 204 ML-DSA-87 signature from `@noble/post-quantum` returns `true`;
  a tampered signature or altered message returns `false`.

```
npm install
npm run probe
```

## Contracts

- `src/KeyfallRegistry.sol` — stores hashes of signed scan reports and holds a small treasury.
  Every write needs an ML-DSA-87 signature over a digest bound to chain id, contract, action,
  nonce and deadline. `msg.sender` is never trusted, so a leaked classical key has no privilege.
  Key rotation needs proof of possession of the new key; `cancel` revokes unsent authorizations.

| Deployment (testnet) | |
|---|---|
| KeyfallRegistry | [`0x3cc2c6ccbf30ea28d683a1df3ac8576169eeaf60`](https://explore.qore.network) (`qor18npvdn9lxr4z345r580n4jzhv957atmqa8mhkt`) |
| Deploy tx | `0xe70681ba626532f68249b213eb4e9001e08c883ff80132fd7d85264bcd72f23b` |

`node scripts/attack-registry.mjs` runs 16 attack and replay checks against the live contract
using the real PQC precompile. Current result: **16/16 pass**.

## Limits (stated up front)

- A clean report means "nothing found in N runs", not "safe". Fuzzing can't prove absence.
- Protocol-level admission rules (scoped EVM windows) are enforced by the chain, not the fork.
  Findings are labelled by layer.
- v1 scans verified contracts only.
- Off-chain relayers and frontends are out of scope.

## Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): threat model, pipeline, severity rules
- [docs/PLAN.md](docs/PLAN.md): milestones to 2 Dec
- [docs/PITCH.md](docs/PITCH.md): pitch and video script
- [CLAUDE.md](CLAUDE.md): project memory, decisions and verified network facts
- [AI_USAGE.md](AI_USAGE.md): how AI was used and how its output was verified

## Network

EVM RPC `https://evm-testnet.qore.host` · EVM chain id 9800 · PQC Verify `0x0000000000000000000000000000000000000a01`

## Team

- **Rita** ([@Ritapossible](https://github.com/Ritapossible)): author

## License

MIT
