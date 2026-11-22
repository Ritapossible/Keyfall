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

## Results (v0.2, 22 Nov 2026, testnet)

`keyfall scan` against five benchmark vaults deployed on testnet, plus Keyfall's own registry.
Every report is signed with ML-DSA-87 and anchored in `KeyfallRegistry`.

| Contract | Planted bug | Keyfall finding | Report |
|---|---|---|---|
| `NoNonce` `0xc1a6…3ad9` | PQC digest has no nonce | **Critical**: replaying a past PQC-authorized `withdraw` drains the vault (signature verified genuine off-chain) | [report](reports/0xc1a690a79d4f7cbd2ada7925ae5454f3a2783ad9/report.json) |
| `UnguardedSetter` `0x6750…b1b1` | guardian set via `msg.sender` | **High** `setGuardian` by owner's classical key · **Medium** `freeze` by guardian's key | [report](reports/0x67508e00454a1f66bf4564c8a3c3b913c878b1b1/report.json) |
| `RecoveryVault` `0xca91…2254` | recovery agent appointed via `msg.sender` | **Critical** (two-step): owner's classical key appoints the attacker, attacker sweeps 0.9 QOR · **High** `setRecoveryAgent` alone | [report](reports/0xca9171c2d60a43f57fcaa23e7bbfdf2dd7d32254/report.json) |
| `NoDomain` B `0xebf8…c6f4` | digest doesn't name contract/chain | **Critical** (cross-contract): a withdrawal signed for vault A `0x371a…3ed7` drains vault B (`--harvest-from` A) | [report](reports/0xebf86aedc6baefdfbc5272ff118b460de3e0c6f4/report.json) |
| `SafeVault` `0xb03b…21d3` | none | **clean** (0 findings) | [report](reports/0xb03b09742168f16a5a8f75b0a744788370a421d3/report.json) |
| `KeyfallRegistry` `0x3cc2…af60` | none | **clean**; all 3 past txs fail to replay | [report](reports/0x3cc2c6ccbf30ea28d683a1df3ac8576169eeaf60/report.json) |

Each finding has a standalone replay script in `reports/<address>/replays/` (local fork only).

## Usage

```bash
npm install
# needs Foundry's anvil on PATH (or KEYFALL_ANVIL=/path/to/anvil)
node cli/keyfall.mjs scan <address> --source <file.sol:Contract> [--account 0x…] [--harvest-from <sibling>]
node scripts/anchor-report.mjs reports/<address>/report.json   # sign + anchor on-chain
```

How v0 decides, in one paragraph: on a local fork, the **Q-Day world** stubs the PQC precompile to
reject and calls every state-changing function as each privileged account (getters, deployer,
EIP-1967 admin) and as a keyless attacker. The **replay world** re-sends every past transaction
to the target as the attacker with the precompile stubbed to accept, traces the call, and verifies
every signature the contract checked with real ML-DSA-87 off-chain. A replay counts only if all
of them are genuinely valid, so the fork behaves exactly as the chain would. `--harvest-from` adds a
sibling contract's history (e.g. one sharing the signing key) to catch signatures that aren't bound to
the contract they were made for. Every successful call is also tried as the first step of a two-call
sequence, reported only when the pair is worse than either call alone. Severity: value out
= Critical, control change = High, pause/freeze/nonce change = Medium.

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
