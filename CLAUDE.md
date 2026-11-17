# Keyfall: project memory

Read this first in every session. It is the single source of truth for context,
decisions and current state. Update the **Current state** and **Log** sections at the end
of every work session.

## What this is

Keyfall measures a QoreChain contract's **leak surface**: every state change an attacker
holding only classical (ECDSA) keys can cause. It forks testnet, plays that attacker, and
reports each finding with a working replay. Clean reports are ML-DSA-87 signed and anchored
in `KeyfallRegistry`.

- Hackathon: QoreChain *Build Before Q-Day*. Category: **Post-Quantum dApp**. Region: NG (MEA).
- Project page: https://build.qorechain.io/p/keyfall
- Tagline: "Prove what a leaked key can still do."
- Owner: @Ritapossible (solo).

## Deadlines

| Date (UTC) | What |
|---|---|
| 18 Nov | Q-Day Drill day (only if a drill account was registered) |
| 19 Nov 23:59 | Submit the drill proof tx hash (tx must be dated 18 Nov) |
| **2 Dec 23:59** | **Final: repo, README, ≤3-min video, testnet address(es)** |
| 3–5 Dec | Organizer checks |
| 16 Dec | Winners |

## Hackathon rules that affect the code

- Public repo, MIT licence (done), README.
- At least one testnet address the project uses must be listed on the project page.
- Kits and network features ticked on the page are **verified against the code and testnet**.
  Tick only what is really used.
- Commits must happen during the event; the QoreChain GitHub App must be installed.
- AI-Native award: keep `AI_USAGE.md` current.

## Network facts (verified)

| Item | Value |
|---|---|
| EVM RPC | `https://evm-testnet.qore.host` |
| EVM chain id | 9800 (`0x2648`) |
| Cosmos chain id | `qorechain-diana` |
| PQC Verify precompile | `0x0000000000000000000000000000000000000a01` |
| Interface | `pqcVerify(bytes pubkey, bytes signature, bytes message) returns (bool)` |
| Sizes | pubkey 2592 B, signature 4627 B (FIPS 204 ML-DSA-87) |
| Gas | 25,000 base + 8/byte of input (~85–90k typical) |
| Inactive precompile | returns empty data (`0x`) → callers must fail closed |
| PQC key status | **not** a precompile. REST: `GET https://api-testnet.qore.host/qorechain/pqc/v1/account/{address}`. JSON-RPC `qor_getPQCKeyStatus` is planned, returns -32601 today |
| Explorer | https://explore.qore.network |
| Faucet | https://dashboard.qorechain.io/faucet |
| Docs | https://docs.qorechain.io/developer-guide/evm-precompiles |
| EVM lane admission | sender needs a registered PQC key **and** an open EVM window (`MsgOpenEVMWindow`, hybrid-signed): blocks ≤17,280, maxTxs ≤1,000, maxValue in uqor incl. fees. `allowed_targets` / `native_only` forbid contract creation |
| SDK | `@qorechain/sdk` 0.14 (`EthNativeSigner`, `buildRegisterPqcKeyMsg`, `openEvmWindowMsg`, `fetchEvmWindow`) |

Verified on 17 Nov 2026:
- The RPC serves `eth_getBlockByNumber`, `eth_getStorageAt` (also at past blocks), `eth_getProof`
  and `eth_getCode`. That's enough for `anvil --fork-url`.
- `debug_traceCall` is **not** available. Do traces locally on the fork.
- `scripts/probe-precompile.mjs`: a `@noble/post-quantum` v0.7.1 `ml_dsa87.sign(msg, sk)` signature
  verifies on-chain (`true`). A tampered signature or altered message returns `false`. No context
  string is used.
- **Not yet verified:** that `anvil --fork-url` runs cleanly against this RPC (Foundry wasn't
  installable in the first session).

## Decisions (do not reopen without a reason)

1. **Contract-level scanner, not an account checker.** Account-level tools already exist on
   the board (Q-Day Readiness Audit, Qore PQ Health, Fenestella, qorechain-pq-check).
2. **Replay harvesting is the core feature.** It's the QoreChain-native bug class and the
   answer to "this is just a generic fuzzer". Never cut it.
3. **Reuse Foundry, don't write a fuzzer.** Generate invariant-test harnesses and let `forge`
   fuzz and shrink.
4. **Severity comes from rules over the state diff, never from an LLM.** Precision is 100% by
   construction: every finding has a replay that works.
5. **v1 scans verified contracts only.** Recovering an ABI from bytecode comes later.
6. **Never broadcast attacks.** Everything runs on a local fork. Scans of other teams' contracts
   are opt-in, with private disclosure before anything is published.
7. **`KeyfallRegistry` never trusts `msg.sender`.** Its controlling ML-DSA-87 key is a
   dedicated key generated locally (not the QoreX account key). Only `keccak256(pubkey)` is
   stored on-chain.

## Secrets

Never commit or paste: ECDSA private keys, the ML-DSA-87 secret key, or the drill key. Keep
them in `.env` or `keys/` (both gitignored).

## Conventions

- Solidity pinned `0.8.28` (evmVersion paris), sources in `src/`, Foundry tests in `test/`, deploy scripts in `script/`.
- Node scripts are ESM (`.mjs`) in `scripts/`, using `viem` and `@noble/post-quantum`.
- Addresses in Solidity must use the correct checksum. The PQC address is all lowercase.
- Commit small and often. Every commit counts as event activity.

## Current state

- [x] Project created on build.qorechain.io
- [x] Repo: licence, README, badge, AI_USAGE.md
- [x] `KeyfallRegistry` reviewed (fixes: rotation proof of possession, `cancel`, pinned 0.8.28) and **deployed**:
  `0x3cc2c6ccbf30ea28d683a1df3ac8576169eeaf60` (see `deployments.json`), funded with 2 QOR.
- [x] `scripts/attack-registry.mjs`: 16/16 checks pass on testnet against the real precompile.
- [x] Deployer has its own ML-DSA-87 key registered and an EVM window (`scripts/setup-evm-access.mjs`).
- [x] Precompile probe passing
- [ ] Drill: registry address goes in the drill form (user registers the drill account in QoreX)
- Next: see `docs/PLAN.md` → Milestone 1.

## Log

- **17 Nov.** Idea chosen (see `docs/PITCH.md`), repo scaffolded, precompile verified, project page live.
- **17 Nov (later).** Registry reviewed and hardened, deployed to testnet, 16/16 attack checks pass.
  Finding: the EVM lane refuses txs from accounts without a registered PQC key and an open
  EVM window (codes 26–28). So the drill attacker, holding only a classical key, can't send EVM
  txs at all unless the account has a window open. Keyfall's findings need a `protocol` layer label for this.
