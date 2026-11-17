# Architecture

## Threat model

The attacker:
- holds the **classical ECDSA private key** of every privileged account of the target
  (owner, admin, guardian, deployer, operator), which is exactly the Q-Day Drill's model;
- can see every past transaction, including calldata that carried valid ML-DSA-87 signatures;
- **cannot** forge ML-DSA-87 signatures.

The question Keyfall answers: *which state changes can this attacker cause?* That set is the
contract's **leak surface**.

## Core method: two worlds on one fork

| | Q-Day world | Honest world |
|---|---|---|
| Callers | privileged accounts (via `vm.prank`), classical key only | same |
| PQC Verify `0x…0a01` | stub that always returns `false` | stub that accepts signatures from a test key, or the real result |
| Answers | what the attacker can do | what the PQC layer actually protects |

A **finding** is a call sequence that succeeds in the Q-Day world **and** produces a
value-moving or control-changing state diff. Because the finding is an executed transaction
on the fork, it always comes with a replay. There are no false positives by construction.
The cost is that a clean result means "nothing found in N runs", not "proven safe".

## Pipeline

```
target address
   │
   ▼
┌────────────┐  ABI + source (explorer), privileged accounts,
│ Resolver   │  fork block, token balances held by the target
└─────┬──────┘
      ▼
┌────────────────────┐  generates test/generated/<addr>.t.sol:
│ Harness generator  │  fork at block N, vm.etch the PQC stub, handler contract whose
└─────┬──────────────┘  functions prank as privileged accounts and call target selectors
      ▼
┌────────────────────┐  forge test --fork-url … (invariant + fuzz)
│ Runner             │  plus the replay harvester: resubmit harvested PQC-signed calldata
└─────┬──────────────┘
      ▼
┌────────────────────┐  state diff → severity rules; forge shrinks to a minimal sequence
│ Classifier         │
└─────┬──────────────┘
      ▼
┌────────────────────┐  report.json (canonical) + report.html, with a `cast` replay per finding
│ Reporter           │
└─────┬──────────────┘
      ▼
┌────────────────────┐  keccak256(report.json) → ML-DSA-87 sign → KeyfallRegistry.anchorReport
│ Attestor           │
└────────────────────┘
```

### 1. Resolver
- ABI and source from the explorer's verified-contract API (v1 requires verified source).
- Privileged accounts are the union of:
  - the return values of zero-arg getters returning `address` whose names match
    `owner|admin|guardian|operator|manager|governor|keeper|signer|controller`;
  - the EIP-1967 admin slot `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`;
  - the contract's deployer (from the creation tx);
  - addresses the user adds with `--account`.
- Value at risk: native balance plus balances of the faucet tokens (fUSD, fETH, fBTC) and any
  ERC-20 that appears in the target's `Transfer` logs.

### 2. Harness generator
- Writes a Foundry test per target. In `setUp`: `vm.createSelectFork(rpc, block)`,
  `vm.etch(PQC, rejectStub)`, and a handler as the invariant target.
- Each handler function: pick a privileged account → `vm.prank` → call one selector of the
  target with fuzzed args. Argument dictionaries are seeded with the attacker address, the
  privileged accounts, 0, max, and the target's own token balances.
- Invariants checked after every call:
  - `ValueOut`: the target's native and token balances did not fall to an attacker-controlled address.
  - `ControlStable`: owner/admin getters, the EIP-1967 slots and the PQC key binding are unchanged.
- Sequence depth: up to 3 (Foundry `invariant.depth`).

### 3. Replay harvester (the QoreChain-native part)
- Collect every past transaction to the target (explorer API, or scan `eth_getLogs` plus
  blocks), and keep those whose calldata contains a 4627-byte segment, i.e. likely carrying an
  ML-DSA-87 signature.
- In the Q-Day world **with the real verification semantics** (the stub replaced by an oracle
  table of `(pubkey, msg, sig)` triples observed as valid on-chain), resubmit each one from an
  attacker address, as-is and with the `to`/`amount`-style arguments mutated.
- A finding means the contract accepted an old authorization again (no nonce), in another
  context (no domain separation), or late (no deadline).

### 4. Classifier (deterministic)

| Severity | Rule over the state diff |
|---|---|
| Critical | native or token balance of the target decreases and an attacker-controlled address gains |
| High | a control variable changes: owner/admin getter, EIP-1967 admin or implementation slot, guardian set, limits, PQC key hash |
| Medium | griefing: pause or freeze set, pending ops cancelled, funds locked (balance unchanged but withdrawals revert afterwards) |
| Info | succeeded without a meaningful diff |

Each finding is labelled with its **layer**: `contract` (proven on the fork) or `protocol`
(depends on QoreChain admission rules such as scoped EVM windows, which the fork does not
model; flagged and never claimed).

### 5. Reporter
- `report.json` has a canonical key order. It holds the target, its code hash, the fork block,
  the accounts, the findings (severity, layer, call sequence, state diff) and the Keyfall version.
- Each finding has a replay script made of `cast send` commands against a local `anvil` fork.

### 6. Attestor and `KeyfallRegistry`
- `reportHash = keccak256(report.json)`.
- The signed message is the registry's `digest(ACTION_ANCHOR, payload, deadline)`, which is
  bound to chain id, registry address, action, nonce and deadline.
- `anchorReport` checks the ML-DSA-87 signature through the precompile. `msg.sender` is
  ignored, so anyone can relay.
- The registry also holds a small treasury (`withdraw`) and supports key rotation (`rotateKey`),
  both PQC-gated. That makes it a meaningful Q-Day Drill target.

## Interfaces

- CLI: `keyfall scan <address> [--block N] [--account 0x…] [--depth 3] [--runs 256] [--out dir]`
- CI: GitHub Action `keyfall/check`, which fails if any Critical or High finding is at layer `contract`.
- Web (stretch): a static report viewer that reads `report.json` and checks the anchor on-chain.

## Repo layout (target)

```
src/                 Solidity: KeyfallRegistry, PQC stubs
test/                Foundry tests for the registry
bench/               benchmark vaults: 8 with planted bugs, 2 correct
cli/                 keyfall CLI (TypeScript): resolver, generator, runner, classifier, reporter
scripts/             one-off scripts (probe, deploy, sign)
docs/                ARCHITECTURE, PLAN, PITCH
```

## Known limits

- Fuzzing finds bugs but can't prove there are none.
- Protocol-level rules (scoped EVM windows, account PQC enforcement) aren't modelled by the fork.
- Unverified contracts aren't supported in v1.
- Off-chain relayers and frontends are out of scope.
- If the PQC stub's semantics differ from the real precompile on some edge case, findings
  could be wrong for that case. The honest world uses the real precompile through the fork
  wherever possible.
