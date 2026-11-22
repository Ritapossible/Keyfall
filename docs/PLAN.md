# Plan

Final deadline: **2 Dec 2026, 23:59 UTC**. Tick boxes as work lands, and keep `CLAUDE.md`
→ *Current state* in sync.

## Milestone 0: Setup (17 Nov) ✅
- [x] Project page created
- [x] Repo with MIT licence, README, badge, AI_USAGE.md
- [x] `KeyfallRegistry.sol` drafted and compiling
- [x] PQC Verify precompile probe passing on testnet

## Milestone 1: Registry on testnet (18–19 Nov)
- [x] Install Foundry
- [x] Spike: `anvil --fork-url https://evm-testnet.qore.host` and `cast call` a contract on the fork
- [ ] `src/test/PQCStub.sol`: reject-all stub and a test-key stub
- [ ] `test/KeyfallRegistry.t.sol`: valid anchor; garbage signature from any sender; replay of the
      same signature; anchor signature reused for withdraw (action binding); expired deadline;
      wrong pubkey; precompile missing (fail closed); withdraw; rotateKey (old key stops working)
- [ ] `scripts/keygen.mjs`: generate the registry's ML-DSA-87 key into `keys/` (gitignored)
- [ ] `scripts/sign.mjs`: read `digest()` from the chain, sign, print calldata
- [ ] `script/Deploy.s.sol`: deploy to testnet
- [x] Anchor one test report on testnet (4 real scan reports anchored 18 Nov)
- [ ] Add the registry address to the project page, and tick the PQC Verify network feature
- [ ] Drill (if entered): one tx from the drill account on 18 Nov, hash submitted by 19 Nov

## Milestone 2: Benchmark (20–21 Nov)
- [ ] `bench/` with 10 vaults (each 30–80 lines):
  1. `SafeVault` ✅ deployed: correct (nonce, domain, deadline, PQC on everything)
  2. `SafeTimelockVault`: correct, with a timelock
  3. `UnguardedSetter` ✅ deployed: `setGuardian` without PQC
  4. `NoNonce` ✅ deployed: a PQC-signed withdraw can be replayed
  5. `NoDomain` ✅ deployed (A/B pair): the signature isn't bound to the contract, so it replays across two instances
  6. `NoDeadline`: an old signature is valid forever (only matters with nonce gaps)
  7. `ActionConfusion`: the same digest is accepted for withdraw and setLimit
  8. `MsgSenderOwner`: `onlyOwner` via `msg.sender`
  9. `TimelockBypass` (covered in spirit by `RecoveryVault` ✅, a two-step escalation): `setDelay(0)` → `queue` → `execute`, all classical
  10. `UpgradeableNoPQC`: UUPS `upgradeTo` gated by `msg.sender`
- [ ] Deploy all 10 to testnet (more testnet addresses for the page)

## Milestone 3: Scanner core (22–26 Nov)
- [x] `cli/` skeleton (Node ESM, viem): `keyfall scan <address>`
- [ ] Resolver: explorer ABI fetch, privileged-account discovery, value at risk
- [ ] Harness generator: fork, stub, handler, invariants
- [ ] Runner: invoke `forge`, parse the results and counterexamples
- [x] Replay harvester: collect past txs (logs) and resubmit them on the fork, verifying signatures off-chain
- [x] Classifier and `report.json` (+ replay scripts)
- [ ] Target: 8/8 planted bugs found, 0 findings on the 2 correct vaults

## Milestone 4: Attestation and CI (27–28 Nov)
- [x] Attestor: sign `report.json` and anchor it in the registry
- [ ] HTML report with replay commands
- [ ] GitHub Action (cut first if late)

## Milestone 5: Real-world run (29 Nov)
- [ ] Scan opt-in hackathon contracts on the fork only
- [ ] Private disclosure to affected teams before anything is published
- [ ] Benchmark and real-world results table in the README

## Milestone 6: Ship (30 Nov – 2 Dec)
- [ ] README: final architecture, results, limits, how to run
- [ ] 3-minute video (script in `docs/PITCH.md`)
- [ ] Cover image (optional)
- [ ] Project page: "How it's made" updated, all testnet addresses, kits and features ticked only if verified
- [ ] `AI_USAGE.md` final
- [ ] Buffer day

## Cut list (in order)
1. GitHub Action
2. HTML report (keep the JSON and CLI output)
3. Sequence depth 3 → 1
4. On-chain anchoring (keep the signed JSON)

**Never cut:** replay harvesting, the benchmark, the registry deployment.
