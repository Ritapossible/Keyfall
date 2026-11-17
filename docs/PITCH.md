# Pitch

## One line
Keyfall proves what a leaked classical key can still do to your QoreChain contract, and every
finding ships with a working replay.

## Tagline
Prove what a leaked key can still do.

## 30 seconds (spoken)
"Twenty projects in this hackathon say a leaked ECDSA key can't drain them. None of them can
prove it. Keyfall can. Give it a contract address and it forks the chain, becomes the attacker
holding the classical key, and tries everything, including replaying real post-quantum
signatures the contract already accepted. Anything that works is reported with a replay, so
there are no false positives. A clean report is signed with ML-DSA-87 and anchored on-chain.
It turns the Q-Day Drill from a one-day event into a check you run on every deploy."

## Why it can win
- **Not crowded:** no contract-level attack simulator among the ~77 projects. Account-level
  checkers exist, and Keyfall complements them.
- **QoreChain-native:** replay of on-chain PQC authorizations is a bug class that exists only
  on chains with on-chain PQC verification.
- **Rigour:** independent-oracle design (two worlds), 100% precision by construction, a public
  benchmark with recall reported honestly.
- **Ecosystem value:** every other team's vault is a test case. It's the Q-Day Drill as a tool.

## Prior art and how Keyfall differs
- Q-Day Readiness Audit, Qore PQ Health, Fenestella, Unyoke: these check **accounts**.
  Keyfall checks **contract logic**.
- qorechain-pq-check: protocol admission. Keyfall: what the contract allows once a tx is admitted.

## 3-minute video script
1. **0:00–0:20.** "A leaked ECDSA key can't drain this" claims scroll past. "Has anyone checked?"
2. **0:20–1:20.** `keyfall scan` on the `NoNonce` benchmark vault → Critical: replaying an old
   PQC signature drains it. Run the replay live on the fork.
3. **1:20–2:00.** Scan `SafeVault` → empty leak surface. Sign the report, anchor it, show the
   tx in the explorer.
4. **2:00–2:30.** A CI run fails on a PR that adds an unguarded setter.
5. **2:30–3:00.** Benchmark score (x/8 found, 0 false positives), limits stated plainly.
