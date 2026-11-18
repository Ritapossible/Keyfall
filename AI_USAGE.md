# AI usage

Keyfall is built by Rita (@Ritapossible) with **Claude Code** as a pair programmer. This file
records what the AI did, what the human did, and how AI output was checked. It's updated
every work session.

## Principles

1. **The human decides, the AI drafts.** Scope, threat model, trade-offs and what ships are
   decided by the author. The AI proposes and implements.
2. **Nothing is trusted because the AI said it.** Each claim about QoreChain is checked
   against the official docs or the live testnet before code depends on it. Each contract
   change is checked by tests.
3. **No AI in the scanner's verdicts.** Keyfall's findings come from executing transactions
   on a fork and applying fixed severity rules. An LLM never decides whether something is a
   vulnerability. That keeps results reproducible and free of hallucinated findings.
4. **Secrets never go to the AI.** Private keys stay in gitignored files and are never pasted
   into prompts.

## Where AI was used

| Area | What the AI did | What the human did | How it was verified |
|---|---|---|---|
| Idea selection | Compared candidate ideas against the ~77 projects already registered and against patterns from past hackathon winners. Flagged crowded categories (PQC vaults, agent guardians, inheritance) | Picked the direction and category | Read the projects board directly |
| Threat model and architecture (`docs/ARCHITECTURE.md`) | Drafted the two-worlds method, the replay-harvesting attack class and the severity rules | Reviewed and accepted the scope, and the "never cut replay harvesting" decision | Design review; the rules will be measured on the benchmark |
| Network research | Read the QoreChain docs for the precompile address, interface, sizes, gas and failure mode | Confirmed the facts were needed | **Live testnet probes**: RPC methods needed for forking (`eth_getStorageAt` at past blocks, `eth_getProof`, `eth_getCode`); `debug_traceCall` found to be unavailable |
| `scripts/probe-precompile.mjs` | Wrote a read-only `eth_call` probe of PQC Verify (`0x…0a01`) | Ran it | Real ML-DSA-87 signature → `true`; tampered signature → `false`; altered message → `false` |
| `src/KeyfallRegistry.sol` | Drafted the PQC-gated registry: no `msg.sender` trust, a digest bound to chain id, contract, action, nonce and deadline, and fail-closed handling when the precompile returns empty data | Reviewed the security model | Compiles (solc 0.8.28). It caught its own address-checksum compile error. **Tests are pending (Milestone 1)** |
| Docs (`README`, `CLAUDE.md`, `docs/`) | Drafted | Edited and approved | n/a |

## Problems the AI caught or that we caught in AI output

- An early idea (a PQC social-recovery vault) was dropped after checking the board showed at
  least 5 near-duplicates.
- Precompile addresses suggested by another AI assistant were checked against the official
  docs before use. PQC key status turned out to be a REST endpoint, not a precompile as
  first suggested.
- The docs list EVM chain id 9801 on one page, but the testnet RPC returns 9800. The code
  uses the value read from the chain.

## Tooling

- Claude Code (Anthropic), in cloud sessions on this repository
- `CLAUDE.md` is the shared project memory that keeps sessions consistent

## Log

- **17 Nov.** Idea, architecture, precompile probe, registry draft, repo scaffold.
- **17 Nov (later).** Pre-deploy security review requested by the author. AI found no critical or high issues
  and fixed three lower ones (rotation could brick the registry with a wrong key hash → proof of
  possession; no way to revoke a signed-but-unsent authorization → `cancel`; floating pragma → pinned).
  The first deploy was refused by the chain (no PQC key or EVM window); AI read the docs and SDK types
  and wrote the hybrid-signed setup. Verified by 16 on-chain attack checks, all passing.
- **18 Nov.** AI wrote the benchmark vaults, scanner v0 and the report anchoring. Design choice made to keep
  verdicts free of AI judgement: replayed signatures are checked with real ML-DSA-87, severity is a fixed
  rule. Verified by scanning all four contracts (expected results matched) and running the generated
  replay scripts on a fresh fork. AI caught its own bug (integer width in argument generation).
