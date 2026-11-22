#!/usr/bin/env node
// Keyfall v0: measure a QoreChain contract's leak surface.
//
//   node cli/keyfall.mjs scan <address> --source <file.sol:Contract> [--account 0x..]... [--out dir]
//
// Two worlds on one local fork (anvil), never on the live chain:
//   Q-Day world   — the PQC Verify precompile rejects everything (the attacker cannot forge ML-DSA-87).
//                   Every state-changing function is called as each privileged account and as a
//                   fresh attacker. Anything that moves value or changes state is a finding.
//   Replay world  — every past transaction to the target is re-sent by the attacker. The precompile is
//                   stubbed to accept, the replay is traced, and every signature the contract checked is
//                   verified OFF-CHAIN with real ML-DSA-87. Only if all of them are genuinely valid does
//                   the replay count, so the result matches what the real chain would do.
// Severity is a fixed rule over the state diff. Each finding ships with a replay script.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import {
  createPublicClient, createTestClient, createWalletClient, http, keccak256, toHex, decodeFunctionData,
  parseAbi, formatEther, encodeFunctionData, getAddress, isAddress, zeroAddress, toFunctionSelector, toFunctionSignature,
} from 'viem';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { compile, qore } from '../scripts/lib.mjs';

const VERSION = '0.2.0';
const PQC = '0x0000000000000000000000000000000000000a01';
const STUB_REJECT = '0x600060005260206000f3'; // returns abi.encode(false)
const STUB_ACCEPT = '0x600160005260206000f3'; // returns abi.encode(true)
const EIP1967_ADMIN = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';
const PQC_ABI = parseAbi(['function pqcVerify(bytes pubkey, bytes signature, bytes message) view returns (bool)']);
const GRIEF = /paus|frozen|freez|lock|halt|stop|nonce/i;
const json = (o) => JSON.stringify(o, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2);

// ------------------------------------------------------------------ args
const argv = process.argv.slice(2);
if (argv[0] !== 'scan' || !argv[1]) {
  console.error('usage: keyfall scan <address> --source <file.sol:Contract> [--account 0x..] [--out dir] [--rpc url]');
  process.exit(2);
}
const target = getAddress(argv[1]);
const opt = (name) => { const i = argv.indexOf(name); return i > 0 ? argv[i + 1] : undefined; };
const opts = (name) => argv.flatMap((a, i) => (a === name ? [argv[i + 1]] : []));
const RPC = opt('--rpc') ?? 'https://evm-testnet.qore.host';
const outDir = opt('--out') ?? `reports/${target.toLowerCase()}`;
const ANVIL = process.env.KEYFALL_ANVIL ?? 'anvil';

// ------------------------------------------------------------------ resolve
const live = createPublicClient({ chain: qore, transport: http(RPC) });
const [srcFile, srcName] = (opt('--source') ?? '').split(':');
if (!srcFile || !srcName) throw new Error('v0 needs --source <file.sol:Contract> (verified source)');
const { abi, deployedBytecode } = compile(srcFile, srcName);
const code = await live.getCode({ address: target });
if (!code || code === '0x') throw new Error(`no contract at ${target}`);
const sourceMatches = code.toLowerCase() === deployedBytecode.toLowerCase();
const forkBlock = await live.getBlockNumber();
const log = (...a) => console.error('[keyfall]', ...a);
log(`target ${target}  fork block ${forkBlock}  source ${srcFile}:${srcName} ${sourceMatches ? '(bytecode matches)' : '(WARNING: bytecode differs from source)'}`);

// creation block by binary search on historical code, then the deployer from that block
async function creation() {
  let lo = 0n, hi = forkBlock;
  while (lo < hi) {
    const mid = (lo + hi) / 2n;
    const c = await live.getCode({ address: target, blockNumber: mid }).catch(() => '0x');
    if (c && c !== '0x') hi = mid; else lo = mid + 1n;
  }
  const block = await live.getBlock({ blockNumber: lo, includeTransactions: true });
  for (const tx of block.transactions) {
    if (tx.to) continue;
    const r = await live.getTransactionReceipt({ hash: tx.hash });
    if (r.contractAddress && getAddress(r.contractAddress) === target) return { block: lo, deployer: getAddress(tx.from), tx: tx.hash };
  }
  return { block: lo };
}
const created = await creation();
log(`created at block ${created.block}${created.deployer ? ` by ${created.deployer}` : ''}`);

// ------------------------------------------------------------------ fork
const port = 20000 + Math.floor(Math.random() * 20000);
const anvil = spawn(ANVIL, ['--fork-url', RPC, '--fork-block-number', String(forkBlock), '--chain-id', '9800', '--port', String(port), '--silent'], { stdio: 'ignore' });
process.on('exit', () => anvil.kill());
const FORK = `http://127.0.0.1:${port}`;
const chain = { ...qore, rpcUrls: { default: { http: [FORK] } } };
const fork = createPublicClient({ chain, transport: http(FORK) });
const test = createTestClient({ chain, mode: 'anvil', transport: http(FORK) });
const wallet = createWalletClient({ chain, transport: http(FORK) });
for (let i = 0; ; i++) {
  try { await fork.getChainId(); break; } catch { if (i > 60) throw new Error('anvil did not start'); await new Promise((r) => setTimeout(r, 500)); }
}

// ------------------------------------------------------------------ accounts + state
const attacker = getAddress(toHex(randomBytes(20)));
const views = abi.filter((f) => f.type === 'function' && ['view', 'pure'].includes(f.stateMutability) && f.inputs.length === 0 && f.outputs.length === 1);
const mutating = abi.filter((f) => f.type === 'function' && !['view', 'pure'].includes(f.stateMutability));

async function readGetters() {
  const out = {};
  for (const f of views) {
    try { out[f.name] = await fork.readContract({ address: target, abi: [f], functionName: f.name }); } catch { /* reverted getter */ }
  }
  return out;
}
const getters0 = await readGetters();
const privileged = new Map(); // address -> role
const addRole = (a, role) => { if (a && isAddress(a) && a !== zeroAddress && getAddress(a) !== target && a.toLowerCase() !== PQC) privileged.set(getAddress(a), privileged.get(getAddress(a)) ?? role); };
for (const f of views) if (f.outputs[0].type === 'address') addRole(getters0[f.name], `${f.name}()`);
addRole(created.deployer, 'deployer');
const adminSlot = await fork.getStorageAt({ address: target, slot: EIP1967_ADMIN });
if (adminSlot && BigInt(adminSlot) !== 0n) addRole('0x' + adminSlot.slice(-40), 'EIP-1967 admin');
for (const a of opts('--account')) addRole(a, '--account');
const callers = [[attacker, 'attacker (no keys)'], ...privileged];
log(`privileged accounts: ${[...privileged].map(([a, r]) => `${r}=${a}`).join(', ') || 'none'}`);

const balanceOf = (address) => fork.getBalance({ address });
async function snapshotState() { return { balance: await balanceOf(target), getters: await readGetters() }; }
function diff(before, after) {
  const changes = [];
  for (const k of Object.keys({ ...before.getters, ...after.getters })) {
    if (json(before.getters[k]) !== json(after.getters[k])) changes.push({ getter: `${k}()`, before: before.getters[k], after: after.getters[k] });
  }
  return { valueOut: before.balance > after.balance ? before.balance - after.balance : 0n, changes };
}
function classify(d) {
  if (d.valueOut > 0n) return 'Critical';
  if (d.changes.some((c) => !GRIEF.test(c.getter))) return 'High';
  if (d.changes.length) return 'Medium';
  return null;
}

// ------------------------------------------------------------------ argument candidates
function candidates(type, bal) {
  if (type.endsWith('[]')) return [[]];
  if (type === 'address') return [attacker];
  if (type.startsWith('uint')) {
    const max = 2n ** BigInt(type.slice(4) || 256) - 1n;
    return [...new Set([bal > 0n ? bal : 1n, 1n, 2n ** 64n].map((v) => (v > max ? max : v)))];
  }
  if (type.startsWith('int')) return [1n];
  if (type === 'bool') return [true, false];
  if (type.startsWith('bytes') && type !== 'bytes') return ['0x' + '00'.repeat(Number(type.slice(5)) - 1) + '01'];
  if (type === 'bytes') return ['0x'];
  if (type === 'string') return ['keyfall'];
  return [undefined];
}
function argSets(f, bal) {
  const opts = f.inputs.map((i) => (i.type === 'tuple' ? [i.components.map((c) => candidates(c.type, bal)[0])] : candidates(i.type, bal)));
  const base = opts.map((o) => o[0]);
  const sets = [base];
  opts.forEach((o, i) => o.slice(1).forEach((v) => { const s = [...base]; s[i] = v; sets.push(s); }));
  return sets.slice(0, 8);
}

// ------------------------------------------------------------------ execution helper
async function execAs(from, data) {
  await test.impersonateAccount({ address: from });
  await test.setBalance({ address: from, value: 10n ** 21n });
  const hash = await wallet.sendTransaction({ account: from, to: target, data, gas: 15_000_000n });
  const receipt = await fork.waitForTransactionReceipt({ hash });
  return { hash, ok: receipt.status === 'success' };
}

const findings = [];
const callable = [];
const replayLog = [];
const replayScript = (f) => [
  '#!/usr/bin/env bash',
  `# Keyfall replay: ${f.id} (${f.severity}) — ${f.title}`,
  '# Runs on a LOCAL fork only. Needs Foundry (anvil + cast).',
  'set -euo pipefail',
  `anvil --fork-url ${RPC} --fork-block-number ${forkBlock} --chain-id 9800 --port 8555 --silent & ANVIL=$!; trap "kill $ANVIL" EXIT; sleep 6`,
  'R=http://127.0.0.1:8555',
  `cast rpc anvil_setCode ${PQC} ${f.kind.includes('replay') ? STUB_ACCEPT : STUB_REJECT} --rpc-url $R >/dev/null  # ${f.kind.includes('replay') ? 'accept: every signature in this replay was verified valid off-chain' : 'reject: attacker has no ML-DSA-87 key'}`,
  `echo "target balance before: $(cast balance ${target} --rpc-url $R)"`,
  ...f.steps.flatMap((st, i) => [
    `# step ${i + 1}: ${st.function} as ${st.callerRole}`,
    `cast rpc anvil_impersonateAccount ${st.caller} --rpc-url $R >/dev/null`,
    `cast rpc anvil_setBalance ${st.caller} 0x3635c9adc5dea00000 --rpc-url $R >/dev/null`,
    `cast send --unlocked --from ${st.caller} ${target} ${st.calldata} --gas-limit 15000000 --rpc-url $R >/dev/null`,
  ]),
  `echo "target balance after:  $(cast balance ${target} --rpc-url $R)"`,
  ...f.changes.map((c) => `echo "${c.getter}: $(cast call ${target} '${c.getter.replace('()', '')}()' --rpc-url $R)"`),
  '',
].join('\n');

// ------------------------------------------------------------------ Q-Day world
await test.setCode({ address: PQC, bytecode: STUB_REJECT });
const qdaySnap = await test.snapshot();
let qdayCalls = 0;
const enablers = []; // successful single calls, the first step of possible sequences
const step = (f, caller, role, data) => ({ function: toFunctionSignature(f), caller, callerRole: role, calldata: data });
for (const f of mutating) {
  const sig = toFunctionSignature(f);
  let found = false;
  for (const [caller, role] of callers) {
    if (found) break;
    for (const args of argSets(f, await balanceOf(target))) {
      const data = encodeFunctionData({ abi: [f], functionName: f.name, args });
      const snap = await test.snapshot();
      const before = await snapshotState();
      let r;
      try { r = await execAs(caller, data); } catch { r = { ok: false }; }
      qdayCalls++;
      if (r.ok) {
        const d = diff(before, await snapshotState());
        const sev = classify(d);
        enablers.push({ ...step(f, caller, role, data), severity: sev });
        if (sev) {
          findings.push({ severity: sev, layer: 'contract', kind: 'unguarded', title: `${sig} succeeds for ${role} without any PQC signature`,
            function: sig, caller, callerRole: role, calldata: data, steps: [step(f, caller, role, data)], valueOut: d.valueOut, changes: d.changes });
          found = true;
        } else callable.push({ function: sig, caller: role });
      }
      await test.revert({ id: snap });
      if (found) break;
    }
  }
}
// two-step sequences: every successful first call, followed by every function as every caller.
// Reported only when the pair is strictly worse than anything either step does alone.
const RANK = { Critical: 3, High: 2, Medium: 1 };
const worstSingle = (sig) => Math.max(0, ...findings.filter((x) => x.function === sig).map((x) => RANK[x.severity]));
let seqCalls = 0;
for (const e of enablers) {
  for (const f2 of mutating) {
    let done = false;
    for (const [caller, role] of callers) {
      if (done) break;
      for (const args of argSets(f2, await balanceOf(target))) {
        const data = encodeFunctionData({ abi: [f2], functionName: f2.name, args });
        const snap = await test.snapshot();
        const before = await snapshotState();
        let r1, r2;
        try { r1 = await execAs(e.caller, e.calldata); } catch { r1 = { ok: false }; }
        if (r1.ok) { try { r2 = await execAs(caller, data); } catch { r2 = { ok: false }; } seqCalls++; }
        if (r1.ok && r2.ok) {
          const d = diff(before, await snapshotState());
          const sev = classify(d);
          const f2sig = toFunctionSignature(f2);
          if (sev && RANK[sev] > Math.max(RANK[e.severity] ?? 0, worstSingle(f2sig), worstSingle(e.function))) {
            findings.push({ severity: sev, layer: 'contract', kind: 'sequence',
              title: `${e.function} as ${e.callerRole}, then ${f2sig} as ${role}, without any PQC signature`,
              function: `${e.function} → ${f2sig}`, caller: e.caller, callerRole: e.callerRole, calldata: e.calldata,
              steps: [e, step(f2, caller, role, data)].map(({ severity, ...st }) => st), valueOut: d.valueOut, changes: d.changes });
            done = true;
          }
        }
        await test.revert({ id: snap });
        if (done) break;
      }
    }
  }
}
await test.revert({ id: qdaySnap });
log(`Q-Day world: ${qdayCalls} single calls + ${seqCalls} two-step sequences across ${mutating.length} functions and ${callers.length} callers`);

// ------------------------------------------------------------------ Replay world
// --harvest-from <address>: also harvest a sibling contract's history (e.g. one sharing the same
// signing key) to catch signatures that are not bound to the contract they were made for.
const sources = [target, ...opts('--harvest-from').map(getAddress)];
async function harvest() {
  const txs = [];
  for (const src of sources) {
    const hashes = new Set();
    const start = src === target ? created.block : created.block > 30000n ? created.block - 30000n : 0n;
    for (let from = start; from <= forkBlock; from += 10000n) {
      const to = from + 9999n > forkBlock ? forkBlock : from + 9999n;
      for (const l of await live.getLogs({ address: src, fromBlock: from, toBlock: to })) hashes.add(l.transactionHash);
    }
    for (const h of hashes) {
      const tx = await live.getTransaction({ hash: h });
      if (tx.to && getAddress(tx.to) === src && tx.input !== '0x') txs.push(tx);
    }
  }
  return txs;
}
function pqcCalls(trace) {
  const out = [];
  (function walk(c) { if (c.to && c.to.toLowerCase() === PQC) out.push(c.input); (c.calls ?? []).forEach(walk); })(trace);
  return out;
}
const history = await harvest();
const selectors = new Map(mutating.map((f) => [toFunctionSelector(f), f]));
for (const tx of history) {
  const f = selectors.get(tx.input.slice(0, 10));
  if (!f) continue;
  const snap = await test.snapshot();
  await test.setCode({ address: PQC, bytecode: STUB_ACCEPT });
  const before = await snapshotState();
  let r;
  try { r = await execAs(attacker, tx.input); } catch { r = { ok: false }; }
  const entry = { sourceTx: tx.hash, function: toFunctionSignature(f), replayed: r.ok };
  if (r.ok) {
    const trace = await fork.request({ method: 'debug_traceTransaction', params: [r.hash, { tracer: 'callTracer' }] });
    const calls = pqcCalls(trace);
    const verdicts = calls.map((input) => {
      try {
        const { args: [pk, sg, msg] } = decodeFunctionData({ abi: PQC_ABI, data: input });
        return ml_dsa87.verify(Buffer.from(sg.slice(2), 'hex'), Buffer.from(msg.slice(2), 'hex'), Buffer.from(pk.slice(2), 'hex'));
      } catch { return false; }
    });
    entry.pqcChecks = calls.length;
    entry.allSignaturesValid = calls.length > 0 && verdicts.every(Boolean);
    if (entry.allSignaturesValid) {
      const d = diff(before, await snapshotState());
      const sev = classify(d);
      entry.effect = sev ?? 'none';
      const cross = getAddress(tx.to) !== target;
      if (sev) findings.push({ severity: sev, layer: 'contract', kind: cross ? 'cross-contract-replay' : 'replay',
        title: cross ? `a PQC-authorized ${toFunctionSignature(f)} made for ${getAddress(tx.to)} is accepted here too (signature not bound to this contract)`
          : `replaying past PQC-authorized ${toFunctionSignature(f)} succeeds (signature accepted again)`,
        function: toFunctionSignature(f), caller: attacker, callerRole: 'attacker (no keys)', sourceTx: tx.hash, sourceContract: tx.to, calldata: tx.input,
        steps: [{ function: toFunctionSignature(f), caller: attacker, callerRole: 'attacker (no keys)', calldata: tx.input }],
        pqcChecks: calls.length, valueOut: d.valueOut, changes: d.changes });
    }
  }
  replayLog.push(entry);
  await test.revert({ id: snap });
}
log(`Replay world: ${history.length} past transactions harvested, ${replayLog.filter((e) => e.allSignaturesValid && e.effect !== 'none').length} still work`);

// ------------------------------------------------------------------ report
const order = { Critical: 0, High: 1, Medium: 2 };
findings.sort((a, b) => order[a.severity] - order[b.severity]);
findings.forEach((f, i) => { f.id = `KF-${String(i + 1).padStart(2, '0')}`; f.valueOutQOR = formatEther(f.valueOut); });
const summary = { critical: 0, high: 0, medium: 0 };
findings.forEach((f) => summary[f.severity.toLowerCase()]++);
const report = {
  keyfall: VERSION, network: 'qorechain-diana', chainId: 9800, target, codeHash: keccak256(code),
  source: { file: srcFile, contract: srcName, bytecodeMatches: sourceMatches },
  forkBlock, createdBlock: created.block, deployer: created.deployer ?? null,
  threatModel: 'attacker holds the classical ECDSA key of every privileged account and sees all past calldata; cannot forge ML-DSA-87',
  accounts: { attacker, privileged: Object.fromEntries([...privileged].map(([a, r]) => [a, r])) },
  coverage: { functions: mutating.map(toFunctionSignature), qdayCalls, sequenceCalls: seqCalls, harvestedFrom: sources, harvestedTxs: history.length, replays: replayLog },
  callableWithoutEffect: callable,
  leakSurface: findings.length, summary, findings,
  limits: ['A clean result means nothing was found in these runs, not proof of safety.', 'Protocol-layer admission (EVM windows) is not modelled on the fork.', 'Sequences up to two calls; fixed argument candidates (no fuzzing yet).'],
};
mkdirSync(join(outDir, 'replays'), { recursive: true });
writeFileSync(join(outDir, 'report.json'), json(report) + '\n');
for (const f of findings) writeFileSync(join(outDir, 'replays', `${f.id}.sh`), replayScript(f), { mode: 0o755 });

console.log(`\nKeyfall ${VERSION} — ${srcName} ${target}`);
console.log(`leak surface: ${findings.length}  (critical ${summary.critical}, high ${summary.high}, medium ${summary.medium})`);
for (const f of findings) console.log(`  ${f.id} ${f.severity.padEnd(8)} ${f.title}${f.valueOut > 0n ? `  [${f.valueOutQOR} QOR out]` : ''}${f.changes.length ? `  [${f.changes.map((c) => c.getter).join(', ')} changed]` : ''}`);
console.log(`report: ${join(outDir, 'report.json')}`);
anvil.kill();
process.exit(0);
