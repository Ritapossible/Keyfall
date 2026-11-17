// End-to-end attack test against a DEPLOYED KeyfallRegistry, using the REAL PQC precompile.
// Attacks are simulated with eth_call from an attacker address (no state change);
// only the positive cases send real transactions (relayed by the deployer).
// Usage: node scripts/attack-registry.mjs
import { randomBytes } from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { decodeErrorResult, keccak256, toHex, parseEther, encodeFunctionData } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { RPC, publicClient, deployer } from './lib.mjs';
import { abi, deployment, anchorCall, withdrawCall, signFor } from './registry.mjs';

const REG = deployment().KeyfallRegistry;
const attacker = privateKeyToAccount(generatePrivateKey()).address;
const { account, wallet } = deployer();
const now = BigInt(Math.floor(Date.now() / 1000));
const later = now + 3600n;
let pass = 0, fail = 0;

async function simulate(data, from = attacker) {
  const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ from, to: REG, data, gas: '0x1c9c380' }, 'latest'] }) }).then((r) => r.json());
  if (!res.error) return { ok: true };
  const raw = res.error.data;
  let name = res.error.message;
  try { if (raw && raw !== '0x') name = decodeErrorResult({ abi, data: raw }).errorName; } catch {}
  return { ok: false, name };
}
function expect(label, got, want) {
  const okk = want === 'success' ? got.ok : !got.ok && got.name === want;
  okk ? pass++ : fail++;
  console.log(`${okk ? 'PASS' : 'FAIL'}  ${label.padEnd(58)} -> ${got.ok ? 'success' : got.name}${okk ? '' : `  (wanted ${want})`}`);
}
const garbage = toHex(randomBytes(4627));
const report = (n) => ({ reportHash: keccak256(toHex(`keyfall-e2e-${n}-${now}`)),
  report: { target: REG, targetCodeHash: keccak256(toHex('code')), blockNumber: 1n, findings: 0 }, deadline: later });

console.log('registry', REG, 'attacker', attacker, '\n');
const { publicKey } = (await import('./lib.mjs')).mldsa();
const pk = toHex(publicKey);

// --- attacks (classical key / no valid PQC signature) ---
expect('withdraw with garbage signature', await simulate(encodeFunctionData({ abi, functionName: 'withdraw', args: [attacker, 1n, later, pk, garbage] })), 'InvalidPQCSignature');
const evil = ml_dsa87.keygen(randomBytes(32));
expect("withdraw signed by attacker's own ML-DSA-87 key", await simulate(await withdrawCall(REG, { to: attacker, amount: 1n, deadline: later }, evil)), 'BadPubkey');
expect('rotateKey to attacker key, garbage signature', await simulate(encodeFunctionData({ abi, functionName: 'rotateKey', args: [keccak256(toHex(evil.publicKey)), later, pk, garbage] })), 'InvalidPQCSignature');
{ // valid owner signature for withdraw-to-owner, attacker swaps recipient
  const okData = await withdrawCall(REG, { to: account.address, amount: 1n, deadline: later });
  const { args } = (await import('viem')).decodeFunctionData({ abi, data: okData });
  expect('valid withdraw signature, recipient swapped to attacker', await simulate(encodeFunctionData({ abi, functionName: 'withdraw', args: [attacker, ...args.slice(1)] })), 'InvalidPQCSignature');
}
{ // anchor signature reused for withdraw (action confusion)
  const { pubkey, sig } = await signFor(REG, 'ACTION_ANCHOR', '0x', later);
  expect('anchor-action signature reused for withdraw', await simulate(encodeFunctionData({ abi, functionName: 'withdraw', args: [attacker, 1n, later, pubkey, sig] })), 'InvalidPQCSignature');
}
expect('expired deadline', await simulate(await withdrawCall(REG, { to: account.address, amount: 1n, deadline: now - 60n })), 'Expired');

// --- legitimate use: anyone can relay a valid PQC authorization ---
const r1 = report(1);
const anchorData = await anchorCall(REG, r1);
expect('valid anchor relayed by the ATTACKER address (simulated)', await simulate(anchorData), 'success');
const h1 = await wallet.sendTransaction({ to: REG, data: anchorData, gas: 2_000_000n });
const rc1 = await publicClient.waitForTransactionReceipt({ hash: h1 });
expect(`real anchor tx ${h1.slice(0, 12)}… gas ${rc1.gasUsed}`, { ok: rc1.status === 'success', name: rc1.status }, 'success');
expect('replay of the exact anchor calldata', await simulate(anchorData), 'AlreadyAnchored');

const bal = await publicClient.getBalance({ address: REG });
if (bal > 0n) {
  const wData = await withdrawCall(REG, { to: account.address, amount: 1n, deadline: later });
  const h2 = await wallet.sendTransaction({ to: REG, data: wData, gas: 2_000_000n });
  const rc2 = await publicClient.waitForTransactionReceipt({ hash: h2 });
  expect(`real withdraw(1 wei) tx ${h2.slice(0, 12)}…`, { ok: rc2.status === 'success', name: rc2.status }, 'success');
  expect('replay of the exact withdraw calldata (nonce consumed)', await simulate(wData), 'InvalidPQCSignature');
} else console.log('SKIP  withdraw cases (registry unfunded)');

console.log(`\n${pass} passed, ${fail} failed. nonce now ${await publicClient.readContract({ address: REG, abi, functionName: 'nonce' })}`);
process.exit(fail ? 1 : 0);
