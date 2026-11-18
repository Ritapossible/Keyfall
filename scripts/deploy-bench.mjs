// Deploys the benchmark vaults to testnet, funds each, and makes one legitimate PQC-signed
// withdrawal from each so there is real on-chain history for Keyfall's replay harvester.
// Vault owner key: keys/bench-mldsa87.json (created if missing). Writes deployments.json → bench.
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { keccak256, toHex, toBytes, parseEther, encodeAbiParameters, encodeFunctionData } from 'viem';
import { publicClient, deployer, compile, KEYS, hasKey, readJson } from './lib.mjs';

if (!hasKey('bench-mldsa87.json')) {
  const kp = ml_dsa87.keygen(randomBytes(32));
  writeFileSync(new URL('bench-mldsa87.json', KEYS), JSON.stringify({
    publicKey: Buffer.from(kp.publicKey).toString('hex'), secretKey: Buffer.from(kp.secretKey).toString('hex') }), { mode: 0o600 });
}
const bk = readJson('bench-mldsa87.json');
const pk = Uint8Array.from(Buffer.from(bk.publicKey, 'hex')), sk = Uint8Array.from(Buffer.from(bk.secretKey, 'hex'));
const keyHash = keccak256(toHex(pk));
const { account, wallet } = deployer();
const guardian = '0x' + randomBytes(20).toString('hex'); // a classical-only guardian address
const send = async (req) => { const h = await wallet.sendTransaction({ gas: 3_000_000n, ...req }); const r = await publicClient.waitForTransactionReceipt({ hash: h }); if (r.status !== 'success') throw new Error('reverted ' + h); return { h, r }; };
const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
const ONE = parseEther('1'), TENTH = parseEther('0.1');

const out = {};
for (const [file, name, args] of [
  ['bench/SafeVault.sol', 'SafeVault', [keyHash, guardian]],
  ['bench/UnguardedSetter.sol', 'UnguardedSetter', [keyHash, guardian]],
  ['bench/NoNonce.sol', 'NoNonce', [keyHash]],
]) {
  const { abi, bytecode } = compile(file, name);
  const h = await wallet.deployContract({ abi, bytecode, args, gas: 3_000_000n });
  const r = await publicClient.waitForTransactionReceipt({ hash: h });
  const address = r.contractAddress;
  await send({ to: address, value: ONE });

  // one legitimate PQC-signed withdrawal of 0.1 QOR back to the deployer
  let digest, data;
  if (name === 'NoNonce') {
    digest = await publicClient.readContract({ address, abi, functionName: 'digest', args: [account.address, TENTH] });
    const sig = ml_dsa87.sign(toBytes(digest), sk);
    data = encodeFunctionData({ abi, functionName: 'withdraw', args: [account.address, TENTH, toHex(pk), toHex(sig)] });
  } else {
    const payload = encodeAbiParameters([{ type: 'address' }, { type: 'uint256' }], [account.address, TENTH]);
    digest = await publicClient.readContract({ address, abi, functionName: 'digest', args: [keccak256(toHex('WITHDRAW')), payload, deadline] });
    const sig = ml_dsa87.sign(toBytes(digest), sk);
    data = encodeFunctionData({ abi, functionName: 'withdraw', args: [account.address, TENTH, deadline, toHex(pk), toHex(sig)] });
  }
  const w = await send({ to: address, data });
  out[name] = { address, deployTx: h, block: Number(r.blockNumber), legitWithdrawTx: w.h };
  console.log(name.padEnd(16), address, 'block', Number(r.blockNumber), 'legit withdraw', w.h);
}
const dep = JSON.parse(readFileSync(new URL('../deployments.json', import.meta.url), 'utf8'));
dep.bench = { ownerKeyHash: keyHash, guardian, ...out };
writeFileSync(new URL('../deployments.json', import.meta.url), JSON.stringify(dep, null, 2) + '\n');
