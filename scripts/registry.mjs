// Builds PQC-authorized calls to a deployed KeyfallRegistry.
import { readFileSync } from 'node:fs';
import { encodeAbiParameters, keccak256, toHex, toBytes, encodeFunctionData } from 'viem';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { publicClient, compileRegistry, mldsa } from './lib.mjs';

export const { abi } = compileRegistry();
export const deployment = () => JSON.parse(readFileSync(new URL('../deployments.json', import.meta.url), 'utf8'));
const read = (address, functionName, args = []) => publicClient.readContract({ address, abi, functionName, args });

export async function signFor(address, action, payload, deadline, key = mldsa()) {
  const digest = await read(address, 'digest', [await read(address, action), payload, deadline]);
  const sig = ml_dsa87.sign(toBytes(digest), key.secretKey);
  return { digest, pubkey: toHex(key.publicKey), sig: toHex(sig) };
}

export async function anchorCall(address, { reportHash, report, deadline }, key) {
  const payload = encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'address' }, { type: 'bytes32' }, { type: 'uint64' }, { type: 'uint32' }],
    [reportHash, report.target, report.targetCodeHash, report.blockNumber, report.findings]);
  const { pubkey, sig } = await signFor(address, 'ACTION_ANCHOR', payload, deadline, key);
  const r = { ...report, anchoredAt: 0n };
  return encodeFunctionData({ abi, functionName: 'anchorReport', args: [reportHash, r, deadline, pubkey, sig] });
}

export async function withdrawCall(address, { to, amount, deadline }, key) {
  const payload = encodeAbiParameters([{ type: 'address' }, { type: 'uint256' }], [to, amount]);
  const { pubkey, sig } = await signFor(address, 'ACTION_WITHDRAW', payload, deadline, key);
  return encodeFunctionData({ abi, functionName: 'withdraw', args: [to, amount, deadline, pubkey, sig] });
}
