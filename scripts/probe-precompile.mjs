// Read-only probe: does QoreChain's PQC Verify precompile accept a FIPS 204 ML-DSA-87
// signature produced by @noble/post-quantum? Uses eth_call only; sends no transaction.
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { createPublicClient, http, encodeFunctionData, parseAbi, toHex, keccak256 } from 'viem';

const RPC = process.env.QORE_EVM_RPC ?? 'https://evm-testnet.qore.host';
const PQC = '0x0000000000000000000000000000000000000a01';
const abi = parseAbi(['function pqcVerify(bytes pubkey, bytes signature, bytes message) view returns (bool)']);
const client = createPublicClient({ transport: http(RPC) });

const seed = new Uint8Array(32).fill(7); // throwaway deterministic key, probe only
const { publicKey, secretKey } = ml_dsa87.keygen(seed);
const message = new Uint8Array(Buffer.from(keccak256(toHex('keyfall-probe')).slice(2), 'hex'));
const sig = ml_dsa87.sign(message, secretKey);
console.log('pubkey', publicKey.length, 'sig', sig.length, 'local verify', ml_dsa87.verify(sig, message, publicKey));

async function call(label, pk, s, m) {
  const data = encodeFunctionData({ abi, functionName: 'pqcVerify', args: [toHex(pk), toHex(s), toHex(m)] });
  try {
    const r = await client.call({ to: PQC, data });
    console.log(label.padEnd(16), '->', r.data ?? '(no data)');
  } catch (e) { console.log(label.padEnd(16), '-> REVERT/ERROR', e.shortMessage ?? e.message); }
}
await call('valid', publicKey, sig, message);
const bad = Uint8Array.from(sig); bad[100] ^= 1;
await call('tampered sig', publicKey, bad, message);
const m2 = Uint8Array.from(message); m2[0] ^= 1;
await call('wrong message', publicKey, sig, m2);
