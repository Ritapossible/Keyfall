// Creates (once) the registry's ML-DSA-87 key and an EVM deployer key in keys/ (gitignored).
// Never overwrites existing keys. Prints only public values.
import { writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { keccak256, toHex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { KEYS, hasKey, readJson, toQor } from './lib.mjs';

if (!hasKey('registry-mldsa87.json')) {
  const { publicKey, secretKey } = ml_dsa87.keygen(randomBytes(32));
  writeFileSync(new URL('registry-mldsa87.json', KEYS), JSON.stringify({
    publicKey: Buffer.from(publicKey).toString('hex'), secretKey: Buffer.from(secretKey).toString('hex'),
  }), { mode: 0o600 });
}
if (!hasKey('deployer.json')) {
  writeFileSync(new URL('deployer.json', KEYS), JSON.stringify({ privateKey: generatePrivateKey() }), { mode: 0o600 });
}
const pk = Buffer.from(readJson('registry-mldsa87.json').publicKey, 'hex');
const addr = privateKeyToAccount(readJson('deployer.json').privateKey).address;
console.log('registry ML-DSA-87 keyHash:', keccak256(toHex(pk)));
console.log('deployer EVM address     :', addr);
console.log('deployer native address  :', toQor(addr));
