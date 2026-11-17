// One-time setup so the deployer can use QoreChain's EVM lane:
//   1. register an ML-DSA-87 key for the deployer account (classical-signed bootstrap tx)
//   2. open an EVM authorisation window (hybrid secp256k1 + ML-DSA-87 signed)
// The deployer's PQC key is stored in keys/deployer-mldsa87.json (gitignored).
// Usage: node scripts/setup-evm-access.mjs [blocks] [maxTxs] [maxValueQOR]
import { writeFileSync } from 'node:fs';
import { StargateClient } from '@cosmjs/stargate';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  EthNativeSigner, addressesFrom20, buildRegisterPqcKeyMsg, openEvmWindowMsg, generatePqcKeypair,
  signProofOfPossession, fetchEvmWindow,
} from '@qorechain/sdk';
import { KEYS, hasKey, readJson } from './lib.mjs';

const REST = 'https://api-testnet.qore.host';
const RPC = 'https://rpc-testnet.qore.host';
const CHAIN = 'qorechain-diana';
const [blocks = 17280, maxTxs = 100, maxQor = 30] = process.argv.slice(2).map(Number);

const { privateKey } = readJson('deployer.json');
if (!hasKey('deployer-mldsa87.json')) {
  const kp = generatePqcKeypair();
  writeFileSync(new URL('deployer-mldsa87.json', KEYS), JSON.stringify({
    publicKey: Buffer.from(kp.publicKey).toString('hex'), secretKey: Buffer.from(kp.secretKey).toString('hex') }), { mode: 0o600 });
}
const k = readJson('deployer-mldsa87.json');
const pqc = { publicKey: Uint8Array.from(Buffer.from(k.publicKey, 'hex')), secretKey: Uint8Array.from(Buffer.from(k.secretKey, 'hex')) };

const priv = Buffer.from(privateKey.slice(2), 'hex');
const compressed = secp256k1.getPublicKey(priv, true);
const uncompressed = secp256k1.getPublicKey(priv, false);
const { keccak256 } = await import('viem');
const addr20 = Buffer.from(keccak256(uncompressed.slice(1)).slice(2), 'hex').subarray(12);
const account = { ...addressesFrom20(addr20), privateKey, publicKey: '0x' + Buffer.from(compressed).toString('hex'), pqc };
console.log('account', account.cosmos, account.evm);

const transport = await StargateClient.connect(RPC);
const get = (p) => fetch(REST + p).then((r) => r.json());
async function seq() {
  const { account: a } = await get(`/cosmos/auth/v1beta1/accounts/${account.cosmos}`);
  return { accountNumber: BigInt(a.account_number), sequence: BigInt(a.sequence) };
}
async function waitTx(hash) {
  for (let i = 0; i < 40; i++) {
    const r = await get(`/cosmos/tx/v1beta1/txs/${hash}`);
    if (r.tx_response) return r.tx_response;
    await new Promise((s) => setTimeout(s, 1500));
  }
  throw new Error('tx not found: ' + hash);
}
async function send(signer, messages, gas) {
  const fee = { amount: [{ denom: 'uqor', amount: String(Math.ceil(gas * 0.1)) }], gas: String(gas) };
  const res = await signer.signAndBroadcast(transport, { chainId: CHAIN, messages, fee, ...(await seq()) });
  if (res.code) throw new Error(`broadcast code ${res.code}: ${res.rawLog}`);
  const r = await waitTx(res.transactionHash);
  if (r.code) throw new Error(`tx ${res.transactionHash} failed code ${r.code} (${r.codespace}): ${r.raw_log}`);
  return res.transactionHash;
}

// 1. register the PQC key (skip if already registered)
const status = await get(`/qorechain/pqc/v1/account/${account.cosmos}`);
if (!status.found) {
  const pop = signProofOfPossession({ chainId: CHAIN, algorithmId: 1, account: account.cosmos, keypair: pqc });
  const classical = new EthNativeSigner(account, { signMode: 'classical' });
  let h;
  try {
    h = await send(classical, [buildRegisterPqcKeyMsg(account.cosmos, { pqcKeypair: pqc, ecdsaPubkey: compressed, keyType: 'hybrid', proofOfPossession: pop })], 700000);
  } catch (e) {
    console.log('register with proof of possession failed, retrying without:', e.message.slice(0, 200));
    h = await send(classical, [buildRegisterPqcKeyMsg(account.cosmos, { pqcKeypair: pqc, ecdsaPubkey: compressed, keyType: 'hybrid' })], 700000);
  }
  console.log('PQC key registered, tx', h);
} else console.log('PQC key already registered');

// 2. open the EVM window (hybrid-signed)
const hybrid = new EthNativeSigner(account, { signMode: 'hybrid', rest: REST });
const msg = openEvmWindowMsg({ sender: account.cosmos, blocks, maxTxs, maxValue: String(maxQor * 1_000_000) });
const h2 = await send(hybrid, [msg], 500000);
console.log('EVM window opened, tx', h2);
console.log(JSON.stringify(await fetchEvmWindow({ rest: REST, address: account.cosmos }), (_, v) => typeof v === 'bigint' ? v.toString() : v));
