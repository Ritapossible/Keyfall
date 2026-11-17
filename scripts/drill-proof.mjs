// Q-Day Drill proof: send a tiny hybrid-signed (secp256k1 + ML-DSA-87) native transfer from the
// drill account, showing it still works on drill day while its classical key is public.
// Must be run ON 18 NOV 2026 (UTC). Prints the 64-hex native tx hash (no 0x) to submit.
// Usage: node scripts/drill-proof.mjs [--dry-run]
import { StargateClient } from '@cosmjs/stargate';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import { EthNativeSigner, addressesFrom20, MSG_SEND_TYPE_URL } from '@qorechain/sdk';
import { readJson } from './lib.mjs';

const REST = 'https://api-testnet.qore.host', RPC = 'https://rpc-testnet.qore.host', CHAIN = 'qorechain-diana';
const DRY = process.argv.includes('--dry-run');
const TO = 'qor1xxzfy3qkmaky8dxxv9clh363y8ljw3jmgklph7'; // Keyfall deployer

const { privateKey } = readJson('drill.json');
const k = readJson('drill-mldsa87.json');
const pqc = { publicKey: Uint8Array.from(Buffer.from(k.publicKey, 'hex')), secretKey: Uint8Array.from(Buffer.from(k.secretKey, 'hex')) };
const priv = Buffer.from(privateKey.slice(2), 'hex');
const addr20 = Buffer.from(keccak256(secp256k1.getPublicKey(priv, false).slice(1)).slice(2), 'hex').subarray(12);
const account = { ...addressesFrom20(addr20), privateKey, publicKey: '0x' + Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex'), pqc };

const day = new Date().toISOString().slice(0, 10);
if (!DRY && day !== '2026-11-18') console.warn(`WARNING: today is ${day} UTC; the drill proof must be dated 2026-11-18.`);

const { account: a } = await fetch(`${REST}/cosmos/auth/v1beta1/accounts/${account.cosmos}`).then((r) => r.json());
const params = {
  chainId: CHAIN, accountNumber: BigInt(a.account_number), sequence: BigInt(a.sequence),
  fee: { amount: [{ denom: 'uqor', amount: '40000' }], gas: '400000' }, memo: 'Keyfall Q-Day Drill proof',
  messages: [{ typeUrl: MSG_SEND_TYPE_URL, value: { fromAddress: account.cosmos, toAddress: TO, amount: [{ denom: 'uqor', amount: '1' }] } }],
};
const signer = new EthNativeSigner(account, { signMode: 'hybrid', rest: REST });
console.log('drill account', account.cosmos, account.evm);
if (DRY) {
  const signed = signer.sign({ ...params, signBytesVersion: await signer.resolveSignBytesVersion(CHAIN) });
  console.log('dry run: hybrid tx signed OK,', Object.keys(signed).join(', '));
  process.exit(0);
}
const res = await signer.signAndBroadcast(await StargateClient.connect(RPC), params);
if (res.code) throw new Error(`refused code ${res.code}: ${res.rawLog}`);
console.log('PROOF TX HASH (submit this):', res.transactionHash.replace(/^0x/, '').toUpperCase());
