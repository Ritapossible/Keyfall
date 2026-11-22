// Deploys the second benchmark set: RecoveryVault (two-step bug) and two NoDomain vaults sharing
// one key (cross-contract replay). Vault A gets a legitimate PQC-signed withdrawal; B gets none.
import { readFileSync, writeFileSync } from 'node:fs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { keccak256, toHex, toBytes, parseEther, encodeAbiParameters, encodeFunctionData } from 'viem';
import { publicClient, deployer, compile, readJson } from './lib.mjs';

const bk = readJson('bench-mldsa87.json');
const pk = Uint8Array.from(Buffer.from(bk.publicKey, 'hex')), sk = Uint8Array.from(Buffer.from(bk.secretKey, 'hex'));
const keyHash = keccak256(toHex(pk));
const { account, wallet } = deployer();
const send = async (req) => { const h = await wallet.sendTransaction({ gas: 3_000_000n, ...req }); const r = await publicClient.waitForTransactionReceipt({ hash: h }); if (r.status !== 'success') throw new Error('reverted ' + h); return h; };
async function deploy(file, name) {
  const { abi, bytecode } = compile(file, name);
  const h = await wallet.deployContract({ abi, bytecode, args: [keyHash], gas: 3_000_000n });
  const r = await publicClient.waitForTransactionReceipt({ hash: h });
  await send({ to: r.contractAddress, value: parseEther('1') });
  return { abi, address: r.contractAddress, deployTx: h, block: Number(r.blockNumber) };
}
const TENTH = parseEther('0.1');
const out = {};

const rv = await deploy('bench/RecoveryVault.sol', 'RecoveryVault');
{ const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const payload = encodeAbiParameters([{ type: 'address' }, { type: 'uint256' }], [account.address, TENTH]);
  const d = await publicClient.readContract({ address: rv.address, abi: rv.abi, functionName: 'digest', args: [keccak256(toHex('WITHDRAW')), payload, deadline] });
  rv.legitWithdrawTx = await send({ to: rv.address, data: encodeFunctionData({ abi: rv.abi, functionName: 'withdraw', args: [account.address, TENTH, deadline, toHex(pk), toHex(ml_dsa87.sign(toBytes(d), sk))] }) }); }

const a = await deploy('bench/NoDomain.sol', 'NoDomain');
const b = await deploy('bench/NoDomain.sol', 'NoDomain');
{ const deadline = BigInt(Math.floor(Date.now() / 1000) + 30 * 86400); // a long-lived authorization
  const d = await publicClient.readContract({ address: a.address, abi: a.abi, functionName: 'digest', args: [account.address, TENTH, deadline] });
  a.legitWithdrawTx = await send({ to: a.address, data: encodeFunctionData({ abi: a.abi, functionName: 'withdraw', args: [account.address, TENTH, deadline, toHex(pk), toHex(ml_dsa87.sign(toBytes(d), sk))] }) }); }

for (const [k, v] of [['RecoveryVault', rv], ['NoDomainA', a], ['NoDomainB', b]]) { const { abi, ...rest } = v; out[k] = rest; console.log(k.padEnd(14), v.address, v.legitWithdrawTx ? 'legit withdraw ' + v.legitWithdrawTx : '(no history)'); }
const dep = JSON.parse(readFileSync(new URL('../deployments.json', import.meta.url), 'utf8'));
Object.assign(dep.bench, out);
writeFileSync(new URL('../deployments.json', import.meta.url), JSON.stringify(dep, null, 2) + '\n');
