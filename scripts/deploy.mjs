// Deploys KeyfallRegistry with the registry ML-DSA-87 keyHash, optionally funding it.
// Usage: node scripts/deploy.mjs [fundQOR]
import { writeFileSync } from 'node:fs';
import { keccak256, toHex, parseEther, formatEther } from 'viem';
import { publicClient, deployer, mldsa, compileRegistry, KEYS, toQor } from './lib.mjs';

const fund = process.argv[2] ? parseEther(process.argv[2]) : 0n;
const { abi, bytecode } = compileRegistry();
const { account, wallet } = deployer();
const keyHash = keccak256(toHex(mldsa().publicKey));
console.log('deployer', account.address, 'balance', formatEther(await publicClient.getBalance({ address: account.address })), 'QOR');

const hash = await wallet.deployContract({ abi, bytecode, args: [keyHash] });
console.log('deploy tx', hash);
const rcpt = await publicClient.waitForTransactionReceipt({ hash });
if (rcpt.status !== 'success') throw new Error('deploy reverted');
const address = rcpt.contractAddress;
console.log('KeyfallRegistry', address, toQor(address));

if (fund > 0n) {
  const h = await wallet.sendTransaction({ to: address, value: fund });
  await publicClient.waitForTransactionReceipt({ hash: h });
  console.log('funded', formatEther(fund), 'QOR tx', h);
}
writeFileSync(new URL('../deployments.json', import.meta.url), JSON.stringify({
  network: 'qorechain-diana', chainId: 9800, KeyfallRegistry: address, deployTx: hash, keyHash, block: Number(rcpt.blockNumber),
}, null, 2) + '\n');
