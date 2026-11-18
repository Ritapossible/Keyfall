// Anchors a Keyfall report in KeyfallRegistry: reportHash = keccak256(report.json bytes), signed with
// the registry's ML-DSA-87 key (the signature covers the report hash, target, code hash, fork block
// and finding count) and relayed by the deployer. Writes attestation.json next to the report.
// Usage: node scripts/anchor-report.mjs reports/<address>/report.json
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { keccak256, toHex } from 'viem';
import { publicClient, deployer } from './lib.mjs';
import { abi, deployment, anchorCall } from './registry.mjs';

const file = process.argv[2];
const bytes = readFileSync(file);
const report = JSON.parse(bytes);
const reportHash = keccak256(toHex(bytes));
const REG = deployment().KeyfallRegistry;
const existing = await publicClient.readContract({ address: REG, abi, functionName: 'reports', args: [reportHash] });
if (existing[3] !== 0n) { console.log('already anchored', reportHash); process.exit(0); }

const r = { target: report.target, targetCodeHash: report.codeHash, blockNumber: BigInt(report.forkBlock), findings: report.leakSurface };
const data = await anchorCall(REG, { reportHash, report: r, deadline: BigInt(Math.floor(Date.now() / 1000) + 3600) });
const { wallet } = deployer();
const hash = await wallet.sendTransaction({ to: REG, data, gas: 2_000_000n });
const rc = await publicClient.waitForTransactionReceipt({ hash });
if (rc.status !== 'success') throw new Error('anchor reverted ' + hash);
const att = { registry: REG, reportHash, anchorTx: hash, block: Number(rc.blockNumber), target: report.target, findings: report.leakSurface,
  verify: `cast call ${REG} "reports(bytes32)(address,bytes32,uint64,uint64,uint32)" ${reportHash} --rpc-url https://evm-testnet.qore.host` };
writeFileSync(join(dirname(file), 'attestation.json'), JSON.stringify(att, null, 2) + '\n');
console.log(`anchored ${report.source.contract.padEnd(16)} findings=${report.leakSurface} hash=${reportHash.slice(0, 18)}… tx=${hash}`);
